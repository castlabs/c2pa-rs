// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Verifiable Segment Info (VSI) signing for live video (C2PA section 19.4).
//!
//! Each media segment carries a COSE_Sign1 inside an `emsg` box, signed by a
//! session key provided by the caller.  The init segment carries the
//! session key in a `c2pa.session-keys` assertion; the session key's
//! `signerBinding` is a detached COSE_Sign1 where the session key signs the
//! signer's end-entity certificate, proving the key is associated with the
//! manifest signer (§18.25.2).

use std::sync::Arc;

use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use pkcs8::DecodePublicKey;

use super::{
    bmff::{parse_init_segment, parse_media_segment, InitSegmentInfo},
    cose_key::{
        build_ed25519_cose_key, cose_key_to_der, kid_from_cose_key, signing_alg_from_cose_key,
    },
    verifiable_segment_info::{VSI_SCHEME_ID_URI, VSI_URI_OFFSET_IN_EMSG},
};
use crate::{
    assertions::{BmffHash, DataMap, ExclusionsMap, SessionKey, SessionKeys},
    builder::Builder,
    cbor_types::DateT,
    error::{Error, Result},
    live_video::verifiable_segment_info::SegmentInfoMap,
    Context, Reader, Signer, SigningAlg,
};

const VSI_VALUE_FSEG: &str = "fseg";

/// Identifies why a VSI session-key signature is being requested.
///
/// Callers must authorize based on this explicit value rather than inferring
/// purpose from callback order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VsiSigningPurpose {
    /// Signs the detached COSE Sig_structure that binds the session key to the
    /// manifest signer's end-entity certificate.
    SignerBinding,
    /// Signs the final VSI COSE Sig_structure for a media segment.
    Vsi {
        /// The actual `mfhd` and VSI sequence number represented by the payload.
        sequence_number: u64,
    },
}

/// Synchronous, non-exportable session-key signing interface for live-video VSI.
///
/// `sig_structure` is the exact final COSE Sig_structure byte string. The
/// implementation must return a raw COSE signature: exactly 64 bytes for both
/// Ed25519 and ES256 (`r || s`, not ASN.1 DER). Implementations may call a
/// hardware or remote keystore, but the call remains synchronous to the SDK.
pub trait VsiSessionSigner: Send + Sync + 'static {
    /// Signs one COSE Sig_structure for the explicit signing purpose.
    fn sign(&self, purpose: VsiSigningPurpose, sig_structure: &[u8]) -> Result<Vec<u8>>;
}

impl<F> VsiSessionSigner for F
where
    F: Fn(VsiSigningPurpose, &[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
{
    fn sign(&self, purpose: VsiSigningPurpose, sig_structure: &[u8]) -> Result<Vec<u8>> {
        self(purpose, sig_structure)
    }
}

/// Public metadata and verification material for one VSI session key.
///
/// `public_cose_key_cbor` must encode a public COSE_Key map whose algorithm and
/// non-empty `kid` agree with the explicit fields. Milestone 2 initially accepts
/// EdDSA/Ed25519 and ES256/P-256 only.
#[derive(Clone, Debug)]
pub struct VsiSessionConfig {
    /// Session signing algorithm.
    pub algorithm: SigningAlg,
    /// Non-empty binary COSE key identifier.
    pub kid: Vec<u8>,
    /// CBOR-encoded public COSE_Key map.
    pub public_cose_key_cbor: Vec<u8>,
    /// First valid BMFF `mfhd` sequence number.
    pub min_sequence_number: u64,
    /// RFC 3339 session-key creation time emitted unchanged as `createdAt`.
    pub created_at: String,
    /// Session-key validity period in seconds.
    pub validity_period_secs: u64,
}

struct LocalEd25519SessionSigner(SigningKey);

impl VsiSessionSigner for LocalEd25519SessionSigner {
    fn sign(&self, _purpose: VsiSigningPurpose, sig_structure: &[u8]) -> Result<Vec<u8>> {
        let signature: ed25519_dalek::Signature = Ed25519Signer::sign(&self.0, sig_structure);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Signs live video segments using the Verifiable Segment Info method (§19.4).
///
/// The caller provides a local Ed25519 session key via [`from_signing_key`] or
/// a generic session signer via [`from_session_signer`]. The
/// init segment is signed with the manifest [`Signer`] and carries a
/// `c2pa.session-keys` assertion that includes the session public key and a
/// `signerBinding` COSE_Sign1 proving the key is associated with the manifest
/// signer.
///
/// Each media segment receives a COSE_Sign1 `emsg` box signed by the session
/// key; the box is prepended to the segment bytes.
///
/// [`from_signing_key`]: LiveVideoVsiSigner::from_signing_key
/// [`from_session_signer`]: LiveVideoVsiSigner::from_session_signer
pub struct LiveVideoVsiSigner {
    context: Arc<Context>,
    session_signer: Arc<dyn VsiSessionSigner>,
    algorithm: SigningAlg,
    session_cose_key: c2pa_cbor::Value,
    kid: Vec<u8>,
    signer_binding: Option<c2pa_cbor::Value>,
    manifest_signer_ee_cert_der: Vec<u8>,
    min_sequence_number: u64,
    created_at: DateT,
    validity_period: u64,
    next_sequence_number: u64,
    next_event_id: u32,
    base_manifest_json: String,
    /// Instance ID of the active manifest from the signed init segment.
    /// Populated by `sign_init_segment` and embedded in every media segment's
    /// `segment-info-map` as `manifestId` per §19.4.
    active_manifest_id: Option<String>,
    /// Track ID and timescale read from a valid signed initialization segment.
    track_id: Option<u32>,
    track_timescale: Option<u32>,
    default_sample_duration: Option<u32>,
}

struct RestoredInitState {
    manifest_id: String,
    session_key: SessionKey,
    init_info: InitSegmentInfo,
}

impl LiveVideoVsiSigner {
    /// Creates a VSI signer from a caller-provided Ed25519 session key.
    ///
    /// Builds the `signerBinding` COSE_Sign1 per §18.25.2: the session key
    /// signs the manifest signer's end-entity certificate (detached payload).
    ///
    /// # Arguments
    ///
    /// * `manifest_json` — base manifest JSON (without a `c2pa.session-keys`
    ///   assertion; one is added automatically when signing the init segment).
    /// * `manifest_signer` — the C2PA [`Signer`] whose end-entity certificate
    ///   is bound to the session key via `signerBinding`.
    /// * `signing_key` — Ed25519 session private key.
    /// * `kid` — key identifier for the session key (e.g. `b"session-key-1"`).
    /// * `min_sequence_number` — first sequence number valid for this key.
    /// * `validity_period_secs` — how long (in seconds) the session key is valid.
    pub fn from_signing_key(
        manifest_json: impl Into<String>,
        manifest_signer: &dyn Signer,
        signing_key: SigningKey,
        kid: impl Into<Vec<u8>>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<Self> {
        let context = Arc::new(super::context_from_thread_local_settings()?);
        Self::from_local_ed25519_parts(
            context,
            manifest_json.into(),
            manifest_signer,
            signing_key,
            kid.into(),
            min_sequence_number,
            validity_period_secs,
        )
    }

    /// Creates a local Ed25519 VSI signer using an explicit shared SDK context.
    ///
    /// The context's signer signs the initialization manifest and provides the
    /// end-entity certificate bound by the session key. This constructor is the
    /// context-aware entry point used by language bindings.
    pub fn from_shared_context(
        context: &Arc<Context>,
        manifest_json: impl Into<String>,
        signing_key: SigningKey,
        kid: impl Into<Vec<u8>>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<Self> {
        let manifest_signer = context.signer()?;
        Self::from_local_ed25519_parts(
            Arc::clone(context),
            manifest_json.into(),
            manifest_signer,
            signing_key,
            kid.into(),
            min_sequence_number,
            validity_period_secs,
        )
    }

    /// Creates a VSI signer backed by a generic synchronous session signer.
    ///
    /// The public COSE key is used to verify every callback result before any
    /// output or sequence state is committed. The `signerBinding` callback is
    /// deferred until [`sign_init_segment`](Self::sign_init_segment), allowing
    /// artifact recovery to proceed without requesting a throwaway signature.
    pub fn from_session_signer<S>(
        manifest_json: impl Into<String>,
        manifest_signer: &dyn Signer,
        config: VsiSessionConfig,
        session_signer: S,
    ) -> Result<Self>
    where
        S: VsiSessionSigner,
    {
        let context = Arc::new(super::context_from_thread_local_settings()?);
        Self::from_generic_parts(
            context,
            manifest_json.into(),
            manifest_signer,
            config,
            Arc::new(session_signer),
            false,
        )
    }

    /// Creates a generic VSI signer using an explicit shared SDK context.
    ///
    /// This is the context-aware entry point used by language bindings and
    /// non-exportable keystore integrations.
    pub fn from_shared_context_with_session_signer<S>(
        context: &Arc<Context>,
        manifest_json: impl Into<String>,
        config: VsiSessionConfig,
        session_signer: S,
    ) -> Result<Self>
    where
        S: VsiSessionSigner,
    {
        let manifest_signer = context.signer()?;
        Self::from_generic_parts(
            Arc::clone(context),
            manifest_json.into(),
            manifest_signer,
            config,
            Arc::new(session_signer),
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_local_ed25519_parts(
        context: Arc<Context>,
        manifest_json: String,
        manifest_signer: &dyn Signer,
        signing_key: SigningKey,
        kid: Vec<u8>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<Self> {
        let session_cose_key = build_ed25519_cose_key(&signing_key.verifying_key(), &kid);
        let config = VsiSessionConfig {
            algorithm: SigningAlg::Ed25519,
            kid,
            public_cose_key_cbor: c2pa_cbor::to_vec(&session_cose_key).map_err(|e| {
                Error::BadParam(format!("failed to encode local Ed25519 COSE_Key: {e}"))
            })?,
            min_sequence_number,
            created_at: chrono::Utc::now().to_rfc3339(),
            validity_period_secs,
        };
        Self::from_generic_parts(
            context,
            manifest_json,
            manifest_signer,
            config,
            Arc::new(LocalEd25519SessionSigner(signing_key)),
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_generic_parts(
        context: Arc<Context>,
        manifest_json: String,
        manifest_signer: &dyn Signer,
        config: VsiSessionConfig,
        session_signer: Arc<dyn VsiSessionSigner>,
        create_signer_binding: bool,
    ) -> Result<Self> {
        if !matches!(config.algorithm, SigningAlg::Ed25519 | SigningAlg::Es256) {
            return Err(Error::BadParam(
                "VSI session signing supports only Ed25519 and ES256".to_string(),
            ));
        }
        if config.kid.is_empty() {
            return Err(Error::BadParam(
                "VSI session key kid must not be empty".to_string(),
            ));
        }
        if config.validity_period_secs == 0 {
            return Err(Error::BadParam(
                "VSI session key validity period must be greater than zero".to_string(),
            ));
        }
        if config.min_sequence_number > u64::from(u32::MAX) {
            return Err(Error::BadParam(
                "VSI min sequence number must fit the BMFF mfhd sequence_number field".to_string(),
            ));
        }

        let created_at: chrono::DateTime<chrono::Utc> = config
            .created_at
            .parse()
            .map_err(|_| Error::BadParam("VSI session key createdAt is invalid".to_string()))?;
        let validity = i64::try_from(config.validity_period_secs)
            .map_err(|_| Error::BadParam("VSI session key validity period overflow".to_string()))?;
        created_at
            .timestamp()
            .checked_add(validity)
            .ok_or_else(|| {
                Error::BadParam("VSI session key validity window overflow".to_string())
            })?;

        let session_cose_key: c2pa_cbor::Value =
            c2pa_cbor::from_slice(&config.public_cose_key_cbor).map_err(|e| {
                Error::BadParam(format!("VSI public COSE_Key is not valid CBOR: {e}"))
            })?;
        if signing_alg_from_cose_key(&session_cose_key) != Some(config.algorithm) {
            return Err(Error::BadParam(
                "VSI algorithm does not agree with the public COSE_Key type, curve, and alg"
                    .to_string(),
            ));
        }
        if kid_from_cose_key(&session_cose_key).as_deref() != Some(config.kid.as_slice()) {
            return Err(Error::BadParam(
                "VSI kid does not agree with the public COSE_Key kid".to_string(),
            ));
        }
        let public_key_der = cose_key_to_der(&session_cose_key).ok_or_else(|| {
            Error::BadParam("VSI public COSE_Key has an unsupported key shape".to_string())
        })?;
        match config.algorithm {
            SigningAlg::Ed25519 => {
                ed25519_dalek::VerifyingKey::from_public_key_der(&public_key_der).map_err(|e| {
                    Error::BadParam(format!("VSI Ed25519 public COSE_Key is invalid: {e}"))
                })?;
            }
            SigningAlg::Es256 => {
                p256::PublicKey::from_public_key_der(&public_key_der).map_err(|e| {
                    Error::BadParam(format!("VSI P-256 public COSE_Key is invalid: {e}"))
                })?;
            }
            _ => unreachable!("algorithm checked above"),
        }

        let base_manifest_json = super::prepare_live_manifest_json(&manifest_json)?;

        let ee_cert_der = manifest_signer
            .certs()
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or_else(|| Error::BadParam("manifest signer has no certificates".into()))?;

        let mut signer = Self {
            context,
            session_signer,
            algorithm: config.algorithm,
            session_cose_key,
            kid: config.kid,
            signer_binding: None,
            manifest_signer_ee_cert_der: ee_cert_der,
            min_sequence_number: config.min_sequence_number,
            created_at: DateT(config.created_at),
            validity_period: config.validity_period_secs,
            next_sequence_number: config.min_sequence_number,
            next_event_id: 1,
            base_manifest_json,
            active_manifest_id: None,
            track_id: None,
            track_timescale: None,
            default_sample_duration: None,
        };
        if create_signer_binding {
            signer.ensure_signer_binding()?;
        }
        Ok(signer)
    }

    /// Signs an init segment, embedding a `c2pa.session-keys` assertion.
    ///
    /// Captures the manifest label from the signed output so that
    /// subsequent calls to [`sign_media_segment`] can embed it as `manifestId`
    /// per §19.4.
    ///
    /// Per §19.2.3, the init segment SHOULD NOT contain media data (`mdat`).
    ///
    /// [`sign_media_segment`]: LiveVideoVsiSigner::sign_media_segment
    pub fn sign_init_segment(
        &mut self,
        segment_data: &[u8],
        format: &str,
        manifest_signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let init_info = parse_init_segment(segment_data)?;
        let current_cert = manifest_signer
            .certs()
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or_else(|| Error::BadParam("manifest signer has no certificates".into()))?;
        if current_cert != self.manifest_signer_ee_cert_der {
            return Err(Error::BadParam(
                "initialization manifest signer does not match the certificate bound by the session key"
                    .to_string(),
            ));
        }
        self.ensure_signer_binding()?;
        let session_keys = self.build_session_keys_assertion()?;
        let mut builder = Builder::from_shared_context(&self.context)
            .with_definition(self.base_manifest_json.as_str())?;
        builder.add_assertion_cbor(SessionKeys::LABEL, &session_keys)?;

        let mut source = std::io::Cursor::new(segment_data);
        let mut dest = std::io::Cursor::new(Vec::new());
        builder.sign(manifest_signer, format, &mut source, &mut dest)?;
        let signed_bytes = dest.into_inner();

        let (manifest_id, session_key) =
            self.read_and_validate_init_manifest(&signed_bytes, format)?;
        self.validate_session_key_metadata(&session_key)?;
        self.active_manifest_id = Some(manifest_id);
        self.apply_session_key_metadata(&session_key);
        self.track_id = Some(init_info.track_id);
        self.track_timescale = Some(init_info.timescale);
        self.default_sample_duration = init_info.default_sample_duration;

        Ok(signed_bytes)
    }

    /// Signs an initialization segment with the signer configured on this signer's context.
    pub fn sign_init_segment_with_context(
        &mut self,
        segment_data: &[u8],
        format: &str,
    ) -> Result<Vec<u8>> {
        let context = Arc::clone(&self.context);
        self.sign_init_segment(segment_data, format, context.signer()?)
    }

    /// Signs a media segment by prepending a COSE_Sign1 `emsg` box.
    ///
    /// The COSE_Sign1 payload is a CBOR `SegmentInfoMap` with the current
    /// sequence number, a `bmffHash` covering the segment data excluding VSI
    /// `emsg` boxes, and the `manifestId` from the signed init segment per §19.4.
    pub fn sign_media_segment(&mut self, segment_data: &[u8]) -> Result<Vec<u8>> {
        let signing_time_unix_seconds = chrono::Utc::now().timestamp();
        self.sign_media_segment_at(segment_data, signing_time_unix_seconds)
    }

    /// Signs a media segment at an explicit Unix timestamp.
    ///
    /// `signing_time_unix_seconds` is encoded as the mandatory protected COSE
    /// `iat`, used for session-key validity checks, and included in the exact
    /// Sig_structure passed to a callback-backed session signer.
    pub fn sign_media_segment_at(
        &mut self,
        segment_data: &[u8],
        signing_time_unix_seconds: i64,
    ) -> Result<Vec<u8>> {
        if super::verifiable_segment_info::contains_c2pa_vsi_scheme(segment_data) {
            return Err(Error::BadParam(
                "media segment already contains a C2PA VSI emsg box".to_string(),
            ));
        }
        let manifest_id = self.active_manifest_id.clone().ok_or_else(|| {
            Error::BadParam(
                "a valid signed initialization segment must establish manifestId before media signing"
                    .to_string(),
            )
        })?;
        if !manifest_id.starts_with("urn:c2pa:") || manifest_id.len() == "urn:c2pa:".len() {
            return Err(Error::BadParam(
                "active live manifestId must be a non-empty urn:c2pa: identifier".to_string(),
            ));
        }
        let track_id = self.track_id.ok_or_else(|| {
            Error::BadParam(
                "a valid signed initialization segment must establish a media track before signing"
                    .to_string(),
            )
        })?;
        let timescale = self.track_timescale.ok_or_else(|| {
            Error::BadParam(
                "a valid signed initialization segment must establish a non-zero track timescale before signing"
                    .to_string(),
            )
        })?;
        let sequence_number = self.next_sequence_number;
        let media_info = parse_media_segment(segment_data, self.default_sample_duration)?;

        if u64::from(media_info.sequence_number) != sequence_number {
            return Err(Error::BadParam(format!(
                "VSI sequenceNumber ({sequence_number}) does not match the segment's own \
                 moof/mfhd.sequence_number ({}); the signer's sequence counter has drifted",
                media_info.sequence_number
            )));
        }
        if media_info.track_id != track_id {
            return Err(Error::BadParam(format!(
                "media segment tfhd track_ID ({}) does not match initialization track_ID ({track_id})",
                media_info.track_id
            )));
        }

        let event_duration = media_info.duration_ticks;
        let id = self.next_event_id;
        let next_event_id = id.checked_add(1).ok_or_else(|| {
            Error::BadParam("VSI emsg id cannot advance past u32::MAX".to_string())
        })?;
        let next_sequence_number = sequence_number.checked_add(1).ok_or_else(|| {
            Error::BadParam("VSI sequenceNumber cannot advance past u64::MAX".to_string())
        })?;
        let iat = signing_time_unix_seconds;
        self.ensure_key_valid_at(iat)?;

        // Two passes: the offset-prefix (§18.6.2) must reflect each box's absolute offset
        // in the final segment (emsg + segment_data), which requires knowing emsg's size
        // before its own contents (the hash) can be computed. Pass 1 hashes against a
        // same-size draft emsg (placeholder digest) to get real offsets; pass 2 rebuilds
        // emsg with the real hash, which only changes opaque digest/signature bytes, not
        // their lengths.
        let build_segment_info = |bmff_hash: c2pa_cbor::Value| -> SegmentInfoMap {
            SegmentInfoMap {
                sequence_number,
                bmff_hash,
                manifest_id: manifest_id.clone(),
                manifest_uri: None,
            }
        };

        // Pass 1 is sizing only. A fixed-size dummy digest and signature establish
        // final offsets without invoking the session private key.
        let draft_info = build_segment_info(build_segment_bmff_hash_placeholder()?);
        let draft_cose = build_vsi_cose_sign1_dummy(&draft_info, self.algorithm, &self.kid, iat)?;
        let draft_emsg_box = build_emsg_box(&draft_cose, timescale, event_duration, id)?;
        let mut draft_segment = draft_emsg_box.clone();
        draft_segment.extend_from_slice(segment_data);
        let bmff_hash = build_segment_bmff_hash(&draft_segment)?;

        // Pass 2 performs the only real session signature for this media segment.
        let final_info = build_segment_info(bmff_hash);
        let cose_sign1_bytes = build_vsi_cose_sign1(
            &final_info,
            self.algorithm,
            self.session_signer.as_ref(),
            &self.session_cose_key,
            &self.kid,
            iat,
        )?;
        let emsg_box = build_emsg_box(&cose_sign1_bytes, timescale, event_duration, id)?;
        if draft_emsg_box.len() != emsg_box.len() {
            return Err(Error::BadParam(
                "draft and final VSI emsg boxes differ in size; the c2pa.hash.bmff.v3 \
                 offset-prefix scheme would be computed against the wrong box offsets"
                    .to_string(),
            ));
        }

        let mut signed_segment = emsg_box;
        signed_segment.extend_from_slice(segment_data);

        self.next_sequence_number = next_sequence_number;
        self.next_event_id = next_event_id;
        Ok(signed_segment)
    }

    /// Returns the sequence number assigned to the next media segment.
    pub fn next_sequence_number(&self) -> u64 {
        self.next_sequence_number
    }

    /// Returns the active initialization manifest's C2PA URN, if established.
    pub fn active_manifest_id(&self) -> Option<&str> {
        self.active_manifest_id.as_deref()
    }

    /// Restores the active manifest ID from a previously signed init segment.
    ///
    /// Used when resuming a live session across process invocations.  Re-signing
    /// the init would produce a different UUID, breaking `manifestId` continuity
    /// across segments.  Instead, call this method with the already-signed init
    /// from the output directory to restore the session's `manifestId`.
    ///
    /// This init-only method is safe only before any media segment from the
    /// session has been published. It restores no media counters, so signing
    /// directly after a post-publication init-only restore can reuse a sequence.
    /// Durable resume callers must use [`recover_from_artifacts`] with the last
    /// committed media segment, or call [`resume_from_segment`] before signing.
    pub fn restore_manifest_id_from_signed_init(
        &mut self,
        signed_init_data: &[u8],
        format: &str,
    ) -> Result<()> {
        let restored = self.validate_signed_init_state(signed_init_data, format)?;
        self.apply_restored_init_state(restored, true);
        Ok(())
    }

    /// Atomically recovers session state from signed publication artifacts.
    ///
    /// The signed initialization segment is always validated. When supplied,
    /// `previous_segment` must be the complete last published VSI media segment;
    /// its signature, hash, manifest, track, timing, and counters are validated
    /// before any recovered state is accepted. Recovery never invokes the
    /// session signing callback.
    ///
    /// Omitting `previous_segment` is valid only when no media segment from this
    /// session has ever been published. It restores the initial sequence and
    /// event counters; using it after publication would permit sequence reuse.
    /// Durable callers must therefore supply their last committed media artifact
    /// or refuse recovery when publication state is unknown.
    pub fn recover_from_artifacts(
        &mut self,
        signed_init_data: &[u8],
        previous_segment: Option<&[u8]>,
        format: &str,
    ) -> Result<()> {
        let restored = self.validate_signed_init_state(signed_init_data, format)?;
        let counters = previous_segment
            .map(|segment| self.validate_resumed_segment(segment, &restored))
            .transpose()?
            .unwrap_or((restored.session_key.min_sequence_number, 1));

        self.apply_restored_init_state(restored, true);
        self.next_sequence_number = counters.0;
        self.next_event_id = counters.1;
        Ok(())
    }

    /// Resumes from a previously signed VSI segment.
    ///
    /// Extracts the `sequenceNumber` from the segment's `emsg` box and sets
    /// `next_sequence_number` to `sequenceNumber + 1` after validating it against the configured
    /// session. Call [`restore_manifest_id_from_signed_init`] first so the init-derived manifest,
    /// track, timescale, and default sample duration are available for validation.
    ///
    /// [`restore_manifest_id_from_signed_init`]: LiveVideoVsiSigner::restore_manifest_id_from_signed_init
    pub fn resume_from_segment(&mut self, segment_data: &[u8]) -> Result<()> {
        let restored = RestoredInitState {
            manifest_id: self.active_manifest_id.clone().ok_or_else(|| {
                Error::BadParam(
                    "restore_manifest_id_from_signed_init must be called before resume_from_segment"
                        .to_string(),
                )
            })?,
            session_key: SessionKey {
                key: self.session_cose_key.clone(),
                min_sequence_number: self.min_sequence_number,
                created_at: self.created_at.clone(),
                validity_period: self.validity_period,
                signer_binding: self.signer_binding.clone().ok_or_else(|| {
                    Error::BadParam(
                        "restore_manifest_id_from_signed_init must establish signerBinding before resume_from_segment"
                            .to_string(),
                    )
                })?,
            },
            init_info: InitSegmentInfo {
                track_id: self.track_id.ok_or_else(|| {
                    Error::BadParam("restored initialization track is missing".to_string())
                })?,
                timescale: self.track_timescale.ok_or_else(|| {
                    Error::BadParam("restored initialization timescale is missing".to_string())
                })?,
                default_sample_duration: self.default_sample_duration,
            },
        };
        let (next_sequence_number, next_event_id) =
            self.validate_resumed_segment(segment_data, &restored)?;
        self.next_sequence_number = next_sequence_number;
        self.next_event_id = next_event_id;
        Ok(())
    }

    fn validate_resumed_segment(
        &self,
        segment_data: &[u8],
        restored: &RestoredInitState,
    ) -> Result<(u64, u32)> {
        use crate::live_video::verifiable_segment_info::parse_vsi;

        let event = super::verifiable_segment_info::extract_vsi_emsg_from_segment(segment_data)?
            .ok_or_else(|| {
                Error::BadParam("previous segment does not contain a VSI emsg box".into())
            })?;

        let parsed = parse_vsi(&event.message_data)?;
        let media_info =
            parse_media_segment(segment_data, restored.init_info.default_sample_duration)?;
        if parsed.segment_info_map.sequence_number != u64::from(media_info.sequence_number) {
            return Err(Error::BadParam(
                "resumed VSI sequenceNumber does not match moof/mfhd.sequence_number".to_string(),
            ));
        }
        if parsed.sign1.unprotected.key_id != self.kid {
            return Err(Error::BadParam(
                "resumed VSI kid does not match the configured session key".to_string(),
            ));
        }
        if parsed.segment_info_map.manifest_id != restored.manifest_id {
            return Err(Error::BadParam(
                "resumed VSI manifestId does not match the restored initialization manifest"
                    .to_string(),
            ));
        }
        if restored.init_info.track_id != media_info.track_id {
            return Err(Error::BadParam(
                "resumed VSI media track does not match the restored initialization track"
                    .to_string(),
            ));
        }
        if parsed.segment_info_map.sequence_number < restored.session_key.min_sequence_number {
            return Err(Error::BadParam(
                "resumed VSI sequenceNumber is below the session key minSequenceNumber".to_string(),
            ));
        }
        let expected_event_id = parsed
            .segment_info_map
            .sequence_number
            .checked_sub(restored.session_key.min_sequence_number)
            .and_then(|offset| offset.checked_add(1))
            .and_then(|id| u32::try_from(id).ok())
            .ok_or_else(|| {
                Error::BadParam(
                    "resumed VSI sequenceNumber cannot map to a valid emsg id".to_string(),
                )
            })?;
        if event.presentation_time_delta != 0
            || restored.init_info.timescale != event.timescale
            || event.event_duration != media_info.duration_ticks
            || event.id != expected_event_id
        {
            return Err(Error::BadParam(
                "resumed VSI emsg timing or id does not match the restored init, sequence, and media segment"
                    .to_string(),
            ));
        }
        let tbs = parsed.sign1.tbs_data(b"");
        super::session_key_validation::verify_cose_sign1_signature(
            &parsed.sign1,
            &self.session_cose_key,
            &tbs,
        )
        .map_err(|e| Error::BadParam(format!("resumed VSI signature is invalid: {e}")))?;
        let resumed_iat = protected_iat(&parsed.sign1)?;
        ensure_key_valid_at(
            &restored.session_key.created_at,
            restored.session_key.validity_period,
            resumed_iat,
        )?;
        verify_segment_bmff_hash(segment_data, &parsed.segment_info_map.bmff_hash)?;
        let next_sequence_number = parsed
            .segment_info_map
            .sequence_number
            .checked_add(1)
            .ok_or_else(|| Error::BadParam("resumed VSI sequenceNumber overflow".to_string()))?;
        let next_event_id = event
            .id
            .checked_add(1)
            .ok_or_else(|| Error::BadParam("resumed VSI emsg id overflow".to_string()))?;
        Ok((next_sequence_number, next_event_id))
    }

    fn validate_signed_init_state(
        &self,
        signed_init_data: &[u8],
        format: &str,
    ) -> Result<RestoredInitState> {
        let init_info = parse_init_segment(signed_init_data)?;
        let (manifest_id, session_key) =
            self.read_and_validate_init_manifest(signed_init_data, format)?;
        self.validate_session_key_metadata(&session_key)?;
        Ok(RestoredInitState {
            manifest_id,
            session_key,
            init_info,
        })
    }

    fn apply_restored_init_state(&mut self, restored: RestoredInitState, reset_sequence: bool) {
        self.active_manifest_id = Some(restored.manifest_id);
        self.apply_session_key_metadata(&restored.session_key);
        self.track_id = Some(restored.init_info.track_id);
        self.track_timescale = Some(restored.init_info.timescale);
        self.default_sample_duration = restored.init_info.default_sample_duration;
        if reset_sequence {
            self.next_sequence_number = restored.session_key.min_sequence_number;
            self.next_event_id = 1;
        }
    }

    /// Reads back `signed_data`'s active manifest and, if it has a label, stores it as
    /// `active_manifest_id` (its c2pa URN label per §8.1). Used after signing an init segment
    /// and when restoring state from a previously-signed one.
    fn read_and_validate_init_manifest(
        &self,
        signed_data: &[u8],
        format: &str,
    ) -> Result<(String, SessionKey)> {
        let reader = Reader::from_shared_context(&self.context)
            .with_stream(format, std::io::Cursor::new(signed_data))?;
        if let Some(status) = reader.validation_status().and_then(|statuses| {
            statuses.iter().find(|status| {
                !status.passed() && super::is_manifest_integrity_failure(status.code())
            })
        }) {
            return Err(Error::BadParam(format!(
                "signed initialization manifest failed integrity validation: {}",
                status.code()
            )));
        }

        let manifest = reader.active_manifest().ok_or_else(|| {
            Error::BadParam("signed initialization segment has no active manifest".to_string())
        })?;
        let label = manifest.label().ok_or_else(|| {
            Error::BadParam("signed initialization manifest has no label".to_string())
        })?;
        if !label.starts_with("urn:c2pa:") || label.len() == "urn:c2pa:".len() {
            return Err(Error::BadParam(
                "signed initialization manifest label must be a non-empty urn:c2pa: identifier"
                    .to_string(),
            ));
        }

        let session_keys: SessionKeys =
            manifest.find_assertion(SessionKeys::LABEL).map_err(|_| {
                Error::BadParam(
                    "signed initialization manifest has no c2pa.session-keys assertion".to_string(),
                )
            })?;
        if session_keys.keys.len() != 1 {
            return Err(Error::BadParam(
                "Milestone 1 signed initialization manifest must contain exactly one session key"
                    .to_string(),
            ));
        }
        let session_key = session_keys.keys.into_iter().next().ok_or_else(|| {
            Error::BadParam("signed initialization manifest has no session key".to_string())
        })?;
        let signed_key = &session_key.key;
        if kid_from_cose_key(signed_key).as_deref() != Some(self.kid.as_slice())
            || signing_alg_from_cose_key(signed_key) != Some(self.algorithm)
            || cose_key_to_der(signed_key) != cose_key_to_der(&self.session_cose_key)
        {
            return Err(Error::BadParam(
                "signed initialization session kid, algorithm, or public key does not match the configured session key"
                    .to_string(),
            ));
        }

        let signature_info = manifest.signature_info().ok_or_else(|| {
            Error::BadParam("signed initialization manifest has no signature info".to_string())
        })?;
        let certs = pem::parse_many(signature_info.cert_chain()).map_err(|e| {
            Error::BadParam(format!(
                "signed initialization certificate chain is invalid: {e}"
            ))
        })?;
        let ee_cert_der = certs
            .into_iter()
            .next()
            .map(pem::Pem::into_contents)
            .ok_or_else(|| {
                Error::BadParam(
                    "signed initialization manifest has no end-entity certificate".to_string(),
                )
            })?;
        if ee_cert_der != self.manifest_signer_ee_cert_der {
            return Err(Error::BadParam(
                "restored initialization manifest signer does not match the configured claim signer"
                    .to_string(),
            ));
        }
        self.verify_restored_signer_binding(&session_key, &ee_cert_der)?;
        self.validate_session_key_metadata(&session_key)?;

        Ok((label.to_string(), session_key))
    }

    fn validate_session_key_metadata(&self, session_key: &SessionKey) -> Result<()> {
        if session_key.validity_period == 0 {
            return Err(Error::BadParam(
                "signed initialization session key has zero validityPeriod".to_string(),
            ));
        }
        if session_key.min_sequence_number > u64::from(u32::MAX) {
            return Err(Error::BadParam(
                "signed initialization minSequenceNumber does not fit mfhd".to_string(),
            ));
        }
        let created_at: chrono::DateTime<chrono::Utc> = session_key
            .created_at
            .0
            .parse()
            .map_err(|_| Error::BadParam("session key createdAt is invalid".to_string()))?;
        let validity = i64::try_from(session_key.validity_period)
            .map_err(|_| Error::BadParam("session key validityPeriod overflow".to_string()))?;
        created_at
            .timestamp()
            .checked_add(validity)
            .ok_or_else(|| Error::BadParam("session key validity window overflow".to_string()))?;
        Ok(())
    }

    fn apply_session_key_metadata(&mut self, session_key: &SessionKey) {
        self.min_sequence_number = session_key.min_sequence_number;
        self.created_at = session_key.created_at.clone();
        self.validity_period = session_key.validity_period;
        self.signer_binding = Some(session_key.signer_binding.clone());
        if self.next_sequence_number < self.min_sequence_number {
            self.next_sequence_number = self.min_sequence_number;
        }
    }

    fn verify_restored_signer_binding(
        &self,
        session_key: &SessionKey,
        ee_cert_der: &[u8],
    ) -> Result<()> {
        let binding_bytes = super::session_key_validation::extract_signer_binding_bytes(
            &session_key.signer_binding,
        )
        .ok_or_else(|| Error::BadParam("session key signerBinding is malformed".to_string()))?;
        let sign1 = coset::CoseSign1::from_tagged_slice(&binding_bytes)
            .map_err(|e| Error::BadParam(format!("invalid signerBinding COSE_Sign1: {e}")))?;
        if sign1.payload.is_some() {
            return Err(Error::BadParam(
                "signerBinding payload must be detached".to_string(),
            ));
        }
        let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
            .map_err(|e| {
                Error::BadParam(format!("failed to encode signerBinding certificate: {e}"))
            })?;
        let tbs = sign1.tbs_detached_data(&external_payload, b"");
        super::session_key_validation::verify_cose_sign1_signature(
            &sign1,
            &self.session_cose_key,
            &tbs,
        )
        .map_err(|e| Error::BadParam(format!("signerBinding verification failed: {e}")))
    }

    fn ensure_key_valid_at(&self, unix_seconds: i64) -> Result<()> {
        ensure_key_valid_at(&self.created_at, self.validity_period, unix_seconds)
    }

    fn ensure_signer_binding(&mut self) -> Result<()> {
        if self.signer_binding.is_none() {
            self.signer_binding = Some(build_signer_binding(
                &self.manifest_signer_ee_cert_der,
                self.algorithm,
                self.session_signer.as_ref(),
                &self.session_cose_key,
            )?);
        }
        Ok(())
    }

    fn build_session_keys_assertion(&self) -> Result<SessionKeys> {
        let signer_binding = self.signer_binding.clone().ok_or_else(|| {
            Error::BadParam("VSI signerBinding has not been established".to_string())
        })?;
        Ok(SessionKeys {
            keys: vec![SessionKey {
                key: self.session_cose_key.clone(),
                min_sequence_number: self.min_sequence_number,
                created_at: self.created_at.clone(),
                validity_period: self.validity_period,
                signer_binding,
            }],
        })
    }
}

fn ensure_key_valid_at(created_at: &DateT, validity_period: u64, unix_seconds: i64) -> Result<()> {
    use chrono::{DateTime, TimeZone};

    chrono::Utc
        .timestamp_opt(unix_seconds, 0)
        .single()
        .ok_or_else(|| {
            Error::BadParam("VSI signing time is outside the supported range".to_string())
        })?;

    let created_at: DateTime<chrono::Utc> = created_at.0.parse().map_err(|_| {
        Error::BadParam("session key createdAt is not a valid RFC 3339 datetime".to_string())
    })?;
    let validity = i64::try_from(validity_period)
        .map_err(|_| Error::BadParam("session key validityPeriod overflow".to_string()))?;
    let created_at = created_at.timestamp();
    let expires_at = created_at
        .checked_add(validity)
        .ok_or_else(|| Error::BadParam("session key validity window overflow".to_string()))?;
    if unix_seconds < created_at || unix_seconds > expires_at {
        return Err(Error::BadParam(
            "session key is outside its published validity period".to_string(),
        ));
    }
    Ok(())
}

// ── BMFF hash helper ─────────────────────────────────────────────────────────

fn vsi_emsg_exclusion() -> ExclusionsMap {
    let mut exclusion = ExclusionsMap::new("/emsg".to_string());
    exclusion.data = Some(vec![DataMap {
        offset: VSI_URI_OFFSET_IN_EMSG,
        value: VSI_SCHEME_ID_URI.as_bytes().to_vec(),
    }]);
    exclusion
}

/// A `bmff-hash-map` scoped to exclude the VSI `emsg` box, per §19.4.1. Defaults to
/// `bmff_version` 3, which per §18.6.2 hashes each included root box as `offset || data`
/// (8-byte big-endian file offset prefix).
fn new_vsi_bmff_hash() -> BmffHash {
    let mut bmff_hash = BmffHash::new("jumbf manifest", "sha256", None);
    bmff_hash.add_exclusions(&mut vec![vsi_emsg_exclusion()]);
    bmff_hash
}

/// A same-shape `bmff-hash-map` with a zero-filled placeholder digest, used to size
/// the draft `emsg` box in [`LiveVideoVsiSigner::sign_media_segment`]'s first pass.
pub(super) fn build_segment_bmff_hash_placeholder() -> Result<c2pa_cbor::Value> {
    let mut bmff_hash = new_vsi_bmff_hash();
    bmff_hash.set_hash(vec![0u8; 32]); // sha256 digest size; value is irrelevant, only length matters
    c2pa_cbor::value::to_value(&bmff_hash)
        .map_err(|e| Error::BadParam(format!("failed to serialize placeholder bmffHash: {e}")))
}

/// Computes the `bmff-hash-map` for a media segment per §19.4.1.
///
/// `full_segment` must be the complete bytes that will be delivered — i.e. the
/// (draft or real) `emsg` box followed by the raw segment data — so that the
/// `c2pa.hash.bmff.v3` offset-prefix (§18.6.2) reflects each box's real final
/// position. The hash excludes the VSI `emsg` box itself, identified by its
/// `scheme_id_uri` field ("urn:c2pa:verifiable-segment-info").
pub(super) fn build_segment_bmff_hash(full_segment: &[u8]) -> Result<c2pa_cbor::Value> {
    let mut bmff_hash = new_vsi_bmff_hash();

    let mut cursor = std::io::Cursor::new(full_segment);
    bmff_hash
        .gen_hash_from_stream(&mut cursor)
        .map_err(|e| Error::BadParam(format!("failed to compute segment bmffHash: {e}")))?;

    c2pa_cbor::value::to_value(&bmff_hash)
        .map_err(|e| Error::BadParam(format!("failed to serialize bmffHash to CBOR: {e}")))
}

fn verify_segment_bmff_hash(full_segment: &[u8], bmff_hash_value: &c2pa_cbor::Value) -> Result<()> {
    let mut bmff_hash: BmffHash = c2pa_cbor::value::from_value(bmff_hash_value.clone())
        .map_err(|e| Error::BadParam(format!("invalid resumed VSI bmffHash: {e}")))?;
    if bmff_hash.merkle().is_some() {
        return Err(Error::BadParam(
            "resumed VSI bmffHash must not contain a merkle field".to_string(),
        ));
    }
    let has_vsi_exclusion = bmff_hash.exclusions().iter().any(|exclusion| {
        exclusion.xpath == "/emsg"
            && exclusion.data.as_deref().is_some_and(|data| {
                data.iter().any(|entry| {
                    entry.offset == VSI_URI_OFFSET_IN_EMSG
                        && entry.value == VSI_SCHEME_ID_URI.as_bytes()
                })
            })
    });
    if !has_vsi_exclusion {
        return Err(Error::BadParam(
            "resumed VSI bmffHash lacks the required C2PA emsg exclusion".to_string(),
        ));
    }
    bmff_hash.set_bmff_version(3);
    bmff_hash
        .verify_in_memory_hash(full_segment, None)
        .map_err(|e| Error::BadParam(format!("resumed VSI bmffHash verification failed: {e}")))
}

// ── Signer binding (§18.25.2) ────────────────────────────────────────────────
//
// Per the spec the `signerBinding` is a **detached** COSE_Sign1 where:
//   - the **session key** signs,
//   - the **payload** is the signer's end-entity certificate encoded as a CBOR
//     byte string (used in Sig_structure but NOT carried in the COSE_Sign1).

fn build_signer_binding(
    ee_cert_der: &[u8],
    algorithm: SigningAlg,
    session_signer: &dyn VsiSessionSigner,
    session_cose_key: &c2pa_cbor::Value,
) -> Result<c2pa_cbor::Value> {
    let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
        .map_err(|e| Error::BadParam(format!("failed to CBOR-encode EE certificate: {e}")))?;

    let protected = HeaderBuilder::new()
        .algorithm(cose_algorithm(algorithm)?)
        .build();

    let mut sign1 = CoseSign1Builder::new().protected(protected).build();

    // signerBinding is a detached-payload COSE_Sign1: the cert bytes are the
    // external payload, not AAD. Use tbs_detached_data per RFC 9052 §4.4.
    let tbs = sign1.tbs_detached_data(&external_payload, b"");
    sign1.signature = session_signer.sign(VsiSigningPurpose::SignerBinding, &tbs)?;
    validate_callback_signature(algorithm, &sign1.signature)?;
    super::session_key_validation::verify_cose_sign1_signature(&sign1, session_cose_key, &tbs)
        .map_err(|e| {
            Error::BadParam(format!(
                "VSI signerBinding callback signature is invalid: {e}"
            ))
        })?;

    let binding_bytes = sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode signer binding: {e}")))?;

    // Deserialize back to a Value so the COSE_Sign1 is embedded as a tagged
    // CBOR structure (tag 18) rather than an opaque bstr.
    c2pa_cbor::from_slice(&binding_bytes).map_err(|e| {
        Error::BadParam(format!(
            "failed to decode signer binding as CBOR Value: {e}"
        ))
    })
}

// ── VSI COSE_Sign1 construction ──────────────────────────────────────────────

fn build_vsi_cose_sign1(
    segment_info_map: &SegmentInfoMap,
    algorithm: SigningAlg,
    session_signer: &dyn VsiSessionSigner,
    session_cose_key: &c2pa_cbor::Value,
    kid: &[u8],
    iat: i64,
) -> Result<Vec<u8>> {
    let mut sign1 = build_vsi_cose_sign1_unsigned(segment_info_map, algorithm, kid, iat)?;
    let tbs = sign1.tbs_data(b"");
    sign1.signature = session_signer.sign(
        VsiSigningPurpose::Vsi {
            sequence_number: segment_info_map.sequence_number,
        },
        &tbs,
    )?;
    validate_callback_signature(algorithm, &sign1.signature)?;
    super::session_key_validation::verify_cose_sign1_signature(&sign1, session_cose_key, &tbs)
        .map_err(|e| Error::BadParam(format!("VSI callback signature is invalid: {e}")))?;

    sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode COSE_Sign1: {e}")))
}

fn build_vsi_cose_sign1_dummy(
    segment_info_map: &SegmentInfoMap,
    algorithm: SigningAlg,
    kid: &[u8],
    iat: i64,
) -> Result<Vec<u8>> {
    let mut sign1 = build_vsi_cose_sign1_unsigned(segment_info_map, algorithm, kid, iat)?;
    sign1.signature = vec![0; 64];
    sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode dummy COSE_Sign1: {e}")))
}

fn build_vsi_cose_sign1_unsigned(
    segment_info_map: &SegmentInfoMap,
    algorithm: SigningAlg,
    kid: &[u8],
    iat: i64,
) -> Result<coset::CoseSign1> {
    let payload = c2pa_cbor::to_vec(segment_info_map)
        .map_err(|e| Error::BadParam(format!("failed to encode SegmentInfoMap: {e}")))?;

    // The live-video profile requires a protected `iat` field: a `NumericDate` (RFC 8392)
    // giving the "claimed time of signing". It lets a validator check the segment
    // against the session key's validity period using this claimed time rather than its own
    // wall-clock time, which matters for any validation run after the fact (e.g. archival/VOD
    // validation of a recording), since the key's validity window is anchored to createdAt.
    let protected = HeaderBuilder::new()
        .algorithm(cose_algorithm(algorithm)?)
        .text_value("iat".to_string(), coset::cbor::value::Value::from(iat))
        .build();
    let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();

    Ok(CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .build())
}

fn cose_algorithm(algorithm: SigningAlg) -> Result<iana::Algorithm> {
    match algorithm {
        SigningAlg::Ed25519 => Ok(iana::Algorithm::EdDSA),
        SigningAlg::Es256 => Ok(iana::Algorithm::ES256),
        _ => Err(Error::BadParam(
            "VSI session signing supports only Ed25519 and ES256".to_string(),
        )),
    }
}

fn validate_callback_signature(algorithm: SigningAlg, signature: &[u8]) -> Result<()> {
    if signature.len() != 64 {
        let format = if algorithm == SigningAlg::Es256 {
            "64-byte P1363 r||s"
        } else {
            "64 raw bytes"
        };
        return Err(Error::BadParam(format!(
            "VSI {algorithm:?} callback must return exactly {format}, got {} bytes",
            signature.len()
        )));
    }
    Ok(())
}

fn protected_iat(sign1: &coset::CoseSign1) -> Result<i64> {
    let mut values = sign1
        .protected
        .header
        .rest
        .iter()
        .filter(|(label, _)| matches!(label, coset::Label::Text(name) if name == "iat"));
    let Some((_, value)) = values.next() else {
        return Err(Error::BadParam(
            "VSI COSE_Sign1 protected header must contain iat".to_string(),
        ));
    };
    if values.next().is_some() {
        return Err(Error::BadParam(
            "VSI COSE_Sign1 protected header contains duplicate iat values".to_string(),
        ));
    }
    let integer = value.as_integer().ok_or_else(|| {
        Error::BadParam("VSI COSE_Sign1 protected iat must be an integer NumericDate".to_string())
    })?;
    i64::try_from(integer)
        .map_err(|_| Error::BadParam("VSI COSE_Sign1 protected iat is out of range".to_string()))
}

// ── emsg box construction ────────────────────────────────────────────────────

/// Builds a `emsg` v0 box carrying the VSI COSE_Sign1.
///
/// Per §19.4.2: `timescale` and `event_duration` shall cover the whole
/// segment, and `id` shall be a session-unique value.
fn build_emsg_box(
    cose_sign1_bytes: &[u8],
    timescale: u32,
    event_duration: u32,
    id: u32,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(VSI_SCHEME_ID_URI.as_bytes());
    body.push(0); // null terminator
    body.extend_from_slice(VSI_VALUE_FSEG.as_bytes());
    body.push(0); // null terminator
    body.extend_from_slice(&timescale.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // presentation_time_delta, shall be 0
    body.extend_from_slice(&event_duration.to_be_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(cose_sign1_bytes);

    // 8 bytes header + 4 bytes version/flags + body
    let total_size = u32::try_from(
        12usize
            .checked_add(body.len())
            .ok_or_else(|| Error::BadParam("VSI emsg size overflow".to_string()))?,
    )
    .map_err(|_| Error::BadParam("VSI emsg is too large for a 32-bit BMFF box".to_string()))?
    .to_be_bytes();

    let mut emsg = Vec::new();
    emsg.extend_from_slice(&total_size);
    emsg.extend_from_slice(b"emsg");
    emsg.push(0); // version 0
    emsg.extend_from_slice(&[0u8; 3]); // flags
    emsg.extend_from_slice(&body);
    Ok(emsg)
}

/// Parses `moof/mfhd`'s `sequence_number` field from a media segment, per ISO/IEC 14496-12
/// §8.8.5. Used to cross-check the signer's own sequence counter (§19.4.1).
///
/// Public so callers can infer a VSI session's starting `minSequenceNumber` from a live
/// stream's first segment, rather than assuming the packager starts at 1 (it commonly
/// doesn't). Returns `None` when the Milestone 1 single-track media layout is not satisfied,
/// including missing, duplicate, malformed, or truncated `moof`, `mfhd`, or `traf` boxes.
pub fn moof_sequence_number(segment_data: &[u8]) -> Option<u32> {
    super::bmff::moof_sequence_number(segment_data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::Mutex;

    use super::*;
    use crate::{
        dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
        live_video::{
            verifiable_segment_info::extract_vsi_payload_from_segment, LiveVideoValidator,
        },
        status_tracker::StatusTracker,
        utils::ephemeral_signer::EphemeralSigner,
    };

    fn make_test_segment(sequence_number: u32) -> Vec<u8> {
        make_test_media_segment_with_moof(sequence_number, &[1000])
    }

    fn make_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        b.extend_from_slice(fourcc);
        b.extend_from_slice(payload);
        b
    }

    fn make_fullbox(fourcc: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(version);
        body.extend_from_slice(&flags.to_be_bytes()[1..]);
        body.extend_from_slice(payload);
        make_box(fourcc, &body)
    }

    fn make_test_init_segment(timescale: u32) -> Vec<u8> {
        let mut tkhd_payload = Vec::new();
        tkhd_payload.extend_from_slice(&0u32.to_be_bytes()); // creation_time
        tkhd_payload.extend_from_slice(&0u32.to_be_bytes()); // modification_time
        tkhd_payload.extend_from_slice(&1u32.to_be_bytes()); // track_ID
        let tkhd = make_fullbox(b"tkhd", 0, 0, &tkhd_payload);

        let mut mdhd_payload = Vec::new();
        mdhd_payload.extend_from_slice(&0u32.to_be_bytes()); // creation_time
        mdhd_payload.extend_from_slice(&0u32.to_be_bytes()); // modification_time
        mdhd_payload.extend_from_slice(&timescale.to_be_bytes());
        mdhd_payload.extend_from_slice(&0u32.to_be_bytes()); // duration
        mdhd_payload.extend_from_slice(&0u16.to_be_bytes()); // language
        mdhd_payload.extend_from_slice(&0u16.to_be_bytes()); // pre_defined
        let mdhd = make_fullbox(b"mdhd", 0, 0, &mdhd_payload);
        let mdia = make_box(b"mdia", &mdhd);
        let trak = make_box(b"trak", &[tkhd, mdia].concat());
        make_box(b"moov", &trak)
    }

    /// Builds a `moof/traf/tfhd+trun` segment with the given per-sample
    /// durations (`trun`'s sample-duration-present flag set), plus a trailing
    /// `mdat`.
    fn make_test_media_segment_with_moof(
        sequence_number: u32,
        sample_durations: &[u32],
    ) -> Vec<u8> {
        let mfhd = make_fullbox(b"mfhd", 0, 0, &sequence_number.to_be_bytes());
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&1u32.to_be_bytes()); // track_ID
        let tfhd = make_fullbox(b"tfhd", 0, 0, &tfhd_payload);

        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&(sample_durations.len() as u32).to_be_bytes());
        for d in sample_durations {
            trun_payload.extend_from_slice(&d.to_be_bytes());
        }
        let trun = make_fullbox(b"trun", 0, 0x000100, &trun_payload); // sample-duration-present

        let traf = make_box(b"traf", &[tfhd, trun].concat());
        let moof = make_box(b"moof", &[mfhd, traf].concat());
        let mdat = make_box(b"mdat", &[0u8; 4]);
        [moof, mdat].concat()
    }

    #[test]
    fn parses_mdhd_timescale_from_init_segment() {
        let init = make_test_init_segment(48_000);
        assert_eq!(parse_init_segment(&init).unwrap().timescale, 48_000);
    }

    #[test]
    fn parses_moof_duration_from_trun_sample_durations() {
        let seg = make_test_media_segment_with_moof(1, &[1000, 1000, 1000]);
        assert_eq!(
            parse_media_segment(&seg, None).unwrap().duration_ticks,
            3000
        );
    }

    #[test]
    fn falls_back_to_tfhd_default_sample_duration_when_trun_omits_durations() {
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&1u32.to_be_bytes()); // track_ID
        tfhd_payload.extend_from_slice(&2000u32.to_be_bytes()); // default_sample_duration
        let tfhd = make_fullbox(b"tfhd", 0, 0x000008, &tfhd_payload); // default-sample-duration-present

        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&4u32.to_be_bytes()); // sample_count, no per-sample durations
        let trun = make_fullbox(b"trun", 0, 0, &trun_payload);

        let traf = make_box(b"traf", &[tfhd, trun].concat());
        let mfhd = make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes());
        let moof = make_box(b"moof", &[mfhd, traf].concat());

        assert_eq!(
            parse_media_segment(&moof, None).unwrap().duration_ticks,
            8000
        );
    }

    #[test]
    fn parsers_reject_segments_without_the_relevant_boxes() {
        let plain_segment = make_box(b"mdat", &[]);
        assert!(parse_init_segment(&plain_segment).is_err());
        assert!(parse_media_segment(&plain_segment, None).is_err());
    }

    #[test]
    fn signed_segments_have_real_emsg_timing_fields() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);
        let seg1 = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_moof(1, &[1000, 1000]))
            .unwrap();
        let seg2 = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_moof(2, &[1000, 1000]))
            .unwrap();

        let (timescale1, duration1, id1) = read_emsg_timing_fields(&seg1);
        let (timescale2, duration2, id2) = read_emsg_timing_fields(&seg2);

        assert_eq!(
            timescale1, 48_000,
            "emsg timescale must reflect the track's mdhd timescale"
        );
        assert_eq!(timescale2, 48_000);
        assert_eq!(
            duration1, 2000,
            "emsg event_duration must cover the whole segment"
        );
        assert_eq!(duration2, 2000);
        assert_ne!(
            id1, 0,
            "emsg id must not be the spec-prohibited placeholder 0"
        );
        assert_ne!(id2, 0);
        assert_ne!(id1, id2, "emsg id must be session-unique across segments");
    }

    fn make_test_media_segment_with_mfhd(sequence_number: u32) -> Vec<u8> {
        make_test_media_segment_with_moof(sequence_number, &[1000])
    }

    /// Regression test: per §19.4.1, sequenceNumber must match the segment's own
    /// `moof/mfhd.sequence_number` when present. If the signer's internal counter has
    /// drifted from the segment actually being signed (e.g. a skipped/reordered segment),
    /// signing must fail loudly rather than silently embed a mismatched sequenceNumber.
    #[test]
    fn sign_media_segment_rejects_mfhd_sequence_number_mismatch() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1); // starts at sequenceNumber 1

        let err = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_mfhd(5))
            .unwrap_err();
        assert!(
            format!("{err}").contains("sequenceNumber"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sign_media_segment_accepts_matching_mfhd_sequence_number() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1); // starts at sequenceNumber 1

        vsi_signer
            .sign_media_segment(&make_test_media_segment_with_mfhd(1))
            .unwrap();
    }

    /// Test-only: reads back `(timescale, event_duration, id)` from a signed
    /// segment's `emsg` box, to assert on what [`build_emsg_box`] actually wrote.
    fn read_emsg_timing_fields(signed_segment: &[u8]) -> (u32, u32, u32) {
        assert_eq!(&signed_segment[4..8], b"emsg");
        let emsg_size = u32::from_be_bytes(signed_segment[..4].try_into().unwrap()) as usize;
        let body = &signed_segment[8..emsg_size];
        let fields = &body[4..]; // skip FullBox version+flags
        let mut pos = fields.iter().position(|&b| b == 0).unwrap() + 1; // scheme_id_uri\0
        pos += fields[pos..].iter().position(|&b| b == 0).unwrap() + 1; // value\0
        let timescale = u32::from_be_bytes(fields[pos..pos + 4].try_into().unwrap());
        let event_duration = u32::from_be_bytes(fields[pos + 8..pos + 12].try_into().unwrap());
        let id = u32::from_be_bytes(fields[pos + 12..pos + 16].try_into().unwrap());
        (timescale, event_duration, id)
    }

    fn overwrite_emsg_id(signed_segment: &mut [u8], id: u32) {
        assert_eq!(&signed_segment[4..8], b"emsg");
        let emsg_size = u32::from_be_bytes(signed_segment[..4].try_into().unwrap()) as usize;
        let body = &signed_segment[8..emsg_size];
        let fields = &body[4..];
        let mut pos = fields.iter().position(|&byte| byte == 0).unwrap() + 1;
        pos += fields[pos..].iter().position(|&byte| byte == 0).unwrap() + 1;
        let id_offset = 8 + 4 + pos + 12;
        signed_segment[id_offset..id_offset + 4].copy_from_slice(&id.to_be_bytes());
    }

    fn make_test_signer() -> EphemeralSigner {
        EphemeralSigner::new("test-vsi.local").unwrap()
    }

    const TEST_DYNAMIC_ASSERTION_LABEL: &str = "com.example.vsi-dynamic";

    struct TestDynamicAssertion {
        short: bool,
        invocations: Arc<Mutex<Vec<(String, Option<usize>)>>>,
    }

    impl DynamicAssertion for TestDynamicAssertion {
        fn label(&self) -> String {
            TEST_DYNAMIC_ASSERTION_LABEL.to_string()
        }

        fn reserve_size(&self) -> Result<usize> {
            Ok(64)
        }

        fn content(
            &self,
            label: &str,
            size: Option<usize>,
            _claim: &PartialClaim,
        ) -> Result<DynamicAssertionContent> {
            self.invocations
                .lock()
                .unwrap()
                .push((label.to_string(), size));
            if self.short {
                return Ok(DynamicAssertionContent::Cbor(vec![
                    0xa1, 0x61, b'i', 0x61, b'x',
                ]));
            }

            // One-entry CBOR map with an encoded length of exactly 64 bytes.
            let mut content = vec![b'x'; 64];
            content[..6].copy_from_slice(&[0xa1, 0x62, b'i', b'd', 0x78, 58]);
            Ok(DynamicAssertionContent::Cbor(content))
        }
    }

    struct DynamicEphemeralSigner {
        signer: EphemeralSigner,
        short: bool,
        invocations: Arc<Mutex<Vec<(String, Option<usize>)>>>,
    }

    impl Signer for DynamicEphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            self.signer.sign(data)
        }

        fn alg(&self) -> SigningAlg {
            self.signer.alg()
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            self.signer.certs()
        }

        fn reserve_size(&self) -> usize {
            self.signer.reserve_size()
        }

        fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
            vec![Box::new(TestDynamicAssertion {
                short: self.short,
                invocations: Arc::clone(&self.invocations),
            })]
        }
    }

    fn make_dynamic_test_signer(
        short: bool,
    ) -> (
        DynamicEphemeralSigner,
        Arc<Mutex<Vec<(String, Option<usize>)>>>,
    ) {
        let invocations = Arc::new(Mutex::new(Vec::new()));
        (
            DynamicEphemeralSigner {
                signer: make_test_signer(),
                short,
                invocations: Arc::clone(&invocations),
            },
            invocations,
        )
    }

    fn make_test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn es256_cose_key(signing_key: &p256::ecdsa::SigningKey, kid: &[u8]) -> c2pa_cbor::Value {
        let point = signing_key.verifying_key().to_encoded_point(false);
        let mut map = std::collections::BTreeMap::new();
        map.insert(c2pa_cbor::Value::Integer(1), c2pa_cbor::Value::Integer(2));
        map.insert(
            c2pa_cbor::Value::Integer(2),
            c2pa_cbor::Value::Bytes(kid.to_vec()),
        );
        map.insert(c2pa_cbor::Value::Integer(3), c2pa_cbor::Value::Integer(-7));
        map.insert(c2pa_cbor::Value::Integer(-1), c2pa_cbor::Value::Integer(1));
        map.insert(
            c2pa_cbor::Value::Integer(-2),
            c2pa_cbor::Value::Bytes(point.x().unwrap().to_vec()),
        );
        map.insert(
            c2pa_cbor::Value::Integer(-3),
            c2pa_cbor::Value::Bytes(point.y().unwrap().to_vec()),
        );
        c2pa_cbor::Value::Map(map)
    }

    fn es256_config(
        signing_key: &p256::ecdsa::SigningKey,
        kid: &[u8],
        min_sequence_number: u64,
    ) -> VsiSessionConfig {
        VsiSessionConfig {
            algorithm: SigningAlg::Es256,
            kid: kid.to_vec(),
            public_cose_key_cbor: c2pa_cbor::to_vec(&es256_cose_key(signing_key, kid)).unwrap(),
            min_sequence_number,
            created_at: chrono::Utc::now().to_rfc3339(),
            validity_period_secs: 3600,
        }
    }

    fn es256_signature(signing_key: &p256::ecdsa::SigningKey, tbs: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;

        let signature: p256::ecdsa::Signature = signing_key.sign(tbs);
        signature.to_bytes().to_vec()
    }

    /// A manifest with a `c2pa.created` action, required for `sign_init_segment`'s internal
    /// read-back (via `Reader`) to pass full manifest validation.
    fn test_manifest_json_with_actions() -> &'static str {
        r#"{"assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}}]}"#
    }

    fn make_vsi_signer(signer: &EphemeralSigner, kid: &[u8], min_seq: u64) -> LiveVideoVsiSigner {
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            signer,
            make_test_signing_key(),
            kid.to_vec(),
            min_seq,
            3600,
        )
        .unwrap();
        initialize_test_signer(&mut vsi_signer);
        vsi_signer
    }

    fn initialize_test_signer(vsi_signer: &mut LiveVideoVsiSigner) {
        vsi_signer.active_manifest_id = Some("urn:c2pa:test-manifest".to_string());
        vsi_signer.track_id = Some(1);
        vsi_signer.track_timescale = Some(48_000);
        vsi_signer.default_sample_duration = None;
    }

    fn initialize_test_validator(validator: &mut LiveVideoValidator) {
        validator.init_track_id = Some(1);
        validator.init_timescale = Some(48_000);
        validator.init_default_sample_duration = None;
    }

    #[test]
    fn sign_media_segment_prepends_emsg_box() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let segment = make_test_segment(1);
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        assert!(signed.len() > segment.len());

        let vsi_payload = extract_vsi_payload_from_segment(&signed);
        assert!(
            vsi_payload.is_some(),
            "VSI emsg payload not found in signed segment"
        );
    }

    #[test]
    fn explicit_time_is_protected_iat_and_produces_stable_callback_tbs() {
        let manifest_signer = make_test_signer();
        let session_key = Arc::new(p256::ecdsa::SigningKey::from_slice(&[21u8; 32]).unwrap());
        let mut config = es256_config(&session_key, b"explicit-time", 1);
        config.created_at = "2020-01-01T00:00:00Z".to_string();
        config.validity_period_secs = 60;
        let signing_time = 1_577_836_830;

        let make_signer = |observations: Arc<Mutex<Vec<Vec<u8>>>>| {
            let callback_key = Arc::clone(&session_key);
            let mut signer = LiveVideoVsiSigner::from_session_signer(
                r#"{"assertions": []}"#,
                &manifest_signer,
                config.clone(),
                move |purpose, tbs: &[u8]| {
                    assert_eq!(purpose, VsiSigningPurpose::Vsi { sequence_number: 1 });
                    observations.lock().unwrap().push(tbs.to_vec());
                    Ok(es256_signature(&callback_key, tbs))
                },
            )
            .unwrap();
            initialize_test_signer(&mut signer);
            signer
        };

        let first_observations = Arc::new(Mutex::new(Vec::new()));
        let second_observations = Arc::new(Mutex::new(Vec::new()));
        let mut first = make_signer(Arc::clone(&first_observations));
        let mut second = make_signer(Arc::clone(&second_observations));
        let input = make_test_segment(1);
        let signed = first.sign_media_segment_at(&input, signing_time).unwrap();
        second.sign_media_segment_at(&input, signing_time).unwrap();

        let event = super::super::verifiable_segment_info::extract_vsi_emsg_from_segment(&signed)
            .unwrap()
            .unwrap();
        let parsed = super::super::verifiable_segment_info::parse_vsi(&event.message_data).unwrap();
        assert_eq!(protected_iat(&parsed.sign1).unwrap(), signing_time);
        assert_eq!(first_observations.lock().unwrap().len(), 1);
        assert_eq!(second_observations.lock().unwrap().len(), 1);
        let first_tbs = first_observations.lock().unwrap()[0].clone();
        let second_tbs = second_observations.lock().unwrap()[0].clone();
        assert_eq!(
            first_tbs, second_tbs,
            "the same restored public state, input, and explicit time must produce identical TBS"
        );
    }

    #[test]
    fn explicit_time_validity_boundaries_are_inclusive_and_transactional() {
        let manifest_signer = make_test_signer();
        let session_key = Arc::new(p256::ecdsa::SigningKey::from_slice(&[22u8; 32]).unwrap());
        let mut config = es256_config(&session_key, b"validity-boundaries", 1);
        config.created_at = "2020-01-01T00:00:00Z".to_string();
        config.validity_period_secs = 60;
        let created_at = 1_577_836_800;
        let expires_at = created_at + 60;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let callback_key = Arc::clone(&session_key);
        let callback_observations = Arc::clone(&observations);
        let mut signer = LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            config,
            move |purpose, tbs: &[u8]| {
                callback_observations.lock().unwrap().push(purpose);
                Ok(es256_signature(&callback_key, tbs))
            },
        )
        .unwrap();
        initialize_test_signer(&mut signer);

        assert!(signer
            .sign_media_segment_at(&make_test_segment(1), created_at - 1)
            .is_err());
        assert_eq!(signer.next_sequence_number(), 1);
        assert_eq!(signer.next_event_id, 1);
        assert!(observations.lock().unwrap().is_empty());

        signer
            .sign_media_segment_at(&make_test_segment(1), created_at)
            .unwrap();
        signer
            .sign_media_segment_at(&make_test_segment(2), expires_at)
            .unwrap();
        assert_eq!(signer.next_sequence_number(), 3);
        assert_eq!(signer.next_event_id, 3);
        assert_eq!(observations.lock().unwrap().len(), 2);

        assert!(signer
            .sign_media_segment_at(&make_test_segment(3), expires_at + 1)
            .is_err());
        assert_eq!(signer.next_sequence_number(), 3);
        assert_eq!(signer.next_event_id, 3);
        assert_eq!(observations.lock().unwrap().len(), 2);
    }

    #[test]
    fn sequence_numbers_advance_per_segment() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        assert_eq!(vsi_signer.next_sequence_number(), 1);

        vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        vsi_signer
            .sign_media_segment(&make_test_segment(2))
            .unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 3);
    }

    #[test]
    fn signed_segment_passes_vsi_validation() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        initialize_test_validator(&mut validator);
        let mut tracker = StatusTracker::default();

        validator
            .validate_session_keys(
                &session_keys,
                "urn:c2pa:test-manifest",
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();

        let segment = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();

        validator
            .validate_verifiable_segment_info(&segment, &mut tracker)
            .unwrap();

        let failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            failures.is_empty(),
            "unexpected validation failures: {failures:?}"
        );
    }

    #[test]
    fn vsi_payload_contains_correct_sequence_number() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 5);

        let signed = vsi_signer
            .sign_media_segment(&make_test_segment(5))
            .unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert_eq!(info_map.sequence_number, 5);
    }

    #[test]
    fn signer_binding_roundtrip_validates() {
        let signer = make_test_signer();
        let vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();

        let mut validator = LiveVideoValidator::new();
        initialize_test_validator(&mut validator);
        let mut tracker = StatusTracker::default();

        validator
            .validate_session_keys(
                &session_keys,
                "urn:c2pa:test-manifest",
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();

        let failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            failures.is_empty(),
            "signerBinding validation failures: {failures:?}"
        );
    }

    #[test]
    fn second_segment_has_next_sequence_number() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        let seg1 = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        let seg2 = vsi_signer
            .sign_media_segment(&make_test_segment(2))
            .unwrap();

        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();

        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);
    }

    #[test]
    fn resume_from_segment_advances_sequence_number() {
        let signer = make_test_signer();
        let session_key = make_test_signing_key();
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        initialize_test_signer(&mut vsi_signer);

        let seg1 = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        let mut resumed_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key,
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        // This test bypasses signed-init restoration, so copy the published
        // key timestamp explicitly instead of relying on two constructors to
        // run within the same wall-clock second.
        resumed_signer.created_at = vsi_signer.created_at.clone();
        initialize_test_signer(&mut resumed_signer);
        resumed_signer.resume_from_segment(&seg1).unwrap();
        assert_eq!(resumed_signer.next_sequence_number(), 2);
    }

    #[test]
    fn sign_media_segment_bmff_hash_is_not_null() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        let signed = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert!(
            !info_map.bmff_hash.is_null(),
            "bmffHash must not be null per §19.4 — regression guard"
        );
    }

    #[test]
    fn sign_media_segment_rejects_media_without_signed_init() {
        let signer = make_test_signer();
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            make_test_signing_key(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();

        let error = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap_err();
        assert!(error.to_string().contains("initialization segment"));
    }

    #[test]
    fn sign_media_segment_manifest_id_populated_after_signing_init() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        // Init-segment read-back does full manifest validation; EphemeralSigner certs are
        // intentionally untrusted (see ephemeral_signer.rs), so disable trust checking here.
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        // Use a real DASH init segment so Builder::sign can embed the manifest.
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            make_test_signing_key(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();

        vsi_signer
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();

        let signed = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert!(
            !info_map.manifest_id.is_empty(),
            "manifestId must be populated from the signed init segment per §19.4"
        );
    }

    #[test]
    fn exact_size_dynamic_assertion_signs_vsi_init_and_media() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let (manifest_signer, invocations) = make_dynamic_test_signer(false);
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &manifest_signer,
            make_test_signing_key(),
            b"dynamic-exact".to_vec(),
            1,
            3600,
        )
        .unwrap();

        let signed_init = vsi_signer
            .sign_init_segment(init_data, "video/mp4", &manifest_signer)
            .unwrap();
        assert_eq!(
            invocations.lock().unwrap().as_slice(),
            &[(TEST_DYNAMIC_ASSERTION_LABEL.to_string(), Some(64))]
        );

        let reader = Reader::from_context(Context::new())
            .with_stream("video/mp4", std::io::Cursor::new(&signed_init))
            .unwrap();
        let failed_statuses: Vec<_> = reader
            .validation_status()
            .unwrap_or_default()
            .iter()
            .filter(|status| {
                !status.passed()
                    && status.code() != crate::validation_status::SIGNING_CREDENTIAL_UNTRUSTED
            })
            .collect();
        assert!(
            failed_statuses.is_empty(),
            "signed init validation failures: {failed_statuses:?}"
        );
        let manifest = reader.active_manifest().unwrap();
        let assertion: serde_json::Value = manifest
            .find_assertion(TEST_DYNAMIC_ASSERTION_LABEL)
            .unwrap();
        assert_eq!(assertion["id"], "x".repeat(58));

        let signed_media = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        assert!(extract_vsi_payload_from_segment(&signed_media).is_some());
    }

    #[test]
    fn short_dynamic_assertion_fails_vsi_init_before_embedding() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let (manifest_signer, invocations) = make_dynamic_test_signer(true);
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &manifest_signer,
            make_test_signing_key(),
            b"dynamic-short".to_vec(),
            1,
            3600,
        )
        .unwrap();

        // This is generic DynamicAssertion reservation enforcement at assertion
        // replacement, not a VSI incompatibility or final BMFF-layout failure.
        let error = vsi_signer
            .sign_init_segment(init_data, "video/mp4", &manifest_signer)
            .expect_err("short dynamic assertion must fail init signing");
        let message = error.to_string();
        assert!(message.contains(TEST_DYNAMIC_ASSERTION_LABEL));
        assert!(message.contains("expected 64 bytes, actual 5"));
        assert!(!message.contains("assertion.bmffHash.mismatch"));
        assert_eq!(
            invocations.lock().unwrap().as_slice(),
            &[(TEST_DYNAMIC_ASSERTION_LABEL.to_string(), Some(64))]
        );
        assert!(vsi_signer.active_manifest_id().is_none());
    }

    #[test]
    fn resume_from_segment_enables_continued_signing() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        let mut signer1 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        initialize_test_signer(&mut signer1);
        let seg1 = signer1.sign_media_segment(&make_test_segment(1)).unwrap();

        let mut signer2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        // This test bypasses signed-init restoration, so preserve the first
        // signer's published key timestamp explicitly.
        signer2.created_at = signer1.created_at.clone();
        initialize_test_signer(&mut signer2);
        signer2.resume_from_segment(&seg1).unwrap();
        let seg2 = signer2.sign_media_segment(&make_test_segment(2)).unwrap();

        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();
        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);

        let session_keys = signer2.build_session_keys_assertion().unwrap();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        initialize_test_validator(&mut validator);
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys(
                &session_keys,
                "urn:c2pa:test-manifest",
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();

        validator
            .validate_verifiable_segment_info(&seg1, &mut tracker)
            .unwrap();
        validator
            .validate_verifiable_segment_info(&seg2, &mut tracker)
            .unwrap();

        let failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(failures.is_empty(), "validation failures: {failures:?}");
    }

    #[test]
    fn resume_from_segment_requires_restored_signed_init_state() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        let mut signer1 = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer1
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();
        let seg1 = signer1.sign_media_segment(&make_test_segment(1)).unwrap();

        let mut signer2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key,
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        let error = signer2.resume_from_segment(&seg1).unwrap_err();
        assert!(error
            .to_string()
            .contains("restore_manifest_id_from_signed_init"));
    }

    /// Regression test for the dynamic-manifestId bug: when the CLI is invoked once per
    /// segment (live session), `sign_init_segment` must not be called again.
    /// Instead, `restore_manifest_id_from_signed_init` must produce the same `manifestId`
    /// as the original `sign_init_segment` call.
    #[test]
    fn restore_manifest_id_from_signed_init_matches_original_manifest_id() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        // Init-segment read-back does full manifest validation; EphemeralSigner certs are
        // intentionally untrusted (see ephemeral_signer.rs), so disable trust checking here.
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        // Simulate first CLI invocation: sign init + seg_001.
        let mut signer_call1 = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        let signed_init = signer_call1
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();
        let seg1 = signer_call1
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();

        // Simulate second CLI invocation: new signer process, restore state.
        let mut signer_call2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer_call2
            .restore_manifest_id_from_signed_init(&signed_init, "video/mp4")
            .unwrap();
        signer_call2.resume_from_segment(&seg1).unwrap();
        let seg2 = signer_call2
            .sign_media_segment(&make_test_segment(2))
            .unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();

        // Both segments must reference the same manifestId.
        assert_eq!(
            map1.manifest_id, map2.manifest_id,
            "manifestId must be identical across per-segment invocations (§19.4)"
        );
        assert!(
            map2.manifest_id.starts_with("urn:c2pa:"),
            "manifestId must be the manifest's c2pa URN label (§8.1), got: {}",
            map2.manifest_id
        );
        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);
    }

    #[test]
    fn es256_callback_signs_exact_structures_and_validates() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let manifest_signer = make_test_signer();
        let session_key = Arc::new(p256::ecdsa::SigningKey::random(&mut rand::thread_rng()));
        let config = es256_config(&session_key, b"es256-session", 1);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let callback_key = Arc::clone(&session_key);
        let callback_observations = Arc::clone(&observations);
        let callback = move |purpose, tbs: &[u8]| {
            callback_observations
                .lock()
                .unwrap()
                .push((purpose, tbs.to_vec()));
            Ok(es256_signature(&callback_key, tbs))
        };

        let mut vsi_signer = LiveVideoVsiSigner::from_session_signer(
            test_manifest_json_with_actions(),
            &manifest_signer,
            config,
            callback,
        )
        .unwrap();
        assert!(observations.lock().unwrap().is_empty());

        let signed_init = vsi_signer
            .sign_init_segment(init_data, "video/mp4", &manifest_signer)
            .unwrap();
        let signed_media = vsi_signer
            .sign_media_segment(&make_test_segment(1))
            .unwrap();
        let observed = observations.lock().unwrap().clone();
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].0, VsiSigningPurpose::SignerBinding);
        assert_eq!(observed[1].0, VsiSigningPurpose::Vsi { sequence_number: 1 });

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
        let binding_bytes = super::super::session_key_validation::extract_signer_binding_bytes(
            &session_keys.keys[0].signer_binding,
        )
        .unwrap();
        let binding = coset::CoseSign1::from_tagged_slice(&binding_bytes).unwrap();
        let ee_cert_der = manifest_signer.certs().unwrap().into_iter().next().unwrap();
        let external_payload =
            c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.clone())).unwrap();
        assert_eq!(
            observed[0].1,
            binding.tbs_detached_data(&external_payload, b"")
        );
        let event =
            super::super::verifiable_segment_info::extract_vsi_emsg_from_segment(&signed_media)
                .unwrap()
                .unwrap();
        let parsed = super::super::verifiable_segment_info::parse_vsi(&event.message_data).unwrap();
        assert_eq!(observed[1].1, parsed.sign1.tbs_data(b""));

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&signed_init, &mut tracker)
            .unwrap();
        validator
            .validate_session_keys(
                &session_keys,
                vsi_signer.active_manifest_id().unwrap(),
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();
        validator
            .validate_verifiable_segment_info(&signed_media, &mut tracker)
            .unwrap();
        assert!(tracker.filter_errors().next().is_none());
    }

    #[test]
    fn generic_constructor_rejects_algorithm_key_and_kid_mismatches() {
        let manifest_signer = make_test_signer();
        let session_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let valid = es256_config(&session_key, b"correct-kid", 1);

        let mut wrong_algorithm = valid.clone();
        wrong_algorithm.algorithm = SigningAlg::Ed25519;
        assert!(LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            wrong_algorithm,
            |_, _: &[u8]| Err(Error::BadParam("must not sign".to_string())),
        )
        .is_err());

        let mut wrong_kid = valid.clone();
        wrong_kid.kid = b"wrong-kid".to_vec();
        assert!(LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            wrong_kid,
            |_, _: &[u8]| Err(Error::BadParam("must not sign".to_string())),
        )
        .is_err());

        let mut invalid_point = valid;
        let mut cose_key: c2pa_cbor::Value =
            c2pa_cbor::from_slice(&invalid_point.public_cose_key_cbor).unwrap();
        if let c2pa_cbor::Value::Map(map) = &mut cose_key {
            map.insert(
                c2pa_cbor::Value::Integer(-2),
                c2pa_cbor::Value::Bytes(vec![0; 32]),
            );
            map.insert(
                c2pa_cbor::Value::Integer(-3),
                c2pa_cbor::Value::Bytes(vec![0; 32]),
            );
        }
        invalid_point.public_cose_key_cbor = c2pa_cbor::to_vec(&cose_key).unwrap();
        assert!(LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            invalid_point,
            |_, _: &[u8]| Err(Error::BadParam("must not sign".to_string())),
        )
        .is_err());
    }

    #[derive(Clone, Copy)]
    enum CallbackFailure {
        Der,
        Short,
        Oversized,
        Corrupt,
        Error,
    }

    #[test]
    fn callback_failures_do_not_advance_media_state() {
        for failure in [
            CallbackFailure::Der,
            CallbackFailure::Short,
            CallbackFailure::Oversized,
            CallbackFailure::Corrupt,
            CallbackFailure::Error,
        ] {
            let manifest_signer = make_test_signer();
            let session_key = Arc::new(p256::ecdsa::SigningKey::random(&mut rand::thread_rng()));
            let config = es256_config(&session_key, b"failure-key", 1);
            let observations = Arc::new(Mutex::new(Vec::new()));
            let callback_key = Arc::clone(&session_key);
            let callback_observations = Arc::clone(&observations);
            let callback = move |purpose, tbs: &[u8]| {
                callback_observations.lock().unwrap().push(purpose);
                if purpose == VsiSigningPurpose::SignerBinding {
                    return Ok(es256_signature(&callback_key, tbs));
                }
                match failure {
                    CallbackFailure::Der => {
                        use p256::ecdsa::signature::Signer as _;
                        let signature: p256::ecdsa::Signature = callback_key.sign(tbs);
                        Ok(signature.to_der().as_bytes().to_vec())
                    }
                    CallbackFailure::Short => Ok(vec![0; 63]),
                    CallbackFailure::Oversized => Ok(vec![0; 65]),
                    CallbackFailure::Corrupt => Ok(vec![0; 64]),
                    CallbackFailure::Error => {
                        Err(Error::BadParam("callback refused signing".to_string()))
                    }
                }
            };
            let mut vsi_signer = LiveVideoVsiSigner::from_session_signer(
                r#"{"assertions": []}"#,
                &manifest_signer,
                config,
                callback,
            )
            .unwrap();
            vsi_signer.ensure_signer_binding().unwrap();
            initialize_test_signer(&mut vsi_signer);

            assert!(vsi_signer
                .sign_media_segment(&make_test_segment(1))
                .is_err());
            assert_eq!(vsi_signer.next_sequence_number(), 1);
            assert_eq!(vsi_signer.next_event_id, 1);
            assert_eq!(
                observations
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|purpose| matches!(purpose, VsiSigningPurpose::Vsi { .. }))
                    .count(),
                1,
                "the draft sizing pass must not invoke the callback"
            );
        }
    }

    #[test]
    fn es256_callback_recovers_artifacts_without_signing_and_resumes() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let manifest_signer = make_test_signer();
        let session_key = Arc::new(p256::ecdsa::SigningKey::random(&mut rand::thread_rng()));
        let mut config = es256_config(&session_key, b"recover-key", 1);
        config.created_at = "2020-01-01T00:00:00Z".to_string();
        config.validity_period_secs = 1_000_000_000;
        let historical_signing_time = 1_577_836_801;

        let first_key = Arc::clone(&session_key);
        let mut first = LiveVideoVsiSigner::from_session_signer(
            test_manifest_json_with_actions(),
            &manifest_signer,
            config.clone(),
            move |_, tbs: &[u8]| Ok(es256_signature(&first_key, tbs)),
        )
        .unwrap();
        let signed_init = first
            .sign_init_segment(init_data, "video/mp4", &manifest_signer)
            .unwrap();
        let segment1 = first
            .sign_media_segment_at(&make_test_segment(1), historical_signing_time)
            .unwrap();

        let init_only_observations = Arc::new(Mutex::new(Vec::new()));
        let init_only_key = Arc::clone(&session_key);
        let callback_observations = Arc::clone(&init_only_observations);
        let mut init_only = LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            config.clone(),
            move |purpose, tbs: &[u8]| {
                callback_observations.lock().unwrap().push(purpose);
                Ok(es256_signature(&init_only_key, tbs))
            },
        )
        .unwrap();
        init_only
            .recover_from_artifacts(&signed_init, None, "video/mp4")
            .unwrap();
        assert!(init_only_observations.lock().unwrap().is_empty());
        assert_eq!(init_only.next_sequence_number(), 1);
        assert_eq!(init_only.next_event_id, 1);

        let recovered_observations = Arc::new(Mutex::new(Vec::new()));
        let recovered_key = Arc::clone(&session_key);
        let callback_observations = Arc::clone(&recovered_observations);
        let mut recovered = LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            config.clone(),
            move |purpose, tbs: &[u8]| {
                callback_observations.lock().unwrap().push(purpose);
                Ok(es256_signature(&recovered_key, tbs))
            },
        )
        .unwrap();
        recovered
            .recover_from_artifacts(&signed_init, Some(&segment1), "video/mp4")
            .unwrap();
        assert!(recovered_observations.lock().unwrap().is_empty());
        assert_eq!(recovered.next_sequence_number(), 2);
        let segment2 = recovered
            .sign_media_segment_at(&make_test_segment(2), historical_signing_time + 1)
            .unwrap();
        assert_eq!(
            recovered_observations.lock().unwrap().as_slice(),
            &[VsiSigningPurpose::Vsi { sequence_number: 2 }]
        );

        let failed_observations = Arc::new(Mutex::new(Vec::new()));
        let failed_key = Arc::clone(&session_key);
        let callback_observations = Arc::clone(&failed_observations);
        let mut failed = LiveVideoVsiSigner::from_session_signer(
            r#"{"assertions": []}"#,
            &manifest_signer,
            config,
            move |purpose, tbs: &[u8]| {
                callback_observations.lock().unwrap().push(purpose);
                Ok(es256_signature(&failed_key, tbs))
            },
        )
        .unwrap();
        let mut tampered = segment1.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(failed
            .recover_from_artifacts(&signed_init, Some(&tampered), "video/mp4")
            .is_err());
        assert!(failed.active_manifest_id().is_none());
        assert_eq!(failed.next_sequence_number(), 1);
        assert!(failed_observations.lock().unwrap().is_empty());

        // emsg.id is outside both the COSE payload and bmffHash exclusion, so
        // recovery must enforce the deterministic sequence-to-id invariant.
        let mut tampered_id = segment1.clone();
        overwrite_emsg_id(&mut tampered_id, 99);
        assert!(failed
            .recover_from_artifacts(&signed_init, Some(&tampered_id), "video/mp4")
            .is_err());
        assert!(failed.active_manifest_id().is_none());
        assert_eq!(failed.next_sequence_number(), 1);
        assert!(failed_observations.lock().unwrap().is_empty());

        let session_keys = recovered.build_session_keys_assertion().unwrap();
        let ee_cert_der = manifest_signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&signed_init, &mut tracker)
            .unwrap();
        validator
            .validate_session_keys(
                &session_keys,
                recovered.active_manifest_id().unwrap(),
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();
        validator
            .validate_verifiable_segment_info(&segment1, &mut tracker)
            .unwrap();
        validator
            .validate_verifiable_segment_info(&segment2, &mut tracker)
            .unwrap();
        assert!(tracker.filter_errors().next().is_none());
    }

    #[test]
    fn signer_binding_callback_failure_leaves_session_uninitialized() {
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let manifest_signer = make_test_signer();
        let session_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let config = es256_config(&session_key, b"binding-failure", 1);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let callback_observations = Arc::clone(&observations);
        let mut vsi_signer = LiveVideoVsiSigner::from_session_signer(
            test_manifest_json_with_actions(),
            &manifest_signer,
            config,
            move |purpose, _: &[u8]| {
                callback_observations.lock().unwrap().push(purpose);
                Err(Error::BadParam("binding authorization denied".to_string()))
            },
        )
        .unwrap();

        assert!(vsi_signer
            .sign_init_segment(init_data, "video/mp4", &manifest_signer)
            .is_err());
        assert_eq!(
            observations.lock().unwrap().as_slice(),
            &[VsiSigningPurpose::SignerBinding]
        );
        assert!(vsi_signer.active_manifest_id().is_none());
        assert!(vsi_signer.signer_binding.is_none());
        assert_eq!(vsi_signer.next_sequence_number(), 1);
        assert_eq!(vsi_signer.next_event_id, 1);
    }
}
