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

//! Prehashed trusted VSI signing (see `docs/trusted-vsi-native-contract.md`).
//!
//! A trusted stream processor owns media bytes, ordering, and MFHD/VSI
//! sequence equality. This session owns the session-key binding, the reserved
//! initialization manifest, and — in signer-composed mode — EMSG composition.
//! Two modes are pinned at construction:
//!
//! * `ExpertSigStructure`: the processor composes the exact COSE
//!   Sig_structure; this session validates its canonical framing, signs the
//!   original bytes unchanged, and returns only the raw signature.
//! * `SignerComposedEmsg`: this session reserves and finalizes complete EMSG
//!   boxes around processor-supplied canonical bmff-hash maps.
//!
//! State is exported as an explicit versioned JSON record with exact
//! artifacts, never a heap snapshot. Once an external signing call begins a
//! failure blocks the local session; callers retry by importing the durable
//! pre-operation record into a new instance.

use std::{io::Cursor, sync::Arc};

use coset::TaggedCborSerializable;
use serde::{Deserialize, Serialize};

use super::{
    trusted_cbor::{self, KeyRule, Scanner, MAX_SIG_STRUCTURE_LEN, MAX_SMALL_CBOR_LEN},
    verifiable_segment_info::SegmentInfoMap,
    vsi_signing::{
        build_emsg_box, build_signer_binding, build_signer_binding_placeholder,
        build_vsi_cose_sign1_dummy, build_vsi_cose_sign1_unsigned, ensure_key_valid_at,
        new_vsi_bmff_hash, validate_session_config, verify_raw_session_signature, VsiSessionSigner,
        VsiSigningPurpose,
    },
    VsiSessionConfig, C2PA_UUID,
};
use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, DataMap, ExclusionsMap, SessionKey, SessionKeys, UserCbor},
    builder::Builder,
    cbor_types::DateT,
    crypto::hash::sha256,
    error::Error,
    status_tracker::StatusTracker,
    store::Store,
    Context, Result, SigningAlg,
};

const STATE_FORMAT: &str = "c2pa.trusted-vsi.state";
/// Version 2 pins the Context signer's dynamic-assertion declarations and
/// claim reserve size in the session identity. Version 1 records lack them and
/// are rejected (unreleased; no migration).
const STATE_VERSION: u32 = 2;
const MAX_STATE_LEN: usize = 64 * 1024 * 1024;
/// Header of a C2PA manifest UUID box: size, type, extended type,
/// version/flags, `"manifest\0"`, and the Merkle offset.
const UUID_BOX_PREFIX_LEN: usize = 8 + 16 + 4 + 9 + 8;
const INIT_FORMAT: &str = "mp4";

/// Capability bits for prehashed trusted VSI signing.
///
/// Bit 0 (1) split init UUID, bit 1 (2) expert Sig_structure signing, bit 2 (4)
/// signer-composed EMSG, bit 3 (8) versioned state export/import restoration,
/// bit 4 (16) signing-context V1, and bit 5 (32) full `u32` handling.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustedVsiCapabilities(u64);

impl TrustedVsiCapabilities {
    /// Bit mask for expert Sig_structure support.
    pub const EXPERT_SIG_STRUCTURE_BIT: u64 = 2;
    /// Bit mask for safely signing through the full `u32` sequence space.
    pub const FULL_UINT32_EXHAUSTION_BIT: u64 = 32;
    /// Bit mask for versioned state export/import restoration.
    pub const RECOVERY_BIT: u64 = 8;
    /// Bit mask for signer-composed EMSG support.
    pub const SIGNER_COMPOSED_EMSG_BIT: u64 = 4;
    /// Bit mask for [`VsiSigningContextV1`] support.
    pub const SIGNING_CONTEXT_V1_BIT: u64 = 16;
    /// Bit mask for split initialization-segment UUID support.
    pub const SPLIT_INIT_UUID_BIT: u64 = 1;

    /// Returns the capabilities implemented by this build.
    pub const fn current() -> Self {
        Self(
            Self::SPLIT_INIT_UUID_BIT
                | Self::EXPERT_SIG_STRUCTURE_BIT
                | Self::SIGNER_COMPOSED_EMSG_BIT
                | Self::RECOVERY_BIT
                | Self::SIGNING_CONTEXT_V1_BIT
                | Self::FULL_UINT32_EXHAUSTION_BIT,
        )
    }

    /// Returns the raw capability bit mask.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Reports whether split initialization-segment UUID signing is supported.
    pub const fn supports_split_init_uuid(self) -> bool {
        self.0 & Self::SPLIT_INIT_UUID_BIT != 0
    }

    /// Reports whether exact caller-composed Sig_structure signing is supported.
    pub const fn supports_expert_sig_structure(self) -> bool {
        self.0 & Self::EXPERT_SIG_STRUCTURE_BIT != 0
    }

    /// Reports whether the SDK can compose a reserved EMSG around a supplied hash.
    pub const fn supports_signer_composed_emsg(self) -> bool {
        self.0 & Self::SIGNER_COMPOSED_EMSG_BIT != 0
    }

    /// Reports whether versioned state export/import restoration is supported.
    pub const fn supports_recovery(self) -> bool {
        self.0 & Self::RECOVERY_BIT != 0
    }

    /// Reports whether callbacks receive [`VsiSigningContextV1`].
    pub const fn supports_signing_context_v1(self) -> bool {
        self.0 & Self::SIGNING_CONTEXT_V1_BIT != 0
    }

    /// Reports whether the terminal `u32::MAX` sequence can be signed safely.
    pub const fn supports_full_uint32_exhaustion(self) -> bool {
        self.0 & Self::FULL_UINT32_EXHAUSTION_BIT != 0
    }
}

/// Signing mode pinned when a session is constructed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedVsiMode {
    /// The processor supplies exact Sig_structure bytes; signatures only.
    ExpertSigStructure = 1,
    /// The session reserves and finalizes complete EMSG boxes.
    SignerComposedEmsg = 2,
}

impl TrustedVsiMode {
    /// Converts the stable numeric discriminant.
    pub fn from_u32(value: u32) -> Result<Self> {
        match value {
            1 => Ok(Self::ExpertSigStructure),
            2 => Ok(Self::SignerComposedEmsg),
            _ => Err(Error::BadParam(format!("unknown trusted VSI mode {value}"))),
        }
    }
}

/// Construction options pinned for the life of a session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedVsiSessionOptions {
    /// Mode pinned for every operation and import.
    pub mode: TrustedVsiMode,
    /// 32 lowercase hex characters of coordinator-retained public randomness.
    /// Domain-separates deterministic manifest and instance identifiers. It is
    /// never used as key material.
    pub reservation_nonce: String,
    /// Pinned initialization time, which must lie within the key validity.
    pub signing_time_unix_seconds: i64,
    /// Inclusive highest usable sequence. Absent means `u32::MAX`.
    #[serde(default)]
    pub sequence_max: Option<u32>,
}

impl TrustedVsiSessionOptions {
    /// Parses the JSON option object documented for the C ABI.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::BadParam(format!("invalid trusted VSI options: {e}")))
    }
}

/// Operation selector for [`TrustedVsiPrehashedSession::preflight`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedVsiOperation {
    /// [`TrustedVsiPrehashedSession::reserve_init_uuid`].
    ReserveInit = 0,
    /// [`TrustedVsiPrehashedSession::finalize_init_uuid`].
    FinalizeInit = 1,
    /// [`TrustedVsiPrehashedSession::commit_init_uuid`].
    CommitInit = 2,
    /// [`TrustedVsiPrehashedSession::sign_sig_structure`].
    ExpertSign = 3,
    /// [`TrustedVsiPrehashedSession::reserve_media_emsg_at`].
    ReserveMedia = 4,
    /// [`TrustedVsiPrehashedSession::finalize_media_emsg`].
    FinalizeMedia = 5,
}

impl TrustedVsiOperation {
    /// Converts the stable numeric discriminant.
    pub fn from_u32(value: u32) -> Result<Self> {
        Ok(match value {
            0 => Self::ReserveInit,
            1 => Self::FinalizeInit,
            2 => Self::CommitInit,
            3 => Self::ExpertSign,
            4 => Self::ReserveMedia,
            5 => Self::FinalizeMedia,
            _ => {
                return Err(Error::BadParam(format!(
                    "unknown trusted VSI operation {value}"
                )))
            }
        })
    }
}

/// Input kind for static trusted VSI validation and hash helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedVsiInputKind {
    /// Canonical init bmff-hash map.
    InitHash = 0,
    /// Exact expert COSE Sig_structure.
    SigStructure = 1,
    /// Canonical media bmff-hash map.
    MediaHash = 2,
}

impl TrustedVsiInputKind {
    /// Converts the stable numeric discriminant.
    pub fn from_u32(value: u32) -> Result<Self> {
        Ok(match value {
            0 => Self::InitHash,
            1 => Self::SigStructure,
            2 => Self::MediaHash,
            _ => {
                return Err(Error::BadParam(format!(
                    "unknown trusted VSI input kind {value}"
                )))
            }
        })
    }
}

/// Purpose of a trusted VSI signing callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedVsiSigningPurpose {
    /// Bind the session key to the claim signer's certificate.
    SignerBinding,
    /// Sign one media segment's VSI Sig_structure.
    Vsi,
}

/// Version-one authorization metadata for a trusted VSI signing callback.
///
/// SignerBinding has no sequence or event. Expert media carries purpose `Vsi`,
/// the processor-supplied sequence, no event, and `exhaust_after_sign = false`
/// (the processor owns rollover). Composed media carries the reserved event and
/// marks the final usable identifier with `exhaust_after_sign = true`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VsiSigningContextV1 {
    purpose: TrustedVsiSigningPurpose,
    sequence_number: Option<u32>,
    event_id: Option<u32>,
    exhaust_after_sign: bool,
}

impl VsiSigningContextV1 {
    const SIGNER_BINDING: Self = Self {
        purpose: TrustedVsiSigningPurpose::SignerBinding,
        sequence_number: None,
        event_id: None,
        exhaust_after_sign: false,
    };

    /// Returns the explicit reason for the signature request.
    pub const fn purpose(&self) -> TrustedVsiSigningPurpose {
        self.purpose
    }

    /// Returns the media sequence number, when the request represents media.
    pub const fn sequence_number(&self) -> Option<u32> {
        self.sequence_number
    }

    /// Returns the EMSG event identifier, when one has been reserved.
    pub const fn event_id(&self) -> Option<u32> {
        self.event_id
    }

    /// Returns whether this signature exhausts the usable identifier space.
    pub const fn exhaust_after_sign(&self) -> bool {
        self.exhaust_after_sign
    }
}

/// Reserved initialization UUID bytes and their manifest identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedVsiInitUuidReservation {
    bytes: Vec<u8>,
    manifest_id: String,
}

impl TrustedVsiInitUuidReservation {
    /// Returns the immutable reserved UUID box bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the manifest identifier represented by the UUID reservation.
    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }
}

/// Reserved complete media EMSG bytes and their signing metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedVsiMediaEmsgReservation {
    bytes: Vec<u8>,
    signing_time_unix_seconds: i64,
    timescale: u32,
    event_duration: u32,
    signing_context: VsiSigningContextV1,
}

impl TrustedVsiMediaEmsgReservation {
    /// Returns the immutable placeholder EMSG box bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the pinned protected COSE `iat`.
    pub const fn signing_time_unix_seconds(&self) -> i64 {
        self.signing_time_unix_seconds
    }

    /// Returns the EMSG timescale.
    pub const fn timescale(&self) -> u32 {
        self.timescale
    }

    /// Returns the EMSG event duration.
    pub const fn event_duration(&self) -> u32 {
        self.event_duration
    }

    /// Returns the callback authorization metadata reserved for this EMSG.
    pub const fn signing_context(&self) -> &VsiSigningContextV1 {
        &self.signing_context
    }
}

/// Successful terminal reason for a trusted VSI session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedVsiExhaustionReason {
    /// The final configured sequence (`sequence_max`, default `u32::MAX`) was consumed.
    SequenceMax,
    /// The final `u32::MAX` EMSG event identifier was consumed.
    EventIdMax,
    /// A migrated legacy session stopped at the former sequence sentinel.
    LegacySentinel,
}

/// Public state of a prehashed trusted VSI session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedVsiStatus {
    init_uuid_committed: bool,
    init_uuid_pending: bool,
    media_emsg_pending: bool,
    next_sequence_number: Option<u32>,
    next_event_id: Option<u32>,
    exhausted: bool,
    exhaustion_reason: Option<TrustedVsiExhaustionReason>,
    blocked: bool,
}

impl TrustedVsiStatus {
    /// Returns whether the initialization UUID has been committed (activated).
    pub const fn init_uuid_committed(&self) -> bool {
        self.init_uuid_committed
    }

    /// Returns whether an initialization UUID is reserved or finalized but not committed.
    pub const fn init_uuid_pending(&self) -> bool {
        self.init_uuid_pending
    }

    /// Returns whether a media EMSG reservation is pending.
    pub const fn media_emsg_pending(&self) -> bool {
        self.media_emsg_pending
    }

    /// Returns the next composed media sequence. Always `None` in expert mode.
    pub const fn next_sequence_number(&self) -> Option<u32> {
        self.next_sequence_number
    }

    /// Returns the next composed EMSG event identifier. Always `None` in expert mode.
    pub const fn next_event_id(&self) -> Option<u32> {
        self.next_event_id
    }

    /// Returns whether no further composed media can be signed.
    pub const fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Returns the successful terminal reason, when exhausted.
    pub const fn exhaustion_reason(&self) -> Option<TrustedVsiExhaustionReason> {
        self.exhaustion_reason
    }

    /// Returns whether an external signing step failed; import a pre-operation
    /// record into a new session to retry.
    pub const fn blocked(&self) -> bool {
        self.blocked
    }
}

// ── explicit exported state ─────────────────────────────────────────────────

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::crypto::base64::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        crate::crypto::base64::decode(&text).map_err(serde::de::Error::custom)
    }
}

mod b64_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => s.serialize_some(&crate::crypto::base64::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| crate::crypto::base64::decode(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    New,
    InitReserved,
    InitFinalized,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingMedia {
    sequence_number: u32,
    event_id: u32,
    signing_time_unix_seconds: i64,
    timescale: u32,
    event_duration: u32,
    #[serde(with = "b64")]
    placeholder: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletedMedia {
    sequence_number: u32,
    event_id: u32,
    signing_time_unix_seconds: i64,
    timescale: u32,
    event_duration: u32,
    #[serde(with = "b64")]
    hash_input: Vec<u8>,
    #[serde(with = "b64")]
    signed_emsg: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionState {
    phase: Phase,
    manifest_id: Option<String>,
    #[serde(with = "b64_opt")]
    reserved_jumbf: Option<Vec<u8>>,
    #[serde(with = "b64_opt")]
    reserved_uuid: Option<Vec<u8>>,
    #[serde(with = "b64_opt")]
    init_hash_input: Option<Vec<u8>>,
    #[serde(with = "b64_opt")]
    signed_uuid: Option<Vec<u8>>,
    next_sequence_number: Option<u32>,
    next_event_id: Option<u32>,
    exhaustion_reason: Option<TrustedVsiExhaustionReason>,
    pending_media: Option<PendingMedia>,
    last_media: Option<CompletedMedia>,
    blocked: bool,
}

impl SessionState {
    fn new() -> Self {
        Self {
            phase: Phase::New,
            manifest_id: None,
            reserved_jumbf: None,
            reserved_uuid: None,
            init_hash_input: None,
            signed_uuid: None,
            next_sequence_number: None,
            next_event_id: None,
            exhaustion_reason: None,
            pending_media: None,
            last_media: None,
            blocked: false,
        }
    }
}

/// One Context-signer dynamic assertion declaration, in registration order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DynamicAssertionDeclaration {
    label: String,
    reserve_size: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionIdentity {
    mode: TrustedVsiMode,
    algorithm: String,
    #[serde(with = "b64")]
    kid: Vec<u8>,
    #[serde(with = "b64")]
    public_cose_key: Vec<u8>,
    min_sequence_number: u32,
    sequence_max: u32,
    created_at: String,
    validity_period_secs: u64,
    reservation_nonce: String,
    signing_time_unix_seconds: i64,
    manifest_json_sha256: String,
    claim_signer_certificate_sha256: String,
    claim_signer_reserve_size: usize,
    dynamic_assertions: Vec<DynamicAssertionDeclaration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateRecord {
    format: String,
    version: u32,
    identity: SessionIdentity,
    state: SessionState,
}

// ── static validation ───────────────────────────────────────────────────────

fn invalid(message: impl Into<String>) -> Error {
    Error::BadParam(message.into())
}

fn protected_alg_encoding(algorithm: SigningAlg) -> Result<u8> {
    match algorithm {
        SigningAlg::Ed25519 => Ok(0x27), // -8
        SigningAlg::Es256 => Ok(0x26),   // -7
        _ => Err(invalid(
            "trusted VSI supports only Ed25519 and ES256 session keys",
        )),
    }
}

fn validate_protected_header(protected: &[u8], algorithm: SigningAlg) -> Result<()> {
    if protected.len() > MAX_SMALL_CBOR_LEN {
        return Err(invalid("protected header exceeds 64 KiB"));
    }
    let expected_alg = protected_alg_encoding(algorithm)?;
    let mut scanner = Scanner::new(protected);
    let entries = scanner.map(KeyRule::CoseLabel)?;
    if !scanner.at_end() {
        return Err(invalid("protected header has trailing bytes"));
    }
    let alg = entries
        .iter()
        .find(|(key, _)| *key == [0x01])
        .ok_or_else(|| invalid("protected header must contain an integer alg"))?;
    if alg.1 != [expected_alg] {
        return Err(invalid(
            "protected alg must be the integer matching the pinned session key algorithm",
        ));
    }
    Ok(())
}

/// Validates an expert Sig_structure: one untagged definite four-element
/// array `["Signature1", protected, h'', payload]`. The payload is opaque.
fn validate_sig_structure(algorithm: SigningAlg, data: &[u8]) -> Result<()> {
    if data.len() > MAX_SIG_STRUCTURE_LEN {
        return Err(invalid("Sig_structure exceeds 1 MiB"));
    }
    protected_alg_encoding(algorithm)?;
    let mut scanner = Scanner::new(data);
    let (major, _, count) = scanner.head()?;
    if major != 4 || count != 4 {
        return Err(invalid(
            "Sig_structure must be one untagged definite four-element array",
        ));
    }
    let context = scanner.value(1)?;
    let mut expected_context = vec![0x6a];
    expected_context.extend_from_slice(b"Signature1");
    if context != expected_context.as_slice() {
        return Err(invalid("Sig_structure context must be \"Signature1\""));
    }
    validate_protected_header(scanner.bytes()?, algorithm)?;
    if !scanner.bytes()?.is_empty() {
        return Err(invalid("external AAD must be empty"));
    }
    scanner.bytes()?; // opaque payload; intentionally not decoded
    if !scanner.at_end() {
        return Err(invalid(format!(
            "Sig_structure has trailing bytes after offset {}",
            scanner.position()
        )));
    }
    Ok(())
}

fn hash_template_struct(kind: TrustedVsiInputKind, hash: &[u8]) -> Result<BmffHash> {
    let mut bmff_hash = match kind {
        TrustedVsiInputKind::InitHash => {
            let mut bmff_hash = BmffHash::new("jumbf manifest", "sha256", None);
            let mut exclusion = ExclusionsMap::new("/uuid".to_string());
            exclusion.data = Some(vec![DataMap {
                offset: 8,
                value: C2PA_UUID.to_vec(),
            }]);
            bmff_hash.add_exclusions(&mut vec![exclusion]);
            bmff_hash
        }
        TrustedVsiInputKind::MediaHash => new_vsi_bmff_hash(),
        TrustedVsiInputKind::SigStructure => {
            return Err(invalid("Sig_structure has no hash template"))
        }
    };
    bmff_hash.set_bmff_version(3);
    bmff_hash.set_hash(hash.to_vec());
    Ok(bmff_hash)
}

fn hash_template_value(kind: TrustedVsiInputKind, hash: &[u8]) -> Result<c2pa_cbor::Value> {
    c2pa_cbor::value::to_value(hash_template_struct(kind, hash)?)
        .map_err(|e| invalid(format!("failed to encode bmff-hash template: {e}")))
}

/// Returns the canonical zero-digest bmff-hash template for a hash kind.
pub fn trusted_vsi_hash_template(kind: TrustedVsiInputKind) -> Result<Vec<u8>> {
    trusted_cbor::encode_deterministic(&hash_template_value(kind, &[0; 32])?)
}

/// Computes the canonical bmff-hash input over complete final-placement bytes
/// (the init segment with its reserved UUID installed, or the reserved EMSG
/// followed by the media segment). Pure: no session, key, or callback use.
pub fn trusted_vsi_compute_hash(kind: TrustedVsiInputKind, final_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut bmff_hash = hash_template_struct(kind, &[0; 32])?;
    bmff_hash
        .gen_hash_from_stream(&mut Cursor::new(final_bytes))
        .map_err(|e| invalid(format!("failed to compute bmff hash: {e}")))?;
    let hash = bmff_hash
        .hash()
        .cloned()
        .ok_or_else(|| invalid("bmff hash was not computed"))?;
    trusted_cbor::encode_deterministic(&hash_template_value(kind, &hash)?)
}

/// Validates a canonical hash input and returns its SHA-256 digest bytes.
fn parse_hash_input(kind: TrustedVsiInputKind, data: &[u8]) -> Result<Vec<u8>> {
    trusted_cbor::validate_single_value(data, MAX_SMALL_CBOR_LEN)?;
    let value: c2pa_cbor::Value =
        c2pa_cbor::from_slice(data).map_err(|e| invalid(format!("hash input is not CBOR: {e}")))?;
    let hash = match &value {
        c2pa_cbor::Value::Map(map) => match map.get(&c2pa_cbor::Value::Text("hash".into())) {
            Some(c2pa_cbor::Value::Bytes(hash)) if hash.len() == 32 => hash.clone(),
            _ => return Err(invalid("hash input must contain a 32-byte SHA-256 hash")),
        },
        _ => return Err(invalid("hash input must be a bmff-hash map")),
    };
    let expected = trusted_cbor::encode_deterministic(&hash_template_value(kind, &hash)?)?;
    if expected != data {
        return Err(invalid(
            "hash input must exactly match the native bmff-hash template except for its hash",
        ));
    }
    Ok(hash)
}

/// Statically validates an input without a session, key, or callback.
pub fn validate_trusted_vsi_input(
    kind: TrustedVsiInputKind,
    algorithm: SigningAlg,
    data: &[u8],
) -> Result<()> {
    match kind {
        TrustedVsiInputKind::SigStructure => validate_sig_structure(algorithm, data),
        _ => parse_hash_input(kind, data).map(|_| ()),
    }
}

fn algorithm_name(algorithm: SigningAlg) -> &'static str {
    match algorithm {
        SigningAlg::Ed25519 => "ed25519",
        _ => "es256",
    }
}

/// Reads the Context signer's DA declarations (labels and reserve sizes, in
/// registration order). Never requests DA content.
fn declare_dynamic_assertions(
    signer: &dyn crate::Signer,
) -> Result<Vec<DynamicAssertionDeclaration>> {
    signer
        .dynamic_assertions()
        .iter()
        .map(|da| {
            Ok(DynamicAssertionDeclaration {
                label: da.label(),
                reserve_size: da.reserve_size()?,
            })
        })
        .collect()
}

fn signed_media_emsg(
    sign1: coset::CoseSign1,
    timescale: u32,
    event_duration: u32,
    event_id: u32,
) -> Result<Vec<u8>> {
    let cose = sign1
        .to_tagged_vec()
        .map_err(|e| invalid(format!("failed to encode COSE_Sign1: {e}")))?;
    build_emsg_box(&cose, timescale, event_duration, event_id)
}

// ── session ─────────────────────────────────────────────────────────────────

type TrustedCallback = dyn Fn(&VsiSigningContextV1, &[u8]) -> Result<Vec<u8>> + Send + Sync;

struct CallbackSessionSigner(Arc<TrustedCallback>);

impl VsiSessionSigner for CallbackSessionSigner {
    fn sign(&self, purpose: VsiSigningPurpose, sig_structure: &[u8]) -> Result<Vec<u8>> {
        match purpose {
            VsiSigningPurpose::SignerBinding => {
                (self.0)(&VsiSigningContextV1::SIGNER_BINDING, sig_structure)
            }
            VsiSigningPurpose::Vsi { .. } => Err(invalid(
                "trusted init signing must not request media signatures",
            )),
        }
    }
}

/// Callback-backed prehashed trusted VSI session.
///
/// The callback receives V1 metadata and exact Sig_structure bytes and must
/// return a raw 64-byte signature (Ed25519, or ES256 P1363 `r || s`). Operations
/// on one session must be externally serialized.
pub struct TrustedVsiPrehashedSession {
    context: Arc<Context>,
    callback: Arc<TrustedCallback>,
    base_manifest_json: String,
    config: VsiSessionConfig,
    options: TrustedVsiSessionOptions,
    session_cose_key: c2pa_cbor::Value,
    min_sequence_number: u32,
    sequence_max: u32,
    claim_certificate_der: Vec<u8>,
    claim_signer_reserve_size: usize,
    dynamic_assertions: Vec<DynamicAssertionDeclaration>,
    state: SessionState,
}

impl TrustedVsiPrehashedSession {
    /// Returns the prehashed trusted VSI capabilities implemented by this build.
    pub const fn capabilities() -> TrustedVsiCapabilities {
        TrustedVsiCapabilities::current()
    }

    /// Creates a callback-backed session. Validates configuration, public key,
    /// options, and manifest JSON and reads the Context claim signer's public
    /// certificate. Never invokes a signer or callback.
    pub fn from_shared_context_with_callback<F>(
        context: &Arc<Context>,
        manifest_json: impl Into<String>,
        config: VsiSessionConfig,
        options: TrustedVsiSessionOptions,
        callback: F,
    ) -> Result<Self>
    where
        F: Fn(&VsiSigningContextV1, &[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
    {
        let session_cose_key = validate_session_config(&config)?;
        if let c2pa_cbor::Value::Map(map) = &session_cose_key {
            if map.contains_key(&c2pa_cbor::Value::Integer(-4)) {
                return Err(invalid(
                    "session COSE_Key must not contain private key material",
                ));
            }
        }
        let nonce = &options.reservation_nonce;
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid(
                "reservation_nonce must be exactly 32 lowercase hexadecimal characters",
            ));
        }
        let min_sequence_number = u32::try_from(config.min_sequence_number)
            .map_err(|_| invalid("min_sequence_number must fit uint32"))?;
        let sequence_max = options.sequence_max.unwrap_or(u32::MAX);
        if sequence_max < min_sequence_number {
            return Err(invalid(
                "sequence_max must not be below min_sequence_number",
            ));
        }
        ensure_key_valid_at(
            &DateT(config.created_at.clone()),
            config.validity_period_secs,
            options.signing_time_unix_seconds,
        )?;
        let base_manifest_json = super::prepare_live_manifest_json(&manifest_json.into())?;
        let definition: serde_json::Value = serde_json::from_str(&base_manifest_json)
            .map_err(|e| invalid(format!("invalid manifest JSON: {e}")))?;
        if definition.get("label").is_some() {
            return Err(invalid(
                "trusted VSI derives the manifest label; manifest JSON must not set label",
            ));
        }
        if let Some(assertions) = definition.get("assertions").and_then(|a| a.as_array()) {
            for assertion in assertions {
                let label = assertion
                    .get("label")
                    .and_then(|l| l.as_str())
                    .unwrap_or("");
                if label.starts_with(SessionKeys::LABEL) || label.starts_with("c2pa.hash.") {
                    return Err(invalid(format!(
                        "manifest JSON must not contain native-owned assertion {label}"
                    )));
                }
            }
        }
        let claim_signer = context.signer()?;
        let claim_certificate_der = claim_signer
            .certs()?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("context claim signer has no certificate"))?;
        let claim_signer_reserve_size = claim_signer.reserve_size();
        let dynamic_assertions = declare_dynamic_assertions(claim_signer)?;
        let callback: Arc<TrustedCallback> = Arc::new(callback);
        Ok(Self {
            context: Arc::clone(context),
            callback,
            base_manifest_json,
            config,
            options,
            session_cose_key,
            min_sequence_number,
            sequence_max,
            claim_certificate_der,
            claim_signer_reserve_size,
            dynamic_assertions,
            state: SessionState::new(),
        })
    }

    fn mode(&self) -> TrustedVsiMode {
        self.options.mode
    }

    fn derived_uuid(&self, domain: &str) -> Result<String> {
        let nonce = hex::decode(&self.options.reservation_nonce)
            .map_err(|_| invalid("reservation_nonce is not hexadecimal"))?;
        let mut input = b"c2pa-trusted-vsi-v1:".to_vec();
        input.extend_from_slice(domain.as_bytes());
        input.push(0);
        input.extend_from_slice(&nonce);
        let digest = sha256(&input);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Ok(uuid::Builder::from_random_bytes(bytes)
            .into_uuid()
            .hyphenated()
            .to_string())
    }

    fn not_blocked(&self) -> Result<()> {
        if self.state.blocked {
            return Err(invalid(
                "session is blocked after a failed external signing step; import the \
                 pre-operation state into a new session to retry",
            ));
        }
        Ok(())
    }

    fn require_mode(&self, mode: TrustedVsiMode) -> Result<()> {
        if self.mode() != mode {
            return Err(invalid(format!(
                "operation requires mode {mode:?}; session is pinned to {:?}",
                self.mode()
            )));
        }
        Ok(())
    }

    fn require_committed(&self) -> Result<()> {
        if self.state.phase != Phase::Committed {
            return Err(invalid(
                "initialization UUID must be finalized and committed before media signing",
            ));
        }
        Ok(())
    }

    // ── init UUID ───────────────────────────────────────────────────────────

    fn check_reserve_init(&self, format: &str) -> Result<()> {
        self.not_blocked()?;
        match format.trim().to_ascii_lowercase().as_str() {
            "mp4" | "video/mp4" => {}
            _ => {
                return Err(invalid(
                    "trusted VSI init UUID supports only MP4 (video/mp4)",
                ))
            }
        }
        match self.state.phase {
            Phase::New | Phase::InitReserved => Ok(()),
            _ => Err(invalid("initialization UUID was already finalized")),
        }
    }

    /// Reserves the initialization UUID once, freezing the real manifest
    /// label, assertion salts, DA slots and complete box capacity. Repeated
    /// calls return the same reservation. Signs nothing; never invokes the
    /// session callback or DA content.
    pub fn reserve_init_uuid(&mut self, format: &str) -> Result<TrustedVsiInitUuidReservation> {
        self.check_reserve_init(format)?;
        if self.state.phase == Phase::InitReserved {
            return self.init_reservation();
        }

        let mut definition: serde_json::Value = serde_json::from_str(&self.base_manifest_json)
            .map_err(|e| invalid(format!("invalid manifest JSON: {e}")))?;
        let object = definition
            .as_object_mut()
            .ok_or_else(|| invalid("manifest JSON must be an object"))?;
        let manifest_label = format!("urn:c2pa:{}", self.derived_uuid("manifest")?);
        object.insert("label".into(), manifest_label.clone().into());
        if !object.contains_key("instance_id") {
            object.insert(
                "instance_id".into(),
                format!("xmp:iid:{}", self.derived_uuid("instance")?).into(),
            );
        }
        object
            .entry("format")
            .or_insert_with(|| serde_json::Value::from("video/mp4"));
        let definition = serde_json::to_string(&definition)?;

        let mut builder =
            Builder::from_shared_context(&self.context).with_definition(definition)?;
        builder.add_assertion_cbor(
            SessionKeys::LABEL,
            &self.session_keys(build_signer_binding_placeholder(self.config.algorithm)?),
        )?;
        let mut store = builder.to_store()?;
        let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.add_assertion(&hash_template_struct(
            TrustedVsiInputKind::InitHash,
            &[0; 32],
        )?)?;
        let manifest_id = pc.label().to_string();
        if manifest_id != manifest_label {
            return Err(invalid(
                "reserved manifest label does not match the derived label",
            ));
        }
        let signer = self.context.signer()?;
        self.check_claim_signer_declarations()?;
        store.add_dynamic_assertion_placeholders(&signer.dynamic_assertions())?;
        self.check_dynamic_assertion_slots(&store)?;
        let jumbf = store.to_jumbf_internal(self.claim_signer_reserve_size)?;
        let uuid = Store::get_composed_manifest(&jumbf, INIT_FORMAT, &self.context)?;

        self.state.phase = Phase::InitReserved;
        self.state.manifest_id = Some(manifest_id);
        self.state.reserved_jumbf = Some(jumbf);
        self.state.reserved_uuid = Some(uuid);
        self.init_reservation()
    }

    fn session_keys(&self, signer_binding: c2pa_cbor::Value) -> SessionKeys {
        SessionKeys {
            keys: vec![SessionKey {
                key: self.session_cose_key.clone(),
                min_sequence_number: u64::from(self.min_sequence_number),
                created_at: DateT(self.config.created_at.clone()),
                validity_period: self.config.validity_period_secs,
                signer_binding,
            }],
        }
    }

    fn init_reservation(&self) -> Result<TrustedVsiInitUuidReservation> {
        Ok(TrustedVsiInitUuidReservation {
            bytes: self
                .state
                .reserved_uuid
                .clone()
                .ok_or_else(|| invalid("no initialization UUID is reserved"))?,
            manifest_id: self.reserved_manifest_id()?.to_string(),
        })
    }

    /// Returns the manifest ID held by the initialization reservation.
    pub fn reserved_manifest_id(&self) -> Result<&str> {
        self.state
            .manifest_id
            .as_deref()
            .ok_or_else(|| invalid("no initialization UUID is reserved"))
    }

    fn check_finalize_init(&self, canonical_bmff_hash: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.state.phase {
            Phase::InitFinalized | Phase::Committed => {
                if self.state.init_hash_input.as_deref() == Some(canonical_bmff_hash) {
                    return Ok(self.state.signed_uuid.clone());
                }
                Err(invalid(
                    "initialization UUID was already finalized with a different hash input",
                ))
            }
            Phase::New => Err(invalid("no initialization UUID is reserved")),
            Phase::InitReserved => {
                self.not_blocked()?;
                parse_hash_input(TrustedVsiInputKind::InitHash, canonical_bmff_hash)?;
                // DA slot/assignment and signer consistency, before any
                // signerBinding, DA, or claim-signer call.
                self.check_claim_signer_declarations()?;
                let jumbf = self
                    .state
                    .reserved_jumbf
                    .as_deref()
                    .ok_or_else(|| invalid("no initialization UUID is reserved"))?;
                let store = Store::from_jumbf_with_context(
                    jumbf,
                    &mut StatusTracker::default(),
                    &self.context,
                )?;
                self.check_dynamic_assertion_slots(&store)?;
                Ok(None)
            }
        }
    }

    /// Finalizes the reserved UUID with the processor's canonical init
    /// bmff-hash: runs signerBinding and the Context signer's DAs in their
    /// reserved order, signs and verifies the claim, and preserves the exact
    /// reserved UUID length. Identical retries replay the signed bytes.
    pub fn finalize_init_uuid(&mut self, canonical_bmff_hash: &[u8]) -> Result<Vec<u8>> {
        if let Some(signed) = self.check_finalize_init(canonical_bmff_hash)? {
            return Ok(signed);
        }
        let hash = parse_hash_input(TrustedVsiInputKind::InitHash, canonical_bmff_hash)?;
        let reserved_jumbf = self
            .state
            .reserved_jumbf
            .clone()
            .ok_or_else(|| invalid("no initialization UUID is reserved"))?;
        let reserved_uuid_len = self.state.reserved_uuid.as_ref().map_or(0, Vec::len);

        // Local preparation: no external calls yet.
        let mut store = Store::from_jumbf_with_context(
            &reserved_jumbf,
            &mut StatusTracker::default(),
            &self.context,
        )?;
        {
            let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
            pc.update_bmff_hash(hash_template_struct(TrustedVsiInputKind::InitHash, &hash)?)?;
        }

        match self.finalize_init_external(store, reserved_jumbf.len(), reserved_uuid_len) {
            Ok(signed_uuid) => {
                self.state.phase = Phase::InitFinalized;
                self.state.init_hash_input = Some(canonical_bmff_hash.to_vec());
                self.state.signed_uuid = Some(signed_uuid.clone());
                Ok(signed_uuid)
            }
            Err(error) => {
                self.state.blocked = true;
                Err(error)
            }
        }
    }

    fn finalize_init_external(
        &self,
        mut store: Store,
        reserved_jumbf_len: usize,
        reserved_uuid_len: usize,
    ) -> Result<Vec<u8>> {
        let binding = build_signer_binding(
            &self.claim_certificate_der,
            self.config.algorithm,
            &CallbackSessionSigner(Arc::clone(&self.callback)),
            &self.session_cose_key,
        )?;
        let session_keys = c2pa_cbor::to_vec(&self.session_keys(binding))
            .map_err(|e| invalid(format!("failed to encode session keys: {e}")))?;
        {
            let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
            let reserved_len = pc
                .claim_assertion_store()
                .iter()
                .find(|a| a.label_raw() == SessionKeys::LABEL)
                .map(|a| a.assertion().data().len())
                .ok_or_else(|| invalid("reserved manifest has no session-keys assertion"))?;
            if reserved_len != session_keys.len() {
                return Err(invalid("final session-keys assertion changed size"));
            }
            pc.replace_assertion(UserCbor::new(SessionKeys::LABEL, session_keys).to_assertion()?)?;
            pc.clear_data();
        }

        let signer = self.context.signer()?;
        let jumbf = store.sign_manifest_reserved(signer, &self.context, None)?;
        if !self.context.settings().verify.verify_after_sign {
            store.verify_store_strict(None, &self.context)?;
        }
        if jumbf.len() != reserved_jumbf_len {
            return Err(invalid(format!(
                "final manifest store is {} bytes but {reserved_jumbf_len} were reserved",
                jumbf.len()
            )));
        }
        let uuid = Store::get_composed_manifest(&jumbf, INIT_FORMAT, &self.context)?;
        if uuid.len() != reserved_uuid_len {
            return Err(invalid(
                "final UUID box length differs from the reservation",
            ));
        }
        Ok(uuid)
    }

    fn check_commit(&self) -> Result<()> {
        match self.state.phase {
            Phase::InitFinalized | Phase::Committed => self.not_blocked(),
            _ => Err(invalid(
                "initialization UUID must be finalized before commit",
            )),
        }
    }

    /// Activates the finalized initialization after the coordinator durably
    /// recorded it. This is not a publication acknowledgement.
    pub fn commit_init_uuid(&mut self) -> Result<()> {
        self.check_commit()?;
        if self.state.phase == Phase::InitFinalized {
            self.state.phase = Phase::Committed;
            if self.mode() == TrustedVsiMode::SignerComposedEmsg {
                self.state.next_sequence_number = Some(self.min_sequence_number);
                self.state.next_event_id = Some(1);
            }
        }
        Ok(())
    }

    // ── expert mode ─────────────────────────────────────────────────────────

    fn check_expert_sign(&self, sig_structure: &[u8], sequence_number: u32) -> Result<()> {
        self.require_mode(TrustedVsiMode::ExpertSigStructure)?;
        self.not_blocked()?;
        self.require_committed()?;
        if sequence_number < self.min_sequence_number || sequence_number > self.sequence_max {
            return Err(invalid(format!(
                "sequence number {sequence_number} is outside [{}, {}]",
                self.min_sequence_number, self.sequence_max
            )));
        }
        validate_sig_structure(self.config.algorithm, sig_structure)
    }

    /// Signs exact caller-composed Sig_structure bytes and returns only the
    /// verified raw signature. The processor-supplied sequence is passed to
    /// the callback unchanged; the payload is never decoded and no counter,
    /// event, or exhaustion state is kept.
    pub fn sign_sig_structure(
        &mut self,
        sig_structure: &[u8],
        sequence_number: u32,
    ) -> Result<Vec<u8>> {
        self.check_expert_sign(sig_structure, sequence_number)?;
        let context = VsiSigningContextV1 {
            purpose: TrustedVsiSigningPurpose::Vsi,
            sequence_number: Some(sequence_number),
            event_id: None,
            exhaust_after_sign: false,
        };
        let result = (self.callback)(&context, sig_structure).and_then(|signature| {
            verify_raw_session_signature(
                self.config.algorithm,
                &self.session_cose_key,
                sig_structure,
                &signature,
            )?;
            Ok(signature)
        });
        if result.is_err() {
            self.state.blocked = true;
        }
        result
    }

    // ── composed mode ───────────────────────────────────────────────────────

    fn media_placeholder(&self, manifest_id: &str, pending: &PendingMedia) -> Result<Vec<u8>> {
        let info = SegmentInfoMap {
            sequence_number: u64::from(pending.sequence_number),
            bmff_hash: hash_template_value(TrustedVsiInputKind::MediaHash, &[0; 32])?,
            manifest_id: manifest_id.to_string(),
            manifest_uri: None,
        };
        let cose = build_vsi_cose_sign1_dummy(
            &info,
            self.config.algorithm,
            &self.config.kid,
            pending.signing_time_unix_seconds,
        )?;
        build_emsg_box(
            &cose,
            pending.timescale,
            pending.event_duration,
            pending.event_id,
        )
    }

    /// Builds the unsigned VSI COSE_Sign1 for one media segment.
    fn media_sign1(
        &self,
        manifest_id: &str,
        sequence_number: u32,
        signing_time_unix_seconds: i64,
        canonical_bmff_hash: &[u8],
    ) -> Result<coset::CoseSign1> {
        let bmff_hash: c2pa_cbor::Value = c2pa_cbor::from_slice(canonical_bmff_hash)
            .map_err(|e| invalid(format!("hash input is not CBOR: {e}")))?;
        let info = SegmentInfoMap {
            sequence_number: u64::from(sequence_number),
            bmff_hash,
            manifest_id: manifest_id.to_string(),
            manifest_uri: None,
        };
        build_vsi_cose_sign1_unsigned(
            &info,
            self.config.algorithm,
            &self.config.kid,
            signing_time_unix_seconds,
        )
    }

    fn media_context(&self, pending: &PendingMedia) -> VsiSigningContextV1 {
        VsiSigningContextV1 {
            purpose: TrustedVsiSigningPurpose::Vsi,
            sequence_number: Some(pending.sequence_number),
            event_id: Some(pending.event_id),
            exhaust_after_sign: pending.sequence_number == self.sequence_max
                || pending.event_id == u32::MAX,
        }
    }

    fn media_reservation(&self, pending: &PendingMedia) -> TrustedVsiMediaEmsgReservation {
        TrustedVsiMediaEmsgReservation {
            bytes: pending.placeholder.clone(),
            signing_time_unix_seconds: pending.signing_time_unix_seconds,
            timescale: pending.timescale,
            event_duration: pending.event_duration,
            signing_context: self.media_context(pending),
        }
    }

    /// Returns `Some` when an identical reservation is already pending.
    fn check_reserve_media(
        &self,
        sequence_number: u32,
        signing_time_unix_seconds: i64,
        timescale: u32,
        event_duration: u32,
    ) -> Result<Option<TrustedVsiMediaEmsgReservation>> {
        self.require_mode(TrustedVsiMode::SignerComposedEmsg)?;
        self.not_blocked()?;
        self.require_committed()?;
        if let Some(pending) = &self.state.pending_media {
            if pending.sequence_number == sequence_number
                && pending.signing_time_unix_seconds == signing_time_unix_seconds
                && pending.timescale == timescale
                && pending.event_duration == event_duration
            {
                return Ok(Some(self.media_reservation(pending)));
            }
            return Err(invalid("a different media EMSG reservation is pending"));
        }
        if self.state.exhaustion_reason.is_some() {
            return Err(invalid("session identifiers are exhausted"));
        }
        let next = self
            .state
            .next_sequence_number
            .ok_or_else(|| invalid("session has no next sequence"))?;
        if sequence_number != next {
            return Err(invalid(format!(
                "composed media sequence {sequence_number} must equal the next sequence {next}"
            )));
        }
        if timescale == 0 || event_duration == 0 {
            return Err(invalid("timescale and event_duration must be positive"));
        }
        ensure_key_valid_at(
            &DateT(self.config.created_at.clone()),
            self.config.validity_period_secs,
            signing_time_unix_seconds,
        )?;
        Ok(None)
    }

    /// Reserves a complete placeholder EMSG for the supplied sequence, pinning
    /// the allocated event ID, iat, and timing. Signs nothing.
    pub fn reserve_media_emsg_at(
        &mut self,
        sequence_number: u32,
        signing_time_unix_seconds: i64,
        timescale: u32,
        event_duration: u32,
    ) -> Result<TrustedVsiMediaEmsgReservation> {
        if let Some(existing) = self.check_reserve_media(
            sequence_number,
            signing_time_unix_seconds,
            timescale,
            event_duration,
        )? {
            return Ok(existing);
        }
        let mut pending = PendingMedia {
            sequence_number,
            event_id: self
                .state
                .next_event_id
                .ok_or_else(|| invalid("session has no next event"))?,
            signing_time_unix_seconds,
            timescale,
            event_duration,
            placeholder: Vec::new(),
        };
        pending.placeholder = self.media_placeholder(self.reserved_manifest_id()?, &pending)?;
        let reservation = self.media_reservation(&pending);
        self.state.pending_media = Some(pending);
        Ok(reservation)
    }

    fn check_finalize_media(&self, canonical_bmff_hash: &[u8]) -> Result<Option<Vec<u8>>> {
        self.require_mode(TrustedVsiMode::SignerComposedEmsg)?;
        if self.state.pending_media.is_none() {
            return match &self.state.last_media {
                Some(last) if last.hash_input == canonical_bmff_hash => {
                    Ok(Some(last.signed_emsg.clone()))
                }
                _ => Err(invalid("no media EMSG reservation is pending")),
            };
        }
        self.not_blocked()?;
        parse_hash_input(TrustedVsiInputKind::MediaHash, canonical_bmff_hash)?;
        Ok(None)
    }

    /// Finalizes the pending EMSG with the processor's canonical media
    /// bmff-hash. Only the hash and signature change; the complete EMSG length
    /// is preserved. Identical retries of the last finalize replay its bytes.
    pub fn finalize_media_emsg(&mut self, canonical_bmff_hash: &[u8]) -> Result<Vec<u8>> {
        if let Some(signed) = self.check_finalize_media(canonical_bmff_hash)? {
            return Ok(signed);
        }
        let pending = self
            .state
            .pending_media
            .clone()
            .ok_or_else(|| invalid("no media EMSG reservation is pending"))?;
        let mut sign1 = self.media_sign1(
            self.reserved_manifest_id()?,
            pending.sequence_number,
            pending.signing_time_unix_seconds,
            canonical_bmff_hash,
        )?;
        let tbs = sign1.tbs_data(b"");
        let context = self.media_context(&pending);

        let result = (|| {
            let signature = (self.callback)(&context, &tbs)?;
            verify_raw_session_signature(
                self.config.algorithm,
                &self.session_cose_key,
                &tbs,
                &signature,
            )?;
            sign1.signature = signature;
            let emsg = signed_media_emsg(
                sign1,
                pending.timescale,
                pending.event_duration,
                pending.event_id,
            )?;
            if emsg.len() != pending.placeholder.len() {
                return Err(invalid("final EMSG length differs from the reservation"));
            }
            Ok(emsg)
        })();

        match result {
            Ok(emsg) => {
                self.state.pending_media = None;
                self.state.last_media = Some(CompletedMedia {
                    sequence_number: pending.sequence_number,
                    event_id: pending.event_id,
                    signing_time_unix_seconds: pending.signing_time_unix_seconds,
                    timescale: pending.timescale,
                    event_duration: pending.event_duration,
                    hash_input: canonical_bmff_hash.to_vec(),
                    signed_emsg: emsg.clone(),
                });
                if context.exhaust_after_sign {
                    self.state.exhaustion_reason =
                        Some(if pending.sequence_number == self.sequence_max {
                            TrustedVsiExhaustionReason::SequenceMax
                        } else {
                            TrustedVsiExhaustionReason::EventIdMax
                        });
                    self.state.next_sequence_number = None;
                    self.state.next_event_id = None;
                } else {
                    self.state.next_sequence_number = Some(pending.sequence_number + 1);
                    self.state.next_event_id = Some(pending.event_id + 1);
                }
                Ok(emsg)
            }
            Err(error) => {
                self.state.blocked = true;
                Err(error)
            }
        }
    }

    // ── preflight, status, persistence ──────────────────────────────────────

    /// Checks whether an operation would be accepted in the current state
    /// with the supplied inputs. Performs no callbacks, key use, reservation
    /// generation, or state mutation. Unused numeric inputs are ignored.
    #[allow(clippy::too_many_arguments)]
    pub fn preflight(
        &self,
        operation: TrustedVsiOperation,
        data: &[u8],
        sequence_number: u32,
        signing_time_unix_seconds: i64,
        timescale: u32,
        event_duration: u32,
        format: &str,
    ) -> Result<()> {
        match operation {
            TrustedVsiOperation::ReserveInit => self.check_reserve_init(format),
            TrustedVsiOperation::FinalizeInit => self.check_finalize_init(data).map(|_| ()),
            TrustedVsiOperation::CommitInit => self.check_commit(),
            TrustedVsiOperation::ExpertSign => self.check_expert_sign(data, sequence_number),
            TrustedVsiOperation::ReserveMedia => self
                .check_reserve_media(
                    sequence_number,
                    signing_time_unix_seconds,
                    timescale,
                    event_duration,
                )
                .map(|_| ()),
            TrustedVsiOperation::FinalizeMedia => self.check_finalize_media(data).map(|_| ()),
        }
    }

    /// Returns the public session status.
    pub fn status(&self) -> Result<TrustedVsiStatus> {
        let composed_active = self.mode() == TrustedVsiMode::SignerComposedEmsg
            && self.state.phase == Phase::Committed;
        Ok(TrustedVsiStatus {
            init_uuid_committed: self.state.phase == Phase::Committed,
            init_uuid_pending: matches!(
                self.state.phase,
                Phase::InitReserved | Phase::InitFinalized
            ),
            media_emsg_pending: self.state.pending_media.is_some(),
            next_sequence_number: self.state.next_sequence_number.filter(|_| composed_active),
            next_event_id: self.state.next_event_id.filter(|_| composed_active),
            exhausted: self.state.exhaustion_reason.is_some(),
            exhaustion_reason: self.state.exhaustion_reason,
            blocked: self.state.blocked,
        })
    }

    fn identity(&self) -> SessionIdentity {
        SessionIdentity {
            mode: self.mode(),
            algorithm: algorithm_name(self.config.algorithm).to_string(),
            kid: self.config.kid.clone(),
            public_cose_key: self.config.public_cose_key_cbor.clone(),
            min_sequence_number: self.min_sequence_number,
            sequence_max: self.sequence_max,
            created_at: self.config.created_at.clone(),
            validity_period_secs: self.config.validity_period_secs,
            reservation_nonce: self.options.reservation_nonce.clone(),
            signing_time_unix_seconds: self.options.signing_time_unix_seconds,
            manifest_json_sha256: hex::encode(sha256(self.base_manifest_json.as_bytes())),
            claim_signer_certificate_sha256: hex::encode(sha256(&self.claim_certificate_der)),
            claim_signer_reserve_size: self.claim_signer_reserve_size,
            dynamic_assertions: self.dynamic_assertions.clone(),
        }
    }

    /// Exports explicit versioned public state with exact artifacts. Contains
    /// no private keys, callbacks, Context, or heap snapshot. The coordinator
    /// must authenticate and atomically persist these records.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&StateRecord {
            format: STATE_FORMAT.to_string(),
            version: STATE_VERSION,
            identity: self.identity(),
            state: self.state.clone(),
        })
        .map_err(Error::JsonError)
    }

    /// Imports a record into a new, unused session with identical
    /// configuration, options, manifest JSON, and claim-signer certificate.
    /// All artifacts and invariants are validated before any mutation.
    pub fn import_state(&mut self, state: &[u8]) -> Result<()> {
        if self.state != SessionState::new() {
            return Err(invalid(
                "state can be imported only into a new unused session",
            ));
        }
        if state.len() > MAX_STATE_LEN {
            return Err(invalid("state record exceeds 64 MiB"));
        }
        let record: StateRecord = serde_json::from_slice(state)
            .map_err(|e| invalid(format!("invalid trusted VSI state record: {e}")))?;
        if record.format != STATE_FORMAT || record.version != STATE_VERSION {
            return Err(invalid("unsupported trusted VSI state format or version"));
        }
        if record.identity != self.identity() {
            return Err(invalid(
                "state record identity does not match this session's mode, key, options, \
                 manifest, or claim signer",
            ));
        }
        self.validate_state(&record.state)?;
        self.state = record.state;
        Ok(())
    }

    fn validate_state(&self, state: &SessionState) -> Result<()> {
        let reserved = state.phase != Phase::New;
        let finalized = matches!(state.phase, Phase::InitFinalized | Phase::Committed);
        let composed_committed =
            self.mode() == TrustedVsiMode::SignerComposedEmsg && state.phase == Phase::Committed;
        let consistent = reserved == state.manifest_id.is_some()
            && reserved == state.reserved_jumbf.is_some()
            && reserved == state.reserved_uuid.is_some()
            && finalized == state.init_hash_input.is_some()
            && finalized == state.signed_uuid.is_some()
            && (composed_committed
                || (state.next_sequence_number.is_none()
                    && state.next_event_id.is_none()
                    && state.exhaustion_reason.is_none()
                    && state.pending_media.is_none()
                    && state.last_media.is_none()));
        if !consistent {
            return Err(invalid(
                "state record fields are inconsistent with its phase",
            ));
        }
        if let (Some(manifest_id), Some(jumbf), Some(uuid)) = (
            &state.manifest_id,
            &state.reserved_jumbf,
            &state.reserved_uuid,
        ) {
            if Store::get_composed_manifest(jumbf, INIT_FORMAT, &self.context)? != *uuid {
                return Err(invalid(
                    "reserved UUID does not match the reserved manifest store",
                ));
            }
            let store = Store::from_jumbf_with_context(
                jumbf,
                &mut StatusTracker::default(),
                &self.context,
            )?;
            if store.provenance_claim().map(|c| c.label()) != Some(manifest_id.as_str())
                || *manifest_id != format!("urn:c2pa:{}", self.derived_uuid("manifest")?)
            {
                return Err(invalid("reserved manifest identity does not match"));
            }
            self.check_claim_signer_declarations()?;
            self.check_dynamic_assertion_slots(&store)?;
            if let (Some(input), Some(signed)) = (&state.init_hash_input, &state.signed_uuid) {
                self.validate_signed_init(manifest_id, jumbf, uuid, input, signed)?;
            }
        }
        if composed_committed {
            let manifest_id = state.manifest_id.as_deref().unwrap_or_default();
            self.validate_composed_history(manifest_id, state)?;
        }
        Ok(())
    }
}

impl TrustedVsiPrehashedSession {
    /// Requires the Context signer to still declare exactly the DA set and
    /// claim reserve size pinned at construction.
    fn check_claim_signer_declarations(&self) -> Result<()> {
        let signer = self.context.signer()?;
        if signer.reserve_size() != self.claim_signer_reserve_size
            || declare_dynamic_assertions(signer)? != self.dynamic_assertions
        {
            return Err(invalid(
                "context claim signer's dynamic-assertion declarations or reserve size \
                 changed since the session was created",
            ));
        }
        Ok(())
    }

    /// Requires the reserved store's placeholder slots (every assertion after
    /// the native session-keys/bmff-hash assertions) to match the pinned
    /// declarations exactly: count, labels, order, and reserve sizes.
    fn check_dynamic_assertion_slots(&self, store: &Store) -> Result<()> {
        let reject = |why: String| {
            invalid(format!(
                "reserved dynamic-assertion slots do not match the claim signer: {why}"
            ))
        };
        let claim = store
            .provenance_claim()
            .ok_or_else(|| reject("no active manifest".into()))?;
        let assertions = claim.claim_assertion_store();
        let declared = &self.dynamic_assertions;
        let native = [SessionKeys::LABEL, crate::assertions::labels::BMFF_HASH];
        let slots = assertions
            .iter()
            .rev()
            .take_while(|a| {
                let label = a.label_raw();
                !native.iter().any(|n| label.starts_with(n))
            })
            .count();
        if slots != declared.len() {
            return Err(reject(format!(
                "{} declared, {slots} reserved",
                declared.len()
            )));
        }
        let tail = &assertions[assertions.len() - slots..];
        for (slot, declaration) in tail.iter().zip(declared) {
            let data = slot.assertion().data();
            let zeros: Option<Vec<u64>> = c2pa_cbor::from_slice(data).ok();
            if slot.label_raw() != declaration.label
                || data.len() != declaration.reserve_size
                || !zeros.is_some_and(|z| z.iter().all(|v| *v == 0))
            {
                return Err(reject(format!(
                    "slot {} does not match declaration {} ({} bytes)",
                    slot.label(),
                    declaration.label,
                    declaration.reserve_size
                )));
            }
        }
        Ok(())
    }

    /// Verifies an imported finalized init UUID as a genuine signed artifact of
    /// this session: claim signature and store integrity, claim-signer identity,
    /// hard binding equal to the recorded input, pinned session key, and a
    /// signerBinding that verifies over the claim certificate.
    fn validate_signed_init(
        &self,
        manifest_id: &str,
        reserved_jumbf: &[u8],
        reserved_uuid: &[u8],
        init_hash_input: &[u8],
        signed_uuid: &[u8],
    ) -> Result<()> {
        let reject = |why: &str| invalid(format!("signed initialization UUID rejected: {why}"));
        let expected_hash = parse_hash_input(TrustedVsiInputKind::InitHash, init_hash_input)?;
        if signed_uuid.len() != reserved_uuid.len()
            || signed_uuid.get(..UUID_BOX_PREFIX_LEN) != reserved_uuid.get(..UUID_BOX_PREFIX_LEN)
        {
            return Err(reject("shape does not match the reservation"));
        }
        let signed_jumbf = &signed_uuid[UUID_BOX_PREFIX_LEN..];
        if signed_jumbf.len() != reserved_jumbf.len() {
            return Err(reject("manifest store length differs from the reservation"));
        }
        let mut store = Store::from_jumbf_with_context(
            signed_jumbf,
            &mut StatusTracker::default(),
            &self.context,
        )
        .map_err(|e| reject(&format!("manifest store does not parse: {e}")))?;
        if Store::get_composed_manifest(signed_jumbf, INIT_FORMAT, &self.context)? != signed_uuid {
            return Err(reject(
                "UUID box is not the canonical composition of its store",
            ));
        }
        // Claim signature, assertion hashes, and DA content (no asset binding).
        store
            .verify_store_strict(None, &self.context)
            .map_err(|e| reject(&format!("claim verification failed: {e}")))?;

        let reserved_store = Store::from_jumbf_with_context(
            reserved_jumbf,
            &mut StatusTracker::default(),
            &self.context,
        )?;
        let claim = store
            .provenance_claim()
            .ok_or_else(|| reject("no active manifest"))?;
        let reserved_claim = reserved_store
            .provenance_claim()
            .ok_or_else(|| reject("reserved store has no active manifest"))?;
        if claim.label() != manifest_id {
            return Err(reject("manifest identity does not match"));
        }
        let labels = |c: &crate::claim::Claim| -> Vec<String> {
            c.claim_assertion_store()
                .iter()
                .map(|a| a.label())
                .collect()
        };
        if labels(claim) != labels(reserved_claim) {
            return Err(reject("assertions differ from the reservation"));
        }

        // Claim-signer identity must be the pinned Context certificate.
        let sign1 = coset::CoseSign1::from_tagged_slice(claim.signature_val())
            .map_err(|e| reject(&format!("claim signature is not COSE_Sign1: {e}")))?;
        let chain = crate::crypto::cose::cert_chain_from_sign1(&sign1)
            .map_err(|e| reject(&format!("claim signature has no certificate chain: {e}")))?;
        if chain.first().map(Vec::as_slice) != Some(self.claim_certificate_der.as_slice()) {
            return Err(reject("claim was not signed by the pinned claim signer"));
        }

        // Hard binding must be exactly the recorded canonical init input.
        let hashes = claim.bmff_hash_assertions();
        let [binding] = hashes.as_slice() else {
            return Err(reject("expected exactly one bmff-hash assertion"));
        };
        let binding = BmffHash::from_assertion(binding.assertion())
            .map_err(|e| reject(&format!("bmff-hash assertion is invalid: {e}")))?;
        let binding = c2pa_cbor::value::to_value(&binding)
            .map_err(|e| reject(&format!("bmff-hash assertion is invalid: {e}")))?;
        if binding != hash_template_value(TrustedVsiInputKind::InitHash, &expected_hash)? {
            return Err(reject(
                "hard binding does not match the recorded init hash input",
            ));
        }

        // Session key must be the pinned key with a genuine signerBinding.
        let keys = claim
            .claim_assertion_store()
            .iter()
            .find(|a| a.label_raw() == SessionKeys::LABEL)
            .ok_or_else(|| reject("no session-keys assertion"))?;
        let keys = SessionKeys::from_assertion(keys.assertion())
            .map_err(|e| reject(&format!("session-keys assertion is invalid: {e}")))?;
        let [key] = keys.keys.as_slice() else {
            return Err(reject("expected exactly one session key"));
        };
        if keys != self.session_keys(key.signer_binding.clone()) {
            return Err(reject(
                "session key does not match the pinned configuration",
            ));
        }
        let mut tracker = StatusTracker::default();
        if !super::LiveVideoValidator::new().verify_signer_binding(
            key,
            &self.claim_certificate_der,
            &mut tracker,
        )? {
            return Err(reject("signerBinding does not verify"));
        }
        Ok(())
    }

    /// Checks composed counters, terminal state, and the pending reservation
    /// against the completed history, and verifies the cached signed EMSG.
    fn validate_composed_history(&self, manifest_id: &str, state: &SessionState) -> Result<()> {
        let reject = |why: &str| invalid(format!("composed state rejected: {why}"));
        // Sequences and events advance together from (min, 1).
        let event_for = |sequence: u32| (sequence - self.min_sequence_number).checked_add(1);
        let in_range =
            |sequence: u32| (self.min_sequence_number..=self.sequence_max).contains(&sequence);
        match &state.last_media {
            None => {
                if state.exhaustion_reason.is_some()
                    || state.next_sequence_number != Some(self.min_sequence_number)
                    || state.next_event_id != Some(1)
                {
                    return Err(reject("counters do not match an empty media history"));
                }
            }
            Some(last) => {
                if !in_range(last.sequence_number)
                    || event_for(last.sequence_number) != Some(last.event_id)
                {
                    return Err(reject("completed media identifiers are out of order"));
                }
                let terminal_reason = if last.sequence_number == self.sequence_max {
                    Some(TrustedVsiExhaustionReason::SequenceMax)
                } else if last.event_id == u32::MAX {
                    Some(TrustedVsiExhaustionReason::EventIdMax)
                } else {
                    None
                };
                match terminal_reason {
                    Some(_) => {
                        if state.exhaustion_reason != terminal_reason
                            || state.next_sequence_number.is_some()
                            || state.next_event_id.is_some()
                            || state.pending_media.is_some()
                        {
                            return Err(reject("terminal state does not match history"));
                        }
                    }
                    None => {
                        if state.exhaustion_reason.is_some()
                            || state.next_sequence_number != Some(last.sequence_number + 1)
                            || state.next_event_id != Some(last.event_id + 1)
                        {
                            return Err(reject("counters do not follow the last media"));
                        }
                    }
                }
                self.validate_completed_media(manifest_id, last)?;
            }
        }
        if let Some(pending) = &state.pending_media {
            if Some(pending.sequence_number) != state.next_sequence_number
                || Some(pending.event_id) != state.next_event_id
                || pending.timescale == 0
                || pending.event_duration == 0
                || ensure_key_valid_at(
                    &DateT(self.config.created_at.clone()),
                    self.config.validity_period_secs,
                    pending.signing_time_unix_seconds,
                )
                .is_err()
                || self.media_placeholder(manifest_id, pending)? != pending.placeholder
            {
                return Err(reject("pending media reservation is inconsistent"));
            }
        }
        Ok(())
    }

    /// Rebuilds the cached signed EMSG from its recorded metadata and hash and
    /// verifies its signature against the pinned session key.
    fn validate_completed_media(&self, manifest_id: &str, last: &CompletedMedia) -> Result<()> {
        let reject = |why: &str| invalid(format!("completed media record rejected: {why}"));
        parse_hash_input(TrustedVsiInputKind::MediaHash, &last.hash_input)?;
        if last.timescale == 0 || last.event_duration == 0 {
            return Err(reject("timing must be positive"));
        }
        let cose = super::verifiable_segment_info::extract_vsi_emsg_from_segment(&last.signed_emsg)
            .ok()
            .flatten()
            .ok_or_else(|| reject("cached bytes are not one C2PA VSI EMSG"))?
            .message_data;
        let signature = coset::CoseSign1::from_tagged_slice(&cose)
            .map_err(|e| reject(&format!("EMSG payload is not COSE_Sign1: {e}")))?
            .signature;
        let mut sign1 = self.media_sign1(
            manifest_id,
            last.sequence_number,
            last.signing_time_unix_seconds,
            &last.hash_input,
        )?;
        verify_raw_session_signature(
            self.config.algorithm,
            &self.session_cose_key,
            &sign1.tbs_data(b""),
            &signature,
        )
        .map_err(|e| reject(&format!("signature does not verify: {e}")))?;
        sign1.signature = signature;
        let expected =
            signed_media_emsg(sign1, last.timescale, last.event_duration, last.event_id)?;
        if expected != last.signed_emsg {
            return Err(reject("cached EMSG does not match its recorded metadata"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "trusted_vsi_tests.rs"]
mod tests;
