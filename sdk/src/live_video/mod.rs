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

//! Support for C2PA Live Video signing and validation (section 19 of the C2PA Technical Specification).
//!
//! Implements two validation methods:
//!
//! - **Section 19.3** (per-segment C2PA Manifest Box): each segment carries its own C2PA
//!   Manifest with a [`crate::assertions::LiveVideoSegment`] assertion. Use
//!   [`crate::live_video::LiveVideoValidator::validate_media_segment`].
//!
//! - **Section 19.4** (Verifiable Segment Info): the init segment manifest contains a
//!   [`crate::assertions::SessionKeys`] assertion; each media segment carries a COSE_Sign1 in
//!   an `emsg` box. Use [`crate::live_video::LiveVideoValidator::validate_session_keys`] and
//!   [`crate::live_video::LiveVideoValidator::validate_verifiable_segment_info`].
//!
//! # Signing
//!
//! Use [`crate::live_video::LiveVideoSigner`] to sign an init segment and a sequence of media
//! segments.
//!
//! # Validation
//!
//! Use [`crate::live_video::LiveVideoValidator`] to validate a signed live video stream.
//!
//! See [C2PA Technical Specification - Live Video](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#live-video).

mod bmff;
pub(crate) mod cose_key;
mod segment_manifest_validation;
mod session_key_validation;
mod signing;
mod trusted_vsi;
pub mod verifiable_segment_info;
mod vsi_signing;

pub use ed25519_dalek::SigningKey as Ed25519SessionKey;
pub use signing::LiveVideoSigner;
pub use trusted_vsi::{
    TrustedVsiCapabilities, TrustedVsiExhaustionReason, TrustedVsiInitUuidReservation,
    TrustedVsiMediaEmsgReservation, TrustedVsiPrehashedSession, TrustedVsiSignResult,
    TrustedVsiSigningPurpose, TrustedVsiStatus, VsiSigningContextV1,
};
pub use vsi_signing::{
    moof_sequence_number, LiveVideoVsiSigner, VsiSessionConfig, VsiSessionSigner, VsiSigningPurpose,
};

use self::cose_key::kid_from_cose_key;
use crate::{
    assertions::{LiveVideoSegment, SessionKey, SessionKeys},
    error::{Error, Result},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_INIT_INVALID, LIVEVIDEO_MANIFEST_INVALID, LIVEVIDEO_SEGMENT_INVALID,
        LIVEVIDEO_SESSIONKEY_INVALID,
    },
};

/// Builds a [`crate::Context`] from thread-local settings, for callers ([`LiveVideoSigner`],
/// [`LiveVideoVsiSigner`]) that don't yet take an explicit `Context`.
pub(super) fn context_from_thread_local_settings() -> Result<crate::Context> {
    let settings = crate::settings::get_thread_local_settings();
    crate::Context::new().with_settings(settings)
}

/// Normalizes a live manifest definition to the C2PA 2.4 declaration required by section 19.
/// A conflicting caller-provided value is rejected rather than silently overwritten.
pub(super) fn prepare_live_manifest_json(manifest_json: &str) -> Result<String> {
    let mut value: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|e| Error::BadParam(format!("invalid manifest JSON: {e}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::BadParam("manifest JSON must be an object".to_string()))?;

    if let Some(version) = object
        .get("claim_version")
        .and_then(serde_json::Value::as_u64)
    {
        if version != 2 {
            return Err(Error::BadParam(
                "live video requires claim_version 2 for C2PA 2.4".to_string(),
            ));
        }
    }

    let infos = object
        .entry("claim_generator_info")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            Error::BadParam("claim_generator_info must be an array for live video".to_string())
        })?;
    if infos.is_empty() {
        infos.push(serde_json::json!({
            "name": crate::NAME,
            "version": crate::VERSION,
        }));
    }

    let first = infos[0].as_object_mut().ok_or_else(|| {
        Error::BadParam("the first claim_generator_info entry must be an object".to_string())
    })?;
    match first.get("specVersion") {
        Some(serde_json::Value::String(version)) if version == "2.4" => {}
        Some(_) => {
            return Err(Error::BadParam(
                "live video claim_generator_info specVersion conflicts with required value 2.4"
                    .to_string(),
            ));
        }
        None => {
            first.insert(
                "specVersion".to_string(),
                serde_json::Value::String("2.4".to_string()),
            );
        }
    }

    serde_json::to_string(&value)
        .map_err(|e| Error::BadParam(format!("failed to serialize live manifest JSON: {e}")))
}

pub(super) fn is_manifest_integrity_failure(code: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "signingCredential.",
        "claimSignature.",
        "timeStamp.",
        "claim.hardBindings.",
        "assertion.hashedURI.",
        "assertion.dataHash.",
        "assertion.bmffHash.",
        "assertion.boxesHash.",
    ];
    code == crate::validation_results::validation_codes::HARD_BINDINGS_MULTIPLE
        || PREFIXES.iter().any(|prefix| code.starts_with(prefix))
}

/// C2PA UUID identifying a `uuid` box that contains a C2PA Manifest Store.
const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

const MDAT_BOX_TYPE: u32 = 0x6d646174;
const UUID_BOX_TYPE: u32 = 0x75756964;

fn fail_validation(
    description: impl Into<String>,
    status_code: &'static str,
    tracker: &mut StatusTracker,
) -> Result<()> {
    let description: String = description.into();
    log_item!("live_video", description, "LiveVideoValidator")
        .validation_status(status_code)
        .failure(tracker, Error::BadParam(status_code.into()))?;
    Ok(())
}

struct SegmentState {
    sequence_number: u64,
    stream_id: String,
    manifest_id: String,
}

/// Validates a sequence of live video segments against C2PA section 19 rules.
///
/// Supports section [19.3] (per-segment C2PA Manifest Box) and section [19.4] (Verifiable
/// Segment Info). Create one instance per live stream; for 19.4 call
/// [`validate_session_keys`] after [`validate_init_segment`].
///
/// [19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
/// [19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
/// [`validate_session_keys`]: LiveVideoValidator::validate_session_keys
/// [`validate_init_segment`]: LiveVideoValidator::validate_init_segment
pub struct LiveVideoValidator {
    previous_segment: Option<SegmentState>,
    session_keys: Vec<SessionKey>,
    /// The manifest identifier (c2pa URN label) of the trusted manifest that carried the
    /// `c2pa.session-keys` assertion, captured by [`validate_session_keys`]. Every VSI
    /// segment's `manifestId` is checked against this (§19.4.4).
    ///
    /// [`validate_session_keys`]: LiveVideoValidator::validate_session_keys
    expected_manifest_id: Option<String>,
    manifest_box_init_id: Option<String>,
    init_track_id: Option<u32>,
    init_timescale: Option<u32>,
    init_default_sample_duration: Option<u32>,
    seen_emsg_ids: std::collections::HashSet<u32>,
}

impl LiveVideoValidator {
    pub fn new() -> Self {
        Self {
            previous_segment: None,
            session_keys: Vec::new(),
            expected_manifest_id: None,
            manifest_box_init_id: None,
            init_track_id: None,
            init_timescale: None,
            init_default_sample_duration: None,
            seen_emsg_ids: std::collections::HashSet::new(),
        }
    }

    /// Validates an initialization segment ([§19.7.1]).
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn validate_init_segment(
        &mut self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.previous_segment = None;
        self.session_keys.clear();
        self.expected_manifest_id = None;
        self.manifest_box_init_id = None;
        self.init_track_id = None;
        self.init_timescale = None;
        self.init_default_sample_duration = None;
        self.seen_emsg_ids.clear();

        if segment_manifest_validation::segment_contains_box_type(segment_data, MDAT_BOX_TYPE) {
            fail_validation(
                "initialization segment must not contain an mdat box",
                LIVEVIDEO_INIT_INVALID,
                tracker,
            )?;
        }
        match bmff::parse_init_segment(segment_data) {
            Ok(info) => {
                self.init_track_id = Some(info.track_id);
                self.init_timescale = Some(info.timescale);
                self.init_default_sample_duration = info.default_sample_duration;
            }
            Err(error) => {
                fail_validation(
                    format!("invalid initialization segment layout or track timing: {error}"),
                    LIVEVIDEO_INIT_INVALID,
                    tracker,
                )?;
            }
        }
        Ok(())
    }

    /// Records a manifest-level validation failure for a segment ([§19.3]).
    ///
    /// Use this when the segment's C2PA manifest cannot be read or has no active manifest.
    ///
    /// [§19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
    pub fn fail_segment_manifest(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_MANIFEST_INVALID, tracker)
    }

    /// Records an initialization-segment-level validation failure ([§19.7.1]).
    ///
    /// Use this when the init segment's C2PA manifest cannot be read, has no active manifest,
    /// or is not cryptographically valid and trusted.
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn fail_init_manifest(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_INIT_INVALID, tracker)
    }

    /// Records a malformed or unverifiable `c2pa.session-keys` assertion.
    pub fn fail_session_keys(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_SESSIONKEY_INVALID, tracker)
    }

    /// Registers the trusted signed-init manifest as the predecessor of the first §19.3 media
    /// segment.
    pub fn register_manifest_box_init(
        &mut self,
        manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if !manifest_id.starts_with("urn:c2pa:") || manifest_id.len() == "urn:c2pa:".len() {
            return fail_validation(
                "initialization manifest label must be a non-empty urn:c2pa: identifier",
                LIVEVIDEO_INIT_INVALID,
                tracker,
            );
        }
        self.manifest_box_init_id = Some(manifest_id.to_string());
        Ok(())
    }

    /// Validates a media segment using the per-segment C2PA Manifest Box method ([§19.3]).
    ///
    /// [§19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
    pub fn validate_media_segment(
        &mut self,
        segment_data: &[u8],
        manifest_id: &str,
        assertion: &LiveVideoSegment,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        // `fail_validation` logs failures via `StatusTracker::failure`, which under the
        // default `ErrorBehavior::ContinueWhenPossible` returns `Ok(())` even after logging
        // a real failure — so the `?` calls below do not short-circuit on a failed check.
        // Snapshot the failure count so a failed segment doesn't become the trusted
        // continuity baseline for the next one.
        let failures_before = tracker.filter_errors().count();

        self.validate_segment_has_c2pa_or_emsg(segment_data, tracker)?;
        self.validate_continuity_rules(assertion, manifest_id, tracker)?;

        if self.previous_segment.is_none() {
            match (
                self.manifest_box_init_id.as_deref(),
                assertion.previous_manifest_id.as_deref(),
            ) {
                (Some(expected), Some(actual)) if expected == actual => {}
                (Some(_), _) => {
                    fail_validation(
                        "first media segment previousManifestId must reference the signed initialization manifest",
                        LIVEVIDEO_SEGMENT_INVALID,
                        tracker,
                    )?;
                }
                (None, _) => {}
            }
        }

        if let Some(previous) = &self.previous_segment {
            self.validate_sequence_number(assertion, previous, tracker)?;
            self.validate_stream_id(assertion, previous, tracker)?;
        }

        if tracker.filter_errors().count() > failures_before {
            return Ok(());
        }

        self.previous_segment = Some(SegmentState {
            sequence_number: assertion.sequence_number,
            stream_id: assertion.stream_id.clone(),
            manifest_id: manifest_id.to_string(),
        });

        Ok(())
    }

    /// Validates a `c2pa.session-keys` assertion and stores the keys for VSI verification ([§19.4]).
    ///
    /// `ee_cert_der` must be the DER-encoded end-entity certificate of the *trusted* manifest
    /// signer that carried this assertion; each key's `signerBinding` COSE_Sign1 is verified
    /// against it ([§19.7.3]). Per §19.7.3, a key whose `signerBinding` does not verify shall
    /// not be used to validate any media segment — if `ee_cert_der` is `None` (the caller could
    /// not obtain a trusted certificate), no key in this assertion can be verified, so all keys
    /// are rejected rather than accepted unchecked.
    ///
    /// `manifest_id` is the c2pa URN label of that same trusted manifest; every subsequent VSI
    /// segment's `manifestId` is checked against it ([§19.4.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
    /// [§19.4.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_manifest_retrieval_from_the_manifestid_field
    /// [§19.7.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_verifiable_segment_info_validation
    pub fn validate_session_keys(
        &mut self,
        assertion: &SessionKeys,
        manifest_id: &str,
        ee_cert_der: Option<&[u8]>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.session_keys.clear();
        self.expected_manifest_id = None;

        if !manifest_id.starts_with("urn:c2pa:") || manifest_id.len() == "urn:c2pa:".len() {
            return fail_validation(
                "session-keys manifest ID must be a non-empty urn:c2pa: identifier",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        }
        if assertion.keys.is_empty() {
            return fail_validation(
                "session-keys assertion must contain at least one key",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        }

        let Some(cert) = ee_cert_der else {
            return fail_validation(
                "cannot verify session key signerBinding without the manifest signer's \
                 end-entity certificate; per §19.7.3 a key that cannot be verified shall not \
                 be used",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        };

        let mut verified_keys = Vec::with_capacity(assertion.keys.len());
        let mut seen_kids = std::collections::HashSet::new();
        for key in &assertion.keys {
            let Some(kid) = kid_from_cose_key(&key.key).filter(|kid| !kid.is_empty()) else {
                return fail_validation(
                    "session key COSE_Key must include a non-empty kid (key identifier)",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            };
            if !seen_kids.insert(kid) {
                return fail_validation(
                    "session key COSE_Key kid values must be unique",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            if cose_key::signing_alg_from_cose_key(&key.key).is_none()
                || cose_key::cose_key_to_der(&key.key).is_none()
            {
                return fail_validation(
                    "session COSE_Key has an unsupported or inconsistent algorithm/public key",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            if key.validity_period == 0 {
                return fail_validation(
                    "session key validityPeriod must be greater than zero",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            // Per §19.7.3, a key whose signerBinding fails to verify shall not be used to
            // validate any media segment, so it must not be added to `verified_keys` below.
            if !self.verify_signer_binding(key, cert, tracker)? {
                continue;
            }

            verified_keys.push(key.clone());
        }

        self.session_keys = verified_keys;
        self.expected_manifest_id = Some(manifest_id.to_string());
        Ok(())
    }

    /// Validates a media segment using the Verifiable Segment Info method ([§19.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
    pub fn validate_verifiable_segment_info(
        &mut self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.require_session_keys(tracker)?;
        let (parsed, event) = self.extract_and_parse_vsi(segment_data, tracker)?;
        let session_key = self.resolve_session_key(&parsed.sign1, tracker)?;
        let seq_num = parsed.segment_info_map.sequence_number;
        let media_info =
            match bmff::parse_media_segment(segment_data, self.init_default_sample_duration) {
                Ok(info) => info,
                Err(error) => {
                    fail_validation(
                        format!("invalid Milestone 1 media segment layout or timing: {error}"),
                        LIVEVIDEO_SEGMENT_INVALID,
                        tracker,
                    )?;
                    return Ok(());
                }
            };

        // See the comment in `validate_media_segment`: `fail_validation` logs a failure but
        // still returns `Ok(())` under the default tracker, so these `?` calls do not
        // short-circuit on failure. Snapshot the failure count so a failed segment doesn't
        // become the trusted continuity baseline for the next one.
        let failures_before = tracker.filter_errors().count();

        if event.presentation_time_delta != 0 {
            fail_validation(
                "VSI emsg presentation_time_delta must be zero",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        if event.timescale == 0 || self.init_timescale != Some(event.timescale) {
            fail_validation(
                "VSI emsg timescale must be non-zero and match the initialization track timescale",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        if event.event_duration != media_info.duration_ticks {
            fail_validation(
                "VSI emsg event_duration must cover the complete media segment",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        if self.seen_emsg_ids.contains(&event.id) {
            fail_validation(
                "VSI emsg id must be unique within the live session",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        if event.id == 0 {
            fail_validation(
                "VSI emsg id must be nonzero",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }

        self.validate_vsi_manifest_id(&parsed.segment_info_map.manifest_id, tracker)?;
        if seq_num != u64::from(media_info.sequence_number) {
            fail_validation(
                "VSI sequenceNumber must match moof/mfhd.sequence_number",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        if self
            .init_track_id
            .is_some_and(|track_id| track_id != media_info.track_id)
        {
            fail_validation(
                "media segment tfhd track_ID does not match the initialization track_ID",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        self.validate_vsi_sequence_bounds(seq_num, &session_key, tracker)?;
        self.validate_vsi_key_validity(&session_key, &parsed.sign1, tracker)?;
        self.validate_vsi_signature(&parsed.sign1, &session_key, tracker)?;
        self.validate_vsi_sequence_continuity(seq_num, tracker)?;
        self.validate_vsi_bmff_hash(segment_data, &parsed.segment_info_map.bmff_hash, tracker)?;

        if tracker.filter_errors().count() > failures_before {
            return Ok(());
        }

        self.previous_segment = Some(SegmentState {
            sequence_number: seq_num,
            stream_id: String::new(),
            manifest_id: parsed.segment_info_map.manifest_id.clone(),
        });
        self.seen_emsg_ids.insert(event.id);

        Ok(())
    }
}

impl Default for LiveVideoValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod manifest_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn live_manifest_injects_spec_version_without_overwriting_generator() {
        let json = prepare_live_manifest_json(
            r#"{"claim_generator_info":[{"name":"caller","version":"1"}],"assertions":[]}"#,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let info = &value["claim_generator_info"][0];
        assert_eq!(info["name"], "caller");
        assert_eq!(info["specVersion"], "2.4");
    }

    #[test]
    fn live_manifest_rejects_conflicting_spec_version() {
        let error = prepare_live_manifest_json(
            r#"{"claim_generator_info":[{"name":"caller","specVersion":"2.3"}]}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
    }
}

#[cfg(test)]
mod test_helpers;
