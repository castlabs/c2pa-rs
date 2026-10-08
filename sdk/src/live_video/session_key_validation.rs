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

use c2pa_raw_crypto::validator_for_signing_alg;
use coset::TaggedCborSerializable;
use pkcs8::DecodePublicKey;

use super::{
    cose_key::{cose_key_to_der, kid_from_cose_key, signing_alg_from_cose_key},
    fail_validation,
    verifiable_segment_info::{extract_vsi_emsg_from_segment, parse_vsi, ParsedVsi, VsiEmsg},
    LiveVideoValidator,
};
use crate::{
    assertions::SessionKey,
    error::{Error, Result},
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_SEGMENT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
    },
};

impl LiveVideoValidator {
    pub(super) fn require_session_keys(&self, tracker: &mut StatusTracker) -> Result<()> {
        if self.session_keys.is_empty() {
            return fail_validation(
                "no session keys available; validate_session_keys must be called first",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    pub(super) fn extract_and_parse_vsi(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<(ParsedVsi, VsiEmsg)> {
        let event = match extract_vsi_emsg_from_segment(segment_data) {
            Ok(Some(event)) => event,
            Ok(None) => {
                fail_validation(
                    "segment must contain a VSI emsg box (urn:c2pa:verifiable-segment-info)",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                )?;
                return Err(Error::BadParam("livevideo.segment.invalid".into()));
            }
            Err(error) => {
                fail_validation(error.to_string(), LIVEVIDEO_SEGMENT_INVALID, tracker)?;
                return Err(Error::BadParam("livevideo.segment.invalid".into()));
            }
        };

        let parsed = parse_vsi(&event.message_data).map_err(|_| {
            let _ = fail_validation(
                "failed to parse SegmentInfoMap from VSI COSE_Sign1 payload",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
            Error::BadParam("livevideo.segment.invalid".into())
        })?;
        Ok((parsed, event))
    }

    pub(super) fn resolve_session_key(
        &self,
        sign1: &coset::CoseSign1,
        tracker: &mut StatusTracker,
    ) -> Result<SessionKey> {
        let kid = &sign1.unprotected.key_id;
        if kid.is_empty() {
            fail_validation(
                "COSE_Sign1 unprotected header must contain a kid identifying the session key",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
            return Err(Error::BadParam("livevideo.segment.invalid".into()));
        }

        match self.find_session_key_by_kid(kid) {
            Some(sk) => Ok(sk),
            None => {
                // Per §19.7.3: "Validation fails if the key cannot be found ... and shall
                // fail with a failure code of livevideo.segment.invalid."
                fail_validation(
                    "no session key matches the kid in the COSE_Sign1 unprotected header",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                )?;
                Err(Error::BadParam("livevideo.segment.invalid".into()))
            }
        }
    }

    /// Verifies the segment-info-map's `manifestId` matches the trusted manifest that carried
    /// the `c2pa.session-keys` assertion ([§19.4.4]).
    ///
    /// [§19.4.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_manifest_retrieval_from_the_manifestid_field
    pub(super) fn validate_vsi_manifest_id(
        &self,
        manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Some(expected) = &self.expected_manifest_id {
            if manifest_id != expected {
                return fail_validation(
                    format!(
                        "segment-info-map manifestId ({manifest_id:?}) does not match the \
                         verified manifest that carried the session keys ({expected:?})"
                    ),
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                );
            }
        }
        Ok(())
    }

    pub(super) fn validate_vsi_sequence_bounds(
        &self,
        seq_num: u64,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if seq_num < session_key.min_sequence_number {
            return fail_validation(
                "sequenceNumber is below the session key's minSequenceNumber",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    pub(super) fn validate_vsi_key_validity(
        &self,
        session_key: &SessionKey,
        sign1: &coset::CoseSign1,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        // Per §19.7.3, "the segment's presentation time is outside the key's validity period"
        // is a segment-info-map parsing error, coded livevideo.segment.invalid (not
        // livevideo.sessionkey.invalid, which is reserved for signerBinding/shape failures).
        if let Err(msg) = self.check_key_validity_period(session_key, sign1) {
            return fail_validation(msg, LIVEVIDEO_SEGMENT_INVALID, tracker);
        }
        Ok(())
    }

    pub(super) fn validate_vsi_signature(
        &self,
        sign1: &coset::CoseSign1,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Err(msg) = self.verify_cose_sign1(sign1, session_key) {
            return fail_validation(msg, LIVEVIDEO_SEGMENT_INVALID, tracker);
        }
        Ok(())
    }

    pub(super) fn validate_vsi_sequence_continuity(
        &self,
        seq_num: u64,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Some(previous) = &self.previous_segment {
            if seq_num <= previous.sequence_number {
                return fail_validation(
                    "VSI sequenceNumber must be strictly greater than the previous segment's",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                );
            }
        }
        Ok(())
    }

    /// Verifies the segment's BMFF hash against the `bmffHash` in the segment-info-map (§19.7.3).
    ///
    /// `bmffHash` is a mandatory field of the segment-info-map (§19.4.1); a missing or `Null`
    /// value is rejected rather than treated as "nothing to verify", since that would let a
    /// signed COSE_Sign1 bind only `sequenceNumber`/`manifestId` while leaving the actual
    /// segment media completely unverified.
    pub(super) fn validate_vsi_bmff_hash(
        &self,
        segment_data: &[u8],
        bmff_hash_value: &c2pa_cbor::Value,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if bmff_hash_value.is_null() {
            return fail_validation(
                "segment-info-map bmffHash is missing; VSI requires a hash binding the \
                 segment's media bytes",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        let mut bmff_hash: crate::assertions::BmffHash =
            match c2pa_cbor::value::from_value(bmff_hash_value.clone()) {
                Ok(h) => h,
                Err(e) => {
                    return fail_validation(
                        format!("failed to deserialize bmffHash from segment-info-map: {e}"),
                        LIVEVIDEO_SEGMENT_INVALID,
                        tracker,
                    );
                }
            };

        // Per §19.4.1, the `merkle` field shall be absent from a VSI bmffHash.
        if bmff_hash.merkle().is_some() {
            return fail_validation(
                "segment-info-map bmffHash must not contain a merkle field",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        // Per §19.4.1, bmffHash shall contain at least one exclusion-map scoped to the VSI
        // `emsg` box specifically (xpath "/emsg" with a `data` sub-field matching the VSI
        // scheme_id_uri) — not just any "/emsg" exclusion, which could also exclude an
        // unrelated (e.g. SCTE-35) emsg box coexisting in the same segment from the hash.
        let has_vsi_emsg_exclusion = bmff_hash.exclusions().iter().any(|excl| {
            excl.xpath == "/emsg"
                && excl.data.as_deref().is_some_and(|data| {
                    data.iter().any(|d| {
                        d.offset == super::verifiable_segment_info::VSI_URI_OFFSET_IN_EMSG
                            && d.value
                                == super::verifiable_segment_info::VSI_SCHEME_ID_URI.as_bytes()
                    })
                })
        });
        if !has_vsi_emsg_exclusion {
            return fail_validation(
                "segment-info-map bmffHash must contain an exclusion-map for xpath \"/emsg\" \
                 scoped to the VSI scheme_id_uri",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        // bmff_version is `#[serde(skip)]` and doesn't survive the wire; the VSI CDDL
        // fixes this field to `c2pa.hash.bmff.v3` (§19.4.1).
        bmff_hash.set_bmff_version(3);

        if let Err(e) = bmff_hash.verify_in_memory_hash(segment_data, None) {
            return fail_validation(
                format!("segment bmffHash verification failed: {e}"),
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        Ok(())
    }

    fn find_session_key_by_kid(&self, kid: &[u8]) -> Option<SessionKey> {
        self.session_keys
            .iter()
            .find(|sk| {
                kid_from_cose_key(&sk.key)
                    .map(|k| k == kid)
                    .unwrap_or(false)
            })
            .cloned()
    }

    fn check_key_validity_period(
        &self,
        key: &SessionKey,
        sign1: &coset::CoseSign1,
    ) -> std::result::Result<(), String> {
        use chrono::{DateTime, TimeZone, Utc};

        let created_at: DateTime<Utc> =
            key.created_at.0.parse().map_err(|_| {
                "session key createdAt is not a valid RFC 3339 datetime".to_string()
            })?;

        let validity_seconds = i64::try_from(key.validity_period)
            .map_err(|_| "validityPeriod overflow".to_string())?;

        let created_at_seconds = created_at.timestamp();
        let expires_at_seconds = created_at_seconds
            .checked_add(validity_seconds)
            .ok_or_else(|| "session key validity period overflows its createdAt".to_string())?;

        // Per §19.4.1, the protected header's `iat` claims the segment's actual time of
        // signing. Prefer it over wall-clock time so validation done after the fact (e.g.
        // archival/VOD validation of a recorded live stream) checks the segment against the
        // time it was actually produced, not the time it happens to be validated.
        let claimed_time = extract_iat(sign1)?
            .map(|secs| {
                Utc.timestamp_opt(secs, 0)
                    .single()
                    .ok_or_else(|| "session VSI iat is outside the supported range".to_string())
            })
            .transpose()?;
        let uses_iat = claimed_time.is_some();
        let now = claimed_time.unwrap_or_else(Utc::now);

        if now.timestamp() < created_at_seconds {
            return Err(format!(
                "session key is not yet valid: createdAt={}, {}={now}",
                key.created_at.0,
                if uses_iat { "iat" } else { "now" },
            ));
        }
        if now.timestamp() > expires_at_seconds {
            return Err(format!(
                "session key expired: createdAt={}, validityPeriod={}s, {}={now}",
                key.created_at.0,
                key.validity_period,
                if uses_iat { "iat" } else { "now" },
            ));
        }

        Ok(())
    }

    fn verify_cose_sign1(
        &self,
        sign1: &coset::CoseSign1,
        session_key: &SessionKey,
    ) -> std::result::Result<(), String> {
        let tbs = sign1.tbs_data(b"");
        verify_cose_sign1_signature(sign1, &session_key.key, &tbs)
    }

    /// Verifies the `signerBinding` detached COSE_Sign1 on a session key (§18.25.2).
    ///
    /// Per the spec the `signerBinding` is signed by the **session key** and the
    /// detached payload is the signer's end-entity certificate encoded as a CBOR
    /// byte string.  Verification uses the session key's public key (from the
    /// `key` field of the session-key object).
    /// Returns `Ok(true)` if the key's `signerBinding` verifies against `ee_cert_der`,
    /// `Ok(false)` if it does not (a `livevideo.sessionkey.invalid` failure is recorded on
    /// `tracker` in that case), or `Err` for an unexpected internal error unrelated to the
    /// binding's validity.
    ///
    /// Per §19.7.3, a key whose `signerBinding` does not verify shall not be used to validate
    /// any media segment — callers must not treat this key as trusted when this returns `false`.
    pub(super) fn verify_signer_binding(
        &self,
        key: &SessionKey,
        ee_cert_der: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<bool> {
        let binding_bytes = extract_signer_binding_bytes(&key.signer_binding);
        let binding_bytes = match &binding_bytes {
            Some(b) if !b.is_empty() => b,
            _ => {
                return reject_signer_binding(
                    "session key signerBinding must be a non-empty COSE_Sign1_Tagged byte string",
                    tracker,
                );
            }
        };

        let sign1 = match coset::CoseSign1::from_tagged_slice(binding_bytes) {
            Ok(s) => s,
            Err(e) => {
                return reject_signer_binding(
                    format!("failed to parse signerBinding as COSE_Sign1: {e}"),
                    tracker,
                )
            }
        };

        if sign1.payload.is_some() {
            return reject_signer_binding(
                "session key signerBinding payload must be detached",
                tracker,
            );
        }

        let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
            .map_err(|e| {
                let _ = fail_validation(
                    format!("failed to CBOR-encode EE certificate for signerBinding: {e}"),
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
                Error::BadParam("livevideo.sessionkey.invalid".into())
            })?;

        // signerBinding is a detached-payload COSE_Sign1: the cert bytes are the
        // external payload, not AAD. Use tbs_detached_data per RFC 9052 §4.4.
        let tbs = sign1.tbs_detached_data(&external_payload, b"");
        if let Err(e) = verify_cose_sign1_signature(&sign1, &key.key, &tbs) {
            return reject_signer_binding(
                format!("signerBinding signature verification failed: {e}"),
                tracker,
            );
        }

        Ok(true)
    }
}

/// Verifies a COSE_Sign1 signature over an already assembled Sig_structure.
///
/// Signing and recovery use this same path as validation so callback output is
/// checked against the published COSE_Key before any bytes or state are committed.
pub(super) fn verify_cose_sign1_signature(
    sign1: &coset::CoseSign1,
    cose_key: &c2pa_cbor::Value,
    tbs: &[u8],
) -> std::result::Result<(), String> {
    let alg = signing_alg_from_cose_key(cose_key).ok_or_else(|| {
        "unsupported or inconsistent key type, curve, or alg in session COSE_Key".to_string()
    })?;

    let protected_alg = crate::crypto::cose::signing_alg_from_sign1(sign1)
        .map_err(|_| "COSE_Sign1 must contain a supported protected alg".to_string())?;
    if protected_alg != alg || sign1.unprotected.alg.is_some() {
        return Err(
            "COSE_Sign1 protected alg must agree with the session COSE_Key and must not be duplicated in the unprotected header"
                .to_string(),
        );
    }

    let public_key_der = cose_key_to_der(cose_key)
        .ok_or_else(|| "failed to convert session key to DER".to_string())?;

    // Keep Ed25519 validation strict across signing, normal validation, and
    // artifact recovery. This rejects non-canonical and weak-key signatures
    // that a backend's generic Ed25519 verifier might otherwise accept.
    if alg == crate::SigningAlg::Ed25519 {
        let public_key = ed25519_dalek::VerifyingKey::from_public_key_der(&public_key_der)
            .map_err(|e| format!("invalid Ed25519 session public key: {e}"))?;
        let signature = ed25519_dalek::Signature::try_from(sign1.signature.as_slice())
            .map_err(|e| format!("invalid Ed25519 session signature encoding: {e}"))?;
        return public_key
            .verify_strict(tbs, &signature)
            .map_err(|e| format!("COSE_Sign1 signature verification failed: {e}"));
    }

    let validator = validator_for_signing_alg(alg)
        .ok_or_else(|| format!("no validator available for {alg:?}"))?;

    validator
        .validate(&sign1.signature, tbs, &public_key_der)
        .map_err(|e| format!("COSE_Sign1 signature verification failed: {e}"))
}

/// Records a `livevideo.sessionkey.invalid` failure and returns `Ok(false)`, the shared shape
/// of every rejection branch in [`LiveVideoValidator::verify_signer_binding`].
fn reject_signer_binding(msg: impl Into<String>, tracker: &mut StatusTracker) -> Result<bool> {
    fail_validation(msg, LIVEVIDEO_SESSIONKEY_INVALID, tracker)?;
    Ok(false)
}

/// Extracts the `iat` ("claimed time of signing", §19.4.1/RFC 8392) protected header field, if
/// present, as a Unix timestamp in seconds.
fn extract_iat(sign1: &coset::CoseSign1) -> std::result::Result<Option<i64>, String> {
    let mut values = sign1
        .protected
        .header
        .rest
        .iter()
        .filter(|(label, _)| matches!(label, coset::Label::Text(s) if s == "iat"));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("COSE_Sign1 protected header contains duplicate iat values".to_string());
    }
    let integer = value
        .as_integer()
        .ok_or_else(|| "COSE_Sign1 protected iat must be an integer NumericDate".to_string())?;
    let seconds = i64::try_from(integer)
        .map_err(|_| "COSE_Sign1 protected iat is outside the supported range".to_string())?;
    Ok(Some(seconds))
}

/// Extracts raw COSE_Sign1_Tagged bytes from a `signerBinding` CBOR value.
///
/// The value may appear in different forms depending on the serialization roundtrip:
/// - `Value::Array` with 4 elements — COSE_Sign1 inner content, possibly from JSON roundtrip
///   where byte strings become integer arrays. Re-serialized with tag 18.
/// - `Value::Array` of integers — legacy: flat byte representation of tagged COSE_Sign1 bytes
/// - `Value::Bytes` — direct CBOR byte string (ideal CBOR-only case)
/// - `Value::Text` — base64-encoded string (serde_json with base64 for bytes)
pub(super) fn extract_signer_binding_bytes(value: &c2pa_cbor::Value) -> Option<Vec<u8>> {
    match value {
        c2pa_cbor::Value::Array(items) if is_cose_sign1_array(items) => {
            // COSE_Sign1 inner array [protected, unprotected, payload, signature].
            // After a JSON roundtrip, bstr elements become integer arrays — coerce
            // them back to Bytes so that the CBOR re-serialization is spec-correct.
            let fixed =
                c2pa_cbor::Value::Array(items.iter().map(coerce_int_array_to_bytes).collect());
            let mut buf = Vec::new();
            c2pa_cbor::tags::encode_tagged(&mut buf, 18, &fixed).ok()?;
            Some(buf)
        }
        // Legacy: flat array of integers (Value::Bytes after JSON roundtrip)
        c2pa_cbor::Value::Array(items) => items
            .iter()
            .map(|v| match v {
                c2pa_cbor::Value::Integer(i) => u8::try_from(*i).ok(),
                _ => None,
            })
            .collect(),
        c2pa_cbor::Value::Bytes(bytes) => Some(bytes.clone()),
        c2pa_cbor::Value::Text(text) => {
            use base64::{engine::general_purpose, Engine};
            general_purpose::STANDARD
                .decode(text)
                .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(text))
                .ok()
        }
        _ => None,
    }
}

/// Returns true if the array looks like a COSE_Sign1 structure (4 elements
/// where not all are plain integers).
fn is_cose_sign1_array(items: &[c2pa_cbor::Value]) -> bool {
    items.len() == 4
        && items
            .iter()
            .any(|v| !matches!(v, c2pa_cbor::Value::Integer(_)))
}

/// If the value is an array of integers (from a JSON roundtrip of a CBOR bstr),
/// convert it back to `Value::Bytes`. Otherwise return the value unchanged.
fn coerce_int_array_to_bytes(value: &c2pa_cbor::Value) -> c2pa_cbor::Value {
    if let c2pa_cbor::Value::Array(items) = value {
        if let Some(bytes) = items
            .iter()
            .map(|v| match v {
                c2pa_cbor::Value::Integer(i) => u8::try_from(*i).ok(),
                _ => None,
            })
            .collect::<Option<Vec<u8>>>()
        {
            return c2pa_cbor::Value::Bytes(bytes);
        }
    }
    value.clone()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use coset::TaggedCborSerializable;

    use super::super::{test_helpers::*, LiveVideoValidator};
    #[cfg(feature = "rust_native_crypto")]
    use super::super::{LIVEVIDEO_SEGMENT_GAP, LIVEVIDEO_SEGMENT_LEADING_GAP};
    #[cfg(feature = "rust_native_crypto")]
    use crate::status_tracker::{ErrorBehavior, LogKind, StatusTracker};
    use crate::{
        assertions::{SessionKey, SessionKeys},
        cbor_types::DateT,
        validation_results::validation_codes::{
            LIVEVIDEO_SEGMENT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
        },
    };

    fn cbor_int(val: i64) -> c2pa_cbor::Value {
        c2pa_cbor::Value::Integer(val)
    }

    fn minimal_session_keys() -> SessionKeys {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(1), cbor_int(2)); // kty: EC2
        map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(b"k".to_vec())); // kid
        map.insert(cbor_int(3), cbor_int(-7)); // alg: ES256
        map.insert(cbor_int(-1), cbor_int(1)); // crv: P-256
        map.insert(cbor_int(-2), c2pa_cbor::Value::Bytes(vec![0; 32]));
        map.insert(cbor_int(-3), c2pa_cbor::Value::Bytes(vec![0; 32]));

        SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(map),
                min_sequence_number: 0,
                created_at: DateT(chrono::Utc::now().to_rfc3339()),
                validity_period: 3600,
                signer_binding: c2pa_cbor::Value::Bytes(vec![]),
            }],
        }
    }

    /// Builds an `emsg` version 0 box with C2PA VSI scheme carrying `message_data`.
    #[cfg(feature = "rust_native_crypto")]
    fn make_vsi_emsg_box(message_data: &[u8]) -> Vec<u8> {
        make_vsi_emsg_box_with_timing(message_data, 1, 1, 0)
    }

    #[cfg(feature = "rust_native_crypto")]
    fn make_vsi_emsg_box_with_timing(
        message_data: &[u8],
        timescale: u32,
        event_duration: u32,
        id: u32,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"urn:c2pa:verifiable-segment-info\0");
        body.extend_from_slice(b"fseg\0");
        body.extend_from_slice(&timescale.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&event_duration.to_be_bytes());
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(message_data);

        let total_size = (8u32 + 4 + body.len() as u32).to_be_bytes();
        let mut emsg = Vec::new();
        emsg.extend_from_slice(&total_size);
        emsg.extend_from_slice(b"emsg");
        emsg.push(0); // version 0
        emsg.extend_from_slice(&[0u8; 3]); // flags
        emsg.extend_from_slice(&body);
        emsg
    }

    #[cfg(feature = "rust_native_crypto")]
    mod vsi_crypto_helpers {
        use super::*;
        use crate::{
            live_video::verifiable_segment_info::SegmentInfoMap, status_tracker::StatusTracker,
        };

        pub const TEST_KID: &[u8] = b"test-key-1";
        /// A stand-in for the label of the manifest that carried the session-keys assertion.
        /// Kept constant across a test's segments since `validate_vsi_manifest_id` now checks
        /// every VSI segment's `manifestId` against the trusted manifest captured at
        /// `validate_session_keys` time (§19.4.4).
        pub const TEST_MANIFEST_ID: &str = "urn:c2pa:test-manifest";

        pub fn test_ee_cert_der() -> Vec<u8> {
            let signer =
                crate::utils::ephemeral_signer::EphemeralSigner::new("test-vsi-validation.local")
                    .unwrap();
            signer.cert_chain_der[0].clone()
        }

        pub fn generate_test_key_pair() -> (p256::ecdsa::SigningKey, c2pa_cbor::Value) {
            let signing_key = p256::ecdsa::SigningKey::random(&mut rand_core_06::OsRng);
            let verifying_key = signing_key.verifying_key();
            let point = verifying_key.to_encoded_point(false);

            let mut map = std::collections::BTreeMap::new();
            map.insert(cbor_int(1), cbor_int(2)); // kty: EC2
            map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(TEST_KID.to_vec()));
            map.insert(cbor_int(3), cbor_int(-7)); // alg: ES256
            map.insert(cbor_int(-1), cbor_int(1)); // crv: P-256
            map.insert(
                cbor_int(-2),
                c2pa_cbor::Value::Bytes(point.x().unwrap().to_vec()),
            );
            map.insert(
                cbor_int(-3),
                c2pa_cbor::Value::Bytes(point.y().unwrap().to_vec()),
            );

            (signing_key, c2pa_cbor::Value::Map(map))
        }

        /// Builds a `signerBinding` detached COSE_Sign1 (§18.25.2) for a P-256 session key.
        pub fn make_signer_binding_for_ee_cert_p256(
            session_signing_key: &p256::ecdsa::SigningKey,
            ee_cert_der: &[u8],
        ) -> Vec<u8> {
            use coset::{iana, HeaderBuilder, TaggedCborSerializable};
            use p256::ecdsa::{signature::Signer, Signature};

            let external_payload =
                c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec())).unwrap();

            let protected = HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build();
            let mut sign1 = coset::CoseSign1Builder::new().protected(protected).build();

            let tbs = sign1.tbs_detached_data(&external_payload, b"");
            let sig: Signature = session_signing_key.sign(&tbs);
            sign1.signature = sig.to_bytes().to_vec();
            sign1.to_tagged_vec().unwrap()
        }

        /// Builds a `SessionKeys` assertion with a real `signerBinding` over `ee_cert_der`, so
        /// `validate_session_keys`'s now-mandatory signerBinding check succeeds.
        pub fn session_keys_with_cose_key(
            cose_key: c2pa_cbor::Value,
            signing_key: &p256::ecdsa::SigningKey,
            ee_cert_der: &[u8],
        ) -> SessionKeys {
            let binding = make_signer_binding_for_ee_cert_p256(signing_key, ee_cert_der);
            SessionKeys {
                keys: vec![SessionKey {
                    key: cose_key,
                    min_sequence_number: 0,
                    created_at: DateT(chrono::Utc::now().to_rfc3339()),
                    validity_period: 3600,
                    signer_binding: c2pa_cbor::Value::Bytes(binding),
                }],
            }
        }

        fn make_signed_cose_sign1_with_kid(
            segment_info_map: &SegmentInfoMap,
            signing_key: &p256::ecdsa::SigningKey,
            kid: &[u8],
        ) -> Vec<u8> {
            use coset::{iana, HeaderBuilder, TaggedCborSerializable};
            use p256::ecdsa::{signature::Signer, Signature};

            let payload = c2pa_cbor::to_vec(segment_info_map).unwrap();

            let protected = HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build();

            let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();

            let mut sign1 = coset::CoseSign1Builder::new()
                .protected(protected)
                .unprotected(unprotected)
                .payload(payload)
                .build();

            let tbs = sign1.tbs_data(b"");
            let sig: Signature = signing_key.sign(&tbs);
            sign1.signature = sig.to_bytes().to_vec();

            sign1.to_tagged_vec().unwrap()
        }

        /// Builds a fully VSI-conformant signed media segment: a real, two-pass
        /// `c2pa.hash.bmff.v3` `bmffHash` (matching production's
        /// `LiveVideoVsiSigner::sign_media_segment`) over the `emsg` box plus a trailing
        /// `mdat` box, so `validate_vsi_bmff_hash`'s now-mandatory hash check succeeds.
        pub fn make_signed_vsi_segment(
            sequence_number: u64,
            manifest_id: &str,
            signing_key: &p256::ecdsa::SigningKey,
        ) -> Vec<u8> {
            make_signed_vsi_segment_with_ids(
                sequence_number,
                manifest_id,
                signing_key,
                TEST_KID,
                u32::try_from(sequence_number).unwrap(),
            )
        }

        pub fn make_signed_vsi_segment_with_ids(
            sequence_number: u64,
            manifest_id: &str,
            signing_key: &p256::ecdsa::SigningKey,
            kid: &[u8],
            event_id: u32,
        ) -> Vec<u8> {
            fn bmff_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
                let mut data = Vec::new();
                data.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
                data.extend_from_slice(box_type);
                data.extend_from_slice(payload);
                data
            }

            fn full_box(box_type: &[u8; 4], flags: u32, payload: &[u8]) -> Vec<u8> {
                let mut body = vec![0];
                body.extend_from_slice(&flags.to_be_bytes()[1..]);
                body.extend_from_slice(payload);
                bmff_box(box_type, &body)
            }

            let sequence_number_u32 = u32::try_from(sequence_number).unwrap();
            let mfhd = full_box(b"mfhd", 0, &sequence_number_u32.to_be_bytes());
            let mut tfhd_payload = 1u32.to_be_bytes().to_vec();
            tfhd_payload.extend_from_slice(&1000u32.to_be_bytes());
            let tfhd = full_box(b"tfhd", 0x000008, &tfhd_payload);
            let trun = full_box(b"trun", 0, &1u32.to_be_bytes());
            let traf = bmff_box(b"traf", &[tfhd, trun].concat());
            let trailer = [bmff_box(b"moof", &[mfhd, traf].concat()), make_mdat_box()].concat();
            let build = |bmff_hash: c2pa_cbor::Value| -> Vec<u8> {
                let map = SegmentInfoMap {
                    sequence_number,
                    bmff_hash,
                    manifest_id: manifest_id.to_string(),
                    manifest_uri: None,
                };
                let mut seg = super::make_vsi_emsg_box_with_timing(
                    &make_signed_cose_sign1_with_kid(&map, signing_key, kid),
                    1000,
                    1000,
                    event_id,
                );
                seg.extend_from_slice(&trailer);
                seg
            };

            let draft = build(
                crate::live_video::vsi_signing::build_segment_bmff_hash_placeholder().unwrap(),
            );
            let real_hash =
                crate::live_video::vsi_signing::build_segment_bmff_hash(&draft).unwrap();
            let signed = build(real_hash);
            assert_eq!(
                draft.len(),
                signed.len(),
                "draft/final VSI test segment size mismatch"
            );
            signed
        }

        pub fn setup_vsi_validator() -> (LiveVideoValidator, p256::ecdsa::SigningKey) {
            let (signing_key, cose_key) = generate_test_key_pair();
            let ee_cert_der = test_ee_cert_der();
            let mut validator = LiveVideoValidator::new();
            validator.init_track_id = Some(1);
            validator.init_timescale = Some(1000);
            validator.init_default_sample_duration = Some(1000);
            let mut tracker = StatusTracker::default();
            let keys = session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der);
            validator
                .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
                .unwrap();
            (validator, signing_key)
        }
    }

    #[cfg(feature = "rust_native_crypto")]
    fn update_init(track: u32, timescale: u32, duration: u32) -> Vec<u8> {
        fn boxed(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
            [
                u32::try_from(data.len() + 8)
                    .unwrap()
                    .to_be_bytes()
                    .as_slice(),
                kind,
                data,
            ]
            .concat()
        }
        let tkhd = boxed(
            b"tkhd",
            &[vec![0; 12], track.to_be_bytes().to_vec()].concat(),
        );
        let mdhd = boxed(
            b"mdhd",
            &[vec![0; 12], timescale.to_be_bytes().to_vec(), vec![0; 8]].concat(),
        );
        let trak = boxed(b"trak", &[tkhd, boxed(b"mdia", &mdhd)].concat());
        let trex = boxed(
            b"trex",
            &[
                vec![0; 4],
                track.to_be_bytes().to_vec(),
                1u32.to_be_bytes().to_vec(),
                duration.to_be_bytes().to_vec(),
                vec![0; 8],
            ]
            .concat(),
        );
        boxed(b"moov", &[trak, boxed(b"mvex", &trex)].concat())
    }

    #[test]
    #[cfg(feature = "rust_native_crypto")]
    fn vsi_update_preserves_sequence_replay_coverage_and_rotates_all_keys() {
        use vsi_crypto_helpers::*;
        for stop in [false, true] {
            let new_tracker = || {
                StatusTracker::with_error_behavior(if stop {
                    ErrorBehavior::StopOnFirstError
                } else {
                    ErrorBehavior::ContinueWhenPossible
                })
            };
            let (mut validator, old_key) = setup_vsi_validator();
            let mut tracker = new_tracker();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &old_key),
                    &mut tracker,
                )
                .unwrap();
            let cert = test_ee_cert_der();
            let (key, cose) = generate_test_key_pair();
            let mut keys = session_keys_with_cose_key(cose, &key, &cert);
            let (second_key, mut second_cose) = generate_test_key_pair();
            if let c2pa_cbor::Value::Map(map) = &mut second_cose {
                map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(b"second".to_vec()));
            }
            keys.keys
                .extend(session_keys_with_cose_key(second_cose, &second_key, &cert).keys);
            let init = update_init(1, 1000, 1000);
            for candidate_init in [Some(init.as_slice()), None, Some(init.as_slice())] {
                validator
                    .update_vsi_context(
                        candidate_init,
                        &keys,
                        "urn:c2pa:rotated",
                        Some(&cert),
                        &mut tracker,
                    )
                    .unwrap();
                assert_eq!(
                    validator.previous_segment.as_ref().unwrap().sequence_number,
                    5
                );
                assert!(validator.seen_emsg_ids.contains(&5));
                assert_eq!(validator.sequence_coverage().missing_ranges, vec![0..=4]);
                assert_eq!(validator.session_keys.len(), 2);
            }
            for (seq, manifest, signing_key, event_id) in [
                (5, "urn:c2pa:rotated", &key, 50),
                (4, "urn:c2pa:rotated", &key, 40),
                (6, "urn:c2pa:rotated", &key, 5),
                (6, TEST_MANIFEST_ID, &key, 6),
                (6, TEST_MANIFEST_ID, &old_key, 6),
            ] {
                let mut rejected = new_tracker();
                let _ = validator.validate_verifiable_segment_info(
                    &make_signed_vsi_segment_with_ids(
                        seq,
                        manifest,
                        signing_key,
                        TEST_KID,
                        event_id,
                    ),
                    &mut rejected,
                );
                assert!(rejected.filter_errors().count() > 0);
                assert_eq!(
                    validator.previous_segment.as_ref().unwrap().sequence_number,
                    5
                );
            }
            let mut rejected = new_tracker();
            let _ = validator.validate_verifiable_segment_info(
                &make_signed_vsi_segment(6, "urn:c2pa:rotated", &old_key),
                &mut rejected,
            );
            let failures: Vec<_> = rejected.filter_errors().collect();
            assert_eq!(failures.len(), 1);
            assert!(failures[0]
                .description
                .contains("signature verification failed"));
            assert_eq!(
                validator.previous_segment.as_ref().unwrap().sequence_number,
                5
            );
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(8, "urn:c2pa:rotated", &key),
                    &mut tracker,
                )
                .unwrap();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment_with_ids(
                        9,
                        "urn:c2pa:rotated",
                        &second_key,
                        b"second",
                        9,
                    ),
                    &mut tracker,
                )
                .unwrap();
            assert_eq!(
                validator.sequence_coverage().missing_ranges,
                vec![0..=4, 6..=7]
            );
            let (replacement_key, replacement_cose) = generate_test_key_pair();
            let mut replacement =
                session_keys_with_cose_key(replacement_cose, &replacement_key, &cert);
            replacement.keys[0].min_sequence_number = 12;
            validator
                .update_vsi_context(
                    None,
                    &replacement,
                    "urn:c2pa:key-only",
                    Some(&cert),
                    &mut tracker,
                )
                .unwrap();
            assert_eq!(
                validator.previous_segment.as_ref().unwrap().sequence_number,
                9
            );
            assert!(validator.seen_emsg_ids.contains(&5));
            for (seq, signing_key, kid, expected_failure) in [
                (
                    10,
                    &replacement_key,
                    TEST_KID,
                    "below the session key's minSequenceNumber",
                ),
                (
                    12,
                    &second_key,
                    b"second".as_slice(),
                    "no session key matches the kid",
                ),
            ] {
                let mut rejected = new_tracker();
                let _ = validator.validate_verifiable_segment_info(
                    &make_signed_vsi_segment_with_ids(
                        seq,
                        "urn:c2pa:key-only",
                        signing_key,
                        kid,
                        seq as u32,
                    ),
                    &mut rejected,
                );
                let failures: Vec<_> = rejected.filter_errors().collect();
                assert_eq!(failures.len(), 1);
                assert!(failures[0].description.contains(expected_failure));
                assert_eq!(
                    validator.previous_segment.as_ref().unwrap().sequence_number,
                    9
                );
                assert!(!validator.seen_emsg_ids.contains(&(seq as u32)));
                assert_eq!(
                    validator.sequence_coverage().missing_ranges,
                    vec![0..=4, 6..=7]
                );
            }
            let mut after_rotation = new_tracker();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(12, "urn:c2pa:key-only", &replacement_key),
                    &mut after_rotation,
                )
                .unwrap();
            assert_eq!(
                validator.sequence_coverage().missing_ranges,
                vec![0..=4, 6..=7, 10..=11]
            );
            assert!(after_rotation.has_status(LIVEVIDEO_SEGMENT_GAP));
            assert!(!after_rotation.has_status(LIVEVIDEO_SEGMENT_LEADING_GAP));
            assert_eq!(after_rotation.filter_errors().count(), 0);
            assert_eq!(tracker.filter_errors().count(), 0);
        }
    }

    #[test]
    #[cfg(feature = "rust_native_crypto")]
    fn vsi_update_rejects_candidates_atomically_in_both_tracker_modes() {
        use vsi_crypto_helpers::*;
        for stop in [false, true] {
            let new_tracker = || {
                StatusTracker::with_error_behavior(if stop {
                    ErrorBehavior::StopOnFirstError
                } else {
                    ErrorBehavior::ContinueWhenPossible
                })
            };
            let (mut validator, old_key) = setup_vsi_validator();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &old_key),
                    &mut StatusTracker::default(),
                )
                .unwrap();
            let cert = test_ee_cert_der();
            let (key, cose) = generate_test_key_pair();
            let keys = session_keys_with_cose_key(cose, &key, &cert);
            let mut mixed = keys.clone();
            let mut bad = keys.keys[0].clone();
            if let c2pa_cbor::Value::Map(map) = &mut bad.key {
                map.insert(
                    cbor_int(2),
                    c2pa_cbor::Value::Bytes(b"bad-binding".to_vec()),
                );
            }
            bad.signer_binding = c2pa_cbor::Value::Bytes(vec![]);
            mixed.keys.push(bad);
            let mut duplicate = keys.clone();
            duplicate.keys.push(keys.keys[0].clone());
            let empty = SessionKeys { keys: vec![] };
            let invalid_inits = [
                vec![],
                update_init(2, 1000, 1000),
                update_init(1, 2000, 1000),
                update_init(1, 1000, 2000),
                update_init(1, 1000, 0),
                [update_init(1, 1000, 1000), make_mdat_box()].concat(),
            ];
            for init in &invalid_inits {
                assert!(validator
                    .update_vsi_context(
                        Some(init),
                        &keys,
                        "urn:c2pa:new",
                        Some(&cert),
                        &mut new_tracker()
                    )
                    .is_err());
            }
            for (assertion, manifest, certificate) in [
                (&mixed, "urn:c2pa:new", Some(cert.as_slice())),
                (&duplicate, "urn:c2pa:new", Some(cert.as_slice())),
                (&empty, "urn:c2pa:new", Some(cert.as_slice())),
                (&keys, "invalid", Some(cert.as_slice())),
                (&keys, "urn:c2pa:new", None),
                (&keys, "urn:c2pa:new", Some(b"invalid-cert".as_slice())),
            ] {
                assert!(validator
                    .update_vsi_context(None, assertion, manifest, certificate, &mut new_tracker())
                    .is_err());
            }
            assert_eq!(
                validator.expected_manifest_id.as_deref(),
                Some(TEST_MANIFEST_ID)
            );
            assert_eq!(validator.session_keys.len(), 1);
            assert_eq!(validator.init_track_id, Some(1));
            assert_eq!(validator.init_timescale, Some(1000));
            assert_eq!(validator.init_default_sample_duration, Some(1000));
            assert_eq!(
                validator.previous_segment.as_ref().unwrap().sequence_number,
                5
            );
            assert_eq!(validator.seen_emsg_ids, [5].into_iter().collect());
            assert_eq!(validator.sequence_coverage().missing_ranges, vec![0..=4]);
            let mut tracker = new_tracker();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(6, TEST_MANIFEST_ID, &old_key),
                    &mut tracker,
                )
                .unwrap();
            assert_eq!(tracker.filter_errors().count(), 0);

            let mut fresh = LiveVideoValidator::new();
            assert!(fresh
                .update_vsi_context(
                    Some(&update_init(1, 1000, 1000)),
                    &keys,
                    TEST_MANIFEST_ID,
                    Some(&cert),
                    &mut tracker
                )
                .is_err());
            validator
                .register_manifest_box_init(TEST_MANIFEST_ID, &mut tracker)
                .unwrap();
            validator.reset_continuity();
            assert!(validator
                .update_vsi_context(None, &keys, TEST_MANIFEST_ID, Some(&cert), &mut tracker)
                .is_err());

            // A manifest-method observation without registered init is also a method
            // commitment, even with an empty stream ID and after playback reset.
            let (mut manifest_validator, _) = setup_vsi_validator();
            manifest_validator
                .validate_media_segment(
                    &make_uuid_box(true),
                    TEST_MANIFEST_ID,
                    &make_segment(1, ""),
                    &mut new_tracker(),
                )
                .unwrap();
            manifest_validator.reset_continuity();
            assert!(manifest_validator
                .update_vsi_context(
                    None,
                    &keys,
                    TEST_MANIFEST_ID,
                    Some(&cert),
                    &mut new_tracker()
                )
                .is_err());
        }
    }

    #[test]
    #[cfg(feature = "rust_native_crypto")]
    fn vsi_update_preserves_reset_suppression_and_ignores_prior_tracker_failures() {
        use vsi_crypto_helpers::*;
        let (mut validator, _) = setup_vsi_validator();
        validator.reset_continuity();
        let cert = test_ee_cert_der();
        let (key, cose) = generate_test_key_pair();
        let keys = session_keys_with_cose_key(cose, &key, &cert);
        let mut tracker = StatusTracker::default();
        validator
            .fail_session_keys("earlier unrelated failure", &mut tracker)
            .unwrap();
        assert!(validator
            .update_vsi_context(
                Some(&[]),
                &keys,
                TEST_MANIFEST_ID,
                Some(&cert),
                &mut tracker
            )
            .is_err());
        assert!(validator.suppress_initial_continuity);
        let prior_failures = tracker.filter_errors().count();
        validator
            .update_vsi_context(None, &keys, TEST_MANIFEST_ID, Some(&cert), &mut tracker)
            .unwrap();
        assert!(validator.suppress_initial_continuity);
        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(8, TEST_MANIFEST_ID, &key),
                &mut tracker,
            )
            .unwrap();
        assert!(validator.sequence_coverage().missing_ranges.is_empty());
        assert_eq!(tracker.filter_errors().count(), prior_failures);
    }

    // ── validate_session_keys ─────────────────────────────────────────────────

    #[test]
    fn session_keys_empty_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_session_keys(
            &SessionKeys { keys: vec![] },
            "urn:c2pa:test-manifest",
            None,
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn session_keys_zero_validity_period_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                validity_period: 0,
                ..minimal_session_keys().keys.remove(0)
            }],
        };
        let _ =
            validator.validate_session_keys(&keys, "urn:c2pa:test-manifest", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn session_keys_missing_kid_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(
            c2pa_cbor::Value::Integer(1),
            c2pa_cbor::Value::Integer(2), // kty: EC2
        );
        let keys = SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(key_map),
                ..minimal_session_keys().keys.remove(0)
            }],
        };
        let _ =
            validator.validate_session_keys(&keys, "urn:c2pa:test-manifest", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    /// Per §19.7.3, a key whose `signerBinding` cannot be verified shall not be used. Without a
    /// manifest signer certificate to verify against, no key in the assertion can be verified,
    /// so `validate_session_keys` must fail closed (reject all keys) rather than accept them
    /// unchecked.
    #[test]
    fn session_keys_none_cert_fails_closed() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_session_keys(
            &minimal_session_keys(),
            "urn:c2pa:test-manifest",
            None,
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
        assert!(
            validator.session_keys.is_empty(),
            "no key should be trusted when its signerBinding could not be verified"
        );
    }

    // ── validate_verifiable_segment_info ───────────────────────────────────────

    #[test]
    fn vsi_without_session_keys_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_segment_without_emsg_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_segment_with_invalid_cose_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let segment = make_vsi_emsg_box(b"not-a-cose-sign1");
        let _ = validator.validate_verifiable_segment_info(&segment, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_valid_sequence_advances_state() {
        use vsi_crypto_helpers::*;
        let (mut validator, signing_key) = setup_vsi_validator();
        validator.session_keys[0].min_sequence_number = 1;
        let mut tracker = aggregate_tracker();

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(2, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_gap_and_following_segment_succeed_with_informational_coverage() {
        use vsi_crypto_helpers::*;

        let (mut validator, signing_key) = setup_vsi_validator();
        validator.session_keys[0].min_sequence_number = 1;
        let mut tracker = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        for sequence_number in [1, 3, 4] {
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(sequence_number, TEST_MANIFEST_ID, &signing_key),
                    &mut tracker,
                )
                .unwrap();
        }

        let coverage = validator.sequence_coverage();
        assert_eq!(coverage.missing_ranges, vec![2..=2]);
        assert_eq!(coverage.total_missing, 1);
        assert!(!coverage.ranges_truncated);
        assert_eq!(tracker.filter_errors().count(), 0);
        assert_eq!(tracker.logged_items().len(), 1);
        let gap = &tracker.logged_items()[0];
        assert_eq!(
            gap.validation_status.as_deref(),
            Some(LIVEVIDEO_SEGMENT_GAP)
        );
        assert_eq!(gap.kind, LogKind::Informational);
        assert!(gap.err_val.is_none());
        assert_eq!(
            validator.previous_segment.as_ref().unwrap().sequence_number,
            4
        );
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_equal_sequence_number_with_fresh_emsg_id_fails() {
        use vsi_crypto_helpers::*;

        let (mut validator, signing_key) = setup_vsi_validator();
        validator.session_keys[0].min_sequence_number = 1;
        let mut tracker = aggregate_tracker();
        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();

        let mut duplicate = make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key);
        // The VSI emsg is hash-excluded; a fresh event ID isolates sequence equality
        // from replay detection without changing the authenticated payload or media.
        let id_offset = 12 + b"urn:c2pa:verifiable-segment-info\0".len() + b"fseg\0".len() + 12;
        duplicate[id_offset..id_offset + 4].copy_from_slice(&2u32.to_be_bytes());
        validator
            .validate_verifiable_segment_info(&duplicate, &mut tracker)
            .unwrap();

        let failures: Vec<_> = tracker.filter_errors().collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0].validation_status.as_deref(),
            Some(LIVEVIDEO_SEGMENT_INVALID)
        );
        assert!(failures[0].description.contains("strictly greater"));
        assert_eq!(validator.sequence_coverage().total_missing, 0);
        assert_eq!(
            validator.previous_segment.as_ref().unwrap().sequence_number,
            1
        );

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(2, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 1);
        assert_eq!(validator.sequence_coverage().total_missing, 0);
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_leading_gap_uses_literal_session_key_minimum() {
        use vsi_crypto_helpers::*;

        for (minimum, first, expected_range, expected_total) in
            [(10, 12, 10..=11, 2u128), (0, 1, 0..=0, 1u128)]
        {
            let (mut validator, signing_key) = setup_vsi_validator();
            validator.session_keys[0].min_sequence_number = minimum;
            let mut tracker = aggregate_tracker();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(first, TEST_MANIFEST_ID, &signing_key),
                    &mut tracker,
                )
                .unwrap();

            let coverage = validator.sequence_coverage();
            assert_eq!(coverage.missing_ranges, vec![expected_range]);
            assert_eq!(coverage.total_missing, expected_total);
            assert!(!coverage.ranges_truncated);
            assert_eq!(tracker.filter_errors().count(), 0);
            assert_eq!(tracker.logged_items().len(), 1);
            let gap = &tracker.logged_items()[0];
            assert_eq!(
                gap.validation_status.as_deref(),
                Some(LIVEVIDEO_SEGMENT_LEADING_GAP)
            );
            assert_eq!(gap.kind, LogKind::Informational);
            assert!(gap.err_val.is_none());
        }
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_rejected_media_or_signature_does_not_record_gap_or_advance() {
        use vsi_crypto_helpers::*;

        for tamper_media in [true, false] {
            let (mut validator, signing_key) = setup_vsi_validator();
            validator.session_keys[0].min_sequence_number = 1;
            let mut tracker = aggregate_tracker();
            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
                    &mut tracker,
                )
                .unwrap();

            let mut invalid = if tamper_media {
                make_signed_vsi_segment(4, TEST_MANIFEST_ID, &signing_key)
            } else {
                let (other_key, _) = generate_test_key_pair();
                make_signed_vsi_segment(4, TEST_MANIFEST_ID, &other_key)
            };
            if tamper_media {
                // The fixture ends in an empty mdat; add a byte while keeping its box valid.
                let mdat_offset = invalid.len() - 8;
                invalid[mdat_offset..mdat_offset + 4].copy_from_slice(&9u32.to_be_bytes());
                invalid.push(1);
            }
            validator
                .validate_verifiable_segment_info(&invalid, &mut tracker)
                .unwrap();

            let failures: Vec<_> = tracker.filter_errors().collect();
            assert_eq!(failures.len(), 1);
            assert_eq!(
                failures[0].validation_status.as_deref(),
                Some(LIVEVIDEO_SEGMENT_INVALID)
            );
            assert!(failures[0].description.contains(if tamper_media {
                "bmffHash verification failed"
            } else {
                "signature verification failed"
            }));
            assert!(validator.sequence_coverage().missing_ranges.is_empty());
            assert_eq!(validator.sequence_coverage().total_missing, 0);
            assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_GAP));
            assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_LEADING_GAP));
            assert_eq!(
                validator.previous_segment.as_ref().unwrap().sequence_number,
                1
            );

            validator
                .validate_verifiable_segment_info(
                    &make_signed_vsi_segment(4, TEST_MANIFEST_ID, &signing_key),
                    &mut tracker,
                )
                .unwrap();
            assert_eq!(tracker.filter_errors().count(), 1);
            assert_eq!(validator.sequence_coverage().missing_ranges, vec![2..=3]);
            assert_eq!(validator.sequence_coverage().total_missing, 2);
            assert!(!validator.sequence_coverage().ranges_truncated);
            assert!(tracker.has_status(LIVEVIDEO_SEGMENT_GAP));
            assert_eq!(
                validator.previous_segment.as_ref().unwrap().sequence_number,
                4
            );
        }
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_reset_allows_replay_retains_coverage_and_suppresses_only_leading_gap() {
        use vsi_crypto_helpers::*;

        let (mut validator, signing_key) = setup_vsi_validator();
        validator.session_keys[0].min_sequence_number = 1;
        let mut tracker = aggregate_tracker();
        let first = make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key);
        let third = make_signed_vsi_segment(3, TEST_MANIFEST_ID, &signing_key);
        validator
            .validate_verifiable_segment_info(&first, &mut tracker)
            .unwrap();
        validator
            .validate_verifiable_segment_info(&third, &mut tracker)
            .unwrap();
        let recorded = validator.sequence_coverage().clone();
        assert_eq!(recorded.missing_ranges, vec![2..=2]);

        validator.reset_continuity();
        assert!(validator.previous_segment.is_none());
        assert!(validator.seen_emsg_ids.is_empty());
        assert_eq!(validator.session_keys.len(), 1);
        assert_eq!(validator.session_keys[0].min_sequence_number, 1);
        assert_eq!(
            validator.expected_manifest_id.as_deref(),
            Some(TEST_MANIFEST_ID)
        );
        assert_eq!(validator.sequence_coverage(), &recorded);
        validator
            .validate_verifiable_segment_info(&third, &mut tracker)
            .unwrap();
        assert_eq!(validator.sequence_coverage(), &recorded);
        assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_LEADING_GAP));

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();
        let coverage = validator.sequence_coverage();
        assert_eq!(coverage.missing_ranges, vec![2..=2, 4..=4]);
        assert_eq!(coverage.total_missing, 2);
        assert!(!coverage.ranges_truncated);
        assert_eq!(tracker.filter_errors().count(), 0);
        assert_eq!(tracker.logged_items().len(), 2);
        assert!(tracker.logged_items().iter().all(|item| {
            item.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_GAP)
                && item.kind == LogKind::Informational
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_regressed_sequence_number_fails() {
        use vsi_crypto_helpers::*;

        use crate::validation_results::validation_codes::LIVEVIDEO_SEGMENT_INVALID;
        let (mut validator, signing_key) = setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(4, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_min_sequence_number_enforced() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                min_sequence_number: 10,
                ..session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der)
                    .keys
                    .remove(0)
            }],
        };
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_expired_key_fails() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                created_at: DateT("2020-01-01T00:00:00Z".to_string()),
                validity_period: 1,
                ..session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der)
                    .keys
                    .remove(0)
            }],
        };
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        // Per §19.7.3, "the segment's presentation time is outside the key's validity
        // period" is coded livevideo.segment.invalid.
        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_bad_signature_fails() {
        use vsi_crypto_helpers::*;
        let (correct_signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = session_keys_with_cose_key(cose_key, &correct_signing_key, &ee_cert_der);
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let (other_key, _) = generate_test_key_pair();
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &other_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    // ── signer_binding verification (§18.25.2) ─────────────────────────────────
    //
    // Per the spec, signerBinding is a **detached** COSE_Sign1 where the session
    // key signs the signer's EE certificate (as CBOR byte string).

    fn generate_ed25519_session_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    fn build_ed25519_cose_key_value(
        verifying_key: &ed25519_dalek::VerifyingKey,
        kid: &[u8],
    ) -> c2pa_cbor::Value {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(1), cbor_int(1)); // kty: OKP
        map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(kid.to_vec())); // kid
        map.insert(cbor_int(3), cbor_int(-8)); // alg: EdDSA
        map.insert(cbor_int(-1), cbor_int(6)); // crv: Ed25519
        map.insert(
            cbor_int(-2),
            c2pa_cbor::Value::Bytes(verifying_key.as_bytes().to_vec()),
        ); // x
        c2pa_cbor::Value::Map(map)
    }

    fn make_signer_binding_for_ee_cert(
        session_signing_key: &ed25519_dalek::SigningKey,
        ee_cert_der: &[u8],
    ) -> Vec<u8> {
        use coset::{iana, HeaderBuilder, TaggedCborSerializable};
        use ed25519_dalek::Signer;

        let external_payload =
            c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec())).unwrap();

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let mut sign1 = coset::CoseSign1Builder::new().protected(protected).build();

        let tbs = sign1.tbs_detached_data(&external_payload, b"");
        let sig: ed25519_dalek::Signature = session_signing_key.sign(&tbs);
        sign1.signature = sig.to_bytes().to_vec();
        sign1.to_tagged_vec().unwrap()
    }

    fn session_key_with_ed25519_binding(
        cose_key: c2pa_cbor::Value,
        binding_bytes: Vec<u8>,
    ) -> SessionKeys {
        SessionKeys {
            keys: vec![SessionKey {
                key: cose_key,
                min_sequence_number: 0,
                created_at: DateT(chrono::Utc::now().to_rfc3339()),
                validity_period: 3600,
                signer_binding: c2pa_cbor::Value::Bytes(binding_bytes),
            }],
        }
    }

    #[test]
    fn signer_binding_valid_passes() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");
        let binding = make_signer_binding_for_ee_cert(&session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        validator
            .validate_session_keys(
                &keys,
                "urn:c2pa:test-manifest",
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn signer_binding_bad_signature_fails() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");

        // Sign with a *different* session key — binding won't match the `key` field
        let other_session_key = generate_ed25519_session_key();
        let binding = make_signer_binding_for_ee_cert(&other_session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        let _ = validator.validate_session_keys(
            &keys,
            "urn:c2pa:test-manifest",
            Some(&ee_cert_der),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    /// Per §19.7.3, a key whose `signerBinding` cannot be verified shall not be used. Without a
    /// manifest signer certificate, `validate_session_keys` must fail closed rather than accept
    /// the key unchecked (this used to silently skip the check and accept the key).
    #[test]
    fn signer_binding_none_cert_fails_closed() {
        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");
        let keys = session_key_with_ed25519_binding(cose_key, vec![0xde, 0xad]);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        let _ =
            validator.validate_session_keys(&keys, "urn:c2pa:test-manifest", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
        assert!(
            validator.session_keys.is_empty(),
            "no key should be trusted when its signerBinding could not be verified"
        );
    }

    #[test]
    fn signer_binding_wrong_ee_cert_fails() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");
        let binding = make_signer_binding_for_ee_cert(&session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        // Validate with a different EE cert — signerBinding should fail
        let other_signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("other-cert.local").unwrap();
        let other_ee_cert = other_signer.cert_chain_der[0].clone();

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        let _ = validator.validate_session_keys(
            &keys,
            "urn:c2pa:test-manifest",
            Some(&other_ee_cert),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    /// Regression test: per §19.7.3, a key whose `signerBinding` fails to verify shall not be
    /// used to validate any media segment. Verifies the key is dropped from the validator's
    /// trusted key set entirely, not merely flagged in the tracker while still being usable.
    #[test]
    fn signer_binding_bad_signature_key_is_not_retained() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");

        // Sign with a *different* session key — binding won't match the `key` field.
        let other_session_key = generate_ed25519_session_key();
        let binding = make_signer_binding_for_ee_cert(&other_session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        let _ = validator.validate_session_keys(
            &keys,
            "urn:c2pa:test-manifest",
            Some(&ee_cert_der),
            &mut tracker,
        );

        assert!(
            validator.session_keys.is_empty(),
            "a key with a failed signerBinding must not be retained for segment validation"
        );
    }

    // ── COSE_Sign1 wire format tests (§18.25.2) ─────────────────────────────────

    #[test]
    fn signer_binding_is_cose_sign1_tagged() {
        // Verify the COSE_Sign1 starts with CBOR tag 18 (0xD2)
        let session_key = generate_ed25519_session_key();
        let ee_cert_der = b"fake-cert-for-tag-test";
        let binding_bytes = make_signer_binding_for_ee_cert(&session_key, ee_cert_der);

        assert!(
            !binding_bytes.is_empty(),
            "binding bytes should not be empty"
        );
        assert_eq!(
            binding_bytes[0], 0xd2,
            "signerBinding must start with CBOR tag 18 (0xD2), got 0x{:02X}",
            binding_bytes[0]
        );
    }

    #[test]
    fn signer_binding_payload_is_detached() {
        // Per §18.25.2, the COSE_Sign1 payload must be null (detached)
        let session_key = generate_ed25519_session_key();
        let binding_bytes = make_signer_binding_for_ee_cert(&session_key, b"cert");

        let sign1 = coset::CoseSign1::from_tagged_slice(&binding_bytes).unwrap();
        assert!(
            sign1.payload.is_none(),
            "signerBinding payload must be None (detached), got {:?}",
            sign1.payload
        );
    }

    #[test]
    fn signer_binding_protected_header_contains_algorithm() {
        let session_key = generate_ed25519_session_key();
        let binding_bytes = make_signer_binding_for_ee_cert(&session_key, b"cert");

        let sign1 = coset::CoseSign1::from_tagged_slice(&binding_bytes).unwrap();
        let alg = sign1.protected.header.alg;
        assert_eq!(
            alg,
            Some(coset::RegisteredLabelWithPrivate::Assigned(
                coset::iana::Algorithm::EdDSA
            )),
            "signerBinding protected header must contain alg = EdDSA"
        );
    }

    #[test]
    fn cose_key_contains_alg_field() {
        // build_ed25519_cose_key must include field 3 (alg = -8 EdDSA) per RFC 9052
        let session_key = generate_ed25519_session_key();
        let key = super::super::cose_key::build_ed25519_cose_key(
            &session_key.verifying_key(),
            b"test-kid",
        );

        if let c2pa_cbor::Value::Map(map) = &key {
            let alg_value = map.get(&c2pa_cbor::Value::Integer(3));
            assert_eq!(
                alg_value,
                Some(&c2pa_cbor::Value::Integer(-8)),
                "COSE_Key must contain field 3 (alg) = -8 (EdDSA)"
            );
        } else {
            panic!("COSE_Key must be a CBOR map");
        }
    }
}
