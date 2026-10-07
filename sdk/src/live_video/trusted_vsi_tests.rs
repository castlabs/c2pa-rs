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

#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    io::Cursor,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use c2pa_cbor::Value;
use coset::TaggedCborSerializable;

use super::*;
use crate::{
    dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
    live_video::{
        bmff::{parse_init_segment, parse_media_segment},
        cose_key::build_ed25519_cose_key,
        vsi_signing::build_segment_bmff_hash,
        LiveVideoValidator,
    },
    utils::ephemeral_signer::EphemeralSigner,
    validation_status, Reader, Signer,
};

const INIT: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
const MEDIA: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s128.m4s");
const MEDIA_NEXT: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s129.m4s");
const IAT: i64 = 1_700_000_000;
const NONCE: &str = "00112233445566778899aabbccddeeff";
const MANIFEST: &str = r#"{"assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}}]}"#;

type Observations = Arc<Mutex<Vec<(VsiSigningContextV1, Vec<u8>)>>>;

#[derive(Clone)]
enum SessionKeyMaterial {
    Ed25519(ed25519_dalek::SigningKey),
    Es256(p256::ecdsa::SigningKey),
}

impl SessionKeyMaterial {
    fn algorithm(&self) -> SigningAlg {
        match self {
            Self::Ed25519(_) => SigningAlg::Ed25519,
            Self::Es256(_) => SigningAlg::Es256,
        }
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(tbs).to_bytes().to_vec()
            }
            Self::Es256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = key.sign(tbs);
                signature.to_bytes().to_vec()
            }
        }
    }

    fn cose_key(&self, kid: &[u8]) -> Value {
        match self {
            Self::Ed25519(key) => build_ed25519_cose_key(&key.verifying_key(), kid),
            Self::Es256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                let mut map = BTreeMap::new();
                map.insert(Value::Integer(1), Value::Integer(2));
                map.insert(Value::Integer(2), Value::Bytes(kid.to_vec()));
                map.insert(Value::Integer(3), Value::Integer(-7));
                map.insert(Value::Integer(-1), Value::Integer(1));
                map.insert(
                    Value::Integer(-2),
                    Value::Bytes(point.x().unwrap().to_vec()),
                );
                map.insert(
                    Value::Integer(-3),
                    Value::Bytes(point.y().unwrap().to_vec()),
                );
                Value::Map(map)
            }
        }
    }
}

fn ed25519() -> SessionKeyMaterial {
    SessionKeyMaterial::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]))
}

fn es256() -> SessionKeyMaterial {
    SessionKeyMaterial::Es256(p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap())
}

const KID: &[u8] = b"trusted-session";

fn config(key: &SessionKeyMaterial, min_sequence_number: u64) -> VsiSessionConfig {
    VsiSessionConfig {
        algorithm: key.algorithm(),
        kid: KID.to_vec(),
        public_cose_key_cbor: c2pa_cbor::to_vec(&key.cose_key(KID)).unwrap(),
        min_sequence_number,
        created_at: "2020-01-01T00:00:00Z".to_string(),
        validity_period_secs: 1_000_000_000,
    }
}

fn options(mode: TrustedVsiMode, sequence_max: Option<u32>) -> TrustedVsiSessionOptions {
    TrustedVsiSessionOptions {
        mode,
        reservation_nonce: NONCE.to_string(),
        signing_time_unix_seconds: IAT,
        sequence_max,
    }
}

fn context_with_signer<S: Signer + Send + Sync + 'static>(signer: S) -> Arc<Context> {
    let mut context = Context::new().with_signer(signer);
    context.settings_mut().verify.verify_trust = false;
    context.into_shared()
}

fn test_context() -> Arc<Context> {
    context_with_signer(EphemeralSigner::new("trusted-vsi.local").unwrap())
}

struct Harness {
    session: TrustedVsiPrehashedSession,
    observations: Observations,
    corrupt: Arc<AtomicBool>,
}

fn session_with(
    context: &Arc<Context>,
    key: &SessionKeyMaterial,
    min_sequence_number: u64,
    opts: TrustedVsiSessionOptions,
) -> Harness {
    session_with_manifest(context, key, min_sequence_number, opts, MANIFEST)
}

fn session_with_manifest(
    context: &Arc<Context>,
    key: &SessionKeyMaterial,
    min_sequence_number: u64,
    opts: TrustedVsiSessionOptions,
    manifest: &str,
) -> Harness {
    let observations: Observations = Arc::default();
    let corrupt = Arc::new(AtomicBool::new(false));
    let (observed, corrupting, signing_key) =
        (Arc::clone(&observations), Arc::clone(&corrupt), key.clone());
    let session = TrustedVsiPrehashedSession::from_shared_context_with_callback(
        context,
        manifest,
        config(key, min_sequence_number),
        opts,
        move |context, tbs| {
            observed.lock().unwrap().push((*context, tbs.to_vec()));
            let mut signature = signing_key.sign(tbs);
            if corrupting.load(Ordering::SeqCst) {
                signature[0] ^= 1;
            }
            Ok(signature)
        },
    )
    .unwrap();
    Harness {
        session,
        observations,
        corrupt,
    }
}

fn insert_after_ftyp(init: &[u8], uuid: &[u8]) -> Vec<u8> {
    assert_eq!(&init[4..8], b"ftyp");
    let ftyp_len = u32::from_be_bytes(init[..4].try_into().unwrap()) as usize;
    [&init[..ftyp_len], uuid, &init[ftyp_len..]].concat()
}

fn media_sequence(media: &[u8]) -> u32 {
    crate::live_video::moof_sequence_number(media).unwrap()
}

/// Reserves, hashes the final placement, finalizes, and returns the complete
/// signed init together with the reserved and signed UUID bytes.
fn establish_init(harness: &mut Harness) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let reservation = harness.session.reserve_init_uuid("video/mp4").unwrap();
    let placed = insert_after_ftyp(INIT, reservation.bytes());
    let hash = trusted_vsi_compute_hash(TrustedVsiInputKind::InitHash, &placed).unwrap();
    let signed = harness.session.finalize_init_uuid(&hash).unwrap();
    assert_eq!(signed.len(), reservation.bytes().len());
    (
        insert_after_ftyp(INIT, &signed),
        reservation.bytes().to_vec(),
        signed,
    )
}

/// Validates the signed init with the SDK Reader and prepares a VSI validator.
fn validator_for(
    context: &Arc<Context>,
    signed_init: &[u8],
    manifest_id: &str,
) -> LiveVideoValidator {
    let reader = Reader::from_shared_context(context)
        .with_stream("video/mp4", Cursor::new(signed_init))
        .unwrap();
    let failures: Vec<_> = reader
        .validation_status()
        .unwrap_or_default()
        .iter()
        .filter(|s| !s.passed() && s.code() != validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
        .map(|s| s.code().to_string())
        .collect();
    assert!(failures.is_empty(), "signed init failures: {failures:?}");
    let manifest = reader.active_manifest().unwrap();
    assert_eq!(manifest.label(), Some(manifest_id));
    let session_keys: SessionKeys = manifest.find_assertion(SessionKeys::LABEL).unwrap();
    let certs = context.signer().unwrap().certs().unwrap();

    let mut validator = LiveVideoValidator::new();
    let mut tracker = StatusTracker::default();
    validator
        .validate_init_segment(signed_init, &mut tracker)
        .unwrap();
    validator
        .validate_session_keys(&session_keys, manifest_id, Some(&certs[0]), &mut tracker)
        .unwrap();
    assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
    validator
}

fn assert_valid_segment(validator: &mut LiveVideoValidator, segment: &[u8]) {
    let mut tracker = StatusTracker::default();
    validator
        .validate_verifiable_segment_info(segment, &mut tracker)
        .unwrap();
    assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
}

fn media_timing(media: &[u8]) -> (u32, u32) {
    let init = parse_init_segment(INIT).unwrap();
    let info = parse_media_segment(media, init.default_sample_duration).unwrap();
    (init.timescale, info.duration_ticks)
}

/// Composes an expert Sig_structure exactly as a trusted processor would.
fn expert_sig_structure(
    key: &SessionKeyMaterial,
    manifest_id: &str,
    media: &[u8],
    event_id: u32,
) -> (coset::CoseSign1, Vec<u8>, u32, u32) {
    let (timescale, duration) = media_timing(media);
    let info = |bmff_hash| SegmentInfoMap {
        sequence_number: u64::from(media_sequence(media)),
        bmff_hash,
        manifest_id: manifest_id.to_string(),
        manifest_uri: None,
    };
    let draft = build_vsi_cose_sign1_dummy(
        &info(hash_template_value(TrustedVsiInputKind::MediaHash, &[0; 32]).unwrap()),
        key.algorithm(),
        KID,
        IAT,
    )
    .unwrap();
    let draft_emsg = build_emsg_box(&draft, timescale, duration, event_id).unwrap();
    let hash = build_segment_bmff_hash(&[draft_emsg.as_slice(), media].concat()).unwrap();
    let sign1 = build_vsi_cose_sign1_unsigned(&info(hash), key.algorithm(), KID, IAT).unwrap();
    let tbs = sign1.tbs_data(b"");
    (sign1, tbs, timescale, duration)
}

fn expert_segment(
    session: &mut TrustedVsiPrehashedSession,
    key: &SessionKeyMaterial,
    manifest_id: &str,
    media: &[u8],
    event_id: u32,
) -> Vec<u8> {
    let (mut sign1, tbs, timescale, duration) =
        expert_sig_structure(key, manifest_id, media, event_id);
    let signature = session
        .sign_sig_structure(&tbs, media_sequence(media))
        .unwrap();
    assert_eq!(signature.len(), 64);
    sign1.signature = signature;
    let emsg = build_emsg_box(
        &sign1.to_tagged_vec().unwrap(),
        timescale,
        duration,
        event_id,
    )
    .unwrap();
    [emsg.as_slice(), media].concat()
}

fn composed_segment(session: &mut TrustedVsiPrehashedSession, media: &[u8]) -> Vec<u8> {
    let (timescale, duration) = media_timing(media);
    let reservation = session
        .reserve_media_emsg_at(media_sequence(media), IAT, timescale, duration)
        .unwrap();
    let placed = [reservation.bytes(), media].concat();
    let hash = trusted_vsi_compute_hash(TrustedVsiInputKind::MediaHash, &placed).unwrap();
    let emsg = session.finalize_media_emsg(&hash).unwrap();
    assert_eq!(emsg.len(), reservation.bytes().len());
    [emsg.as_slice(), media].concat()
}

#[test]
fn capabilities_are_fully_wired() {
    let capabilities = TrustedVsiPrehashedSession::capabilities();
    assert_eq!(capabilities.bits(), 63);
    assert!(capabilities.supports_split_init_uuid());
    assert!(capabilities.supports_expert_sig_structure());
    assert!(capabilities.supports_signer_composed_emsg());
    assert!(capabilities.supports_recovery());
    assert!(capabilities.supports_signing_context_v1());
    assert!(capabilities.supports_full_uint32_exhaustion());
}

#[test]
fn expert_mode_end_to_end_for_both_algorithms() {
    for key in [ed25519(), es256()] {
        let context = test_context();
        let sequence = media_sequence(MEDIA);
        let mut harness = session_with(
            &context,
            &key,
            1,
            options(TrustedVsiMode::ExpertSigStructure, None),
        );
        let (signed_init, _, _) = establish_init(&mut harness);
        let manifest_id = harness.session.reserved_manifest_id().unwrap().to_string();
        // Only the signer binding was requested during init.
        {
            let observed = harness.observations.lock().unwrap();
            assert_eq!(observed.len(), 1);
            assert_eq!(
                observed[0].0.purpose(),
                TrustedVsiSigningPurpose::SignerBinding
            );
            assert_eq!(observed[0].0.sequence_number(), None);
            assert!(!observed[0].0.exhaust_after_sign());
        }
        assert!(harness
            .session
            .sign_sig_structure(
                &expert_sig_structure(&key, &manifest_id, MEDIA, 1).1,
                sequence
            )
            .is_err()); // not committed yet
        assert!(!harness.session.status().unwrap().blocked());
        harness.session.commit_init_uuid().unwrap();

        let mut validator = validator_for(&context, &signed_init, &manifest_id);
        let first = expert_segment(&mut harness.session, &key, &manifest_id, MEDIA, 1);
        assert_valid_segment(&mut validator, &first);
        let second = expert_segment(&mut harness.session, &key, &manifest_id, MEDIA_NEXT, 2);
        assert_valid_segment(&mut validator, &second);

        let observed = harness.observations.lock().unwrap();
        let (media_context, media_tbs) = &observed[1];
        assert_eq!(media_context.purpose(), TrustedVsiSigningPurpose::Vsi);
        assert_eq!(media_context.sequence_number(), Some(sequence));
        assert_eq!(media_context.event_id(), None);
        assert!(!media_context.exhaust_after_sign());
        // Original bytes are passed through unchanged.
        assert_eq!(
            media_tbs,
            &expert_sig_structure(&key, &manifest_id, MEDIA, 1).1
        );
        let status = harness.session.status().unwrap();
        assert!(status.init_uuid_committed());
        assert_eq!(status.next_sequence_number(), None);
        assert_eq!(status.next_event_id(), None);
        assert!(!status.exhausted());
    }
}

fn raw_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    c2pa_cbor::to_vec(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ]))
    .unwrap()
}

fn expert_tbs(key: &SessionKeyMaterial, manifest_id: &str, sequence: u32, iat: i64) -> Vec<u8> {
    build_vsi_cose_sign1_unsigned(
        &SegmentInfoMap {
            sequence_number: u64::from(sequence),
            bmff_hash: hash_template_value(TrustedVsiInputKind::MediaHash, &[0; 32]).unwrap(),
            manifest_id: manifest_id.into(),
            manifest_uri: None,
        },
        key.algorithm(),
        KID,
        iat,
    )
    .unwrap()
    .tbs_data(b"")
}

fn native_payload(tbs: &[u8]) -> Vec<u8> {
    let Value::Array(fields) = c2pa_cbor::from_slice(tbs).unwrap() else {
        panic!()
    };
    let Value::Bytes(payload) = &fields[3] else {
        panic!()
    };
    payload.clone()
}

fn committed_expert(key: &SessionKeyMaterial, sequence_max: Option<u32>) -> Harness {
    let context = test_context();
    let mut harness = session_with(
        &context,
        key,
        10,
        options(TrustedVsiMode::ExpertSigStructure, sequence_max),
    );
    establish_init(&mut harness);
    harness.session.commit_init_uuid().unwrap();
    harness
}

#[test]
fn expert_signs_vsi_payloads_any_order_and_uint32_max_without_counters() {
    let key = ed25519();
    let mut harness = committed_expert(&key, None);
    let id = harness.session.reserved_manifest_id().unwrap().to_string();
    let session_key = key.cose_key(KID);
    for sequence in [500, 10, 500, u32::MAX, 11] {
        let tbs = expert_tbs(&key, &id, sequence, IAT);
        let signature = harness.session.sign_sig_structure(&tbs, sequence).unwrap();
        verify_raw_session_signature(SigningAlg::Ed25519, &session_key, &tbs, &signature).unwrap();
    }
    let observed = harness.observations.lock().unwrap();
    let media: Vec<_> = observed.iter().skip(1).collect();
    assert_eq!(media.len(), 5);
    for (context, bytes) in &media {
        assert_eq!(
            bytes,
            &expert_tbs(&key, &id, context.sequence_number().unwrap(), IAT)
        );
        assert_eq!(context.event_id(), None);
        assert!(!context.exhaust_after_sign());
    }
    assert_eq!(media[3].0.sequence_number(), Some(u32::MAX));
}

#[test]
fn expert_rejections_happen_before_key_use() {
    let key = es256();
    let mut harness = committed_expert(&key, Some(20));
    let before = harness.observations.lock().unwrap().len();
    let good = expert_tbs(
        &key,
        harness.session.reserved_manifest_id().unwrap(),
        10,
        IAT,
    );
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&good);
    let mut trailing = good.clone();
    trailing.push(0x00);
    let mut rejected = vec![
        (good.clone(), 9),                                              // below min
        (good.clone(), 21),                                             // above max
        (tagged, 10),                                                   // tagged
        (trailing, 10),                                                 // trailing bytes
        (raw_sig_structure(&[0xa1, 0x01, 0x27], b"p"), 10),             // wrong alg
        (raw_sig_structure(&[0xa1, 0x02, 0x41, 0x00], b"p"), 10),       // missing alg
        (raw_sig_structure(&[0xa1, 0x01, 0x38, 0x06], b"p"), 10),       // non-minimal -7
        (raw_sig_structure(&[0xa2, 0x01, 0x26, 0x01, 0x26], b"p"), 10), // duplicate
        (raw_sig_structure(&[0xbf, 0x01, 0x26, 0xff], b"p"), 10),       // indefinite
        (raw_sig_structure(&[0xa1, 0x01, 0x26, 0x00], b"p"), 10),       // trailing protected
        (raw_sig_structure(&[0xa1, 0x41, 0x01, 0x26], b"p"), 10),       // bytes label
        (vec![0x85, 0x6a], 10),                                         // five elements
    ];
    let mut with_aad = good.clone();
    let mut scan = Scanner::new(&good);
    scan.head().unwrap();
    scan.value(1).unwrap();
    scan.bytes().unwrap();
    let aad_at = scan.position();
    with_aad[aad_at] = 0x41;
    with_aad.insert(aad_at + 1, 0x00);
    rejected.push((with_aad, 10));
    let mut wrong_context = good.clone();
    wrong_context[11] = b'2';
    rejected.push((wrong_context, 10));
    rejected.push((vec![0x84; MAX_SIG_STRUCTURE_LEN + 1], 10));
    for (bytes, sequence) in rejected {
        assert!(
            harness
                .session
                .sign_sig_structure(&bytes, sequence)
                .is_err(),
            "accepted {:02x?}",
            &bytes[..bytes.len().min(24)]
        );
        assert!(harness
            .session
            .preflight(
                TrustedVsiOperation::ExpertSign,
                &bytes,
                sequence,
                0,
                0,
                0,
                ""
            )
            .is_err());
    }
    assert_eq!(harness.observations.lock().unwrap().len(), before);
    assert!(!harness.session.status().unwrap().blocked());
    // Rich canonical protected headers remain accepted.
    let rich = [
        0xa5, 0x01, 0x26, 0x02, 0x81, 0x03, 0x04, 0x42, 0x6b, 0x31, 0x63, b'i', b'a', b't', 0x1a,
        0x65, 0x53, 0xf1, 0x00, 0x64, b'x', b't', b'r', b'a', 0xa2, 0x01, 0xf9, 0x3c, 0x00, 0x41,
        0x00, 0xc1, 0x00,
    ];
    // Keys: 1, 2, 4, "iat", "xtra" (bytewise ordered); nested map has int and bytes keys.
    let rich_tbs = raw_sig_structure(&rich, &native_payload(&good));
    harness
        .session
        .preflight(TrustedVsiOperation::ExpertSign, &rich_tbs, 10, 0, 0, 0, "")
        .unwrap();
    harness.session.sign_sig_structure(&rich_tbs, 10).unwrap();
}

#[test]
fn expert_failure_after_callback_blocks_and_prestate_retries() {
    let key = ed25519();
    let mut harness = committed_expert(&key, None);
    let prestate = harness.session.export_state().unwrap();
    let tbs = expert_tbs(
        &key,
        harness.session.reserved_manifest_id().unwrap(),
        10,
        IAT,
    );
    harness.corrupt.store(true, Ordering::SeqCst);
    assert!(harness.session.sign_sig_structure(&tbs, 10).is_err());
    assert!(harness.session.status().unwrap().blocked());
    harness.corrupt.store(false, Ordering::SeqCst);
    assert!(harness.session.sign_sig_structure(&tbs, 10).is_err());
    let blocked_record: serde_json::Value =
        serde_json::from_slice(&harness.session.export_state().unwrap()).unwrap();
    assert_eq!(blocked_record["state"]["blocked"], true);

    let context = Arc::clone(&harness.session.context);
    let mut retry = session_with(
        &context,
        &key,
        10,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    retry.session.import_state(&prestate).unwrap();
    assert!(retry.session.import_state(&prestate).is_err()); // only once, into a new session
    retry.session.sign_sig_structure(&tbs, 10).unwrap();
    assert_eq!(retry.observations.lock().unwrap().len(), 1);
}

#[test]
fn expert_rejects_foreign_certificate_signer_binding_for_both_algorithms() {
    struct BindingSigner(SessionKeyMaterial, Arc<Mutex<Vec<u8>>>);
    impl VsiSessionSigner for BindingSigner {
        fn sign(&self, purpose: VsiSigningPurpose, tbs: &[u8]) -> Result<Vec<u8>> {
            assert_eq!(purpose, VsiSigningPurpose::SignerBinding);
            *self.1.lock().unwrap() = tbs.to_vec();
            Ok(self.0.sign(tbs))
        }
    }
    for key in [ed25519(), es256()] {
        let mut harness = committed_expert(&key, None);
        let foreign_cert = test_context().signer().unwrap().certs().unwrap().remove(0);
        assert_ne!(foreign_cert, harness.session.claim_certificate_der);
        let captured = Arc::new(Mutex::new(vec![]));
        build_signer_binding(
            &foreign_cert,
            key.algorithm(),
            &BindingSigner(key.clone(), captured.clone()),
            &key.cose_key(KID),
        )
        .unwrap();
        let attack = captured.lock().unwrap().clone();
        let before = harness.session.export_state().unwrap();
        let calls = harness.observations.lock().unwrap().len();
        assert!(harness.session.sign_sig_structure(&attack, 10).is_err());
        // Adding an otherwise valid VSI protected header cannot turn the
        // detached certificate bstr into a media segment payload either.
        let genuine = expert_tbs(
            &key,
            harness.session.reserved_manifest_id().unwrap(),
            10,
            IAT,
        );
        let Value::Array(fields) = c2pa_cbor::from_slice(&genuine).unwrap() else {
            panic!()
        };
        let Value::Bytes(protected) = &fields[1] else {
            panic!()
        };
        let attack_with_iat = raw_sig_structure(protected, &native_payload(&attack));
        assert!(harness
            .session
            .sign_sig_structure(&attack_with_iat, 10)
            .is_err());
        assert!(validate_trusted_vsi_input(
            TrustedVsiInputKind::SigStructure,
            key.algorithm(),
            &attack_with_iat
        )
        .is_err());
        assert_eq!(harness.session.export_state().unwrap(), before);
        assert_eq!(harness.observations.lock().unwrap().len(), calls);
    }
}

#[test]
fn expert_enforces_signed_fields_shapes_duplicates_and_inclusive_iat() {
    for key in [ed25519(), es256()] {
        let mut harness = committed_expert(&key, None);
        let id = harness.session.reserved_manifest_id().unwrap().to_string();
        let good = expert_tbs(&key, &id, 10, IAT);
        let Value::Array(fields) = c2pa_cbor::from_slice(&good).unwrap() else {
            panic!()
        };
        let Value::Bytes(protected) = &fields[1] else {
            panic!()
        };
        let payload = native_payload(&good);
        let mut oversized_iat = vec![
            0xa2,
            0x01,
            protected_alg_encoding(key.algorithm()).unwrap(),
            0x63,
            b'i',
            b'a',
            b't',
            0x1b,
        ];
        oversized_iat.extend_from_slice(&(1u64 << 63).to_be_bytes());
        let negative_iat = expert_tbs(&key, &id, 10, -1);
        validate_trusted_vsi_input(
            TrustedVsiInputKind::SigStructure,
            key.algorithm(),
            &negative_iat,
        )
        .unwrap();
        assert_eq!(
            validate_sig_structure(key.algorithm(), &negative_iat)
                .unwrap()
                .2,
            -1
        );
        let float_iat_header = [
            0xa2,
            0x01,
            protected_alg_encoding(key.algorithm()).unwrap(),
            0x63,
            b'i',
            b'a',
            b't',
            0xf9,
            0xbc,
            0x00,
        ]; // canonical f16 -1.0
        trusted_cbor::validate_single_value(&float_iat_header, MAX_SMALL_CBOR_LEN).unwrap();
        let float_iat = raw_sig_structure(&float_iat_header, &payload);
        assert!(validate_sig_structure(key.algorithm(), &float_iat)
            .unwrap_err()
            .to_string()
            .contains("untagged integer NumericDate"));
        let sequence_key = b"\x6esequenceNumber";
        let sequence_at = payload
            .windows(sequence_key.len())
            .position(|bytes| bytes == sequence_key)
            .unwrap()
            + sequence_key.len();
        assert_eq!(payload[sequence_at], 10);
        let mut float_sequence_payload = payload.clone();
        float_sequence_payload.splice(sequence_at..sequence_at + 1, [0xf9, 0x49, 0x00]); // canonical f16 10.0
        Scanner::well_formed(&float_sequence_payload)
            .map(KeyRule::Nested)
            .unwrap();
        let float_sequence = raw_sig_structure(protected, &float_sequence_payload);
        assert!(validate_sig_structure(key.algorithm(), &float_sequence)
            .unwrap_err()
            .to_string()
            .contains("untagged uint32"));
        let mut rejected = vec![
            (good.clone(), 11),
            (raw_sig_structure(&oversized_iat, &payload), 10),
            (negative_iat, 10),
            (float_iat, 10),
            (float_sequence, 10),
            (expert_tbs(&key, "urn:c2pa:foreign", 10, IAT), 10),
            (expert_tbs(&key, &id, 10, 1_577_836_799), 10),
            (expert_tbs(&key, &id, 10, 2_577_836_801), 10),
            (
                raw_sig_structure(
                    &[0xa1, 0x01, protected_alg_encoding(key.algorithm()).unwrap()],
                    &payload,
                ),
                10,
            ),
            (
                raw_sig_structure(protected, &[payload.as_slice(), &[0]].concat()),
                10,
            ),
            (
                raw_sig_structure(protected, &[&[0xc1], payload.as_slice()].concat()),
                10,
            ),
        ];
        let mut duplicate = payload.clone();
        duplicate[0] += 1;
        duplicate.extend(c2pa_cbor::to_vec(&Value::Text("sequenceNumber".into())).unwrap());
        duplicate.push(10);
        rejected.push((raw_sig_structure(protected, &duplicate), 10));
        let bmff_hash = c2pa_cbor::to_vec(
            &hash_template_value(TrustedVsiInputKind::MediaHash, &[0; 32]).unwrap(),
        )
        .unwrap();
        let at = payload
            .windows(bmff_hash.len())
            .position(|bytes| bytes == bmff_hash)
            .unwrap();
        let mut duplicate_hash = bmff_hash.clone();
        duplicate_hash[0] += 1;
        duplicate_hash.extend(c2pa_cbor::to_vec(&Value::Text("hash".into())).unwrap());
        duplicate_hash.extend(c2pa_cbor::to_vec(&Value::Bytes(vec![0; 32])).unwrap());
        let duplicate_nested = [
            &payload[..at],
            &duplicate_hash,
            &payload[at + bmff_hash.len()..],
        ]
        .concat();
        rejected.push((raw_sig_structure(protected, &duplicate_nested), 10));
        for changed in ["name", "alg", "exclusions"] {
            let Value::Map(mut fields) = Value::from_tagged_slice(&payload).unwrap() else {
                panic!()
            };
            let Value::Map(hash) = fields.get_mut(&Value::Text("bmffHash".into())).unwrap() else {
                panic!()
            };
            if changed == "exclusions" {
                let Value::Array(exclusions) =
                    hash.get_mut(&Value::Text("exclusions".into())).unwrap()
                else {
                    panic!()
                };
                let Value::Map(exclusion) = &mut exclusions[0] else {
                    panic!()
                };
                exclusion.insert(Value::Text("xpath".into()), Value::Text("/mdat".into()));
            } else {
                hash.insert(
                    Value::Text(changed.into()),
                    Value::Text(
                        if changed == "alg" {
                            "sha384"
                        } else {
                            "other segment"
                        }
                        .into(),
                    ),
                );
            }
            assert_eq!(
                hash.get(&Value::Text("hash".into())),
                Some(&Value::Bytes(vec![0; 32]))
            );
            let near_miss =
                raw_sig_structure(protected, &c2pa_cbor::to_vec(&Value::Map(fields)).unwrap());
            assert!(validate_sig_structure(key.algorithm(), &near_miss)
                .unwrap_err()
                .to_string()
                .contains("supported native media template"));
            rejected.push((near_miss, 10));
        }
        for (field, value) in [
            ("sequenceNumber", Value::Integer(-1)),
            ("sequenceNumber", Value::Integer(i64::from(u32::MAX) + 1)),
            (
                "sequenceNumber",
                Value::Tag(1, Box::new(Value::Integer(10))),
            ),
            ("manifestId", Value::Bytes(id.as_bytes().to_vec())),
            ("bmffHash", Value::Array(vec![])),
            ("manifestUri", Value::Null),
            ("extra", Value::Bool(true)),
        ] {
            let Value::Map(mut map) = c2pa_cbor::from_slice(&payload).unwrap() else {
                panic!()
            };
            map.insert(Value::Text(field.into()), value);
            rejected.push((
                raw_sig_structure(protected, &c2pa_cbor::to_vec(&Value::Map(map)).unwrap()),
                10,
            ));
        }
        for value in [
            Value::Text(IAT.to_string()),
            Value::Tag(1, Box::new(Value::Integer(IAT.into()))),
        ] {
            let Value::Map(mut map) = c2pa_cbor::from_slice(protected).unwrap() else {
                panic!()
            };
            map.insert(Value::Text("iat".into()), value);
            let value = Value::Map(map);
            let header = trusted_cbor::encode_deterministic(&value).unwrap();
            rejected.push((raw_sig_structure(&header, &payload), 10));
        }
        let before = harness.session.export_state().unwrap();
        let calls = harness.observations.lock().unwrap().len();
        for (tbs, sequence) in rejected {
            assert!(harness
                .session
                .preflight(TrustedVsiOperation::ExpertSign, &tbs, sequence, 0, 0, 0, "")
                .is_err());
            assert!(harness.session.sign_sig_structure(&tbs, sequence).is_err());
            assert_eq!(harness.session.export_state().unwrap(), before);
        }
        assert_eq!(harness.observations.lock().unwrap().len(), calls);
        for iat in [1_577_836_800, IAT, 2_577_836_800] {
            let tbs = expert_tbs(&key, &id, 10, iat);
            harness.session.sign_sig_structure(&tbs, 10).unwrap();
            assert_eq!(
                &harness.observations.lock().unwrap().last().unwrap().1,
                &tbs
            );
        }
        let Value::Map(mut fields) = c2pa_cbor::from_slice(&payload).unwrap() else {
            panic!()
        };
        fields.insert(
            Value::Text("manifestUri".into()),
            Value::Map(BTreeMap::from([
                (
                    Value::Text("url".into()),
                    Value::Text("https://example.test/manifest".into()),
                ),
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (Value::Text("hash".into()), Value::Bytes(vec![1; 32])),
            ])),
        );
        let with_uri =
            raw_sig_structure(protected, &c2pa_cbor::to_vec(&Value::Map(fields)).unwrap());
        harness.session.sign_sig_structure(&with_uri, 10).unwrap();
        assert_eq!(harness.session.export_state().unwrap(), before);
    }
}

#[test]
fn mode_is_pinned() {
    let key = ed25519();
    let mut expert = committed_expert(&key, None);
    assert!(expert.session.reserve_media_emsg_at(10, IAT, 1, 1).is_err());
    assert!(expert.session.finalize_media_emsg(b"").is_err());

    let context = test_context();
    let mut composed = session_with(
        &context,
        &key,
        10,
        options(TrustedVsiMode::SignerComposedEmsg, None),
    );
    establish_init(&mut composed);
    composed.session.commit_init_uuid().unwrap();
    let tbs = expert_tbs(
        &key,
        composed.session.reserved_manifest_id().unwrap(),
        10,
        IAT,
    );
    assert!(composed.session.sign_sig_structure(&tbs, 10).is_err());
    assert_eq!(composed.observations.lock().unwrap().len(), 1);
}

#[test]
fn composed_mode_end_to_end_restore_and_replay() {
    for key in [ed25519(), es256()] {
        let context = test_context();
        let first_sequence = media_sequence(MEDIA);
        let mut harness = session_with(
            &context,
            &key,
            u64::from(first_sequence),
            options(TrustedVsiMode::SignerComposedEmsg, None),
        );
        let (signed_init, _, _) = establish_init(&mut harness);
        let manifest_id = harness.session.reserved_manifest_id().unwrap().to_string();
        assert!(harness
            .session
            .reserve_media_emsg_at(first_sequence, IAT, 1, 1)
            .is_err());
        harness.session.commit_init_uuid().unwrap();
        let mut validator = validator_for(&context, &signed_init, &manifest_id);

        let first = composed_segment(&mut harness.session, MEDIA);
        assert_valid_segment(&mut validator, &first);

        // Reserve the next segment, persist, and finalize in a new instance.
        let (timescale, duration) = media_timing(MEDIA_NEXT);
        assert!(harness
            .session
            .reserve_media_emsg_at(first_sequence + 2, IAT, timescale, duration)
            .is_err()); // must equal the next sequence
        let reservation = harness
            .session
            .reserve_media_emsg_at(first_sequence + 1, IAT, timescale, duration)
            .unwrap();
        assert_eq!(reservation.signing_context().event_id(), Some(2));
        assert_eq!(
            harness
                .session
                .reserve_media_emsg_at(first_sequence + 1, IAT, timescale, duration)
                .unwrap(),
            reservation
        );
        assert!(harness
            .session
            .reserve_media_emsg_at(first_sequence + 1, IAT + 1, timescale, duration)
            .is_err());
        let calls_before = harness.observations.lock().unwrap().len();
        let record = harness.session.export_state().unwrap();
        let mut restored = session_with(
            &context,
            &key,
            u64::from(first_sequence),
            options(TrustedVsiMode::SignerComposedEmsg, None),
        );
        restored.session.import_state(&record).unwrap();
        assert!(restored.session.status().unwrap().media_emsg_pending());
        let placed = [reservation.bytes(), MEDIA_NEXT].concat();
        let hash = trusted_vsi_compute_hash(TrustedVsiInputKind::MediaHash, &placed).unwrap();
        let emsg = restored.session.finalize_media_emsg(&hash).unwrap();
        assert_eq!(restored.session.finalize_media_emsg(&hash).unwrap(), emsg);
        assert_valid_segment(&mut validator, &[emsg.as_slice(), MEDIA_NEXT].concat());
        assert_eq!(harness.observations.lock().unwrap().len(), calls_before);
        let observed = restored.observations.lock().unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0.sequence_number(), Some(first_sequence + 1));
        assert_eq!(observed[0].0.event_id(), Some(2));
        let status = restored.session.status().unwrap();
        assert_eq!(status.next_sequence_number(), Some(first_sequence + 2));
        assert_eq!(status.next_event_id(), Some(3));
    }
}

#[test]
fn composed_exhaustion_is_terminal_at_sequence_max() {
    let key = ed25519();
    let context = test_context();
    let sequence = media_sequence(MEDIA);
    let mut harness = session_with(
        &context,
        &key,
        u64::from(sequence),
        options(TrustedVsiMode::SignerComposedEmsg, Some(sequence)),
    );
    establish_init(&mut harness);
    harness.session.commit_init_uuid().unwrap();
    let (timescale, duration) = media_timing(MEDIA);
    let reservation = harness
        .session
        .reserve_media_emsg_at(sequence, IAT, timescale, duration)
        .unwrap();
    assert!(reservation.signing_context().exhaust_after_sign());
    let hash = trusted_vsi_compute_hash(
        TrustedVsiInputKind::MediaHash,
        &[reservation.bytes(), MEDIA].concat(),
    )
    .unwrap();
    harness.session.finalize_media_emsg(&hash).unwrap();
    let status = harness.session.status().unwrap();
    assert!(status.exhausted());
    assert_eq!(
        status.exhaustion_reason(),
        Some(TrustedVsiExhaustionReason::SequenceMax)
    );
    assert_eq!(status.next_sequence_number(), None);
    assert!(harness
        .session
        .reserve_media_emsg_at(sequence, IAT, timescale, duration)
        .is_err());
    assert!(harness.observations.lock().unwrap()[1]
        .0
        .exhaust_after_sign());
    let record = harness.session.export_state().unwrap();
    let mut restored = session_with(
        &context,
        &key,
        u64::from(sequence),
        options(TrustedVsiMode::SignerComposedEmsg, Some(sequence)),
    );
    restored.session.import_state(&record).unwrap();
    assert!(restored.session.status().unwrap().exhausted());
}

#[test]
fn composed_uint32_max_terminal_sequence() {
    let key = ed25519();
    let context = test_context();
    let mut harness = session_with(
        &context,
        &key,
        u64::from(u32::MAX),
        options(TrustedVsiMode::SignerComposedEmsg, None),
    );
    establish_init(&mut harness);
    harness.session.commit_init_uuid().unwrap();
    let reservation = harness
        .session
        .reserve_media_emsg_at(u32::MAX, IAT, 90_000, 180_000)
        .unwrap();
    assert!(reservation.signing_context().exhaust_after_sign());
    let hash = trusted_vsi_compute_hash(
        TrustedVsiInputKind::MediaHash,
        &[reservation.bytes(), MEDIA].concat(),
    )
    .unwrap();
    harness.session.finalize_media_emsg(&hash).unwrap();
    assert!(harness.session.status().unwrap().exhausted());
}

#[test]
fn init_reservation_is_frozen_replayable_and_restorable() {
    let key = ed25519();
    let context = test_context();
    let mut harness = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    let reservation = harness.session.reserve_init_uuid("mp4").unwrap();
    assert_eq!(
        harness.session.reserve_init_uuid("video/mp4").unwrap(),
        reservation
    );
    assert!(harness.session.reserve_init_uuid("image/jpeg").is_err());
    assert!(reservation.manifest_id().starts_with("urn:c2pa:"));
    let record = harness.session.export_state().unwrap();
    assert!(!String::from_utf8_lossy(&record).contains("\"d\""));
    assert_eq!(harness.observations.lock().unwrap().len(), 0);

    let placed = insert_after_ftyp(INIT, reservation.bytes());
    let hash = trusted_vsi_compute_hash(TrustedVsiInputKind::InitHash, &placed).unwrap();
    let signed = harness.session.finalize_init_uuid(&hash).unwrap();
    assert_eq!(harness.session.finalize_init_uuid(&hash).unwrap(), signed);
    let mut other_hash = hash.clone();
    let digest_at = other_hash.len() - 1;
    other_hash[digest_at] ^= 1;
    assert!(harness.session.finalize_init_uuid(&other_hash).is_err());

    // A new instance restored from the reservation finalizes identically:
    // the manifest identity, salts, and slots are frozen in the record.
    let mut restored = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    restored.session.import_state(&record).unwrap();
    assert_eq!(
        restored.session.reserve_init_uuid("mp4").unwrap(),
        reservation
    );
    assert_eq!(restored.session.finalize_init_uuid(&hash).unwrap(), signed);

    // Same nonce derives the same manifest identity in an independent session.
    let mut fresh = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    let fresh_reservation = fresh.session.reserve_init_uuid("mp4").unwrap();
    assert_eq!(fresh_reservation.manifest_id(), reservation.manifest_id());
    assert_eq!(fresh_reservation.bytes(), reservation.bytes());
}

#[test]
fn import_and_finalize_bind_entire_reservation_not_editable_identity_digest() {
    for key in [ed25519(), es256()] {
        let base = Arc::new(EphemeralSigner::new("trusted-vsi-content.local").unwrap());
        let counted = da_context(&base, &[("com.example.slot", 64), ("com.example.slot", 96)]);
        let opts = options(TrustedVsiMode::ExpertSigStructure, None);
        let mut definition: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        definition["title"] = "expected title".into();
        definition["assertions"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"label":"com.example.static","data":{"value":"expected"}}));
        definition["claim_generator_info"] =
            serde_json::json!([{"name":"trusted test","version":"1","custom":"expected"}]);
        let expected_manifest = definition.to_string();
        for changed in ["title", "static", "generator"] {
            let mut foreign = definition.clone();
            match changed {
                "title" => foreign["title"] = "foreign! title".into(),
                "static" => foreign["assertions"][1]["data"]["value"] = "foreign!".into(),
                _ => foreign["claim_generator_info"][0]["custom"] = "foreign!".into(),
            }
            let mut source = session_with_manifest(
                &counted.context,
                &key,
                1,
                opts.clone(),
                &foreign.to_string(),
            );
            source.session.reserve_init_uuid("mp4").unwrap();
            let reserved = source.session.export_state().unwrap();
            establish_init(&mut source);
            let finalized = source.session.export_state().unwrap();
            source.session.commit_init_uuid().unwrap();
            let committed = source.session.export_state().unwrap();
            let mut genuine_signed =
                session_with_manifest(&counted.context, &key, 1, opts.clone(), &expected_manifest);
            establish_init(&mut genuine_signed);
            let mut signed_swap: serde_json::Value =
                serde_json::from_slice(&genuine_signed.session.export_state().unwrap()).unwrap();
            let foreign_signed: serde_json::Value = serde_json::from_slice(&finalized).unwrap();
            signed_swap["state"]["signed_uuid"] = foreign_signed["state"]["signed_uuid"].clone();
            signed_swap["state"]["init_hash_input"] =
                foreign_signed["state"]["init_hash_input"].clone();
            let signed_swap = serde_json::to_vec(&signed_swap).unwrap();
            for record in [&reserved, &finalized, &committed, &signed_swap] {
                let mut target = session_with_manifest(
                    &counted.context,
                    &key,
                    1,
                    opts.clone(),
                    &expected_manifest,
                );
                let before = target.session.export_state().unwrap();
                let calls = (
                    counted.content_calls.load(Ordering::SeqCst),
                    counted.sign_calls.load(Ordering::SeqCst),
                );
                let mut forged: serde_json::Value = serde_json::from_slice(record).unwrap();
                forged["identity"] = serde_json::from_slice::<serde_json::Value>(&before).unwrap()
                    ["identity"]
                    .clone();
                assert!(
                    target
                        .session
                        .import_state(&serde_json::to_vec(&forged).unwrap())
                        .is_err(),
                    "{changed}"
                );
                assert_eq!(target.session.export_state().unwrap(), before);
                assert!(target.observations.lock().unwrap().is_empty());
                assert_eq!(
                    (
                        counted.content_calls.load(Ordering::SeqCst),
                        counted.sign_calls.load(Ordering::SeqCst)
                    ),
                    calls
                );
            }
            // Defense at the signing boundary even for an internally corrupted
            // reservation, not just the public import path.
            let mut target =
                session_with_manifest(&counted.context, &key, 1, opts.clone(), &expected_manifest);
            let forged: StateRecord = serde_json::from_slice(&reserved).unwrap();
            target.session.state = forged.state;
            let before = target.session.export_state().unwrap();
            let calls = counted.sign_calls.load(Ordering::SeqCst);
            assert!(target
                .session
                .finalize_init_uuid(
                    &trusted_vsi_hash_template(TrustedVsiInputKind::InitHash).unwrap()
                )
                .is_err());
            assert_eq!(target.session.export_state().unwrap(), before);
            assert_eq!(counted.sign_calls.load(Ordering::SeqCst), calls);
            assert!(target.observations.lock().unwrap().is_empty());
        }
        let mut genuine =
            session_with_manifest(&counted.context, &key, 1, opts.clone(), &expected_manifest);
        let reservation = genuine.session.reserve_init_uuid("mp4").unwrap();
        let record = genuine.session.export_state().unwrap();
        let mut repeated =
            session_with_manifest(&counted.context, &key, 1, opts.clone(), &expected_manifest);
        assert_eq!(
            repeated.session.reserve_init_uuid("mp4").unwrap(),
            reservation
        );
        let mut recovered =
            session_with_manifest(&counted.context, &key, 1, opts.clone(), &expected_manifest);
        recovered.session.import_state(&record).unwrap();
        assert_eq!(
            recovered.session.reserve_init_uuid("mp4").unwrap(),
            reservation
        );
        let hash = trusted_vsi_hash_template(TrustedVsiInputKind::InitHash).unwrap();
        assert_eq!(
            genuine.session.finalize_init_uuid(&hash).unwrap(),
            recovered.session.finalize_init_uuid(&hash).unwrap()
        );
        let finalized = genuine.session.export_state().unwrap();
        let mut restored =
            session_with_manifest(&counted.context, &key, 1, opts, &expected_manifest);
        restored.session.import_state(&finalized).unwrap();
        // Version 2's random-salt state is not reinterpreted as version 3.
        let mut old: serde_json::Value = serde_json::from_slice(&record).unwrap();
        old["version"] = 2.into();
        let mut fresh = session_with_manifest(
            &counted.context,
            &key,
            1,
            options(TrustedVsiMode::ExpertSigStructure, None),
            &expected_manifest,
        );
        assert!(fresh
            .session
            .import_state(&serde_json::to_vec(&old).unwrap())
            .is_err());
    }
}

#[test]
fn reservation_reconstruction_rejects_injected_resources_and_databoxes() {
    let key = ed25519();
    let context = test_context();
    let opts = options(TrustedVsiMode::ExpertSigStructure, None);
    let mut genuine = session_with(&context, &key, 1, opts.clone());
    genuine.session.reserve_init_uuid("mp4").unwrap();
    for databox in [false, true] {
        let mut forged: StateRecord =
            serde_json::from_slice(&genuine.session.export_state().unwrap()).unwrap();
        let mut store = Store::from_jumbf_with_context(
            forged.state.reserved_jumbf.as_ref().unwrap(),
            &mut StatusTracker::default(),
            &context,
        )
        .unwrap();
        let claim = store.provenance_claim_mut().unwrap();
        claim.set_reservation_salt_nonce(genuine.session.reservation_nonce_bytes().unwrap());
        claim.clear_data();
        let unchanged = store
            .to_jumbf_internal(genuine.session.claim_signer_reserve_size)
            .unwrap();
        assert_eq!(
            forged.state.reserved_jumbf.as_deref(),
            Some(unchanged.as_slice())
        );
        let unchanged_uuid =
            Store::get_composed_manifest(&unchanged, INIT_FORMAT, &context).unwrap();
        assert_eq!(
            forged.state.reserved_uuid.as_deref(),
            Some(unchanged_uuid.as_slice())
        );
        forged.state.reserved_jumbf = Some(unchanged);
        forged.state.reserved_uuid = Some(unchanged_uuid);
        let mut control = session_with(&context, &key, 1, opts.clone());
        control
            .session
            .import_state(&serde_json::to_vec(&forged).unwrap())
            .unwrap();
        assert!(control.observations.lock().unwrap().is_empty());
        let claim = store.provenance_claim_mut().unwrap();
        if databox {
            claim
                .add_databox(
                    "application/octet-stream",
                    b"foreign resource".to_vec(),
                    None,
                )
                .unwrap();
            // A loaded claim retains the original order, which has no databox
            // store. Include the injected box so the negative artifact is real.
            claim.set_box_order(vec![
                crate::jumbf::labels::ASSERTIONS,
                crate::jumbf::labels::CLAIM,
                crate::jumbf::labels::SIGNATURE,
                crate::jumbf::labels::DATABOXES,
            ]);
        } else {
            claim
                .add_assertion(&crate::assertions::EmbeddedData::new(
                    "c2pa.thumbnail.claim",
                    "image/jpeg",
                    b"foreign resource".to_vec(),
                ))
                .unwrap();
        }
        claim.clear_data();
        let jumbf = store
            .to_jumbf_internal(genuine.session.claim_signer_reserve_size)
            .unwrap();
        assert_ne!(
            forged.state.reserved_jumbf.as_deref(),
            Some(jumbf.as_slice())
        );
        forged.state.reserved_uuid =
            Some(Store::get_composed_manifest(&jumbf, INIT_FORMAT, &context).unwrap());
        forged.state.reserved_jumbf = Some(jumbf);
        let mut fresh = session_with(&context, &key, 1, opts.clone());
        let before = fresh.session.export_state().unwrap();
        assert!(fresh
            .session
            .import_state(&serde_json::to_vec(&forged).unwrap())
            .is_err());
        assert_eq!(fresh.session.export_state().unwrap(), before);
        assert!(fresh.observations.lock().unwrap().is_empty());
    }
}

#[test]
fn private_reservation_salting_covers_resource_conversion_and_leaves_defaults_random() {
    for version in [1, 2] {
        let context = test_context();
        let label = if version == 1 {
            "urn:uuid:00112233-4455-4677-8899-aabbccddeeff"
        } else {
            "urn:c2pa:00112233-4455-4677-8899-aabbccddeeff"
        };
        let definition = serde_json::json!({"claim_version":version,"label":label,"instance_id":"fixed","claim_generator_info":[{"name":"resource-test","icon":{"format":"image/png","identifier":"icon"}}],"assertions":[{"label":"com.example.static","data":{"v":1}}]}).to_string();
        let build = || {
            let mut builder = Builder::from_shared_context(&context)
                .with_definition(&definition)
                .unwrap();
            builder.resources.add("icon", b"resource bytes").unwrap();
            builder
        };
        let expected = build()
            .to_trusted_reservation_store([7; 16])
            .unwrap()
            .to_jumbf_internal(1024)
            .unwrap();
        assert_eq!(
            build()
                .to_trusted_reservation_store([7; 16])
                .unwrap()
                .to_jumbf_internal(1024)
                .unwrap(),
            expected
        );
        assert_ne!(
            build().to_store().unwrap().to_jumbf_internal(1024).unwrap(),
            build().to_store().unwrap().to_jumbf_internal(1024).unwrap()
        );
    }
}

#[test]
fn import_rejects_mismatched_identity_and_tampering() {
    let key = ed25519();
    let context = test_context();
    let mut harness = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    harness.session.reserve_init_uuid("mp4").unwrap();
    let record = harness.session.export_state().unwrap();

    let mut other_nonce = options(TrustedVsiMode::ExpertSigStructure, None);
    other_nonce.reservation_nonce = "ffffffffffffffffffffffffffffffff".into();
    let mismatches = [
        session_with(&context, &key, 1, other_nonce),
        session_with(
            &context,
            &key,
            1,
            options(TrustedVsiMode::SignerComposedEmsg, None),
        ),
        session_with(
            &context,
            &key,
            2,
            options(TrustedVsiMode::ExpertSigStructure, None),
        ),
        session_with(
            &test_context(),
            &key,
            1,
            options(TrustedVsiMode::ExpertSigStructure, None),
        ),
    ];
    for mut mismatch in mismatches {
        assert!(mismatch.session.import_state(&record).is_err());
        assert_eq!(
            mismatch.session.status().unwrap().init_uuid_pending(),
            false
        );
    }
    let mut value: serde_json::Value = serde_json::from_slice(&record).unwrap();
    value["state"]["manifest_id"] = "urn:c2pa:00000000-0000-4000-8000-000000000000".into();
    let tampered = serde_json::to_vec(&value).unwrap();
    let mut fresh = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    assert!(fresh.session.import_state(&tampered).is_err());
    value = serde_json::from_slice(&record).unwrap();
    value["state"]["unexpected"] = true.into();
    assert!(fresh
        .session
        .import_state(&serde_json::to_vec(&value).unwrap())
        .is_err());
    fresh.session.import_state(&record).unwrap();
}

#[test]
fn dynamic_assertions_keep_order_refresh_and_reservation() {
    #[derive(Clone)]
    struct Recording(Arc<Mutex<Vec<(String, Vec<(String, Vec<u8>)>)>>>);

    struct Da(u8, Recording);
    impl DynamicAssertion for Da {
        fn label(&self) -> String {
            "com.example.trusted".to_string()
        }

        fn reserve_size(&self) -> Result<usize> {
            Ok(64)
        }

        fn content(
            &self,
            label: &str,
            _size: Option<usize>,
            claim: &PartialClaim,
        ) -> Result<DynamicAssertionContent> {
            let view = claim.assertions().map(|a| (a.url(), a.hash())).collect();
            self.1 .0.lock().unwrap().push((label.to_string(), view));
            if self.0 == b'b' {
                let mut content = r#"{"id":"b"}"#.to_string();
                content.push_str(&" ".repeat(64 - content.len()));
                return Ok(DynamicAssertionContent::Json(content));
            }
            let mut content = vec![self.0; 64];
            content[..6].copy_from_slice(&[0xa1, 0x62, b'i', b'd', 0x78, 58]);
            Ok(DynamicAssertionContent::Cbor(content))
        }
    }

    struct DaSigner(EphemeralSigner, Recording);
    impl Signer for DaSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            self.0.sign(data)
        }

        fn alg(&self) -> SigningAlg {
            self.0.alg()
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            self.0.certs()
        }

        fn reserve_size(&self) -> usize {
            self.0.reserve_size()
        }

        fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
            vec![
                Box::new(Da(b'a', self.1.clone())),
                Box::new(Da(b'b', self.1.clone())),
            ]
        }
    }

    let recording = Recording(Arc::default());
    let context = context_with_signer(DaSigner(
        EphemeralSigner::new("trusted-vsi-da.local").unwrap(),
        recording.clone(),
    ));
    let key = ed25519();
    let mut harness = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    harness.session.reserve_init_uuid("mp4").unwrap();
    assert!(
        recording.0.lock().unwrap().is_empty(),
        "DA content ran at reserve"
    );
    let (signed_init, reserved, signed) = establish_init(&mut harness);
    assert_eq!(reserved.len(), signed.len());
    validator_for(
        &context,
        &signed_init,
        harness.session.reserved_manifest_id().unwrap(),
    );

    let calls = recording.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "com.example.trusted");
    assert_eq!(calls[1].0, "com.example.trusted__1");
    assert!(!calls[0]
        .1
        .iter()
        .any(|(url, _)| url.ends_with("/com.example.trusted")));
    let signed_store = Store::from_jumbf(
        &signed[UUID_BOX_PREFIX_LEN..],
        &mut StatusTracker::default(),
    )
    .unwrap();
    let final_first = signed_store
        .provenance_claim()
        .unwrap()
        .assertions()
        .iter()
        .find(|a| a.url().ends_with("/com.example.trusted"))
        .unwrap()
        .hash();
    let seen = calls[1]
        .1
        .iter()
        .find(|(url, _)| url.ends_with("/com.example.trusted"))
        .unwrap();
    assert_eq!(
        seen.1, final_first,
        "second DA must see the refreshed first hash"
    );
    assert!(!calls[1].1.iter().any(|(url, _)| url.ends_with("__1")));
    drop(calls);
    let record = harness.session.export_state().unwrap();
    let mut restored = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    restored.session.import_state(&record).unwrap();
    assert!(restored.observations.lock().unwrap().is_empty());
    assert_eq!(recording.0.lock().unwrap().len(), 2);
    assert_eq!(restored.session.export_state().unwrap(), record);
}

#[test]
fn reserve_and_preflight_never_invoke_keys_or_mutate() {
    let key = ed25519();
    let context = test_context();
    let mut harness = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::SignerComposedEmsg, None),
    );
    let s = &harness.session;
    s.preflight(TrustedVsiOperation::ReserveInit, &[], 0, 0, 0, 0, "mp4")
        .unwrap();
    assert!(s
        .preflight(TrustedVsiOperation::FinalizeInit, &[], 0, 0, 0, 0, "")
        .is_err());
    assert!(s
        .preflight(TrustedVsiOperation::ReserveMedia, &[], 1, IAT, 1, 1, "")
        .is_err());
    let before = harness.session.export_state().unwrap();
    s.preflight(TrustedVsiOperation::ReserveInit, &[], 0, 0, 0, 0, "mp4")
        .unwrap();
    assert_eq!(harness.session.export_state().unwrap(), before);

    let reservation = harness.session.reserve_init_uuid("mp4").unwrap();
    let hash = trusted_vsi_compute_hash(
        TrustedVsiInputKind::InitHash,
        &insert_after_ftyp(INIT, reservation.bytes()),
    )
    .unwrap();
    let s = &harness.session;
    s.preflight(TrustedVsiOperation::FinalizeInit, &hash, 0, 0, 0, 0, "")
        .unwrap();
    assert!(s
        .preflight(TrustedVsiOperation::FinalizeInit, b"\xa0", 0, 0, 0, 0, "")
        .is_err());
    assert!(s
        .preflight(TrustedVsiOperation::CommitInit, &[], 0, 0, 0, 0, "")
        .is_err());
    assert_eq!(harness.observations.lock().unwrap().len(), 0);

    harness.session.finalize_init_uuid(&hash).unwrap();
    harness.session.commit_init_uuid().unwrap();
    let before = harness.observations.lock().unwrap().len();
    let s = &harness.session;
    s.preflight(
        TrustedVsiOperation::ReserveMedia,
        &[],
        1,
        IAT,
        90_000,
        1,
        "",
    )
    .unwrap();
    assert!(s
        .preflight(
            TrustedVsiOperation::ReserveMedia,
            &[],
            2,
            IAT,
            90_000,
            1,
            ""
        )
        .is_err());
    assert!(s
        .preflight(TrustedVsiOperation::ReserveMedia, &[], 1, IAT, 0, 1, "")
        .is_err());
    assert!(s
        .preflight(TrustedVsiOperation::ReserveMedia, &[], 1, 0, 1, 1, "")
        .is_err());
    assert!(s
        .preflight(TrustedVsiOperation::FinalizeMedia, &[], 0, 0, 0, 0, "")
        .is_err());
    let reservation = harness
        .session
        .reserve_media_emsg_at(1, IAT, 90_000, 1)
        .unwrap();
    let media_hash = trusted_vsi_compute_hash(
        TrustedVsiInputKind::MediaHash,
        &[reservation.bytes(), MEDIA].concat(),
    )
    .unwrap();
    harness
        .session
        .preflight(
            TrustedVsiOperation::FinalizeMedia,
            &media_hash,
            0,
            0,
            0,
            0,
            "",
        )
        .unwrap();
    assert_eq!(harness.observations.lock().unwrap().len(), before);
}

#[test]
fn hash_inputs_must_match_native_templates_exactly() {
    for kind in [
        TrustedVsiInputKind::InitHash,
        TrustedVsiInputKind::MediaHash,
    ] {
        let template = trusted_vsi_hash_template(kind).unwrap();
        validate_trusted_vsi_input(kind, SigningAlg::Ed25519, &template).unwrap();
        trusted_cbor::validate_single_value(&template, MAX_SMALL_CBOR_LEN).unwrap();
        let other = if kind == TrustedVsiInputKind::InitHash {
            TrustedVsiInputKind::MediaHash
        } else {
            TrustedVsiInputKind::InitHash
        };
        assert!(validate_trusted_vsi_input(other, SigningAlg::Ed25519, &template).is_err());
        let mut trailing = template.clone();
        trailing.push(0);
        assert!(validate_trusted_vsi_input(kind, SigningAlg::Ed25519, &trailing).is_err());
        let text = String::from_utf8_lossy(&template).to_string();
        assert!(text.contains("sha256"));
        let renamed: Vec<u8> = template
            .windows(6)
            .position(|w| w == b"sha256")
            .map(|at| {
                let mut bytes = template.clone();
                bytes[at..at + 6].copy_from_slice(b"sha512");
                bytes
            })
            .unwrap();
        assert!(validate_trusted_vsi_input(kind, SigningAlg::Ed25519, &renamed).is_err());
        // A non-deterministic re-encoding of the same map is rejected.
        let decoded: Value = c2pa_cbor::from_slice(&template).unwrap();
        let serde_order = c2pa_cbor::to_vec(&decoded).unwrap();
        if serde_order != template {
            assert!(validate_trusted_vsi_input(kind, SigningAlg::Ed25519, &serde_order).is_err());
        }
    }
    assert!(trusted_vsi_hash_template(TrustedVsiInputKind::SigStructure).is_err());
}

#[test]
fn options_and_configuration_are_validated() {
    let parsed = TrustedVsiSessionOptions::from_json(&format!(
        r#"{{"mode":"signer_composed_emsg","reservation_nonce":"{NONCE}","signing_time_unix_seconds":{IAT}}}"#
    ))
    .unwrap();
    assert_eq!(parsed, options(TrustedVsiMode::SignerComposedEmsg, None));
    assert!(TrustedVsiSessionOptions::from_json(&format!(
        r#"{{"mode":"expert_sig_structure","reservation_nonce":"{NONCE}","signing_time_unix_seconds":{IAT},"extra":1}}"#
    ))
    .is_err());
    let context = test_context();
    let key = ed25519();
    let build = |min: u64, opts: TrustedVsiSessionOptions, manifest: &str| {
        TrustedVsiPrehashedSession::from_shared_context_with_callback(
            &context,
            manifest,
            config(&key, min),
            opts,
            |_, _| Err(Error::BadParam("must not be called".into())),
        )
    };
    let mut bad_nonce = options(TrustedVsiMode::ExpertSigStructure, None);
    bad_nonce.reservation_nonce = NONCE.to_uppercase();
    assert!(build(1, bad_nonce, MANIFEST).is_err());
    let mut expired = options(TrustedVsiMode::ExpertSigStructure, None);
    expired.signing_time_unix_seconds = 1;
    assert!(build(1, expired, MANIFEST).is_err());
    assert!(build(
        10,
        options(TrustedVsiMode::ExpertSigStructure, Some(9)),
        MANIFEST
    )
    .is_err());
    assert!(build(
        u64::from(u32::MAX) + 1,
        options(TrustedVsiMode::ExpertSigStructure, None),
        MANIFEST
    )
    .is_err());
    assert!(build(
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
        r#"{"label":"urn:c2pa:x"}"#
    )
    .is_err());
    assert!(build(
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
        r#"{"assertions":[{"label":"c2pa.session-keys","data":{}}]}"#
    )
    .is_err());
    build(
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
        MANIFEST,
    )
    .unwrap();
}

fn b64_field(value: &serde_json::Value) -> Vec<u8> {
    crate::crypto::base64::decode(value.as_str().unwrap()).unwrap()
}

fn b64_value(bytes: &[u8]) -> serde_json::Value {
    crate::crypto::base64::encode(bytes).into()
}

/// Imports each tampered variant into a fresh session and requires rejection
/// before any mutation; the untampered record must still import.
fn assert_tampers_rejected(
    context: &Arc<Context>,
    key: &SessionKeyMaterial,
    min_sequence_number: u64,
    opts: &TrustedVsiSessionOptions,
    record: &[u8],
    tampers: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)>,
) {
    for (name, tamper) in tampers {
        let mut value: serde_json::Value = serde_json::from_slice(record).unwrap();
        tamper(&mut value);
        let tampered = serde_json::to_vec(&value).unwrap();
        assert_ne!(tampered, record, "{name}: tamper had no effect");
        let mut fresh = session_with(context, key, min_sequence_number, opts.clone());
        let before = fresh.session.export_state().unwrap();
        assert!(
            fresh.session.import_state(&tampered).is_err(),
            "{name}: tampered record was accepted"
        );
        assert_eq!(
            fresh.session.export_state().unwrap(),
            before,
            "{name}: mutated"
        );
        assert!(fresh.observations.lock().unwrap().is_empty());
    }
    let mut fresh = session_with(context, key, min_sequence_number, opts.clone());
    fresh.session.import_state(record).unwrap();
}

fn flip_after(bytes: &mut [u8], needle: &[u8]) {
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("needle {:?} not found", String::from_utf8_lossy(needle)));
    bytes[at + needle.len() - 1] ^= 0x01;
}

#[test]
fn import_rejects_unsigned_or_tampered_signed_init() {
    for key in [ed25519(), es256()] {
        for mode in [
            TrustedVsiMode::ExpertSigStructure,
            TrustedVsiMode::SignerComposedEmsg,
        ] {
            let context = test_context();
            let opts = options(mode, None);
            let mut harness = session_with(&context, &key, 1, opts.clone());
            establish_init(&mut harness);
            let finalized = harness.session.export_state().unwrap();
            harness.session.commit_init_uuid().unwrap();
            let committed = harness.session.export_state().unwrap();

            // The same init finalized by a different claim signer.
            let other_context = test_context();
            let mut other = session_with(&other_context, &key, 1, opts.clone());
            establish_init(&mut other);
            let foreign: serde_json::Value =
                serde_json::from_slice(&other.session.export_state().unwrap()).unwrap();
            let foreign_uuid = foreign["state"]["signed_uuid"].clone();

            for record in [&finalized, &committed] {
                let foreign_uuid = foreign_uuid.clone();
                let tampers: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
                    (
                        "reserved UUID swapped in as signed",
                        Box::new(|v| {
                            v["state"]["signed_uuid"] = v["state"]["reserved_uuid"].clone()
                        }),
                    ),
                    (
                        "session key kid altered",
                        Box::new(|v| {
                            let mut signed = b64_field(&v["state"]["signed_uuid"]);
                            flip_after(&mut signed, KID);
                            v["state"]["signed_uuid"] = b64_value(&signed);
                        }),
                    ),
                    (
                        "manifest assertion content altered",
                        Box::new(|v| {
                            let mut signed = b64_field(&v["state"]["signed_uuid"]);
                            flip_after(&mut signed, b"c2pa.created");
                            v["state"]["signed_uuid"] = b64_value(&signed);
                        }),
                    ),
                    (
                        "recorded init hash input differs from hard binding",
                        Box::new(|v| {
                            let template =
                                trusted_vsi_hash_template(TrustedVsiInputKind::InitHash).unwrap();
                            v["state"]["init_hash_input"] = b64_value(&template);
                        }),
                    ),
                    (
                        "signed by a different claim signer",
                        Box::new(move |v| v["state"]["signed_uuid"] = foreign_uuid.clone()),
                    ),
                ];
                assert_tampers_rejected(&context, &key, 1, &opts, record, tampers);
            }
        }
    }
}

#[test]
fn import_rejects_composed_counters_inconsistent_with_history() {
    for key in [ed25519(), es256()] {
        let context = test_context();
        let first = media_sequence(MEDIA);
        let min = u64::from(first);
        let opts = options(TrustedVsiMode::SignerComposedEmsg, None);
        let mut harness = session_with(&context, &key, min, opts.clone());
        establish_init(&mut harness);
        harness.session.commit_init_uuid().unwrap();
        let empty = harness.session.export_state().unwrap();
        composed_segment(&mut harness.session, MEDIA);
        composed_segment(&mut harness.session, MEDIA_NEXT);
        let completed = harness.session.export_state().unwrap();
        let (timescale, duration) = media_timing(MEDIA_NEXT);
        harness
            .session
            .reserve_media_emsg_at(first + 2, IAT, timescale, duration)
            .unwrap();
        let pending = harness.session.export_state().unwrap();

        let counter_tampers = || -> Vec<(&'static str, Box<dyn Fn(&mut serde_json::Value)>)> {
            vec![
                (
                    "event rolled back (to 1, or to 0 when already 1)",
                    Box::new(|v| {
                        let n = v["state"]["next_event_id"].as_u64().unwrap();
                        v["state"]["next_event_id"] = if n > 1 { 1 } else { 0 }.into();
                    }),
                ),
                (
                    "event skipped ahead",
                    Box::new(|v| {
                        let n = v["state"]["next_event_id"].as_u64().unwrap();
                        v["state"]["next_event_id"] = (n + 1).into();
                    }),
                ),
                (
                    "sequence rolled back",
                    Box::new(|v| {
                        let n = v["state"]["next_sequence_number"].as_u64().unwrap();
                        v["state"]["next_sequence_number"] = (n - 1).into();
                    }),
                ),
                (
                    "fabricated terminal state",
                    Box::new(|v| {
                        v["state"]["exhaustion_reason"] = "sequence_max".into();
                        v["state"]["next_sequence_number"] = serde_json::Value::Null;
                        v["state"]["next_event_id"] = serde_json::Value::Null;
                        v["state"]["pending_media"] = serde_json::Value::Null;
                    }),
                ),
                (
                    "fabricated legacy terminal state",
                    Box::new(|v| {
                        v["state"]["exhaustion_reason"] = "legacy_sentinel".into();
                        v["state"]["next_sequence_number"] = serde_json::Value::Null;
                        v["state"]["next_event_id"] = serde_json::Value::Null;
                        v["state"]["pending_media"] = serde_json::Value::Null;
                    }),
                ),
            ]
        };
        let mut empty_tampers = counter_tampers();
        empty_tampers.push((
            "fabricated completed media on empty history",
            Box::new(|v| {
                v["state"]["next_sequence_number"] =
                    (v["state"]["next_sequence_number"].as_u64().unwrap() + 1).into();
                v["state"]["next_event_id"] = 2.into();
            }),
        ));
        assert_tampers_rejected(&context, &key, min, &opts, &empty, empty_tampers);

        let mut history_tampers = counter_tampers();
        history_tampers.extend::<Vec<(&'static str, Box<dyn Fn(&mut serde_json::Value)>)>>(vec![
            (
                "last media event reused",
                Box::new(|v| v["state"]["last_media"]["event_id"] = 1.into()),
            ),
            (
                "last media removed",
                Box::new(|v| v["state"]["last_media"] = serde_json::Value::Null),
            ),
            (
                "cached EMSG signature altered",
                Box::new(|v| {
                    let mut emsg = b64_field(&v["state"]["last_media"]["signed_emsg"]);
                    let last = emsg.len() - 1;
                    emsg[last] ^= 0x01;
                    v["state"]["last_media"]["signed_emsg"] = b64_value(&emsg);
                }),
            ),
            (
                "cached EMSG replaced by arbitrary bytes",
                Box::new(|v| v["state"]["last_media"]["signed_emsg"] = b64_value(b"not an emsg")),
            ),
            (
                "recorded hash input differs from the cached EMSG",
                Box::new(|v| {
                    let template =
                        trusted_vsi_hash_template(TrustedVsiInputKind::MediaHash).unwrap();
                    v["state"]["last_media"]["hash_input"] = b64_value(&template);
                }),
            ),
            (
                "recorded iat altered",
                Box::new(|v| {
                    let iat = v["state"]["last_media"]["signing_time_unix_seconds"]
                        .as_i64()
                        .unwrap();
                    v["state"]["last_media"]["signing_time_unix_seconds"] = (iat + 1).into();
                }),
            ),
            (
                "recorded duration altered",
                Box::new(|v| {
                    let d = v["state"]["last_media"]["event_duration"].as_u64().unwrap();
                    v["state"]["last_media"]["event_duration"] = (d + 1).into();
                }),
            ),
        ]);
        assert_tampers_rejected(&context, &key, min, &opts, &completed, history_tampers);

        let pending_tampers: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
            (
                "pending event rolled back",
                Box::new(|v| v["state"]["pending_media"]["event_id"] = 1.into()),
            ),
            (
                "pending and counters rolled back together",
                Box::new(|v| {
                    v["state"]["pending_media"]["event_id"] = 1.into();
                    v["state"]["next_event_id"] = 1.into();
                }),
            ),
            (
                "pending timing zero",
                Box::new(|v| v["state"]["pending_media"]["timescale"] = 0.into()),
            ),
            (
                "pending placeholder altered",
                Box::new(|v| {
                    let mut p = b64_field(&v["state"]["pending_media"]["placeholder"]);
                    let last = p.len() - 1;
                    p[last] ^= 0x01;
                    v["state"]["pending_media"]["placeholder"] = b64_value(&p);
                }),
            ),
        ];
        assert_tampers_rejected(&context, &key, min, &opts, &pending, pending_tampers);
    }
}

/// RFC 8949 §4.2.1 bytewise key order applies to expert protected headers:
/// `{1: -8, 1000: 0, "a": 0}` is accepted; the obsolete RFC 7049 length-first
/// order `{1: -8, "a": 0, 1000: 0}` is rejected.
#[test]
fn expert_protected_header_uses_rfc8949_bytewise_order() {
    let bytewise = [
        0xa4, 0x01, 0x27, 0x19, 0x03, 0xe8, 0x00, 0x61, b'a', 0x00, 0x63, b'i', b'a', b't', 0x00,
    ];
    let length_first = [
        0xa4, 0x01, 0x27, 0x61, b'a', 0x00, 0x19, 0x03, 0xe8, 0x00, 0x63, b'i', b'a', b't', 0x00,
    ];
    let payload = native_payload(&expert_tbs(&ed25519(), "urn:c2pa:test", 1, IAT));
    let accepted = raw_sig_structure(&bytewise, &payload);
    let rejected = raw_sig_structure(&length_first, &payload);
    validate_trusted_vsi_input(
        TrustedVsiInputKind::SigStructure,
        SigningAlg::Ed25519,
        &accepted,
    )
    .unwrap();
    assert!(validate_trusted_vsi_input(
        TrustedVsiInputKind::SigStructure,
        SigningAlg::Ed25519,
        &rejected,
    )
    .is_err());
}

/// DA whose declared reserve size is shared and observable, and which counts
/// every content request.
struct CountingDa {
    label: &'static str,
    size: Arc<std::sync::atomic::AtomicUsize>,
    content_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl DynamicAssertion for CountingDa {
    fn label(&self) -> String {
        self.label.to_string()
    }

    fn reserve_size(&self) -> Result<usize> {
        Ok(self.size.load(Ordering::SeqCst))
    }

    fn content(
        &self,
        _label: &str,
        size: Option<usize>,
        _claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent> {
        self.content_calls.fetch_add(1, Ordering::SeqCst);
        let size = size.unwrap_or(self.size.load(Ordering::SeqCst));
        // CBOR text-keyed map {"id": bytes} padded to exactly `size`.
        let mut content = vec![b'x'; size];
        content[..5].copy_from_slice(&[0xa1, 0x62, b'i', b'd', 0x78]);
        content[5] = u8::try_from(size - 6).unwrap();
        Ok(DynamicAssertionContent::Cbor(content))
    }
}

/// Claim signer sharing one certificate across contexts that differ only in
/// their declared dynamic assertions.
struct SharedCertSigner {
    base: Arc<EphemeralSigner>,
    das: Vec<(&'static str, Arc<std::sync::atomic::AtomicUsize>)>,
    content_calls: Arc<std::sync::atomic::AtomicUsize>,
    sign_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Signer for SharedCertSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        self.base.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.base.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.base.certs()
    }

    fn reserve_size(&self) -> usize {
        self.base.reserve_size()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        self.das
            .iter()
            .map(|(label, size)| {
                Box::new(CountingDa {
                    label,
                    size: Arc::clone(size),
                    content_calls: Arc::clone(&self.content_calls),
                }) as Box<dyn DynamicAssertion>
            })
            .collect()
    }
}

struct DaContext {
    context: Arc<Context>,
    content_calls: Arc<std::sync::atomic::AtomicUsize>,
    sign_calls: Arc<std::sync::atomic::AtomicUsize>,
}

fn da_context(base: &Arc<EphemeralSigner>, das: &[(&'static str, usize)]) -> DaContext {
    let content_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let das = das
        .iter()
        .map(|(label, size)| (*label, Arc::new(std::sync::atomic::AtomicUsize::new(*size))))
        .collect();
    DaContext {
        context: context_with_signer(SharedCertSigner {
            base: Arc::clone(base),
            das,
            content_calls: Arc::clone(&content_calls),
            sign_calls: Arc::clone(&sign_calls),
        }),
        content_calls,
        sign_calls,
    }
}

#[test]
fn import_rejects_mismatched_dynamic_assertion_declarations() {
    let key = ed25519();
    let base = Arc::new(EphemeralSigner::new("trusted-vsi-shared.local").unwrap());
    let opts = options(TrustedVsiMode::ExpertSigStructure, None);
    let one = [("com.example.functional", 64)];
    let declarations: [&[(&'static str, usize)]; 5] = [
        &[],
        &one,
        &[("com.example.functional", 96)],
        &[("com.example.functional", 64), ("com.example.other", 64)],
        &[("com.example.other", 64), ("com.example.functional", 64)],
    ];
    for (source_index, source) in declarations.iter().enumerate() {
        let source_context = da_context(&base, source);
        let mut harness = session_with(&source_context.context, &key, 1, opts.clone());
        harness.session.reserve_init_uuid("mp4").unwrap();
        let pending = harness.session.export_state().unwrap();
        for (target_index, target) in declarations.iter().enumerate() {
            let target_context = da_context(&base, target);
            let mut fresh = session_with(&target_context.context, &key, 1, opts.clone());
            let before = fresh.session.export_state().unwrap();
            let result = fresh.session.import_state(&pending);
            if source_index == target_index {
                result.unwrap();
                continue;
            }
            assert!(
                result.is_err(),
                "DA set {source:?} imported into {target:?}"
            );
            assert_eq!(fresh.session.export_state().unwrap(), before);
            assert!(fresh.observations.lock().unwrap().is_empty());
            assert_eq!(target_context.content_calls.load(Ordering::SeqCst), 0);
            assert_eq!(target_context.sign_calls.load(Ordering::SeqCst), 0);
        }
    }

    // A v1 record (no pinned declarations) is rejected.
    let context = da_context(&base, &one);
    let mut harness = session_with(&context.context, &key, 1, opts.clone());
    harness.session.reserve_init_uuid("mp4").unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&harness.session.export_state().unwrap()).unwrap();
    assert_eq!(value["version"], 3);
    assert_eq!(
        value["identity"]["dynamic_assertions"],
        serde_json::json!([{"label": "com.example.functional", "reserve_size": 64}])
    );
    value["version"] = 1.into();
    value["identity"]
        .as_object_mut()
        .unwrap()
        .remove("dynamic_assertions");
    let mut fresh = session_with(&context.context, &key, 1, opts);
    assert!(fresh
        .session
        .import_state(&serde_json::to_vec(&value).unwrap())
        .is_err());
}

#[test]
fn finalize_rejects_dynamic_assertion_drift_before_any_callback() {
    let key = ed25519();
    let base = Arc::new(EphemeralSigner::new("trusted-vsi-drift.local").unwrap());
    let size = Arc::new(std::sync::atomic::AtomicUsize::new(64));
    let content_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let context = context_with_signer(SharedCertSigner {
        base,
        das: vec![("com.example.functional", Arc::clone(&size))],
        content_calls: Arc::clone(&content_calls),
        sign_calls: Arc::clone(&sign_calls),
    });
    let mut harness = session_with(
        &context,
        &key,
        1,
        options(TrustedVsiMode::ExpertSigStructure, None),
    );
    let reservation = harness.session.reserve_init_uuid("mp4").unwrap();
    let placed = insert_after_ftyp(INIT, reservation.bytes());
    let hash = trusted_vsi_compute_hash(TrustedVsiInputKind::InitHash, &placed).unwrap();

    // The DA's declaration drifts after reservation.
    size.store(96, Ordering::SeqCst);
    assert!(harness
        .session
        .preflight(TrustedVsiOperation::FinalizeInit, &hash, 0, 0, 0, 0, "")
        .is_err());
    let error = harness.session.finalize_init_uuid(&hash).unwrap_err();
    assert!(error.to_string().contains("dynamic-assertion"), "{error}");
    assert!(harness.observations.lock().unwrap().is_empty());
    assert_eq!(content_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);
    let status = harness.session.status().unwrap();
    assert!(!status.blocked());
    assert!(status.init_uuid_pending());

    // Not blocked: once declarations match again, the same session finalizes.
    size.store(64, Ordering::SeqCst);
    let signed = harness.session.finalize_init_uuid(&hash).unwrap();
    assert_eq!(signed.len(), reservation.bytes().len());
    assert_eq!(harness.observations.lock().unwrap().len(), 1);
    assert_eq!(content_calls.load(Ordering::SeqCst), 1);
    validator_for(
        &context,
        &insert_after_ftyp(INIT, &signed),
        harness.session.reserved_manifest_id().unwrap(),
    );
}
