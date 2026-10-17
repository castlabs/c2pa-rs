// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Reader-verified init updates using real BMFF assets and either crypto backend.

#![allow(clippy::unwrap_used)]

use std::{io::Cursor, sync::Arc};

use super::{
    bmff::parse_init_segment, verifiable_segment_info::extract_vsi_emsg_from_segment,
    Ed25519SessionKey, LiveVideoValidator, LiveVideoVsiSigner, SequenceCoverage,
    LIVEVIDEO_SEGMENT_GAP, LIVEVIDEO_SEGMENT_LEADING_GAP,
};
use crate::{
    assertions::SessionKeys,
    live_video::moof_sequence_number,
    status_tracker::{ErrorBehavior, StatusTracker},
    utils::{test::test_context, test_signer::test_signer},
    validation_results::{validation_codes, ValidationState},
    Context, Reader, SigningAlg,
};

const INIT: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s_init.mp4");
const MEDIA_A: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s102.m4s");
const MEDIA_B: &[u8] =
    include_bytes!("../../tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s103.m4s");

fn trusted_context() -> Arc<Context> {
    // Override the settings' TSA-enabled signer, not the verification requirements.
    let mut context = test_context().with_signer(test_signer(SigningAlg::Es256));
    let settings = context.settings_mut();
    settings.verify.verify_after_reading = true;
    settings.verify.verify_after_sign = true;
    settings.verify.verify_after_sign_hash = true;
    settings.verify.verify_trust = true;
    settings.verify.verify_timestamp_trust = true;
    settings.verify.ocsp_fetch = false;
    settings.verify.remote_manifest_fetch = false;
    settings.builder.certificate_status_fetch = None;
    assert!(context.signer().unwrap().time_authority_url().is_none());
    context.into_shared()
}

fn producer(context: &Arc<Context>, first_media: &[u8]) -> LiveVideoVsiSigner {
    let minimum = u64::from(moof_sequence_number(first_media).unwrap());
    LiveVideoVsiSigner::from_shared_context(
        context,
        r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
        Ed25519SessionKey::from_bytes(&[0x42; 32]),
        b"verified-update-session".to_vec(),
        minimum,
        3600,
    )
    .unwrap()
}

fn read_init(context: &Arc<Context>, init: &[u8]) -> Reader {
    Reader::from_shared_context(context)
        .with_stream("video/mp4", Cursor::new(init))
        .unwrap()
}

fn verified_init_material(reader: &Reader) -> Option<(SessionKeys, String, Vec<u8>)> {
    // The raw update API does not establish trust or verify the init hard binding.
    if reader.validation_state() != ValidationState::Trusted {
        return None;
    }
    let results = reader.validation_results().unwrap();
    if !results.active_manifest().unwrap().failure().is_empty() {
        return None;
    }
    let manifest = reader.active_manifest().unwrap();
    let keys = manifest.find_assertion(SessionKeys::LABEL).unwrap();
    let label = manifest.label().unwrap().to_string();
    let certs = pem::parse_many(manifest.signature_info().unwrap().cert_chain()).unwrap();
    let leaf_der = certs.into_iter().next().unwrap().into_contents();
    Some((keys, label, leaf_der))
}

fn initialized_receiver(
    init: &[u8],
    reader: &Reader,
    behavior: ErrorBehavior,
) -> (LiveVideoValidator, StatusTracker) {
    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    assert!(reader
        .validation_results()
        .unwrap()
        .active_manifest()
        .unwrap()
        .failure()
        .is_empty());
    let (keys, label, leaf) = verified_init_material(reader).unwrap();
    let mut receiver = LiveVideoValidator::new();
    let mut tracker = StatusTracker::with_error_behavior(behavior);
    receiver.validate_init_segment(init, &mut tracker).unwrap();
    receiver
        .validate_session_keys(&keys, &label, Some(&leaf), &mut tracker)
        .unwrap();
    assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
    (receiver, tracker)
}

fn assert_media_accepted(
    receiver: &mut LiveVideoValidator,
    tracker: &mut StatusTracker,
    media: &[u8],
    label: &str,
    event_id: u32,
) {
    let event = extract_vsi_emsg_from_segment(media).unwrap().unwrap();
    assert_eq!(event.id, event_id);
    receiver
        .validate_verifiable_segment_info(media, tracker)
        .unwrap();
    // Aggregate mode can return Ok after logging a failure.
    assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
    let previous = receiver.previous_segment.as_ref().unwrap();
    assert_eq!(
        previous.sequence_number,
        u64::from(moof_sequence_number(media).unwrap())
    );
    assert_eq!(previous.manifest_id, label);
    assert_eq!(receiver.expected_manifest_id.as_deref(), Some(label));
    assert!(receiver.seen_emsg_ids.contains(&event_id));
    assert_eq!(receiver.sequence_coverage(), &SequenceCoverage::default());
    assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_GAP));
    assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_LEADING_GAP));
}

#[test]
fn reader_verified_vsi_update_preserves_producer_and_receiver_continuity() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        assert_eq!(
            moof_sequence_number(MEDIA_B).unwrap(),
            moof_sequence_number(MEDIA_A).unwrap() + 1
        );
        let context = trusted_context();
        let mut producer = producer(&context, MEDIA_A);
        let init_a = producer
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let (keys_a, label_a, leaf_a) = verified_init_material(&reader_a).unwrap();
        let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, behavior);
        let media_a = producer.sign_media_segment(MEDIA_A).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_a, &label_a, 1);

        // Re-sign on the SAME producer: neither sequence nor EMSG ID may restart.
        let init_b = producer
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let reader_b = read_init(&context, &init_b);
        assert_eq!(reader_b.validation_state(), ValidationState::Trusted);
        let (keys_b, label_b, leaf_b) = verified_init_material(&reader_b).unwrap();
        assert_ne!(label_a, label_b);
        assert_eq!(keys_a.keys[0].key, keys_b.keys[0].key);
        assert_eq!(leaf_a, leaf_b);
        receiver
            .update_vsi_context(
                Some(&init_b),
                &keys_b,
                &label_b,
                Some(&leaf_b),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
        let previous = receiver.previous_segment.as_ref().unwrap();
        assert_eq!(previous.manifest_id, label_a);
        assert_eq!(
            previous.sequence_number,
            u64::from(moof_sequence_number(MEDIA_A).unwrap())
        );
        assert_eq!(receiver.seen_emsg_ids, [1].into_iter().collect());

        let media_b = producer.sign_media_segment(MEDIA_B).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_b, &label_b, 2);
        assert_eq!(receiver.seen_emsg_ids, [1, 2].into_iter().collect());
    }
}

#[test]
fn reader_untrusted_vsi_init_is_not_installed_and_old_context_remains_usable() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let context = trusted_context();
        let mut producer = producer(&context, MEDIA_A);
        let init_a = producer
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let label_a = reader_a.active_manifest().unwrap().label().unwrap();
        let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, behavior);
        let media_a = producer.sign_media_segment(MEDIA_A).unwrap();
        let next_a = producer.sign_media_segment(MEDIA_B).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_a, label_a, 1);
        let init_b = producer
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let trusted_b = read_init(&context, &init_b);
        assert!(verified_init_material(&trusted_b).is_some());
        assert_ne!(trusted_b.active_manifest().unwrap().label(), Some(label_a));

        let mut anchorless = test_context();
        *anchorless.settings_mut() = context.settings().clone();
        // Trust::default() loads test CAs under cfg(test); remove all anchor allow-lists too.
        anchorless.settings_mut().trust.anchors = Some(vec![]);
        assert!(anchorless.settings().verify.verify_trust);
        assert!(anchorless.settings().verify.verify_after_reading);
        let reader_b = read_init(&anchorless.into_shared(), &init_b);
        assert_ne!(reader_b.validation_state(), ValidationState::Trusted);
        assert!(reader_b
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .failure()
            .iter()
            .any(|status| status.code() == validation_codes::SIGNING_CREDENTIAL_UNTRUSTED));

        // A caller must not invoke update with material from this untrusted Reader.
        assert!(verified_init_material(&reader_b).is_none());
        // The failed admission gate intentionally prevents any update call.
        assert_eq!(receiver.seen_emsg_ids, [1].into_iter().collect());
        assert_media_accepted(&mut receiver, &mut tracker, &next_a, label_a, 2);
    }
}

#[test]
fn reader_hard_binding_failure_blocks_vsi_update_without_losing_old_context() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let context = trusted_context();
        let mut producer = producer(&context, MEDIA_A);
        let init_a = producer
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let label_a = reader_a.active_manifest().unwrap().label().unwrap();
        let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, behavior);
        let media_a = producer.sign_media_segment(MEDIA_A).unwrap();
        let next_a = producer.sign_media_segment(MEDIA_B).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_a, label_a, 1);
        let mut init_b = producer
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let valid_b = read_init(&context, &init_b);
        assert!(verified_init_material(&valid_b).is_some());
        assert_ne!(valid_b.active_manifest().unwrap().label(), Some(label_a));
        let original_layout = parse_init_segment(&init_b).unwrap();

        // Change mvhd's fixed-point playback rate, outside the manifest/exclusions.
        // Keep box layout and all VSI track/timing fields parseable and unchanged.
        let mvhd = init_b
            .windows(4)
            .position(|bytes| bytes == b"mvhd")
            .unwrap();
        assert_eq!(init_b[mvhd + 4], 0, "fixture uses a version-0 mvhd");
        init_b[mvhd + 27] ^= 1;
        assert_eq!(parse_init_segment(&init_b).unwrap(), original_layout);
        let reader_b = read_init(&context, &init_b);
        assert_eq!(reader_b.validation_state(), ValidationState::Invalid);
        assert_eq!(
            reader_b.active_manifest().unwrap().label(),
            valid_b.active_manifest().unwrap().label()
        );
        assert!(reader_b
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .failure()
            .iter()
            .any(|status| status.code() == validation_codes::ASSERTION_BMFFHASH_MISMATCH));
        assert!(verified_init_material(&reader_b).is_none());
        // The failed hard-binding gate intentionally prevents any update call.
        assert_eq!(receiver.seen_emsg_ids, [1].into_iter().collect());
        assert_media_accepted(&mut receiver, &mut tracker, &next_a, label_a, 2);
    }
}

#[test]
fn reader_verified_fresh_producer_event_id_collision_does_not_advance_receiver() {
    for behavior in [
        ErrorBehavior::ContinueWhenPossible,
        ErrorBehavior::StopOnFirstError,
    ] {
        let stop_on_error = behavior == ErrorBehavior::StopOnFirstError;
        let context = trusted_context();
        let mut producer_a = producer(&context, MEDIA_A);
        let init_a = producer_a
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let reader_a = read_init(&context, &init_a);
        let (keys_a, label_a, _) = verified_init_material(&reader_a).unwrap();
        let (mut receiver, mut tracker) = initialized_receiver(&init_a, &reader_a, behavior);
        let media_a = producer_a.sign_media_segment(MEDIA_A).unwrap();
        assert_media_accepted(&mut receiver, &mut tracker, &media_a, &label_a, 1);

        // A new producer can use the right key and next MFHD yet restart EMSG IDs.
        let mut producer_b = producer(&context, MEDIA_B);
        let init_b = producer_b
            .sign_init_segment_with_context(INIT, "video/mp4")
            .unwrap();
        let reader_b = read_init(&context, &init_b);
        assert_eq!(reader_b.validation_state(), ValidationState::Trusted);
        let (keys_b, label_b, leaf_b) = verified_init_material(&reader_b).unwrap();
        assert_ne!(label_a, label_b);
        assert_eq!(keys_a.keys[0].key, keys_b.keys[0].key);
        assert_eq!(
            keys_b.keys[0].min_sequence_number,
            u64::from(moof_sequence_number(MEDIA_B).unwrap())
        );
        receiver
            .update_vsi_context(
                Some(&init_b),
                &keys_b,
                &label_b,
                Some(&leaf_b),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0, "{tracker:?}");
        let media_b = producer_b.sign_media_segment(MEDIA_B).unwrap();
        assert_eq!(
            extract_vsi_emsg_from_segment(&media_b).unwrap().unwrap().id,
            1
        );
        let result = receiver.validate_verifiable_segment_info(&media_b, &mut tracker);
        assert_eq!(result.is_err(), stop_on_error);
        let failures: Vec<_> = tracker.filter_errors().collect();
        assert_eq!(failures.len(), 1, "{tracker:?}");
        assert_eq!(
            failures[0].validation_status.as_deref(),
            Some(validation_codes::LIVEVIDEO_SEGMENT_INVALID)
        );
        assert_eq!(
            failures[0].description,
            "VSI emsg id must be unique within the live session"
        );
        let previous = receiver.previous_segment.as_ref().unwrap();
        assert_eq!(previous.manifest_id, label_a);
        assert_eq!(
            previous.sequence_number,
            u64::from(moof_sequence_number(MEDIA_A).unwrap())
        );
        assert_eq!(
            receiver.expected_manifest_id.as_deref(),
            Some(label_b.as_str())
        );
        assert_eq!(receiver.seen_emsg_ids, [1].into_iter().collect());
        assert_eq!(receiver.sequence_coverage(), &SequenceCoverage::default());
        assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_GAP));
        assert!(!tracker.has_status(LIVEVIDEO_SEGMENT_LEADING_GAP));
    }
}
