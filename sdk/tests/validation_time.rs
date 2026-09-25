// Copyright 2026 Castlabs. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Caller-controlled validation time and per-purpose trust selection.

mod common;

use std::io::Cursor;

use c2pa::{settings::Settings, validation_status, Builder, Context, Reader, Result};
use common::{test_settings, test_signer};

const MANIFEST: &str = r#"{
    "claim_generator_info": [{"name": "validation-time-test", "version": "1"}],
    "assertions": [{
        "label": "c2pa.actions.v2",
        "data": {"actions": [{
            "action": "c2pa.created",
            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
        }]}
    }]
}"#;

/// Sign a JPEG without a time stamp so certificate validity depends only on the
/// evaluation instant (fixture signer valid 2022-06-10 .. 2030-08-26).
fn signed_untimestamped() -> Result<Vec<u8>> {
    let mut settings = test_settings();
    settings.verify.verify_after_sign = false;
    let context = Context::new().with_settings(settings)?;
    let mut builder = Builder::from_context(context).with_definition(MANIFEST)?;
    let mut source = Cursor::new(include_bytes!("fixtures/earth_apollo17.jpg").to_vec());
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), "image/jpeg", &mut source, &mut dest)?;
    Ok(dest.into_inner())
}

fn read_at(asset: &[u8], validation_time: Option<&str>, strict: bool) -> Result<Reader> {
    let mut settings = test_settings();
    settings.verify.validation_time = validation_time.map(str::to_string);
    settings.verify.strict_trust_purposes = strict;
    // Remove the fixture signer/TSA so no network or signer settings are involved.
    settings.signer = None;
    Reader::from_context(Context::new().with_settings(settings)?)
        .with_stream("image/jpeg", Cursor::new(asset.to_vec()))
}

fn codes(reader: &Reader) -> (Vec<String>, Vec<String>) {
    let results = reader.validation_results().expect("validation results");
    let active = results.active_manifest().expect("active manifest codes");
    (
        active
            .success()
            .iter()
            .map(|s| s.code().to_string())
            .collect(),
        active
            .failure()
            .iter()
            .map(|s| s.code().to_string())
            .collect(),
    )
}

#[test]
fn untimestamped_credential_follows_supplied_time() -> Result<()> {
    let asset = signed_untimestamped()?;

    for (time, expect_expired) in [
        ("2021-01-01T00:00:00Z", true),
        ("2027-01-15T08:00:00Z", false),
        ("2031-01-01T00:00:00+01:00", true),
    ] {
        let reader = read_at(&asset, Some(time), false)?;
        let (success, failure) = codes(&reader);
        assert_eq!(
            failure
                .iter()
                .any(|c| c == validation_status::SIGNING_CREDENTIAL_EXPIRED),
            expect_expired,
            "{time}: success={success:?} failure={failure:?}"
        );
        if !expect_expired {
            assert!(success
                .iter()
                .any(|c| c == validation_status::SIGNING_CREDENTIAL_TRUSTED));
        }
        // The report carries the same normalized instant.
        let reported = reader
            .validation_results()
            .and_then(|r| r.validation_time())
            .expect("validation time");
        let expected = chrono::DateTime::parse_from_rfc3339(time).unwrap();
        let reported_dt = chrono::DateTime::parse_from_rfc3339(reported).unwrap();
        assert_eq!(expected, reported_dt, "{time} vs {reported}");
    }
    Ok(())
}

#[test]
fn crjson_reports_supplied_validation_time() -> Result<()> {
    let asset = signed_untimestamped()?;
    let reader = read_at(&asset, Some("2027-01-15T10:00:00.5+02:00"), false)?;
    let crjson: serde_json::Value = serde_json::from_str(&reader.crjson_checked()?)?;
    let text = crjson.to_string();
    assert!(text.contains("2027-01-15T08:00:00Z"), "{text}");
    Ok(())
}

#[test]
fn crjson_ancestor_without_delta_uses_supplied_time() -> Result<()> {
    let mut asset = signed_untimestamped()?;
    let ancestor_label = read_at(&asset, Some("2027-01-15T08:00:00Z"), false)?
        .active_label()
        .unwrap()
        .to_string();
    let mut parent_label = String::new();
    for _ in 0..2 {
        let mut settings = test_settings();
        settings.verify.verify_after_sign = false;
        settings.verify.validation_time = Some("2027-01-15T08:00:00Z".into());
        let mut builder = Builder::from_context(Context::new().with_settings(settings)?)
            .with_definition(MANIFEST)?;
        builder.add_ingredient_from_stream("{}", "image/jpeg", &mut Cursor::new(asset))?;
        let mut source = Cursor::new(include_bytes!("fixtures/earth_apollo17.jpg").to_vec());
        let mut dest = Cursor::new(Vec::new());
        builder.sign(&test_signer(), "image/jpeg", &mut source, &mut dest)?;
        asset = dest.into_inner();
        if parent_label.is_empty() {
            parent_label = read_at(&asset, Some("2027-01-15T08:00:00Z"), false)?
                .active_label()
                .unwrap()
                .to_string();
        }
    }

    let mut tampered = asset.clone();
    // Change scan data, not the JPEG framing or embedded manifest.
    let sos = tampered
        .windows(2)
        .rposition(|w| w == [0xff, 0xda])
        .unwrap();
    let scan_start = sos + 2 + u16::from_be_bytes([tampered[sos + 2], tampered[sos + 3]]) as usize;
    let byte = tampered[scan_start..]
        .iter_mut()
        .find(|b| **b < 0xfe)
        .unwrap();
    *byte ^= 1;

    let time = "2027-01-15T10:00:00.5+02:00";
    for (input, expect_mismatch) in [(&asset, false), (&tampered, true)] {
        let reader = read_at(input, Some(time), false)?;
        let results = reader.validation_results().unwrap();
        // The middle manifest's ingredient is the ancestor. Its historical
        // attestations must not become fresh results just to supply a time.
        assert!(
            results.ingredient_deltas().into_iter().flatten().all(|d| {
                !d.ingredient_assertion_uri()
                    .starts_with(&format!("self#jumbf=/c2pa/{parent_label}/"))
            }),
            "{results:?}"
        );
        let active_codes = results.active_manifest().unwrap();
        assert_eq!(
            active_codes
                .failure()
                .iter()
                .any(|s| s.code() == validation_status::ASSERTION_DATAHASH_MISMATCH),
            expect_mismatch
        );
        assert!(!active_codes
            .failure()
            .iter()
            .any(|s| s.code() == validation_status::SIGNING_CREDENTIAL_EXPIRED));

        let exported = reader.crjson_checked()?;
        let report: serde_json::Value = serde_json::from_str(&exported)?;
        let manifests = report["manifests"].as_array().unwrap();
        assert_eq!(manifests.len(), 3);
        let expected = chrono::DateTime::parse_from_rfc3339(time)
            .unwrap()
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        for manifest in manifests {
            let validation = &manifest["validationResults"];
            let reported = validation["validationTime"].as_str().unwrap();
            assert_eq!(
                reported, expected,
                "{}: {time} vs {reported}",
                manifest["label"]
            );
            if manifest["label"] == reader.active_label().unwrap() {
                for (key, statuses) in [
                    ("success", active_codes.success()),
                    ("informational", active_codes.informational()),
                    ("failure", active_codes.failure()),
                ] {
                    assert_eq!(validation[key], serde_json::to_value(statuses)?);
                }
            }
            if manifest["label"] == ancestor_label {
                for key in ["success", "informational", "failure"] {
                    assert_eq!(validation[key], serde_json::json!([]));
                }
            }
        }
        assert_eq!(exported, reader.crjson_checked()?);
    }
    Ok(())
}

#[test]
fn claim_signer_cannot_use_tsa_only_list() -> Result<()> {
    let asset = signed_untimestamped()?;
    let base = test_settings();
    let mut settings = Settings::default();
    // Re-tag every configured anchor list as TSA-only.
    let mut anchors = base.trust.anchors.clone().unwrap_or_default();
    for a in anchors.iter_mut() {
        a.trust_kind = c2pa::settings::TrustListKind::TSA;
    }
    settings.trust.anchors = Some(anchors);
    settings.verify.validation_time = Some("2027-01-15T08:00:00Z".into());
    settings.verify.strict_trust_purposes = true;
    let reader = Reader::from_context(Context::new().with_settings(settings)?)
        .with_stream("image/jpeg", Cursor::new(asset))?;
    let (success, failure) = codes(&reader);
    assert!(
        failure
            .iter()
            .any(|c| c == validation_status::SIGNING_CREDENTIAL_UNTRUSTED),
        "success={success:?} failure={failure:?}"
    );
    Ok(())
}

#[test]
fn concurrent_contexts_do_not_share_time() -> Result<()> {
    let asset = std::sync::Arc::new(signed_untimestamped()?);
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let asset = asset.clone();
            std::thread::spawn(move || {
                let (time, expired) = if i % 2 == 0 {
                    ("2027-01-15T08:00:00Z", false)
                } else {
                    ("2031-01-01T00:00:00Z", true)
                };
                let reader = read_at(&asset, Some(time), false).unwrap();
                let (_, failure) = codes(&reader);
                assert_eq!(
                    failure
                        .iter()
                        .any(|c| c == validation_status::SIGNING_CREDENTIAL_EXPIRED),
                    expired
                );
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread");
    }
    Ok(())
}

#[test]
fn invalid_validation_time_is_rejected() {
    let mut settings = test_settings();
    settings.verify.validation_time = Some("2027-01-15 08:00:00".into());
    assert!(Context::new().with_settings(settings).is_err());
}
