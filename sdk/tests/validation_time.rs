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

//! Caller-controlled validation time (`verify.validation_time`).

mod common;

use std::io::Cursor;

use c2pa::{validation_status, Builder, BuilderIntent, Context, Reader, Result};
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

fn read_at(asset: &[u8], validation_time: Option<&str>) -> Result<Reader> {
    let mut settings = test_settings();
    settings.verify.validation_time = validation_time.map(str::to_string);
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
        let reader = read_at(&asset, Some(time))?;
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
        // The report carries the same instant, normalized to UTC.
        let reported = reader
            .validation_results()
            .and_then(|r| r.validation_time())
            .expect("validation time");
        let expected = chrono::DateTime::parse_from_rfc3339(time)
            .unwrap()
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert_eq!(reported, expected, "{time}");
    }
    Ok(())
}

#[test]
fn unset_validation_time_uses_current_time() -> Result<()> {
    let asset = signed_untimestamped()?;
    let before = chrono::Utc::now().timestamp() - 1;
    let reader = read_at(&asset, None)?;
    let reported = reader
        .validation_results()
        .and_then(|r| r.validation_time())
        .expect("validation time");
    let reported = chrono::DateTime::parse_from_rfc3339(reported)
        .unwrap()
        .timestamp();
    assert!(reported >= before, "{reported} < {before}");
    Ok(())
}

#[test]
fn crjson_reports_supplied_validation_time() -> Result<()> {
    let asset = signed_untimestamped()?;
    let reader = read_at(&asset, Some("2027-01-15T10:00:00.5+02:00"))?;
    let crjson: serde_json::Value = serde_json::from_str(&reader.crjson_checked()?)?;
    let active = reader.active_label().unwrap();
    let manifest = crjson["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["label"] == active)
        .expect("active manifest");
    assert_eq!(
        manifest["validationResults"]["validationTime"],
        "2027-01-15T08:00:00Z"
    );
    Ok(())
}

/// Every manifest in a multi-manifest crJSON report carries the configured
/// instant, including ancestors without an ingredient validation delta.
#[test]
fn crjson_reports_supplied_validation_time_for_all_manifests() -> Result<()> {
    let mut settings = test_settings();
    settings.verify.verify_after_sign = false;
    let context = Context::new().with_settings(settings)?.into_shared();
    // Three generations: the oldest manifest is an ingredient of an ingredient,
    // so the active manifest's validation results carry no delta for it.
    let mut asset = include_bytes!("fixtures/earth_apollo17.jpg").to_vec();
    for _ in 0..3 {
        let mut builder = Builder::from_shared_context(&context);
        builder.set_intent(BuilderIntent::Edit);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(
            &test_signer(),
            "image/jpeg",
            &mut Cursor::new(asset),
            &mut dest,
        )?;
        asset = dest.into_inner();
    }

    let reader = read_at(&asset, Some("2027-01-15T10:00:00+02:00"))?;
    let expected = "2027-01-15T08:00:00Z";
    let results = reader.validation_results().expect("validation results");
    assert_eq!(results.validation_time(), Some(expected));
    // Make sure at least one ancestor has no validation delta.
    let delta_count = results.ingredient_deltas().map_or(0, |d| d.len());

    let crjson: serde_json::Value = serde_json::from_str(&reader.crjson_checked()?)?;
    for document in [crjson, reader.to_crjson_value()?] {
        let manifests = document["manifests"].as_array().unwrap();
        assert!(
            manifests.len() > 1 + delta_count,
            "expected an ancestor manifest without a validation delta"
        );
        for manifest in manifests {
            assert_eq!(
                manifest["validationResults"]["validationTime"], expected,
                "manifest {}",
                manifest["label"]
            );
        }
    }
    Ok(())
}

// WASI test runners cannot spawn threads.
#[cfg(not(target_os = "wasi"))]
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
                let reader = read_at(&asset, Some(time)).unwrap();
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
    for bad in [
        "2027-01-15 08:00:00",
        "2027-01-15",
        "2027-01-15T08:00:00",
        "not a time",
    ] {
        let mut settings = test_settings();
        settings.verify.validation_time = Some(bad.into());
        assert!(Context::new().with_settings(&settings).is_err(), "{bad}");
        assert!(Context::new().with_settings(settings).is_err(), "{bad}");
        let json = format!(r#"{{"verify": {{"validation_time": "{bad}"}}}}"#);
        assert!(
            Context::new().with_settings(json.as_str()).is_err(),
            "{bad}"
        );
    }
}
