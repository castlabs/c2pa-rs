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

use std::{
    collections::HashSet,
    fs::File,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use c2pa::{
    assertions::SessionKeys, format_from_path, live_video::LiveVideoValidator,
    status_tracker::StatusTracker, Context as C2paContext, Reader, ValidationState,
};
use serde::Deserialize;

const MAX_SCHEDULE_BYTES: u64 = 1024 * 1024;
const MAX_UPDATES: usize = 1024;
const MAX_INIT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    version: u32,
    updates: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    before_segment: String,
    init: PathBuf,
}

pub(super) struct VerifiedContext {
    pub session_keys: SessionKeys,
    pub manifest_id: String,
    pub ee_cert_der: Vec<u8>,
}

pub(super) struct Update {
    pub segment_index: usize,
    pub init_path: PathBuf,
    init_data: Vec<u8>,
    verified: VerifiedContext,
}

pub(super) fn require_verification(context: &C2paContext) -> Result<()> {
    let settings = context.settings();
    if !settings.get_value::<bool>("verify.verify_after_reading")?
        || !settings.get_value::<bool>("verify.verify_trust")?
    {
        bail!("--updates requires verify_after_reading and verify_trust enabled");
    }
    Ok(())
}

fn reader_context(context: &C2paContext) -> Result<Arc<C2paContext>> {
    let settings = context
        .settings()
        .clone()
        .with_value("verify.remote_manifest_fetch", false)?;
    Ok(Arc::new(C2paContext::new().with_settings(settings)?))
}

fn read_snapshot(path: &Path, max_bytes: u64, remaining: &mut u64) -> Result<Vec<u8>> {
    let limit = max_bytes.min(*remaining);
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("Cannot read VSI init snapshot: {path:?}"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("VSI init snapshot exceeds available raw-byte limit ({limit} bytes): {path:?}");
    }
    *remaining -= bytes.len() as u64;
    Ok(bytes)
}

pub(super) fn read_init(path: &Path) -> Result<Vec<u8>> {
    let mut remaining = MAX_INIT_BYTES;
    read_snapshot(path, MAX_INIT_BYTES, &mut remaining)
}

pub(super) fn read_context(
    context: &Arc<C2paContext>,
    init_path: &Path,
    init_data: &[u8],
) -> Result<VerifiedContext> {
    require_verification(context)?;
    let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());
    // Disable asset-directed manifest fetching before the Reader sees any init bytes.
    let reader_context = reader_context(context)?;
    let reader = Reader::from_shared_context(&reader_context)
        .with_stream(&format, Cursor::new(init_data))
        .with_context(|| format!("Cannot verify signed VSI init: {init_path:?}"))?;
    let active = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .context("--updates requires active manifest validation results")?;
    if reader.validation_state() != ValidationState::Trusted || !active.failure().is_empty() {
        bail!("--updates requires a Trusted init with no active manifest failures: {init_path:?}");
    }
    if !reader.is_embedded() {
        bail!("--updates requires an embedded signed init manifest: {init_path:?}");
    }
    // All installation material is extracted from this exact verified Reader.
    let manifest = reader
        .active_manifest()
        .context("VSI init has no active manifest")?;
    let session_keys = manifest
        .find_assertion::<SessionKeys>(SessionKeys::LABEL)
        .context("--updates supports only VSI signed init assets, not manifest-box streams")?;
    let manifest_id = manifest
        .label()
        .filter(|id| id.starts_with("urn:c2pa:") && id.len() > "urn:c2pa:".len())
        .context("VSI init manifest label must be a non-empty urn:c2pa: identifier")?
        .to_string();
    let ee_cert_der = super::extract_ee_cert_der(manifest)
        .context("VSI init manifest has no readable leaf certificate")?;
    Ok(VerifiedContext {
        session_keys,
        manifest_id,
        ee_cert_der,
    })
}

fn references(path: &Path, segments: &[PathBuf]) -> Result<Vec<(usize, PathBuf)>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("Cannot read VSI update schedule: {path:?}"))?
        .take(MAX_SCHEDULE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SCHEDULE_BYTES {
        bail!("VSI update schedule exceeds 1 MiB");
    }
    // Serde struct deserializers also accept positional arrays; the schedule requires objects.
    let shape: serde_json::Value =
        serde_json::from_slice(&bytes).context("Invalid VSI update schedule")?;
    if !shape.is_object()
        || shape
            .get("updates")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|updates| updates.iter().any(|event| !event.is_object()))
    {
        bail!("VSI update schedule and its events must be JSON objects");
    }
    let schedule: Schedule =
        serde_json::from_slice(&bytes).context("Invalid VSI update schedule")?;
    if schedule.version != 1 {
        bail!("VSI update schedule version must be 1");
    }
    if schedule.updates.len() > MAX_UPDATES {
        bail!("VSI update schedule exceeds 1024 events");
    }
    let mut seen = HashSet::new();
    let mut resolved = Vec::new();
    for event in schedule.updates {
        let name = &event.before_segment;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':', '\0']) {
            bail!("before_segment must be a single filename: {name:?}");
        }
        if !seen.insert(event.before_segment.clone()) {
            bail!("Duplicate VSI update target: {name:?}");
        }
        let mut matches = segments.iter().enumerate().filter(|(_, segment)| {
            segment.file_name().and_then(|name| name.to_str()) == Some(name.as_str())
        });
        let (index, _) = matches.next().with_context(|| {
            format!("VSI update target does not match any selected media segment: {name:?}")
        })?;
        if matches.next().is_some() {
            bail!("Ambiguous VSI update target among selected media segments: {name:?}");
        }
        if event.init.as_os_str().is_empty() {
            bail!("VSI update init path must not be empty");
        }
        resolved.push((
            index,
            path.parent().unwrap_or(Path::new(".")).join(event.init),
        ));
    }
    resolved.sort_by_key(|(index, _)| *index);
    Ok(resolved)
}

pub(super) fn load_plan(
    context: &Arc<C2paContext>,
    path: &Path,
    segments: &[PathBuf],
) -> Result<Vec<Update>> {
    load_plan_with_budget(context, path, segments, MAX_PLAN_BYTES)
}

fn load_plan_with_budget(
    context: &Arc<C2paContext>,
    path: &Path,
    segments: &[PathBuf],
    mut remaining: u64,
) -> Result<Vec<Update>> {
    references(path, segments)?
        .into_iter()
        .map(|(segment_index, init_path)| {
            let init_data = read_snapshot(&init_path, MAX_INIT_BYTES, &mut remaining)?;
            let verified = read_context(context, &init_path, &init_data)?;
            Ok(Update {
                segment_index,
                init_path,
                init_data,
                verified,
            })
        })
        .collect()
}

impl Update {
    pub(super) fn install(
        &self,
        validator: &mut LiveVideoValidator,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let failures_before = tracker.filter_errors().count();
        let result = validator.update_vsi_context(
            Some(&self.init_data),
            &self.verified.session_keys,
            &self.verified.manifest_id,
            Some(&self.verified.ee_cert_der),
            tracker,
        );
        let failures = tracker
            .filter_errors()
            .skip(failures_before)
            .map(|item| item.description.to_string())
            .collect::<Vec<_>>();
        if !failures.is_empty() {
            bail!("VSI update rejected: {}", failures.join("; "));
        }
        result.with_context(|| format!("VSI update rejected: {:?}", self.init_path))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use c2pa::{
        live_video::{Ed25519SessionKey, LiveVideoVsiSigner},
        settings::Settings,
    };
    use clap::Parser;
    use serde_json::{json, Value};
    use tempfile::TempDir;

    use super::*;

    const MANIFEST: &str = r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#;

    fn schedule(dir: &TempDir, value: Value) -> PathBuf {
        let path = dir.path().join("updates.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    fn event(name: &str, init: &Path) -> Value {
        json!({"before_segment": name, "init": init})
    }

    #[test]
    fn update_reader_disables_only_remote_manifest_fetch() {
        let trusted = trusted_context();
        for ocsp_fetch in [false, true] {
            let settings = trusted
                .settings()
                .with_value("verify.remote_manifest_fetch", true)
                .unwrap()
                .with_value("verify.ocsp_fetch", ocsp_fetch)
                .unwrap();
            let context = C2paContext::new().with_settings(settings.clone()).unwrap();
            let isolated = reader_context(&context).unwrap();
            assert_eq!(
                isolated.settings(),
                &settings
                    .with_value("verify.remote_manifest_fetch", false)
                    .unwrap()
            );
            assert!(context
                .settings()
                .get_value::<bool>("verify.remote_manifest_fetch")
                .unwrap());
        }
    }

    #[test]
    fn init_snapshot_limits_are_inclusive_and_share_remaining_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init.mp4");
        fs::write(&path, b"12345").unwrap();
        let mut remaining = 7;
        assert!(read_snapshot(&path, 4, &mut remaining).is_err());
        assert_eq!(remaining, 7);
        fs::write(&path, b"1234").unwrap();
        assert_eq!(read_snapshot(&path, 4, &mut remaining).unwrap(), b"1234");
        assert_eq!(remaining, 3);
        assert!(read_snapshot(&path, 4, &mut remaining).is_err());
        assert_eq!(remaining, 3);
        fs::write(&path, b"123").unwrap();
        assert_eq!(read_snapshot(&path, 4, &mut remaining).unwrap(), b"123");
        assert_eq!(remaining, 0);
        assert!(read_snapshot(&path, 4, &mut remaining).is_err());
        fs::write(&path, b"").unwrap();
        assert!(read_snapshot(&path, 4, &mut remaining).unwrap().is_empty());
    }

    #[test]
    fn updates_flag_is_optional_and_scoped_to_live_video() {
        for updates in [None, Some("updates.json")] {
            let mut args = vec![
                "c2patool",
                "init.mp4",
                "live-video",
                "--segments_glob",
                "seg-*.m4s",
            ];
            if let Some(path) = updates {
                args.extend(["--updates", path]);
            }
            let args = crate::CliArgs::try_parse_from(args).unwrap();
            match args.command.unwrap() {
                crate::Commands::LiveVideo {
                    updates: actual, ..
                } => {
                    assert_eq!(actual.as_deref(), updates.map(Path::new));
                }
                _ => panic!("expected live-video"),
            }
        }
        assert!(crate::CliArgs::try_parse_from([
            "c2patool",
            "init.mp4",
            "--updates",
            "updates.json",
        ])
        .is_err());
    }

    #[test]
    fn schedule_schema_and_version_are_strict() {
        let dir = tempfile::tempdir().unwrap();
        let selected = vec![PathBuf::from("seg-103.m4s")];
        for value in [
            json!([1, []]),
            json!({"version": 0, "updates": []}),
            json!({"version": 2, "updates": []}),
            json!({"version": 1, "updates": [], "extra": true}),
            json!({"updates": []}),
            json!({"version": 1}),
            json!({"version": 1, "updates": [["seg-103.m4s", "b.mp4"]]}),
            json!({"version": 1, "updates": [{"before_segment": "seg-103.m4s"}]}),
            json!({"version": 1, "updates": [{"before_segment": "seg-103.m4s", "init": "init.mp4", "extra": true}]}),
        ] {
            assert!(references(&schedule(&dir, value), &selected).is_err());
        }
        let path = dir.path().join("updates.json");
        for bytes in [
            r#"{"version":1,"version":1,"updates":[]}"#,
            r#"{"version":1,"updates":[{"before_segment":"seg-103.m4s","init":"b.mp4","init":"c.mp4"}]}"#,
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(references(&path, &selected).is_err());
        }
        assert!(references(&schedule(&dir, json!({"version": 1, "updates": []})), &[]).is_ok());
    }

    #[test]
    fn schedule_byte_and_event_limits_are_inclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = schedule(&dir, json!({"version": 1, "updates": []}));
        let mut bytes = fs::read(&path).unwrap();
        bytes.resize(MAX_SCHEDULE_BYTES as usize, b' ');
        fs::write(&path, &bytes).unwrap();
        assert!(references(&path, &[]).is_ok());
        bytes.push(b' ');
        fs::write(&path, bytes).unwrap();
        assert!(references(&path, &[])
            .unwrap_err()
            .to_string()
            .contains("1 MiB"));

        let selected: Vec<_> = (0..=MAX_UPDATES)
            .map(|index| PathBuf::from(format!("seg-{index}.m4s")))
            .collect();
        let events: Vec<_> = selected
            .iter()
            .map(|path| event(path.to_str().unwrap(), Path::new("init.mp4")))
            .collect();
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": &events[..MAX_UPDATES]}),
        );
        assert_eq!(references(&path, &selected).unwrap().len(), MAX_UPDATES);
        let path = schedule(&dir, json!({"version": 1, "updates": events}));
        assert!(references(&path, &selected)
            .unwrap_err()
            .to_string()
            .contains("1024"));
    }

    #[test]
    fn schedule_requires_unique_selected_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let selected = vec![PathBuf::from("media/seg-103.m4s")];
        for name in [
            "",
            ".",
            "..",
            "./seg-103.m4s",
            "../seg-103.m4s",
            "media/seg-103.m4s",
            "media\\seg-103.m4s",
            "C:seg-103.m4s",
            "seg-104.m4s",
        ] {
            let path = schedule(
                &dir,
                json!({"version": 1, "updates": [event(name, Path::new("b.mp4"))]}),
            );
            assert!(references(&path, &selected).is_err(), "accepted {:?}", name);
        }
        let update = event("seg-103.m4s", Path::new("b.mp4"));
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [update.clone(), update.clone()]}),
        );
        assert!(references(&path, &selected)
            .unwrap_err()
            .to_string()
            .contains("Duplicate"));
        let path = schedule(&dir, json!({"version": 1, "updates": [update]}));
        let ambiguous = vec![selected[0].clone(), PathBuf::from("other/seg-103.m4s")];
        assert!(references(&path, &ambiguous)
            .unwrap_err()
            .to_string()
            .contains("Ambiguous"));
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [event("seg-103.m4s", Path::new(""))]}),
        );
        assert!(references(&path, &selected).is_err());
    }

    #[test]
    fn schedule_resolves_init_paths_and_uses_selected_media_order() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = dir.path().join("init-c.mp4");
        let selected = vec![PathBuf::from("seg-2.m4s"), PathBuf::from("seg-10.m4s")];
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg-10.m4s", &absolute),
                event("seg-2.m4s", Path::new("../init-b.mp4")),
            ]}),
        );
        assert_eq!(
            references(&path, &selected).unwrap(),
            vec![(0, dir.path().join("../init-b.mp4")), (1, absolute),]
        );
    }

    fn trusted_context() -> Arc<C2paContext> {
        let settings = Settings::new()
            .with_toml(include_str!(
                "../tests/fixtures/trust/cawg_test_settings.toml"
            ))
            .unwrap()
            .with_value("verify.remote_manifest_fetch", false)
            .unwrap()
            .with_value("verify.ocsp_fetch", false)
            .unwrap();
        let signer = c2pa::create_signer::from_keys(
            include_bytes!("../../sdk/tests/fixtures/certs/es256.pub"),
            include_bytes!("../../sdk/tests/fixtures/certs/es256.pem"),
            c2pa::SigningAlg::Es256,
            None,
        )
        .unwrap();
        Arc::new(
            C2paContext::new()
                .with_settings(settings)
                .unwrap()
                .with_signer(signer),
        )
    }

    fn producer(context: &Arc<C2paContext>, minimum: u64) -> LiveVideoVsiSigner {
        LiveVideoVsiSigner::from_shared_context(
            context,
            MANIFEST,
            Ed25519SessionKey::from_bytes(&[0x42; 32]),
            b"session-key-1".to_vec(),
            minimum,
            3600,
        )
        .unwrap()
    }

    // Use public APIs and the same cert/media fixtures as the existing CLI VSI test.
    // No SDK test helpers, private state or network services are involved.
    fn signed_corpus(fresh_producer: bool) -> (TempDir, Arc<C2paContext>, PathBuf) {
        let context = trusted_context();
        let dir = tempfile::tempdir().unwrap();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sdk/tests/fixtures/bunny/bunny_595491bps");
        let init = fs::read(fixtures.join("BigBuckBunny_2s_init.mp4")).unwrap();
        let mut signer = producer(&context, 277);
        let a = signer
            .sign_init_segment_with_context(&init, "video/mp4")
            .unwrap();
        let first = signer
            .sign_media_segment(&fs::read(fixtures.join("BigBuckBunny_2s277.m4s")).unwrap())
            .unwrap();
        if fresh_producer {
            signer = producer(&context, 278); // Restarts emsg IDs, not the media sequence.
        }
        let b = signer
            .sign_init_segment_with_context(&init, "video/mp4")
            .unwrap();
        let second = signer
            .sign_media_segment(&fs::read(fixtures.join("BigBuckBunny_2s278.m4s")).unwrap())
            .unwrap();
        fs::write(dir.path().join("init-a.mp4"), a).unwrap();
        fs::write(dir.path().join("init-b.mp4"), b).unwrap();
        fs::write(dir.path().join("seg-277.m4s"), first).unwrap();
        fs::write(dir.path().join("seg-278.m4s"), second).unwrap();
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg-278.m4s", Path::new("init-b.mp4")),
            ]}),
        );
        (dir, context, path)
    }

    #[test]
    fn signed_update_succeeds_and_legacy_path_does_not_install_it() {
        let (dir, context, path) = signed_corpus(false);
        let init = dir.path().join("init-a.mp4");
        let glob = Path::new("seg-*.m4s");
        // Without a schedule, A media still passes, but B's new manifestId cannot.
        super::super::validate_live_video(&context, &init, Path::new("seg-277.m4s"), None).unwrap();
        assert!(super::super::validate_live_video(&context, &init, glob, None).is_err());
        super::super::validate_live_video(&context, &init, glob, Some(&path)).unwrap();
    }

    #[test]
    fn loaded_plan_counts_every_retained_snapshot_against_total_budget() {
        let (dir, context, _) = signed_corpus(false);
        let selected = vec![
            dir.path().join("seg-277.m4s"),
            dir.path().join("seg-278.m4s"),
        ];
        let path = schedule(
            &dir,
            json!({"version": 1, "updates": [
                event("seg-277.m4s", Path::new("init-b.mp4")),
                event("seg-278.m4s", Path::new("init-b.mp4")),
            ]}),
        );
        let total = fs::metadata(dir.path().join("init-b.mp4")).unwrap().len() * 2;
        let plan = load_plan_with_budget(&context, &path, &selected, total).unwrap();
        assert_eq!(
            plan.iter()
                .map(|update| update.init_data.len() as u64)
                .sum::<u64>(),
            total
        );
        let error = load_plan_with_budget(&context, &path, &selected, total - 1)
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("snapshot exceeds available raw-byte limit"));
    }

    #[test]
    fn untrusted_tampered_and_missing_candidates_fail_before_media() {
        let (dir, context, path) = signed_corpus(false);
        let selected = vec![dir.path().join("seg-278.m4s")];
        let anchorless = Arc::new(
            C2paContext::new()
                .with_settings(
                    context
                        .settings()
                        .with_value("trust.anchors", json!([]))
                        .unwrap(),
                )
                .unwrap(),
        );
        assert!(load_plan(&anchorless, &path, &selected).is_err());
        let init = dir.path().join("init-a.mp4");
        assert!(super::super::validate_live_video(
            &anchorless,
            &init,
            Path::new("seg-*.m4s"),
            Some(&path),
        )
        .is_err());
        let b = dir.path().join("init-b.mp4");
        let mut bytes = fs::read(&b).unwrap();
        let mvhd = bytes
            .windows(4)
            .position(|window| window == b"mvhd")
            .unwrap();
        bytes[mvhd + 8] ^= 1;
        fs::write(&b, bytes).unwrap();
        // Candidate verification rejects before even opening the selected media files.
        fs::write(dir.path().join("seg-277.m4s"), b"not media").unwrap();
        fs::write(&selected[0], b"not media").unwrap();
        assert!(load_plan(&context, &path, &selected).is_err());
        let error =
            super::super::validate_live_video(&context, &init, Path::new("seg-*.m4s"), Some(&path))
                .unwrap_err();
        assert!(!error.to_string().contains("segment(s) failed"));
        fs::remove_file(&b).unwrap();
        assert!(load_plan(&context, &path, &selected).is_err());
    }

    #[test]
    fn initial_context_must_be_trusted_and_verification_cannot_be_disabled() {
        let (dir, context, _) = signed_corpus(false);
        let init = dir.path().join("init-a.mp4");
        let empty = schedule(&dir, json!({"version": 1, "updates": []}));
        let anchorless = Arc::new(
            C2paContext::new()
                .with_settings(
                    context
                        .settings()
                        .with_value("trust.anchors", json!([]))
                        .unwrap(),
                )
                .unwrap(),
        );
        assert!(super::super::validate_live_video(
            &anchorless,
            &init,
            Path::new("seg-277.m4s"),
            Some(&empty),
        )
        .is_err());
        for setting in ["verify.verify_after_reading", "verify.verify_trust"] {
            let disabled = C2paContext::new()
                .with_settings(context.settings().with_value(setting, false).unwrap())
                .unwrap();
            assert!(require_verification(&disabled).is_err());
        }
    }

    #[test]
    fn fresh_producer_cannot_clear_replay_history_with_a_trusted_update() {
        let (dir, context, path) = signed_corpus(true);
        let init_path = dir.path().join("init-a.mp4");
        let init_data = fs::read(&init_path).unwrap();
        let verified = read_context(&context, &init_path, &init_data).unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init_data, &mut tracker)
            .unwrap();
        validator
            .validate_session_keys(
                &verified.session_keys,
                &verified.manifest_id,
                Some(&verified.ee_cert_der),
                &mut tracker,
            )
            .unwrap();
        assert!(super::super::validate_segment_vsi(
            &dir.path().join("seg-277.m4s"),
            &mut validator,
            &mut tracker,
        ));
        let selected = vec![dir.path().join("seg-278.m4s")];
        load_plan(&context, &path, &selected).unwrap()[0]
            .install(&mut validator, &mut tracker)
            .unwrap();
        assert!(!super::super::validate_segment_vsi(
            &selected[0],
            &mut validator,
            &mut tracker,
        ));
        assert!(tracker
            .filter_errors()
            .any(|item| { item.description.contains("emsg id must be unique") }));
        let error = super::super::validate_live_video(
            &context,
            &init_path,
            Path::new("seg-*.m4s"),
            Some(&path),
        )
        .unwrap_err();
        assert!(error.to_string().contains("1/2 segment(s) failed"));
    }

    #[test]
    fn trusted_but_incompatible_update_stops_at_boundary() {
        let (dir, context, path) = signed_corpus(false);
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sdk/tests/fixtures/bunny/bunny_595491bps");
        let mut init = fs::read(fixtures.join("BigBuckBunny_2s_init.mp4")).unwrap();
        let mdhd = init
            .windows(4)
            .position(|window| window == b"mdhd")
            .unwrap();
        assert_eq!(init[mdhd + 4], 0); // This fixture uses the version-0 mdhd layout.
        init[mdhd + 19] ^= 1; // Change the track timescale, keeping the BMFF structure valid.
        let candidate = producer(&context, 278)
            .sign_init_segment_with_context(&init, "video/mp4")
            .unwrap();
        fs::write(dir.path().join("init-b.mp4"), candidate).unwrap();
        fs::write(dir.path().join("seg-278.m4s"), b"must not be validated").unwrap();
        let error = super::super::validate_live_video(
            &context,
            &dir.path().join("init-a.mp4"),
            Path::new("seg-*.m4s"),
            Some(&path),
        )
        .unwrap_err();
        assert!(error.to_string().contains("VSI update FAIL"));
        assert!(error.to_string().contains("timescale"));
    }

    #[test]
    fn updates_reject_a_trusted_manifest_box_init() {
        let context = trusted_context();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sdk/tests/fixtures/bunny/bunny_595491bps");
        let init = fs::read(fixtures.join("BigBuckBunny_2s_init.mp4")).unwrap();
        let mut builder = c2pa::Builder::from_shared_context(&context)
            .with_definition(MANIFEST)
            .unwrap();
        let mut signed = Cursor::new(Vec::new());
        builder
            .sign(
                context.signer().unwrap(),
                "video/mp4",
                &mut Cursor::new(init),
                &mut signed,
            )
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let init = dir.path().join("init-mb.mp4");
        fs::write(&init, signed.into_inner()).unwrap();
        let path = schedule(&dir, json!({"version": 1, "updates": []}));
        let error =
            super::super::validate_live_video(&context, &init, Path::new("seg-*.m4s"), Some(&path))
                .unwrap_err();
        assert!(format!("{error:#}").contains("not manifest-box streams"));
    }
}
