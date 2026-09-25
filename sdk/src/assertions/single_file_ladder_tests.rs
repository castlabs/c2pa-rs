// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

#![allow(clippy::unwrap_used)]

use std::{io::Cursor, path::PathBuf};

use serde_bytes::ByteBuf;

use super::BmffHash;
use crate::{
    asset_handlers::bmff_io::read_bmff_c2pa_boxes,
    dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
    utils::{io_utils::tempdirectory, test_signer::test_signer},
    Builder, Context, Reader, Result, Settings, Signer, SigningAlg, ValidationState,
};

const RELATIVE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments.mp4");
const ABSOLUTE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments_absolute.mp4");
const DEFINITION: &str = r#"{"title":"ladder","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}]}}]}"#;

fn builder() -> Builder {
    let settings = Settings::new()
        .with_value("verify.verify_after_sign", true)
        .unwrap();
    Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
}

fn binding(data: &[u8]) -> BmffHash {
    let reader = Reader::default()
        .with_stream("video/mp4", Cursor::new(data))
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    let mut hash: BmffHash = reader
        .active_manifest()
        .unwrap()
        .find_assertion("c2pa.hash.bmff.v3")
        .unwrap();
    hash.set_bmff_version(3);
    hash.verify_stream_hash(&mut Cursor::new(data), None)
        .unwrap();
    hash
}

fn paths(dir: &std::path::Path, data: &[Vec<u8>]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let sources: Vec<_> = data
        .iter()
        .enumerate()
        .map(|(i, data)| {
            let path = dir.join(format!("source{i}.mp4"));
            std::fs::write(&path, data).unwrap();
            path
        })
        .collect();
    let outputs = (0..data.len())
        .map(|i| dir.join(format!("output{i}.mp4")))
        .collect();
    (sources, outputs)
}

// Reassemble real encoded fragments without optional indexes, allowing unequal
// fragment counts without manufacturing media or leaving invalid index entries.
fn shortened() -> Vec<u8> {
    let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(RELATIVE)).unwrap();
    let mut output = Vec::new();
    let mut fragments = 0;
    for b in boxes.box_infos {
        if b.path == "moof" {
            fragments += 1;
        }
        if fragments > 1 {
            break;
        }
        if b.path == "sidx" || b.path == "mfra" {
            continue;
        }
        output.extend_from_slice(&RELATIVE[b.offset as usize..(b.offset + b.size) as usize]);
    }
    output
}

#[test]
fn ladder_unequal_fragments_shared_manifest_and_tampering() {
    let data = vec![RELATIVE.to_vec(), ABSOLUTE.to_vec(), shortened()];
    let dir = tempdirectory().unwrap();
    let (sources, outputs) = paths(dir.path(), &data);
    let manifest = builder()
        .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
        .unwrap();
    for (i, output) in outputs.iter().enumerate() {
        let bytes = std::fs::read(output).unwrap();
        let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(boxes.manifest_bytes.as_deref(), Some(manifest.as_slice()));
        assert_eq!(
            boxes.first_aux_uuid_offset,
            boxes.bmff_merkle_box_infos[0].offset
        );
        assert_eq!(boxes.bmff_merkle.len(), [3, 3, 1][i]);
        super::single_file_bmff_tests::check_tfra(&bytes);
        // The sidx reference ranges include each inserted Merkle UUID and end
        // at the corresponding mdat, independently of the writer's arithmetic.
        if let Some(sidx) = boxes.box_infos.iter().find(|b| b.path == "sidx") {
            let payload = sidx.offset as usize + 8;
            let wide = bytes[payload] == 1;
            let first_at = payload + 12 + if wide { 8 } else { 4 };
            let first = if wide {
                u64::from_be_bytes(bytes[first_at..first_at + 8].try_into().unwrap())
            } else {
                u32::from_be_bytes(bytes[first_at..first_at + 4].try_into().unwrap()) as u64
            };
            let entries = first_at + if wide { 8 } else { 4 } + 4;
            let mut start = sidx.offset + sidx.size + first;
            for (index, mdat) in boxes
                .box_infos
                .iter()
                .filter(|b| b.path == "mdat")
                .enumerate()
            {
                assert_eq!(start, boxes.bmff_merkle_box_infos[index].offset);
                let at = entries + 12 * index;
                let size = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
                assert_eq!(size & 0x80000000, 0);
                start += size as u64;
                assert_eq!(start, mdat.offset + mdat.size);
            }
        }
        for (location, map) in boxes.bmff_merkle.iter().enumerate() {
            assert_eq!(
                (map.unique_id, map.local_id, map.location),
                (i + 1, 1, location)
            );
        }
        let hash = binding(&bytes);
        let maps = hash.merkle.as_ref().unwrap();
        assert_eq!(maps.len(), 3);
        for (index, map) in maps.iter().enumerate() {
            assert_eq!(map.unique_id, index + 1);
            assert_eq!(map.count, [3, 3, 1][index]);
            assert_eq!(map.hashes.0.len(), map.count);
        }
        let mut own = binding(&bytes);
        own.merkle.as_mut().unwrap()[i].hashes.0[0] = ByteBuf::from(vec![0; 32]);
        assert!(own
            .verify_stream_hash(&mut Cursor::new(&bytes), None)
            .is_err());
        let mut sibling = binding(&bytes);
        let map = &mut sibling.merkle.as_mut().unwrap()[(i + 1) % 3];
        map.hashes.0[0] = ByteBuf::from(vec![0; 32]);
        map.init_hash = Some(ByteBuf::from(vec![0; 32]));
        sibling
            .verify_stream_hash(&mut Cursor::new(&bytes), None)
            .unwrap();
        let mut tampered = bytes.clone();
        let mdat = boxes.box_infos.iter().find(|b| b.path == "mdat").unwrap();
        tampered[(mdat.offset + mdat.size - 1) as usize] ^= 1;
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(tampered), None)
            .is_err());
        assert_eq!(std::fs::read(&sources[i]).unwrap(), data[i]);
    }
}

#[test]
fn ladder_one_rung_matches_single_file_signing() {
    for data in [RELATIVE, ABSOLUTE] {
        let dir = tempdirectory().unwrap();
        let (sources, outputs) = paths(dir.path(), &[data.to_vec()]);
        builder()
            .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
            .unwrap();
        let alone = dir.path().join("alone.mp4");
        builder()
            .sign_file(test_signer(SigningAlg::Es256).as_ref(), &sources[0], &alone)
            .unwrap();
        let alone = std::fs::read(alone).unwrap();
        let rung = std::fs::read(&outputs[0]).unwrap();
        assert_eq!(binding(&alone).merkle, binding(&rung).merkle);
        let strip = |bytes: &[u8]| {
            let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(bytes)).unwrap();
            let at = boxes.manifest_box_offset.unwrap() as usize;
            let end = at + boxes.manifest_box_bytes.unwrap().len();
            [bytes[..at].to_vec(), bytes[end..].to_vec()]
        };
        assert_eq!(strip(&alone), strip(&rung));
    }
}

#[test]
fn ladder_rendition_ids_cross_cbor_width_boundary() {
    let dir = tempdirectory().unwrap();
    let (sources, outputs) = paths(dir.path(), &vec![shortened(); 25]);
    let manifest = builder()
        .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
        .unwrap();
    for (index, output) in outputs.iter().enumerate() {
        let bytes = std::fs::read(output).unwrap();
        let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(boxes.manifest_bytes.as_deref(), Some(manifest.as_slice()));
        assert_eq!(boxes.bmff_merkle[0].unique_id, index + 1);
        assert_eq!(binding(&bytes).merkle.unwrap().len(), 25);
    }
}

#[test]
fn ladder_patch_failure_never_falls_back_to_a_full_write() {
    use std::sync::{Arc, Mutex};

    let dir = tempdirectory().unwrap();
    let (sources, outputs) = paths(dir.path(), &[RELATIVE.to_vec()]);
    let output = outputs[0].clone();
    let damaged = Arc::new(Mutex::new(Vec::new()));
    let saved = Arc::clone(&damaged);
    let context = Context::new().with_progress_callback(move |phase, _, _| {
        if phase == crate::context::ProgressPhase::Signing {
            // Simulate a changed placeholder after the final-layout hash pass.
            let mut bytes = std::fs::read(&output).unwrap();
            let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(&bytes)).unwrap();
            let end = boxes.manifest_box_offset.unwrap() as usize
                + boxes.manifest_box_bytes.unwrap().len();
            bytes[end - 1] ^= 1;
            std::fs::write(&output, &bytes).unwrap();
            *saved.lock().unwrap() = bytes;
        }
        true
    });
    let result = Builder::from_context(context)
        .with_definition(DEFINITION)
        .unwrap()
        .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs);
    assert!(matches!(result, Err(crate::Error::JumbfCreationError)));
    assert_eq!(
        std::fs::read(&outputs[0]).unwrap(),
        *damaged.lock().unwrap()
    );
    assert_eq!(std::fs::read(&sources[0]).unwrap(), RELATIVE);
}

#[test]
fn ladder_never_clobbers_existing_files_or_aliases() {
    let dir = tempdirectory().unwrap();
    let data = vec![RELATIVE.to_vec(), ABSOLUTE.to_vec()];
    let (sources, _) = paths(dir.path(), &data);
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let source_link = dir.path().join("source_link.mp4");
    std::fs::hard_link(&sources[1], &source_link).unwrap();
    let existing = dir.path().join("existing.mp4");
    std::fs::write(&existing, b"preserve me").unwrap();
    let existing_link = dir.path().join("existing_link.mp4");
    std::fs::hard_link(&existing, &existing_link).unwrap();
    let duplicate = dir.path().join("duplicate.mp4");
    let cases = vec![
        vec![sources[0].clone(), dir.path().join("unused1.mp4")],
        vec![sub.join("../source1.mp4"), dir.path().join("unused2.mp4")],
        vec![source_link, dir.path().join("unused3.mp4")],
        vec![existing.clone(), existing_link],
        vec![duplicate.clone(), sub.join("../duplicate.mp4")],
    ];
    #[cfg(unix)]
    let cases = {
        let mut cases = cases;
        let dangling = dir.path().join("dangling.mp4");
        let target = dir.path().join("target.mp4");
        std::os::unix::fs::symlink(&target, &dangling).unwrap();
        cases.push(vec![dangling, target]);
        cases
    };
    for outputs in cases {
        assert!(builder()
            .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
            .is_err());
        for (source, original) in sources.iter().zip(&data) {
            assert_eq!(&std::fs::read(source).unwrap(), original);
        }
        assert_eq!(std::fs::read(&existing).unwrap(), b"preserve me");
    }
    assert_eq!(std::fs::metadata(duplicate).unwrap().len(), 0);
    builder()
        .sign_ladder_files(
            test_signer(SigningAlg::Es256).as_ref(),
            &sources,
            &[sub.join("../fresh.mp4"), dir.path().join("fresh2.mp4")],
        )
        .unwrap();
}

#[test]
fn ladder_case_and_unicode_destination_aliases() {
    for names in [
        ["case.mp4", "CASE.mp4"],
        ["caf\u{e9}.mp4", "cafe\u{301}.mp4"],
    ] {
        let dir = tempdirectory().unwrap();
        let (sources, _) = paths(dir.path(), &[RELATIVE.to_vec(), ABSOLUTE.to_vec()]);
        let outputs = names.map(|name| dir.path().join(name));
        // Probe this filesystem, then test both destinations initially absent.
        std::fs::write(&outputs[0], []).unwrap();
        let aliases = outputs[1].exists();
        std::fs::remove_file(&outputs[0]).unwrap();
        let result = builder().sign_ladder_files(
            test_signer(SigningAlg::Es256).as_ref(),
            &sources,
            &outputs,
        );
        if aliases {
            assert!(result.is_err());
            assert_eq!(std::fs::metadata(&outputs[0]).unwrap().len(), 0);
        } else {
            let manifest = result.unwrap();
            for (index, output) in outputs.iter().enumerate() {
                let bytes = std::fs::read(output).unwrap();
                assert_eq!(
                    read_bmff_c2pa_boxes(&mut Cursor::new(&bytes))
                        .unwrap()
                        .manifest_bytes,
                    Some(manifest.clone())
                );
                assert_eq!(binding(&bytes).merkle.unwrap().len(), 2);
                assert_eq!(
                    std::fs::read(&sources[index]).unwrap(),
                    [RELATIVE, ABSOLUTE][index]
                );
            }
        }
    }
}

#[test]
fn ladder_rejects_invalid_inputs_before_writing() {
    let dir = tempdirectory().unwrap();
    let (sources, outputs) = paths(
        dir.path(),
        &[
            RELATIVE.to_vec(),
            include_bytes!("../../tests/fixtures/video1_no_manifest.mp4").to_vec(),
        ],
    );
    let signer = test_signer(SigningAlg::Es256);
    let settings = Settings::new()
        .with_value("core.merkle_tree_max_leaves", 1)
        .unwrap();
    assert!(
        Builder::from_context(Context::new().with_settings(settings).unwrap())
            .with_definition(DEFINITION)
            .unwrap()
            .sign_ladder_files(signer.as_ref(), &sources[..1], &outputs[..1])
            .is_err()
    );
    assert!(!outputs[0].exists());
    assert!(builder()
        .sign_ladder_files(signer.as_ref(), &sources, &outputs)
        .is_err());
    assert!(!outputs[0].exists());
    assert!(builder()
        .sign_ladder_files(signer.as_ref(), &sources[..0], &outputs[..0])
        .is_err());
    assert!(builder()
        .sign_ladder_files(signer.as_ref(), &sources[..1], &outputs)
        .is_err());
    assert!(builder()
        .sign_ladder_files(
            signer.as_ref(),
            &vec![sources[0].clone(); 257],
            &vec![outputs[0].clone(); 257]
        )
        .is_err());
    for (no_embed, remote) in [(true, false), (true, true), (false, true)] {
        let mut b = builder();
        b.set_no_embed(no_embed);
        if remote {
            b.set_remote_url("https://example.invalid/manifest.c2pa");
        }
        let error = b
            .sign_ladder_files(signer.as_ref(), &sources[..1], &outputs[..1])
            .unwrap_err();
        assert!(matches!(error, crate::Error::BadParam(ref message)
            if message.contains("remote and sidecar manifests are not supported")));
        assert!(!outputs[0].exists());
    }
}

#[test]
fn ladder_rejects_existing_whole_file_provenance_before_writing() {
    for input in [RELATIVE, ABSOLUTE] {
        let signed = super::single_file_bmff_tests::historical_flat(input);
        let hash = binding(&signed);
        assert!(hash.hash().is_some());
        assert!(hash.merkle().is_none());
        let boxes = read_bmff_c2pa_boxes(&mut Cursor::new(&signed)).unwrap();
        assert!(boxes.manifest_bytes.is_some());
        assert!(boxes.bmff_merkle.is_empty());

        let dir = tempdirectory().unwrap();
        // Even a valid clean first rung must not be written before the later
        // rung's existing whole-file provenance has been rejected.
        let originals = [input.to_vec(), signed];
        let (sources, outputs) = paths(dir.path(), &originals);
        let error = builder()
            .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
            .unwrap_err();
        assert!(matches!(error, crate::Error::BadParam(ref message)
            if message == "ladder sources must not contain C2PA boxes"));
        for (source, original) in sources.iter().zip(&originals) {
            assert_eq!(&std::fs::read(source).unwrap(), original);
        }
        assert!(outputs.iter().all(|output| !output.exists()));
    }
}

struct DynamicSigner(Box<dyn Signer>);
struct Dynamic;
impl DynamicAssertion for Dynamic {
    fn label(&self) -> String {
        "org.example.ladder-test".into()
    }

    fn reserve_size(&self) -> Result<usize> {
        Ok(64)
    }

    fn content(
        &self,
        _: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent> {
        assert_eq!(size, Some(64));
        let binding = claim
            .assertions()
            .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
            .unwrap();
        let mut content = vec![0xa2, 0x64, b'h', b'a', b's', b'h', 0x58, 0x20];
        content.extend(binding.hash());
        content.extend([0x63, b'p', b'a', b'd', 0x73]);
        content.extend([b'x'; 19]);
        Ok(DynamicAssertionContent::Cbor(content))
    }
}
impl Signer for DynamicSigner {
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
        vec![Box::new(Dynamic)]
    }
}

#[test]
fn ladder_dynamic_assertion_endorses_final_binding() {
    let dir = tempdirectory().unwrap();
    let (sources, outputs) = paths(dir.path(), &[RELATIVE.to_vec(), shortened()]);
    let manifest = builder()
        .sign_ladder_files(
            &DynamicSigner(test_signer(SigningAlg::Es256)),
            &sources,
            &outputs,
        )
        .unwrap();
    let store = crate::store::Store::from_jumbf(
        &manifest,
        &mut crate::status_tracker::StatusTracker::default(),
    )
    .unwrap();
    let hash = store
        .provenance_claim()
        .unwrap()
        .assertions()
        .iter()
        .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
        .unwrap()
        .hash();
    #[derive(serde::Deserialize)]
    struct Endorsement {
        hash: ByteBuf,
    }
    for output in outputs {
        let bytes = std::fs::read(output).unwrap();
        binding(&bytes);
        let reader = Reader::default()
            .with_stream("video/mp4", Cursor::new(bytes))
            .unwrap();
        let endorsement: Endorsement = reader
            .active_manifest()
            .unwrap()
            .find_assertion("org.example.ladder-test")
            .unwrap();
        assert_eq!(endorsement.hash.as_ref(), hash);
    }
}

#[test]
#[ignore = "requires ffmpeg; run explicitly for native release qualification"]
fn ladder_video_audio_decode_equivalence() {
    use std::process::Command;

    let dir = tempdirectory().unwrap();
    let (mut sources, mut outputs) = paths(
        dir.path(),
        &[RELATIVE.to_vec(), ABSOLUTE.to_vec(), shortened()],
    );
    for (i, duration) in ["1", "2"].iter().enumerate() {
        let source = dir.path().join(format!("audio{i}.mp4"));
        let result = Command::new("ffmpeg")
            .args([
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000",
                "-t",
                duration,
                "-c:a",
                "aac",
                "-threads",
                "2",
                "-movflags",
                "+frag_keyframe+empty_moov+default_base_moof+global_sidx",
                "-frag_duration",
                "500000",
            ])
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        sources.push(source);
        outputs.push(dir.path().join(format!("signed_audio{i}.mp4")));
    }
    let originals: Vec<_> = sources.iter().map(|p| std::fs::read(p).unwrap()).collect();
    builder()
        .sign_ladder_files(test_signer(SigningAlg::Es256).as_ref(), &sources, &outputs)
        .unwrap();
    let decode = |path: &std::path::Path| {
        let result = Command::new("ffmpeg")
            .args(["-v", "error", "-i"])
            .arg(path)
            .args(["-threads", "2", "-f", "framemd5", "-"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            result.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout)
            .lines()
            .any(|l| l.starts_with("0,")));
        result.stdout
    };
    for ((source, output), original) in sources.iter().zip(&outputs).zip(&originals) {
        assert_eq!(std::fs::read(source).unwrap(), *original);
        assert_eq!(decode(source), decode(output));
        binding(&std::fs::read(output).unwrap());
    }
}
