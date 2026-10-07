// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

// Fixture setup and validation intentionally panic on unexpected results.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Seek};

use sha2::{Digest, Sha256};

use super::BmffHash;
use crate::{
    asset_handlers::bmff_io::read_bmff_c2pa_boxes,
    dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
    utils::test_signer::{async_test_signer, test_signer},
    Builder, BuilderIntent, Context, Reader, Result, Settings, Signer, SigningAlg, ValidationState,
};

const RELATIVE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments.mp4");
const ABSOLUTE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments_absolute.mp4");
const DEFINITION: &str = r#"{"title":"single-file fragments","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}]}}]}"#;

fn builder() -> Builder {
    Builder::default().with_definition(DEFINITION).unwrap()
}

fn sign(input: &[u8]) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut output,
        )
        .unwrap();
    output.into_inner()
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
}

// Deliberately independent of the SDK's BMFF tree and offset/hash helpers.
#[derive(Clone, Copy, Debug)]
struct B {
    start: usize,
    payload: usize,
    end: usize,
    kind: [u8; 4],
}

fn boxes(data: &[u8], start: usize, end: usize) -> Vec<B> {
    let mut result = Vec::new();
    let mut at = start;
    while end - at >= 8 {
        let size = u32_at(data, at);
        let (size, header) = match size {
            0 => (end - at, 8),
            1 => (u64_at(data, at + 8) as usize, 16),
            _ => (size as usize, 8),
        };
        assert!(size >= header && at + size <= end);
        result.push(B {
            start: at,
            payload: at + header,
            end: at + size,
            kind: data[at + 4..at + 8].try_into().unwrap(),
        });
        at += size;
    }
    assert!(end - at < 8);
    result
}

fn roots(data: &[u8]) -> Vec<B> {
    boxes(data, 0, data.len())
}
fn children(data: &[u8], b: B) -> Vec<B> {
    boxes(data, b.payload, b.end)
}
fn named(list: &[B], kind: &[u8; 4]) -> B {
    *list.iter().find(|b| &b.kind == kind).unwrap()
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
    hash.set_bmff_version(3); // Deserializing assertion data alone does not carry its label version.
    hash.verify_stream_hash(&mut Cursor::new(data), None)
        .unwrap();
    hash
}

fn independent_hash(data: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut digest = Sha256::new();
    let parsed = roots(data);
    for b in parsed.iter().filter(|b| b.start >= start && b.end <= end) {
        if [*b"ftyp", *b"mfra", *b"free", *b"skip"].contains(&b.kind)
            || (b.kind == *b"uuid"
                && data[b.payload..b.payload + 16]
                    == [
                        0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28,
                        0x87, 0x7e, 0xc4, 0x81,
                    ])
        {
            continue;
        }
        digest.update((b.start as u64).to_be_bytes());
        digest.update(&data[b.start..b.end]);
    }
    let suffix_start = parsed.last().map_or(0, |b| b.end);
    if suffix_start >= start && suffix_start < end {
        digest.update(&data[suffix_start..end]);
    }
    digest.finalize().to_vec()
}

fn check_aux_locator(signed: &[u8]) {
    let root = roots(signed);
    let first_merkle = root
        .iter()
        .find(|b| {
            b.kind == *b"uuid" && signed.get(b.payload + 20..b.payload + 27) == Some(b"merkle\0")
        })
        .unwrap();
    let primary = root
        .iter()
        .find(|b| {
            b.kind == *b"uuid"
                && matches!(
                    signed.get(b.payload + 20..b.payload + 29),
                    Some(b"manifest\0" | b"original\0")
                )
        })
        .unwrap();
    assert_eq!(
        u64_at(signed, primary.payload + 29),
        first_merkle.start as u64
    );
}

fn check_output(original: &[u8], signed: &[u8]) {
    let hash = binding(signed);
    assert!(hash.hash().is_none());
    let maps = hash.merkle().unwrap();
    assert_eq!(maps.len(), 1);
    let map = &maps[0];
    let count = roots(original)
        .iter()
        .filter(|b| b.kind == *b"moof")
        .count();
    assert_eq!(map.count, count);
    let moov = named(&roots(original), b"moov");
    let trak = named(&children(original, moov), b"trak");
    let tkhd = named(&children(original, trak), b"tkhd");
    let track_id = u32_at(
        original,
        tkhd.payload + if original[tkhd.payload] == 1 { 20 } else { 12 },
    );
    assert_ne!(track_id, 0);
    assert_eq!(map.local_id, track_id as usize);
    check_aux_locator(signed);
    assert!(map.fixed_block_size.is_none() && map.variable_block_sizes.is_none());
    let root = roots(signed);
    let moofs: Vec<_> = root
        .iter()
        .filter(|b| b.kind == *b"moof")
        .copied()
        .collect();
    assert_eq!(moofs.len(), count);
    assert_eq!(
        map.init_hash.as_ref().unwrap().as_ref(),
        independent_hash(signed, 0, moofs[0].start)
    );
    let c2pa = read_bmff_c2pa_boxes(&mut Cursor::new(signed)).unwrap();
    assert_eq!(c2pa.bmff_merkle.len(), count);
    for (i, moof) in moofs.iter().enumerate() {
        let uuid = &c2pa.bmff_merkle_box_infos[i];
        assert_eq!(uuid.end(), moof.start as u64);
        assert_eq!(uuid.size(), c2pa.bmff_merkle_box_infos[0].size());
        assert_eq!(c2pa.bmff_merkle[i].location, i);
        assert_eq!(c2pa.bmff_merkle[i].unique_id, map.unique_id);
        assert_eq!(c2pa.bmff_merkle[i].local_id, map.local_id);
        let end = moofs.get(i + 1).map_or(signed.len(), |b| b.start);
        assert_eq!(
            map.hashes.0[i].as_ref(),
            independent_hash(signed, moof.start, end)
        );
    }
    // Every media payload and mfhd sequence is preserved; tfhd is the only moof
    // field that may change (when its base is absolute).
    let old_roots = roots(original);
    for (old, new) in old_roots
        .iter()
        .filter(|b| b.kind == *b"mdat")
        .zip(root.iter().filter(|b| b.kind == *b"mdat"))
    {
        assert_eq!(&original[old.start..old.end], &signed[new.start..new.end]);
    }
    for (old, new) in old_roots.iter().filter(|b| b.kind == *b"moof").zip(&moofs) {
        let mut expected = original[old.start..old.end].to_vec();
        let old_traf = named(&children(original, *old), b"traf");
        let old_tfhd = named(&children(original, old_traf), b"tfhd");
        let new_traf = named(&children(signed, *new), b"traf");
        let new_tfhd = named(&children(signed, new_traf), b"tfhd");
        if u32_at(original, old_tfhd.payload) & 1 != 0 {
            assert_eq!(u64_at(signed, new_tfhd.payload + 8), new.start as u64);
            let at = old_tfhd.payload + 8 - old.start;
            expected[at..at + 8].copy_from_slice(&(new.start as u64).to_be_bytes());
        } else {
            assert_ne!(u32_at(signed, new_tfhd.payload) & 0x020000, 0);
        }
        assert_eq!(expected, signed[new.start..new.end]);
        let trun = named(&children(signed, new_traf), b"trun");
        let offset = u32_at(signed, trun.payload + 8) as i32;
        assert_eq!((new.start as i64 + i64::from(offset)) as usize, new.end + 8);
    }
    // sidx must include the new UUID in each reference, not just move first_offset.
    if let Some(sidx) = root.iter().find(|b| b.kind == *b"sidx") {
        let wide = signed[sidx.payload] == 1;
        let first_at = sidx.payload + 12 + if wide { 8 } else { 4 };
        let first = if wide {
            u64_at(signed, first_at)
        } else {
            u64::from(u32_at(signed, first_at))
        };
        let mut start = sidx.end + first as usize;
        let entries = first_at + if wide { 8 } else { 4 } + 4;
        assert_eq!(
            u16::from_be_bytes(signed[entries - 2..entries].try_into().unwrap()),
            count as u16
        );
        for (i, moof) in moofs.iter().enumerate() {
            assert_eq!(start as u64, c2pa.bmff_merkle_box_infos[i].start());
            let length = u32_at(signed, entries + 12 * i);
            assert_eq!(length & 0x80000000, 0);
            start += length as usize;
            let mdat = root
                .iter()
                .find(|b| b.kind == *b"mdat" && b.start > moof.start)
                .unwrap();
            assert_eq!(start, mdat.end);
        }
    }
    // All tfra entries must address their own moof, not the last moof for a track.
    check_tfra(signed);
}

fn check_tfra(signed: &[u8]) {
    let root = roots(signed);
    let moofs: Vec<_> = root.iter().filter(|b| b.kind == *b"moof").collect();
    let count = moofs.len();
    if let Some(mfra) = root.iter().find(|b| b.kind == *b"mfra") {
        let tfra = named(&children(signed, *mfra), b"tfra");
        let wide = signed[tfra.payload] == 1;
        let widths = u32_at(signed, tfra.payload + 8);
        assert_eq!(u32_at(signed, tfra.payload + 12), count as u32);
        let mut at = tfra.payload + 16;
        for moof in moofs {
            at += if wide { 8 } else { 4 };
            let offset = if wide {
                u64_at(signed, at)
            } else {
                u64::from(u32_at(signed, at))
            };
            assert_eq!(offset, moof.start as u64);
            at += if wide { 8 } else { 4 };
            at += (((widths >> 4) & 3) + ((widths >> 2) & 3) + (widths & 3) + 3) as usize;
        }
    }
}

#[test]
fn single_file_stream_offsets_and_hashes() {
    for input in [RELATIVE, ABSOLUTE] {
        check_output(input, &sign(input));
    }
}

#[test]
#[cfg(feature = "file_io")]
fn single_file_sign_file() {
    let dir = tempfile::tempdir().unwrap();
    for (i, input) in [RELATIVE, ABSOLUTE].iter().enumerate() {
        let source = dir.path().join(format!("source{i}.mp4"));
        let dest = dir.path().join(format!("signed{i}.mp4"));
        std::fs::write(&source, input).unwrap();
        builder()
            .sign_file(test_signer(SigningAlg::Es256).as_ref(), &source, &dest)
            .unwrap();
        check_output(input, &std::fs::read(dest).unwrap());
    }
}

#[tokio::test]
async fn single_file_async() {
    for input in [RELATIVE, ABSOLUTE] {
        let mut output = Cursor::new(Vec::new());
        builder()
            .sign_async(
                async_test_signer(SigningAlg::Es256).as_ref(),
                "video/mp4",
                &mut Cursor::new(input),
                &mut output,
            )
            .await
            .unwrap();
        check_output(input, output.get_ref());
    }
}

#[test]
fn single_file_tampering_and_resign() {
    let signed = sign(RELATIVE);
    let hash = binding(&signed);
    for kind in [b"moov", b"moof", b"mdat"] {
        let b = named(&roots(&signed), kind);
        let mut corrupted = signed.clone();
        let at = if kind == b"moof" {
            named(&children(&signed, b), b"mfhd").payload + 7
        } else {
            b.end - 1
        };
        corrupted[at] ^= 1;
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(corrupted), None)
            .is_err());
    }
    let error = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(&signed),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("existing Merkle boxes"),
        "{error}"
    );
}

#[test]
fn single_file_reject_cross_fragment_trun_and_limit() {
    let mut bad = RELATIVE.to_vec();
    let moof = named(&roots(&bad), b"moof");
    let traf = named(&children(&bad, moof), b"traf");
    let trun = named(&children(&bad, traf), b"trun");
    bad[trun.payload + 8..trun.payload + 12].copy_from_slice(&(-100i32).to_be_bytes());
    let err = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(bad),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(err.to_string().contains("trun samples outside"), "{err}");
    let settings = Settings::new()
        .with_value("core.merkle_tree_max_leaves", 2)
        .unwrap();
    let err = Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(RELATIVE),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(err.to_string().contains("merkle_tree_max_leaves"), "{err}");
}

#[test]
fn single_file_reject_unsupported_addressing() {
    let moof = named(&roots(RELATIVE), b"moof");
    let traf = named(&children(RELATIVE, moof), b"traf");
    let tfhd = named(&children(RELATIVE, traf), b"tfhd");
    let trun = named(&children(RELATIVE, traf), b"trun");
    let sidx = named(&roots(RELATIVE), b"sidx");
    let mut variants = Vec::new();
    let mut implicit = RELATIVE.to_vec();
    let flags = u32_at(&implicit, tfhd.payload) & !0x020000;
    implicit[tfhd.payload..tfhd.payload + 4].copy_from_slice(&flags.to_be_bytes());
    variants.push((implicit, "implicit tfhd base"));
    let mut overrun = RELATIVE.to_vec();
    overrun[trun.payload + 8..trun.payload + 12].copy_from_slice(&(moof.end as i32).to_be_bytes());
    variants.push((overrun, "trun samples outside"));
    let mut auxiliary = RELATIVE.to_vec();
    auxiliary[trun.start + 4..trun.start + 8].copy_from_slice(b"saio");
    variants.push((auxiliary, "saio"));
    let mut hierarchical = RELATIVE.to_vec();
    let entry = sidx.payload + if RELATIVE[sidx.payload] == 1 { 32 } else { 24 };
    hierarchical[entry] |= 0x80;
    variants.push((hierarchical, "hierarchical sidx"));
    for (input, message) in variants {
        let err = builder()
            .sign(
                test_signer(SigningAlg::Es256).as_ref(),
                "video/mp4",
                &mut Cursor::new(input),
                &mut Cursor::new(Vec::new()),
            )
            .unwrap_err();
        assert!(err.to_string().contains(message), "{message}: {err}");
    }
}

#[test]
fn single_file_fragment_binding_overrides_mdat_chunk_setting() {
    let settings = Settings::new()
        .with_value("core.merkle_tree_chunk_size_in_kb", 1)
        .unwrap();
    let mut output = Cursor::new(Vec::new());
    Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(RELATIVE),
            &mut output,
        )
        .unwrap();
    check_output(RELATIVE, output.get_ref());
}

#[test]
#[ignore = "requires the ffmpeg executable; run explicitly for native release qualification"]
fn single_file_ffmpeg_decode_equivalence() {
    let dir = tempfile::tempdir().unwrap();
    for input in [RELATIVE, ABSOLUTE] {
        let source = dir.path().join("source.mp4");
        let dest = dir.path().join("signed.mp4");
        std::fs::write(&source, input).unwrap();
        std::fs::write(&dest, sign(input)).unwrap();
        let decode = |path: &std::path::Path| {
            let result = std::process::Command::new("ffmpeg")
                .args(["-v", "error", "-i"])
                .arg(path)
                .args(["-f", "framemd5", "-"])
                .output()
                .expect("ffmpeg is required for this explicitly selected test");
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
            result.stdout
        };
        let before = decode(&source);
        assert_eq!(
            String::from_utf8_lossy(&before)
                .lines()
                .filter(|l| l.starts_with("0,"))
                .count(),
            6
        );
        assert_eq!(before, decode(&dest));
    }
}

struct DynamicSigner(Box<dyn Signer>);
struct Dynamic;
impl DynamicAssertion for Dynamic {
    fn label(&self) -> String {
        "com.castlabs.fragment-test".into()
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
fn single_file_dynamic_assertion_and_update() {
    let signer = DynamicSigner(test_signer(SigningAlg::Es256));
    let mut signed = Cursor::new(Vec::new());
    builder()
        .sign(
            &signer,
            "video/mp4",
            &mut Cursor::new(RELATIVE),
            &mut signed,
        )
        .unwrap();
    check_output(RELATIVE, signed.get_ref());
    let reader = Reader::default()
        .with_stream("video/mp4", &mut signed)
        .unwrap();
    #[derive(serde::Deserialize)]
    struct Endorsement {
        hash: serde_bytes::ByteBuf,
    }
    let endorsement: Endorsement = reader
        .active_manifest()
        .unwrap()
        .find_assertion("com.castlabs.fragment-test")
        .unwrap();
    let boxes = read_bmff_c2pa_boxes(&mut signed).unwrap();
    let store = crate::store::Store::from_jumbf(
        &boxes.manifest_bytes.unwrap(),
        &mut crate::status_tracker::StatusTracker::default(),
    )
    .unwrap();
    let final_binding = store
        .provenance_claim()
        .unwrap()
        .assertions()
        .iter()
        .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
        .unwrap();
    assert_eq!(endorsement.hash.as_ref(), final_binding.hash());
    let mut update = Builder::default();
    update.set_intent(BuilderIntent::Update);
    update
        .add_action(crate::assertions::Action::new("c2pa.published"))
        .unwrap();
    signed.rewind().unwrap();
    let mut output = Cursor::new(Vec::new());
    update
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut signed,
            &mut output,
        )
        .unwrap();
    let reader = Reader::default()
        .with_stream("video/mp4", &mut output)
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    binding(signed.get_ref())
        .verify_stream_hash(&mut output, None)
        .unwrap();
    check_aux_locator(output.get_ref());
}

fn historical_flat(input: &[u8]) -> Vec<u8> {
    // Reproduce the historical file-level binding using the caller-owned hash
    // API. The first pass fixes the layout; the second fills the same-size hash.
    let settings = Settings::new()
        .with_value("verify.verify_after_sign", false)
        .unwrap();
    let mut hash = BmffHash::new("historical flat fMP4", "sha256", None);
    hash.set_default_exclusions();
    hash.add_place_holder_hash().unwrap();
    let mut signed = Vec::new();
    for _ in 0..2 {
        let mut b = Builder::from_context(Context::new().with_settings(settings.clone()).unwrap())
            .with_definition(DEFINITION)
            .unwrap();
        b.add_assertion("c2pa.hash.bmff.v3", &hash).unwrap();
        let mut output = Cursor::new(Vec::new());
        b.sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut output,
        )
        .unwrap();
        signed = output.into_inner();
        hash.gen_hash_from_stream(&mut Cursor::new(&signed))
            .unwrap();
    }
    signed
}

#[test]
fn single_file_historical_flat_binding_still_verifies() {
    let signed = historical_flat(RELATIVE);
    let hash = binding(&signed);
    assert!(hash.hash().is_some() && hash.merkle().is_none());
    assert!(read_bmff_c2pa_boxes(&mut Cursor::new(&signed))
        .unwrap()
        .bmff_merkle
        .is_empty());
    // Re-signing legacy flat-bound fMP4 upgrades it to fragment Merkle binding.
    check_output(RELATIVE, &sign(&signed));
}

#[test]
fn single_file_trailing_bytes_are_bound_through_eof() {
    let clean = sign(RELATIVE);
    let clean_binding = binding(&clean);
    for len in 1..=7 {
        let mut appended = clean.clone();
        appended.extend(vec![0x51; len]);
        assert!(clean_binding
            .verify_stream_hash(&mut Cursor::new(appended), None)
            .is_err());
        let mut input = RELATIVE.to_vec();
        input.extend(vec![0x51; len]);
        let signed = sign(&input);
        check_output(&input, &signed);
        let hash = binding(&signed);
        let mut changed = signed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(changed), None)
            .is_err());
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(&signed[..signed.len() - 1]), None)
            .is_err());
    }
}

#[test]
fn single_file_track_id_and_changing_tracks() {
    assert_eq!(binding(&sign(RELATIVE)).merkle().unwrap()[0].local_id, 1);
    let mut input = RELATIVE.to_vec();
    let root = roots(&input);
    let moov = named(&root, b"moov");
    let trak = named(&children(&input, moov), b"trak");
    let tkhd = named(&children(&input, trak), b"tkhd");
    let trex = named(
        &children(&input, named(&children(&input, moov), b"mvex")),
        b"trex",
    );
    input[tkhd.payload + 12..tkhd.payload + 16].copy_from_slice(&137u32.to_be_bytes());
    input[trex.payload + 4..trex.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    for moof in root.iter().filter(|b| b.kind == *b"moof") {
        let traf = named(&children(&input, *moof), b"traf");
        let tfhd = named(&children(&input, traf), b"tfhd");
        input[tfhd.payload + 4..tfhd.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    }
    let sidx = named(&root, b"sidx");
    input[sidx.payload + 4..sidx.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    let tfra = named(&children(&input, named(&root, b"mfra")), b"tfra");
    input[tfra.payload + 4..tfra.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    let signed = sign(&input);
    check_output(&input, &signed);
    assert_eq!(binding(&signed).merkle().unwrap()[0].local_id, 137);
    let moof = named(&root, b"moof");
    let tfhd = named(
        &children(&input, named(&children(&input, moof), b"traf")),
        b"tfhd",
    );
    input[tfhd.payload + 4..tfhd.payload + 8].copy_from_slice(&138u32.to_be_bytes());
    let error = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(error.to_string().contains("matching tfhd"), "{error}");
}

#[test]
fn single_file_uuid_size_at_cbor_integer_boundaries() {
    let root = roots(RELATIVE);
    let moofs: Vec<_> = root
        .iter()
        .filter(|b| b.kind == *b"moof")
        .copied()
        .collect();
    let first = moofs[0];
    let mdat = *root
        .iter()
        .find(|b| b.kind == *b"mdat" && b.start > first.start)
        .unwrap();
    let traf = named(&children(RELATIVE, first), b"traf");
    let tfdt = named(&children(RELATIVE, traf), b"tfdt");
    let next_tfdt = named(
        &children(RELATIVE, named(&children(RELATIVE, moofs[1]), b"traf")),
        b"tfdt",
    );
    assert_eq!(RELATIVE[tfdt.payload], 1);
    let duration = u64_at(RELATIVE, next_tfdt.payload + 4) - u64_at(RELATIVE, tfdt.payload + 4);
    let mfhd = named(&children(RELATIVE, first), b"mfhd");
    for count in [25, 257] {
        // Repeat real encoded fragments with advancing decode time/sequence.
        // Omit optional indexes so source offsets remain moof-relative.
        let mut input = RELATIVE[..named(&root, b"moov").end].to_vec();
        for index in 0..count {
            let mut fragment = RELATIVE[first.start..mdat.end].to_vec();
            let at = mfhd.payload + 4 - first.start;
            fragment[at..at + 4].copy_from_slice(&((index + 1) as u32).to_be_bytes());
            let at = tfdt.payload + 4 - first.start;
            fragment[at..at + 8].copy_from_slice(&(index as u64 * duration).to_be_bytes());
            input.extend(fragment);
        }
        let signed = sign(&input);
        check_output(&input, &signed);
        let parsed = read_bmff_c2pa_boxes(&mut Cursor::new(&signed)).unwrap();
        assert_eq!(parsed.bmff_merkle.len(), count);
        let size = parsed.bmff_merkle_box_infos.last().unwrap().size();
        assert!(parsed
            .bmff_merkle_box_infos
            .iter()
            .all(|b| b.size() == size));
    }
}

#[test]
fn single_file_preprocessing_xmp_and_manifest_removal() {
    for input in [RELATIVE, ABSOLUTE] {
        let legacy = historical_flat(input);
        let handler = crate::jumbf_io::get_assetio_handler("video/mp4").unwrap();
        let mut stripped = Cursor::new(Vec::new());
        handler
            .get_writer("video/mp4")
            .unwrap()
            .remove_cai_store_from_stream(&mut Cursor::new(&legacy), &mut stripped)
            .unwrap();
        assert_eq!(stripped.get_ref(), input); // Includes every original tfra/tfhd/sidx field.
        let mut remote = builder();
        remote.set_remote_url("https://example.invalid/manifest.c2pa");
        let mut output = Cursor::new(Vec::new());
        remote
            .sign(
                test_signer(SigningAlg::Es256).as_ref(),
                "video/mp4",
                &mut Cursor::new(&legacy),
                &mut output,
            )
            .unwrap();
        check_output(input, output.get_ref());
        for remote_only in [false, true] {
            let mut sidecar = builder();
            sidecar.set_no_embed(true);
            if remote_only {
                sidecar.set_remote_url("https://example.invalid/detached.c2pa");
            }
            let mut output = Cursor::new(Vec::new());
            let manifest = sidecar
                .sign(
                    test_signer(SigningAlg::Es256).as_ref(),
                    "video/mp4",
                    &mut Cursor::new(&legacy),
                    &mut output,
                )
                .unwrap();
            let reader = Reader::default()
                .with_manifest_data_and_stream(&manifest, "video/mp4", &mut output)
                .unwrap();
            assert_ne!(
                reader.validation_state(),
                ValidationState::Invalid,
                "{reader}"
            );
            check_tfra(output.get_ref());
            let parsed = read_bmff_c2pa_boxes(&mut output).unwrap();
            assert!(parsed.manifest_bytes.is_none());
            assert_eq!(parsed.bmff_merkle.len(), 3);
        }
    }
}

#[test]
#[cfg(feature = "file_io")]
fn single_file_aux_locator_xmp_replacement_and_in_place_patch() {
    let signed = sign(ABSOLUTE);
    let handler = crate::jumbf_io::get_assetio_handler("video/mp4").unwrap();
    let manifest = read_bmff_c2pa_boxes(&mut Cursor::new(&signed))
        .unwrap()
        .manifest_bytes
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("patched.mp4");
    std::fs::write(&path, &signed).unwrap();
    handler
        .asset_patch_ref()
        .unwrap()
        .patch_cai_store(&path, &manifest)
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), signed);
    let mut source = signed;
    for url in [
        "https://example.invalid/long-manifest-name.c2pa",
        "https://example.invalid/x",
    ] {
        let mut output = Cursor::new(Vec::new());
        handler
            .remote_ref_writer_ref()
            .unwrap()
            .embed_reference_to_stream(
                &mut Cursor::new(&source),
                &mut output,
                crate::asset_io::RemoteRefEmbedType::Xmp(url.into()),
            )
            .unwrap();
        // Modifying XMP requires re-signing the binding, but the media indexes
        // and the existing manifest's auxiliary locator must still be correct.
        check_aux_locator(output.get_ref());
        check_tfra(output.get_ref());
        source = output.into_inner();
    }
}

#[test]
fn single_file_rejects_multiple_initialization_tracks() {
    let root = roots(RELATIVE);
    let moov = named(&root, b"moov");
    let trak = named(&children(RELATIVE, moov), b"trak");
    let mut extra_track = RELATIVE[trak.start..trak.end].to_vec();
    let tkhd = named(&children(RELATIVE, trak), b"tkhd");
    let at = tkhd.payload + 12 - trak.start;
    extra_track[at..at + 4].copy_from_slice(&2u32.to_be_bytes());
    let mut input = RELATIVE.to_vec();
    input.splice(moov.end..moov.end, extra_track.iter().copied());
    input[moov.start..moov.start + 4]
        .copy_from_slice(&((moov.end - moov.start + extra_track.len()) as u32).to_be_bytes());
    let error = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("multiplexed/changing tracks"),
        "{error}"
    );
}

/// Rewrite the `uniqueId` every `merkle` uuid box of `signed` carries from
/// `1` to `0`: the value the writer used before the 1-based fix. CBOR encodes
/// both as one byte, so the boxes keep their size and every hash still holds.
fn with_legacy_zero_ids(signed: &[u8]) -> Vec<u8> {
    let parsed = read_bmff_c2pa_boxes(&mut Cursor::new(signed)).unwrap();
    assert!(!parsed.bmff_merkle.is_empty());
    let mut out = signed.to_vec();
    let key = b"\x68uniqueId\x01";
    let mut rewritten = 0;
    for info in &parsed.bmff_merkle_box_infos {
        let start = info.offset as usize;
        let end = start + info.size() as usize;
        if let Some(at) = out[start..end].windows(key.len()).position(|w| w == key) {
            out[start + at + key.len() - 1] = 0;
            rewritten += 1;
        }
    }
    assert_eq!(rewritten, parsed.bmff_merkle.len());
    out
}

/// The one map a freshly signed lone asset carries.
fn own_map(signed: &[u8]) -> super::MerkleMap {
    let mut hash = binding(signed);
    let mut maps = hash.merkle.take().unwrap();
    assert_eq!(maps.len(), 1);
    maps.remove(0)
}

/// A sibling rendition's map: another `uniqueId`, garbage everywhere else.
fn invalid_sibling_of(own: &super::MerkleMap) -> super::MerkleMap {
    use serde_bytes::ByteBuf;
    super::MerkleMap {
        unique_id: own.unique_id + 1,
        local_id: own.local_id,
        count: own.count + 2,
        alg: own.alg.clone(),
        init_hash: Some(ByteBuf::from(vec![0xaa; 32])),
        hashes: super::VecByteBuf(vec![ByteBuf::from(vec![0xbb; 32]); own.count + 2]),
        fixed_block_size: None,
        variable_block_sizes: None,
    }
}

/// Verifier-level selection: a lone asset keeps validating against its own
/// map while an unrelated -- and deliberately invalid -- sibling map sits in
/// the same assertion, and the ids it selects by are the asset's own.
#[test]
fn single_file_verifier_ignores_an_invalid_sibling_map() {
    let signed = sign(RELATIVE);
    let own = own_map(&signed);
    // New output pins the 1-based id.
    assert_eq!(
        (own.unique_id, own.local_id),
        (super::SINGLE_RENDITION_ID, 1)
    );

    let mut with_sibling = binding(&signed);
    with_sibling
        .merkle
        .as_mut()
        .unwrap()
        .push(invalid_sibling_of(&own));
    with_sibling
        .verify_stream_hash(&mut Cursor::new(&signed), None)
        .expect("the asset's own map must be selected; the sibling is not this asset");

    // ...in either order, so neither selected-map loop can be reverted to
    // "first map" or "every map" without this test noticing.
    let mut sibling_first = binding(&signed);
    sibling_first.merkle = Some(vec![invalid_sibling_of(&own), own_map(&signed)]);
    sibling_first
        .verify_stream_hash(&mut Cursor::new(&signed), None)
        .expect("selection must not depend on map order");

    // localId is half of the key: a map sharing this asset's uniqueId but
    // naming another track is a sibling too, and must not be selected.
    let mut other_track = binding(&signed);
    let mut same_id_other_track = invalid_sibling_of(&own);
    same_id_other_track.unique_id = own.unique_id;
    same_id_other_track.local_id = own.local_id + 1;
    other_track.merkle = Some(vec![same_id_other_track, own_map(&signed)]);
    other_track
        .verify_stream_hash(&mut Cursor::new(&signed), None)
        .expect("a map with this uniqueId but another localId is not this asset");

    // With only the sibling present the asset names a tree the manifest
    // lacks, and must fail rather than be checked against the sibling.
    let mut only_sibling = binding(&signed);
    only_sibling.merkle = Some(vec![invalid_sibling_of(&own)]);
    let err = only_sibling
        .verify_stream_hash(&mut Cursor::new(&signed), None)
        .unwrap_err();
    assert!(
        err.to_string().contains("no MerkleMap for this asset"),
        "{err}"
    );
}

/// An asset written before the 1-based fix names tree `0` in its own boxes;
/// it keeps validating against a map numbered `0`, and is not silently
/// matched to a map numbered `1`.
#[test]
fn single_file_verifier_honours_legacy_zero_ids_end_to_end() {
    let signed = sign(RELATIVE);
    let count = own_map(&signed).count;
    let legacy_asset = with_legacy_zero_ids(&signed);
    assert_eq!(
        read_bmff_c2pa_boxes(&mut Cursor::new(&legacy_asset))
            .unwrap()
            .bmff_merkle
            .iter()
            .map(|b| b.unique_id)
            .collect::<Vec<_>>(),
        vec![0; count]
    );

    let mut legacy_manifest = binding(&signed);
    legacy_manifest.merkle.as_mut().unwrap()[0].unique_id = 0;
    legacy_manifest
        .verify_stream_hash(&mut Cursor::new(&legacy_asset), None)
        .expect("a pre-fix asset must keep validating against its own map 0");

    let err = binding(&signed)
        .verify_stream_hash(&mut Cursor::new(&legacy_asset), None)
        .unwrap_err();
    assert!(
        err.to_string().contains("no MerkleMap for this asset"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Verifying one fragment of a single-file asset without the whole file.
//
// A byte-range HLS player hands the validator the initialization bytes and
// one segment at a time. The leaf hashes of a single-file asset cover
// absolute root-box offsets, so the segment must be verified "at" the offset
// it was cut from. These tests pin down the cut the specification implies
// (merkle uuid to merkle uuid, last one through EOF) and show that every
// other cut, and the right cut at the wrong offset, is rejected.
// ---------------------------------------------------------------------------

/// The C2PA box usertype (ISO/IEC 23001-7 style uuid), spelled out so the
/// test stays independent of the SDK's constant.
const C2PA_BOX_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

/// Byte ranges of the merkle uuid boxes, in file order.
fn merkle_uuids(data: &[u8]) -> Vec<B> {
    roots(data)
        .into_iter()
        .filter(|b| {
            b.kind == *b"uuid"
                && b.end - b.payload >= 16 + 4 + 7
                && data[b.payload..b.payload + 16] == C2PA_BOX_UUID
                && &data[b.payload + 20..b.payload + 27] == b"merkle\0"
        })
        .collect()
}

/// The cut a byte-range playlist must use: init = everything before the
/// first merkle uuid; segment i = from merkle uuid i to the next one, the last
/// one through end of file. Returns `(init, [(absolute_offset, bytes)])`.
fn spec_cut(signed: &[u8]) -> (Vec<u8>, Vec<(u64, Vec<u8>)>) {
    let uuids = merkle_uuids(signed);
    assert!(!uuids.is_empty(), "no merkle uuid boxes in signed output");
    let init = signed[..uuids[0].start].to_vec();
    let segments = uuids
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let end = uuids.get(i + 1).map_or(signed.len(), |n| n.start);
            (u.start as u64, signed[u.start..end].to_vec())
        })
        .collect();
    (init, segments)
}

fn segment_reader(init: &[u8], segment: &[u8], offset: u64) -> Result<Reader> {
    Reader::from_fragment_at_offset("video/mp4", Cursor::new(init), Cursor::new(segment), offset)
}

fn assert_segment_valid(init: &[u8], segment: &[u8], offset: u64) {
    let reader = segment_reader(init, segment, offset).unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    assert!(
        reader
            .validation_results()
            .and_then(|r| r.active_manifest())
            .is_some_and(|m| m
                .success()
                .iter()
                .any(|s| s.code() == crate::validation_status::ASSERTION_BMFFHASH_MATCH)),
        "segment at {offset} did not report a BMFF hash match: {reader}"
    );
}

/// A rejected segment is reported, not thrown: the reader comes back
/// `Invalid` with `assertion.bmffHash.mismatch`, like every other hard-binding
/// failure, so a player can show it. An `Err` here would be a regression.
fn assert_segment_rejected(init: &[u8], segment: &[u8], offset: u64, why: &str) {
    let expected = format!("{why}: expected a reported mismatch, got an error");
    let reader = segment_reader(init, segment, offset).expect(&expected);
    assert_eq!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{why}: expected rejection, got {reader}"
    );
    assert!(
        reader
            .validation_results()
            .and_then(|r| r.active_manifest())
            .is_some_and(|m| m
                .failure()
                .iter()
                .any(|s| s.code() == crate::validation_status::ASSERTION_BMFFHASH_MISMATCH)),
        "{why}: expected a BMFF hash mismatch, got {reader}"
    );
}

#[test]
fn single_file_segments_verify_at_their_absolute_offset() {
    for input in [RELATIVE, ABSOLUTE] {
        let signed = sign(input);
        let (init, segments) = spec_cut(&signed);
        let expected = binding(&signed).merkle.unwrap()[0].count;
        assert_eq!(segments.len(), expected);

        // Every segment verifies on its own, given only the init bytes and
        // the offset it was cut from; the whole-file reader is never involved.
        for (offset, segment) in &segments {
            assert_segment_valid(&init, segment, *offset);
        }

        // The init prefix may equally end at the first moof: the merkle uuid
        // in between is excluded from the hash either way.
        let first_moof = named(&roots(&signed), b"moof").start;
        assert!(first_moof > init.len());
        let (offset, segment) = &segments[0];
        assert_segment_valid(&signed[..first_moof], segment, *offset);
    }
}

#[test]
fn single_file_segments_reject_wrong_offset_and_cut() {
    let signed = sign(RELATIVE);
    let (init, segments) = spec_cut(&signed);
    let (offset, segment) = &segments[1];

    // The multi-file reader hashes the segment as if it started at byte 0.
    assert_segment_rejected(&init, segment, 0, "offset 0");
    assert_segment_rejected(&init, segment, offset + 1, "offset off by one");
    assert_segment_rejected(
        &init,
        segment,
        offset - 1,
        "offset off by one the other way",
    );
    assert_segment_rejected(&init, segment, u64::MAX, "offset overflow");

    // Dropping the tail (the bytes between the last mdat and the next merkle
    // uuid belong to this leaf) or the head changes the hash.
    let short = &segment[..segment.len() - 1];
    assert_segment_rejected(&init, short, *offset, "segment missing its last byte");
    let shifted = &segment[1..];
    assert_segment_rejected(&init, shifted, offset + 1, "segment missing its first byte");

    // A cut from moof to moof carries the NEXT fragment's merkle uuid and so
    // names the wrong leaf.
    let moofs: Vec<B> = roots(&signed)
        .into_iter()
        .filter(|b| b.kind == *b"moof")
        .collect();
    let moof_cut = &signed[moofs[1].start..moofs[2].start];
    assert_segment_rejected(&init, moof_cut, moofs[1].start as u64, "moof-to-moof cut");

    // A segment that runs on to the next moof carries two merkle uuid boxes,
    // its own and the next fragment's. The next one names a leaf whose bytes
    // are not in the segment, so the segment as a whole is rejected.
    let own_uuid = merkle_uuids(&signed)[1];
    let to_next_moof = &signed[own_uuid.start..moofs[2].start];
    assert!(to_next_moof.len() > segment.len());
    assert_segment_rejected(
        &init,
        to_next_moof,
        own_uuid.start as u64,
        "segment carrying the next merkle uuid",
    );

    // The init bytes are hashed at offset 0 and must be the file's prefix.
    // Cutting them short truncates a box, which is a structural error rather
    // than a hash mismatch: the reader refuses the init before hashing.
    assert!(segment_reader(&init[..init.len() - 1], segment, *offset).is_err());
    assert!(segment_reader(&init[1..], segment, *offset).is_err());
    // An extra box keeps the structure intact, so this one is a plain
    // mismatch. (`free` and `skip` would be excluded from the hash by the
    // assertion's exclusion list and accepted; any other type is hashed.)
    let mut padded = init.clone();
    padded.extend_from_slice(&[0, 0, 0, 8, b'w', b'i', b'd', b'e']);
    assert_segment_rejected(&padded, segment, *offset, "init with an extra box");
}

#[test]
fn single_file_segment_offsets_are_mandatory_on_the_old_api() {
    // The pre-existing multi-file entry point is unchanged: it cannot verify
    // a segment of a single-file asset, by construction.
    let signed = sign(RELATIVE);
    let (init, segments) = spec_cut(&signed);
    for (_, segment) in &segments {
        let reader =
            Reader::from_fragment("video/mp4", Cursor::new(&init), Cursor::new(segment)).unwrap();
        assert_eq!(reader.validation_state(), ValidationState::Invalid);
        assert!(reader
            .validation_results()
            .and_then(|r| r.active_manifest())
            .is_some_and(|m| m
                .failure()
                .iter()
                .any(|s| s.code() == crate::validation_status::ASSERTION_BMFFHASH_MISMATCH)));
    }
}

#[tokio::test]
async fn single_file_segments_verify_async() {
    let signed = sign(RELATIVE);
    let (init, segments) = spec_cut(&signed);
    for (offset, segment) in &segments {
        let reader = Reader::from_fragment_at_offset_async(
            "video/mp4",
            Cursor::new(&init),
            Cursor::new(segment),
            *offset,
        )
        .await
        .unwrap();
        assert_ne!(
            reader.validation_state(),
            ValidationState::Invalid,
            "{reader}"
        );
    }
    let (offset, segment) = &segments[0];
    let wrong = Reader::from_fragment_at_offset_async(
        "video/mp4",
        Cursor::new(&init),
        Cursor::new(segment),
        offset + 8,
    )
    .await
    .unwrap();
    assert_eq!(
        wrong.validation_state(),
        ValidationState::Invalid,
        "{wrong}"
    );
}

#[test]
fn single_file_segment_direct_hash_api() {
    // The assertion-level API behaves the same without a Reader.
    let signed = sign(ABSOLUTE);
    let hash = binding(&signed);
    let (init, segments) = spec_cut(&signed);
    for (offset, segment) in &segments {
        hash.verify_stream_segment_at_offset(
            &mut Cursor::new(&init),
            &mut Cursor::new(segment),
            *offset,
            None,
        )
        .unwrap();
        assert!(hash
            .verify_stream_segment(&mut Cursor::new(&init), &mut Cursor::new(segment), None)
            .is_err());
    }
}

// ---------------------------------------------------------------------------
// Per-fragment `sidx` (FFmpeg `+dash`, the layout byte-range HLS packagers
// cut at): each `sidx` is hashed with the previous fragment's leaf, so a
// segment cut at its `sidx` matches no leaf, while the specification's cut
// (merkle box to merkle box) verifies at its offset.
// ---------------------------------------------------------------------------

/// ffmpeg 6.1.1 `+dash` output: a `sidx` before every `moof`, then `mfra`.
const PER_FRAGMENT_SIDX: &[u8] =
    include_bytes!("../../tests/fixtures/single_file_fragments_sidx.mp4");

/// The cut a sidx-walking packager writes: init = everything before the first
/// `sidx`; segment i = from `sidx` i to the end of `mdat` i.
fn sidx_cut(signed: &[u8]) -> (Vec<u8>, Vec<(u64, Vec<u8>)>) {
    let r = roots(signed);
    let sidx: Vec<B> = r.iter().copied().filter(|b| b.kind == *b"sidx").collect();
    let mdat: Vec<B> = r.iter().copied().filter(|b| b.kind == *b"mdat").collect();
    assert_eq!(sidx.len(), mdat.len());
    let init = signed[..sidx[0].start].to_vec();
    let segments = sidx
        .iter()
        .zip(&mdat)
        .map(|(s, m)| (s.start as u64, signed[s.start..m.end].to_vec()))
        .collect();
    (init, segments)
}

/// Independent check of a per-fragment-sidx output: whole file verifies; one
/// merkle box right before every moof; every sidx's first reference starts at
/// its fragment's merkle box and covers through that fragment's mdat; init
/// and leaf hashes recomputed here match the assertion.
fn check_per_fragment_sidx_output(signed: &[u8]) {
    let hash = binding(signed);
    let map = &hash.merkle().unwrap()[0];
    let r = roots(signed);
    let of = |k: &[u8; 4]| -> Vec<B> { r.iter().copied().filter(|b| &b.kind == k).collect() };
    let (sidx, moof, mdat) = (of(b"sidx"), of(b"moof"), of(b"mdat"));
    let merkle = merkle_uuids(signed);
    assert_eq!(map.count, moof.len());
    assert_eq!(merkle.len(), moof.len());
    for i in 0..moof.len() {
        assert_eq!(merkle[i].end, moof[i].start);
        assert_eq!(sidx[i].end, merkle[i].start);
        // sidx: version/flags, reference_ID, timescale, earliest_presentation_time
        // and first_offset (32 bits each in v0, 64 bits in v1), reserved,
        // reference_count, then the first reference (31-bit size).
        let p = sidx[i].payload;
        let (first_offset, first_ref) = if signed[p] == 0 {
            (u32_at(signed, p + 16) as usize, p + 24)
        } else {
            (u64_at(signed, p + 20) as usize, p + 32)
        };
        let size = (u32_at(signed, first_ref) & 0x7fff_ffff) as usize;
        assert_eq!(
            sidx[i].end + first_offset,
            merkle[i].start,
            "sidx {i} target"
        );
        assert_eq!(merkle[i].start + size, mdat[i].end, "sidx {i} size");
    }
    let leaf = |start: usize, end: usize| -> Vec<u8> {
        let mut digest = Sha256::new();
        for b in r.iter().filter(|b| b.start >= start && b.end <= end) {
            let excluded = [*b"ftyp", *b"mfra", *b"free", *b"skip"].contains(&b.kind)
                || (b.kind == *b"uuid" && signed[b.payload..b.payload + 16] == C2PA_BOX_UUID);
            if !excluded {
                digest.update((b.start as u64).to_be_bytes());
                digest.update(&signed[b.start..b.end]);
            }
        }
        digest.finalize().to_vec()
    };
    assert_eq!(
        map.init_hash.as_ref().unwrap().as_ref(),
        leaf(0, moof[0].start)
    );
    for i in 0..moof.len() {
        let end = moof.get(i + 1).map_or(signed.len(), |b| b.start);
        assert_eq!(
            map.hashes.0[i].as_ref(),
            leaf(moof[i].start, end),
            "leaf {i}"
        );
    }
}

#[test]
fn single_file_per_fragment_sidx_belongs_to_the_previous_leaf() {
    let signed = sign(PER_FRAGMENT_SIDX);
    check_per_fragment_sidx_output(&signed);

    let (spec_init, spec_segments) = spec_cut(&signed);
    assert_eq!(spec_segments.len(), 3);
    for (offset, segment) in &spec_segments {
        assert_segment_valid(&spec_init, segment, *offset);
    }

    // A segment cut at its sidx carries the previous leaf's sidx and lacks
    // its own trailing one.
    let (init, segments) = sidx_cut(&signed);
    let (offset, segment) = &segments[1];
    assert_segment_rejected(&init, segment, *offset, "sidx cut");
}
