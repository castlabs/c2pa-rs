# Trusted VSI Consolidation Merges

Date: 2026-09-30. Branch: `feat/trusted-vsi-functional` (fork base
`3569fb86`), consolidated on local branch `consolidation/trusted-vsi-merges`
in `~/opencode-worktrees/c2pa-rs-vsi-consolidation`. Not pushed.

Each candidate head was re-verified with `git ls-remote staging <branch>`
immediately before merging and merged with `git merge --no-ff` (true merges,
no cherry-picks, no rebases). One merge commit per candidate, in this order:

| # | Candidate | Head | PR |
|---|---|---|---|
| 1 | `fix/tfra-moof-offset-adjust-upstream` | `c8375443` | contentauth #2710 |
| 2 | `fix/single-file-fmp4-merkle-upstream` | `4c69020e` | contentauth #2715 |
| 3 | `fix/fragmented-merkle-map-selection-upstream` | `dfddc82a` | mstattma #16 |
| 4 | `fix/single-file-merkle-id-normalization` | `d9e0351a` | mstattma #18 |
| 5 | `feat/fragmented-signing-ffi-upstream` | `27e949ca` | mstattma #17 |
| 6 | `feat/single-file-presentation-signing-upstream` | `8334583a` | mstattma #19 |
| 7 | `ci/codecov-upstream-only` | `912c9fe4` | mstattma #20 |

The candidates are based on newer ContentAuth `main` than the fork (fork
merge base `312491af`; candidates up to `d589cf7e`), so merge 1-3 also bring in
the intervening upstream history.

## Resolution principles

Preserve both sides: the fork's exact dynamic-assertion (DA) reservation,
trust purpose isolation, trusted VSI, live-video FFI, and Context-based
fragmented read-back; and each candidate's fix (TFRA offsets, single-file
Merkle, fragmented map selection, Merkle ID normalization, fragmented signing
FFI including the output-resolves-to-source rejection, presentation/ladder
signing). Where the fork's earlier fragmented FFI (`9e1a9607`, read-back as in
`3b068790`) overlaps #17, #17's current version is taken unless the fork's
behavior is strictly needed (documented below).

## Qualification decisions

- **MSRV**: upstream #2624 sets `rust-version = "1.96.0"`; the fork's
  qualification previously pinned Rust 1.88.0. The merged source requires
  Rust 1.96.0, so the workflow, script, tests, cache key, and documentation now
  pin 1.96.0. The merged SDK, FFI, and c2patool suites pass without
  `--ignore-rust-version`.
- **c2patool / Cargo.lock**: upstream #2617 removes `cli/` and untracks
  `Cargo.lock`. Kept both (fork qualification builds/tests c2patool
  live-video and runs `--locked`). The FFI dev dependency now uses the same
  `c2pa_cbor` 0.78.0 as the SDK, removing the stale 0.77.4 copy from the lockfile.

## Per-merge conflict resolutions

### 1. fix/tfra-moof-offset-adjust-upstream @c8375443 (#2710)
Brings upstream main d589cf7e-era commits (base c18ee8d7) incl. #2617 (c2patool removed), #2624 (MSRV 1.96), #2517 (sign_manifest reserves DA placeholders itself), c2pa_cbor 0.78.
- CHANGELOG.md [Unreleased]: kept both (our Experimental section, then candidate's Fixed TFRA entry).
- docs/experimental-features.md table: kept our live-video row + prose; inserted upstream rows (structured-text A.9, plain-text A.8) into the table before our prose.
- sdk/Cargo.toml features: kept both `unstable_live_video = ["dep:p256"]` and upstream `unstable_plain_text`. Deps: took upstream `c2pa_cbor = "0.78.0"` (ours was 0.77.4).
- Cargo.lock / cli/** (modify/delete vs upstream #2617): kept ours — fork ships c2patool live-video and qualifies with --locked + lockfile hash evidence. Restored the whole cli/ tree from HEAD, re-added "cli" to workspace members, and replaced upstream's `/Cargo.lock` ignore rule with a fork note. Cargo.lock refreshed by cargo for new deps.
- sdk/src/store.rs `sign_manifest`: took upstream #2517 signature `sign_manifest(context, target_len)` (signer from Context, reserves DA placeholders itself, BMFF oversize exemption, target_len padding). Refactored into `sign_manifest_impl(signer, context, target_len, reserve_placeholders)` and added crate-private `sign_manifest_reserved(signer, context, target_len)` for pre-reserved stores (trusted-VSI init finalization, our exact-reservation tests): it does not append new slots and runs `resolve_dynamic_assertion_labels` for an early actionable error. Our exact `add_dynamic_assertion_placeholders`, `resolve_dynamic_assertion_labels`, and resolved-label `write_dynamic_assertions` retained. Callers updated: live_video/trusted_vsi.rs finalize_init_external, two store.rs reservation tests.
- c2pa_c_ffi (no textual conflict, semantic breakage from upstream #2559 opaque-handle checkout guards: deref macros now return TypedShared/TypedExclusive guards): adapted fork FFI code — `let mut` for exclusive guards (live_video.rs sessions/signers, c2pa_builder_sign_fragmented builder, c2pa_signer_add_dynamic_assertion signer), `&context` for from_shared_context* calls (fragmented reader, trusted-VSI session, VSI signers), `&*signer` where `&dyn Signer` is required (c2pa_builder_sign, sign_fragmented, sign_data_hashed_embeddable), test `&mut *dest.stream_mut()`. Removed test use of deleted `validate_pointer` (buffer tracking still asserted by `c2pa_free(..) == 0`). live_video.rs import block re-wrapped by rustfmt.
- MSRV: upstream #2624 declares rust-version 1.96.0 (sdk, macros, export_schema). Kept upstream value; fork qualification pins 1.88.0 which now needs `--ignore-rust-version` (checks pass on 1.88 with it). NOT changed here — coordinator decision (bump qualification to 1.96.0 or pin rust-version).

### 2. fix/single-file-fmp4-merkle-upstream @4c69020e (#2715)
Also carries upstream main up to 6c92bc32 (#2697 identity underflow fix).
- CHANGELOG.md: appended the candidate's Fixed bullet to our Fixed section.
- sdk/src/asset_handlers/bmff_io.rs (hunk before `adjust_known_offsets`): took the candidate's new `single_file_fragment_track_id`, `relocate_single_file_fragments`, `insert_fragment_merkle_boxes` block; kept #2710's (ours-side) doc comment for `adjust_known_offsets` (range-aware TFRA semantics) instead of the candidate's older one-line comment.
- sdk/src/identity/builder/identity_assertion_builder.rs (`finalize_identity_assertion`): kept our exact-fill padding (pad1/pad2 hole bridging, checked arithmetic, fallible allocation). Replaced upstream #2697's auto-merged 15-byte `min_size` guard with the plain `len > assertion_size` check: our algorithm fills any non-negative gap without underflow, and the guard would have rejected small exact reservations the fork relies on (DA exact reservation). Tests: kept ours (`referenced_assertion_labels_match_numeric_instance_suffixes`) and upstream's `rejects_reserve_size_that_is_too_small`, adapted: sizes {0, 1, unpadded-1} must be BadParam; sizes {unpadded, +1, +14, +15, +24} must fill exactly.
- sdk/src/store.rs: auto-merged (single-file fragment Merkle path in save_to_stream); no conflict with our sign_manifest refactor.

### 3. fix/fragmented-merkle-map-selection-upstream @dfddc82a (#16)
Also carries upstream main up to d589cf7e (id3 1.17.2, flate2 dev-dep, certificate profile / mp3 / flac fixes) and the Codecov-upstream-only CI commit (`.github/workflows/tier-1a.yml`).
- CHANGELOG.md: appended the candidate's Fixed bullet to our Fixed section. No code conflicts; `sdk/src/assertions/bmff_hash.rs` auto-merged.

### 4. fix/single-file-merkle-id-normalization @d9e0351a (#18)
- CHANGELOG.md: kept both Fixed bullets (map selection #16, rendition ID 1 normalization #18). No code conflicts; `bmff_hash.rs` / `single_file_bmff_tests.rs` auto-merged.

### 5. feat/fragmented-signing-ffi-upstream @27e949ca (#17) — supersedes fork 9e1a9607 / 3b068790 FFI shape
- c2pa_c_ffi/src/c_api.rs `c2pa_builder_sign_fragmented` (2 hunks: doc comment + body): took #17 — `reserve_fragmented_output` preflight/exclusive reservation, glob-aware `asset_path`, optional (NULL-allowed) `manifest_bytes_ptr`, Context read-back via `builder.context().read_embedded_manifest_from_file` (#17's version of our 3b068790 read-back). One deliberate deviation (ours strictly needed): the signer passed to `sign_fragmented_files` is `&*signer` (the fork's DA-aware `impl Signer for C2paSigner`) instead of `signer.signer.as_ref()`, so FFI dynamic assertions registered via `c2pa_signer_add_dynamic_assertion` still apply (asserted by fork test `test_fragmented_file_set_ffi_round_trip_and_settings`, which counts one DA callback invocation).
- Fork test `test_fragmented_signer_ffi_rejects_invalid_inputs` adapted to #17 semantics: an invalid asset glob (`[`) now fails with "Invalid glob pattern" (was "literal initialization-segment path"); the NULL `manifest_bytes_ptr` case was removed (NULL is now allowed and skips allocation); NULL builder case kept.
- sdk/src/asset_handlers/bmff_io.rs `SUPPORTED_TYPES`: both sides added `m4s`/`cmfv`; took #17's 18-entry array (ours had the same entries at a different position plus `video/iso.segment` from base → would have been a duplicate list).
- sdk/src/utils/mime.rs: took #17 (`m4s` → `video/iso.segment`, `cmfv` → `video/mp4`), superseding ours (`m4s` → `video/mp4`). BMFF handler still accepts both MIME types.
- sdk/src/context.rs: took #17 (doc paragraph for `read_embedded_manifest_from_file`; WASI-aware temp dir in the custom-handler test, cf214ed2).
- docs/supported-formats.md: took #17's row layout (`m4s` → `video/iso.segment` row; removed our combined `m4s, cmfv` row).
- CHANGELOG.md / c2pa_c_ffi/CHANGELOG.md: merged #17's `### Added` bullets into ours.
- sdk/src/store.rs `save_to_bmff_fragmented` (d4500537 preflight, f5734ff7 output-resolves-to-source rejection) and sdk/src/builder.rs: auto-merged; result matches #17 exactly in these functions; our fragmented DA exact-layout equality check retained.

### 6. feat/single-file-presentation-signing-upstream @8334583a (#19)
Its base already contains #2715/#18/#16 (merged above); only the ladder commits are new.
- sdk/src/store.rs (adjacent additions after `save_to_bmff_fragmented`): kept both — our `requires_embedded_manifest_layout_match` (DA exact-reservation layout invariant) and #19's `save_to_bmff_ladder`. The ladder path reserves DA placeholders with our exact `add_dynamic_assertion_placeholders` and fills them via `write_dynamic_assertions`, then enforces equal unsigned/final JUMBF length — consistent with the fork's exact-reservation semantics.
- CHANGELOG.md: kept ours (#19 adds no new bullets; its three Fixed bullets were already present from #2715/#16/#18).
- c2pa_c_ffi/src/c_api.rs `c2pa_builder_sign_ladder` (auto-merged, follow-up edit in the merge commit): pass `&*signer` instead of `signer.signer.as_ref()` so FFI dynamic assertions apply, consistent with the fork's other FFI signing entry points (`c2pa_builder_sign`, `c2pa_builder_sign_fragmented`, `c2pa_builder_sign_data_hashed_embeddable`).

### 7. ci/codecov-upstream-only @912c9fe4 (#20)
Not an ancestor (the same change arrived as different commits via #16/#17/#18/#19), content already present: the merge is tree-neutral and only records ancestry of 912c9fe4.

## Post-merge reconciliation and verification

- Upstream #2559 replaced raw C pointer handles with checked-out opaque handles.
  The fork's dynamic-assertion and fragmented-reader FFI tests now check out
  the handles and release each guard before calling `c2pa_free`. This changes
  tests, not the signing or ownership contract.
- `m4s` now resolves to `video/iso.segment` under #17. The Context MIME test
  asserts that spelling; `mp4` and `cmfv` still resolve to `video/mp4`.
- The synchronous remote CAWG signer test runs signing on a scoped plain thread:
  the fork's blocking reqwest feature set cannot drop its runtime from inside
  the test's Tokio executor. The signing assertion itself is unchanged.
- The CLI and FFI build, SDK/FFI/C2PATool test runs, and qualification
  scripts use the tracked refreshed Cargo.lock. Rust 1.96.0 final gates:
  SDK library 1438 passed / 17 ignored; BMFF timed-media 26 passed; FFI 204
  passed / 25 example doctests ignored; c2patool 25 unit + 38 integration
  passed; qualification support 22 passed; generated C11 header/prototypes,
  trusted capability mask 63, and formatting passed. The debug library SHA-256
  is `dc79e81a084fc7b25e12423539b137f24d69693da46cb0166cb04538bd5589f9`.
- The seven candidate merges were independently reviewed and published as
  `feat/trusted-vsi-functional` @`5c186c07`; Castlabs live-video qualification
  run 36659887610 passed on Linux and Windows.

## ContentAuth main @69907b5a

True merge (`--no-ff`) of `contentauth/c2pa-rs` `main` @`69907b5a` into
`5c186c07`. Merge base `d589cf7e`; seven upstream commits: #2713, #2695, #2688,
#2658, #2686, #2702, #2746. Upstream changed no Cargo manifest, `Cargo.lock`,
`c2pa_c_ffi` source or header, so the FFI exports, workspace version
`0.92.0-dev`, MSRV 1.96.0 and `c2pa_cbor` 0.78.0 are unchanged.

- sdk/src/claim.rs (only conflict, comment-only): the fork already carried the
  #2746 serialization change; kept the fork's explanatory comment above the
  identical `spec_version` code. Upstream's round-trip tests merge alongside the
  fork's duplicate-CGI-version test.
- #2702 (auto-merged, sdk/src/assertions/bmff_hash.rs): sequential Merkle proof
  locations are now required on the single-file fragmented, timed-media and
  mdat verification paths. The fork's single-file and ladder producers emit
  `location = 0..n` in physical order, Merkle id normalization and tfra/moof
  offset adjustment do not change locations, and per-segment/live-VSI
  verification (`verify_stream_segment(s)`) is not affected.
- #2688 (auto-merged, sdk/src/crypto/cose/ocsp.rs): live OCSP responder
  certificates are checked with `CertificateTrustPolicy::check_certificate_trust`.
  In this fork that entry point is scoped to `TrustListKind::Manifest` (trust
  anchor purpose isolation), whereas upstream checks all anchors. A responder
  that chains only to a TSA or CAWG anchor is therefore not trusted here. This
  is intended: OCSP responders vouch for manifest signing certificates.
- #2686 / #2713 (auto-merged, validation_results.rs, signer_payload.rs):
  unreferenced claims are ignored when reconciling statuses, and CAWG signer
  payload mismatches are logged through the status tracker
  (`cawg.identity.assertion.mismatch`) rather than returned early, except under
  stop-on-first-error.

