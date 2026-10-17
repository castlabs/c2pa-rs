# Upstream Fix Extraction From the Trusted-VSI Merge

Date: 2026-09-28. Source: merge commit `e0f980ec` on `feat/trusted-vsi-functional`,
isolated with `git show --remerge-diff e0f980ec`. Evidence for the original fixes
is in `docs/archive/trusted-vsi-upstream-integration.md`.

All branches are **local only**. Nothing has been pushed to `staging`
(mstattma/c2pa-rs), and nothing was opened or pushed on contentauth/c2pa-rs.
They are waiting for coordinator review.

## Branches

| # | Branch | Base | Local commit(s) | Worktree |
|---|---|---|---|---|
| 1 | `fix/trust-anchor-purpose-isolation-upstream` | `integration/upstream-base-d589cf7e` (`d589cf7e`) | `8c1953c6` fix: Scope trust anchors to their verification purpose (amended from `02c10704` after review) | `~/opencode-worktrees/c2pa-rs-trust-purpose-upstream` |
| 2 | `fix/credential-holder-sig-type-ownership-upstream` | `d589cf7e` | `c96f6363` fix!: Return a borrowed sig_type from credential holders | `~/opencode-worktrees/c2pa-rs-sig-type-upstream` |
| 3 | `fix/credential-holder-capacity-upstream` | stacked on #2 (`c96f6363`) | `5441a8b3` fix!: Reserve complete identity assertions for credential callbacks | `~/opencode-worktrees/c2pa-rs-capacity-upstream` |
| 4 | `feat/fragmented-signing-ffi-upstream` (existing, staging PR #17) | `staging/feat/fragmented-signing-ffi-upstream` (`50a435ed`) | `3b068790` fix(ffi): Read back fragmented manifests through the builder Context (on top of `50a435ed`) | `/root/opencode-worktrees/c2pa-rs-fragmented-ffi-upstream` |

Author and committer for every commit: `Michael Stattmann <mstattma@users.noreply.github.com>`
(taken from the existing repository config; git config was not changed).
Each new branch has no upstream tracking configured, so a bare `git push`
cannot target the wrong remote branch.

## Decisions

### 1. Trust-anchor purpose isolation (`fix:`)

- Ported: purpose filter in both `certificate_trust/{openssl,rust_native}.rs`;
  `check_certificate_trust_for` and `add_end_entity_credentials_for` in
  `certificate_trust_policy.rs`; `verify_signature_for` in `verifier.rs`; TSA
  purpose in `time_stamp/verify.rs`; CAWG purpose in
  `identity_assertion/assertion.rs` and `x509_signature_verifier.rs`; Store
  allow-list scoping (the crate-private `Store::add_trust_allowed_list` was
  removed, as in `e0f980ec`). Only these hunks of `store.rs` were taken, plus the
  `manifest_trust_purpose_and_reporting_are_isolated` test. The DA-loop and
  ZIP-layout hunks were not.
- Tests ported: `trust_purpose_isolation_sync_and_async`,
  `private_credentials_are_purpose_scoped_and_never_authorize_tsa`,
  `timestamp_trust_requires_tsa_purpose`,
  `cawg_trust_purpose_isolation_preserves_signature_validity`,
  `manifest_trust_purpose_and_reporting_are_isolated`; the adjusted
  `continue_when_possible.rs` tests and the `create_signer.rs` trust hunk.
- Why those tests were adjusted: in test builds, `CertificateTrustPolicy::default()`
  registers the test root bundle as **Manifest** anchors under
  `https://c2pa-rs/unknown_tl`. The malformed-assertion tests assert
  `cawg.x509.credential.trusted` with that URI, and
  `from_x509_identity_signs_and_validates` asserts `Trusted`. Both passed only
  because of the leak. They now declare the same roots as CAWG anchors, and
  their assertions are unchanged. No other upstream library test depended on
  the leak.
- New relative to `e0f980ec` (needed because the base moved):
  - `d589cf7e` added OCSP responder checks through `check_certificate_trust`.
    Those are only reached for manifest claim signatures (`store.rs`,
    `claim.rs`), so manifest-only is the correct purpose. The commit body says
    so.
  - Docs now state the manifest-only semantics on `check_certificate_trust`
    and `add_end_entity_credentials`, and the purpose scoping on
    `TrustAnchor::allowed_list`.
  - Clippy `unwrap_used` allow on the new `time_stamp/verify.rs` test module.
- The commit body notes the public API semantics change:
  `check_certificate_trust`, `verify_signature` and `add_end_entity_credentials`
  are now manifest-only.
- Review follow-up (P2, amended into `8c1953c6`): the manifest-only
  `add_end_entity_credentials` combined with a crate-private
  `add_end_entity_credentials_for` meant external code building
  `X509SignatureVerifier { cose_verifier: Verifier::VerifyTrustPolicy(..) }`
  could no longer allow-list CAWG leaf certificates. Now public:
  `CertificateTrustPolicy::add_end_entity_credentials_for(pems, TrustListKind)`
  and `check_certificate_trust_for[_async](chain, cert, time, TrustListKind)`
  (the same regression applied to `check_certificate_trust` callers checking
  CAWG/TSA certificates). `TrustListKind` was already public as
  `c2pa::settings::TrustListKind`. `verify_signature_for` stays crate-private
  because `X509SignatureVerifier` is the public CAWG path. Docs say TSA private
  credentials are never trusted. The commit body has a migration note.
  New integration test `sdk/tests/integration.rs::cawg_private_credentials::cawg_leaf_can_be_allow_listed_with_public_api`
  uses only public APIs (`X509CredentialHolder` to sign, `X509SignatureVerifier`
  to verify). It checks that the leaf is trusted only for CAWG and is untrusted
  for the legacy API, Manifest and TSA. Against the old code it does not compile,
  because the method was private.

### 2. Borrowed `sig_type` (`fix!:`)

- Ported: `sig_type(&self) -> &str` on both traits, `ArcCredentialHolder`,
  `create_signer.rs` test impls, C API `CallbackCredentialHolder` owning a
  `String`, and removal of `Box::leak`.
- The owned-`sig_type` half of the FFI test is a standalone test,
  `test_credential_holder_owns_sig_type_after_caller_frees_it`. It uses its own
  callback so it does not race on the shared `HOLDER_CALLS` static.
  `RecordingCredentialHolder` now owns a `String` to exercise the Rust side.
- Known limit: the owned-`sig_type` C test frees the caller's string before
  signing, so it catches a borrowed or dangling pointer. It cannot detect
  the old per-call `Box::leak`, which also passes. Leak freedom follows from
  the `String` field; no allocation-counting test was added.
- Adapted to upstream `aab387ed` opaque handles: tests read through
  `&mut *dest.stream_mut()`.

### 3. Credential-holder capacity (`fix!:`, stacked on #2)

- Ported: `signature_capacity`, `max_byte_string_payload`, exact-fill checked
  padding with fallible allocation, the `isize` guards, reservation docs, C API
  capacity from the actual payload, the `reserve_size` ISIZE_MAX guard and
  docs, the boundary test, and the capacity FFI test.
- Conflict with upstream #2697 (already in `d589cf7e`): #2697 required
  `reserve_size >= unpadded + 15`, and its `rejects_reserve_size_that_is_too_small`
  test expected `unpadded` and `unpadded + 14` to be rejected. The 15-byte floor
  came from the fixed `-15`/`-6` padding arithmetic, not from CBOR or the CAWG
  spec. With measured padding those sizes fill exactly. The test now rejects
  `0`, `1`, `unpadded - 1` and `usize::MAX`, and asserts that `unpadded`,
  `+1` and `+14` fill exactly. #2697's checked, non-panicking error path is
  kept, including the "Padded assertion is N bytes" error text.
- Dropped as fork-only: `Box::new(c2pa_signer)` (upstream keeps
  `Box::new(c2pa_signer.signer)`), the `dynamic_assertions: Vec::new()` field,
  and the `c2pa_signer_add_dynamic_assertion` / `DynamicCallbackState` test
  lines and inner-DA chaining assertions.
- Contract change: `c2pa_identity_signer_create_with_credential_holder`
  shipped in **c2pa-c-ffi v0.91.0** (#2603, tag `c2pa-c-ffi-v0.91.0`).
  `reserve_size` now reserves the complete encoded assertion, and the callback
  receives a smaller `signed_len`. That is why the commit uses `fix!:` with a
  BREAKING CHANGE footer.

### 4. Fragmented FFI read-back via the builder Context

- Optional review gap, not addressed: there is no FFI-level custom-handler
  read-back test, because the C API has no way to register a custom asset
  handler on a builder Context. The seam is covered by the SDK
  custom-handler test.
- The existing worktree was **clean** at `50a435ed` (== `staging/feat/fragmented-signing-ffi-upstream`)
  when inspected, with no modified files and no stash, so the follow-up was
  made there. No work was discarded.
- Ported: public `Context::read_embedded_manifest_from_file` (file_io),
  delegating to the private `HandlerRegistry::read_c2pa_from_file`; FFI
  `c2pa_builder_sign_fragmented` reads back through `builder.context()`; the
  custom-handler assertion in `test_custom_io_handler_overrides_builtin`.
- Also removed: the now-obsolete `#[cfg_attr(not(test), allow(dead_code))]` on
  `read_c2pa_from_file`. The registry and registration APIs stay private.

### Superseded: fix C (claim spec-version serialization)

The `claim.rs` spec-version hunk and test in `e0f980ec` were **not** extracted.
They are superseded by the open upstream PR contentauth/c2pa-rs#2731 ("fix: Don't
write claim_generator_info specVersion as a claim field") and by the existing
staging branch `fix/claim-specversion-serialization-upstream` (`da505a7f`,
`f5558614`).

### Other `e0f980ec` hunks not extracted

These are fork or trusted-VSI specific, or were merge resolutions:
`session_keys.rs`, `bmff_io.rs`, the `store.rs` DA replacement loop and
ZIP/embedded-layout guard, `claim.rs` `replace_assertion_instance` naming,
`live_video/*`, `sdk/Cargo.toml`, `sdk/tests/integration.rs`, and the C API
dynamic-assertion callbacks / `sign_data_hashed_embeddable` resolution.

## Verification

Linux x86_64, debug builds, Rust **1.96.1** (upstream MSRV 1.96.0),
`CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=2`. One
`CARGO_TARGET_DIR` was shared across all four worktrees:
`/root/opencode-worktrees/c2pa-rs-fragmented-ffi-upstream/target`.
Formatting was checked with `cargo +nightly-2026-01-16 fmt --all -- --check`,
the only installed nightly.

- OpenSSL features: default + `file_io,fetch_remote_manifests,add_thumbnails`
  (the Makefile `FEATURES`).
- Rust-native features: `--no-default-features --features
  rust_native_crypto,file_io,fetch_remote_manifests,add_thumbnails,default_http`.
- FFI: `-p c2pa-c-ffi --features file_io` (default OpenSSL).
- Clippy: `--all-targets -- -D warnings`.
- Docs: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`.

| Branch | SDK tests (OpenSSL) | SDK tests (Rust-native) | FFI tests | Clippy | Docs | fmt |
|---|---|---|---|---|---|---|
| 1 trust purpose (`8c1953c6`) | full lib: 1195 passed, 15 ignored; integration `cawg_private_credentials`: 1 passed | same: 1195 passed, 15 ignored; 1 passed | n/a (SDK only) | `-p c2pa`, both backends: pass | `-p c2pa`: pass | pass |
| 2 sig_type | `identity create_signer settings::signer`: 104 passed, 1 ignored | same filter: 103 passed, 1 ignored | 172 passed | `-p c2pa -p c2pa-c-ffi`: pass | pass | pass |
| 3 capacity (on #2) | `identity create_signer settings::signer dynamic_assertion`: 108 passed, 1 ignored | same filter: 108 passed, 1 ignored | 173 passed | `-p c2pa -p c2pa-c-ffi`: pass | pass | pass |
| 4 fragmented FFI | `context:: asset_io`: 49 passed | same filter: 49 passed | 180 passed (incl. all 9 `fragmented::*`) | `-p c2pa -p c2pa-c-ffi`: pass | pass | pass |

Disk cleanup: every build artifact created in the shared target during this
work was deleted afterward (about 5.5 GB). The new worktrees have no
`target/` of their own, and incremental compilation was disabled.

Not run: SDK integration tests and doctests, the CLI, and WASM/WASI. On
branches 2 and 3 the full SDK library suite was not repeated; only the
filtered selections above ran. Pre-fix failure of the new tests was not
re-demonstrated on `d589cf7e`; the original evidence is in the
trusted-VSI integration archive.

## Fork port of the review follow-up (uncommitted)

The fork worktree had the same limitation: both `*_for` methods were crate-private
in the merged `certificate_trust_policy.rs`. The same public API, docs and
integration test were applied **uncommitted** to
`/root/opencode-worktrees/c2pa-rs-trusted-vsi-functional`, in
`sdk/src/crypto/cose/certificate_trust_policy.rs` and `sdk/tests/integration.rs`.

Verification used Rust 1.88.0 (fork MSRV) with the fork's own `target/`,
`CARGO_BUILD_JOBS=1`, and the SDK/FFI feature sets recorded in
`trusted-vsi-upstream-integration.md`:

- Focused SDK trust/identity/signer selection (`certificate_trust`,
  `time_stamp::verify`, `x509_signature_verifier`, `continue_when_possible`,
  `manifest_trust_purpose`, `create_signer`, `identity_assertion`): 53 passed.
  This includes all five purpose-isolation tests.
- Integration `cawg_private_credentials`: 1 passed.
- Complete FFI library suite: 155 passed.
- Rebuilt debug FFI library:
  - `target/debug/libc2pa_c.so` sha256 `d7eed14670e9778854222b4488d8340da0239c58288b298bfea879154b3102d6`
  - `target/debug/c2pa.h` sha256 `5622cb90ef3cd79ae0e3804a8be88d4ead401847e4441596ef3a441146c7a06b`

  These differ from the integration-checkpoint hashes because the fork HEAD
  moved on to `1d605b5a`. This change touches no FFI source.
- The fork's `target/debug/incremental` was removed afterwards.
