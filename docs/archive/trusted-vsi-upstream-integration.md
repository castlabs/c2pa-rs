# Trusted VSI Upstream Integration Checkpoint

Date: 2026-09-10. Stage: **integration**. Trusted capability mask: **0**.
This is the disabled upstream-integration checkpoint, not functional trusted VSI
implementation or release qualification. Review and a separate integration
commit are required before expert/init/composed implementation begins.

## Source

- Fork base: `cee86aae03887b5a0dddcd765a39e96360963bb0`.
- Exact ContentAuth merge target: `312491af0e3e9fb5b3ba604d86ef44194ab580d9`.
- Branch: `feat/trusted-vsi-functional`.
- Worktree: `/root/opencode-worktrees/c2pa-rs-trusted-vsi-functional`.
- Integrated using `git merge --no-commit --no-ff`; no commit or push performed
  during implementation or review follow-up. Artifacts describe the merged
  working source, not the unchanged HEAD alone.

## Preserved Behavior

The fork's DA loop remains authoritative: actual stored reservation sizes,
distinct static/dynamic same-label slots, own-placeholder exclusion, refreshed
PartialClaim hashes after each callback, and wrong-size/Binary rejection.
Upstream's weaker deferred replacement loop was not adopted. Instance replacement
uses one helper name, `replace_assertion_instance`.

C callbacks survive Context transfer and the upstream credential-holder wrapper.
Complete-buffer live-video and fragmented APIs remain available. The trusted SDK
scaffold and full live-video FFI module remain unchanged from the fork base;
the actual shared-library trusted capability query returns zero.

## Review Corrections

1. Session-key serialization accepts either the internal raw COSE array or one
   caller-supplied tag-18 wrapper, and emits exactly one tag. Nested/wrong outer
   tags and invalid COSE field shapes are rejected on serialization. Regressions
   cover pretagged input, invalid shapes, date-time tag 0, and raw-array round trips.
2. The spec-version round-trip test clears restored cached claim bytes before
   comparing re-serialized data. The integration fix therefore exercises the
   serializer rather than only its original-byte cache.
3. ZIP-family containers use the operation's Context classification for the
   embedded-layout guard, accounting for the placeholder central-directory hash.
   Tests cover registered ZIP aliases, collection-only and detached claims, and
   ZIP signing with an exact-size DA followed by collection-hash verification.
4. Fragmented FFI readback uses the signing Builder's actual Context. The narrow
   public SDK method `Context::read_embedded_manifest_from_file` delegates to its
   private handler registry without validation, remote fetching, or Reader-based
   re-serialization. A custom-handler regression proves that the registry is
   honored. The private registry and registration APIs were not exposed.

## Qualification

### Trust-Purpose Security Gate

An unchanged native-backed Python regression exposed an upstream authorization
bug: manifest verification searched the shared anchor pool without filtering
`trust_kind`, so CAWG-only or TSA-only roots could produce
`signingCredential.trusted` and `Trusted` for `C.jpg`.

The integration now selects purpose before certificate-chain lookup in BOTH
Rust-native and OpenSSL backends. Existing public manifest verification entry
points remain manifest-only; CAWG X.509 verification (direct and embedded,
sync and async) explicitly requests CAWG trust, and RFC 3161 verification
explicitly requests TSA trust. Matching trust-list URIs are retained. Wrong
purposes produce untrusted statuses while valid cryptographic signatures remain
validated; errors/statuses are not hidden or rewritten by Python.

Typed private credential allow-lists are also purpose-scoped. They authorize
only the matching manifest or CAWG operation, never TSA trust (C2PA 14.4.3).
Legacy trust-field conversion and the existing untyped private-credential API
remain manifest-only. No production roots, EKUs, trust-check defaults, or
revocation-fetch defaults were added or broadened. ICA issuer-DID lookup was
already CAWG-scoped and remains so; existing explicit/legacy timestamp no-check
paths are unchanged.

Regressions cover all three purposes, mixed pools and their returned URIs,
private credential isolation, native manifest status reporting, both CAWG
entry paths, and actual fixture timestamp verification. Tests that deliberately
expect a trusted CAWG fixture now declare that membership explicitly, preserving
their existing assertions. The timestamp test pins the issuing CA from the
fixed `C.jpg` timestamp fixture, rather than adding it to any default store.

Linux `x86_64-unknown-linux-gnu`, debug builds, Rust **1.88.0**,
`CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=2`. All outputs use this new worktree's
`target`; the older qualified native artifact was not overwritten.

SDK features, with defaults disabled:
`rust_native_crypto,http_reqwest,http_reqwest_blocking,add_thumbnails,file_io,fetch_remote_manifests,pdf,unstable_live_video`.

FFI features, with defaults disabled:
`rust_native_crypto,http,add_thumbnails,file_io,unstable_live_video`.

| Trust-gate check (before capacity follow-up below) | Static result |
|---|---|
| Full SDK library regression suite | 1,299 passed; 15 pre-existing ignores |
| Full crypto + identity + signer-construction selection, Rust-native | 179 passed; 1 pre-existing example ignore |
| Same selection, OpenSSL | 179 passed; 1 pre-existing example ignore |
| BMFF timed-media integration | 24 passed |
| Complete FFI test suite, including fragmented APIs | 150 passed; 23 existing C-example doctests ignored |
| Unchanged native-backed Python settings/trust/scaffold tests | 57 passed, 6 subtests passed |
| Build-generated header and C11 ABI compilation | Passed, 24 required declarations |
| Actual ELF callable exports | 24 verified |
| Actual library trusted capability query | 0 |
| Workspace formatting | Passed with installed nightly formatter |

The earlier review gate passed 120 targeted SDK tests and 21 qualification
support tests. The broader pre-review integration baseline passed 1,293 SDK library tests,
103 SDK integration tests, 65 SDK doctests, and 63 CLI tests (CLI defaults retained
with vendored OpenSSL). That baseline had 15 library, 1 integration, and 11 SDK
doctest pre-existing ignores. The trust gate reran the full SDK library and
both crypto backends, but does not claim a repeat of all SDK integration targets,
doctests, CLI tests, or every feature combination.

The Python selection was run without changing Python code or tests:
`tests/test_unit_tests.py::TestSettings`,
`tests/test_unit_tests.py::TestReader::test_stream_read_get_validation_state_with_trust_config`,
and `tests/test_trusted_vsi_api.py`. Pairing used the Python functional worktree's
`src` on `PYTHONPATH`, the absolute library path below in `C2PA_LIBRARY_NAME`,
`C2PA_SOURCE_BUILD_VERSION=0.91.0-dev`, and `C2PA_TRUSTED_VSI_ABI_REQUIRED=1`.

Bare `cargo test` under the reqwest-only profile cannot build the existing
`v2show` example without `http_ureq`; test targets and doctests were qualified
separately instead. Windows/WASM, release builds, and downstream functional
qualification were not performed at this checkpoint. No trusted functional path
was enabled, and no new test ignores were introduced.

### Credential Callback Capacity Gate

Upstream #2603 passed the credential holder's reservation straight through as
the complete DA reservation while documenting it as signature-only capacity.
The identity finalizer then subtracted fixed padding allowances without checked
bounds and asserted its final length. A callback returning an otherwise valid
near-capacity result could therefore trigger an unwind/abort across the C ABI.

The unshipped C API contract is corrected explicitly: `reserve_size` reserves
the COMPLETE encoded identity assertion. The callback's `signed_len` is its
actual signature capacity, computed from the real serialized signer payload,
assertion wrapper, and CBOR length headers. The current DA reservation interface
has no partial claim at reservation time, so a signature-only capacity promise
cannot be implemented exactly without a broader reservation redesign. No magic
headroom allowance or silent signature truncation is used. Rust credential-holder
reservation docs now also match this existing whole-assertion behavior.

Padding uses measured CBOR sizes and checked bounds, with a second padding field
only to bridge byte-string length-header gaps. Exact-fit and all representable
near-fit signatures remain supported. Oversized results return errors rather
than triggering unchecked subtraction or a production assertion. Invalid
address-size reservations are rejected; buffer allocation failures are fallible.
As with the rest of this unsafe C API, host callbacks must honor the offered
buffer capacity; this does not sandbox C writes or impose a new memory quota.

The per-creation `Box::leak` is removed. `sig_type` is owned by the callback holder,
and sync/async `CredentialHolder::sig_type()` returns a borrowed `&str`. Existing
constant-returning implementations remain compatible; delegating wrappers now
return the borrowed lifetime. Rust callers that required a `&'static str` from
the trait must instead retain the holder or own the string. The C ABI and its
copy-at-creation string-lifetime contract are unchanged; no growing cache was added.

| Latest capacity-gate check | Static result |
|---|---|
| Focused SDK identity builders, embeddable signing, signer wrappers and DAs | 25 passed |
| Complete FFI suite | 151 passed; 23 existing C-example doctests ignored |
| Rebuilt generated header / C11 ABI | Passed |
| Required callable exports | 24 verified |
| Actual trusted-VSI capabilities | 0 |
| Formatting / scoped diff checks | Passed |

New tests cover signature and padding CBOR boundaries at 23/24, 255/256 and
65535/65536, all near-fit gaps 0 through 40, exact output lengths and unchanged
signature bytes, undersized/overflow budgets, full offered callback capacity,
an over-reported C callback count, and use after the caller frees its original
`sig_type` string. The whole-hour baseline suites were not repeated for this
localized follow-up; the affected SDK tests and full fast FFI suite were rerun.
All prior DA reservation/hash-refresh and trust-purpose fixes remain intact.

## Rebuilt Artifacts

Paths are relative to the worktree above. The header comes from the actual FFI
build.rs/cbindgen path; C11 qualification uses `-std=c11 -Werror -fsyntax-only`
with the live-video, file-I/O, and dynamic-loading header defines.

| Artifact | SHA-256 |
|---|---|
| `target/debug/libc2pa_c.so` | `d2e5c50ee8343114980bfb29766351b803bef501409494a2229c103ba9236a75` |
| `target/debug/c2pa.h` | `c2afd4b208c50d6c6823b87090d3229c3a9aa2fb533ffad47a1d42596b66bd6f` |

Verbose local runs remain under `target/capacity-*.log`, `target/trust-*.log`
and `target/review-*.log`; this archived record
persists the source bases, stage, results, limitations, and artifact identities
without committing build products or large logs.
