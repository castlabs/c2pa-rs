# Trusted VSI Review Verification

Local evidence for uncommitted review fixes on `fix/trusted-vsi-review-native`,
based on `d6e7b529581a4dfc0fd5585773d246ee2c191378`. These results do not authorize
merge, hosted qualification, downstream repinning or release.

## Native Gates

Rust 1.96.0; one Cargo job; incremental compilation and debug information
disabled. SDK feature profile:
`rust_native_crypto,http_reqwest,http_reqwest_blocking,add_thumbnails,file_io,fetch_remote_manifests,pdf,unstable_live_video`.
C FFI profile: `rust_native_crypto,http,add_thumbnails,file_io,unstable_live_video`.

- trusted-VSI SDK tests: **25 passed**;
- SDK live-video tests: **142 passed**;
- C FFI live-video tests: **18 passed**, including 9 focused trusted cases;
- Claim tests: **41 passed, 5 preexisting ignored**;
- qualification support: **22 passed**;
- feature-off C FFI library check: passed;
- SDK/C FFI library Clippy and rustdoc with warnings denied: passed;
- generated header: 28 declarations, exact trusted function types and C11 ABI
  assertions passed;
- pinned nightly formatting and `git diff --check`: passed.

## Full SDK Library Regression

On 2026-10-07, the final compiled SDK library test executable was reused directly
to avoid another build target under disk pressure. Its SHA-256 was
`5f9c4282d423e9127243fb7939ee71c7914891209377ff2b75c8252f51d0d0cb`.
Run from the SDK crate directory, matching Cargo's test working directory:

```bash
cd sdk
/path/to/target/debug/deps/c2pa-cc1e574043dfa0a0 --test-threads=4
```

Result: **1477 passed, 0 failed, 17 ignored**, in 226.83 seconds. The two
FFmpeg-gated decode-equivalence tests remain among the deliberately ignored
tests; this run is not evidence that they ran.

An initial direct-executable invocation used the workspace root instead of the
SDK directory and failed relative fixture lookups. Correcting the runner's
working directory resolved those failures; no SDK code or assertions changed.

## Binding And Reader Evidence

The matching locally built C FFI library reports `0.92.0-dev` and capability
mask 63. SHA-256:
`149f4b250a5d697e38355a3f3f08ce1abf61c7e2b0418175153f690a456eb357`.

The Python review source based on `12d265db` passed 765 non-threaded tests plus
128 subtests (one installed-release smoke module skip), and 54 threaded tests
with this library. The preserved init-epoch probe passed all six cases: both
algorithms in complete-buffer, expert and composed modes, with nonce-salted
init manifests reading as Trusted and no active-manifest failures.

Fresh-context static reviews examined the exact security changes and follow-ups;
no remaining blocking defect was identified. They do not replace the eventual
integrated Linux/Windows qualification.

## Integration Constraints

- State format is now version 3; versions 1/2 are rejected.
- Reservation recovery needs the pinned reservation-producing build/settings.
- Expert input is now typed and session-bound, not arbitrary opaque payload.
- Public C signatures, V1 layouts and capability mask 63 remain unchanged.
- The existing Python CI native pin is intentionally unchanged. Final native
  revision identification, repinning and hosted qualification remain separate.
- No signer/keystore lifecycle, counter-carry API or release was implemented.
