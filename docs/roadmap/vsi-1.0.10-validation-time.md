# VSI Key Lifetime At Validation Time (Signer 1.0.10)

This candidate changes BMFF/CMAF VSI validation: a session key's validity period
is checked against **the time
at which the segment is validated**. A segment validated before `createdAt` or after
`createdAt + validityPeriod` (both bounds inclusive) fails with
`livevideo.segment.invalid`. The protected `iat` is an optional signer claim and
does not select or relax the clock. This is an integration plan for the next signer
release identity (1.0.10), not release approval or evidence that it has passed.

## Native Scope

Branch `fix/vsi-validation-time-lifetime`, based on `feat/trusted-vsi-functional`
(`6021100c`), changes only `sdk/src/live_video/` plus docs:

- `LiveVideoValidator` reads the current time (the SDK's WASM-safe clock) for the
  lifetime check; a `#[cfg(test)]` setter injects a validation time so tests do not
  depend on the host clock. No public Rust, C or WASM API changes.
- A malformed protected `iat` (duplicate, non-integer, out of range) still fails the
  segment; its value is discarded for the lifetime check.
- The signer is unchanged: it still emits `iat` and refuses to sign when the signing
  time is outside the key window (a sender-side rule), and artifact recovery still
  validates the sender's own published artifact.
- Time bombs from the former historical-`iat` behavior (keys created 2020-01-01 with a
  1e9 s validity) are removed from the recovery and trusted-VSI tests by injecting a
  validation time.

Behavior change: validating live media after its key expired now fails. A historical
`iat` is not an expiry override. `c2patool live-video-sign` fixes `validityPeriod` at
3600 s, so CLI-signed
streams stop validating an hour after signing.

## Qualification

Use the same CI gates as the 1.0.8 plan (`docs/roadmap/vsi-1.0.8-integration.md`):
`.github/workflows/vsi-update-validation.yml` and
`.github/workflows/castlabs-live-video-qualification.yml` on the exact candidate SHA,
merged with a true merge commit (no rebase or force-push). This repository carries no
signer-version string: the `+signer.1.0.10` identities of `c2pa-python`, the signer and
`c2patool` bundles are produced downstream from the qualified native SHA. Do not change
the published 1.0.9 identities.
