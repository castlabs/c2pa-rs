# Castlabs c2pa-rs Agent Guidance

This fork includes both experimental C2PA spec section 19 live-video support
and a Castlabs-specific trusted-processor signing protocol. Do not treat every
change in `sdk/src/live_video/` or `c2pa_c_ffi/src/live_video.rs` as a candidate
for ContentAuth. Classify the *hunk*, not just its file, before extracting it.

## Keep Castlabs-Only

- The **prehashed trusted-processor protocol**: `TrustedVsiSession`, canonical
  hash/template input from a processor, reserved/finalized fixed-size init UUID
  and signer-composed EMSG boxes, expert signing of caller-supplied exact COSE
  `Sig_structure` bytes, and the corresponding trusted C ABI and capability
  mask. Do not propose these APIs as extensions of ContentAuth #2631.
- Expert mode's responsibility split: the processor supplies the media
  `sequenceNumber`, binds it to `moof/mfhd`, and owns ordering, EMSG creation,
  content hashing and publication. The native expert operation returns only a
  verified raw signature. It has no expert media counter or operation journal.
  Composed reserve accepts the supplied sequence and allocates an event ID;
  its reserve/finalize protocol remains Castlabs-only too.
- Trusted session preflight and versioned state export/import, which require
  external authenticated coordinator storage. Native state alone is not a
  retry/authorization journal. Keystore leases, operation-ID/input binding,
  HTTP routes and single-host journals belong to the Castlabs signer/keystore
  repositories; they are not SDK or C-FFI upstream APIs.
- Fork-only ledger, IPFS, watermark, fingerprint and deployment assumptions.
  Do not describe them as C2PA specification requirements.

## Consider Upstream Separately

- Build on ContentAuth [#2631](https://github.com/contentauth/c2pa-rs/pull/2631),
  which supplies experimental section 19.3/19.4 complete-buffer signing and
  validation behind `unstable_live_video`. Potential small follow-ons are
  verifier ambiguity/key/timing/track checks, callback-backed non-exportable
  Ed25519/ES256 **complete-buffer** signing, explicit signing time, recovery,
  the independent `moof/mfhd` sequence-number probe, and a feature-gated
  complete-buffer C ABI. Complete-buffer artifact recovery is distinct from
  trusted-session state import/export. Python `LiveVideoVsiSession` can follow
  a settled C ABI; Python `TrustedVsiSession` cannot.
- A reusable canonical-CBOR/hash helper is a candidate only if the upstream
  complete-buffer signer or validator independently needs it. Do not upstream
  helpers solely to enable the prehashed reservation/expert protocol.
- Trust-purpose isolation, credential-holder `sig_type` and assertion-capacity
  fixes, generic Python native-handle ownership, fragmented BMFF signing and
  ladder writing are separate upstream tracks, not hidden dependencies in a
  VSI PR. Preserve their independent review histories and breaking contracts.
- Section 19.4.1 describes +1 generation, with MFHD equality or the REaP
  indexing alternative. Receiver validation requires strictly increasing
  numbers, not necessarily consecutive observations: specs-core
  [#2521](https://github.com/c2pa-org/specs-core/pull/2521) adds this rule for VSI
  in section 19.7.3, with `livevideo.segment.invalid` for equality/regression.
  This fork reports unobserved ranges as vendor **informational**, never fatal,
  `com.castlabs.livevideo.segment.gap` / `.leadingGap`; a leading comparison is
  literal against the key minimum, including 0 -> 1. Do not imply that a signed
  key minimum proves those segments were produced or maliciously removed.
  Manifest-box predecessor mismatch still fails, but otherwise-validated
  metadata becomes the next comparison baseline so later segments can recover.
  Explicit playback discontinuities preserve coverage history. See
  `docs/live-video-sequence-coverage.md` and the unresolved omission concern in
  specs-core [#1025](https://github.com/c2pa-org/specs-core/issues/1025). Published
  proposals are [#2558](https://github.com/c2pa-org/specs-core/issues/2558) (track
  scope), [#2559](https://github.com/c2pa-org/specs-core/issues/2559) (chunked CMAF
  numbering), [#2560](https://github.com/c2pa-org/specs-core/issues/2560) (signed
  discontinuities), and [#2561](https://github.com/c2pa-org/specs-core/issues/2561)
  (omission reporting). Keep vendor codes until upstream decides. The specs-core
  session owns replies; no further upstream action is authorized. Do not claim
  full alignment: legacy init validation still resets the comparison baseline;
  opt-in `update_vsi_context` preserves VSI continuity atomically. Signed restarts
  and join/seek status reporting are not
  implemented. See the coverage document for reconciliation details. Do not
  require one session key for the whole stream without resolving #2631's
  separate reviewer questions.
- The operator-selected proposal in specs-core
  [#2563](https://github.com/c2pa-org/specs-core/issues/2563) starts the produced
  media chain by omitting `previousManifestId`; init is not a chain member.
  This supersedes the init-rooted design direction, not the current code.
  Read `docs/roadmap/live-video-continuity-reconciliation.md` before implementing
  update/reset/bootstrap changes. The narrowed VSI update replaces one current
  context, preserves sequence/replay/coverage, and supports multiple keys in that
  manifest; historical overlap/cache is deferred. Caller Reader trust and init
  hard-binding verification remain mandatory. Breaking changes are fine; no
  migration machinery is required. Manifest-box #21/#23 and signing/reset
  reconciliation are separate held work; retain vendor codes and distinguish proposals from
  adopted standards. Implementation is tracked in mstattma/c2pa-rs#24.

## Extraction Checklist

1. Ask whether a change remains useful to an independent, ordinary section
   19 complete-buffer signer or validator without processor-supplied prehashes,
   fixed-layout reserve/finalize or a Castlabs coordinator. If not, keep it in
   the fork. Split mixed source files into narrow, reviewable upstream hunks.
2. Keep the feature-off build unchanged. For upstream candidates, test both
   crypto backends, malformed/adversarial segments, current MSRV, Wasm where
   relevant, and generated C-header ABI if C-FFI changes. Do not claim that
   fork-stack qualification proves an extracted patch works independently.
3. Stage reviewable proposals on `mstattma` only after checking #2631's current
   head and open design comments. Never rebase, retarget, or force-push the
   other session's stable ladder branches. Do not submit to ContentAuth or
   publish a release without separate operator approval.

Current fork contracts are in `docs/trusted-vsi-native-contract.md`; merge
decisions and historical qualification are in
`docs/archive/vsi-consolidation-merges.md`. Neither changes this boundary.
