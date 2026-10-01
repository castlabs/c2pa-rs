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
- Section 19.4.1 describes generated VSI sequence numbers increasing by one
  for each subsequent segment, with MFHD equality or the REaP indexing
  alternative. A verifier may receive only some segments. This fork currently
  marks a non-consecutive received VSI sequence invalid; whether to report a
  missing-segment coverage gap separately instead is a proposed upstream
  policy change, not current behavior. Do not change that validation rule or
  require one session key for the whole stream without resolving section 19.7
  and #2631's reviewer questions first.

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
