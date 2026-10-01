# Live Video Sequence Coverage

Experimental fork extension behind `unstable_live_video`. Segment validity and
observed coverage are separate: authentic received segments do not prove that
the complete stream was received or presented.

## Specification Boundary

[specs-core#2521](https://github.com/c2pa-org/specs-core/pull/2521) requires VSI
sequence numbers to be strictly greater than the preceding observation, failing
equality/regression with `livevideo.segment.invalid`. It does not define a gap
warning. Section 19.7.2 also requires strictly greater numbers for the per-segment
manifest method, with `livevideo.assertion.invalid` for equality/regression;
#2521 applies specifically to VSI. The omission concern raised in
[#1025](https://github.com/c2pa-org/specs-core/issues/1025) therefore remains
relevant even when every received signature and hash validates. The separate
specs-core session owns proposing an upstream resolution, obtaining publication
approval, and handling replies. Add the resulting issue URL here once published
and reconcile this extension with the upstream decision; neither code below is
a standard C2PA status.

## Report-Only Gaps

- `com.castlabs.livevideo.segment.gap`: an unobserved inclusive sequence range
  between two otherwise-authenticated segment observations.
- `com.castlabs.livevideo.segment.leadingGap`: the first authenticated VSI
  segment is above the matching session key's `minSequenceNumber`. Report the
  range literally, including minimum 0 / first segment 1.

Both are `LogKind::Informational`. They do not change a segment's signature/hash
verdict. Descriptions include the expected and received numbers and explicitly
avoid claiming production or malicious removal. A key minimum is an eligibility
bound, not a commitment that every eligible sequence number was used.
Legitimate live joining, seeking, delivery loss and catch-up may also leave
unobserved ranges. A player must present coverage separately from authenticity.

The per-segment manifest method still fails a `previousManifestId` mismatch
with `livevideo.segment.invalid`. If all other checks pass, the authenticated
metadata becomes the new comparison baseline; the failed segment and its gap
remain reported, but later segments can recover. Missing/unsupported continuity
metadata, non-increasing sequence, stream mismatch, or other failures do not
advance that baseline. `validate_media_segment` requires the caller to validate
the manifest's signature, trust, assertions and hard binding before calling it.
Stop-on-first-error still returns the chain-break error even when recovery state
has been recorded for a later call.

This baseline recovery is a fork policy, not a new requirement from #2521.
It has an availability trade-off: an authentic later segment delivered early
can advance the baseline and cause genuine earlier media delivered afterward
to fail ordering until the stream catches up or trusted playback control
explicitly resets the observation interval. A manifest chain break remains a
failure, so recovery does not hide that signal. Strict-increase VSI validation
has the same ordering effect even without a manifest predecessor chain.

## Coverage And Playback Control

`LiveVideoValidator::sequence_coverage()` returns `SequenceCoverage`:

- `missing_ranges`: the first 1024 inclusive unobserved ranges.
- `total_missing`: their full accumulated count, including ranges beyond that
  limit; arithmetic saturates only at `u128::MAX`.
- `ranges_truncated`: some range detail was omitted at the retention limit.

`reset_continuity()` starts a caller-requested observation interval, such as a
seek. It clears the predecessor and per-interval EMSG replay-ID set and suppresses
the leading-gap/init-predecessor comparison until the next otherwise-validated
observation; failed attempts do not consume the suppression. Required predecessor
metadata must still be present. It retains trusted keys,
key minima, manifest/track checks, signature/hash validation and prior coverage.
Only trusted playback control may call it, never a stream-supplied reset flag.
Duplicate/reversed sequences and repeated EMSG IDs still fail within each new
interval. Repeated traversals count as separate observations; the totals are
not a deduplicated inventory of content missing from the full presentation.

Coverage history also survives `validate_init_segment`, but that method still
resets predecessor/key/replay state as before. Continuity across repeated init
segments or key rotation is unresolved and is not claimed by these reports.
Range retention is bounded; callers must also manage their `StatusTracker`
lifetime because its informational log history is not capped by this API.

## c2patool

`c2patool <init> live-video --segments_glob <glob>` prints a
`Coverage gaps (informational)` block only when gaps are observed, listing
retained ranges, total count and truncation. Gaps alone do not change its exit
status. Real failures, including a manifest predecessor mismatch, still fail
the command. Gap-free output is unchanged for evidence-pinned consumers.

Absence of gap entries does not establish an authenticated ending or complete
presentation. True live streams have an advancing live edge; JIT-packaged VOD
needs a separate authenticated expected endpoint to detect tail truncation.

## Local Verification

Rust 1.96.0, `CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`; no hosted qualification
or downstream repin is implied by these local results:

- Feature-enabled live-video SDK tests: 133 passed with Rust-native crypto;
  121 passed with OpenSSL (ES256-specific fixtures are native-feature gated).
- Feature-enabled c2patool: 30 unit and 38 integration tests passed, including
  trusted three-segment signing/validation, omission of the middle segment,
  and rejection of a tampered surviving segment.
- Warnings-denied Clippy passed for the feature-enabled SDK library and all
  c2patool targets. SDK test-target Clippy remains blocked by 15 pre-existing
  test-only panic/expect/type-complexity/bool-assert lints outside this change.
  No lint policy was relaxed to hide them.
- A process-level smoke against the retained signed conformance corpus
  confirmed unchanged gap-free output, a visible leading range `1..=1` when
  selecting only segment 2, and exit status 0 for that informational-only gap.
- The independent CLI signing smoke exposed the existing signing bridge's
  thread-local trust-settings mismatch (`signingCredential.untrusted` with
  explicit CLI test-root settings). The signed-corpus validation smoke and
  the trusted unit test avoid that unrelated limitation; signing code is not
  changed here.

Feature-enabled rustdoc passed with warnings denied for the new API. Two existing
signing-method links were qualified with `Self::`, and one equivalent CBOR-key `match` was
changed to `matches!` to unblock library Clippy; neither changes signing policy.
