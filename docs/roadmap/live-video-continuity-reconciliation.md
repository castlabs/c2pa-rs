# Live Video Continuity Reconciliation

## Status And Scope

**Narrowed VSI update implemented; other reconciliation remains design only.**
The approved slice is `LiveVideoValidator::update_vsi_context`: atomic replacement
of one current verified init/manifest/key context while retaining VSI sequence,
replay and coverage state. `previousManifestId` is NOT part of VSI. Manifest-box
bootstrap (#21/#23), signing and reset APIs are separate held work, not dependencies
of this slice. Breaking changes are acceptable for this experimental scope; no
migration or backward-compatibility layer is required. Open decisions below still
require approval outside this slice. These proposals are **not adopted C2PA standard requirements**.
Scope is experimental complete-buffer live-video signing/validation; no trusted-
processor protocol changes, hosted qualification, downstream repins or publication.

Specification discussion: [#2558](https://github.com/c2pa-org/specs-core/issues/2558)
addresses track/switching-set scope; [#2559](https://github.com/c2pa-org/specs-core/issues/2559)
addresses chunk signing units; [#2560](https://github.com/c2pa-org/specs-core/issues/2560)
addresses signed restarts (syntax undecided); [#2561](https://github.com/c2pa-org/specs-core/issues/2561)
addresses gaps and continuity across updates.
[#2563](https://github.com/c2pa-org/specs-core/issues/2563) is Michael's approved
proposal: the first **produced** media manifest omits `previousManifestId`; init is
not in the media chain. First received is not necessarily first produced.

The init-rooted policy in [mstattma#21](https://github.com/mstattma/c2pa-rs/issues/21)
and [#23](https://github.com/mstattma/c2pa-rs/pull/23) is superseded as design policy,
not automatically removed from code. [#24](https://github.com/mstattma/c2pa-rs/issues/24)
tracks implementation; [#22](https://github.com/mstattma/c2pa-rs/pull/22) remains an
independent VSI status-code fix. The init-rooted policy introduced in `d33d869a`
and gap-reporting branch snapshot `d2a2ffd9` both differ from the proposed unified
behavior; neither should be treated as its finished implementation.

## Current Code And Gaps

- `sdk/src/live_video/mod.rs`: `validate_init_segment` clears predecessor, keys,
  manifest association, track/timing and replay state before validating input.
  Coverage survives, but update continuity and rollback safety do not. It also
  clears the suppression set by an explicit playback reset.
- `validate_session_keys` clears installed keys first; aggregate error handling
  can install a verified subset after signer-binding failures. It is not an
  atomic update, and `Ok(())` alone does not imply validation success.
- `update_vsi_context` instead stages those existing checks on an isolated
  candidate, rejects any newly recorded failure in either tracker mode, and
  commits only the complete context. `Ok(())` guarantees installation. It requires
  an initialized, non-manifest-box track context. Optional init must match the
  current track ID, timescale and optional default sample duration exactly; `None`
  retains them. Multiple keys in the installed manifest remain supported. No
  historical manifest/key cache is installed. See the current
  [API contract and trust boundary](../live-video-sequence-coverage.md#atomic-vsi-updates).
- `reset_continuity` retains keys, init track and coverage but clears
  `previous_segment`, including the manifest-method `streamId` baseline. Its
  documentation must not be read as preserving that identity check today.
- `session_key_validation.rs` resolves a key by `kid`, then checks one global
  `expected_manifest_id`. It cannot represent overlapping manifest/key contexts.
- `signing.rs` sets the init manifest as predecessor on sign/restore and requires
  it before signing media. `register_manifest_box_init` mirrors that old policy.
  Gap-branch mismatch recovery already advances otherwise-valid metadata only.
  c2patool registers its verified init as predecessor; signer init restoration
  likewise installs that label. Both consumers need reconciliation, not just
  the comparison helper.

## Proposed State Separation

Keep three responsibilities distinct, without requiring three public types:

1. **Trusted material:** validated init layout/timing, trusted manifest identity,
   verified session keys and their issuing-manifest association. A candidate must
   pass all required trust, assertion, binding and layout checks before commit.
2. **Continuity:** logical-stream identity, pinned track, method, last authenticated
   sequence/media manifest and interval replay IDs. Ordinary init/key/manifest
   updates preserve this state. Store manifest `streamId` independently of the
   resettable predecessor. Same track ID alone is not proof of the same stream.
3. **Reporting:** bounded unobserved ranges, retained failures and explicit playback
   interval events. None installs trust or authorizes a new chain/numbering epoch.

A trusted caller establishes logical-stream scope; signed identifiers constrain
it. Retain today's single-track profile. A different validated init track ID,
different stream identity or new root must be rejected/deferred unless the trusted
caller explicitly selects a new epoch. No automatic switching-set mapping.
Playback seek/join only changes observation interval, not logical-stream identity.
Unsigned playlist flags never authorize producer numbering restarts.

## Transition Matrix

All acceptance rows require signature/trust, assertions, hard binding, key bounds,
timing, track/stream and applicable ordering/replay checks. An unknown predecessor
means no comparison baseline in this interval, not merely an unfamiliar ID.

| Input / condition | Continuity transition | Result / report |
|---|---|---|
| First produced media, predecessor absent, no conflicting chain state | Establish media baseline; init excluded | Accept chain-start declaration; no completeness claim |
| Predecessor present, no received baseline (initial join or explicit seek) | Establish authenticated media baseline | Accept; report predecessor not received, not mismatch |
| Predecessor present, known baseline matches | Advance | Accept; report any numeric gap |
| Predecessor present, known baseline differs; all other checks pass | Advance to this authenticated media manifest | Fail this segment once; retain failure/gap; next correct link can recover |
| Predecessor absent in established chain, without verified signed restart | No advance | Fail; a missing field is not an implicit reset |
| Unsupported metadata, bad binding/signature, wrong identity, non-increase or replay | No advance or success-derived coverage | Fail, including when predecessor also mismatches |
| VSI increasing sequence, with jump | Advance | Accept; informational range only |
| VSI first observation above selected key minimum | Establish baseline | Literal leading range, including 0 -> 1; not proof of production |
| Ordinary same-scope init/key/manifest update | Atomically replace approved trusted material; preserve baseline/replay/identity | No fresh leading comparison; history retained |
| Invalid or incompatible update | Keep all previous installed state | Fail/defer candidate; diagnostics retained |
| Trusted player seek/join | Clear predecessor/replay interval; retain identity/trust/history | Report playback discontinuity; suppress next leading range, not authentication |
| Different track/stream or unsolicited new chain root | No same-stream commit | Reject/defer pending trusted new-epoch decision |
| Authenticated signed restart | Reserved transition, not currently available | Defer until #2560 syntax, scope and authorization are agreed |

Field absence is allowed only for a chain start or verified signed restart, never
just because the receiver reset. After a seek, an authenticated start may be
revisited, but whether it belongs to the existing logical stream still needs
trusted scope; absence alone cannot authorize substitution or a new epoch.
"Established chain" must therefore not be inferred solely from a nonempty
resettable predecessor. Selecting retained history/scope evidence is part of
the open reset/epoch design, not an already-approved API. Reporting a predecessor
not received is informational unverified continuity, not a predecessor mismatch.

## API Decisions And Remaining Choices

- **Update boundary (approved/implemented):** opt-in `update_vsi_context`, taking
  optional init plus the existing caller-verified manifest assertion, ID and signer
  certificate. No prepare/commit type or raw-input trust shortcut. Existing initial
  setup APIs retain their contracts; callers must opt into this operation for updates.
- **Key overlap (deferred roadmap item):** current policy replaces one complete
  context atomically and rejects late media from unavailable old manifests, even
  when a `kid` is reused. Future overlap/cache support must bound contexts by count,
  bytes and lifetime, define eviction and late-arrival behavior, and associate
  signed `manifestId` + `kid` with exactly the issuing manifest. Never union keys
  under one global manifest ID. Risks include reused kids, changed minima/validity
  windows, incompatible init timing, stale trust/revocation, memory exhaustion and
  eviction-dependent availability. Retention must not reset sequence/replay or let
  an old context reauthorize regression. This is not implemented or authorized by
  the current update slice; multiple keys within the current manifest are supported.
- **Reset/epoch control:** choose an additive reason-bearing playback operation
  versus an explicitly approved change to `reset_continuity`; separately decide
  whether a new epoch uses a new validator or an explicit trusted-caller API.
  Neither is a substitute for a normative signed-restart schema.
- **Reporting names:** `com.castlabs.livevideo.segment.predecessorNotReceived`
  and `com.castlabs.livevideo.player.discontinuity` are candidate spellings only,
  **OPEN and not authorized names**. Decide names, payload and event timing.
  Existing vendor gap codes stay informational pending upstream decisions.
- **Signer reconciliation (separate manifest-box work):** separate init readiness
  from media predecessor. Breaking changes are approved; no migration machinery
  is required. This is not a prerequisite for VSI context updates and is not
  implemented in this slice.

## Security And Acceptance Gates

| Regression case | Required evidence in eventual implementation |
|---|---|
| Start, late join, matching link, missing field, mismatch then valid successor | #2563 rules; one retained mismatch failure, no perpetual poisoning |
| Tamper plus mismatch; wrong stream after seek; unsolicited root | No recovery advance or implicit identity/epoch switch |
| Repeated init, rotation, manifest update, then duplicate/regression/gap | Baseline and replay checks survive; gaps remain report-only |
| Malformed init, untrusted manifest, invalid/mixed key set | Caller rejects untrusted manifests before update; layout/key failures leave installed state unchanged |
| Overlapping keys, reused kid, wrong manifest, expired/below-minimum key | Exact association; deterministic replacement/retention policy |
| Changed track/timing and trusted new epoch | Reject/defer incompatible update; explicit scope decision, no blind merge |
| Seek, failed first attempt, replay within new interval | Identity/history retained; failures do not consume initial suppression |
| Sign/restore/resume, first and later produced media | Init never linked; successful media establishes next predecessor |
| Both tracker error modes; overflow and bounded range retention | Same state decisions; stop mode returns mismatch error even after recovery |

Authentication does not prove production, malicious omission, presentation or an
authenticated endpoint. No global epoch-completeness guarantee, tail-truncation
detection, general chunk-unit support or switching-set coordination is promised.

## Minimal Phases

1. Cleanup superseded policy references separately; preserve #22's independent scope.
2. Agree remaining reset/scope and reporting choices; historical-context caching is deferred.
3. Implement media-only chaining and retained identity with focused regressions.
4. Implement the agreed transactional update path and explicit interval reporting.
5. Review the matrix before integration; defer signed restarts/chunks/switching sets.

The VSI transactional path in phase 4 is implemented independently of phases 2/3;
explicit interval reporting remains deferred. Persisted signer-state choices do
not block this slice and imply no migration requirement for it. Local verification
is recorded in the current coverage document. No qualification or repins authorized.
