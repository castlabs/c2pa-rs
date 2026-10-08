# Same-Key Init Epoch Compatibility Probe

## Evidence

This is compatibility evidence, not adoption of a new lifecycle contract and not
qualification of the current functional branch.

- Probe date: 2026-10-06.
- Python: 3.12.3; binding source `12d265db92e8dcbf80b8255278e9a7fc5945f750`.
- Native: previously qualified debug library from
  `203dc08db2bc9548a739bf209e6b510a546d70db`, reporting `0.92.0-dev` and the
  functional trusted capabilities.
- Native SHA-256:
  `0401bf3da2060fbdae3223ec0feb926f836b59604d9d4fe9c993122e29d5b6fe`.
- Result: **6 passed in 2.54 seconds**, no skipped tests.
- Matrix: Ed25519 and ES256, each with complete-buffer, expert Sig_structure,
  and signer-composed EMSG native modes.

The probe is preserved at `scripts/probes/test_same_key_init_epochs.py`. It
imports the paired Python test helpers rather than duplicating fixture hashing.
It is not added to the native qualification workflow or its unittest discovery.

Example rerun (replace source/library paths with reviewed artifacts):

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/path/to/c2pa-python/src:/path/to/c2pa-python/tests \
C2PA_LIBRARY_NAME=/path/to/libc2pa_c.so \
python3 -m pytest -q -s -p no:cacheprovider \
  scripts/probes/test_same_key_init_epochs.py
```

## Observed Behavior

Each case uses one physical session key and claim-signing certificate, with two
independent native handles. Both epochs retain the same public COSE key, `kid`,
and physical `createdAt` (`2026-09-10T00:00:00Z`). Epoch A declares a validity
period of 86,400 seconds and starts at media sequence 1. Epoch B declares 172,800
seconds and starts at sequence 2, using a new init manifest and, for trusted
sessions, a different reservation nonce. The second media signing time lies
outside A's declared window and within B's.

All six cases confirm:

- Native callback constructors accept the unchanged key with new finite init
  metadata; no mutable refresh setter is needed to generate another signed init.
- Both initialization assets validate as Trusted through the existing Reader
  and test trust anchors, with no active-manifest failures.
- Manifest identities differ. The public key, `kid`, and `createdAt` remain
  unchanged, while the signed validity periods and sequence minima differ.
- The second signerBinding request has exactly the first request's TBS bytes.
  Returning the cached first binding signature succeeds, including for ES256.
- The original signed init bytes/metadata are unchanged after producing B.
- Media signing succeeds at the respective sequence/time for each epoch.

The four trusted cases additionally reject importing A's state into the new B
handle without changing B's fresh state.

The four complete-buffer/composed cases reject A's out-of-window signing time
without invoking the media callback. The existing expert validator does not
provide that same `iat` policy check; this probe does not certify expert
authorization, payload purpose, media hashes, or the open PR #15 security fixes.

## Counter-Carry Limitation

Both native-generated EMSG modes emit event IDs **1, 1** across these fresh
handles, despite media sequences **1, 2**. Expert mode has no native event
allocator; the packager remains responsible for its IDs.

The newer verifier context-update path at `d6e7b529` preserves EMSG replay
history. Consequently, fresh-handle init generation alone is not proof of a
seamless complete-buffer/composed transition: reusing event ID 1 can conflict
with that retained replay history. This follows from the source paths; the
probe library predates `update_vsi_context` and does not execute that verifier
transition.

An explicit initial-event-ID/counter-carry interface and recovery rules are
required before claiming seamless native-generated EMSG refresh. Do not change
existing defaults silently or reset verifier replay state to hide this issue.

## Boundaries

- A new signed assertion can technically advertise a later validity endpoint
  for the same key while retaining the original `createdAt`. That is an explicit
  new claim authorization, not mutation of previously published validity.
- This probe demonstrates mechanics, not that C2PA expressly standardizes a
  particular same-key refresh policy. The spec calls `createdAt` the key's
  creation time; do not silently redefine it as init-epoch activation time.
- Native constructors do not authorize the epoch or enforce global uniqueness
  across handles. Those remain authoritative coordinator responsibilities.
- A storage shard change must not create an init epoch, rotate keys, or reopen
  signing of a sequence under different epoch/key/TBS metadata.
- Same-key refresh does not remove the uint32 media/event wire limits.
- No keystore replay/expiry behavior, multi-origin authority, ongoing 24/7
  operation, or final integrated stack was qualified by this six-case probe.
