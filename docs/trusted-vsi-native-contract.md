# Trusted VSI Native Contract

Status: current native implementation contract. Python consumers additionally
require the exact SDK version `0.92.0-dev` and capability mask 63 alongside
contract revision 3; a compatible SDK version change still requires coordinated
Python gate updates. This replaces the unshipped
scaffold contracts; complete-buffer live-video APIs are unchanged. Library version
is `0.92.0-dev`. C declarations below are the binding contract for the concurrent
Python and signer-adapter work. No commit/publication is implied. A matching
version string and capability mask do NOT establish ABI/build identity.
`c2pa_live_video_trusted_vsi_contract_revision()` is a safe, no-argument probe
returning `uint32_t` contract revision **3**. Consumers require exactly revision
3 and capability mask 63 before using this trusted ABI. This is a compatibility
gate, not build authentication: the exact source SHA and artifact hash/evidence
are still needed. Contract revision is independent of the SDK/library version
and persisted-state format version, even though the latter also currently equals
3. It does not guarantee state recovery across builds or settings. The probe is
absent when `unstable_live_video` is disabled; no existing signature or V1 layout
changes.

## Configuration And Modes

`TrustedVsiMode`: `expert_sig_structure` = 1, `signer_composed_emsg` = 2.
Mode is immutable, selected at construction, and checked on import and every
operation. The existing `VsiSessionConfig` remains unchanged (algorithm, public
COSE_Key CBOR, nonempty binary kid, min_sequence_number, created_at RFC3339,
validity_period_secs). Only Ed25519 and ES256 are supported, with exactly 64 raw
signature bytes (ES256 P1363, not DER). Private COSE key material is rejected.

The constructor additionally takes `TrustedVsiSessionOptions` / C `options_json`:

```json
{"mode":"expert_sig_structure","reservation_nonce":"0123456789abcdef0123456789abcdef","signing_time_unix_seconds":1789041600,"sequence_max":4294967295}
```

All fields except `sequence_max` are required; absent/null sequence_max means
u32::MAX. Unknown fields are rejected. Nonce is exactly 32 lowercase hex chars
(16 public random bytes, supplied/durably retained by the coordinator). Nonce
domain-separates deterministic manifest/instance IDs and assertion salts for
crash replay; it is NEVER a private-key seed. `signing_time_unix_seconds` is the
pinned initialization iat, within the configured key validity interval.
min_sequence_number must fit uint32 and be <= sequence_max.

Trusted reservations alone derive 16-byte salts from SHA-256 over the public
nonce, a versioned salt domain, artifact kind, and instance-qualified label.
Their static CBOR/JSON and claim maps are serialized in stable map order so
serde HashMap iteration cannot change the reconstructed reservation. Binary
resources are not re-encoded. Ordinary SDK salt and serialization defaults are
unchanged. Resource references must resolve through the existing Builder path;
missing resource bytes remain errors, not import-time comparison exemptions.

Legacy `trust.trust_anchors` and `trust.user_anchors` configure the `Manifest`
trust purpose. They do not supply
CAWG identity or other purpose anchors, and a missing purpose-specific anchor is
not permission to fall back to the Manifest set. These fixes do not weaken that
purpose isolation or change trust defaults.

## Rust Surface

All types are re-exported by `c2pa::live_video`; errors use `c2pa::Result`.

```rust
pub struct TrustedVsiSessionOptions {
    pub mode: TrustedVsiMode,
    pub reservation_nonce: String,
    pub signing_time_unix_seconds: i64,
    pub sequence_max: Option<u32>,
}
impl TrustedVsiPrehashedSession {
    pub fn from_shared_context_with_callback<F>(
        context: &Arc<Context>, manifest_json: impl Into<String>,
        config: VsiSessionConfig, options: TrustedVsiSessionOptions, callback: F,
    ) -> Result<Self>
    where F: Fn(&VsiSigningContextV1, &[u8]) -> Result<Vec<u8>> + Send + Sync + 'static;

    pub fn reserve_init_uuid(&mut self, format: &str) -> Result<TrustedVsiInitUuidReservation>;
    pub fn reserved_manifest_id(&self) -> Result<&str>;
    pub fn finalize_init_uuid(&mut self, canonical_bmff_hash: &[u8]) -> Result<Vec<u8>>;
    pub fn commit_init_uuid(&mut self) -> Result<()>;
    pub fn sign_sig_structure(&mut self, sig_structure: &[u8], sequence_number: u32) -> Result<Vec<u8>>;
    pub fn reserve_media_emsg_at(&mut self, sequence_number: u32,
        signing_time_unix_seconds: i64, timescale: u32, event_duration: u32)
        -> Result<TrustedVsiMediaEmsgReservation>;
    pub fn finalize_media_emsg(&mut self, canonical_bmff_hash: &[u8]) -> Result<Vec<u8>>;
    pub fn export_state(&self) -> Result<Vec<u8>>;
    pub fn import_state(&mut self, state: &[u8]) -> Result<()>;
    pub fn status(&self) -> Result<TrustedVsiStatus>;
    pub fn preflight(&self, operation: TrustedVsiOperation, data: &[u8],
        sequence_number: u32, iat: i64, timescale: u32, event_duration: u32,
        format: &str) -> Result<()>;
}
pub fn validate_trusted_vsi_input(kind: TrustedVsiInputKind, algorithm: SigningAlg,
    data: &[u8]) -> Result<()>;
pub fn trusted_vsi_hash_template(kind: TrustedVsiInputKind) -> Result<Vec<u8>>;
// Additive Rust-only reference helper (no C symbol): computes the canonical
// hash input over complete final-placement bytes. Used by native tests as the
// trusted-processor reference; callers are not required to use it.
pub fn trusted_vsi_compute_hash(kind: TrustedVsiInputKind, final_bytes: &[u8]) -> Result<Vec<u8>>;
```

`TrustedVsiSignResult` is removed. Expert result is signature bytes ONLY.
`recover(signed_uuid, previous_emsg)` is removed: restoration uses explicit state,
not EMSG parsing. Existing reservation `.bytes()`, `.manifest_id()`, timing and
signing-context accessors remain. Status retains its existing fields/accessors;
in expert mode next_sequence_number and next_event_id are ALWAYS absent,
exhausted=false, exhaustion_reason absent. There is no expert media journal.

Operations (uint32): ReserveInit=0, FinalizeInit=1, CommitInit=2,
ExpertSign=3, ReserveMedia=4, FinalizeMedia=5.
Input kinds (uint32): InitHash=0, SigStructure=1, MediaHash=2.

## Exact C ABI

All symbols retain prefix `c2pa_live_video_trusted_vsi_`. Opaque Context and
session types, C2paSigningAlg, V1 callback/context, and V1 status declarations
are as in generated c2pa.h. Parameters below are in exact ABI order.

```c
uint64_t c2pa_live_video_trusted_vsi_capabilities(void);
uint32_t c2pa_live_video_trusted_vsi_contract_revision(void);
C2paLiveVideoTrustedVsiSession *c2pa_live_video_trusted_vsi_session_create_callback_v1(
    C2paContext *context, const char *manifest_json, C2paSigningAlg algorithm,
    const unsigned char *public_cose_key, size_t public_cose_key_len,
    const unsigned char *kid, size_t kid_len, uint64_t min_sequence_number,
    const char *created_at, uint64_t validity_period_secs, const char *options_json,
    void *user_data, C2paLiveVideoTrustedVsiSignCallbackV1 callback);
int64_t c2pa_live_video_trusted_vsi_session_reserve_init_uuid(
    C2paLiveVideoTrustedVsiSession *session, const char *format, const unsigned char **output);
char *c2pa_live_video_trusted_vsi_session_reserved_manifest_id(
    const C2paLiveVideoTrustedVsiSession *session);
int64_t c2pa_live_video_trusted_vsi_session_finalize_init_uuid(
    C2paLiveVideoTrustedVsiSession *session, const unsigned char *data, size_t len,
    const unsigned char **output);
int c2pa_live_video_trusted_vsi_session_commit_init_uuid(C2paLiveVideoTrustedVsiSession *session);
int64_t c2pa_live_video_trusted_vsi_session_sign_sig_structure(
    C2paLiveVideoTrustedVsiSession *session, const unsigned char *data, size_t len,
    uint32_t sequence_number, const unsigned char **output);
int64_t c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
    C2paLiveVideoTrustedVsiSession *session, uint32_t sequence_number, int64_t iat,
    uint32_t timescale, uint32_t event_duration, const unsigned char **output,
    C2paLiveVideoTrustedVsiSigningContextV1 *signing_context);
int64_t c2pa_live_video_trusted_vsi_session_finalize_media_emsg(
    C2paLiveVideoTrustedVsiSession *session, const unsigned char *data, size_t len,
    const unsigned char **output);
int64_t c2pa_live_video_trusted_vsi_session_export_state(
    const C2paLiveVideoTrustedVsiSession *session, const unsigned char **output);
int c2pa_live_video_trusted_vsi_session_import_state(
    C2paLiveVideoTrustedVsiSession *session, const unsigned char *data, size_t len);
int c2pa_live_video_trusted_vsi_session_status_v1(
    const C2paLiveVideoTrustedVsiSession *session, C2paLiveVideoTrustedVsiStatusV1 *status);
int c2pa_live_video_trusted_vsi_validate_input(
    uint32_t kind, C2paSigningAlg algorithm, const unsigned char *data, size_t len);
int64_t c2pa_live_video_trusted_vsi_hash_template(uint32_t kind, const unsigned char **output);
int c2pa_live_video_trusted_vsi_session_preflight(
    const C2paLiveVideoTrustedVsiSession *session, uint32_t operation,
    const unsigned char *data, size_t len, uint32_t sequence_number, int64_t iat,
    uint32_t timescale, uint32_t event_duration, const char *format);
```

The superseded expert assigned-sequence output arguments and old recover symbol
are removed, not aliased. Byte functions return length or -1; other operations
return 0 or -1; c2pa_error supplies details. Creation/string getters return NULL
on error. All supplied writable outputs are cleared before validation; required
NULL outputs are errors. `(NULL,0)` is permitted only for empty preflight data.
Returned bytes/handles are tracked and freed with c2pa_free; the returned
manifest-ID string follows c2pa_string_free. Input buffers are borrowed for the
call. Context is retained by Arc, not consumed. Host owns callback/user_data and
keeps them alive until session destruction. Handle operations are externally
serialized; callback buffers must not escape, and callback must not unwind.

A nonempty byte-output allocation or pointer-tracking failure returns -1 with a
NULL output and retains the allocation/tracking error. This is output-delivery
failure, not necessarily signer failure: successful native finalization is not
rolled back or blocked. Init/media finalize retries with the identical hash replay
the cached signed artifact without another signer call. Reservation retries also
replay the existing reservation. Expert signatures have no native cache; their
provider/coordinator still owns exact signature replay and operation-ID binding.
Reserve-media callback metadata remains cleared when byte delivery fails.

## Planned Python Mapping

```python
TrustedVsiSession.from_callback(
    context, manifest_json, algorithm, public_cose_key, kid,
    min_sequence_number, created_at, validity_period_secs, callback, *,
    mode, reservation_nonce, signing_time_unix_seconds, sequence_max=None)
session.reserve_init_uuid(format="video/mp4") -> bytes
session.reserved_manifest_id() -> str
session.finalize_init_uuid(canonical_bmff_hash: bytes) -> bytes
session.commit_init_uuid() -> None
session.sign_sig_structure(sig_structure: bytes, sequence_number: int) -> bytes
session.reserve_media_emsg_at(sequence_number, signing_time_unix_seconds,
    timescale, event_duration) -> TrustedVsiMediaEmsgReservation
session.finalize_media_emsg(canonical_bmff_hash: bytes) -> bytes
session.export_state() -> bytes
session.import_state(state: bytes) -> None
session.status() -> TrustedVsiStatus
session.preflight(operation, data=b"", *, sequence_number=0, iat=0,
    timescale=0, event_duration=0, format="video/mp4") -> None
validate_trusted_vsi_input(kind, algorithm, data: bytes) -> None
trusted_vsi_hash_template(kind) -> bytes
```

Constructor kwargs serialize into options_json above. Callback receives V1
metadata plus exact bytes, returns bytes. Reservation wrapper contains bytes,
supplied sequence, allocated event_id, pinned iat, timescale and duration.
No Python BMFF construction or native counter prediction is required.

## State And Retry Rules

State transitions: New -> InitReserved -> InitFinalized -> Committed. Commit is
internal durable coordinator activation, NOT public publication acknowledgement.
Media cannot sign/reserve before Committed. Init reserve returns the SAME frozen
reservation on repetition; successful finalize is replayable only for identical
input bytes. Composed mode adds one pending reservation, then finalizes it.
Calls with conflicting state/input fail; operations are mode-pinned.

Expert mode accepts any supplied sequence in [min, max], including repeated older
sequences after later calls. Callback purpose=Vsi, has_sequence=true,
sequence=supplied, has_event=false, exhaust_after_sign=false EVEN AT UINT32_MAX.
No native/backend expert next counter, event counter, or exhaustion exists.
The processor owns MFHD/VSI equality, ordering, replay IDs, and rollover.

Composed mode requires supplied sequence == next_sequence (initially min).
Events start at 1. Reserve pins sequence/event/iat/timescale/duration and signs
nothing. Both timing integers must be positive; iat must be within key validity.
Successful finalize advances counters, or exhausts at sequence_max/u32::MAX or
event u32::MAX without wrapping. The terminal callback has exhaust_after_sign=true.
SignerBinding callback has no sequence/event and exhaust_after_sign=false.

Once an external signing call begins, a failure leaves the local session blocked,
not reset to unused. Export records that failure. Further signing/reservation is
rejected; discard the operation-local object and import the durable PRE-operation
record into a NEW instance for retry. Import is allowed only in New state and
must match mode/config/options and claim-signer identity: certificate, claim
reserve size, and the ordered dynamic-assertion declarations (label and reserve
size of each). Provider
closures/keystore enforce immutable operation-ID input bindings and replay exact
completed signatures. Operation IDs are not native V1 metadata. Native cannot
stop a coordinator deliberately importing an old record with a new operation ID.

State export is versioned bounded JSON containing explicit public configuration,
state/counters, input bindings, and base64 exact reserved/signed artifacts,
including the unsigned JUMBF that preserves real manifest IDs, salts and slots.
It contains no Rust heap snapshot, callback, Context, access secret or private
key. Import validates artifacts/identity/state consistency before mutation.
Current format: `{"format": "c2pa.trusted-vsi.state", "version": 3, "identity",
"state"}`. Versions 1 and 2 (unreleased) are rejected; there is no migration or
silent reinterpretation of their random-salt reservations. Identity retains
`claim_signer_reserve_size`, ordered `dynamic_assertions: [{"label", "reserve_size"}]`,
and recorded media timing. Import and init-finalize preflight reconstruct the
entire unsigned reservation from the pinned base manifest JSON, nonce, config,
Context and signer/DA declarations, without signing or requesting DA content.
The expected manifest ID, JUMBF and composed UUID must match byte-for-byte,
including static assertions, claim metadata, resources/databoxes, native
placeholders and every DA slot. The editable identity hash is not the content
binding. Reserved JUMBF is checked even in finalized/committed records. Signed
init imports additionally reconstruct the finalized store allowing only native
binding writes, declared DA content and the verified signature, and require full
equality, preventing changes outside those finalize slots. This does not prove
the provider provenance of the allowed finalize inputs.
Import also requires
the reserved store's DA placeholder slots (every assertion after the native
session-keys and bmff-hash assertions) to match those declarations exactly in
count, label, order and reserve size.
The coordinator must authenticate and atomically persist these records; they are
not an attacker-controlled interchange format. Expert records contain no per-media
history and do not consume previous EMSG artifacts.

Recovery requires the original reservation-producing SDK/generator version and
Context builder settings. Generator version metadata and settings-dependent
serialization affect the reconstructed bytes; identity checks do not separately
capture every Context setting. The full rebuild is the content-binding check,
and changed builds/settings that produce different bytes are rejected fail-closed.
There is no blanket recovery guarantee across SDK versions or configuration
changes. During upgrades, retain the original pinned build/settings for pending
or otherwise recoverable epochs. A newly authorized epoch may use the new build
without inherently requiring physical key rotation, stream termination or a
sequence reset; continuous/24-hour epoch lifecycle management is separate work,
not implemented by this contract. Never weaken reconstruction by trusting an
editable record version or generator/settings metadata as evidence of origin.

Bounded threat residual: compromise of the private claim-signing key for the
same pinned certificate, together with an existing valid signerBinding, allows
an attacker to produce validly signed DA content and init-hash content externally
while retaining the pinned static reservation. Finalized reconstruction cannot
recompute DA content without invoking the content callbacks; it checks the allowed
slots and signature integrity, not whether the authorized provider produced that
content. Ordinary signature integrity cannot establish provider provenance or
block this compromised-claim-key case. An authenticated, atomically persisted
coordinator record remains necessary; native reconstruction does not replace it.

## Canonical Inputs And Preflight

Expert input: one untagged, definite four-element CBOR array
`["Signature1", protected_bstr, empty_bstr, vsi_payload_bstr]`.
Protected bytes are one canonical map with integer/text COSE labels and exactly
one integer alg (-8 Ed25519, -7 ES256) matching the pinned key and a required
integer `"iat"` NumericDate fitting int64. Other headers are
allowed in the bounded structural domain: integers, bytes, UTF-8 text, arrays,
maps, bool/null, tagged VALUES, and preferred-width floats (canonical half NaN).
Nested map keys are integer/bytes/text; outer protected keys are integer/text.
Reject indefinite lengths, nonminimal integers/lengths/floats, duplicate keys,
non-deterministic key order, malformed UTF-8, trailing
bytes, excessive nesting/items and unsupported simple/key forms. Max total expert
input 1 MiB, protected/hash CBOR 64 KiB, nesting 32, aggregate container items 4096
per decoded CBOR value.
Key order is RFC 8949 §4.2.1 core deterministic encoding (referenced by COSE,
RFC 9052): keys strictly increasing in BYTEWISE lexicographic order of their
complete encodings. It is NOT the obsolete RFC 7049 §3.9 length-first rule. For
example `{1: -7, 1000: 0, "a": 0}` (`a3 01 26 19 03e8 00 61 61 00`) is accepted,
while the length-first order `{1: -7, "a": 0, 1000: 0}` is rejected. Native
templates and all native deterministic encoding use the same bytewise order.
The payload MUST be a bounded untagged segment-info map with exactly the supported
fields/types: `sequenceNumber` (uint32), `manifestId` (nonempty text), `bmffHash`
(untagged native SHA-256 media-template map with a 32-byte hash), and optional
`manifestUri` (untagged hashed-URI map with text `url`, byte-string `hash`, optional
text `alg`, and no extra fields). Duplicates, tags around signed fields, unknown
fields, trailing bytes and type coercions are rejected. Payload map field order
is NOT required to be deterministic: native serde struct serialization remains
interoperable. Definite/minimal encoding and nesting/item bounds still apply.
Session signing/preflight requires signed `sequenceNumber` to equal the supplied
u32, signed `manifestId` to equal the pinned init, and protected `iat` to lie
within the inclusive key validity interval. Static validation checks shape/types
but cannot check a session identity or validity interval. A detached signerBinding
certificate bstr is not a VSI map and cannot be signed under purpose `Vsi`.
Sign original input bytes unchanged; verify the returned raw 64-byte signature
against those same bytes. Repeated/out-of-order expert sequences remain supported
without media counters.

The exact native media bmffHash template is an intentional trusted-expert profile
limit, not a claim that every otherwise legal C2PA bmff-hash variant is supported.
Only the 32-byte digest may vary: `alg`, `name` and exclusions must remain those
of the native SHA-256 media template. Alternative algorithms/names/exclusions,
Merkle forms and URL/extensions are rejected, not accepted opportunistically.
Payload map field-order flexibility does not relax this profile restriction.

Hash inputs are canonical untagged bmff-hash maps (v3, SHA-256), exactly matching
the native hash template except for the 32-byte `hash` value. Templates contain
`alg`, `name`, `exclusions`, `hash`, no Merkle/URL/extensions. Init excludes only
the C2PA UUID box (UUID selector at offset 8); media excludes only C2PA VSI emsg
(scheme URI selector at offset 12). `trusted_vsi_hash_template` returns the exact
canonical zero-digest template. The trusted processor hashes final-placement
bytes with the reserved box installed; native finalize validates shape, not media
bytes it has never received. Only MP4/video/mp4 format is supported here.

Pure static validation and session preflight perform no signing callbacks, key
use/provisioning, new session identifiers or state mutation. Init-finalize preflight
reconstructs the expected reserved bytes but does not create a new reservation.
Bounded temporary
parsing allocation is permitted. Constructor validates configuration/public key
and reads the Context claim signer's public certificate, claim reserve size and
DA declarations (labels and reserve sizes, never content), but does not sign.
Reserve may read DA reserve-size declarations, NEVER DA content or session-key
signatures. Before ANY external call (signerBinding, DA content, claim signer),
finalize (and its preflight) re-reads the signer's declarations and requires
them and the reserved slots to equal the pinned set; a mismatch fails without
blocking the session. Finalize then runs signerBinding, the Context signer/DAs in original order
with refreshed hashes and self-exclusion, claim signing and verification. Actual
reserved UUID/EMSG lengths must be unchanged. Capabilities become 63 only when
all paths and persistence are genuinely wired and qualified; no fake enablement.
