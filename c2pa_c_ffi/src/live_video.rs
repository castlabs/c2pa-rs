// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Experimental stateful C API for C2PA 2.4 Verifiable Segment Info signing.

use std::{
    ffi::c_void,
    os::raw::{c_char, c_int, c_uchar},
};

use c2pa::{
    live_video::{
        Ed25519SessionKey, LiveVideoVsiSigner, TrustedVsiExhaustionReason, TrustedVsiInputKind,
        TrustedVsiOperation, TrustedVsiPrehashedSession, TrustedVsiSessionOptions,
        TrustedVsiSigningPurpose, VsiSessionConfig, VsiSessionSigner, VsiSigningContextV1,
        VsiSigningPurpose,
    },
    SigningAlg,
};
use zeroize::Zeroize;

use crate::{
    c_api::{C2paContext, C2paSigningAlg},
    to_c_bytes, to_c_string, CimplError,
};

/// Callback purpose for a live-video VSI session-key signature.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2paLiveVideoVsiSigningPurpose {
    /// Detached `signerBinding` over the manifest signer's certificate.
    SignerBinding = 0,
    /// Final per-media-segment VSI signature.
    Vsi = 1,
}

/// Sequence-number sentinel supplied for `SignerBinding` callbacks.
pub const C2PA_LIVE_VIDEO_VSI_NO_SEQUENCE: u64 = u64::MAX;

/// Synchronous callback for a live-video VSI session-key signature.
///
/// `tbs` is the exact COSE Sig_structure and is valid only for the invocation.
/// `sequence_number` is the actual media sequence for `Vsi` and
/// `C2PA_LIVE_VIDEO_VSI_NO_SEQUENCE` for `SignerBinding`.
/// `signature` has `signature_capacity` bytes supplied by the SDK. Return the
/// number of bytes written or a negative value on error. Ed25519 and ES256 must
/// return exactly 64 raw bytes; ES256 uses P1363 `r || s`, never ASN.1 DER.
/// The callback must not retain either buffer.
pub type C2paLiveVideoVsiSignCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    purpose: C2paLiveVideoVsiSigningPurpose,
    sequence_number: u64,
    tbs: *const c_uchar,
    tbs_len: usize,
    signature: *mut c_uchar,
    signature_capacity: usize,
) -> isize;

struct FfiVsiSessionSigner {
    callback: C2paLiveVideoVsiSignCallback,
    // Erasing the pointer to an integer makes this adapter Send + Sync. That
    // is sound only under the public C contract: the callback/user_data remain
    // valid for the handle lifetime and callers externally serialize all
    // operations on a handle and access to user_data.
    user_data: usize,
}

impl VsiSessionSigner for FfiVsiSessionSigner {
    fn sign(&self, purpose: VsiSigningPurpose, tbs: &[u8]) -> c2pa::Result<Vec<u8>> {
        let (purpose, sequence_number) = match purpose {
            VsiSigningPurpose::SignerBinding => (
                C2paLiveVideoVsiSigningPurpose::SignerBinding,
                C2PA_LIVE_VIDEO_VSI_NO_SEQUENCE,
            ),
            VsiSigningPurpose::Vsi { sequence_number } => {
                (C2paLiveVideoVsiSigningPurpose::Vsi, sequence_number)
            }
        };
        let mut signature = [0u8; 64];
        let written = unsafe {
            (self.callback)(
                self.user_data as *mut c_void,
                purpose,
                sequence_number,
                tbs.as_ptr(),
                tbs.len(),
                signature.as_mut_ptr(),
                signature.len(),
            )
        };
        if written < 0 {
            return Err(c2pa::Error::BadParam(format!(
                "VSI signing callback returned error code {written}"
            )));
        }
        let written = usize::try_from(written).map_err(|_| {
            c2pa::Error::BadParam("VSI signing callback result is out of range".to_string())
        })?;
        if written > signature.len() {
            return Err(c2pa::Error::BadParam(format!(
                "VSI signing callback reported {written} bytes, exceeding output capacity {}",
                signature.len()
            )));
        }
        Ok(signature[..written].to_vec())
    }
}

/// Opaque state for one Ed25519 or ES256 VSI live-video session.
///
/// Calls operating on the same handle must be externally serialized.
pub struct C2paLiveVideoVsiSigner {
    signer: LiveVideoVsiSigner,
}

/// Version-one callback context for prehashed trusted VSI signatures.
///
/// `has_sequence_number` and `has_event_id` distinguish absent values from
/// zero. SignerBinding has neither. Expert media has the processor-supplied
/// sequence, no event, and `exhaust_after_sign = false` even at `UINT32_MAX`.
/// Composed media has the reserved event and marks its terminal identifier.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2paLiveVideoTrustedVsiSigningContextV1 {
    /// Explicit reason for the signature request.
    pub purpose: u32,
    /// Media sequence number when `has_sequence_number` is true.
    pub sequence_number: u32,
    /// Whether `sequence_number` is present.
    pub has_sequence_number: bool,
    /// EMSG event identifier when `has_event_id` is true.
    pub event_id: u32,
    /// Whether `event_id` is present.
    pub has_event_id: bool,
    /// Whether a successful signature exhausts the usable identifier space.
    pub exhaust_after_sign: bool,
}

impl C2paLiveVideoTrustedVsiSigningContextV1 {
    const fn empty() -> Self {
        Self {
            purpose: C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_SIGNER_BINDING,
            sequence_number: 0,
            has_sequence_number: false,
            event_id: 0,
            has_event_id: false,
            exhaust_after_sign: false,
        }
    }

    fn from_rust(context: &VsiSigningContextV1) -> Self {
        Self {
            purpose: match context.purpose() {
                TrustedVsiSigningPurpose::SignerBinding => {
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_SIGNER_BINDING
                }
                TrustedVsiSigningPurpose::Vsi => C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_VSI,
            },
            sequence_number: context.sequence_number().unwrap_or(0),
            has_sequence_number: context.sequence_number().is_some(),
            event_id: context.event_id().unwrap_or(0),
            has_event_id: context.event_id().is_some(),
            exhaust_after_sign: context.exhaust_after_sign(),
        }
    }
}

/// Synchronous V1 callback for a prehashed trusted VSI signature.
///
/// `context` and `tbs` are borrowed only for the invocation. The callback writes
/// exactly 64 raw signature bytes (Ed25519, or ES256 P1363 `r || s`) into
/// `signature` (capacity `signature_capacity`, always 64) and returns the count
/// written, or a negative value on error. It must not retain buffers or unwind.
pub type C2paLiveVideoTrustedVsiSignCallbackV1 = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        context: *const C2paLiveVideoTrustedVsiSigningContextV1,
        tbs: *const c_uchar,
        tbs_len: usize,
        signature: *mut c_uchar,
        signature_capacity: usize,
    ) -> isize,
>;

/// Public state returned by a prehashed trusted VSI session.
///
/// `blocked` occupies former padding, so the V1 layout and size are unchanged.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct C2paLiveVideoTrustedVsiStatusV1 {
    /// Whether the initialization UUID has been committed (activated).
    pub init_uuid_committed: bool,
    /// Whether an initialization UUID is reserved or finalized but not committed.
    pub init_uuid_pending: bool,
    /// Whether a media EMSG reservation is pending.
    pub media_emsg_pending: bool,
    /// Whether `next_sequence_number` is present (composed mode only).
    pub has_next_sequence_number: bool,
    /// Next composed media sequence number when present.
    pub next_sequence_number: u32,
    /// Whether `next_event_id` is present (composed mode only).
    pub has_next_event_id: bool,
    /// Next composed EMSG event identifier when present.
    pub next_event_id: u32,
    /// Whether no further composed media identifiers can be signed.
    pub exhausted: bool,
    /// Whether `exhaustion_reason` is present.
    pub has_exhaustion_reason: bool,
    /// Whether an external signing step failed; retry by importing the
    /// pre-operation state into a new session.
    pub blocked: bool,
    /// Successful terminal reason when present.
    pub exhaustion_reason: u32,
}

/// Trusted V1 callback purpose value for signer binding.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_SIGNER_BINDING: u32 = 0;
/// Trusted V1 callback purpose value for media VSI.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_VSI: u32 = 1;
/// No successful exhaustion reason is present.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_NONE: u32 = 0;
/// The final configured sequence was consumed.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_SEQUENCE_MAX: u32 = 1;
/// The final EMSG event identifier was consumed.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_EVENT_ID_MAX: u32 = 2;
/// A migrated session stopped at the former sentinel.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_LEGACY_SENTINEL: u32 = 3;
/// Expert Sig_structure mode (`options_json` `"mode":"expert_sig_structure"`).
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_MODE_EXPERT_SIG_STRUCTURE: u32 = 1;
/// Signer-composed EMSG mode (`"mode":"signer_composed_emsg"`).
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_MODE_SIGNER_COMPOSED_EMSG: u32 = 2;
/// Preflight operation: reserve init UUID.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_RESERVE_INIT: u32 = 0;
/// Preflight operation: finalize init UUID.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_FINALIZE_INIT: u32 = 1;
/// Preflight operation: commit init UUID.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_COMMIT_INIT: u32 = 2;
/// Preflight operation: expert Sig_structure signing.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_EXPERT_SIGN: u32 = 3;
/// Preflight operation: reserve composed media EMSG.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_RESERVE_MEDIA: u32 = 4;
/// Preflight operation: finalize composed media EMSG.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_FINALIZE_MEDIA: u32 = 5;
/// Input kind: canonical init bmff-hash map.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_INIT_HASH: u32 = 0;
/// Input kind: expert COSE Sig_structure.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_SIG_STRUCTURE: u32 = 1;
/// Input kind: canonical media bmff-hash map.
pub const C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_MEDIA_HASH: u32 = 2;

/// Opaque state for one prehashed trusted VSI session. Operations on one
/// handle must be externally serialized. Release with `c2pa_free()`.
pub struct C2paLiveVideoTrustedVsiSession {
    session: TrustedVsiPrehashedSession,
}

unsafe fn clear_trusted_vsi_bytes(output: *mut *const c_uchar) {
    if !output.is_null() {
        *output = std::ptr::null();
    }
}

unsafe fn write_trusted_vsi_bytes(output: *mut *const c_uchar, bytes: Vec<u8>) -> i64 {
    let len = match i64::try_from(bytes.len()) {
        Ok(len) => len,
        Err(_) => {
            CimplError::from(c2pa::Error::BadParam("output is too large".to_string())).set_last();
            return -1;
        }
    };
    *output = to_c_bytes(bytes);
    len
}

/// Accepts `(NULL, 0)` as empty input; otherwise requires a readable buffer.
unsafe fn optional_trusted_vsi_bytes<'a>(
    data: *const c_uchar,
    len: usize,
    name: &'static str,
) -> Result<&'a [u8], ()> {
    if data.is_null() && len == 0 {
        return Ok(&[]);
    }
    match crate::safe_slice_from_raw_parts(data, len, name) {
        Ok(slice) => Ok(slice),
        Err(err) => {
            CimplError::from(err).set_last();
            Err(())
        }
    }
}

/// Returns the prehashed trusted VSI capability bit mask.
///
/// Bits are: 1 split init UUID, 2 expert Sig_structure, 4 signer-composed
/// EMSG, 8 versioned state export/import restoration, 16 signing-context V1,
/// and 32 full `u32` handling. This build returns 63.
#[no_mangle]
pub extern "C" fn c2pa_live_video_trusted_vsi_capabilities() -> u64 {
    c2pa::live_video::TrustedVsiCapabilities::current().bits()
}

/// Creates a callback-backed prehashed trusted VSI session.
///
/// `public_cose_key` is a public COSE_Key whose algorithm and non-empty `kid`
/// agree with `algorithm` (Ed25519 or ES256) and `kid`. `options_json` is the
/// contract options object (`mode`, `reservation_nonce`,
/// `signing_time_unix_seconds`, optional `sequence_max`). The context is
/// retained, not consumed; its claim signer certificate is read but nothing is
/// signed. Returns NULL on error. Release the handle with `c2pa_free()`.
///
/// # Safety
///
/// `context` must be tracked; strings must be NUL-terminated UTF-8; buffers must
/// be readable for their lengths. `callback` and `user_data` must remain valid
/// until the handle is freed, and all operations and `user_data` access must be
/// externally serialized.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_create_callback_v1(
    context: *mut C2paContext,
    manifest_json: *const c_char,
    algorithm: C2paSigningAlg,
    public_cose_key: *const c_uchar,
    public_cose_key_len: usize,
    kid: *const c_uchar,
    kid_len: usize,
    min_sequence_number: u64,
    created_at: *const c_char,
    validity_period_secs: u64,
    options_json: *const c_char,
    user_data: *mut c_void,
    callback: C2paLiveVideoTrustedVsiSignCallbackV1,
) -> *mut C2paLiveVideoTrustedVsiSession {
    let Some(callback) = callback else {
        CimplError::null_parameter("callback").set_last();
        return std::ptr::null_mut();
    };
    let context = deref_or_return_null!(context, C2paContext);
    let manifest_json = cstr_or_return_null!(manifest_json);
    let public_cose_key =
        bytes_or_return_null!(public_cose_key, public_cose_key_len, "public_cose_key");
    let kid = bytes_or_return_null!(kid, kid_len, "kid");
    let created_at = cstr_or_return_null!(created_at);
    let options_json = cstr_or_return_null!(options_json);
    let algorithm: SigningAlg = algorithm.into();
    let options = ok_or_return_null!(TrustedVsiSessionOptions::from_json(&options_json));
    let config = VsiSessionConfig {
        algorithm,
        kid: kid.to_vec(),
        public_cose_key_cbor: public_cose_key.to_vec(),
        min_sequence_number,
        created_at,
        validity_period_secs,
    };
    let user_data = user_data as usize;
    let signer = move |context: &VsiSigningContextV1, tbs: &[u8]| -> c2pa::Result<Vec<u8>> {
        let c_context = C2paLiveVideoTrustedVsiSigningContextV1::from_rust(context);
        let mut signature = [0u8; 64];
        let written = unsafe {
            callback(
                user_data as *mut c_void,
                &c_context,
                tbs.as_ptr(),
                tbs.len(),
                signature.as_mut_ptr(),
                signature.len(),
            )
        };
        let written = usize::try_from(written).map_err(|_| {
            c2pa::Error::BadParam(format!(
                "trusted VSI signing callback returned error code {written}"
            ))
        })?;
        if written > signature.len() {
            return Err(c2pa::Error::BadParam(format!(
                "trusted VSI signing callback reported {written} bytes, exceeding capacity 64"
            )));
        }
        Ok(signature[..written].to_vec())
    };
    let session = ok_or_return_null!(
        TrustedVsiPrehashedSession::from_shared_context_with_callback(
            &context,
            manifest_json,
            config,
            options,
            signer,
        )
    );
    box_tracked!(C2paLiveVideoTrustedVsiSession { session })
}

/// Reserves (or returns the existing) initialization UUID box for `format`
/// (`"mp4"` or `"video/mp4"`). Signs nothing. Returns the length or -1; bytes
/// are owned by the caller and released with `c2pa_free()`.
///
/// # Safety
///
/// `output` must point to writable pointer storage; the session must be tracked
/// and `format` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_reserve_init_uuid(
    session: *mut C2paLiveVideoTrustedVsiSession,
    format: *const c_char,
    output: *mut *const c_uchar,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    ptr_or_return_int!(output);
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    let format = cstr_or_return_int!(format);
    let reservation = ok_or_return_int!(session.session.reserve_init_uuid(&format));
    write_trusted_vsi_bytes(output, reservation.bytes().to_vec())
}

/// Returns the reserved manifest ID, or NULL on error. Release the returned
/// string with `c2pa_free()` (or `c2pa_string_free()`).
///
/// # Safety
///
/// The session must be a live tracked trusted-VSI handle.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_reserved_manifest_id(
    session: *const C2paLiveVideoTrustedVsiSession,
) -> *mut c_char {
    let session = deref_or_return_null!(session.cast_mut(), C2paLiveVideoTrustedVsiSession);
    let manifest_id = ok_or_return_null!(session.session.reserved_manifest_id());
    to_c_string(manifest_id.to_string())
}

/// Finalizes the reserved UUID with the exact canonical init bmff-hash map.
/// Invokes the signer-binding callback, the Context claim signer, and its DAs.
/// Identical retries replay the signed bytes. Returns the length or -1.
///
/// # Safety
///
/// `data` must be readable for `len` bytes and `output` writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_finalize_init_uuid(
    session: *mut C2paLiveVideoTrustedVsiSession,
    data: *const c_uchar,
    len: usize,
    output: *mut *const c_uchar,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    ptr_or_return_int!(output);
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    let data = bytes_or_return_int!(data, len, "canonical_bmff_hash");
    let signed = ok_or_return_int!(session.session.finalize_init_uuid(data));
    write_trusted_vsi_bytes(output, signed)
}

/// Activates the finalized initialization after durable coordinator storage.
/// This is not a publication acknowledgement. Returns 0 or -1.
///
/// # Safety
///
/// The session must be a live tracked trusted-VSI handle.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_commit_init_uuid(
    session: *mut C2paLiveVideoTrustedVsiSession,
) -> c_int {
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    ok_or_return_int!(session.session.commit_init_uuid());
    0
}

/// Signs an exact caller-composed COSE Sig_structure without reconstruction.
///
/// `sequence_number` is trusted processor metadata passed unchanged to the
/// callback; no counter is kept and the payload is not decoded. Returns the
/// 64-byte signature length or -1; bytes are released with `c2pa_free()`.
///
/// # Safety
///
/// `data` must be readable for `len` bytes and `output` writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_sign_sig_structure(
    session: *mut C2paLiveVideoTrustedVsiSession,
    data: *const c_uchar,
    len: usize,
    sequence_number: u32,
    output: *mut *const c_uchar,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    ptr_or_return_int!(output);
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    let data = bytes_or_return_int!(data, len, "sig_structure");
    let signature = ok_or_return_int!(session.session.sign_sig_structure(data, sequence_number));
    write_trusted_vsi_bytes(output, signature)
}

/// Reserves a complete placeholder media EMSG for the supplied sequence and
/// writes its callback metadata (with the allocated event ID). Signs nothing.
/// Returns the EMSG length or -1.
///
/// # Safety
///
/// `output` and `signing_context` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
    session: *mut C2paLiveVideoTrustedVsiSession,
    sequence_number: u32,
    iat: i64,
    timescale: u32,
    event_duration: u32,
    output: *mut *const c_uchar,
    signing_context: *mut C2paLiveVideoTrustedVsiSigningContextV1,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    if !signing_context.is_null() {
        *signing_context = C2paLiveVideoTrustedVsiSigningContextV1::empty();
    }
    ptr_or_return_int!(output);
    ptr_or_return_int!(signing_context);
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    let reservation = ok_or_return_int!(session.session.reserve_media_emsg_at(
        sequence_number,
        iat,
        timescale,
        event_duration,
    ));
    let len = write_trusted_vsi_bytes(output, reservation.bytes().to_vec());
    if len >= 0 {
        *signing_context =
            C2paLiveVideoTrustedVsiSigningContextV1::from_rust(reservation.signing_context());
    }
    len
}

/// Finalizes the pending EMSG with the exact canonical media bmff-hash map.
/// Returns the complete signed EMSG length (equal to the reservation) or -1.
///
/// # Safety
///
/// `data` must be readable for `len` bytes and `output` writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_finalize_media_emsg(
    session: *mut C2paLiveVideoTrustedVsiSession,
    data: *const c_uchar,
    len: usize,
    output: *mut *const c_uchar,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    ptr_or_return_int!(output);
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    let data = bytes_or_return_int!(data, len, "canonical_bmff_hash");
    let signed = ok_or_return_int!(session.session.finalize_media_emsg(data));
    write_trusted_vsi_bytes(output, signed)
}

/// Exports the explicit versioned state record (UTF-8 JSON bytes).
/// Returns its length or -1; release with `c2pa_free()`.
///
/// # Safety
///
/// `output` must be writable and the session tracked.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_export_state(
    session: *const C2paLiveVideoTrustedVsiSession,
    output: *mut *const c_uchar,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    ptr_or_return_int!(output);
    let session = deref_or_return_int!(session.cast_mut(), C2paLiveVideoTrustedVsiSession);
    let state = ok_or_return_int!(session.session.export_state());
    write_trusted_vsi_bytes(output, state)
}

/// Imports a state record into a new, unused session with identical identity.
/// Validates before mutation. Returns 0 or -1.
///
/// # Safety
///
/// `data` must be readable for `len` bytes and the session tracked.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_import_state(
    session: *mut C2paLiveVideoTrustedVsiSession,
    data: *const c_uchar,
    len: usize,
) -> c_int {
    let mut session = deref_mut_or_return_int!(session, C2paLiveVideoTrustedVsiSession);
    let data = bytes_or_return_int!(data, len, "state");
    ok_or_return_int!(session.session.import_state(data));
    0
}

/// Writes the public state of a prehashed trusted VSI session. Returns 0 or -1.
///
/// # Safety
///
/// `status` must point to writable [`C2paLiveVideoTrustedVsiStatusV1`] storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_status_v1(
    session: *const C2paLiveVideoTrustedVsiSession,
    status: *mut C2paLiveVideoTrustedVsiStatusV1,
) -> c_int {
    if !status.is_null() {
        *status = C2paLiveVideoTrustedVsiStatusV1::default();
    }
    ptr_or_return_int!(status);
    let session = deref_or_return_int!(session.cast_mut(), C2paLiveVideoTrustedVsiSession);
    let rust = ok_or_return_int!(session.session.status());
    *status = C2paLiveVideoTrustedVsiStatusV1 {
        init_uuid_committed: rust.init_uuid_committed(),
        init_uuid_pending: rust.init_uuid_pending(),
        media_emsg_pending: rust.media_emsg_pending(),
        has_next_sequence_number: rust.next_sequence_number().is_some(),
        next_sequence_number: rust.next_sequence_number().unwrap_or(0),
        has_next_event_id: rust.next_event_id().is_some(),
        next_event_id: rust.next_event_id().unwrap_or(0),
        exhausted: rust.exhausted(),
        has_exhaustion_reason: rust.exhaustion_reason().is_some(),
        blocked: rust.blocked(),
        exhaustion_reason: match rust.exhaustion_reason() {
            None => C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_NONE,
            Some(TrustedVsiExhaustionReason::SequenceMax) => {
                C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_SEQUENCE_MAX
            }
            Some(TrustedVsiExhaustionReason::EventIdMax) => {
                C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_EVENT_ID_MAX
            }
            Some(TrustedVsiExhaustionReason::LegacySentinel) => {
                C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_LEGACY_SENTINEL
            }
        },
    };
    0
}

/// Statically validates a trusted VSI input without a session, key, or
/// callback. `algorithm` applies to Sig_structure inputs. Returns 0 or -1.
///
/// # Safety
///
/// `data` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_validate_input(
    kind: u32,
    algorithm: C2paSigningAlg,
    data: *const c_uchar,
    len: usize,
) -> c_int {
    let data = bytes_or_return_int!(data, len, "data");
    let kind = ok_or_return_int!(TrustedVsiInputKind::from_u32(kind));
    ok_or_return_int!(c2pa::live_video::validate_trusted_vsi_input(
        kind,
        algorithm.into(),
        data,
    ));
    0
}

/// Writes the canonical zero-digest bmff-hash template for a hash input kind.
/// Returns its length or -1; release with `c2pa_free()`.
///
/// # Safety
///
/// `output` must be writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_hash_template(
    kind: u32,
    output: *mut *const c_uchar,
) -> i64 {
    clear_trusted_vsi_bytes(output);
    ptr_or_return_int!(output);
    let kind = ok_or_return_int!(TrustedVsiInputKind::from_u32(kind));
    let template = ok_or_return_int!(c2pa::live_video::trusted_vsi_hash_template(kind));
    write_trusted_vsi_bytes(output, template)
}

/// Checks whether `operation` would be accepted now with the supplied inputs.
/// No callback, key use, reservation generation, or mutation. `(NULL, 0)` data
/// and a NULL `format` are accepted as empty. Returns 0 or -1.
///
/// # Safety
///
/// Non-null `data` must be readable for `len` bytes and `format` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_trusted_vsi_session_preflight(
    session: *const C2paLiveVideoTrustedVsiSession,
    operation: u32,
    data: *const c_uchar,
    len: usize,
    sequence_number: u32,
    iat: i64,
    timescale: u32,
    event_duration: u32,
    format: *const c_char,
) -> c_int {
    let session = deref_or_return_int!(session.cast_mut(), C2paLiveVideoTrustedVsiSession);
    let Ok(data) = optional_trusted_vsi_bytes(data, len, "data") else {
        return -1;
    };
    let format = if format.is_null() {
        String::new()
    } else {
        cstr_or_return_int!(format)
    };
    let operation = ok_or_return_int!(TrustedVsiOperation::from_u32(operation));
    ok_or_return_int!(session.session.preflight(
        operation,
        data,
        sequence_number,
        iat,
        timescale,
        event_duration,
        &format,
    ));
    0
}

/// Reads the ISO BMFF `moof/mfhd.sequence_number` from one media segment.
///
/// The output is a `u32` because ISO/IEC 14496-12 defines the field as an
/// unsigned 32-bit integer. Returns zero on success or -1 on failure. When
/// `sequence_number` is non-null, it is set to zero before input validation and
/// remains zero on failure. No live-video session, key, callback, or allocation
/// is involved.
///
/// # Safety
///
/// `media_segment` must point to a readable buffer of exactly
/// `media_segment_len` bytes, and `sequence_number` must point to writable
/// `u32` storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_moof_sequence_number(
    media_segment: *const c_uchar,
    media_segment_len: usize,
    sequence_number: *mut u32,
) -> c_int {
    ptr_or_return_int!(sequence_number);
    *sequence_number = 0;
    let media_segment = bytes_or_return_int!(media_segment, media_segment_len, "media_segment");
    let parsed = ok_or_return_int!(c2pa::live_video::moof_sequence_number(media_segment)
        .ok_or_else(|| c2pa::Error::BadParam(
            "media segment must contain exactly one moof/traf and a valid mfhd".to_string()
        )));
    *sequence_number = parsed;
    0
}

/// Creates a stateful local Ed25519 VSI signing session.
///
/// The context is borrowed and retained internally. It must have a manifest signer configured.
/// The 32-byte seed and non-empty binary `kid` are copied. The returned handle must be released
/// with `c2pa_free()`.
///
/// # Safety
///
/// `context` must be a tracked C2PA context. `manifest_json` must be a null-terminated UTF-8
/// string. `seed` and `kid` must point to readable buffers of their declared lengths.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_create_ed25519(
    context: *mut C2paContext,
    manifest_json: *const c_char,
    seed: *const c_uchar,
    seed_len: usize,
    kid: *const c_uchar,
    kid_len: usize,
    min_sequence_number: u64,
    validity_period_secs: u64,
) -> *mut C2paLiveVideoVsiSigner {
    let context = deref_or_return_null!(context, C2paContext);
    let manifest_json = cstr_or_return_null!(manifest_json);
    let seed = bytes_or_return_null!(seed, seed_len, "seed");
    let kid = bytes_or_return_null!(kid, kid_len, "kid");

    let mut seed: [u8; 32] = ok_or_return_null!(seed.try_into().map_err(|_| {
        c2pa::Error::BadParam(format!(
            "Ed25519 seed must contain exactly 32 bytes, got {}",
            seed.len()
        ))
    }));
    let session_key = Ed25519SessionKey::from_bytes(&seed);
    seed.zeroize();
    let signer = ok_or_return_null!(LiveVideoVsiSigner::from_shared_context(
        &context,
        manifest_json,
        session_key,
        kid.to_vec(),
        min_sequence_number,
        validity_period_secs,
    ));
    box_tracked!(C2paLiveVideoVsiSigner { signer })
}

/// Creates a callback-backed Ed25519 or ES256 VSI signing session.
///
/// `public_cose_key` is a CBOR-encoded public COSE_Key. Its algorithm and
/// non-empty binary `kid` must agree with `algorithm` and `kid`. `created_at`
/// is an RFC 3339 value copied exactly into the session-key assertion.
///
/// The callback and `user_data` remain caller-owned and must stay valid until
/// the returned handle is freed. Calls are synchronous on the invoking thread.
/// The caller must externally serialize all operations on this handle and any
/// access to `user_data`. The callback must not throw or unwind across the C ABI.
/// It receives the exact COSE Sig_structure, including for `signerBinding`
/// rather than the bare end-entity certificate.
/// Its sequence is the actual media sequence for `Vsi` and
/// `C2PA_LIVE_VIDEO_VSI_NO_SEQUENCE` for `SignerBinding`.
/// The returned handle must be released with `c2pa_free()`.
///
/// # Safety
///
/// `context` must be tracked. All pointer/length inputs must remain readable for
/// this call. `callback` and `user_data` must satisfy the lifetime and threading
/// contract above.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_create_callback(
    context: *mut C2paContext,
    manifest_json: *const c_char,
    algorithm: C2paSigningAlg,
    public_cose_key: *const c_uchar,
    public_cose_key_len: usize,
    kid: *const c_uchar,
    kid_len: usize,
    min_sequence_number: u64,
    created_at: *const c_char,
    validity_period_secs: u64,
    user_data: *mut c_void,
    callback: Option<C2paLiveVideoVsiSignCallback>,
) -> *mut C2paLiveVideoVsiSigner {
    let Some(callback) = callback else {
        CimplError::null_parameter("callback").set_last();
        return std::ptr::null_mut();
    };
    let context = deref_or_return_null!(context, C2paContext);
    let manifest_json = cstr_or_return_null!(manifest_json);
    let public_cose_key =
        bytes_or_return_null!(public_cose_key, public_cose_key_len, "public_cose_key");
    let kid = bytes_or_return_null!(kid, kid_len, "kid");
    let created_at = cstr_or_return_null!(created_at);
    let algorithm: SigningAlg = algorithm.into();
    if !matches!(algorithm, SigningAlg::Ed25519 | SigningAlg::Es256) {
        CimplError::from(c2pa::Error::BadParam(
            "VSI callback signing supports only Ed25519 and ES256".to_string(),
        ))
        .set_last();
        return std::ptr::null_mut();
    }

    let config = VsiSessionConfig {
        algorithm,
        kid: kid.to_vec(),
        public_cose_key_cbor: public_cose_key.to_vec(),
        min_sequence_number,
        created_at,
        validity_period_secs,
    };
    let session_signer = FfiVsiSessionSigner {
        callback,
        user_data: user_data as usize,
    };
    let signer = ok_or_return_null!(LiveVideoVsiSigner::from_shared_context_with_session_signer(
        &context,
        manifest_json,
        config,
        session_signer,
    ));
    box_tracked!(C2paLiveVideoVsiSigner { signer })
}

/// Signs an initialization segment and establishes this session's manifest ID and track timing.
///
/// The returned byte buffer is tracked and must be released with `c2pa_free()`.
///
/// # Safety
///
/// `signer` must be a valid live-video handle. `init_segment` and `format` must remain readable
/// for this call. `signed_segment` must point to writable pointer storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_sign_init_segment(
    signer: *mut C2paLiveVideoVsiSigner,
    init_segment: *const c_uchar,
    init_segment_len: usize,
    format: *const c_char,
    signed_segment: *mut *const c_uchar,
) -> i64 {
    let mut signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
    let init_segment = bytes_or_return_int!(init_segment, init_segment_len, "init_segment");
    let format = cstr_or_return_int!(format);
    ptr_or_return_int!(signed_segment);
    *signed_segment = std::ptr::null();

    let signed = ok_or_return_int!(signer
        .signer
        .sign_init_segment_with_context(init_segment, &format));
    let len = ok_or_return_int!(i64::try_from(signed.len()).map_err(|_| {
        c2pa::Error::BadParam("signed initialization segment is too large".to_string())
    }));
    *signed_segment = to_c_bytes(signed);
    len
}

/// Signs one media segment and advances the session counter exactly once on success.
///
/// The returned byte buffer is tracked and must be released with `c2pa_free()`.
///
/// # Safety
///
/// `signer` must be a valid live-video handle. `media_segment` must remain readable for this
/// call. `signed_segment` must point to writable pointer storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_sign_media_segment(
    signer: *mut C2paLiveVideoVsiSigner,
    media_segment: *const c_uchar,
    media_segment_len: usize,
    signed_segment: *mut *const c_uchar,
) -> i64 {
    let mut signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
    let media_segment = bytes_or_return_int!(media_segment, media_segment_len, "media_segment");
    ptr_or_return_int!(signed_segment);
    *signed_segment = std::ptr::null();

    let signed = ok_or_return_int!(signer.signer.sign_media_segment(media_segment));
    let len = ok_or_return_int!(i64::try_from(signed.len())
        .map_err(|_| { c2pa::Error::BadParam("signed media segment is too large".to_string()) }));
    *signed_segment = to_c_bytes(signed);
    len
}

/// Signs one media segment at an explicit Unix timestamp and advances the
/// session counter exactly once on success.
///
/// The timestamp is encoded as the mandatory protected COSE `iat`, drives the
/// session-key validity check, and is included in the callback TBS. The returned
/// byte buffer is tracked and must be released with `c2pa_free()`.
///
/// # Safety
///
/// `signer` must be a valid live-video handle. `media_segment` must remain readable for this
/// call. `signed_segment` must point to writable pointer storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_sign_media_segment_at(
    signer: *mut C2paLiveVideoVsiSigner,
    media_segment: *const c_uchar,
    media_segment_len: usize,
    signing_time_unix_seconds: i64,
    signed_segment: *mut *const c_uchar,
) -> i64 {
    let mut signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
    let media_segment = bytes_or_return_int!(media_segment, media_segment_len, "media_segment");
    ptr_or_return_int!(signed_segment);
    *signed_segment = std::ptr::null();

    let signed = ok_or_return_int!(signer
        .signer
        .sign_media_segment_at(media_segment, signing_time_unix_seconds));
    let len = ok_or_return_int!(i64::try_from(signed.len())
        .map_err(|_| { c2pa::Error::BadParam("signed media segment is too large".to_string()) }));
    *signed_segment = to_c_bytes(signed);
    len
}

/// Recovers a VSI session from previously published signed artifacts.
///
/// The signed init is mandatory. Pass `previous_media_segment = NULL` and
/// `previous_media_segment_len = 0` for init-only recovery; otherwise both must
/// describe the complete last published media segment. All artifacts are
/// cryptographically and structurally validated before state is accepted. The
/// signing callback is not invoked. Init-only recovery is valid only before any
/// media segment from this session has been published; it restores the initial
/// sequence/event counters and would otherwise permit sequence reuse. Durable
/// callers must provide the last committed media artifact or refuse recovery
/// when publication state is unknown. Returns zero on success or -1 on failure.
///
/// # Safety
///
/// `signer` must be a tracked live-video handle. Required pointer/length pairs
/// and `format` must remain readable for this call. The optional previous-media
/// pair must be either exactly `(NULL, 0)` or a non-null, non-empty buffer.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_recover(
    signer: *mut C2paLiveVideoVsiSigner,
    signed_init_segment: *const c_uchar,
    signed_init_segment_len: usize,
    previous_media_segment: *const c_uchar,
    previous_media_segment_len: usize,
    format: *const c_char,
) -> c_int {
    let mut signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
    let signed_init_segment = bytes_or_return_int!(
        signed_init_segment,
        signed_init_segment_len,
        "signed_init_segment"
    );
    let previous_media_segment =
        if previous_media_segment.is_null() && previous_media_segment_len == 0 {
            None
        } else {
            Some(bytes_or_return_int!(
                previous_media_segment,
                previous_media_segment_len,
                "previous_media_segment"
            ))
        };
    let format = cstr_or_return_int!(format);

    ok_or_return_int!(signer.signer.recover_from_artifacts(
        signed_init_segment,
        previous_media_segment,
        &format,
    ));
    0
}

/// Writes the sequence number that will be assigned to the next media segment.
///
/// # Safety
///
/// `signer` must be a valid live-video handle and `next_sequence_number` must be writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_next_sequence_number(
    signer: *mut C2paLiveVideoVsiSigner,
    next_sequence_number: *mut u64,
) -> c_int {
    let signer = deref_or_return_int!(signer, C2paLiveVideoVsiSigner);
    ptr_or_return_int!(next_sequence_number);
    *next_sequence_number = signer.signer.next_sequence_number();
    0
}

/// Returns the active signed initialization manifest ID, if one has been established.
///
/// On success before init signing, `manifest_id` is set to null. A non-null returned string is
/// tracked and must be released with `c2pa_free()`.
///
/// # Safety
///
/// `signer` must be a valid live-video handle and `manifest_id` must be writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_live_video_vsi_signer_active_manifest_id(
    signer: *mut C2paLiveVideoVsiSigner,
    manifest_id: *mut *mut c_char,
) -> c_int {
    let signer = deref_or_return_int!(signer, C2paLiveVideoVsiSigner);
    ptr_or_return_int!(manifest_id);
    *manifest_id = signer
        .signer
        .active_manifest_id()
        .map(|id| to_c_string(id.to_string()))
        .unwrap_or(std::ptr::null_mut());
    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::{CStr, CString};

    use p256::ecdsa::signature::Signer as _;

    use super::*;
    use crate::c_api::{
        c2pa_context_builder_build, c2pa_context_builder_new, c2pa_context_builder_set_settings,
        c2pa_context_builder_set_signer, c2pa_free, c2pa_settings_new, c2pa_settings_set_value,
        c2pa_signer_from_info, C2paSignerInfo,
    };

    macro_rules! fixture_path {
        ($path:expr) => {
            concat!("../../sdk/tests/fixtures/", $path)
        };
    }

    unsafe fn test_context() -> *mut C2paContext {
        let alg = CString::new("Ed25519").unwrap();
        let cert = CString::new(include_str!(fixture_path!("certs/ed25519.pub"))).unwrap();
        let key = CString::new(include_bytes!(fixture_path!("certs/ed25519.pem"))).unwrap();
        let info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: cert.as_ptr(),
            private_key: key.as_ptr(),
            ta_url: std::ptr::null(),
        };
        let manifest_signer = c2pa_signer_from_info(&info);
        assert!(!manifest_signer.is_null());
        let builder = c2pa_context_builder_new();
        let settings = c2pa_settings_new();
        let path = CString::new("verify.verify_trust").unwrap();
        let value = CString::new("false").unwrap();
        assert_eq!(
            c2pa_settings_set_value(settings, path.as_ptr(), value.as_ptr()),
            0
        );
        assert_eq!(c2pa_context_builder_set_settings(builder, settings), 0);
        assert_eq!(c2pa_free(settings.cast()), 0);
        assert_eq!(c2pa_context_builder_set_signer(builder, manifest_signer), 0);
        c2pa_context_builder_build(builder)
    }

    unsafe fn test_live_signer(
        context: *mut C2paContext,
        min_sequence: u64,
    ) -> *mut C2paLiveVideoVsiSigner {
        let manifest = CString::new(
            r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
        )
        .unwrap();
        let seed = [7u8; 32];
        let kid = b"ffi-session-key";
        c2pa_live_video_vsi_signer_create_ed25519(
            context,
            manifest.as_ptr(),
            seed.as_ptr(),
            seed.len(),
            kid.as_ptr(),
            kid.len(),
            min_sequence,
            3600,
        )
    }

    #[derive(Clone, Copy)]
    enum CallbackMode {
        Valid,
        Error,
        Oversized,
        Short,
        Corrupt,
    }

    struct CallbackState {
        signing_key: p256::ecdsa::SigningKey,
        mode: CallbackMode,
        observations: Vec<(C2paLiveVideoVsiSigningPurpose, u64, usize)>,
    }

    unsafe extern "C" fn es256_callback(
        user_data: *mut c_void,
        purpose: C2paLiveVideoVsiSigningPurpose,
        sequence_number: u64,
        tbs: *const c_uchar,
        tbs_len: usize,
        signature: *mut c_uchar,
        signature_capacity: usize,
    ) -> isize {
        let state = unsafe { &mut *(user_data.cast::<CallbackState>()) };
        state
            .observations
            .push((purpose, sequence_number, signature_capacity));
        if matches!(state.mode, CallbackMode::Error) {
            return -7;
        }
        if matches!(state.mode, CallbackMode::Oversized) {
            return isize::try_from(signature_capacity + 1).unwrap();
        }

        let tbs = unsafe { std::slice::from_raw_parts(tbs, tbs_len) };
        let signature_value: p256::ecdsa::Signature = state.signing_key.sign(tbs);
        let mut output = signature_value.to_bytes().to_vec();
        match state.mode {
            CallbackMode::Short => output.truncate(63),
            CallbackMode::Corrupt => output.fill(0),
            CallbackMode::Valid | CallbackMode::Error | CallbackMode::Oversized => {}
        }
        if output.len() > signature_capacity {
            return isize::try_from(output.len()).unwrap();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(output.as_ptr(), signature, output.len());
        }
        isize::try_from(output.len()).unwrap()
    }

    fn es256_public_cose_key(signing_key: &p256::ecdsa::SigningKey, kid: &[u8]) -> Vec<u8> {
        let point = signing_key.verifying_key().to_encoded_point(false);
        let mut map = std::collections::BTreeMap::new();
        map.insert(c2pa_cbor::Value::Integer(1), c2pa_cbor::Value::Integer(2));
        map.insert(
            c2pa_cbor::Value::Integer(2),
            c2pa_cbor::Value::Bytes(kid.to_vec()),
        );
        map.insert(c2pa_cbor::Value::Integer(3), c2pa_cbor::Value::Integer(-7));
        map.insert(c2pa_cbor::Value::Integer(-1), c2pa_cbor::Value::Integer(1));
        map.insert(
            c2pa_cbor::Value::Integer(-2),
            c2pa_cbor::Value::Bytes(point.x().unwrap().to_vec()),
        );
        map.insert(
            c2pa_cbor::Value::Integer(-3),
            c2pa_cbor::Value::Bytes(point.y().unwrap().to_vec()),
        );
        c2pa_cbor::to_vec(&c2pa_cbor::Value::Map(map)).unwrap()
    }

    unsafe fn test_callback_live_signer(
        context: *mut C2paContext,
        min_sequence: u64,
        state: &mut CallbackState,
    ) -> *mut C2paLiveVideoVsiSigner {
        let manifest = CString::new(
            r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
        )
        .unwrap();
        let kid = b"ffi-es256-session";
        let cose_key = es256_public_cose_key(&state.signing_key, kid);
        let created_at = CString::new("2020-01-01T00:00:00Z").unwrap();
        unsafe {
            c2pa_live_video_vsi_signer_create_callback(
                context,
                manifest.as_ptr(),
                C2paSigningAlg::Es256,
                cose_key.as_ptr(),
                cose_key.len(),
                kid.as_ptr(),
                kid.len(),
                min_sequence,
                created_at.as_ptr(),
                1_000_000_000,
                std::ptr::from_mut(state).cast(),
                Some(es256_callback),
            )
        }
    }

    fn next_media_sequence(mut media: Vec<u8>, sequence_number: u32) -> Vec<u8> {
        let mfhd = media.windows(4).position(|bytes| bytes == b"mfhd").unwrap();
        media[mfhd + 8..mfhd + 12].copy_from_slice(&sequence_number.to_be_bytes());
        media
    }

    fn bmff_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&u32::try_from(8 + payload.len()).unwrap().to_be_bytes());
        data.extend_from_slice(box_type);
        data.extend_from_slice(payload);
        data
    }

    fn probe_media_segment(sequence_number: u32) -> Vec<u8> {
        let mut mfhd_payload = vec![0; 4];
        mfhd_payload.extend_from_slice(&sequence_number.to_be_bytes());
        let mfhd = bmff_box(b"mfhd", &mfhd_payload);
        let traf = bmff_box(b"traf", &[]);
        bmff_box(b"moof", &[mfhd, traf].concat())
    }

    #[test]
    fn ffi_moof_sequence_probe_reads_nonzero_fixture() {
        let media = include_bytes!(fixture_path!("bunny/bunny_791182bps/BigBuckBunny_2s5.m4s"));
        let expected = c2pa::live_video::moof_sequence_number(media).unwrap();
        assert_ne!(expected, 0);
        let mut sequence_number = 0;

        assert_eq!(
            unsafe {
                c2pa_live_video_moof_sequence_number(
                    media.as_ptr(),
                    media.len(),
                    &mut sequence_number,
                )
            },
            0
        );
        assert_eq!(sequence_number, expected);

        let media = probe_media_segment(37);
        assert_eq!(
            unsafe {
                c2pa_live_video_moof_sequence_number(
                    media.as_ptr(),
                    media.len(),
                    &mut sequence_number,
                )
            },
            0
        );
        assert_eq!(sequence_number, 37);

        let media = probe_media_segment(0);
        sequence_number = 99;
        assert_eq!(
            unsafe {
                c2pa_live_video_moof_sequence_number(
                    media.as_ptr(),
                    media.len(),
                    &mut sequence_number,
                )
            },
            0
        );
        assert_eq!(sequence_number, 0);
    }

    #[derive(Clone, Copy, PartialEq)]
    enum TrustedMode {
        Valid,
        Error,
    }

    struct TrustedCallbackState {
        signing_key: p256::ecdsa::SigningKey,
        mode: TrustedMode,
        observations: Vec<C2paLiveVideoTrustedVsiSigningContextV1>,
    }

    unsafe extern "C" fn trusted_vsi_callback_v1(
        user_data: *mut c_void,
        context: *const C2paLiveVideoTrustedVsiSigningContextV1,
        tbs: *const c_uchar,
        tbs_len: usize,
        signature: *mut c_uchar,
        signature_capacity: usize,
    ) -> isize {
        let state = unsafe { &mut *user_data.cast::<TrustedCallbackState>() };
        state.observations.push(unsafe { *context });
        assert_eq!(signature_capacity, 64);
        if state.mode == TrustedMode::Error {
            return -3;
        }
        let tbs = unsafe { std::slice::from_raw_parts(tbs, tbs_len) };
        let value: p256::ecdsa::Signature = state.signing_key.sign(tbs);
        let bytes = value.to_bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), signature, bytes.len()) };
        isize::try_from(bytes.len()).unwrap()
    }

    const TRUSTED_KID: &[u8] = b"ffi-trusted-session";
    const TRUSTED_NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn trusted_state(mode: TrustedMode) -> Box<TrustedCallbackState> {
        Box::new(TrustedCallbackState {
            signing_key: p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap(),
            mode,
            observations: Vec::new(),
        })
    }

    unsafe fn trusted_session(
        context: *mut C2paContext,
        mode: &str,
        state: &mut TrustedCallbackState,
    ) -> *mut C2paLiveVideoTrustedVsiSession {
        let manifest = CString::new(
            r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
        )
        .unwrap();
        let cose_key = es256_public_cose_key(&state.signing_key, TRUSTED_KID);
        let created_at = CString::new("2020-01-01T00:00:00Z").unwrap();
        let options = CString::new(format!(
            r#"{{"mode":"{mode}","reservation_nonce":"{TRUSTED_NONCE}","signing_time_unix_seconds":1700000000}}"#
        ))
        .unwrap();
        unsafe {
            c2pa_live_video_trusted_vsi_session_create_callback_v1(
                context,
                manifest.as_ptr(),
                C2paSigningAlg::Es256,
                cose_key.as_ptr(),
                cose_key.len(),
                TRUSTED_KID.as_ptr(),
                TRUSTED_KID.len(),
                1,
                created_at.as_ptr(),
                1_000_000_000,
                options.as_ptr(),
                std::ptr::from_mut(state).cast(),
                Some(trusted_vsi_callback_v1),
            )
        }
    }

    unsafe fn take_bytes(ptr: *const c_uchar, len: i64) -> Vec<u8> {
        assert!(len >= 0, "{:?}", CimplError::last_message());
        assert!(!ptr.is_null());
        let bytes =
            unsafe { std::slice::from_raw_parts(ptr, usize::try_from(len).unwrap()) }.to_vec();
        assert_eq!(unsafe { c2pa_free(ptr.cast()) }, 0);
        bytes
    }

    unsafe fn trusted_template(kind: u32) -> Vec<u8> {
        let mut output = std::ptr::null();
        let len = unsafe { c2pa_live_video_trusted_vsi_hash_template(kind, &mut output) };
        unsafe { take_bytes(output, len) }
    }

    /// Reserves, finalizes (with the canonical zero-digest template), and commits.
    unsafe fn trusted_establish_init(session: *mut C2paLiveVideoTrustedVsiSession) {
        let format = CString::new("video/mp4").unwrap();
        let mut output = std::ptr::null();
        let len = unsafe {
            c2pa_live_video_trusted_vsi_session_reserve_init_uuid(
                session,
                format.as_ptr(),
                &mut output,
            )
        };
        let reserved = unsafe { take_bytes(output, len) };
        let id = unsafe { c2pa_live_video_trusted_vsi_session_reserved_manifest_id(session) };
        assert!(!id.is_null());
        assert!(unsafe { CStr::from_ptr(id) }
            .to_str()
            .unwrap()
            .starts_with("urn:"));
        assert_eq!(unsafe { c2pa_free(id.cast()) }, 0);
        let hash = unsafe { trusted_template(C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_INIT_HASH) };
        output = std::ptr::null();
        let len = unsafe {
            c2pa_live_video_trusted_vsi_session_finalize_init_uuid(
                session,
                hash.as_ptr(),
                hash.len(),
                &mut output,
            )
        };
        let signed = unsafe { take_bytes(output, len) };
        assert_eq!(signed.len(), reserved.len());
        assert_eq!(
            unsafe { c2pa_live_video_trusted_vsi_session_commit_init_uuid(session) },
            0
        );
    }

    /// `["Signature1", << {1: -7} >>, h'', 'test']`
    fn es256_sig_structure() -> Vec<u8> {
        let mut data = vec![0x84, 0x6a];
        data.extend_from_slice(b"Signature1");
        data.extend_from_slice(&[0x43, 0xa1, 0x01, 0x26, 0x40, 0x44]);
        data.extend_from_slice(b"test");
        data
    }

    unsafe fn trusted_status(
        session: *const C2paLiveVideoTrustedVsiSession,
    ) -> C2paLiveVideoTrustedVsiStatusV1 {
        let mut status = C2paLiveVideoTrustedVsiStatusV1::default();
        assert_eq!(
            unsafe { c2pa_live_video_trusted_vsi_session_status_v1(session, &mut status) },
            0
        );
        status
    }

    unsafe fn trusted_export(session: *const C2paLiveVideoTrustedVsiSession) -> Vec<u8> {
        let mut output = std::ptr::null();
        let len = unsafe { c2pa_live_video_trusted_vsi_session_export_state(session, &mut output) };
        unsafe { take_bytes(output, len) }
    }

    #[test]
    fn ffi_trusted_vsi_capabilities_are_fully_wired() {
        assert_eq!(c2pa_live_video_trusted_vsi_capabilities(), 63);
    }

    #[test]
    fn ffi_trusted_vsi_create_rejects_invalid_inputs_without_callback() {
        unsafe {
            let context = test_context();
            let mut state = trusted_state(TrustedMode::Valid);
            let manifest = CString::new("{}").unwrap();
            let created_at = CString::new("2020-01-01T00:00:00Z").unwrap();
            let cose_key = es256_public_cose_key(&state.signing_key, TRUSTED_KID);
            let bad_options = [
                r#"{"mode":"expert_sig_structure"}"#.to_string(),
                format!(r#"{{"mode":"nope","reservation_nonce":"{TRUSTED_NONCE}","signing_time_unix_seconds":1700000000}}"#),
                format!(r#"{{"mode":"expert_sig_structure","reservation_nonce":"{TRUSTED_NONCE}","signing_time_unix_seconds":1700000000,"extra":1}}"#),
                r#"{"mode":"expert_sig_structure","reservation_nonce":"0123456789ABCDEF0123456789ABCDEF","signing_time_unix_seconds":1700000000}"#.to_string(),
            ];
            for options in bad_options {
                let options = CString::new(options).unwrap();
                let session = c2pa_live_video_trusted_vsi_session_create_callback_v1(
                    context,
                    manifest.as_ptr(),
                    C2paSigningAlg::Es256,
                    cose_key.as_ptr(),
                    cose_key.len(),
                    TRUSTED_KID.as_ptr(),
                    TRUSTED_KID.len(),
                    1,
                    created_at.as_ptr(),
                    1_000_000_000,
                    options.as_ptr(),
                    std::ptr::from_mut(state.as_mut()).cast(),
                    Some(trusted_vsi_callback_v1),
                );
                assert!(session.is_null());
            }
            let session = c2pa_live_video_trusted_vsi_session_create_callback_v1(
                context,
                manifest.as_ptr(),
                C2paSigningAlg::Es256,
                cose_key.as_ptr(),
                cose_key.len(),
                TRUSTED_KID.as_ptr(),
                TRUSTED_KID.len(),
                1,
                created_at.as_ptr(),
                1_000_000_000,
                std::ptr::null(),
                std::ptr::from_mut(state.as_mut()).cast(),
                None,
            );
            assert!(session.is_null());
            assert!(state.observations.is_empty());
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_trusted_vsi_null_sessions_clear_outputs() {
        unsafe {
            let data = es256_sig_structure();
            let mut output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_sign_sig_structure(
                    std::ptr::null_mut(),
                    data.as_ptr(),
                    data.len(),
                    7,
                    &mut output,
                ),
                -1
            );
            assert!(output.is_null());
            let mut context = C2paLiveVideoTrustedVsiSigningContextV1 {
                purpose: 1,
                sequence_number: 9,
                has_sequence_number: true,
                event_id: 9,
                has_event_id: true,
                exhaust_after_sign: true,
            };
            output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
                    std::ptr::null_mut(),
                    1,
                    1,
                    1,
                    1,
                    &mut output,
                    &mut context,
                ),
                -1
            );
            assert!(output.is_null());
            assert_eq!(context, C2paLiveVideoTrustedVsiSigningContextV1::empty());
            // A NULL signing-context pointer is an error; output is still cleared.
            output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
                    std::ptr::null_mut(),
                    1,
                    1,
                    1,
                    1,
                    &mut output,
                    std::ptr::null_mut(),
                ),
                -1
            );
            assert!(output.is_null());
            let mut status = C2paLiveVideoTrustedVsiStatusV1 {
                blocked: true,
                exhausted: true,
                ..Default::default()
            };
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_status_v1(std::ptr::null(), &mut status),
                -1
            );
            assert_eq!(status, C2paLiveVideoTrustedVsiStatusV1::default());
            output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_export_state(std::ptr::null(), &mut output),
                -1
            );
            assert!(output.is_null());
            assert!(
                c2pa_live_video_trusted_vsi_session_reserved_manifest_id(std::ptr::null())
                    .is_null()
            );
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_commit_init_uuid(std::ptr::null_mut()),
                -1
            );
            // Required NULL output storage is an error.
            assert_eq!(
                c2pa_live_video_trusted_vsi_hash_template(
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_INIT_HASH,
                    std::ptr::null_mut(),
                ),
                -1
            );
            output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_hash_template(99, &mut output),
                -1
            );
            assert!(output.is_null());
        }
    }

    #[test]
    fn ffi_trusted_vsi_static_validation_and_templates() {
        unsafe {
            let data = es256_sig_structure();
            assert_eq!(
                c2pa_live_video_trusted_vsi_validate_input(
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_SIG_STRUCTURE,
                    C2paSigningAlg::Es256,
                    data.as_ptr(),
                    data.len(),
                ),
                0
            );
            assert_eq!(
                c2pa_live_video_trusted_vsi_validate_input(
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_SIG_STRUCTURE,
                    C2paSigningAlg::Ed25519,
                    data.as_ptr(),
                    data.len(),
                ),
                -1
            );
            let mut trailing = data.clone();
            trailing.push(0);
            assert_eq!(
                c2pa_live_video_trusted_vsi_validate_input(
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_SIG_STRUCTURE,
                    C2paSigningAlg::Es256,
                    trailing.as_ptr(),
                    trailing.len(),
                ),
                -1
            );
            for kind in [
                C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_INIT_HASH,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_MEDIA_HASH,
            ] {
                let template = trusted_template(kind);
                assert_eq!(
                    c2pa_live_video_trusted_vsi_validate_input(
                        kind,
                        C2paSigningAlg::Es256,
                        template.as_ptr(),
                        template.len(),
                    ),
                    0
                );
            }
            let init = trusted_template(C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_INIT_HASH);
            assert_eq!(
                c2pa_live_video_trusted_vsi_validate_input(
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_MEDIA_HASH,
                    C2paSigningAlg::Es256,
                    init.as_ptr(),
                    init.len(),
                ),
                -1
            );
            let mut output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_hash_template(
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_SIG_STRUCTURE,
                    &mut output,
                ),
                -1
            );
            assert!(output.is_null());
        }
    }

    #[test]
    fn ffi_trusted_vsi_expert_round_trip_blocking_and_prestate_retry() {
        unsafe {
            let context = test_context();
            let mut state = trusted_state(TrustedMode::Valid);
            let session = trusted_session(context, "expert_sig_structure", &mut state);
            assert!(!session.is_null(), "{:?}", CimplError::last_message());
            let data = es256_sig_structure();
            // Preflight performs no callback and no mutation.
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_preflight(
                    session,
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_RESERVE_INIT,
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    c"video/mp4".as_ptr(),
                ),
                0
            );
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_preflight(
                    session,
                    C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_EXPERT_SIGN,
                    data.as_ptr(),
                    data.len(),
                    5,
                    0,
                    0,
                    0,
                    std::ptr::null(),
                ),
                -1
            );
            assert!(state.observations.is_empty());

            trusted_establish_init(session);
            assert_eq!(state.observations.len(), 1);
            assert_eq!(
                state.observations[0],
                C2paLiveVideoTrustedVsiSigningContextV1::empty()
            );
            let status = trusted_status(session);
            assert!(status.init_uuid_committed && !status.blocked);
            assert!(!status.has_next_sequence_number && !status.has_next_event_id);

            // Composed-mode operations are rejected in expert mode.
            let mut output = std::ptr::null();
            let mut signing_context = C2paLiveVideoTrustedVsiSigningContextV1::empty();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
                    session,
                    1,
                    1_700_000_000,
                    1,
                    1,
                    &mut output,
                    &mut signing_context,
                ),
                -1
            );

            for sequence in [5, 2, u32::MAX] {
                output = std::ptr::null();
                let len = c2pa_live_video_trusted_vsi_session_sign_sig_structure(
                    session,
                    data.as_ptr(),
                    data.len(),
                    sequence,
                    &mut output,
                );
                assert_eq!(take_bytes(output, len).len(), 64);
                assert_eq!(
                    *state.observations.last().unwrap(),
                    C2paLiveVideoTrustedVsiSigningContextV1 {
                        purpose: C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_VSI,
                        sequence_number: sequence,
                        has_sequence_number: true,
                        event_id: 0,
                        has_event_id: false,
                        exhaust_after_sign: false,
                    }
                );
            }
            assert!(!trusted_status(session).exhausted);

            let pre_state = trusted_export(session);
            state.mode = TrustedMode::Error;
            output = std::ptr::dangling();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_sign_sig_structure(
                    session,
                    data.as_ptr(),
                    data.len(),
                    6,
                    &mut output,
                ),
                -1
            );
            assert!(output.is_null());
            assert!(trusted_status(session).blocked);
            state.mode = TrustedMode::Valid;
            let calls = state.observations.len();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_sign_sig_structure(
                    session,
                    data.as_ptr(),
                    data.len(),
                    6,
                    &mut output,
                ),
                -1
            );
            assert_eq!(state.observations.len(), calls);
            assert_ne!(trusted_export(session), pre_state);
            assert_eq!(c2pa_free(session.cast()), 0);

            // Retry: import the durable pre-operation record into a NEW session.
            let retry = trusted_session(context, "expert_sig_structure", &mut state);
            assert!(!retry.is_null());
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_import_state(
                    retry,
                    pre_state.as_ptr(),
                    pre_state.len(),
                ),
                0
            );
            // Import only into an unused session.
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_import_state(
                    retry,
                    pre_state.as_ptr(),
                    pre_state.len(),
                ),
                -1
            );
            assert!(trusted_status(retry).init_uuid_committed);
            output = std::ptr::null();
            let len = c2pa_live_video_trusted_vsi_session_sign_sig_structure(
                retry,
                data.as_ptr(),
                data.len(),
                6,
                &mut output,
            );
            assert_eq!(take_bytes(output, len).len(), 64);
            assert_eq!(c2pa_free(retry.cast()), 0);

            // Mode is pinned: an expert record does not import into composed.
            let composed = trusted_session(context, "signer_composed_emsg", &mut state);
            assert!(!composed.is_null());
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_import_state(
                    composed,
                    pre_state.as_ptr(),
                    pre_state.len(),
                ),
                -1
            );
            assert_eq!(c2pa_free(composed.cast()), 0);
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_trusted_vsi_composed_round_trip_and_restore() {
        unsafe {
            let context = test_context();
            let mut state = trusted_state(TrustedMode::Valid);
            let session = trusted_session(context, "signer_composed_emsg", &mut state);
            assert!(!session.is_null(), "{:?}", CimplError::last_message());
            trusted_establish_init(session);
            let status = trusted_status(session);
            assert!(status.has_next_sequence_number && status.has_next_event_id);
            assert_eq!((status.next_sequence_number, status.next_event_id), (1, 1));

            // Expert signing is rejected in composed mode.
            let data = es256_sig_structure();
            let mut output = std::ptr::null();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_sign_sig_structure(
                    session,
                    data.as_ptr(),
                    data.len(),
                    1,
                    &mut output,
                ),
                -1
            );

            let hash = trusted_template(C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_MEDIA_HASH);
            for sequence in 1..=2u32 {
                let calls = state.observations.len();
                let mut signing_context = C2paLiveVideoTrustedVsiSigningContextV1::empty();
                output = std::ptr::null();
                let len = c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
                    session,
                    sequence,
                    1_700_000_000,
                    90_000,
                    180_000,
                    &mut output,
                    &mut signing_context,
                );
                let reserved = take_bytes(output, len);
                assert_eq!(&reserved[4..8], b"emsg");
                assert_eq!(state.observations.len(), calls);
                assert_eq!(
                    signing_context,
                    C2paLiveVideoTrustedVsiSigningContextV1 {
                        purpose: C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_VSI,
                        sequence_number: sequence,
                        has_sequence_number: true,
                        event_id: sequence,
                        has_event_id: true,
                        exhaust_after_sign: false,
                    }
                );
                assert!(trusted_status(session).media_emsg_pending);
                assert_eq!(
                    c2pa_live_video_trusted_vsi_session_preflight(
                        session,
                        C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_FINALIZE_MEDIA,
                        hash.as_ptr(),
                        hash.len(),
                        0,
                        0,
                        0,
                        0,
                        std::ptr::null(),
                    ),
                    0
                );
                output = std::ptr::null();
                let len = c2pa_live_video_trusted_vsi_session_finalize_media_emsg(
                    session,
                    hash.as_ptr(),
                    hash.len(),
                    &mut output,
                );
                let signed = take_bytes(output, len);
                assert_eq!(signed.len(), reserved.len());
                assert_eq!(*state.observations.last().unwrap(), signing_context);
            }
            let status = trusted_status(session);
            assert_eq!((status.next_sequence_number, status.next_event_id), (3, 3));
            assert!(!status.media_emsg_pending);

            // Out-of-order sequences are rejected before any callback.
            let calls = state.observations.len();
            let mut signing_context = C2paLiveVideoTrustedVsiSigningContextV1::empty();
            output = std::ptr::null();
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_reserve_media_emsg(
                    session,
                    7,
                    1_700_000_000,
                    90_000,
                    180_000,
                    &mut output,
                    &mut signing_context,
                ),
                -1
            );
            assert_eq!(state.observations.len(), calls);

            let exported = trusted_export(session);
            let text = std::str::from_utf8(&exported).unwrap();
            assert!(text.contains("c2pa.trusted-vsi.state"));
            assert_eq!(c2pa_free(session.cast()), 0);

            let restored = trusted_session(context, "signer_composed_emsg", &mut state);
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_import_state(
                    restored,
                    exported.as_ptr(),
                    exported.len(),
                ),
                0
            );
            assert_eq!(trusted_status(restored), status);
            let mut tampered = exported.clone();
            let last = tampered.len() - 2;
            tampered[last] ^= 1;
            let other = trusted_session(context, "signer_composed_emsg", &mut state);
            assert_eq!(
                c2pa_live_video_trusted_vsi_session_import_state(
                    other,
                    tampered.as_ptr(),
                    tampered.len(),
                ),
                -1
            );
            assert!(!trusted_status(other).init_uuid_committed);
            assert_eq!(c2pa_free(other.cast()), 0);
            assert_eq!(c2pa_free(restored.cast()), 0);
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_trusted_vsi_v1_layout_and_discriminants_are_stable() {
        use std::mem::{align_of, offset_of, size_of};

        assert_eq!(C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_SIGNER_BINDING, 0);
        assert_eq!(C2PA_LIVE_VIDEO_TRUSTED_VSI_PURPOSE_VSI, 1);
        assert_eq!(C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_NONE, 0);
        assert_eq!(
            C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_SEQUENCE_MAX,
            1
        );
        assert_eq!(
            C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_EVENT_ID_MAX,
            2
        );
        assert_eq!(
            C2PA_LIVE_VIDEO_TRUSTED_VSI_EXHAUSTION_REASON_LEGACY_SENTINEL,
            3
        );
        assert_eq!(C2PA_LIVE_VIDEO_TRUSTED_VSI_MODE_EXPERT_SIG_STRUCTURE, 1);
        assert_eq!(C2PA_LIVE_VIDEO_TRUSTED_VSI_MODE_SIGNER_COMPOSED_EMSG, 2);
        assert_eq!(
            [
                C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_RESERVE_INIT,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_FINALIZE_INIT,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_COMMIT_INIT,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_EXPERT_SIGN,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_RESERVE_MEDIA,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_OP_FINALIZE_MEDIA,
            ],
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!(
            [
                C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_INIT_HASH,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_SIG_STRUCTURE,
                C2PA_LIVE_VIDEO_TRUSTED_VSI_INPUT_MEDIA_HASH,
            ],
            [0, 1, 2]
        );
        type Ctx = C2paLiveVideoTrustedVsiSigningContextV1;
        assert_eq!(align_of::<Ctx>(), 4);
        assert_eq!(size_of::<Ctx>(), 20);
        assert_eq!(offset_of!(Ctx, purpose), 0);
        assert_eq!(offset_of!(Ctx, sequence_number), 4);
        assert_eq!(offset_of!(Ctx, has_sequence_number), 8);
        assert_eq!(offset_of!(Ctx, event_id), 12);
        assert_eq!(offset_of!(Ctx, has_event_id), 16);
        assert_eq!(offset_of!(Ctx, exhaust_after_sign), 17);
        type Status = C2paLiveVideoTrustedVsiStatusV1;
        assert_eq!(align_of::<Status>(), 4);
        assert_eq!(size_of::<Status>(), 24);
        assert_eq!(offset_of!(Status, init_uuid_committed), 0);
        assert_eq!(offset_of!(Status, init_uuid_pending), 1);
        assert_eq!(offset_of!(Status, media_emsg_pending), 2);
        assert_eq!(offset_of!(Status, has_next_sequence_number), 3);
        assert_eq!(offset_of!(Status, next_sequence_number), 4);
        assert_eq!(offset_of!(Status, has_next_event_id), 8);
        assert_eq!(offset_of!(Status, next_event_id), 12);
        assert_eq!(offset_of!(Status, exhausted), 16);
        assert_eq!(offset_of!(Status, has_exhaustion_reason), 17);
        assert_eq!(offset_of!(Status, blocked), 18);
        assert_eq!(offset_of!(Status, exhaustion_reason), 20);
    }

    #[test]
    fn ffi_moof_sequence_probe_rejects_invalid_box_layouts() {
        let valid = probe_media_segment(37);
        let duplicate_moof = [valid.as_slice(), valid.as_slice()].concat();

        let mfhd = bmff_box(b"mfhd", &[0, 0, 0, 0, 0, 0, 0, 37]);
        let duplicate_mfhd = bmff_box(
            b"moof",
            &[
                mfhd.as_slice(),
                mfhd.as_slice(),
                bmff_box(b"traf", &[]).as_slice(),
            ]
            .concat(),
        );

        let traf = bmff_box(b"traf", &[]);
        let duplicate_traf = bmff_box(
            b"moof",
            &[
                bmff_box(b"mfhd", &[0, 0, 0, 0, 0, 0, 0, 37]).as_slice(),
                traf.as_slice(),
                traf.as_slice(),
            ]
            .concat(),
        );
        let no_moof = bmff_box(b"mdat", &[]);

        let cases: &[&[u8]] = &[
            b"",
            b"not bmff",
            no_moof.as_slice(),
            duplicate_moof.as_slice(),
            duplicate_mfhd.as_slice(),
            duplicate_traf.as_slice(),
        ];
        for media in cases {
            let mut sequence_number = 99;
            let result = unsafe {
                c2pa_live_video_moof_sequence_number(
                    media.as_ptr(),
                    media.len(),
                    &mut sequence_number,
                )
            };
            assert_eq!(result, -1);
            assert_eq!(sequence_number, 0);
        }
    }

    #[test]
    fn ffi_moof_sequence_probe_validates_pointers_and_lengths() {
        let media = probe_media_segment(37);

        assert_eq!(
            unsafe {
                c2pa_live_video_moof_sequence_number(
                    media.as_ptr(),
                    media.len(),
                    std::ptr::null_mut(),
                )
            },
            -1
        );

        for (input, len) in [
            (std::ptr::null(), 0),
            (std::ptr::null(), 1),
            (media.as_ptr(), 0),
        ] {
            let mut sequence_number = 99;
            assert_eq!(
                unsafe { c2pa_live_video_moof_sequence_number(input, len, &mut sequence_number) },
                -1
            );
            assert_eq!(sequence_number, 0);
        }
    }

    #[test]
    fn ffi_create_init_media_counter_and_tracked_outputs() {
        unsafe {
            let context = test_context();
            let media = include_bytes!(fixture_path!("bunny/bunny_791182bps/BigBuckBunny_2s5.m4s"));
            let sequence = u64::from(c2pa::live_video::moof_sequence_number(media).unwrap());
            let live = test_live_signer(context, sequence);
            assert!(!live.is_null());

            let mut next = 0;
            assert_eq!(
                c2pa_live_video_vsi_signer_next_sequence_number(live, &mut next),
                0
            );
            assert_eq!(next, sequence);

            let mut manifest_id = std::ptr::null_mut();
            assert_eq!(
                c2pa_live_video_vsi_signer_active_manifest_id(live, &mut manifest_id),
                0
            );
            assert!(manifest_id.is_null());

            let init = include_bytes!(fixture_path!(
                "bunny/bunny_791182bps/BigBuckBunny_2s_init.mp4"
            ));
            let format = CString::new("video/mp4").unwrap();
            let mut signed_init = std::ptr::null();
            let init_len = c2pa_live_video_vsi_signer_sign_init_segment(
                live,
                init.as_ptr(),
                init.len(),
                format.as_ptr(),
                &mut signed_init,
            );
            assert!(init_len > 0);
            // Tracked-buffer ownership is asserted by the c2pa_free(..) == 0 checks below.
            assert!(!signed_init.is_null());

            assert_eq!(
                c2pa_live_video_vsi_signer_active_manifest_id(live, &mut manifest_id),
                0
            );
            assert!(CStr::from_ptr(manifest_id)
                .to_str()
                .unwrap()
                .starts_with("urn:c2pa:"));

            let mut signed_media = std::ptr::null();
            let media_len = c2pa_live_video_vsi_signer_sign_media_segment(
                live,
                media.as_ptr(),
                media.len(),
                &mut signed_media,
            );
            assert!(media_len > media.len() as i64);
            assert!(!signed_media.is_null());
            assert_eq!(
                c2pa_live_video_vsi_signer_next_sequence_number(live, &mut next),
                0
            );
            assert_eq!(next, sequence + 1);

            assert_eq!(c2pa_free(signed_init.cast()), 0);
            assert_eq!(c2pa_free(signed_media.cast()), 0);
            assert_eq!(c2pa_free(manifest_id.cast()), 0);
            assert_eq!(c2pa_free(live.cast()), 0);
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_error_does_not_advance_counter() {
        unsafe {
            let context = test_context();
            let live = test_live_signer(context, 5);
            assert!(!live.is_null());

            let media = include_bytes!(fixture_path!("bunny/bunny_791182bps/BigBuckBunny_2s5.m4s"));
            let mut output = std::ptr::null();
            assert_eq!(
                c2pa_live_video_vsi_signer_sign_media_segment(
                    live,
                    media.as_ptr(),
                    media.len(),
                    &mut output,
                ),
                -1
            );
            assert!(output.is_null());

            let mut next = 0;
            assert_eq!(
                c2pa_live_video_vsi_signer_next_sequence_number(live, &mut next),
                0
            );
            assert_eq!(next, 5);

            assert_eq!(c2pa_free(live.cast()), 0);
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_rejects_wrong_seed_length() {
        unsafe {
            let context = test_context();
            let manifest = CString::new(r#"{"assertions":[]}"#).unwrap();
            let seed = [0u8; 31];
            let kid = b"kid";
            let live = c2pa_live_video_vsi_signer_create_ed25519(
                context,
                manifest.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                kid.as_ptr(),
                kid.len(),
                1,
                60,
            );
            assert!(live.is_null());
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_es256_callback_roundtrip_and_recover_resume() {
        unsafe {
            let context = test_context();
            let media = include_bytes!(fixture_path!("bunny/bunny_791182bps/BigBuckBunny_2s5.m4s"));
            let sequence = c2pa::live_video::moof_sequence_number(media).unwrap();
            let signing_key = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
            let mut state = Box::new(CallbackState {
                signing_key: signing_key.clone(),
                mode: CallbackMode::Valid,
                observations: Vec::new(),
            });
            let live = test_callback_live_signer(context, u64::from(sequence), &mut state);
            assert!(!live.is_null());
            assert!(state.observations.is_empty());

            let init = include_bytes!(fixture_path!(
                "bunny/bunny_791182bps/BigBuckBunny_2s_init.mp4"
            ));
            let format = CString::new("video/mp4").unwrap();
            let mut signed_init = std::ptr::null();
            let init_len = c2pa_live_video_vsi_signer_sign_init_segment(
                live,
                init.as_ptr(),
                init.len(),
                format.as_ptr(),
                &mut signed_init,
            );
            assert!(init_len > 0);
            assert_eq!(state.observations.len(), 1);
            assert_eq!(
                state.observations[0],
                (
                    C2paLiveVideoVsiSigningPurpose::SignerBinding,
                    C2PA_LIVE_VIDEO_VSI_NO_SEQUENCE,
                    64,
                )
            );

            let mut invalid_output = std::ptr::dangling::<c_uchar>();
            assert_eq!(
                c2pa_live_video_vsi_signer_sign_media_segment_at(
                    live,
                    media.as_ptr(),
                    media.len(),
                    1_577_836_799,
                    &mut invalid_output,
                ),
                -1
            );
            assert!(invalid_output.is_null());
            assert_eq!(state.observations.len(), 1);
            let mut next = 0;
            assert_eq!(
                c2pa_live_video_vsi_signer_next_sequence_number(live, &mut next),
                0
            );
            assert_eq!(next, u64::from(sequence));

            let mut signed_media = std::ptr::null();
            let media_len = c2pa_live_video_vsi_signer_sign_media_segment_at(
                live,
                media.as_ptr(),
                media.len(),
                1_577_836_800,
                &mut signed_media,
            );
            assert!(media_len > media.len() as i64);
            assert_eq!(state.observations.len(), 2);
            assert_eq!(
                state.observations[1],
                (C2paLiveVideoVsiSigningPurpose::Vsi, u64::from(sequence), 64,)
            );

            let mut recovered_state = Box::new(CallbackState {
                signing_key,
                mode: CallbackMode::Valid,
                observations: Vec::new(),
            });
            let recovered =
                test_callback_live_signer(context, u64::from(sequence), &mut recovered_state);
            assert!(!recovered.is_null());
            assert_eq!(
                c2pa_live_video_vsi_signer_recover(
                    recovered,
                    signed_init,
                    usize::try_from(init_len).unwrap(),
                    signed_media,
                    usize::try_from(media_len).unwrap(),
                    format.as_ptr(),
                ),
                0
            );
            assert!(recovered_state.observations.is_empty());
            assert_eq!(
                c2pa_live_video_vsi_signer_next_sequence_number(recovered, &mut next),
                0
            );
            assert_eq!(next, u64::from(sequence) + 1);

            let next_media = next_media_sequence(media.to_vec(), sequence + 1);
            let mut signed_media2 = std::ptr::null();
            let media2_len = c2pa_live_video_vsi_signer_sign_media_segment(
                recovered,
                next_media.as_ptr(),
                next_media.len(),
                &mut signed_media2,
            );
            assert!(media2_len > next_media.len() as i64);
            assert_eq!(
                recovered_state.observations,
                vec![(
                    C2paLiveVideoVsiSigningPurpose::Vsi,
                    u64::from(sequence) + 1,
                    64,
                )]
            );

            assert_eq!(c2pa_free(signed_init.cast()), 0);
            assert_eq!(c2pa_free(signed_media.cast()), 0);
            assert_eq!(c2pa_free(signed_media2.cast()), 0);
            assert_eq!(c2pa_free(live.cast()), 0);
            assert_eq!(c2pa_free(recovered.cast()), 0);
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_callback_errors_and_output_bounds_do_not_advance() {
        unsafe {
            let context = test_context();
            let media = include_bytes!(fixture_path!("bunny/bunny_791182bps/BigBuckBunny_2s5.m4s"));
            let sequence = c2pa::live_video::moof_sequence_number(media).unwrap();
            let mut state = Box::new(CallbackState {
                signing_key: p256::ecdsa::SigningKey::from_slice(&[11u8; 32]).unwrap(),
                mode: CallbackMode::Valid,
                observations: Vec::new(),
            });
            let live = test_callback_live_signer(context, u64::from(sequence), &mut state);
            assert!(!live.is_null());

            let init = include_bytes!(fixture_path!(
                "bunny/bunny_791182bps/BigBuckBunny_2s_init.mp4"
            ));
            let format = CString::new("video/mp4").unwrap();
            let mut signed_init = std::ptr::null();
            assert!(
                c2pa_live_video_vsi_signer_sign_init_segment(
                    live,
                    init.as_ptr(),
                    init.len(),
                    format.as_ptr(),
                    &mut signed_init,
                ) > 0
            );

            for mode in [
                CallbackMode::Error,
                CallbackMode::Oversized,
                CallbackMode::Short,
                CallbackMode::Corrupt,
            ] {
                state.mode = mode;
                let mut output = std::ptr::dangling::<c_uchar>();
                assert_eq!(
                    c2pa_live_video_vsi_signer_sign_media_segment(
                        live,
                        media.as_ptr(),
                        media.len(),
                        &mut output,
                    ),
                    -1
                );
                assert!(output.is_null());
                let mut next = 0;
                assert_eq!(
                    c2pa_live_video_vsi_signer_next_sequence_number(live, &mut next),
                    0
                );
                assert_eq!(next, u64::from(sequence));
            }
            assert_eq!(
                state
                    .observations
                    .iter()
                    .filter(|(purpose, _, _)| *purpose == C2paLiveVideoVsiSigningPurpose::Vsi)
                    .count(),
                4
            );

            state.mode = CallbackMode::Valid;
            let mut signed_media = std::ptr::null();
            assert!(
                c2pa_live_video_vsi_signer_sign_media_segment(
                    live,
                    media.as_ptr(),
                    media.len(),
                    &mut signed_media,
                ) > 0
            );

            assert_eq!(c2pa_free(signed_init.cast()), 0);
            assert_eq!(c2pa_free(signed_media.cast()), 0);
            assert_eq!(c2pa_free(live.cast()), 0);
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }

    #[test]
    fn ffi_callback_constructor_rejects_null_callback_and_unsupported_algorithm() {
        unsafe {
            let context = test_context();
            let signing_key = p256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
            let kid = b"ffi-es256-session";
            let cose_key = es256_public_cose_key(&signing_key, kid);
            let manifest = CString::new(r#"{"assertions": []}"#).unwrap();
            let created_at = CString::new("2020-01-01T00:00:00Z").unwrap();

            let null_callback = c2pa_live_video_vsi_signer_create_callback(
                context,
                manifest.as_ptr(),
                C2paSigningAlg::Es256,
                cose_key.as_ptr(),
                cose_key.len(),
                kid.as_ptr(),
                kid.len(),
                1,
                created_at.as_ptr(),
                3600,
                std::ptr::null_mut(),
                None,
            );
            assert!(null_callback.is_null());

            let unsupported = c2pa_live_video_vsi_signer_create_callback(
                context,
                manifest.as_ptr(),
                C2paSigningAlg::Es384,
                cose_key.as_ptr(),
                cose_key.len(),
                kid.as_ptr(),
                kid.len(),
                1,
                created_at.as_ptr(),
                3600,
                std::ptr::null_mut(),
                Some(es256_callback),
            );
            assert!(unsupported.is_null());
            assert_eq!(c2pa_free(context.cast()), 0);
        }
    }
}
