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
        Ed25519SessionKey, LiveVideoVsiSigner, VsiSessionConfig, VsiSessionSigner,
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
        context,
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
        context,
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
    let signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
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
    let signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
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
    let signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
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
    let signer = deref_mut_or_return_int!(signer, C2paLiveVideoVsiSigner);
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
    use crate::{
        c_api::{
            c2pa_context_builder_build, c2pa_context_builder_new,
            c2pa_context_builder_set_settings, c2pa_context_builder_set_signer, c2pa_free,
            c2pa_settings_new, c2pa_settings_set_value, c2pa_signer_from_info, C2paSignerInfo,
        },
        validate_pointer,
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
            assert!(validate_pointer::<Box<[u8]>>(signed_init.cast_mut().cast()).is_ok());

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
            assert!(validate_pointer::<Box<[u8]>>(signed_media.cast_mut().cast()).is_ok());
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
