// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Experimental stateful C API for C2PA 2.4 Verifiable Segment Info signing.

use std::os::raw::{c_char, c_int, c_uchar};

use c2pa::live_video::{Ed25519SessionKey, LiveVideoVsiSigner};
use zeroize::Zeroize;

use crate::{c_api::C2paContext, to_c_bytes, to_c_string};

/// Opaque state for one local Ed25519 VSI live-video session.
///
/// Calls operating on the same handle must be externally serialized.
pub struct C2paLiveVideoVsiSigner {
    signer: LiveVideoVsiSigner,
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
}
