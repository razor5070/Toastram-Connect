//! Minimal C ABI bridge. It never returns the enrollment token.
//! Language wrappers should only wrap these functions, not reimplement trust.

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use toastlink_core::{ConnectionFile, ImportError, MAX_TOASTLINK_BYTES};

pub const TOASTLINK_OK: i32 = 0;
pub const TOASTLINK_INVALID_ARGUMENT: i32 = 1;
pub const TOASTLINK_INVALID_FILE: i32 = 2;
pub const TOASTLINK_BUFFER_TOO_SMALL: i32 = 3;
pub const TOASTLINK_INTERNAL_ERROR: i32 = 4;
pub const TOASTLINK_EXPIRED: i32 = 5;
pub const TOASTLINK_UNSUPPORTED_FORMAT: i32 = 6;

// Existing status values remain unchanged for C ABI compatibility.
fn map_import_error(error: ImportError) -> i32 {
    match error {
        ImportError::Expired => TOASTLINK_EXPIRED,
        ImportError::UnsupportedFormat => TOASTLINK_UNSUPPORTED_FORMAT,
        _ => TOASTLINK_INVALID_FILE,
    }
}

/// Opaque, owning handle. Created by toastlink_import_json and freed once.
pub struct ToastLinkHandle {
    value: ConnectionFile,
}

/// Parse untrusted JSON bytes without any network call.
///
/// # Safety
/// The caller must supply a readable data buffer of length len and a writable
/// out_handle pointer. The returned handle must be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn toastlink_import_json(
    data: *const u8,
    len: usize,
    out_handle: *mut *mut ToastLinkHandle,
) -> i32 {
    if out_handle.is_null() {
        return TOASTLINK_INVALID_ARGUMENT;
    }
    // SAFETY: out_handle is writable by caller contract.
    unsafe { *out_handle = ptr::null_mut() };
    if data.is_null() || len == 0 || len > MAX_TOASTLINK_BYTES {
        return TOASTLINK_INVALID_ARGUMENT;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees data is readable over len bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        match ConnectionFile::from_bytes(bytes) {
            Ok(value) => {
                // SAFETY: caller guarantees out_handle is writable.
                unsafe { *out_handle = Box::into_raw(Box::new(ToastLinkHandle { value })) };
                TOASTLINK_OK
            }
            Err(error) => map_import_error(error),
        }
    })) {
        Ok(code) => code,
        Err(_) => TOASTLINK_INTERNAL_ERROR,
    }
}

/// Retrieve NUL-terminated public metadata JSON with no credentials.
/// On insufficient capacity, required receives the required byte count.
///
/// # Safety
/// Caller must pass a valid live handle and writable required pointer. If
/// capacity is nonzero, buffer must point to at least capacity writable bytes.
#[no_mangle]
pub unsafe extern "C" fn toastlink_metadata_json(
    handle: *const ToastLinkHandle,
    buffer: *mut c_char,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    if handle.is_null() || required.is_null() {
        return TOASTLINK_INVALID_ARGUMENT;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle is a live SDK-owned pointer by caller contract.
        let metadata = unsafe { &*handle }.value.public_metadata_json();
        let bytes = metadata.as_bytes();
        let needed = bytes.len() + 1;
        // SAFETY: caller supplied writable required.
        unsafe { *required = needed };
        if capacity < needed {
            return TOASTLINK_BUFFER_TOO_SMALL;
        }
        if buffer.is_null() {
            return TOASTLINK_INVALID_ARGUMENT;
        }
        // SAFETY: caller guarantees buffer points to capacity bytes.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), bytes.len());
            *buffer.add(bytes.len()) = 0;
        }
        TOASTLINK_OK
    })) {
        Ok(code) => code,
        Err(_) => TOASTLINK_INTERNAL_ERROR,
    }
}

/// Free one SDK-created handle. Accepts null.
///
/// # Safety
/// handle must be null or a live owning pointer returned from this SDK;
/// it must not be used or freed again after this call.
#[no_mangle]
pub unsafe extern "C" fn toastlink_free(handle: *mut ToastLinkHandle) {
    if !handle.is_null() {
        // SAFETY: caller transfers ownership of a unique SDK-issued handle.
        unsafe { drop(Box::from_raw(handle)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_never_returns_non_null_handle() {
        let mut handle = std::ptr::NonNull::<ToastLinkHandle>::dangling().as_ptr();
        let input = br#"{"format":"no"}"#;
        let code = unsafe { toastlink_import_json(input.as_ptr(), input.len(), &mut handle) };
        assert_eq!(code, TOASTLINK_INVALID_FILE);
        assert!(handle.is_null());
    }

    #[test]
    fn reports_expired_and_unsupported_files_to_c_callers() {
        fn file_bytes(format: &str, expires_at: &str) -> Vec<u8> {
            serde_json::json!({
                "format": format,
                "version": 1,
                "server": {
                    "id": "8f694b5238e9a11b86c4cb003b1b346a",
                    "name": "Local ToastRAM",
                    "url": "https://memory.example.lan:18443"
                },
                "tls": {
                    "ca_certificate_pem": include_str!("../../../tests/fixtures/ca.pem")
                },
                "enrollment": {
                    "id": "a2940e55-374b-4a4f-a5e4-b15e3c3a9ed8",
                    "token": "disposable_test_enrollment_secret_only_for_tests",
                    "expires_at": expires_at
                }
            })
            .to_string()
            .into_bytes()
        }

        for (format, expires_at, expected) in [
            ("toastram.connection", "2020-01-01T00:00:00Z", TOASTLINK_EXPIRED),
            ("unknown.format", "2099-01-01T00:00:00Z", TOASTLINK_UNSUPPORTED_FORMAT),
        ] {
            let bytes = file_bytes(format, expires_at);
            let mut handle = ptr::null_mut();
            let rc = unsafe { toastlink_import_json(bytes.as_ptr(), bytes.len(), &mut handle) };
            assert_eq!(rc, expected);
            assert!(handle.is_null());
        }
    }

    #[test]
    fn metadata_rejects_null_handle() {
        let mut needed = 0;
        let rc = unsafe { toastlink_metadata_json(ptr::null(), ptr::null_mut(), 0, &mut needed) };
        assert_eq!(rc, TOASTLINK_INVALID_ARGUMENT);
        unsafe { toastlink_free(ptr::null_mut()) };
    }
}
