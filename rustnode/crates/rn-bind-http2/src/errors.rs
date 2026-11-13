//! `nghttp2ErrorString`, the binding `lib/internal/http2/util.js` builds
//! `NghttpError` messages from.
//!
//! `HttpErrorString` in `src/node_http2.cc` is four lines: read the argument as a
//! `uint32`, hand it to `nghttp2_strerror`, return the C string. The signature is
//! `uint32` rather than `int32` because JavaScript passes error codes as
//! non-negative numbers: `nghttp2_strerror(-517)` is what a caller *means*, but
//! `-517 >>> 0` is what crosses the boundary, and nghttp2 reads the low 32 bits
//! back as `-517`.
//!
//! That conversion is why this is one function and not a table: the strings come
//! from the linked library, so `test-http2-binding.js`'s assertion on `-517`
//! ("GOAWAY has already been sent") is a fact about the vendored code rather than
//! about text copied here.

use rn_v8_sys::v8;

use crate::ffi;

/// `HttpErrorString`: `nghttp2_strerror(code)` as a JavaScript string.
pub fn error_string<'s>(scope: &mut v8::PinScope<'s, '_>, code: u32) -> v8::Local<'s, v8::Value> {
    // SAFETY: `nghttp2_strerror` returns a pointer to static text for every
    // input, including the codes it does not know, for which it returns
    // "Unknown error code".
    let text = unsafe { ffi::nghttp2_strerror(code as i32) };
    if text.is_null() {
        // Not reachable for this library, but a null `char*` must not become a
        // null dereference.
        return v8::undefined(scope).into();
    }
    // SAFETY: the pointer is non-null and NUL-terminated static text.
    let bytes = unsafe { std::ffi::CStr::from_ptr(text) }.to_bytes();
    // The strings are ASCII; invalid UTF-8 would be a library defect, and
    // `undefined` is a more honest answer than a lossy replacement character.
    match std::str::from_utf8(bytes) {
        Ok(text) => match v8::String::new(scope, text) {
            Some(string) => string.into(),
            None => v8::undefined(scope).into(),
        },
        Err(_) => v8::undefined(scope).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_from_the_linked_library() {
        // `process.versions.nghttp2` is built from the same call, and a value
        // that did not come from the binary would name code it does not contain.
        assert_eq!(crate::version(), Some("1.70.0".to_string()));
    }

    #[test]
    fn known_codes_have_nghttp2s_text() {
        // Pinned by `test-http2-binding.js`. Both are checked because one is a
        // protocol error code and one is a library error code, and the two
        // ranges are formatted from different tables inside nghttp2.
        let known = [
            (-517, "GOAWAY has already been sent"),
            (-508, "Data transfer deferred"),
            (-501, "Invalid argument"),
            (-510, "Stream was already closed or invalid"),
            (-901, "Out of memory"),
            (-522, "The length of the frame is invalid"),
            (0, "Success"),
        ];
        for (code, expected) in known {
            // SAFETY: static text, as in `error_string`.
            let text = unsafe { ffi::nghttp2_strerror(code) };
            let text = unsafe { std::ffi::CStr::from_ptr(text) };
            assert_eq!(text.to_str().expect("ASCII"), expected, "code {code}");
        }
    }
}
