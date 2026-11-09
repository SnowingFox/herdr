//! The raw llhttp ABI, and the callback trampoline that turns C calls into
//! JavaScript calls.
//!
//! # Why the callbacks need a V8 scope the caller did not pass
//!
//! `execute(buffer)` is a JavaScript call, so V8's isolate and the current
//! context are already live when llhttp starts running. llhttp then calls back
//! into C, and from there into JavaScript, which needs a `Local` handle — and a
//! `Local` can only be made in a scope. The scope is entered by the caller of
//! `execute`, but that caller is V8 itself and never hands it to us.
//!
//! So the parser holds the `Isolate` pointer and opens a *nested* handle scope
//! for every callback. V8 allows this: a callback runs with the isolate entered
//! and a context on the stack, exactly the precondition `HandleScope::new`
//! needs. It is the same thing `node_http_parser.cc` does — `Parser::Execute`
//! opens an `EscapableHandleScope` — just reached from the other direction.
//!
//! # Why the callbacks are `extern "C" fn` and not closures
//!
//! llhttp's settings struct is a table of plain function pointers with no
//! closure slot. Each one recovers its `Parser` from the `user` pointer, which
//! is the only state a callback gets.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// `llhttp_errno` values this crate names.
pub mod errno {
    use std::os::raw::c_int;

    pub const OK: c_int = 0;
    pub const USER: c_int = 24;
    pub const PAUSED: c_int = 21;
    pub const PAUSED_UPGRADE: c_int = 22;
}

/// `llhttp_type`.
pub mod parser_type {
    use std::os::raw::c_int;

    pub const REQUEST: c_int = 1;
    pub const RESPONSE: c_int = 2;
}

/// The parser state visible to the JavaScript-facing layer.
///
/// One `llhttp_t` plus the callback table, allocated by
/// [`rn_llhttp_new`]. Opaque: Rust never looks inside it, which is the point of
/// the shim.
#[repr(C)]
pub struct Llhttp {
    _private: [u8; 0],
}

/// The JavaScript-facing callbacks, matching [`crate::Parser`]'s handlers.
///
/// `user` is the [`crate::Parser`] pointer. Every function returns `0` to
/// continue, or an `llhttp_errno` to stop — see
/// [`rn_llhttp_user_error`] for the one that reports a reason.
#[repr(C)]
pub struct Callbacks {
    pub user: *mut std::ffi::c_void,
    pub on_message_begin: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int>,
    pub on_url: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, usize) -> c_int>,
    pub on_status:
        Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, usize) -> c_int>,
    pub on_header_field:
        Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, usize) -> c_int>,
    pub on_header_value:
        Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, usize) -> c_int>,
    pub on_headers_complete: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int>,
    pub on_body: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, usize) -> c_int>,
    pub on_message_complete: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int>,
    pub on_chunk_header: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int>,
    pub on_chunk_complete: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int>,
}

extern "C" {
    pub fn rn_llhttp_new(parser_type: c_int, callbacks: *const Callbacks) -> *mut Llhttp;
    pub fn rn_llhttp_free(parser: *mut Llhttp);
    pub fn rn_llhttp_init(parser: *mut Llhttp, parser_type: c_int);
    pub fn rn_llhttp_execute(parser: *mut Llhttp, data: *const c_char, len: usize) -> c_int;
    pub fn rn_llhttp_finish(parser: *mut Llhttp) -> c_int;
    pub fn rn_llhttp_pause(parser: *mut Llhttp);
    pub fn rn_llhttp_resume(parser: *mut Llhttp);
    pub fn rn_llhttp_resume_after_upgrade(parser: *mut Llhttp);
    pub fn rn_llhttp_should_keep_alive(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_errno(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_error_reason(parser: *const Llhttp) -> *const c_char;
    pub fn rn_llhttp_error_offset(parser: *const Llhttp, data: *const c_char) -> isize;
    pub fn rn_llhttp_set_error_reason(parser: *mut Llhttp, reason: *const c_char);
    pub fn rn_llhttp_user_error(parser: *mut Llhttp, reason: *const c_char) -> c_int;
    pub fn rn_llhttp_errno_name(errno_value: c_int) -> *const c_char;
    pub fn rn_llhttp_method_count() -> usize;
    pub fn rn_llhttp_method_at(index: usize) -> *const c_char;
    pub fn rn_llhttp_all_method_count() -> usize;
    pub fn rn_llhttp_all_method_at(index: usize) -> *const c_char;
    pub fn rn_llhttp_type(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_method(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_status_code(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_http_major(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_http_minor(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_upgrade(parser: *const Llhttp) -> c_int;
    pub fn rn_llhttp_set_lenient(parser: *mut Llhttp, flags: u32);
}

/// The reason `Parser::TrackHeader` and `TrackHeaderPair` report.
///
/// A C literal so the pointer the shim stores for `error_reason` stays valid for
/// the life of the process: llhttp keeps the pointer, it does not copy it.
pub const HEADER_OVERFLOW_C: &std::ffi::CStr = c"HPE_HEADER_OVERFLOW:Header overflow";

/// The reason a paused parser reports while paused.
///
/// Node sets this from `MaybePause` before returning `HPE_PAUSED`, but llhttp's
/// own `llhttp_pause` sets exactly the same string, so a pause from `execute`
/// and a pause from a callback report identically.
pub const PAUSED_C: &std::ffi::CStr = c"Paused";

/// Reads a NUL-terminated string the shim handed back.
///
/// # Safety
///
/// `pointer` must be NULL or a valid NUL-terminated string that outlives the
/// call. Every caller here passes a literal from the shim.
unsafe fn c_str<'a>(pointer: *const c_char) -> Option<&'a str> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: delegated to the caller; the shim's tables are static strings.
    unsafe { CStr::from_ptr(pointer) }.to_str().ok()
}

/// The `methods` array: the strings of llhttp's `HTTP_METHOD_MAP`.
///
/// Derived from the C table rather than transcribed, so a new method in a
/// future llhttp appears here without an edit.
pub fn methods() -> Vec<&'static str> {
    // SAFETY: the counts and indices are the shim's own table bounds, and every
    // entry is a string literal.
    unsafe { collect(rn_llhttp_method_count, rn_llhttp_method_at) }
}

/// The `allMethods` array: llhttp's `HTTP_ALL_METHOD_MAP`, i.e. `methods` plus
/// the RTSP verbs and `PRI`.
pub fn all_methods() -> Vec<&'static str> {
    // SAFETY: as `methods`.
    unsafe { collect(rn_llhttp_all_method_count, rn_llhttp_all_method_at) }
}

/// # Safety
///
/// `count` and `at` must describe one of the shim's static tables.
unsafe fn collect(
    count: unsafe extern "C" fn() -> usize,
    at: unsafe extern "C" fn(usize) -> *const c_char,
) -> Vec<&'static str> {
    // SAFETY: delegated to the caller.
    let total = unsafe { count() };
    let mut names = Vec::with_capacity(total);
    for index in 0..total {
        // SAFETY: `index < total`, and `at` returns a static string there.
        if let Some(name) = unsafe { c_str(at(index)) } {
            names.push(name);
        }
    }
    names
}

/// `llhttp_errno_name`, as `"HPE_*"`. Never aborts, unlike llhttp's own.
pub fn errno_name(value: c_int) -> String {
    // SAFETY: a table lookup over the shim's static names.
    let name = unsafe { c_str(rn_llhttp_errno_name(value)) };
    name.unwrap_or("HPE_UNKNOWN").to_string()
}
