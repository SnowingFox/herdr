//! OpenSSL's error queue, as messages rather than bare codes.
//!
//! `TLSWrap` reads the queue in four places and every one of them needs the
//! *text*, not the code: `getPeerCertificate`'s verification failure,
//! `SSL_get_error`'s `SSL_ERROR_SSL` case, the `certCbDone` resume path, and
//! `injectOpenSSLErrorForTesting`/`hasOpenSSLErrorForTesting` beside `wrap` on
//! the namespace.
//!
//! # Why a drain rather than a read
//!
//! The OpenSSL error queue is per-thread and **append-only until read**. Node
//! wraps every path that can leave something on it in a `ClearErrorOnReturn`
//! (`crypto_common.h`), whose destructor drains the queue, precisely so one
//! failure does not leak into the message of the next. [`Captured`] is that
//! discipline: it drains on construction and on drop, so an early return still
//! leaves the queue clean.
//!
//! `rn-crypto-openssl` already owns the shared error mapping for the asymmetric
//! crates. This module exists because `tls_wrap` needs the raw textual reason in
//! a few places where those crates want a typed error, and because
//! `hasOpenSSLErrorForTesting` is a namespace member whose contract is exactly
//! "is the queue non-empty right now".
//!
//! # The declarations below that `openssl-sys` lacks
//!
//! Four functions needed here are not in `openssl-sys 0.9.118`. Each is a real
//! exported symbol in the vendored OpenSSL 3.6.3, checked with
//! `nm -g --defined-only libcrypto.a`, so a missing one would be a link error
//! rather than a silent wrong answer. `ERR_raise` is *not* among them: it is a
//! macro over `ERR_new` + `ERR_set_debug` + `ERR_set_error`, all three of which
//! *are* declared, so [`inject`] expands it the way the macro does.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_ulong};

use openssl_sys as ffi;

/// `#define ERR_TXT_STRING 0x02` in `err.h`: a reason string is attached.
const ERR_TXT_STRING: c_int = 0x02;
/// `#define ERR_LIB_USER 128` in `err.h`.
const ERR_LIB_USER: c_int = 128;
/// `#define ERR_R_INTERNAL_ERROR (259 | ERR_R_FATAL)` in `err.h`.
const ERR_R_INTERNAL_ERROR: c_int = 259;

extern "C" {
    /// `unsigned long ERR_peek_error(void);` — `err.h:418`.
    ///
    /// `openssl-sys` declares `ERR_peek_last_error` but not this one. The
    /// difference matters here: `hasOpenSSLErrorForTesting` must report whether
    /// *anything* is queued, and the last entry is empty on a queue that holds
    /// only one error that another path already drained from the tail.
    fn ERR_peek_error() -> c_ulong;

    /// `void ERR_error_string_n(unsigned long e, char *buf, size_t len);` —
    /// `err.h:459`.
    ///
    /// `openssl-sys` has no declaration for the `_n` form, and the non-`_n`
    /// `ERR_error_string` returns a pointer into a static buffer, which is not
    /// safe to use from two places in one call chain.
    fn ERR_error_string_n(code: c_ulong, buffer: *mut c_char, length: usize);
}

/// One entry from the error queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The library's numeric code, `ERR_GET_LIB`.
    pub library: i32,
    /// The function code.
    pub function: i32,
    /// The reason code, `ERR_GET_REASON`.
    pub reason: i32,
    /// The human-readable string, when the error carried one.
    pub text: Option<String>,
    /// The reason name OpenSSL has for the code, when it has one.
    ///
    /// On OpenSSL 3 most codes have no name, so this is usually empty; when it
    /// is present it is what a test's expected message quotes.
    pub reason_string: Option<String>,
}

impl Entry {
    /// The message Node formats this entry as.
    ///
    /// `crypto_common.cc`'s `ThrowCryptoError` builds
    /// `<reason string>:<library>:<function>:<reason>` and falls back to the
    /// numeric form when there is no text. This produces the same, preferring
    /// the entry's own text over the code's name because that is the order Node
    /// builds it in.
    pub fn message(&self) -> String {
        let text = self
            .text
            .as_deref()
            .or(self.reason_string.as_deref())
            .unwrap_or("");
        if text.is_empty() {
            format!("{}:{}:{}", self.library, self.function, self.reason)
        } else {
            format!(
                "{}:{}:{}:{}",
                text, self.library, self.function, self.reason
            )
        }
    }
}

/// `ERR_reason_error_string`, as an owned `String`.
fn reason_name(code: u64) -> Option<String> {
    if code == 0 {
        return None;
    }
    // SAFETY: `ERR_reason_error_string` accepts any value and returns a static
    // string or null; it takes no ownership.
    let pointer = unsafe { ffi::ERR_reason_error_string(code as c_ulong) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: OpenSSL returns a NUL-terminated static string.
    let text = unsafe { CStr::from_ptr(pointer) }.to_string_lossy();
    if text.is_empty() {
        None
    } else {
        Some(text.into_owned())
    }
}

/// Drains the whole queue into entries, oldest first.
///
/// Oldest first matches `ERR_print_errors_cb`'s order, which is the order
/// `TLSWrap::GetBIOError` produces and therefore the order a test's expected
/// message is in.
pub fn drain() -> Vec<Entry> {
    let mut entries = Vec::new();
    loop {
        // SAFETY: every pointer is a live local `ERR_get_error_all` fills.
        let mut file: *const c_char = std::ptr::null();
        let mut line: c_int = 0;
        let mut function: *const c_char = std::ptr::null();
        let mut data: *const c_char = std::ptr::null();
        let mut flags: c_int = 0;
        let code = unsafe {
            ffi::ERR_get_error_all(&mut file, &mut line, &mut function, &mut data, &mut flags)
        };
        if code == 0 {
            break;
        }
        let text = if flags & ERR_TXT_STRING != 0 && !data.is_null() {
            // SAFETY: `data` is a NUL-terminated string owned by the queue and
            // valid until the next queue call. It is copied here.
            Some(
                unsafe { CStr::from_ptr(data) }
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        };
        entries.push(Entry {
            library: ((code >> 23) & 0xff) as i32,
            function: (code & 0x7fff) as i32,
            reason: (code & 0x7ff) as i32,
            text,
            reason_string: reason_name(code),
        });
    }
    entries
}

/// The queue as one `; `-joined line, or an empty string when it was empty.
pub fn drain_reason() -> String {
    drain()
        .iter()
        .map(Entry::message)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether anything is queued, without removing it.
///
/// `hasOpenSSLErrorForTesting` is defined as exactly this: the member exists so
/// a test can assert an operation did or did not leave an error behind, and
/// popping the queue would make the assertion consume what it measures.
pub fn has_error() -> bool {
    // SAFETY: `ERR_peek_error` only reads the thread's queue head.
    unsafe { ERR_peek_error() != 0 }
}

/// Clears the queue, which `ClearErrorOnReturn` does on scope exit.
pub fn clear() {
    // SAFETY: `ERR_clear_error` discards the calling thread's queue.
    unsafe { ffi::ERR_clear_error() };
}

/// Pushes a synthetic error, which is what `injectOpenSSLErrorForTesting` does.
///
/// Node calls `ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR)`. `ERR_raise` is
/// the macro `(ERR_new(), ERR_set_debug(...), ERR_set_error(...))`, so this is
/// the same three calls rather than a call to a symbol that does not exist.
/// All three are declared by `openssl-sys`, so there is nothing to link by hand.
pub fn inject() {
    // SAFETY: the three calls append one entry to the calling thread's queue and
    // take no ownership of anything. A null `fmt` means "no formatted data",
    // which is what `ERR_raise_data(lib, reason, NULL)` expands to.
    unsafe {
        ffi::ERR_new();
        ffi::ERR_set_debug(std::ptr::null(), 0, std::ptr::null());
        ffi::ERR_set_error(ERR_LIB_USER, ERR_R_INTERNAL_ERROR, std::ptr::null());
    }
}

/// A `ClearErrorOnReturn`, as a value that drains on drop.
///
/// Node's pattern is a stack object whose destructor clears the queue, so a
/// function that returns early still leaves the queue clean. Using it here is
/// the same: `let mut guard = Captured::new();` at the top of a path that talks
/// to OpenSSL.
#[derive(Debug, Default)]
pub struct Captured {
    /// The entries as they were when [`Captured::capture`] ran.
    entries: Vec<Entry>,
}

impl Captured {
    /// Creates the guard, clearing whatever was there before.
    ///
    /// Anything already queued belongs to an earlier operation whose owner did
    /// not drain it; leaving it would attribute it to this one.
    pub fn new() -> Self {
        clear();
        Self {
            entries: Vec::new(),
        }
    }

    /// Drains into the guard, so the reason can be read after the call returned.
    pub fn capture(&mut self) {
        self.entries = drain();
    }

    /// The captured entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The captured reason as one line.
    pub fn reason(&self) -> String {
        self.entries
            .iter()
            .map(Entry::message)
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Whether the captured set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        // Whatever the caller captured, the queue must not outlive this scope:
        // the next operation reads the same thread-local queue.
        clear();
    }
}

/// The queue as newline-separated lines, which is `ERR_print_errors_cb`'s
/// shape and `TLSWrap::GetBIOError`'s output.
pub fn print() -> String {
    drain()
        .iter()
        .map(Entry::message)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `ERR_error_string_n`'s output for one code, in the numeric form.
pub fn format_code(code: u64) -> String {
    let mut buffer = [0 as c_char; 256];
    // SAFETY: `buffer` has room for 256 bytes, which is the documented maximum
    // for `ERR_error_string_n`, and the call always NUL-terminates.
    unsafe { ERR_error_string_n(code as c_ulong, buffer.as_mut_ptr(), buffer.len()) };
    // SAFETY: the call NUL-terminates `buffer`.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Injecting writes something the queue reports, which is the contract
    /// `injectOpenSSLErrorForTesting` and `hasOpenSSLErrorForTesting` share.
    #[test]
    fn an_injected_error_is_visible_and_drainable() {
        clear();
        assert!(!has_error());
        inject();
        assert!(has_error(), "an injected error must be observable");
        let entries = drain();
        assert!(!entries.is_empty());
        assert!(!has_error(), "draining must empty the queue");
    }

    /// Draining an empty queue reports nothing rather than a spurious entry.
    #[test]
    fn an_empty_queue_drains_to_nothing() {
        clear();
        assert_eq!(drain(), Vec::new());
        assert_eq!(drain_reason(), "");
    }

    /// A guard clears on construction and on drop, so a failure in one operation
    /// cannot be attributed to the next.
    #[test]
    fn the_guard_leaves_the_queue_empty() {
        inject();
        {
            let mut guard = Captured::new();
            assert!(!has_error(), "the guard clears on construction");
            inject();
            guard.capture();
            assert!(!guard.entries().is_empty());
            assert!(!guard.is_empty());
        }
        assert!(!has_error(), "the guard must clear on drop");
    }

    /// `Entry::message` includes the text when there is one, because Node's
    /// `ThrowCryptoError` does.
    #[test]
    fn an_entry_formats_with_its_text() {
        let entry = Entry {
            library: 1,
            function: 2,
            reason: 3,
            text: Some("bad thing".to_string()),
            reason_string: None,
        };
        assert_eq!(entry.message(), "bad thing:1:2:3");
        let bare = Entry {
            library: 1,
            function: 2,
            reason: 3,
            text: None,
            reason_string: None,
        };
        assert_eq!(bare.message(), "1:2:3");
    }

    /// When the entry has no text but its code has a name, the name is used, so
    /// a message is never reduced to three bare numbers if OpenSSL has a word
    /// for the failure.
    #[test]
    fn an_entry_falls_back_to_the_reason_name() {
        let entry = Entry {
            library: 1,
            function: 2,
            reason: 3,
            text: None,
            reason_string: Some("named".to_string()),
        };
        assert_eq!(entry.message(), "named:1:2:3");
    }
}
