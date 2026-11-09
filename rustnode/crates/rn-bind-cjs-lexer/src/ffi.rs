//! The `merve` C ABI, and nothing else.
//!
//! `vendor/merve/include/merve_c.h` declares a small `extern "C"` surface over
//! the C++ lexer, and this module is its only consumer. Going through the C ABI
//! rather than `merve.h` matters: `lexer::lexer_analysis` contains
//! `std::vector`, `std::variant` and `std::string_view`, and a `#[repr(C)]`
//! mirror of any of them would be an ABI bug waiting for a compiler change. The
//! C functions hand back an opaque handle plus `merve_string { data, length }`
//! pairs, so no C++ type is ever named on the Rust side.
//!
//! # Lifetimes
//!
//! A returned `merve_string` points either into the source buffer or into the
//! analysis, depending on whether the export name needed unescaping. Both must
//! outlive every string read from the handle, so [`Analysis`] borrows the source
//! it was parsed from and frees itself on drop. That makes the ordering a
//! compile-time property instead of a comment.

use std::ffi::c_char;

/// `merve_string`: a non-owning view into the source or the analysis.
///
/// The bytes are not null-terminated, so `length` is always authoritative.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MerveString {
    pub data: *const c_char,
    pub length: usize,
}

/// `merve_error_loc`: a 1-based, byte-oriented source position.
///
/// A zeroed value means the location was unavailable, which is also what a
/// successful parse reports.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MerveErrorLoc {
    pub line: u32,
    pub column: u32,
}

/// `merve_analysis`: an opaque owned handle to a parse result.
pub type MerveAnalysis = *mut std::ffi::c_void;

extern "C" {
    fn merve_parse_commonjs(
        input: *const c_char,
        length: usize,
        out_err: *mut MerveErrorLoc,
    ) -> MerveAnalysis;

    fn merve_is_valid(result: MerveAnalysis) -> bool;
    fn merve_free(result: MerveAnalysis);

    fn merve_get_exports_count(result: MerveAnalysis) -> usize;
    fn merve_get_reexports_count(result: MerveAnalysis) -> usize;

    fn merve_get_export_name(result: MerveAnalysis, index: usize) -> MerveString;
    fn merve_get_reexport_name(result: MerveAnalysis, index: usize) -> MerveString;

    fn merve_get_last_error() -> i32;
    fn merve_get_version() -> *const c_char;
}

/// The output of one successful `parse_commonjs`.
#[derive(Debug, Default)]
pub struct Parsed {
    /// Names the module statically defines as exports, in source order and
    /// without duplicates. merve deduplicates, so this is already the set Node
    /// reports.
    pub exports: Vec<String>,
    /// Module specifiers from reexport forms such as
    /// `module.exports = require('./other')`.
    pub reexports: Vec<String>,
}

/// An owned parse result, borrowing the buffer it was produced from.
///
/// The borrow is not decoration: merve returns `std::string_view`s into the
/// input for names that needed no unescaping, so reading a name after dropping
/// the source would be a use-after-free that no type in the C ABI can catch.
/// [`Analysis::new`] takes the exact slice the handle was parsed from, so the
/// lifetime that gets inferred is the buffer's, not some unconstrained region.
struct Analysis<'src> {
    handle: MerveAnalysis,
    _source: std::marker::PhantomData<&'src [u8]>,
}

impl<'src> Analysis<'src> {
    /// Takes ownership of `handle`, which must have been parsed from `source`.
    fn new(handle: MerveAnalysis, source: &'src [u8]) -> Self {
        let _ = source;
        Self {
            handle,
            _source: std::marker::PhantomData,
        }
    }
}

impl Drop for Analysis<'_> {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `merve_parse_commonjs`, which returns
        // either a live handle or null, and `Analysis` is only built from the
        // non-null case. `merve_free` accepts null as a no-op regardless.
        unsafe { merve_free(self.handle) }
    }
}

impl<'src> Analysis<'src> {
    /// Reads a `merve_string` as a `String`.
    ///
    /// merve reports an out-of-range or invalid entry as `{null, 0}`, which is
    /// indistinguishable from a legitimately empty name. An empty export name
    /// cannot occur — merve skips names it cannot unescape rather than emitting
    /// them — so an empty read here means the handle did not describe the entry
    /// after all, and it is dropped rather than turned into a bogus `""`.
    fn read(value: MerveString) -> Option<String> {
        if value.data.is_null() || value.length == 0 {
            return None;
        }
        // SAFETY: merve guarantees `data` points at `length` initialised bytes
        // that live as long as the handle (and, for string_view-backed names,
        // as long as the source this `Analysis` borrows). The bytes are the
        // original UTF-8 source or merve's own UTF-8 encoding of an unescaped
        // name, so treating them as UTF-8 is what merve produced them for.
        let bytes = unsafe { std::slice::from_raw_parts(value.data.cast::<u8>(), value.length) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    fn exports(&self) -> Vec<String> {
        // SAFETY: `handle` is live for `self`'s lifetime.
        let count = unsafe { merve_get_exports_count(self.handle) };
        (0..count)
            .filter_map(|index| {
                // SAFETY: `index < count`, and `count` came from this handle.
                Self::read(unsafe { merve_get_export_name(self.handle, index) })
            })
            .collect()
    }

    fn reexports(&self) -> Vec<String> {
        // SAFETY: `handle` is live for `self`'s lifetime.
        let count = unsafe { merve_get_reexports_count(self.handle) };
        (0..count)
            .filter_map(|index| {
                // SAFETY: `index < count`, and `count` came from this handle.
                Self::read(unsafe { merve_get_reexport_name(self.handle, index) })
            })
            .collect()
    }
}

/// Runs merve over `source`.
///
/// `None` means the source did not parse as CommonJS: ESM syntax, an
/// unterminated literal, or unbalanced brackets. Node maps every one of those
/// to an empty result rather than an error, because the JavaScript layer calls
/// this on files it already knows it must load and treats "no static exports
/// found" as the safe answer. The caller decides that; this layer only reports
/// that the analysis failed.
///
/// An empty source is not a failure. merve parses it into zero exports and zero
/// reexports, so `parse("")` and a source with nothing exportable in it both
/// produce `Some(Parsed::default())`.
///
/// # The trailing NUL is required, not defensive
///
/// merve's scanner seeds `pos = source - 1` and loops with `while (pos++ < end)`,
/// so the last iteration reads `source[len]` — one byte *past* the bytes it was
/// given. Node satisfies that by construction: `Utf8Value` zero-terminates
/// (`SetLengthAndZeroTerminate`), so the byte after the source is always a
/// readable `'\0'` that terminates the scan.
///
/// A Rust `&str` gives no such guarantee. For an empty `String` the pointer is
/// a dangling `0x1`, so passing `as_ptr()` straight through dereferences an
/// invalid page; a non-empty one reads whatever heap byte follows the
/// allocation, which usually works and is undefined behaviour regardless. So
/// the source is copied into an owned buffer with an explicit terminator, which
/// is exactly the shape Node hands merve.
pub fn parse_commonjs(source: &str) -> Option<Parsed> {
    let mut buffer = Vec::with_capacity(source.len() + 1);
    buffer.extend_from_slice(source.as_bytes());
    buffer.push(0);

    let mut error = MerveErrorLoc::default();
    // SAFETY: `buffer` is a live allocation of `source.len() + 1` bytes whose
    // last byte is a NUL terminator, and the length passed is the source length
    // merve expects. That satisfies both the documented contract and the
    // one-byte-past-the-end read the scanner performs, and `buffer` outlives
    // every string taken from the returned handle because the handle is freed
    // before this function returns.
    let handle =
        unsafe { merve_parse_commonjs(buffer.as_ptr().cast::<c_char>(), source.len(), &mut error) };
    if handle.is_null() {
        // Documented as out-of-memory only, but the analysis is unusable either
        // way and reporting "nothing found" is what Node does with a result it
        // cannot read.
        return None;
    }

    let analysis = Analysis::new(handle, &buffer);
    // SAFETY: `analysis.handle` is live until `analysis` is dropped.
    if !unsafe { merve_is_valid(analysis.handle) } {
        return None;
    }

    Some(Parsed {
        exports: analysis.exports(),
        reexports: analysis.reexports(),
    })
}

/// merve's version, as reported by the linked library.
///
/// The crate's tests assert on this and `tools/verify-merve.sh` pins the same
/// value against the vendored sources (`MERVE_VERSION` in `merve.h`), so a
/// vendored bump that forgets one side, or a stale object file linked from a
/// different revision, fails loudly instead of quietly analysing with the wrong
/// lexer.
pub fn version() -> String {
    // SAFETY: `merve_get_version` returns a pointer to a static, null-terminated
    // string literal owned by the library; it is never null and never freed.
    let text = unsafe { std::ffi::CStr::from_ptr(merve_get_version()) };
    text.to_string_lossy().into_owned()
}

/// merve's last parse error code, or `None` when the last parse succeeded.
///
/// The C ABI reports this as process-global state, so it is only meaningful
/// immediately after a `parse_commonjs` call on the same thread. The crate uses
/// it in tests to tell "ESM syntax" from "unterminated literal"; nothing in the
/// binding reads it, because Node discards the distinction.
pub fn last_error() -> Option<i32> {
    // SAFETY: reads global state merve owns; no pointers involved.
    match unsafe { merve_get_last_error() } {
        -1 => None,
        code => Some(code),
    }
}
