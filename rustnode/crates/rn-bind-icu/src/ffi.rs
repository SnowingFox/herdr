//! The ICU C API rustnode calls, declared against the copy V8 already links.
//!
//! # Why these declarations exist at all
//!
//! rustnode does not build ICU. It links `librusty_v8.a`, and that archive is
//! built from the same ICU 78 the pinned Node ships — the symbols carry ICU's
//! versioned suffix (`ucnv_open_78`, `u_charType_78`, …) because the build does
//! not disable renaming. Every function this module declares is present and
//! globally defined (`T`) in that archive; `nm --defined-only
//! target/<profile>/gn_out/obj/librusty_v8.a` is the check.
//!
//! They are absent from a linked `rustnode` binary only until something
//! references them: a static archive is searched for unresolved symbols, so an
//! object nobody pulls in contributes nothing. Declaring and *calling* one is
//! what makes the linker include it, which is why this is a supported mechanism
//! rather than a hope. `rn-bind-crypto`'s `enumerate.rs` relies on the same
//! property for the OpenSSL walkers `openssl-sys` does not declare.
//!
//! # Why the `_78` suffix is written out
//!
//! The suffix is the contract, not an accident: a different ICU major renames
//! every entry point, so a list that followed the rename silently would keep
//! compiling while calling into a data format the rest of the tree does not
//! expect. Spelling it out makes an ICU version bump a visible edit here, the
//! same way `crates/rn-cli/src/versions.rs` records the build.
//!
//! # Type fidelity
//!
//! These are transcribed from `deps/icu-small/source/common/unicode/{ucnv.h,
//! uchar.h,ucnv_err.h,utypes.h}` at the pinned revision. ICU is C++, so `UBool`
//! is `int8_t`, `UChar` is a 16-bit unsigned type and `UChar32` is `int32_t`;
//! getting any of those wrong is ABI-visible rather than merely untidy.
//! `tools/audit-ffi-types.py` covers the OpenSSL declarations in this tree but
//! not these, so the header is the only oracle — keep it open when editing.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_void};

/// `UChar32`: a code point, or a lone surrogate's code unit value.
pub type UChar32 = i32;

/// `UChar`: one UTF-16 code unit.
pub type UChar = u16;

/// `UBool`: `int8_t`, not C++ `bool`.
pub type UBool = i8;

/// `UErrorCode`: ICU's error enum, passed by pointer everywhere.
pub type UErrorCode = i32;

/// `UProperty`: the `UProperty` enum (`uchar.h`).
pub type UProperty = i32;

/// `UConverter`: opaque. Only ever held behind a pointer.
#[repr(C)]
pub struct UConverter {
    _opaque: [u8; 0],
}

/// `UConverterToUnicodeArgs`: opaque, because only ICU's own callbacks receive
/// it. `UCNV_TO_U_CALLBACK_STOP` is passed as a value, never invoked from here.
#[repr(C)]
pub struct UConverterToUnicodeArgs {
    _opaque: [u8; 0],
}

/// `UConverterCallbackReason` (`ucnv_err.h`), as the raw enum width.
pub type UConverterCallbackReason = i32;

/// `UConverterToUCallback` (`ucnv_err.h`): `void (*)(const void *,
/// UConverterToUnicodeArgs *, const char *, int32_t, UConverterCallbackReason,
/// UErrorCode *)`.
pub type UConverterToUCallback = Option<
    unsafe extern "C" fn(
        context: *const c_void,
        args: *mut UConverterToUnicodeArgs,
        code_units: *const c_char,
        length: i32,
        reason: UConverterCallbackReason,
        err: *mut UErrorCode,
    ),
>;

// ---------------------------------------------------------------------------
// uchar.h
// ---------------------------------------------------------------------------

/// `UCHAR_EAST_ASIAN_WIDTH`: read only through `u_getIntPropertyValue`.
pub const UCHAR_EAST_ASIAN_WIDTH: UProperty = 0x1004;
/// `UCHAR_EMOJI_PRESENTATION`.
pub const UCHAR_EMOJI_PRESENTATION: UProperty = 58;
/// `UCHAR_EMOJI_MODIFIER`.
pub const UCHAR_EMOJI_MODIFIER: UProperty = 59;

/// `UEastAsianWidth` values, in the enum's order.
pub const U_EA_NEUTRAL: i32 = 0;
pub const U_EA_AMBIGUOUS: i32 = 1;
pub const U_EA_HALFWIDTH: i32 = 2;
pub const U_EA_FULLWIDTH: i32 = 3;
pub const U_EA_NARROW: i32 = 4;
pub const U_EA_WIDE: i32 = 5;

/// `UCharCategory` values the column-width rule tests for.
pub const U_NON_SPACING_MARK: i32 = 6; // Mn
pub const U_ENCLOSING_MARK: i32 = 7; // Me
pub const U_CONTROL_CHAR: i32 = 15; // Cc
pub const U_FORMAT_CHAR: i32 = 16; // Cf

/// `UConverterType` values `ConverterObject` treats as Unicode targets.
pub const UCNV_UTF8: i32 = 4;
pub const UCNV_UTF16_BIG_ENDIAN: i32 = 5;
pub const UCNV_UTF16_LITTLE_ENDIAN: i32 = 6;

// ---------------------------------------------------------------------------
// utypes.h
// ---------------------------------------------------------------------------

/// `U_ZERO_ERROR`.
pub const U_ZERO_ERROR: UErrorCode = 0;
/// `U_ILLEGAL_ARGUMENT_ERROR`: what `Transcode` reports for an encoding it does
/// not support.
pub const U_ILLEGAL_ARGUMENT_ERROR: UErrorCode = 1;
/// `U_INVALID_CHAR_FOUND`: unmappable or malformed input.
pub const U_INVALID_CHAR_FOUND: UErrorCode = 10;

/// `U_SUCCESS(code)` is `code <= U_ZERO_ERROR`, which is why the negative
/// warning codes (`U_STRING_NOT_TERMINATED_WARNING` is `-124`) count as success
/// and `U_FAILURE` is the strict `code > U_ZERO_ERROR`.
pub fn u_success(code: UErrorCode) -> bool {
    code <= U_ZERO_ERROR
}

unsafe extern "C" {
    // uchar.h
    pub fn u_getIntPropertyValue_78(c: UChar32, which: UProperty) -> i32;
    pub fn u_hasBinaryProperty_78(c: UChar32, which: UProperty) -> UBool;
    pub fn u_charType_78(c: UChar32) -> i8;
    // utypes.h
    pub fn u_errorName_78(code: UErrorCode) -> *const c_char;

    // ucnv.h
    pub fn ucnv_open_78(name: *const c_char, err: *mut UErrorCode) -> *mut UConverter;
    pub fn ucnv_close_78(converter: *mut UConverter);
    pub fn ucnv_reset_78(converter: *mut UConverter);
    pub fn ucnv_getMinCharSize_78(converter: *const UConverter) -> i8;
    pub fn ucnv_getMaxCharSize_78(converter: *const UConverter) -> i8;
    pub fn ucnv_getType_78(converter: *const UConverter) -> i32;
    pub fn ucnv_toUCountPending_78(converter: *const UConverter, err: *mut UErrorCode) -> i32;
    pub fn ucnv_toUnicode_78(
        converter: *mut UConverter,
        target: *mut *mut UChar,
        target_limit: *const UChar,
        source: *mut *const c_char,
        source_limit: *const c_char,
        offsets: *mut i32,
        flush: UBool,
        err: *mut UErrorCode,
    );
    pub fn ucnv_fromUChars_78(
        converter: *mut UConverter,
        dest: *mut c_char,
        dest_capacity: i32,
        src: *const UChar,
        src_length: i32,
        err: *mut UErrorCode,
    ) -> i32;
    pub fn ucnv_convertEx_78(
        target_cnv: *mut UConverter,
        source_cnv: *mut UConverter,
        target: *mut *mut c_char,
        target_limit: *const c_char,
        source: *mut *const c_char,
        source_limit: *const c_char,
        pivot_start: *mut UChar,
        pivot_source: *mut *mut UChar,
        pivot_target: *mut *mut UChar,
        pivot_limit: *const UChar,
        reset: UBool,
        flush: UBool,
        err: *mut UErrorCode,
    );
    pub fn ucnv_setSubstChars_78(
        converter: *mut UConverter,
        sub_chars: *const c_char,
        len: i8,
        err: *mut UErrorCode,
    );

    // ucnv_err.h. `UCNV_TO_U_CALLBACK_STOP` is an exported function, not a
    // macro, so it is reachable the same way the rest of the API is.
    pub fn UCNV_TO_U_CALLBACK_STOP_78(
        context: *const c_void,
        args: *mut UConverterToUnicodeArgs,
        code_units: *const c_char,
        length: i32,
        reason: UConverterCallbackReason,
        err: *mut UErrorCode,
    );
    pub fn ucnv_setToUCallBack_78(
        converter: *mut UConverter,
        action: UConverterToUCallback,
        context: *const c_void,
        old_action: *mut UConverterToUCallback,
        old_context: *mut *const c_void,
        err: *mut UErrorCode,
    );
}
