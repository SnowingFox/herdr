//! `ConverterObject`, ported from `src/node_i18n.cc`.
//!
//! `lib/internal/encoding.js` builds every `TextDecoder` that is neither UTF-8
//! nor a single-byte legacy encoding through `getConverter`/`decode`. The handle
//! they share is an ICU `UConverter` with its own decoder state, and that state
//! is the whole point: `TextDecoder({ stream: true })` may end a chunk in the
//! middle of a character, and the incomplete bytes have to stay inside the
//! converter until the next call completes them instead of being decoded,
//! flushed and lost.
//!
//! # The three namespace members
//!
//! * `getConverter(label, flags)` returns a handle, or `undefined` when ICU does
//!   not know the label — the JavaScript turns that into
//!   `ERR_ENCODING_NOT_SUPPORTED`.
//! * `decode(handle, input, flags)` converts one chunk. [`FLUSH`] means "this is
//!   the last chunk": convert with `flush`, then reset the handle
//!   so a later `decode` starts clean.
//! * `hasConverter(label)` is the same `ucnv_open` without keeping the result.
//!
//! # What the flags mean
//!
//! [`FATAL`] installs ICU's stop callback, so malformed input fails the call
//! instead of becoming U+FFFD. [`IGNORE_BOM`] suppresses the one-time BOM strip
//! below. [`UNICODE_TARGET`] is derived from `ucnv_getType` and only matters for
//! that strip: a leading U+FEFF is discarded from the first non-empty output of a
//! stream whose target is a Unicode form, and only when the caller did not ask to
//! keep it. That is `TextDecoder`'s `ignoreBOM` semantics, not ICU's.

use std::ffi::{c_char, c_void, CString};

use rn_v8_sys::v8;

use crate::ffi;

/// `CONVERTER_FLAGS_FLUSH`: convert with `flush`, then reset.
pub const FLUSH: u32 = 0x1;
/// `CONVERTER_FLAGS_FATAL`: malformed input is an error, not U+FFFD.
pub const FATAL: u32 = 0x2;
/// `CONVERTER_FLAGS_IGNORE_BOM`: keep a leading U+FEFF.
pub const IGNORE_BOM: u32 = 0x4;
/// `CONVERTER_FLAGS_UNICODE`: the target is UTF-8 or a UTF-16.
const UNICODE_TARGET: u32 = 0x8;
/// `CONVERTER_FLAGS_BOM_SEEN`: the first output has already been examined.
const BOM_SEEN: u32 = 0x10;

/// Internal field holding the `Box<Handle>`.
const HANDLE_FIELD: i32 = 0;

/// The state behind one `getConverter` handle.
struct Handle {
    converter: *mut ffi::UConverter,
    flags: u32,
    /// Keeps the guaranteed finalizer registered: dropping a `Weak` cancels it.
    weak: Option<v8::Weak<v8::Object>>,
}

impl Handle {
    fn has(&self, flag: u32) -> bool {
        self.flags & flag == flag
    }

    fn set(&mut self, flag: u32, value: bool) {
        if value {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }
}

/// Borrows the handle behind a converter object, or `None` when the argument is
/// not one.
fn with_handle<R>(object: v8::Local<v8::Object>, body: impl FnOnce(&mut Handle) -> R) -> Option<R> {
    if object.internal_field_count() <= HANDLE_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer from `install_handle`, and that
    // allocation lives until the finalizer, which cannot run while `object` is a
    // live local.
    let pointer =
        unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) } as *mut Handle;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. The handle is only reachable through this object, and
    // JavaScript cannot run two `decode` calls over one handle at once.
    Some(body(unsafe { &mut *pointer }))
}

fn converter_type(converter: *mut ffi::UConverter) -> i32 {
    // SAFETY: the pointer came from a successful `ucnv_open` and is live.
    unsafe { ffi::ucnv_getType_78(converter) }
}

/// Installs `handle` on `object` and registers the finalizer that closes the
/// converter.
fn install_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    handle: Handle,
) {
    let pointer = Box::into_raw(Box::new(handle));
    object.set_aligned_pointer_in_internal_field(
        HANDLE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut Handle;
            // SAFETY: `install_handle` allocated this Box and nothing else frees
            // it; the finalizer runs exactly once.
            let boxed = unsafe { Box::from_raw(pointer) };
            // SAFETY: the converter belongs to this handle and nothing else
            // closes or uses it once the object is collected.
            unsafe { ffi::ucnv_close_78(boxed.converter) };
            drop(boxed);
        }),
    );

    // The `Weak` must outlive the registration, so it is parked in the state its
    // own finalizer frees. Dropping it from inside that finalizer is a no-op.
    //
    // SAFETY: `pointer` was just created above and nothing aliases it yet.
    unsafe { (*pointer).weak = Some(weak) };
}

/// `getConverter(label, flags)`: opens a converter, or reports an unknown label.
///
/// `None` covers both an unknown label and an allocation failure; the JavaScript
/// turns either into `ERR_ENCODING_NOT_SUPPORTED`, which is what Node does when
/// `ucnv_open` fails.
pub fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    template: v8::Local<'s, v8::ObjectTemplate>,
    label: &str,
    flags: u32,
) -> Option<v8::Local<'s, v8::Object>> {
    let name = CString::new(label).ok()?;
    let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
    // SAFETY: `name` is a valid NUL-terminated label.
    let converter = unsafe { ffi::ucnv_open_78(name.as_ptr(), &mut status) };
    if !ffi::u_success(status) || converter.is_null() {
        return None;
    }

    if flags & FATAL == FATAL {
        let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
        // SAFETY: `converter` is live. `UCNV_TO_U_CALLBACK_STOP` makes malformed
        // input set a failure code instead of substituting U+FFFD, which is what
        // `{ fatal: true }` promises. The previous callback is not wanted, so
        // both out-parameters are null.
        unsafe {
            ffi::ucnv_setToUCallBack_78(
                converter,
                Some(ffi::UCNV_TO_U_CALLBACK_STOP_78),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut status,
            );
        }
        if !ffi::u_success(status) {
            // SAFETY: opened above, not stored anywhere yet.
            unsafe { ffi::ucnv_close_78(converter) };
            return None;
        }
    }

    let mut handle = Handle {
        converter,
        flags,
        weak: None,
    };

    // Node sizes the substitution bytes from this converter's *minimum* char
    // size. For every encoding `TextDecoder` asks for that is one byte, i.e. a
    // single `?`.
    //
    // SAFETY: `converter` is live.
    let min_char_size = unsafe { ffi::ucnv_getMinCharSize_78(converter) };
    let substitution = vec![b'?'; usize::try_from(min_char_size.max(1)).unwrap_or(1)];
    let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
    // SAFETY: `converter` is live and `substitution` outlives the call.
    unsafe {
        ffi::ucnv_setSubstChars_78(
            converter,
            substitution.as_ptr().cast(),
            i8::try_from(substitution.len()).unwrap_or(1),
            &mut status,
        );
    }
    if !ffi::u_success(status) {
        // SAFETY: as above; nothing holds the converter yet.
        unsafe { ffi::ucnv_close_78(converter) };
        return None;
    }

    if matches!(
        converter_type(converter),
        ffi::UCNV_UTF8 | ffi::UCNV_UTF16_BIG_ENDIAN | ffi::UCNV_UTF16_LITTLE_ENDIAN
    ) {
        handle.flags |= UNICODE_TARGET;
    }

    let object = template.new_instance(scope)?;
    install_handle(scope, object, handle);
    Some(object)
}

/// `hasConverter(label)`: whether ICU resolves the label. The converter is
/// opened and closed rather than cached, because the answer is about ICU's
/// tables, not about this call.
pub fn has_converter(label: &str) -> bool {
    let Ok(name) = CString::new(label) else {
        return false;
    };
    let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
    // SAFETY: `name` is a valid NUL-terminated label.
    let converter = unsafe { ffi::ucnv_open_78(name.as_ptr(), &mut status) };
    if converter.is_null() {
        return false;
    }
    // SAFETY: the converter is owned here.
    unsafe { ffi::ucnv_close_78(converter) };
    ffi::u_success(status)
}

/// Why `decode` produced no text.
pub enum DecodeError {
    /// The first argument was not a converter handle.
    NotAHandle,
    /// ICU rejected the bytes. The caller reports
    /// `ERR_ENCODING_INVALID_ENCODED_DATA`.
    InvalidData,
}

/// `decode(handle, input, flags)`: one chunk through the handle's converter.
///
/// Returns UTF-16 units rather than a `str` because a lone surrogate is a legal
/// intermediary in a UTF-16 stream, and `String` cannot hold one.
pub fn decode(
    object: v8::Local<v8::Object>,
    input: &[u8],
    flags: u32,
) -> Result<Vec<u16>, DecodeError> {
    match with_handle(object, |handle| convert(handle, input, flags)) {
        None => Err(DecodeError::NotAHandle),
        Some(Err(_)) => Err(DecodeError::InvalidData),
        Some(Ok(units)) => Ok(units),
    }
}

fn convert(handle: &mut Handle, input: &[u8], flags: u32) -> Result<Vec<u16>, ffi::UErrorCode> {
    let flush = flags & FLUSH == FLUSH;

    // SAFETY: the converter is live for as long as the handle is.
    let min_char_size =
        usize::try_from(unsafe { ffi::ucnv_getMinCharSize_78(handle.converter) }.max(1))
            .unwrap_or(1);

    // Node's bound: two UChars per input byte, and on the flushing call at least
    // as many as the bytes still pending inside the converter. The pending count
    // is what gives the final call room to emit the character an earlier chunk
    // left half-decoded.
    let available = if flush {
        let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
        // SAFETY: as above.
        let pending = unsafe { ffi::ucnv_toUCountPending_78(handle.converter, &mut status) };
        input.len().max(usize::try_from(pending).unwrap_or(0))
    } else {
        input.len()
    };
    let limit = 2usize
        .saturating_mul(min_char_size)
        .saturating_mul(available);

    // A zero-length limit is legal: ICU writes nothing and the result is empty.
    // The vector still needs a pointer, so it is never zero-capacity.
    let mut output = vec![0u16; limit.max(1)];

    let mut status: ffi::UErrorCode = ffi::U_ZERO_ERROR;
    let mut source = input.as_ptr().cast::<c_char>();
    let mut target = output.as_mut_ptr();

    // SAFETY: the source range is the caller's slice and the target range is
    // inside `output`. No offsets are requested.
    unsafe {
        ffi::ucnv_toUnicode_78(
            handle.converter,
            &mut target,
            output.as_ptr().add(limit),
            &mut source,
            input.as_ptr().add(input.len()).cast(),
            std::ptr::null_mut(),
            if flush { 1 } else { 0 },
            &mut status,
        );
    }

    if flush {
        // Node's `OnScopeLeave`: the converter is reset whether the call
        // succeeded or not, and the BOM decision starts over for the next stream.
        handle.set(BOM_SEEN, false);
        // SAFETY: the converter is live.
        unsafe { ffi::ucnv_reset_78(handle.converter) };
    }

    if !ffi::u_success(status) {
        return Err(status);
    }

    let written = (target as usize - output.as_ptr() as usize) / 2;
    output.truncate(written);

    if !output.is_empty()
        && handle.has(UNICODE_TARGET)
        && !handle.has(IGNORE_BOM)
        && !handle.has(BOM_SEEN)
    {
        // The first non-empty output of the stream decides, once, whether a
        // leading BOM is data or a signature.
        let omit = output[0] == 0xFEFF;
        handle.set(BOM_SEEN, true);
        if omit {
            output.remove(0);
        }
    }

    Ok(output)
}

/// Builds a JavaScript string from UTF-16 units, lone surrogates included.
///
/// `String::new_from_two_byte` does not validate, which is exactly the property
/// `StringBytes::Encode(..., UCS2)` has on Node's side and what a streamed
/// UTF-16 chunk can need.
pub fn units_to_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    units: &[u16],
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_two_byte(scope, units, v8::NewStringType::Normal)
}
