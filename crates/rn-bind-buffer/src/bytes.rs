//! The in-place and comparison members: `compare`, `copy`, `fill`, `indexOf*`,
//! `swap*` and `mask`.
//!
//! These all mutate or read a caller-owned `ArrayBufferView`, so the shared
//! hazard is aliasing: `mask` is called as `mask(buffer, buffer, ...)` for the
//! in-place WebSocket case, and `copy` can be handed two views over the same
//! `ArrayBuffer`. Both are handled the way `node_buffer.cc` handles them —
//! move semantics for `copy`, and a staged source for `mask` when the ranges
//! overlap.

use rn_v8_sys::v8;

use crate::args::{self, parse_index, require_view, Index};
use rn_core::codec::Encoding;

/// `compare(a, b)`: `-1`, `0` or `1` like `Buffer.compare`.
///
/// `normalizeCompareVal` clamps the byte comparison to `[1, -1]`, and when the
/// common prefix ties it compares lengths, so a prefix sorts before the longer
/// buffer.
pub(crate) fn compare(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<i32> {
    let left = args.get(0);
    let right = args.get(1);
    if !require_view(scope, left) || !require_view(scope, right) {
        return None;
    }
    args::with_view_bytes(left, |a| {
        args::with_view_bytes(right, |b| {
            let count = a.len().min(b.len());
            normalize_compare(a[..count].cmp(&b[..count]), a.len(), b.len())
        })
    })
    .flatten()
}

/// `normalizeCompareVal`: clamp a byte-wise comparison to `-1`/`0`/`1`, falling
/// back to the lengths when the common prefix ties.
fn normalize_compare(ordering: std::cmp::Ordering, left: usize, right: usize) -> i32 {
    match ordering {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => match left.cmp(&right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        },
    }
}

/// `compareOffset(target, source, targetStart, sourceStart, targetEnd, sourceEnd)`.
///
/// `lib/buffer.js` calls `compareOffset(this, target, targetStart, sourceStart,
/// targetEnd, sourceEnd)`, so `args[0]` is the source Buffer and `args[1]` the
/// target. `CompareOffset` compares only
/// `min(sourceEnd - sourceStart, targetEnd - targetStart, source.length -
/// sourceStart)` bytes but normalizes the result against the full window
/// lengths, which is why the two are tracked separately below.
pub(crate) fn compare_offset(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<i32> {
    let source = args.get(0);
    let target = args.get(1);
    if !require_view(scope, source) || !require_view(scope, target) {
        return None;
    }
    let source_length = args::view_len(source)?;
    let target_length = args::view_len(target)?;

    let target_start = match parse_index(scope, args.get(2), 0) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let source_start = match parse_index(scope, args.get(3), 0) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let target_end = match parse_index(scope, args.get(4), target_length) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let source_end = match parse_index(scope, args.get(5), source_length) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };

    if source_start > source_length {
        args::throw_range_error(scope, "The value of \"sourceStart\" is out of range.");
        return None;
    }
    if target_start > target_length {
        args::throw_range_error(scope, "The value of \"targetStart\" is out of range.");
        return None;
    }

    args::with_view_bytes(source, |a| {
        args::with_view_bytes(target, |b| {
            let source_window = &a[source_start..source_end.min(a.len())];
            let target_window = &b[target_start..target_end.min(b.len())];
            let count = source_window.len().min(target_window.len());
            normalize_compare(
                source_window[..count].cmp(&target_window[..count]),
                source_window.len(),
                target_window.len(),
            )
        })
    })
    .flatten()
}

/// `copy(source, target, targetStart, sourceStart, toCopy)`.
///
/// Returns the byte count as a double, because lengths above 4 GiB are
/// representable (`SlowCopy` does the same for that reason). `copy_within`
/// provides the move semantics `CopyArrayBufferBytes` has, so an overlapping
/// source and target behave like `memmove` rather than clobbering themselves.
pub(crate) fn copy(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let source = args.get(0);
    let target = args.get(1);
    if !require_view(scope, source) || !require_view(scope, target) {
        return None;
    }
    let target_start = args::number_to_size(scope, args.get(2))?;
    let source_start = args::number_to_size(scope, args.get(3))?;
    let to_copy = args::number_to_size(scope, args.get(4))?;

    let source_length = args::view_len(source)?;
    let target_length = args::view_len(target)?;
    let count = to_copy
        .min(source_length.saturating_sub(source_start))
        .min(target_length.saturating_sub(target_start));
    if count == 0 {
        return Some(0.0);
    }

    if source == target {
        // One view: a move inside its own byte range.
        args::with_view_bytes_mut(target, |bytes| {
            bytes.copy_within(source_start..source_start + count, target_start);
        });
        return Some(count as f64);
    }

    // Two views that may still share an `ArrayBuffer`, so the source bytes are
    // staged before the destination is written.
    let staged = args::copy_view(source)?;
    args::with_view_bytes_mut(target, |bytes| {
        bytes[target_start..target_start + count]
            .copy_from_slice(&staged[source_start..source_start + count]);
    });
    Some(count as f64)
}

/// `fill(buffer, value, offset, end[, encoding])`.
///
/// Returns `-2` for an out-of-bounds range and `-1` for a value that could not
/// be written; `lib/buffer.js` turns those into `ERR_BUFFER_OUT_OF_BOUNDS` and
/// `ERR_INVALID_ARG_VALUE`. Otherwise the buffer is filled and the result is
/// unused.
pub(crate) fn fill(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<i32> {
    let target = args.get(0);
    if !require_view(scope, target) {
        return None;
    }
    let length = args::view_len(target)?;
    let start = match parse_index(scope, args.get(2), 0) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let end = match parse_index(scope, args.get(3), 0) {
        Index::Value(index) => index,
        Index::OutOfRange => {
            args::throw_range_error(scope, "Index out of range");
            return None;
        }
    };
    let fill_length = end.saturating_sub(start);
    if start > end || start + fill_length > length {
        return Some(-2);
    }
    if fill_length == 0 {
        return Some(0);
    }

    let value = args.get(1);

    // A Buffer value is written once and then repeated.
    if value.is_array_buffer_view() {
        let pattern = args::copy_view(value)?;
        if pattern.is_empty() {
            return Some(-1);
        }
        args::with_view_bytes_mut(target, |bytes| {
            let window = &mut bytes[start..start + fill_length];
            let count = pattern.len().min(window.len());
            window[..count].copy_from_slice(&pattern[..count]);
            repeat(window, count);
        });
        return Some(0);
    }

    // Everything that is not a string becomes one byte.
    if !value.is_string() {
        let byte = (value.uint32_value(scope)? & 0xff) as u8;
        args::with_view_bytes_mut(target, |bytes| {
            bytes[start..start + fill_length].fill(byte);
        });
        return Some(0);
    }

    let encoding = args::parse_encoding(scope, Some(args.get(4)), Encoding::Utf8);
    let Ok(string) = v8::Local::<v8::String>::try_from(value) else {
        return None;
    };
    let units = args::string_to_units(&string, scope);
    // `Fill` encodes the string once into the destination and then doubles the
    // written prefix. The repeat unit is therefore whatever fit in one pass —
    // which for `utf8` means a multi-byte character *can* be cut in half, unlike
    // `write`. See `encode_fill_pattern`.
    let pattern = encode_fill_pattern(&units, encoding, fill_length);

    if pattern.is_empty() {
        // An empty string or a value whose encoding produced no bytes. Node
        // reports -1 and `lib/buffer.js` throws ERR_INVALID_ARG_VALUE.
        return Some(-1);
    }
    args::with_view_bytes_mut(target, |bytes| {
        let window = &mut bytes[start..start + fill_length];
        let count = pattern.len().min(window.len());
        window[..count].copy_from_slice(&pattern[..count]);
        if count < window.len() {
            repeat(window, count);
        }
    });
    Some(0)
}

/// The repeat unit `fill` writes, truncated to the fill window.
///
/// `fill` truncates the *encoded* bytes with a plain `memcpy`, so unlike
/// `write` it does split a multi-byte character:
/// `Buffer.alloc(3).fill('😀')` is `f0 9f 98`, and `.fill('é')` into one byte is
/// `c3`. So this encodes without a length limit and truncates afterwards; using
/// [`rn_core::codec::encode_utf8`] with `fill_length` would stop at a character
/// boundary and produce nothing instead.
fn encode_fill_pattern(units: &[u16], encoding: Encoding, fill_length: usize) -> Vec<u8> {
    let whole = match encoding {
        Encoding::Utf8 | Encoding::Buffer => rn_core::codec::encode_utf8(units, usize::MAX),
        Encoding::Ucs2 => rn_core::codec::encode_ucs2(units, usize::MAX),
        Encoding::Ascii | Encoding::Binary => units_to_bytes(units),
        Encoding::Hex => {
            let text = units_to_bytes(units);
            let mut out = vec![0u8; text.len() / 2];
            let written = rn_core::codec::decode_hex(&text, &mut out);
            out.truncate(written);
            out
        }
        Encoding::Base64 | Encoding::Base64Url => {
            let text = units_to_bytes(units);
            let mut out = vec![0u8; text.len()];
            let written = rn_core::codec::decode_base64_forgiving(&text, &mut out);
            out.truncate(written);
            out
        }
    };
    whole[..whole.len().min(fill_length)].to_vec()
}

/// The low byte of each code unit, which is what `StringBytes::Write` casts.
fn units_to_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().map(|unit| (*unit & 0xff) as u8).collect()
}

/// The doubling loop at the end of `Fill`: repeat the written prefix until the
/// whole window is covered.
fn repeat(window: &mut [u8], written: usize) {
    let mut in_there = written;
    while in_there < window.len() - in_there {
        let (head, tail) = window.split_at_mut(in_there);
        tail[..in_there].copy_from_slice(&head[..in_there]);
        in_there *= 2;
    }
    if in_there < window.len() {
        let remaining = window.len() - in_there;
        let (head, tail) = window.split_at_mut(in_there);
        tail[..remaining].copy_from_slice(&head[..remaining]);
    }
}

/// `IndexOfOffset`: where a search starts, or `-1` for "no possible match".
///
/// Negative offsets count back from the end; a forward search from before the
/// start searches everything, while a backward one matches nothing.
pub(crate) fn index_of_offset(
    length: usize,
    offset: i64,
    needle_length: i64,
    forward: bool,
) -> i64 {
    let length = length as i64;
    if offset < 0 {
        if offset + length >= 0 {
            length + offset
        } else if forward || needle_length == 0 {
            0
        } else {
            -1
        }
    } else if offset + needle_length <= length {
        offset
    } else if needle_length == 0 {
        length
    } else if forward {
        -1
    } else {
        length - 1
    }
}

/// The shared argument set of `IndexOfString` and `IndexOfBuffer`.
pub(crate) struct IndexOfRequest {
    offset: i64,
    forward: bool,
    end: i64,
    encoding: Encoding,
}

/// The resolved search window, or the answer for an empty needle.
enum Window {
    /// `(offset, search_end)`.
    Search(usize, usize),
    /// No possible match.
    Missing,
    /// An empty needle: this value is the answer.
    EmptyAnswer(i64),
}

impl IndexOfRequest {
    pub fn parse(
        scope: &mut v8::PinScope<'_, '_>,
        args: &v8::FunctionCallbackArguments<'_>,
    ) -> Self {
        Self {
            offset: args.get(2).integer_value(scope).unwrap_or(0),
            forward: args.get(4).is_true(),
            end: args.get(5).integer_value(scope).unwrap_or(0),
            encoding: args::encoding_argument(scope, args.get(3)),
        }
    }

    /// Resolves the window against a haystack of `haystack_length` bytes.
    fn window(&self, haystack_length: usize, needle_length: usize) -> Window {
        let search_end = self.end.max(0).min(haystack_length as i64) as usize;
        let search_end = if self.encoding.is_wide() {
            search_end & !1
        } else {
            search_end
        };
        let optimal = index_of_offset(
            haystack_length,
            self.offset,
            needle_length as i64,
            self.forward,
        );
        if needle_length == 0 {
            return Window::EmptyAnswer(optimal.min(search_end as i64));
        }
        if haystack_length == 0 || optimal <= -1 {
            return Window::Missing;
        }
        let mut offset = optimal as usize;
        if !self.forward && offset >= search_end {
            if search_end == 0 {
                return Window::Missing;
            }
            offset = search_end - 1;
        } else if self.forward && offset >= search_end {
            return Window::Missing;
        }
        if self.encoding.is_wide() && self.forward {
            offset += offset % 2;
            if offset >= search_end {
                return Window::Missing;
            }
        }
        if (self.forward && needle_length + offset > search_end) || needle_length > search_end {
            return Window::Missing;
        }
        Window::Search(offset, search_end)
    }
}

/// `indexOfString(buffer, string, byteOffset, encoding, dir, end)`.
pub(crate) fn index_of_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let haystack = args.get(0);
    if !require_view(scope, haystack) {
        return None;
    }
    let Ok(needle) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        args::throw_type_error(scope, "argument must be a string");
        return None;
    };
    let request = IndexOfRequest::parse(scope, &args);
    let haystack_length = args::view_len(haystack)?;
    let haystack_length = if request.encoding.is_wide() {
        haystack_length & !1
    } else {
        haystack_length
    };
    let units = args::string_to_units(&needle, scope);
    let needle_bytes = encode_needle(&units, request.encoding);
    // `StringBytes::Size` is what `IndexOfString` validates `search_end`
    // against, and for `ucs2` it is twice the code unit count.
    let needle_length = needle_bytes.len();

    match request.window(haystack_length, needle_length) {
        Window::EmptyAnswer(answer) => Some(answer as f64),
        Window::Missing => Some(-1.0),
        Window::Search(offset, search_end) => {
            let found = args::with_view_bytes(haystack, |haystack_bytes| {
                if request.encoding.is_wide() {
                    if search_end < 2 || units.is_empty() {
                        return search_end;
                    }
                    rn_core::codec::search_ucs2(
                        haystack_bytes,
                        &units,
                        search_end,
                        offset / 2,
                        request.forward,
                    )
                } else {
                    rn_core::codec::search_bytes(
                        haystack_bytes,
                        &needle_bytes,
                        search_end,
                        offset,
                        request.forward,
                    )
                }
            })?;
            Some(if found >= search_end {
                -1.0
            } else {
                found as f64
            })
        }
    }
}

/// The needle bytes for one encoding, as `StringBytes::Write` would produce.
fn encode_needle(units: &[u16], encoding: Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Utf8 | Encoding::Buffer => rn_core::codec::encode_utf8(units, usize::MAX),
        Encoding::Ucs2 => rn_core::codec::encode_ucs2(units, usize::MAX),
        Encoding::Ascii | Encoding::Binary => units_to_bytes(units),
        Encoding::Hex => {
            let text = units_to_bytes(units);
            let mut out = vec![0u8; text.len() / 2];
            let written = rn_core::codec::decode_hex(&text, &mut out);
            out.truncate(written);
            out
        }
        Encoding::Base64 | Encoding::Base64Url => {
            let text = units_to_bytes(units);
            let mut out = vec![0u8; rn_core::codec::base64_encoded_len(text.len(), false)];
            let written = rn_core::codec::decode_base64_forgiving(&text, &mut out);
            out.truncate(written);
            out
        }
    }
}

/// `indexOfBuffer(buffer, needle, byteOffset, encoding, dir, end)`.
pub(crate) fn index_of_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let haystack = args.get(0);
    let needle = args.get(1);
    if !require_view(scope, haystack) || !require_view(scope, needle) {
        return None;
    }
    let request = IndexOfRequest::parse(scope, &args);
    let haystack_length = args::view_len(haystack)?;
    let haystack_length = if request.encoding.is_wide() {
        haystack_length & !1
    } else {
        haystack_length
    };
    let needle_bytes = args::copy_view(needle)?;

    match request.window(haystack_length, needle_bytes.len()) {
        Window::EmptyAnswer(answer) => Some(answer as f64),
        Window::Missing => Some(-1.0),
        Window::Search(offset, search_end) => {
            let found = args::with_view_bytes(haystack, |haystack_bytes| {
                if request.encoding.is_wide() {
                    if search_end < 2 || needle_bytes.len() < 2 {
                        return search_end;
                    }
                    let needle_units = rn_core::codec::decode_ucs2(&needle_bytes);
                    rn_core::codec::search_ucs2(
                        haystack_bytes,
                        &needle_units,
                        search_end,
                        offset / 2,
                        request.forward,
                    )
                } else {
                    rn_core::codec::search_bytes(
                        haystack_bytes,
                        &needle_bytes,
                        search_end,
                        offset,
                        request.forward,
                    )
                }
            })?;
            Some(if found >= search_end {
                -1.0
            } else {
                found as f64
            })
        }
    }
}

/// `indexOfNumber(buffer, value, byteOffset, dir, end)`.
pub(crate) fn index_of_number(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<f64> {
    let haystack = args.get(0);
    if !require_view(scope, haystack) {
        return None;
    }
    let needle = (args.get(1).uint32_value(scope).unwrap_or(0) & 0xff) as u8;
    let offset = args.get(2).integer_value(scope).unwrap_or(0);
    let forward = args.get(3).is_true();
    let end = args.get(4).integer_value(scope).unwrap_or(0);

    let length = args::view_len(haystack)?;
    let optimal = index_of_offset(length, offset, 1, forward);
    if optimal <= -1 || length == 0 {
        return Some(-1.0);
    }
    let start = optimal as usize;
    let search_end = end.max(0).min(length as i64) as usize;

    let found = args::with_view_bytes(haystack, |bytes| {
        if forward {
            if start >= search_end {
                return None;
            }
            bytes[start..search_end]
                .iter()
                .position(|byte| *byte == needle)
                .map(|index| start + index)
        } else {
            let backward_end = (start + 1).min(search_end);
            if backward_end == 0 {
                return None;
            }
            bytes[..backward_end]
                .iter()
                .rposition(|byte| *byte == needle)
        }
    })?;

    Some(found.map_or(-1.0, |index| index as f64))
}

/// `swap16`/`swap32`/`swap64`: reverse the bytes of each word in place.
///
/// The C++ `CHECK`s that the length is a multiple of the word size, and
/// `lib/buffer.js` throws `ERR_INVALID_BUFFER_SIZE` before reaching it for small
/// buffers. A rejected length throws the same error here rather than panicking.
pub(crate) fn swap(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    word: usize,
) -> Option<bool> {
    let target = args.get(0);
    if !require_view(scope, target) {
        return None;
    }
    let length = args::view_len(target)?;
    if length % word != 0 {
        let message = format!("Buffer size must be a multiple of {}-bits", word * 8);
        args::throw_range_error(scope, &message);
        return None;
    }
    args::with_view_bytes_mut(target, |bytes| {
        for chunk in bytes.chunks_exact_mut(word) {
            chunk.reverse();
        }
    });
    Some(true)
}

/// `mask(source, destination, offset, length, mask)`.
///
/// XORs `length` bytes of `source` with the repeating 4-byte little-endian
/// `mask` into `destination` at `offset`. `http.js` calls it with
/// `source === destination` for the in-place unmask, which is why the source
/// bytes are always staged.
pub(crate) fn mask(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
) -> Option<bool> {
    let source = args.get(0);
    let destination = args.get(1);
    if !require_view(scope, source) || !require_view(scope, destination) {
        return None;
    }
    let offset = args::number_to_size(scope, args.get(2))?;
    let length = args::number_to_size(scope, args.get(3))?;
    let mask_value = args.get(4).uint32_value(scope).unwrap_or(0);

    let destination_length = args::view_len(destination)?;
    let source_length = args::view_len(source)?;
    if offset > destination_length || length > destination_length - offset {
        args::throw_range_error(scope, "offset and length are out of range");
        return None;
    }
    if length > source_length {
        args::throw_range_error(scope, "length exceeds the source buffer");
        return None;
    }
    if length == 0 {
        return Some(true);
    }

    let pattern = mask_value.to_le_bytes();
    let staged = args::copy_view(source)?;
    args::with_view_bytes_mut(destination, |bytes| {
        let window = &mut bytes[offset..offset + length];
        for (index, byte) in window.iter_mut().enumerate() {
            *byte = staged[index] ^ pattern[index & 3];
        }
    });
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_normalizes_to_unit_range() {
        assert_eq!(normalize_compare(std::cmp::Ordering::Less, 5, 5), -1);
        assert_eq!(normalize_compare(std::cmp::Ordering::Greater, 5, 5), 1);
        assert_eq!(normalize_compare(std::cmp::Ordering::Equal, 5, 5), 0);
        // Equal prefix: the shorter buffer sorts first.
        assert_eq!(normalize_compare(std::cmp::Ordering::Equal, 4, 5), -1);
        assert_eq!(normalize_compare(std::cmp::Ordering::Equal, 5, 4), 1);
    }

    #[test]
    fn index_of_offset_matches_the_cpp() {
        // Forward, inside range.
        assert_eq!(index_of_offset(10, 3, 2, true), 3);
        // Forward from before the start searches everything.
        assert_eq!(index_of_offset(10, -20, 2, true), 0);
        // Backward from before the start matches nothing.
        assert_eq!(index_of_offset(10, -20, 2, false), -1);
        // A negative offset inside the range counts back from the end.
        assert_eq!(index_of_offset(10, -3, 2, true), 7);
        // An empty needle past the end points at the end.
        assert_eq!(index_of_offset(10, 20, 0, true), 10);
        // Forward past the end: no match.
        assert_eq!(index_of_offset(10, 20, 2, true), -1);
        // Backward past the end searches the whole buffer.
        assert_eq!(index_of_offset(10, 20, 2, false), 9);
    }

    #[test]
    fn repeat_covers_the_whole_window() {
        let mut window = [0u8; 9];
        window[..2].copy_from_slice(b"ab");
        repeat(&mut window, 2);
        assert_eq!(&window, b"ababababa");

        let mut window = [0u8; 4];
        window[..4].copy_from_slice(b"abcd");
        repeat(&mut window, 4);
        assert_eq!(&window, b"abcd");

        let mut window = [0u8; 6];
        window[..3].copy_from_slice(b"xyz");
        repeat(&mut window, 3);
        assert_eq!(&window, b"xyzxyz");
    }

    #[test]
    fn fill_pattern_splits_a_character_like_memcpy() {
        // node: Buffer.alloc(3).fill('😀').toString('hex') -> "f09f98"
        assert_eq!(
            encode_fill_pattern(&[0xD83D, 0xDE00], Encoding::Utf8, 3),
            vec![0xF0, 0x9F, 0x98]
        );
        // node: Buffer.alloc(1).fill('é').toString('hex') -> "c3"
        assert_eq!(
            encode_fill_pattern(&[0x00E9], Encoding::Utf8, 1),
            vec![0xC3]
        );
        assert_eq!(
            encode_fill_pattern(&[0x00E9], Encoding::Utf8, 3),
            vec![0xC3, 0xA9]
        );
        // `ucs2` truncates to whole units because the encoder counts them.
        assert_eq!(
            encode_fill_pattern(&[0x0041, 0x0042], Encoding::Ucs2, 5),
            vec![0x41, 0x00, 0x42, 0x00]
        );
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn needle_encoding_stops_at_invalid_input() {
        assert_eq!(
            encode_needle(&[0x0041, 0x0042], Encoding::Utf8),
            b"AB".to_vec()
        );
        assert_eq!(encode_needle(&units("abc"), Encoding::Hex), vec![0xAB]);
        assert_eq!(encode_needle(&[0x00E9], Encoding::Ascii), vec![0xE9]);
    }
}
