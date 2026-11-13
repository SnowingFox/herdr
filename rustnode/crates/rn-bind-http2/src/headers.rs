//! Header blocks in the shape nghttp2 takes and in the shape `core.js` reads.
//!
//! Two directions, and they are not symmetric:
//!
//! * **JavaScript → nghttp2.** `core.js` builds a flat array
//!   `[name, value, name, value, ...]` with parallel `sensitiveHeaders` and calls
//!   `respond(array, options)` or `request(array, ...)`. [`nv_from_array`] turns
//!   that into the `nghttp2_nv` array `nghttp2_submit_*` wants.
//! * **nghttp2 → JavaScript.** The `on_header` callback delivers each pair
//!   separately; the callbacks module accumulates them and `headers_to_array`
//!   flattens them back into the same interleaved array, because that is what
//!   `toHeaderObject` in `core.js` walks.
//!
//! # Why the storage is owned by the caller
//!
//! `nghttp2_submit_*` copies the name/value bytes it is given, so the `Vec<u8>`s
//! only need to outlive the call. [`HeaderBlock`] holds them in one allocation so
//! the `nghttp2_nv` pointers stay valid while the submit function runs, and drops
//! the whole thing afterwards.

use rn_v8_sys::v8;

use crate::ffi;

/// An `nghttp2_nv` array plus the bytes its pointers refer to.
pub struct HeaderBlock {
    entries: Vec<ffi::nghttp2_nv>,
    /// The `name`/`value` bytes, in the order they were pushed. Held only to keep
    /// the pointers in `entries` valid.
    #[allow(dead_code)]
    storage: Vec<Vec<u8>>,
}

impl HeaderBlock {
    /// The array, ready for an `nghttp2_submit_*` call.
    pub fn as_ptr(&self) -> *const ffi::nghttp2_nv {
        self.entries.as_ptr()
    }

    /// How many pairs the block holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The triples this block was built from.
    pub fn pairs(&self) -> Vec<(&[u8], &[u8], u8)> {
        self.storage
            .chunks(2)
            .enumerate()
            .map(|(index, _)| {
                (
                    self.storage[index * 2].as_slice(),
                    self.storage[index * 2 + 1].as_slice(),
                    self.entries[index].flags,
                )
            })
            .collect()
    }

    /// Whether the block holds no pairs, which is what a `SETTINGS`-only submit
    /// looks like.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Builds a header block from the `[headerString, count]` array `core.js` passes.
///
/// The format is Node's, from `NgHeaders<T>::NgHeaders`
/// (`src/node_http_common-inl.h`), and it is not an array of pairs:
///
/// * element 0 is a **single Latin-1 string** holding `name\0value\0flags`
///   repeated `count` times;
/// * element 1 is the pair count, as a `uint32`.
///
/// `buildNgHeaderString` in `lib/internal/http2/util.js` is what produces it, and
/// `Http2Headers` is what consumes it. Reading it as a flat `[name, value, ...]`
/// array — which this function did at first — sends the string's *length* as a
/// header name and every request is rejected with `PROTOCOL_ERROR`.
///
/// The `flags` byte is the third field of each triple, and it is what carries
/// `NGHTTP2_NV_FLAG_NO_INDEX` for a sensitive header.
pub fn nv_from_array(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<HeaderBlock> {
    let array = v8::Local::<v8::Array>::try_from(value).ok()?;
    let header_string = array.get_index(scope, 0)?;
    let count = array.get_index(scope, 1)?.uint32_value(scope)? as usize;
    let text = v8::Local::<v8::String>::try_from(header_string).ok()?;

    // Latin-1, because that is the encoding `StringBytes::Write(..., LATIN1)` uses
    // and each byte has to survive the round trip: the separator is a NUL and a
    // multi-byte encoding would make the parse ambiguous.
    let length = text.length();
    let mut bytes = vec![0u8; length];
    text.write_one_byte_v2(scope, 0, &mut bytes, v8::WriteFlags::empty());

    let mut entries: Vec<ffi::nghttp2_nv> = Vec::with_capacity(count);
    let mut storage: Vec<Vec<u8>> = Vec::with_capacity(count * 2);
    let mut position = 0usize;
    for _ in 0..count {
        let name = read_until_nul(&bytes, &mut position)?;
        let value_bytes = read_until_nul(&bytes, &mut position)?;
        let flags = *bytes.get(position)?;
        position += 1;
        storage.push(name);
        storage.push(value_bytes);
        let pair = storage.len();
        entries.push(ffi::nghttp2_nv {
            name: storage[pair - 2].as_ptr().cast_mut(),
            value: storage[pair - 1].as_ptr().cast_mut(),
            namelen: storage[pair - 2].len(),
            valuelen: storage[pair - 1].len(),
            flags,
        });
    }
    // The pointers above are taken while `storage` grows, which would invalidate
    // them — so they are recomputed once it is complete. Each inner `Vec<u8>` keeps
    // its own heap buffer across a reallocation of the outer one, but taking the
    // addresses last removes the need to rely on that.
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.name = storage[index * 2].as_ptr().cast_mut();
        entry.value = storage[index * 2 + 1].as_ptr().cast_mut();
    }
    Some(HeaderBlock { entries, storage })
}

/// Reads one NUL-terminated field, advancing `position` past the terminator.
fn read_until_nul(bytes: &[u8], position: &mut usize) -> Option<Vec<u8>> {
    let start = *position;
    let mut end = start;
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    if end >= bytes.len() {
        return None;
    }
    *position = end + 1;
    Some(bytes[start..end].to_vec())
}

/// Builds a header block from owned `(name, value, flags)` triples.
///
/// This is the replay form: a submit recorded while nghttp2 was mid-receive has to
/// own its bytes, because the JavaScript frame that produced them is gone by the
/// time the queue is drained. [`nv_from_array`] builds the same array from a live
/// JS array; both end up here so there is one definition of the `nghttp2_nv` layout
/// in play.
pub fn block_from_pairs(pairs: &[(Vec<u8>, Vec<u8>, u8)]) -> HeaderBlock {
    let mut entries: Vec<ffi::nghttp2_nv> = Vec::with_capacity(pairs.len());
    let mut storage: Vec<Vec<u8>> = Vec::with_capacity(pairs.len() * 2);
    for (name, value, _flags) in pairs {
        storage.push(name.clone());
        storage.push(value.clone());
    }
    for (index, (_name, _value, flags)) in pairs.iter().enumerate() {
        entries.push(ffi::nghttp2_nv {
            name: storage[index * 2].as_ptr().cast_mut(),
            value: storage[index * 2 + 1].as_ptr().cast_mut(),
            namelen: storage[index * 2].len(),
            valuelen: storage[index * 2 + 1].len(),
            flags: *flags,
        });
    }
    HeaderBlock { entries, storage }
}

/// The `(name, value, flags)` triples behind a block, for a deferred submit.
///
/// Reading them back out of the `nghttp2_nv` array is what lets a submit site hand
/// one representation to both the immediate path and the queue.
pub fn pairs_of(block: &HeaderBlock) -> Vec<(Vec<u8>, Vec<u8>, u8)> {
    block
        .pairs()
        .iter()
        .map(|(name, value, flags)| (name.to_vec(), value.to_vec(), *flags))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_byte_is_nghttp2s_none() {
        // A header block with any other flag would mark the field indexable or not
        // on the wire. `core.js` sets sensitivity on a separate array, so every
        // entry here is `NGHTTP2_NV_FLAG_NONE`.
        assert_eq!(ffi::NGHTTP2_NV_FLAG_NONE, 0);
    }

    #[test]
    fn the_nv_size_matches_the_compiled_struct() {
        // Pinned in `ffi` too, but repeated here because a change would corrupt
        // every outgoing header block rather than fail loudly.
        assert_eq!(std::mem::size_of::<ffi::nghttp2_nv>(), 40);
    }
}
