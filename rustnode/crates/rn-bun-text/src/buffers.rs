//! Building and reading `ArrayBuffer`s and typed-array views.
//!
//! Three members need to hand a byte buffer to JavaScript —
//! `Bun.concatArrayBuffers`, `Bun.allocUnsafe` and the `readableStreamTo*`
//! family — and one needs to read bytes back out (`Bun.indexOfLine`). Doing that
//! through V8's allocator rather than a Rust-owned pointer keeps the bytes
//! visible to the collector, so a buffer that outlives the call is still valid
//! and `process.memoryUsage().arrayBuffers` accounts for it.
//!
//! The distinction between `ArrayBuffer` and `Uint8Array` is not cosmetic here:
//! `Bun.concatArrayBuffers` returns a **plain `ArrayBuffer`** and
//! `Bun.allocUnsafe` returns an **unpooled `Uint8Array`** that is not a `Buffer`,
//! and both are checked by their prototype.

use rn_v8_sys::v8;

/// A fresh `ArrayBuffer` holding a copy of `bytes`.
///
/// V8 zero-fills every new backing store, so the copy is the only write needed.
pub fn array_buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    // `new_backing_store` allocates through the isolate's ArrayBuffer allocator,
    // which is the counting one this runtime installs, so the bytes are
    // accounted for and reclaimed with the buffer.
    // `new_backing_store_from_bytes` takes ownership of a container, so V8 frees
    // the memory with the buffer instead of Rust freeing it at the end of this
    // call. That is what makes the result safe to hand to JavaScript.
    let store = v8::ArrayBuffer::new_backing_store_from_bytes(bytes.to_vec());
    Some(v8::ArrayBuffer::with_backing_store(
        scope,
        &store.make_shared(),
    ))
}

/// A `Uint8Array` over `buffer`, covering the whole thing.
pub fn uint8_array_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    buffer: v8::Local<'s, v8::ArrayBuffer>,
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    v8::Uint8Array::new(scope, buffer, 0, buffer.byte_length())
}

/// The bytes of an `ArrayBuffer`, copied out.
pub fn array_buffer_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<Vec<u8>> {
    let _ = scope;
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
    let length = buffer.byte_length();
    let mut bytes = vec![0u8; length];
    if length > 0 {
        let store = buffer.get_backing_store();
        let data = store.data()?;
        // SAFETY: the store covers `byte_length()`, which is the length V8
        // reported for this buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

/// The bytes of an `ArrayBufferView`, copied out (not the whole buffer).
pub fn view_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<Vec<u8>> {
    let _ = scope;
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let mut bytes = vec![0u8; view.byte_length()];
    view.copy_contents(&mut bytes);
    Some(bytes)
}

/// Any `ArrayBuffer` or `ArrayBufferView` as bytes, or `None` for anything else.
pub fn bytes_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    if value.is_array_buffer() {
        return array_buffer_bytes(scope, value);
    }
    if value.is_array_buffer_view() {
        return view_bytes(scope, value);
    }
    None
}
