//! Shared memory between a Rust binding and a JavaScript typed array.
//!
//! Several namespaces expose a small typed array whose contents both sides
//! read and write: `tickInfo` in `task_queue`, `streamBaseState` in
//! `stream_wrap`, and the timing buffer behind `process.hrtime`. Node's
//! `AliasedBuffer` allocates a native array and wraps it in a V8 typed array
//! without copying, and each namespace then keeps a pointer to the same bytes.
//!
//! [`AliasedUint8Array`] reproduces that: the backing store is V8-owned, so the
//! typed array and this handle see one allocation, and the handle keeps the
//! buffer alive for as long as the binding holds it.

use std::cell::Cell;

use rn_v8_sys::v8;

/// A byte buffer shared with a JavaScript `Uint8Array`.
///
/// The Rust side reads and writes through [`get`](Self::get) and
/// [`set`](Self::set); the JavaScript side sees the same bytes in its typed
/// array. Writes are not synchronized: Node's aliased buffers are only ever
/// touched from the isolate's own thread, and so are these.
pub struct AliasedUint8Array {
    /// The typed array the JavaScript layer holds. Keeping a global is what
    /// stops V8 from collecting the store out from under the raw pointer.
    array: v8::Global<v8::Uint8Array>,
    /// The first byte of the store. Valid while `array` is alive.
    data: Cell<*mut u8>,
    length: usize,
}

/// # Safety
///
/// Only used from the isolate that created it. V8 handles are not `Send` and
/// neither is this type: the `Cell` makes it `!Sync` and the `Global` makes it
/// `!Send`.
impl AliasedUint8Array {
    /// Allocates `length` zeroed bytes and wraps them in a typed array.
    pub fn new(scope: &mut v8::PinScope, length: usize) -> Result<Self, String> {
        let backing_store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(
            vec![0u8; length].into_boxed_slice(),
        );
        let backing_store: v8::SharedRef<v8::BackingStore> = backing_store.into();
        let buffer = v8::ArrayBuffer::with_backing_store(scope, &backing_store);
        let array = v8::Uint8Array::new(scope, buffer, 0, length)
            .ok_or("cannot allocate the aliased typed array")?;
        let data = buffer
            .data()
            .map(|data| data.as_ptr().cast::<u8>())
            .ok_or("the backing store has no data pointer")?;

        Ok(Self {
            array: v8::Global::new(scope, array),
            data: Cell::new(data),
            length,
        })
    }

    /// The typed array as the JavaScript layer sees it.
    pub fn array<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Uint8Array> {
        v8::Local::new(scope, &self.array)
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Reads one byte, or `None` when `index` is out of range.
    pub fn get(&self, index: usize) -> Option<u8> {
        if index >= self.length {
            return None;
        }
        // SAFETY: `index` is in range and the pointer is valid while the
        // typed array is alive, which the global field guarantees.
        Some(unsafe { *self.data.get().add(index) })
    }

    /// Writes one byte, returning whether `index` was in range.
    pub fn set(&self, index: usize, value: u8) -> bool {
        if index >= self.length {
            return false;
        }
        // SAFETY: as in `get`; the write stays inside the allocation.
        unsafe { *self.data.get().add(index) = value };
        true
    }

    /// Reads one byte as a flag, treating an out-of-range index as `false`.
    /// Node's tick flags are the common case, so this keeps call sites honest.
    pub fn flag(&self, index: usize) -> bool {
        self.get(index).is_some_and(|value| value != 0)
    }
}
