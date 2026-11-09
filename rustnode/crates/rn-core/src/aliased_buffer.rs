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

/// The element width of the typed array a buffer is exposed as.
///
/// Node's JavaScript indexes these arrays by element, so the width is part of
/// the contract: `tickInfo` is a `Uint8Array(2)` and `hrtimeBuffer` is a
/// `Uint32Array(3)`. Exposing the bytes of a `Uint32Array` as bytes would make
/// `buffer[1]` mean something different on each side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Element {
    /// A `Uint8Array`, one byte per element.
    Byte,
    /// A `Uint32Array`, four bytes per element, native endianness.
    Word,
}

impl Element {
    fn width(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 4,
        }
    }

    /// Renders one element's bytes as the array would report them.
    fn decode(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Byte => bytes[0] as u32,
            Self::Word => u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }

    /// The bytes of one element, in the array's native endianness.
    fn encode(self, value: u32) -> [u8; 4] {
        match self {
            Self::Byte => (value & 0xff).to_ne_bytes(),
            Self::Word => value.to_ne_bytes(),
        }
    }
}

/// A byte buffer shared with a JavaScript typed array.
///
/// The Rust side reads and writes through [`get`](Self::get) and
/// [`set`](Self::set); the JavaScript side sees the same bytes in its typed
/// array. Writes are not synchronized: Node's aliased buffers are only ever
/// touched from the isolate's own thread, and so are these.
pub struct AliasedUint8Array {
    /// The typed array the JavaScript layer holds. Keeping a global is what
    /// stops V8 from collecting the store out from under the raw pointer.
    array: v8::Global<v8::Value>,
    /// The first byte of the store. Valid while `array` is alive.
    data: Cell<*mut u8>,
    /// How many bytes the store holds.
    length: usize,
    element: Element,
}

/// # Safety
///
/// Only used from the isolate that created it. V8 handles are not `Send` and
/// neither is this type: the `Cell` makes it `!Sync` and the `Global` makes it
/// `!Send`.
impl AliasedUint8Array {
    /// Allocates `elements` zeroed elements and wraps them in a typed array of
    /// the matching width.
    pub fn new(
        scope: &mut v8::PinScope,
        elements: usize,
        element: Element,
    ) -> Result<Self, String> {
        let length = elements * element.width();
        let backing_store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(
            vec![0u8; length].into_boxed_slice(),
        );
        let backing_store: v8::SharedRef<v8::BackingStore> = backing_store.into();
        let buffer = v8::ArrayBuffer::with_backing_store(scope, &backing_store);
        let array: v8::Local<v8::Value> = match element {
            Element::Byte => v8::Uint8Array::new(scope, buffer, 0, elements)
                .ok_or("cannot allocate the aliased typed array")?
                .into(),
            Element::Word => v8::Uint32Array::new(scope, buffer, 0, elements)
                .ok_or("cannot allocate the aliased typed array")?
                .into(),
        };
        let data = buffer
            .data()
            .map(|data| data.as_ptr().cast::<u8>())
            .ok_or("the backing store has no data pointer")?;

        Ok(Self {
            array: v8::Global::new(scope, array),
            data: Cell::new(data),
            length,
            element,
        })
    }

    /// The typed array as the JavaScript layer sees it.
    pub fn array<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
        v8::Local::new(scope, &self.array)
    }

    /// How many bytes the store holds.
    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Reads the element at `index`, or `None` when it is out of range.
    ///
    /// "Element" means the array's unit: a byte for a `Uint8Array`, a word for a
    /// `Uint32Array`, so a call site indexes the buffer the same way JavaScript
    /// does.
    pub fn get(&self, index: usize) -> Option<u32> {
        let width = self.element.width();
        let offset = index.checked_mul(width)?;
        if offset + width > self.length {
            return None;
        }
        let mut bytes = [0u8; 4];
        for (position, slot) in bytes.iter_mut().take(width).enumerate() {
            // SAFETY: `offset + position` is inside the allocation, and the
            // pointer is valid while the typed array is alive, which the global
            // field guarantees.
            *slot = unsafe { *self.data.get().add(offset + position) };
        }
        Some(self.element.decode(&bytes))
    }

    /// Writes one element, returning whether `index` was in range.
    pub fn set(&self, index: usize, value: u32) -> bool {
        let width = self.element.width();
        let Some(offset) = index.checked_mul(width) else {
            return false;
        };
        if offset + width > self.length {
            return false;
        }
        let bytes = self.element.encode(value);
        for (position, byte) in bytes.iter().take(width).enumerate() {
            // SAFETY: `offset + position` is inside the allocation.
            unsafe { *self.data.get().add(offset + position) = *byte };
        }
        true
    }

    /// Reads one element as a flag, treating an out-of-range index as `false`.
    /// Node's tick flags are the common case, so this keeps call sites honest.
    pub fn flag(&self, index: usize) -> bool {
        self.get(index).is_some_and(|value| value != 0)
    }
}
