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

/// The element type of the typed array a buffer is exposed as.
///
/// Node's JavaScript indexes these arrays by element, so the width is part of
/// the contract: `tickInfo` is a `Uint8Array(2)`, `hrtimeBuffer` is a
/// `Uint32Array(3)`, `immediateInfo` is a `Uint32Array(3)` and `timeoutInfo` is
/// an `Int32Array(1)`. Exposing the bytes of one as another would make an index
/// mean something different on each side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Element {
    /// A `Uint8Array`, one byte per element.
    Byte,
    /// A `Uint32Array`, four bytes per element, native endianness.
    Word,
    /// An `Int32Array`, four bytes per element, native endianness.
    SignedWord,
    /// A `Float64Array`, eight bytes per element.
    ///
    /// `async_id_fields` and `async_ids_stack` are `Float64Array`s because Node
    /// stores async ids in them, and an id is a double so the same array can
    /// also hold `-1` for "no id" without a separate sentinel.
    Double,
}

impl Element {
    fn width(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word | Self::SignedWord => 4,
            Self::Double => 8,
        }
    }

    /// Renders one element's bytes as the unsigned bit pattern.
    ///
    /// Every integer accessor returns `u32` and every float accessor returns
    /// `f64`, so there is one code path per family rather than one per type.
    fn decode(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Byte => bytes[0] as u32,
            Self::Word | Self::SignedWord => {
                u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
            // A double has no `u32` reading; the caller uses `get_float`.
            Self::Double => 0,
        }
    }

    /// The bytes of one element, in the array's native endianness.
    fn encode(self, value: u32) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        match self {
            Self::Byte => bytes[0] = (value & 0xff) as u8,
            Self::Word | Self::SignedWord => {
                bytes[..4].copy_from_slice(&value.to_ne_bytes());
            }
            // A double has no `u32` reading; the caller uses `set_float`.
            Self::Double => {}
        }
        bytes
    }

    /// Reads an `f64` from one element's bytes.
    fn decode_float(self, bytes: &[u8]) -> f64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[..8]);
        f64::from_ne_bytes(raw)
    }

    /// The bytes of one `f64` element.
    fn encode_float(self, value: f64) -> [u8; 8] {
        value.to_ne_bytes()
    }

    /// Creates the typed array of this element type.
    fn array<'s>(
        self,
        scope: &mut v8::PinScope<'s, '_>,
        buffer: v8::Local<'s, v8::ArrayBuffer>,
        elements: usize,
    ) -> Option<v8::Local<'s, v8::Value>> {
        match self {
            Self::Byte => v8::Uint8Array::new(scope, buffer, 0, elements).map(Into::into),
            Self::Word => v8::Uint32Array::new(scope, buffer, 0, elements).map(Into::into),
            Self::SignedWord => v8::Int32Array::new(scope, buffer, 0, elements).map(Into::into),
            Self::Double => v8::Float64Array::new(scope, buffer, 0, elements).map(Into::into),
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
        let array = element
            .array(scope, buffer, elements)
            .ok_or("cannot allocate the aliased typed array")?;
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
    /// does. A `Float64Array` has no integer reading; use
    /// [`get_float`](Self::get_float) for those.
    pub fn get(&self, index: usize) -> Option<u32> {
        if self.element == Element::Double {
            return None;
        }
        Some(self.element.decode(&self.read(index)?))
    }

    /// Writes one integer element, returning whether `index` was in range.
    pub fn set(&self, index: usize, value: u32) -> bool {
        if self.element == Element::Double {
            return false;
        }
        self.write(index, &self.element.encode(value))
    }

    /// Reads the `f64` element at `index`, for a `Float64Array` buffer.
    pub fn get_float(&self, index: usize) -> Option<f64> {
        if self.element != Element::Double {
            return None;
        }
        Some(self.element.decode_float(&self.read(index)?))
    }

    /// Writes one `f64` element, for a `Float64Array` buffer.
    pub fn set_float(&self, index: usize, value: f64) -> bool {
        if self.element != Element::Double {
            return false;
        }
        self.write(index, &self.element.encode_float(value))
    }

    /// Reads one element's raw bytes.
    fn read(&self, index: usize) -> Option<[u8; 8]> {
        let width = self.element.width();
        let offset = index.checked_mul(width)?;
        if offset + width > self.length {
            return None;
        }
        let mut bytes = [0u8; 8];
        for (position, slot) in bytes.iter_mut().take(width).enumerate() {
            // SAFETY: `offset + position` is inside the allocation, and the
            // pointer is valid while the typed array is alive, which the global
            // field guarantees.
            *slot = unsafe { *self.data.get().add(offset + position) };
        }
        Some(bytes)
    }

    /// Writes one element's raw bytes.
    fn write(&self, index: usize, bytes: &[u8; 8]) -> bool {
        let width = self.element.width();
        let Some(offset) = index.checked_mul(width) else {
            return false;
        };
        if offset + width > self.length {
            return false;
        }
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
