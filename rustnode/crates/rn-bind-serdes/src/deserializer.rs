//! The `Deserializer` constructor and prototype, after `src/node_serdes.cc`.
//!
//! # The buffer is kept, not copied
//!
//! `DeserializerContext` holds a pointer into the `Buffer` it was constructed
//! with and also stores that buffer as `this.buffer` so it cannot be collected
//! while the pointer is live. `lib/v8.js` depends on both halves:
//!
//! ```js
//! Deserializer.prototype.readRawBytes = function readRawBytes(length) {
//!   const offset = this._readRawBytes(length);
//!   return new FastBuffer(this.buffer.buffer,
//!                         this.buffer.byteOffset + offset,
//!                         length);
//! };
//! ```
//!
//! So `_readRawBytes` returns an *offset into the caller's buffer*, and the
//! returned view must alias those bytes. Copying the payload into Rust would
//! break that: the offset would mean nothing and the view would point at freed
//! memory. The `Global` on `this.buffer` is what keeps the bytes alive.
//!
//! `Node` stores the same object rather than a copy, so `der.buffer === input`
//! holds there; it holds here too.
//!
//! # `readHostObject` reads a class the JavaScript side owns
//!
//! `_readHostObject()` is `DefaultDeserializer`'s, and it reconstructs a `Buffer`
//! from the type index and length `_writeHostObject` wrote. Node requires it to
//! return an object and throws `readHostObject must return an object` when it does
//! not, which is the check reproduced below.

use std::cell::RefCell;
use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::delegate;

/// Internal field holding the `*mut DeserializerSlot`.
const SLOT_FIELD: i32 = 0;

/// The state one `Deserializer` object owns.
struct DeserializerSlot {
    /// The V8 deserializer, which calls back into [`Hooks`].
    deserializer: v8::ValueDeserializer<'static>,
    /// The JavaScript object, rooted so `_readHostObject` can be read.
    object: v8::Global<v8::Object>,
    /// A root on the caller's buffer.
    ///
    /// Not read from Rust: it exists so the bytes `_readRawBytes` reports offsets
    /// into stay allocated. Node's `object()->Set(buffer_string, buffer)` does the
    /// same job, and `lib/v8.js` reads it back as `this.buffer`.
    _buffer: v8::Global<v8::Value>,
    /// The first byte of the payload, for turning a pointer V8 hands back into
    /// the offset `_readRawBytes` returns.
    base: *const u8,
    /// The payload length, so the base/offset arithmetic can be checked.
    length: usize,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

/// The delegate V8 calls during `readValue`.
struct Hooks {
    slot: std::cell::Cell<usize>,
}

impl Hooks {
    /// The slot this delegate belongs to.
    fn slot(&self) -> Option<&DeserializerSlot> {
        let address = self.slot.get();
        if address == 0 {
            return None;
        }
        // SAFETY: the address was stored by `build_slot` from a `Box` the
        // finalizer frees, and this delegate lives inside that allocation.
        Some(unsafe { &*(address as *const DeserializerSlot) })
    }
}

impl v8::ValueDeserializerImpl for Hooks {
    fn read_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _deserializer: &dyn v8::ValueDeserializerHelper,
    ) -> Option<v8::Local<'s, v8::Object>> {
        let slot = self.slot()?;
        let object = v8::Local::new(&*scope, &slot.object);
        let returned = delegate::call_hook(scope, object, "_readHostObject", &[]);
        let Some(returned) = returned else {
            // A throw inside the hook leaves an exception pending; `None` tells
            // V8 the read failed.
            return None;
        };
        // `DeserializerContext::ReadHostObject` rejects a non-object explicitly,
        // because the alternative is a confusing failure further up.
        match v8::Local::<v8::Object>::try_from(returned) {
            Ok(object) => Some(object),
            Err(_) => {
                delegate::throw_invalid_arg_type(scope, "readHostObject must return an object");
                None
            }
        }
    }

    fn get_shared_array_buffer_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _transfer_id: u32,
    ) -> Option<v8::Local<'s, v8::SharedArrayBuffer>> {
        // `transferArrayBuffer` accepts one, but `lib/v8.js` never registers one
        // for reading, so nothing V8 writes can reference it. Reporting a clone
        // error keeps the failure legible instead of a silent `undefined`.
        delegate::throw_invalid_arg_type(
            scope,
            "Cannot deserialize a SharedArrayBuffer that was not transferred",
        );
        None
    }

    fn get_wasm_module_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _clone_id: u32,
    ) -> Option<v8::Local<'s, v8::WasmModuleObject>> {
        // WebAssembly modules are transferable in Node's `postMessage`; the
        // `v8` module never transfers one, so there is nothing to resolve.
        delegate::throw_invalid_arg_type(
            scope,
            "Cannot deserialize a WebAssembly module that was not transferred",
        );
        None
    }
}

/// Installs the `Deserializer` constructor and returns it.
pub fn install<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    // `des->SetLength(1)`: the one difference from `Serializer`, and it is
    // visible as `Deserializer.length`.
    let template = v8::FunctionTemplate::builder(new).length(1).build(scope);
    let name = v8::String::new(scope, "Deserializer")
        .ok_or("cannot allocate the Deserializer class name")?;
    template.set_class_name(name);

    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    macro_rules! install_methods {
        ($($method_name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $method_name)
                    .ok_or_else(|| format!("cannot allocate the name {}", $method_name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install_methods! {
        "readHeader" => read_header,
        "readValue" => read_value,
        "getWireFormatVersion" => get_wire_format_version,
        "transferArrayBuffer" => transfer_array_buffer,
        "readUint32" => read_uint32,
        "readUint64" => read_uint64,
        "readDouble" => read_double,
        "_readRawBytes" => read_raw_bytes,
    }
    template.read_only_prototype();

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the Deserializer constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// Runs `body` with the slot behind `object`.
fn with_slot<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&DeserializerSlot) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer installed by `new`, and the
    // object is a live local so its finalizer has not run.
    let address = unsafe { object.get_aligned_pointer_from_internal_field(SLOT_FIELD, 0) } as usize;
    if address == 0 {
        return None;
    }
    // SAFETY: as above.
    Some(body(unsafe { &*(address as *const DeserializerSlot) }))
}

/// `new Deserializer(buffer)`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        delegate::throw_construct_call_required(scope, "Deserializer");
        return;
    }
    let buffer = args.get(0);
    if !buffer.is_array_buffer_view() {
        delegate::throw_invalid_arg_type(scope, "buffer must be a TypedArray or a DataView");
        return;
    }
    let object = args.this();
    if let Some(slot) = build_slot(scope, object, buffer) {
        object.set_aligned_pointer_in_internal_field(SLOT_FIELD, slot.cast::<c_void>(), 0);
        // `object()->Set(buffer_string, buffer)`: `lib/v8.js` reads `this.buffer`
        // to build the view `readRawBytes` returns, and keeping it here is what
        // stops the bytes moving while a pointer into them is live.
        if let Some(key) = v8::String::new(scope, "buffer") {
            object.set(scope, key.into(), buffer);
        }
        rv.set(object.into());
    }
}

/// Allocates the slot, wires the delegate to it, and registers the finalizer.
fn build_slot(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    buffer: v8::Local<'_, v8::Value>,
) -> Option<*mut DeserializerSlot> {
    // `Buffer::Data(buffer)` / `Buffer::Length(buffer)`: a view over any typed
    // array or `DataView`, so the pointer and length come from the view rather
    // than from the array buffer behind it.
    let view = v8::Local::<v8::ArrayBufferView>::try_from(buffer).ok()?;
    let base = view.data().cast::<u8>().cast_const();
    let length = view.byte_length();

    let hooks = Box::new(Hooks {
        slot: std::cell::Cell::new(0),
    });
    let hooks_address = Box::as_ref(&hooks) as *const Hooks;
    let deserializer: v8::ValueDeserializer<'static> = {
        // SAFETY: the payload lives in the caller's view, which the slot roots
        // through `_buffer`; the slice is only read during `readValue`.
        let data = unsafe { std::slice::from_raw_parts(base, length) };
        v8::ValueDeserializer::new(scope, hooks, data)
    };

    let slot = Box::into_raw(Box::new(DeserializerSlot {
        deserializer,
        object: v8::Global::new(scope.as_ref(), object),
        _buffer: v8::Global::new(scope.as_ref(), buffer),
        base,
        length,
        weak: RefCell::new(None),
    }));

    // SAFETY: `hooks_address` is the live delegate the deserializer owns, and
    // `slot` is live and unaliased.
    unsafe {
        (*hooks_address).slot.set(slot as usize);
    }

    let address = slot as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this
            // finalizer runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut DeserializerSlot) });
        }),
    );
    // SAFETY: `slot` is live and this is its only borrow.
    *unsafe { &(*slot).weak }.borrow_mut() = Some(weak);
    Some(slot)
}

/// `readHeader()`.
fn read_header(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let context = scope.get_current_context();
    let read = with_slot(args.this(), |slot| {
        v8::ValueDeserializerHelper::read_header(&slot.deserializer, context)
    });
    if let Some(Some(result)) = read {
        rv.set(v8::Boolean::new(scope, result).into());
    }
}

/// `readValue()`, which may call back into `_readHostObject`.
fn read_value(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let context = scope.get_current_context();
    let read = with_slot(args.this(), |slot| slot.deserializer.read_value(context));
    if let Some(Some(value)) = read {
        rv.set(value);
    }
}

/// `getWireFormatVersion()`.
fn get_wire_format_version(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let version = with_slot(args.this(), |slot| {
        v8::ValueDeserializerHelper::get_wire_format_version(&slot.deserializer)
    });
    if let Some(version) = version {
        rv.set(v8::Integer::new_from_unsigned(scope, version).into());
    }
}

/// `transferArrayBuffer(id, buffer)`: an `ArrayBuffer` or a `SharedArrayBuffer`.
fn transfer_array_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = args.get(0).uint32_value(scope) else {
        return;
    };
    let buffer = args.get(1);
    if let Ok(array_buffer) = v8::Local::<v8::ArrayBuffer>::try_from(buffer) {
        with_slot(args.this(), |slot| {
            v8::ValueDeserializerHelper::transfer_array_buffer(
                &slot.deserializer,
                id,
                array_buffer,
            );
        });
        return;
    }
    if let Ok(shared) = v8::Local::<v8::SharedArrayBuffer>::try_from(buffer) {
        with_slot(args.this(), |slot| {
            v8::ValueDeserializerHelper::transfer_shared_array_buffer(
                &slot.deserializer,
                id,
                shared,
            );
        });
        return;
    }
    delegate::throw_invalid_arg_type(
        scope,
        "arrayBuffer must be an ArrayBuffer or SharedArrayBuffer",
    );
}

/// `readUint32()`.
fn read_uint32(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let mut value = 0u32;
    let read = with_slot(args.this(), |slot| {
        v8::ValueDeserializerHelper::read_uint32(&slot.deserializer, &mut value)
    });
    match read {
        Some(true) => rv.set(v8::Integer::new_from_unsigned(scope, value).into()),
        // `DeserializerContext::ReadUint32` throws rather than returning, because
        // a short read means the next field would be read from the wrong offset.
        _ => delegate::throw_with_code(
            scope,
            delegate::ErrorKind::Error,
            "ERR_INVALID_STATE",
            "ReadUint32() failed",
        ),
    }
}

/// `readUint64()`, as `[high, low]`.
fn read_uint64(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let mut value = 0u64;
    let read = with_slot(args.this(), |slot| {
        v8::ValueDeserializerHelper::read_uint64(&slot.deserializer, &mut value)
    });
    if read != Some(true) {
        delegate::throw_with_code(
            scope,
            delegate::ErrorKind::Error,
            "ERR_INVALID_STATE",
            "ReadUint64() failed",
        );
        return;
    }
    let high = (value >> 32) as u32;
    let low = value as u32;
    let values: [v8::Local<v8::Value>; 2] = [
        v8::Integer::new_from_unsigned(scope, high).into(),
        v8::Integer::new_from_unsigned(scope, low).into(),
    ];
    let array = v8::Array::new_with_elements(scope, &values);
    rv.set(array.into());
}

/// `readDouble()`.
fn read_double(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let mut value = 0.0f64;
    let read = with_slot(args.this(), |slot| {
        v8::ValueDeserializerHelper::read_double(&slot.deserializer, &mut value)
    });
    if read == Some(true) {
        rv.set(v8::Number::new(scope, value).into());
    } else {
        delegate::throw_with_code(
            scope,
            delegate::ErrorKind::Error,
            "ERR_INVALID_STATE",
            "ReadDouble() failed",
        );
    }
}

/// `_readRawBytes(length)`: the offset of `length` bytes inside the caller's
/// buffer.
///
/// Node checks that the bytes are inside the payload it was given, because the
/// returned offset is turned into a view by `lib/v8.js` and an offset past the
/// end would produce a view into unrelated memory.
fn read_raw_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(length) = args.get(0).integer_value(scope) else {
        return;
    };
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    let read = with_slot(args.this(), |slot| {
        v8::ValueDeserializerHelper::read_raw_bytes(&slot.deserializer, length).map(|bytes| {
            let start = bytes.as_ptr() as usize;
            (start, slot.base as usize, slot.length)
        })
    });
    let Some(Some((start, base, total))) = read else {
        delegate::throw_with_code(
            scope,
            delegate::ErrorKind::Error,
            "ERR_INVALID_STATE",
            "ReadRawBytes() failed",
        );
        return;
    };
    // `CHECK_GE(position, data_)` and `CHECK_LE(position + length, data_ + length_)`
    // in `DeserializerContext::ReadRawBytes`. A violation is a bug in V8 rather
    // than a condition a script can cause, so reporting it beats returning an
    // offset that would produce an out-of-bounds view.
    if start < base || start.saturating_add(length) > base.saturating_add(total) {
        delegate::throw_with_code(
            scope,
            delegate::ErrorKind::Error,
            "ERR_INVALID_STATE",
            "ReadRawBytes() returned bytes outside the buffer",
        );
        return;
    }
    let offset = (start - base) as u32;
    rv.set(v8::Integer::new_from_unsigned(scope, offset).into());
}
