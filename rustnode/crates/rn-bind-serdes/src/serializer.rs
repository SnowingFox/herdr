//! The `Serializer` constructor and prototype, after `src/node_serdes.cc`.
//!
//! # The object behind the JavaScript one
//!
//! `SerializerContext` in Node is a `BaseObject` that owns a `ValueSerializer`
//! and is its own delegate. Here the same split is one boxed [`SerializerSlot`]:
//! the V8 serializer, a rooted handle on the JavaScript object (so the hooks can
//! be read when a native write reaches them), and a cell the delegate uses to
//! find that slot.
//!
//! The slot is reached from an internal field holding an `External`, and freed by
//! a guaranteed finalizer, which is the only owner. `ValueSerializer` pins its own
//! heap internally, so the slot can be created after the serializer and the
//! delegate can be told where it is afterwards.
//!
//! # Why the delegate forwards instead of deciding
//!
//! Node's delegate reads a method off the JavaScript object and calls it:
//! `_writeHostObject` for a host object, `_getDataCloneError` for a clone error,
//! `_getSharedArrayBufferId` when a shared buffer is written. That indirection is
//! what lets `class DefaultSerializer extends Serializer` decide how a `Buffer`
//! is serialized, so a Rust delegate that answered by itself would break every
//! subclass.
//!
//! `IsHostObject` is deliberately *not* overridden. Node does not override it
//! either, so V8 falls back to its own rule — an object with embedder fields is a
//! host object — and rustnode inherits exactly the same behaviour.
//!
//! # `writeHeader` and `releaseBuffer` bracket the payload
//!
//! `lib/v8.js` calls `writeHeader()` once, `writeValue()` once, then
//! `releaseBuffer()`. The header is what makes the bytes self-describing, so
//! omitting it produces bytes the deserializer rejects — the same failure Node
//! has, because `Release()` hands back whatever was written.
//!
//! `releaseBuffer` returns a `Buffer`, not a `Uint8Array`: `lib/v8.js` returns it
//! straight from `v8.serialize()`, and Node's tests compare it against `Buffer`
//! literals.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;

use rn_v8_sys::v8;
use v8::ValueSerializerHelper;

use crate::delegate;

/// Internal field holding the `*mut SerializerSlot`.
const SLOT_FIELD: i32 = 0;

/// The state one `Serializer` object owns.
struct SerializerSlot {
    /// The V8 serializer, which calls back into [`Hooks`] for the delegate
    /// methods. Declared first so it is dropped before the object handle it may
    /// still refer to.
    serializer: v8::ValueSerializer<'static>,
    /// The JavaScript object, rooted so a hook can read its methods.
    object: v8::Global<v8::Object>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

/// The delegate V8 calls during `writeValue`.
///
/// It holds the slot's address in a `Cell` rather than a reference because the
/// slot cannot exist before the serializer that lives in it. The address is
/// written once, immediately after the slot is boxed, and read only from a hook —
/// which cannot run before JavaScript has the object.
struct Hooks {
    slot: Cell<usize>,
}

impl Hooks {
    /// The slot this delegate belongs to.
    fn slot(&self) -> Option<&SerializerSlot> {
        let address = self.slot.get();
        if address == 0 {
            return None;
        }
        // SAFETY: the address was stored by `build_slot` from a `Box` the
        // serializer's finalizer frees, and the delegate is dropped with that
        // same allocation, so the slot is live for this call.
        Some(unsafe { &*(address as *const SerializerSlot) })
    }
}

impl v8::ValueSerializerImpl for Hooks {
    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        message: v8::Local<'s, v8::String>,
    ) {
        // `SerializerContext::ThrowDataCloneError` calls
        // `object._getDataCloneError(message)` and throws what it returns. It is
        // a plain call, not a construction: `lib/v8.js` assigns `Error`, and
        // `Error('...')` is already an error object.
        let argument: v8::Local<'s, v8::Value> = message.into();
        let thrown = self.slot().and_then(|slot| {
            let object = v8::Local::new(&*scope, &slot.object);
            delegate::call_hook(scope, object, "_getDataCloneError", &[argument])
        });
        if let Some(error) = thrown {
            scope.throw_exception(error);
        }
    }

    fn write_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
        _serializer: &dyn v8::ValueSerializerHelper,
    ) -> Option<bool> {
        // `_writeHostObject` is where `DefaultSerializer` writes a `Buffer`'s
        // bytes, and where a subclass of its own would write anything else. It
        // calls `this.writeUint32`/`this.writeRawBytes`, so it reaches the very
        // serializer this hook is running inside — which is sound because both
        // take `&self` and only the transfer-id list needs interior mutability.
        let argument: v8::Local<'s, v8::Value> = object.into();
        let called = self.slot().and_then(|slot| {
            let target = v8::Local::new(&*scope, &slot.object);
            delegate::call_hook(scope, target, "_writeHostObject", &[argument])
        });
        // Node ignores the value: a hook that returned without throwing is a
        // successful write, and a throw inside it leaves an exception pending,
        // which is how V8 learns the write failed.
        called.map(|_| true)
    }

    fn get_shared_array_buffer_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        shared_array_buffer: v8::Local<'s, v8::SharedArrayBuffer>,
    ) -> Option<u32> {
        // Node consults the JavaScript hook only when it exists — `lib/v8.js`
        // never defines one — and otherwise falls through to the base delegate,
        // which returns nothing. A `SharedArrayBuffer` is then a clone error with
        // V8's own message rather than a rustnode-specific one.
        let argument: v8::Local<'s, v8::Value> = shared_array_buffer.into();
        let slot = self.slot()?;
        let object = v8::Local::new(&*scope, &slot.object);
        let id = delegate::call_hook(scope, object, "_getSharedArrayBufferId", &[argument])?;
        id.uint32_value(scope)
    }
}

/// Installs the `Serializer` constructor and returns it.
pub fn install<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    // `Serializer.length` is 0: `NewFunctionTemplate`'s default, which
    // `src/node_serdes.cc` never overrides.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name =
        v8::String::new(scope, "Serializer").ok_or("cannot allocate the Serializer class name")?;
    template.set_class_name(name);

    // `SerializerContext::kInternalFieldCount` is 1, and the field holds the
    // slot that owns the V8 serializer.
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    // Each method is installed by its own expansion so every one is a distinct
    // closure type, which is what `MapFnTo<FunctionCallback>` resolves against.
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
        "writeHeader" => write_header,
        "writeValue" => write_value,
        "releaseBuffer" => release_buffer,
        "transferArrayBuffer" => transfer_array_buffer,
        "writeUint32" => write_uint32,
        "writeUint64" => write_uint64,
        "writeDouble" => write_double,
        "writeRawBytes" => write_raw_bytes,
        "_setTreatArrayBufferViewsAsHostObjects" => set_treat_views_as_host_objects,
    }
    // `ser->ReadOnlyPrototype()`: the prototype cannot be replaced, so a subclass
    // cannot break every other serializer in the process.
    template.read_only_prototype();

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the Serializer constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// Runs `body` with the slot behind `object`.
fn with_slot<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&SerializerSlot) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer installed by `new`, and the
    // object is a live local so its finalizer has not run.
    let address = unsafe { object.get_aligned_pointer_from_internal_field(SLOT_FIELD, 0) } as usize;
    if address == 0 {
        return None;
    }
    // SAFETY: as above — the address is the live slot this object owns.
    Some(body(unsafe { &*(address as *const SerializerSlot) }))
}

/// `new Serializer()`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `THROW_ERR_CONSTRUCT_CALL_REQUIRED` rather than
    // `ConstructorBehavior::kThrow`, so `Serializer.prototype` stays reachable
    // for `class DefaultSerializer extends Serializer`.
    if !args.is_construct_call() {
        delegate::throw_construct_call_required(scope, "Serializer");
        return;
    }
    let object = args.this();
    if let Some(slot) = build_slot(scope, object) {
        object.set_aligned_pointer_in_internal_field(SLOT_FIELD, slot.cast::<c_void>(), 0);
        rv.set(object.into());
    }
}

/// Allocates the slot, wires the delegate to it, and registers the finalizer.
fn build_slot(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
) -> Option<*mut SerializerSlot> {
    // The delegate is handed to the serializer by value, so its address is taken
    // first. A `Box`'s allocation does not move when the box does, so the address
    // stays valid once the serializer owns it.
    let hooks = Box::new(Hooks { slot: Cell::new(0) });
    let hooks_address = Box::as_ref(&hooks) as *const Hooks;
    let serializer: v8::ValueSerializer<'static> = v8::ValueSerializer::new(scope, hooks);

    let slot = Box::into_raw(Box::new(SerializerSlot {
        serializer,
        object: v8::Global::new(scope.as_ref(), object),
        weak: RefCell::new(None),
    }));

    // SAFETY: `hooks_address` is the live delegate the serializer owns, reachable
    // for as long as the slot is; `slot` is live and unaliased.
    unsafe {
        (*hooks_address).slot.set(slot as usize);
    }

    let address = slot as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this
            // finalizer runs exactly once. Dropping the slot drops the
            // serializer, which drops the delegate.
            drop(unsafe { Box::from_raw(address as *mut SerializerSlot) });
        }),
    );
    // SAFETY: `slot` is live and this is its only borrow.
    *unsafe { &(*slot).weak }.borrow_mut() = Some(weak);
    Some(slot)
}

/// `writeHeader()`.
fn write_header(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_slot(args.this(), |slot| slot.serializer.write_header());
}

/// `writeValue(value)`, which may call back into `_writeHostObject`.
fn write_value(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = args.get(0);
    let context = scope.get_current_context();
    let written = with_slot(args.this(), |slot| {
        slot.serializer.write_value(context, value)
    });
    // `WriteValue` in Node only sets the return value when V8 produced one, so a
    // pending exception is left as the only thing the caller sees.
    if let Some(Some(result)) = written {
        rv.set(v8::Boolean::new(scope, result).into());
    }
}

/// `releaseBuffer()`: the serialized bytes as a `Buffer`.
fn release_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(data) = with_slot(args.this(), |slot| slot.serializer.release()) else {
        return;
    };
    if let Some(buffer) = buffer_from(scope, data) {
        rv.set(buffer);
    }
}

/// `transferArrayBuffer(id, arrayBuffer)`.
fn transfer_array_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // Node converts the id first and returns without throwing when it cannot,
    // which lets a pending exception through instead of replacing it.
    let Some(id) = args.get(0).uint32_value(scope) else {
        return;
    };
    let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(args.get(1)) else {
        delegate::throw_invalid_arg_type(scope, "arrayBuffer must be an ArrayBuffer");
        return;
    };
    with_slot(args.this(), |slot| {
        slot.serializer.transfer_array_buffer(id, buffer);
    });
}

/// `writeUint32(value)`.
fn write_uint32(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(value) = args.get(0).uint32_value(scope) else {
        return;
    };
    with_slot(args.this(), |slot| slot.serializer.write_uint32(value));
}

/// `writeUint64(high, low)`: two 32-bit halves, because the exposed API takes
/// them separately.
fn write_uint64(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let (Some(high), Some(low)) = (
        args.get(0).uint32_value(scope),
        args.get(1).uint32_value(scope),
    ) else {
        return;
    };
    let value = (u64::from(high) << 32) | u64::from(low);
    with_slot(args.this(), |slot| slot.serializer.write_uint64(value));
}

/// `writeDouble(value)`.
fn write_double(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(value) = args.get(0).number_value(scope) else {
        return;
    };
    with_slot(args.this(), |slot| slot.serializer.write_double(value));
}

/// `writeRawBytes(view)`.
fn write_raw_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let source = args.get(0);
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(source) else {
        delegate::throw_invalid_arg_type(scope, "source must be a TypedArray or a DataView");
        return;
    };
    let length = view.byte_length();
    let base = view.data().cast::<u8>();
    if length != 0 && base.is_null() {
        return;
    }
    let bytes: &[u8] = if length == 0 {
        &[]
    } else {
        // SAFETY: `base` points at `length` bytes of the view's backing store,
        // which the caller keeps alive for the duration of this call.
        unsafe { std::slice::from_raw_parts(base, length) }
    };
    with_slot(args.this(), |slot| slot.serializer.write_raw_bytes(bytes));
}

/// `_setTreatArrayBufferViewsAsHostObjects(flag)`.
///
/// `DefaultSerializer` sets this in its constructor, and it is what routes a
/// `Buffer` through `_writeHostObject` instead of V8's own view serialization —
/// Node's default serializer writes `Buffer` contents rather than the pooled
/// `ArrayBuffer` underneath them.
fn set_treat_views_as_host_objects(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let flag = args.get(0).boolean_value(scope);
    with_slot(args.this(), |slot| {
        slot.serializer
            .set_treat_array_buffer_views_as_host_objects(flag);
    });
}

/// Wraps `data` in a `Buffer`, taking ownership of its bytes.
///
/// Node's `ReleaseBuffer` hands the bytes to `Buffer::New`, which adopts the
/// allocation rather than copying it; `new_backing_store_from_vec` does the same.
/// The prototype is set so `Buffer.isBuffer` holds, using the same technique
/// `rn-bind-spawn-sync` and `rn-bind-udp-wrap` use — reading it off the global
/// keeps one binding out of another's state.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    data: Vec<u8>,
) -> Option<v8::Local<'s, v8::Value>> {
    let length = data.len();
    let store = v8::ArrayBuffer::new_backing_store_from_vec(data).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, length)?;
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    Some(view.into())
}

/// `Buffer.prototype`, as `lib/buffer.js` installed it on the global.
fn buffer_prototype<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype_key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}
