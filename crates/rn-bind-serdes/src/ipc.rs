//! `internalBinding('ipc_serdes')` for rustnode.
//!
//! Two bare functions, `serialize(message, Buffer)` and `deserialize(view)`,
//! used by `lib/internal/child_process/serialization.js` for the `advanced`
//! IPC codec. `src/node_ipc_serdes.cc` is the specification, and the wire
//! format is load-bearing because both ends of a channel must agree on it:
//!
//! ```text
//! [4-byte big-endian payload length][V8 ValueSerializer payload]
//! ```
//!
//! # Why `ArrayBufferView`s are host objects
//!
//! A `Buffer` has to arrive on the other side as a `Buffer`, not a plain
//! `Uint8Array`, so the codec sets `SetTreatArrayBufferViewsAsHostObjects` and
//! writes every view through the host-object hook. Each one is tagged:
//!
//! ```text
//! 0                              // kArrayBufferViewTag
//! uint32 type index              // 10 is Node's Buffer / FastBuffer
//! uint32 byte length
//! raw bytes
//! ```
//!
//! and anything that is not a view is
//!
//! ```text
//! 1                              // kNotArrayBufferViewTag
//! V8-serialized value
//! ```
//!
//! The type indices are the ones `lib/v8.js`'s `arrayBufferViewTypeToIndex`
//! assigns, with 10 reserved for `Buffer`. Getting one wrong does not throw: it
//! produces a view of the wrong element type, silently changing what each index
//! means on the far side.
//!
//! # `Buffer` is passed in, not looked up
//!
//! `serialize` takes the stable `Buffer` constructor as its second argument so a
//! value is classified as a `Buffer` by `value.constructor === Buffer`, which
//! cannot be fooled by reassigning `Buffer.prototype.constructor`. Reading the
//! global instead would be tamperable in exactly the way Node's version avoids.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;
use v8::PropertyDescriptor;

/// Members of this namespace, matching `contracts/ipc_serdes.json`.
pub const MEMBERS: &[&str] = &["deserialize", "serialize"];

/// `kArrayBufferViewTag`.
const ARRAY_BUFFER_VIEW_TAG: u32 = 0;
/// `kNotArrayBufferViewTag`.
const NOT_ARRAY_BUFFER_VIEW_TAG: u32 = 1;
/// The index `lib/v8.js` reserves for Node's `Buffer`.
const BUFFER_INDEX: u32 = 10;
/// Returned by [`view_type_index`] for something no index describes.
const INVALID_VIEW_INDEX: u32 = u32::MAX;

/// `internalBinding('ipc_serdes')`.
pub struct IpcSerdes;

impl BindingModule for IpcSerdes {
    fn namespace(&self) -> &'static str {
        "ipc_serdes"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        install_method(scope, object, "serialize", serialize)?;
        install_method(scope, object, "deserialize", deserialize)?;
        Ok(object)
    }
}

fn install_method(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("could not create ipc_serdes.{name}"))?;
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("could not define {name}"))?;
    Ok(())
}

/// The `arrayBufferViewTypeToIndex` equivalent, from the C++ `if` chain.
fn view_type_index(view: v8::Local<v8::Object>) -> u32 {
    if view.is_int8_array() {
        0
    } else if view.is_uint8_array() {
        1
    } else if view.is_uint8_clamped_array() {
        2
    } else if view.is_int16_array() {
        3
    } else if view.is_uint16_array() {
        4
    } else if view.is_int32_array() {
        5
    } else if view.is_uint32_array() {
        6
    } else if view.is_float32_array() {
        7
    } else if view.is_float64_array() {
        8
    } else if view.is_data_view() {
        9
    } else if view.is_big_int64_array() {
        11
    } else if view.is_big_uint64_array() {
        12
    } else {
        INVALID_VIEW_INDEX
    }
}

/// Bytes per element for an index, from `BytesPerElement` in C++.
fn bytes_per_element(type_index: u32) -> usize {
    match type_index {
        3 | 4 => 2,
        5 | 6 | 7 => 4,
        8 | 11 | 12 => 8,
        // Int8, Uint8, Uint8Clamped, DataView and Buffer.
        _ => 1,
    }
}

/// Whether `value` is an instance of the `Buffer` constructor that was passed in.
///
/// `value.constructor === Buffer`, which is what Node's codec checks. Using the
/// passed-in constructor rather than reading `Buffer.prototype.constructor` is
/// deliberate: the latter is writable, so a script could make any object look
/// like a `Buffer` to the codec.
fn is_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
    buffer_constructor: v8::Local<v8::Value>,
) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    let Some(key) = v8::String::new(scope, "constructor") else {
        return false;
    };
    let Some(constructor) = object.get(scope, key.into()) else {
        return false;
    };
    constructor.strict_equals(buffer_constructor)
}

/// The serializer's host-object hook.
struct SerializerDelegate {
    /// The stable `Buffer` constructor passed from JavaScript.
    ///
    /// The hook receives the serializer it is writing to as an argument, so
    /// nothing else has to be threaded through here.
    buffer_constructor: v8::Global<v8::Value>,
}

impl v8::ValueSerializerImpl for SerializerDelegate {
    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        message: v8::Local<'s, v8::String>,
    ) {
        // `ThrowDataCloneError` throws `Exception::Error(message)` and nothing
        // else: the message V8 supplies is already the final text.
        let error = v8::Exception::error(scope, message);
        scope.throw_exception(error);
    }

    fn write_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
        serializer: &dyn v8::ValueSerializerHelper,
    ) -> Option<bool> {
        if object.is_array_buffer_view() {
            let object_value: v8::Local<v8::Value> = object.into();
            let view = v8::Local::<v8::ArrayBufferView>::try_from(object_value).ok()?;
            let byte_length = view.byte_length();
            let mut bytes = vec![0u8; byte_length];
            if view.copy_contents(&mut bytes) != byte_length {
                return Some(false);
            }

            serializer.write_uint32(ARRAY_BUFFER_VIEW_TAG);
            // A Node `Buffer` is identified by `value.constructor === Buffer`,
            // compared against the stable constructor `serialization.js` passed
            // in rather than `Buffer.prototype.constructor`, which a script can
            // reassign.
            let buffer_constructor = v8::Local::new(&*scope, &self.buffer_constructor);
            let type_index = if is_buffer(scope, object.into(), buffer_constructor) {
                BUFFER_INDEX
            } else {
                let index = view_type_index(object);
                if index == INVALID_VIEW_INDEX {
                    let message = v8::String::new(scope, "Unserializable host object")?;
                    let error = v8::Exception::error(scope, message);
                    scope.throw_exception(error);
                    return Some(false);
                }
                index
            };
            serializer.write_uint32(type_index);
            serializer.write_uint32(byte_length as u32);
            serializer.write_raw_bytes(&bytes);
            return Some(true);
        }

        // A non-view host object is written as a shallow copy of its own
        // enumerable properties, which is what `writeValue({ ...object })` did
        // in the JavaScript codec this replaced. `CreateDataProperty` is used
        // rather than `Set` so an inherited setter is not invoked — the same
        // thing object spread does.
        serializer.write_uint32(NOT_ARRAY_BUFFER_VIEW_TAG);
        let copy = shallow_copy(scope, object)?;
        serializer.write_value(scope.get_current_context(), copy.into())
    }
}

/// A new object holding `object`'s own enumerable string-keyed properties.
///
/// `{ ...object }` in the codec this replaces: own enumerable string keys only,
/// defined with `CreateDataProperty` so no prototype setter runs.
fn shallow_copy<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let copy = v8::Object::new(scope);
    let names = object.get_own_property_names(scope, Default::default())?;
    let length = names.length();
    for index in 0..length {
        let key = names.get_index(scope, index)?;
        let Ok(key) = v8::Local::<v8::Name>::try_from(key) else {
            continue;
        };
        let Some(value) = object.get(scope, key.into()) else {
            continue;
        };
        let descriptor = PropertyDescriptor::new_from_value(value);
        copy.define_property(scope, key.into(), &descriptor);
    }
    Some(copy)
}

/// `serialize(message, Buffer)`.
fn serialize(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let message = args.get(0);
    let buffer_constructor = args.get(1);

    let delegate = Box::new(SerializerDelegate {
        buffer_constructor: v8::Global::new(scope.as_ref(), buffer_constructor),
    });
    let serializer = v8::ValueSerializer::new(scope, delegate);
    // `set_treat_array_buffer_views_as_host_objects` is on the helper trait, and
    // `ValueSerializer` implements it, so the same object is both.
    let helper: &dyn v8::ValueSerializerHelper = &serializer;
    helper.set_treat_array_buffer_views_as_host_objects(true);

    // Four zero bytes reserved for the big-endian length, then the standard V8
    // header and the value, matching the C++.
    helper.write_raw_bytes(&[0u8; 4]);
    helper.write_header();

    let Some(wrote) = helper.write_value(scope.get_current_context(), message) else {
        // A `DataCloneError` is already pending on the scope.
        return;
    };
    if !wrote {
        return;
    }

    let mut bytes = serializer.release();
    if bytes.len() < 4 {
        return;
    }
    let payload_length = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&payload_length.to_be_bytes());

    if let Some(value) = buffer_from(scope, bytes) {
        rv.set(value);
    }
}

/// The deserializer's host-object hook.
struct DeserializerDelegate;

impl v8::ValueDeserializerImpl for DeserializerDelegate {
    fn read_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        deserializer: &dyn v8::ValueDeserializerHelper,
    ) -> Option<v8::Local<'s, v8::Object>> {
        let mut tag = 0u32;
        if !deserializer.read_uint32(&mut tag) {
            return None;
        }
        if tag == NOT_ARRAY_BUFFER_VIEW_TAG {
            // A host object that was not a view: the payload is a nested value.
            let value = deserializer.read_value(scope.get_current_context())?;
            let object = v8::Local::<v8::Object>::try_from(value);
            return object.ok();
        }
        if tag != ARRAY_BUFFER_VIEW_TAG {
            let message = v8::String::new(scope, "Invalid host object tag")?;
            let error = v8::Exception::error(scope, message);
            scope.throw_exception(error);
            return None;
        }

        let mut type_index = 0u32;
        let mut byte_length = 0u32;
        if !deserializer.read_uint32(&mut type_index) || !deserializer.read_uint32(&mut byte_length)
        {
            return None;
        }
        let bytes = deserializer.read_raw_bytes(byte_length as usize)?;

        let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
        make_view(scope, type_index, array_buffer, byte_length as usize)
    }
}

/// `deserialize(view)`.
fn deserialize(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let view = args.get(0);
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(view) else {
        // Node's `CHECK(args[0]->IsArrayBufferView())` aborts; a `TypeError` is
        // the equivalent a caller can observe instead of a dead process.
        throw_type_error(scope, "deserialize expects an ArrayBufferView");
        return;
    };
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    if view.copy_contents(&mut bytes) != length {
        return;
    }

    let deserializer = v8::ValueDeserializer::new(scope, Box::new(DeserializerDelegate), &bytes);
    let helper: &dyn v8::ValueDeserializerHelper = &deserializer;
    let Some(read_header) = helper.read_header(scope.get_current_context()) else {
        return;
    };
    if !read_header {
        return;
    }
    if let Some(value) = helper.read_value(scope.get_current_context()) {
        rv.set(value);
    }
}

/// `MakeView`: the typed array an index names.
fn make_view<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    type_index: u32,
    array_buffer: v8::Local<'s, v8::ArrayBuffer>,
    byte_length: usize,
) -> Option<v8::Local<'s, v8::Object>> {
    let length = byte_length / bytes_per_element(type_index);
    let view: v8::Local<'s, v8::Object> = match type_index {
        0 => v8::Int8Array::new(scope, array_buffer, 0, length)?.into(),
        1 => v8::Uint8Array::new(scope, array_buffer, 0, length)?.into(),
        2 => v8::Uint8ClampedArray::new(scope, array_buffer, 0, length)?.into(),
        3 => v8::Int16Array::new(scope, array_buffer, 0, length)?.into(),
        4 => v8::Uint16Array::new(scope, array_buffer, 0, length)?.into(),
        5 => v8::Int32Array::new(scope, array_buffer, 0, length)?.into(),
        6 => v8::Uint32Array::new(scope, array_buffer, 0, length)?.into(),
        7 => v8::Float32Array::new(scope, array_buffer, 0, length)?.into(),
        8 => v8::Float64Array::new(scope, array_buffer, 0, length)?.into(),
        9 => v8::DataView::new(scope, array_buffer, 0, byte_length).into(),
        11 => v8::BigInt64Array::new(scope, array_buffer, 0, length)?.into(),
        12 => v8::BigUint64Array::new(scope, array_buffer, 0, length)?.into(),
        // Index 10 is `Buffer`, a `Uint8Array` carrying the `Buffer` prototype.
        BUFFER_INDEX => v8::Uint8Array::new(scope, array_buffer, 0, length)?.into(),
        _ => return None,
    };
    if type_index == BUFFER_INDEX {
        if let Some(prototype) = buffer_prototype(scope) {
            view.set_prototype(scope, prototype.into());
        }
    }
    Some(view)
}

/// A `Buffer` from owned bytes, for `serialize`'s return value.
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

/// `Buffer.prototype`, as `lib/buffer.js` installed it.
fn buffer_prototype<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype_key = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype_key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}
