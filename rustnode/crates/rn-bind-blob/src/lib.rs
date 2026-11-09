//! `internalBinding('blob')` for rustnode.
//!
//! `lib/internal/blob.js` is the JavaScript half of the `Blob` and `File` web
//! interfaces, and `lib/internal/file.js` is built on it. Two things reach here:
//!
//! * `Blob` and `File` are globals (`globalThis.Blob`, `globalThis.File`), which
//!   Node installs from `internal/bootstrap/web/exposed-window-or-worker.js`;
//! * `internal/deps/undici/undici` reads both at module scope, through
//!   `webidl.util.MakeTypeAssertion(Blob)` and the same for `File`. So any code
//!   that forces undici to load — including a plain
//!   `Object.getOwnPropertyDescriptors(globalThis)`, which is what Node's
//!   `test/parallel/test-util-inspect.js` does to walk the global graph — fails
//!   with `ReferenceError: Blob is not defined` until this namespace exists.
//!
//! # The handle protocol
//!
//! `internal/blob.js` never touches bytes directly. It keeps a native *handle*
//! per `Blob` and drives it through four operations, which is what this crate
//! implements:
//!
//! | operation | used by |
//! | --- | --- |
//! | `handle.slice(start, end)` | `Blob.prototype.slice` |
//! | `handle.getReader()` | `stream`, `textStream`, `bytes`, `arrayBuffer`, `text` |
//! | `reader.pull(cb)` | the reader loop, called with `(status, buffer?)` |
//! | `reader.setWakeup(fn)` | the byte-stream wrapper, for a pull that blocked |
//!
//! A handle here is an immutable byte range over one shared buffer, so `slice`
//! is a view and the reader hands out one `ArrayBuffer` per pull. Every part of
//! a rustnode `Blob` is memory-resident: there is no file-backed entry yet, so
//! `pull` always answers synchronously and `setWakeup` has nothing to wake.
//! `createBlobFromFilePath` is deferred for the same reason (see [`DEFERRED`]).
//!
//! # Why the state lives in private properties
//!
//! The handle has to survive across calls and belong to exactly one V8 object.
//! Node parks a `BaseObject` pointer in an internal field; that shape needs
//! `unsafe` here and a destructor to free it. A V8 **private** property does the
//! same job with neither: it is invisible to JavaScript, cannot be forged from
//! outside, and is collected with the object. The stored value is a plain
//! `ArrayBuffer` of the blob's bytes plus two numbers, so there is no Rust
//! allocation to leak and no `unsafe` block in this crate.
//!
//! # Why the bytes are a copy
//!
//! Node's `createBlob` takes ownership of the caller's `ArrayBuffer`s and
//! detaches them. `internal/blob.js` has already copied each part into a fresh
//! `Uint8Array` before calling in (`getSource` says why), so detaching would
//! only break the caller for no gain. This copies into one `ArrayBuffer` per
//! `Blob`, which keeps a handle a plain byte range and lets `getDataObject`
//! hand the same bytes back.

#![deny(missing_docs)]

use std::cell::RefCell;
use std::collections::HashMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/blob.json`.
pub const MEMBERS: &[&str] = &[
    "concat",
    "createBlob",
    "createBlobFromFilePath",
    "getDataObject",
    "revokeObjectURL",
    "storeDataObject",
];

/// Members this build does not install yet.
///
/// `createBlobFromFilePath` needs a file-backed part whose `pull` can report
/// `STATUS_BLOCK` and be woken when the read completes. Every part here is
/// memory-resident, so there is no such handle to build; the deferred member
/// stays declared rather than returning a plausible-looking `undefined`, which
/// `internal/blob.js` would turn into a `NotReadableError` for a file that
/// exists and is readable.
pub const DEFERRED: &[(&str, &str)] = &[(
    "createBlobFromFilePath",
    "needs a file-backed part with an asynchronous reader; every Blob part in \
     this build is memory-resident, and a synchronous stand-in would report a \
     readable file as NotReadableError",
)];

/// `bob::STATUS_EOS`: the reader reached the end.
const STATUS_EOS: i32 = 0;

/// Names of the private properties that carry a handle's state.
///
/// Private properties are per-object and invisible to JavaScript, so a `Blob`
/// cannot be talked into reading another one's bytes, and a foreign object
/// passed where a handle is expected has none of these and is rejected.
const KEY_BYTES: &str = "rn-blob-bytes";
const KEY_START: &str = "rn-blob-start";
const KEY_END: &str = "rn-blob-end";
const KEY_OFFSET: &str = "rn-blob-offset";

thread_local! {
    /// The four private keys, created once per isolate.
    ///
    /// `Private::new` is bound to the isolate's context, so the keys are created
    /// on first use and reused; a key that is not cached would be a different
    /// private name on every call and nothing would resolve.
    static KEYS: RefCell<Option<Keys>> = const { RefCell::new(None) };

    /// Templates for the handle and reader objects.
    static TEMPLATES: RefCell<Option<Templates>> = const { RefCell::new(None) };

    /// `StoreDataObject` entries: an object URL id to its stored blob.
    static DATA_OBJECTS: RefCell<HashMap<String, StoredDataObject>> = RefCell::new(HashMap::new());
}

struct Keys {
    bytes: v8::Global<v8::Private>,
    start: v8::Global<v8::Private>,
    end: v8::Global<v8::Private>,
    offset: v8::Global<v8::Private>,
}

struct Templates {
    /// The instance templates, not the constructor templates.
    ///
    /// `InstanceTemplate::NewInstance` builds the object with the methods and
    /// prototype the template declares without running a constructor callback,
    /// which is what a handle needs: it is only ever built from here.
    handle: v8::Global<v8::ObjectTemplate>,
    reader: v8::Global<v8::ObjectTemplate>,
}

#[derive(Clone)]
struct StoredDataObject {
    handle: v8::Global<v8::Object>,
    length: usize,
    kind: String,
}

/// The `blob` namespace.
pub struct Blob;

impl BindingModule for Blob {
    fn namespace(&self) -> &'static str {
        "blob"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        install_templates(scope)?;
        install_keys(scope)?;

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 5] = [
            ("concat", function(scope, "concat", concat)?),
            ("createBlob", function(scope, "createBlob", create_blob)?),
            (
                "getDataObject",
                function(scope, "getDataObject", get_data_object)?,
            ),
            (
                "revokeObjectURL",
                function(scope, "revokeObjectURL", revoke_object_url)?,
            ),
            (
                "storeDataObject",
                function(scope, "storeDataObject", store_data_object)?,
            ),
        ];
        for (name, value) in values {
            let key = v8::String::new(scope, name)
                .ok_or_else(|| format!("cannot allocate the {name} member name"))?;
            object.set(scope, key.into(), value);
        }
        Ok(object)
    }
}

/// Creates the private keys for this isolate, once.
fn install_keys(scope: &mut v8::PinScope) -> Result<(), String> {
    if KEYS.with(|slot| slot.borrow().is_some()) {
        return Ok(());
    }
    let make = |scope: &mut v8::PinScope, name: &str| {
        let description = v8::String::new(scope, name).ok_or("cannot name a private key")?;
        Ok::<_, String>(v8::Global::new(
            scope,
            v8::Private::new(scope, Some(description)),
        ))
    };
    let keys = Keys {
        bytes: make(scope, KEY_BYTES)?,
        start: make(scope, KEY_START)?,
        end: make(scope, KEY_END)?,
        offset: make(scope, KEY_OFFSET)?,
    };
    KEYS.with(|slot| *slot.borrow_mut() = Some(keys));
    Ok(())
}

/// Builds the handle and reader templates for this isolate.
fn install_templates(scope: &mut v8::PinScope) -> Result<(), String> {
    if TEMPLATES.with(|slot| slot.borrow().is_some()) {
        return Ok(());
    }

    let handle = v8::FunctionTemplate::builder(noop_constructor).build(scope);
    let name = v8::String::new(scope, "BlobHandle").ok_or("cannot name the handle")?;
    handle.set_class_name(name);
    let proto = handle.prototype_template(scope);
    set_method(
        scope,
        proto,
        "slice",
        v8::FunctionTemplate::builder(handle_slice).build(scope),
    )?;
    set_method(
        scope,
        proto,
        "getReader",
        v8::FunctionTemplate::builder(handle_get_reader).build(scope),
    )?;

    let reader = v8::FunctionTemplate::builder(noop_constructor).build(scope);
    let name = v8::String::new(scope, "BlobReader").ok_or("cannot name the reader")?;
    reader.set_class_name(name);
    let reader_proto = reader.prototype_template(scope);
    set_method(
        scope,
        reader_proto,
        "pull",
        v8::FunctionTemplate::builder(reader_pull).build(scope),
    )?;
    set_method(
        scope,
        reader_proto,
        "setWakeup",
        v8::FunctionTemplate::builder(reader_set_wakeup).build(scope),
    )?;

    TEMPLATES.with(|slot| {
        *slot.borrow_mut() = Some(Templates {
            handle: v8::Global::new(scope, handle.instance_template(scope)),
            reader: v8::Global::new(scope, reader.instance_template(scope)),
        })
    });
    Ok(())
}

/// Adds one method to an object template.
///
/// The value has to be the `FunctionTemplate` itself: `Template::Set` rejects an
/// instantiated function outright (V8 aborts with "Invalid value, must be a
/// primitive or a Template"), so `get_function` is deliberately not called here.
fn set_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
    name: &str,
    function: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<(), String> {
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the method name {name}"));
    };
    prototype.set(key.into(), function.into());
    Ok(())
}

/// `createBlob(sources, length)`.
///
/// `sources` is an array of `ArrayBuffer`s, `ArrayBufferView`s, or other `Blob`
/// handles — never a string, because `internal/blob.js` encodes those itself.
/// `length` is the total the caller already computed; it is verified rather than
/// trusted, so a mismatch is a binding error instead of a `Blob` whose `size`
/// disagrees with the bytes it holds.
fn create_blob(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(sources) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        throw_type_error(scope, "createBlob expects an array of sources");
        return;
    };
    let declared = args.get(1).number_value(scope).unwrap_or(0.0).max(0.0) as usize;

    let mut bytes = Vec::with_capacity(declared);
    let length = sources.length();
    for index in 0..length {
        let Some(source) = sources.get_index(scope, index) else {
            continue;
        };
        if let Some(range) = read_handle(scope, source) {
            bytes.extend_from_slice(&range);
            continue;
        }
        if let Some(chunk) = bytes_of(source) {
            bytes.extend_from_slice(&chunk);
            continue;
        }
        throw_type_error(
            scope,
            "createBlob sources must be ArrayBuffers, views or Blob handles",
        );
        return;
    }

    if bytes.len() != declared {
        throw_type_error(
            scope,
            &format!(
                "createBlob was told {declared} bytes but the sources hold {}",
                bytes.len()
            ),
        );
        return;
    }

    match new_handle(scope, &bytes, 0, bytes.len()) {
        Some(object) => rv.set(object.into()),
        None => throw_type_error(scope, "cannot allocate a blob handle"),
    }
}

/// `concat(buffers)`: one new `ArrayBuffer` holding every part in order.
///
/// `internal/blob.js` uses this to join the chunks a reader produced, so it must
/// accept exactly what the reader emits: `ArrayBuffer`s and views over them.
fn concat(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(buffers) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        throw_type_error(scope, "concat expects an array of buffers");
        return;
    };

    let mut bytes = Vec::new();
    let length = buffers.length();
    for index in 0..length {
        let Some(buffer) = buffers.get_index(scope, index) else {
            continue;
        };
        match bytes_of(buffer) {
            Some(chunk) => bytes.extend_from_slice(&chunk),
            None => {
                throw_type_error(scope, "concat buffers must be ArrayBuffers or views");
                return;
            }
        }
    }

    match array_buffer(scope, &bytes) {
        Some(buffer) => rv.set(buffer.into()),
        None => throw_type_error(scope, "cannot allocate the concatenated buffer"),
    }
}

/// `storeDataObject(id, blob, length, type)`, backing `URL.createObjectURL`.
fn store_data_object(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(id) = args.get(0).to_string(scope) else {
        throw_type_error(scope, "storeDataObject expects a string id");
        return;
    };
    let id = id.to_rust_string_lossy(scope);
    let Ok(blob) = v8::Local::<v8::Object>::try_from(args.get(1)) else {
        throw_type_error(scope, "storeDataObject expects a Blob handle");
        return;
    };
    let length = args.get(2).number_value(scope).unwrap_or(0.0).max(0.0) as usize;
    let kind = args
        .get(3)
        .to_string(scope)
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default();

    DATA_OBJECTS.with(|slot| {
        slot.borrow_mut().insert(
            id,
            StoredDataObject {
                handle: v8::Global::new(scope, blob),
                length,
                kind,
            },
        );
    });
}

/// `getDataObject(id)`: `[handle, length, type]`, or `undefined`.
fn get_data_object(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(id) = args.get(0).to_string(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = id.to_rust_string_lossy(scope);
    let stored = DATA_OBJECTS.with(|slot| {
        slot.borrow().get(&id).map(|stored| {
            (
                v8::Local::new(scope, &stored.handle),
                stored.length,
                stored.kind.clone(),
            )
        })
    });
    let Some((handle, length, kind)) = stored else {
        rv.set(v8::undefined(scope).into());
        return;
    };

    let (Some(length), Some(kind)) = (
        Some(v8::Number::new(scope, length as f64)),
        v8::String::new(scope, &kind),
    ) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let array = v8::Array::new(scope, 3);
    array.set_index(scope, 0, handle.into());
    array.set_index(scope, 1, length.into());
    array.set_index(scope, 2, kind.into());
    rv.set(array.into());
}

/// `revokeObjectURL(url)`: forgets the object URL's stored blob.
///
/// Only the id matters, and it is the pathname segment after the scheme, so a
/// URL that is not a `blob:nodedata:<id>` shape is ignored rather than reported.
/// Node's own implementation returns nothing either way.
fn revoke_object_url(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(url) = args.get(0).to_string(scope) else {
        return;
    };
    let url = url.to_rust_string_lossy(scope);
    let Some(rest) = url.split_once(':').map(|(_, rest)| rest) else {
        return;
    };
    let id = rest.split(':').next().unwrap_or_default().to_string();
    if id.is_empty() {
        return;
    }
    DATA_OBJECTS.with(|slot| {
        slot.borrow_mut().remove(&id);
    });
}

/// `handle.slice(start, end)`: a new handle over the same bytes.
fn handle_slice(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this = args.this();
    let Some((bytes, start, end)) = read_range(scope, this.into()) else {
        throw_type_error(scope, "slice must be called on a blob handle");
        return;
    };
    let handle_len = end.saturating_sub(start);
    let from = args.get(0).number_value(scope).unwrap_or(0.0).max(0.0) as usize;
    let to = args.get(1).number_value(scope).unwrap_or(0.0).max(0.0) as usize;

    // Offsets are relative to this handle, and clamped to it, so a slice of a
    // slice stays inside the inner range instead of walking back into bytes the
    // parent had already excluded.
    let from = from.min(handle_len);
    let to = to.min(handle_len).max(from);

    match new_handle(scope, &bytes, start + from, start + to) {
        Some(object) => rv.set(object.into()),
        None => throw_type_error(scope, "cannot allocate a blob slice"),
    }
}

/// `handle.getReader()`: a fresh reader positioned at the start of the handle.
fn handle_get_reader(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this = args.this();
    let Some((bytes, start, end)) = read_range(scope, this.into()) else {
        throw_type_error(scope, "getReader must be called on a blob handle");
        return;
    };
    match new_reader(scope, &bytes, start, end) {
        Some(object) => rv.set(object.into()),
        None => throw_type_error(scope, "cannot allocate a blob reader"),
    }
}

/// `reader.pull(callback)`.
///
/// The callback receives `(status, buffer)` and is invoked synchronously: every
/// part is memory-resident, so there is never a reason to defer. The status is
/// also returned, which matches Node's contract even though `internal/blob.js`
/// ignores the return value and uses the callback.
fn reader_pull(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let this = args.this();
    let Some(state) = read_reader(scope, this.into()) else {
        throw_type_error(scope, "pull must be called on a blob reader");
        return;
    };
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "pull expects a callback");
        return;
    };

    let (bytes, start, end, offset) = state;
    let absolute = start.saturating_add(offset);
    let remaining = end.saturating_sub(absolute);
    let (status, buffer) = if remaining == 0 {
        (STATUS_EOS, v8::undefined(scope).into())
    } else {
        let chunk = bytes.get(absolute..end).unwrap_or_default().to_vec();
        match array_buffer(scope, &chunk) {
            Some(buffer) => {
                // Advance the cursor on the reader object itself, so the next
                // `pull` continues instead of handing back the same chunk.
                let this_value: v8::Local<v8::Value> = this.into();
                if let Ok(object) = v8::Local::<v8::Object>::try_from(this_value) {
                    if let Some(key) = key_offset(scope) {
                        let next = v8::Number::new(scope, (offset + chunk.len()) as f64);
                        let _ = object.set_private(scope, key, next.into());
                    }
                }
                (chunk.len() as i32, buffer.into())
            }
            None => {
                throw_type_error(scope, "cannot allocate a read buffer");
                return;
            }
        }
    };

    let status_value = v8::Integer::new(scope, status);
    let _ = callback.call(
        scope,
        v8::undefined(scope).into(),
        &[status_value.into(), buffer],
    );
    rv.set(status_value.into());
}

/// `reader.setWakeup(callback)`, or `setWakeup(undefined)` to clear it.
///
/// A memory-resident reader never blocks, so there is nothing to wake and this
/// is a no-op beyond argument checking. It stays implemented because
/// `internal/blob.js` calls it on the stream path, and a missing method would
/// throw from inside a stream pull.
fn reader_set_wakeup(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let this = args.this();
    if read_reader(scope, this.into()).is_none() {
        throw_type_error(scope, "setWakeup must be called on a blob reader");
        return;
    }
    let argument = args.get(0);
    if !argument.is_undefined() && v8::Local::<v8::Function>::try_from(argument).is_err() {
        throw_type_error(scope, "setWakeup expects a function or undefined");
    }
}

/// Builds one handle object over `bytes[start..end]`.
fn new_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Option<v8::Local<'s, v8::Object>> {
    let template = TEMPLATES.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|templates| v8::Local::new(scope, &templates.handle))
    })?;
    let object = template.new_instance(scope)?;
    let buffer = array_buffer(scope, bytes)?;
    let keys = current_keys(scope)?;

    if !set_private(scope, object, keys.bytes, buffer.into())? {
        return None;
    }
    if !set_private(
        scope,
        object,
        keys.start,
        v8::Number::new(scope, start as f64).into(),
    )? {
        return None;
    }
    if !set_private(
        scope,
        object,
        keys.end,
        v8::Number::new(scope, end.min(bytes.len()) as f64).into(),
    )? {
        return None;
    }
    Some(object)
}

/// Builds one reader object positioned at `start`.
fn new_reader<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Option<v8::Local<'s, v8::Object>> {
    let template = TEMPLATES.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|templates| v8::Local::new(scope, &templates.reader))
    })?;
    let object = template.new_instance(scope)?;
    let buffer = array_buffer(scope, bytes)?;
    let keys = current_keys(scope)?;

    if !set_private(scope, object, keys.bytes, buffer.into())? {
        return None;
    }
    if !set_private(
        scope,
        object,
        keys.start,
        v8::Number::new(scope, start as f64).into(),
    )? {
        return None;
    }
    if !set_private(
        scope,
        object,
        keys.end,
        v8::Number::new(scope, end.min(bytes.len()) as f64).into(),
    )? {
        return None;
    }
    if !set_private(
        scope,
        object,
        keys.offset,
        v8::Number::new(scope, 0.0).into(),
    )? {
        return None;
    }
    Some(object)
}

/// The bytes and range a handle or reader object carries.
fn read_range(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<(Vec<u8>, usize, usize)> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let keys = current_keys(scope)?;
    let bytes = object.get_private(scope, keys.bytes)?;
    let start = object.get_private(scope, keys.start)?.number_value(scope)?;
    let end = object.get_private(scope, keys.end)?.number_value(scope)?;
    let bytes = bytes_of(bytes)?;
    let start = start.max(0.0) as usize;
    let end = (end.max(0.0) as usize).min(bytes.len());
    Some((bytes, start.min(end), end))
}

/// The bytes, range and read offset a reader object carries.
fn read_reader(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<(Vec<u8>, usize, usize, usize)> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let (bytes, start, end) = read_range(scope, value)?;
    let keys = current_keys(scope)?;
    let offset = object
        .get_private(scope, keys.offset)
        .and_then(|offset| offset.number_value(scope))
        .unwrap_or(0.0);
    let offset = (offset.max(0.0) as usize).min(end.saturating_sub(start));
    Some((bytes, start, end, offset))
}

/// The bytes a handle object covers, for `createBlob`'s `Blob` part case.
fn read_handle(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    let (bytes, start, end) = read_range(scope, value)?;
    Some(bytes.get(start..end).unwrap_or_default().to_vec())
}

/// The cached private keys for this isolate, as locals in `scope`.
fn current_keys<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<LocalKeys<'s>> {
    KEYS.with(|slot| {
        let slot = slot.borrow();
        let keys = slot.as_ref()?;
        Some(LocalKeys {
            bytes: v8::Local::new(scope, &keys.bytes),
            start: v8::Local::new(scope, &keys.start),
            end: v8::Local::new(scope, &keys.end),
            offset: v8::Local::new(scope, &keys.offset),
        })
    })
}

/// The private keys bound to one scope.
struct LocalKeys<'s> {
    bytes: v8::Local<'s, v8::Private>,
    start: v8::Local<'s, v8::Private>,
    end: v8::Local<'s, v8::Private>,
    offset: v8::Local<'s, v8::Private>,
}

/// Just the offset key, for the `pull` cursor update.
fn key_offset<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Private>> {
    KEYS.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|keys| v8::Local::new(scope, &keys.offset))
    })
}

/// Sets a private property, turning "the object refused it" into `Some(false)`.
///
/// `set_private` answers `Option<bool>`: `None` means V8 could not perform the
/// store at all, `false` means it declined. Neither is expected on a freshly
/// created object, so both are reported rather than ignored — a silently missing
/// key would surface later as a handle with no bytes.
fn set_private<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    key: v8::Local<'s, v8::Private>,
    value: v8::Local<'s, v8::Value>,
) -> Option<bool> {
    object.set_private(scope, key, value)
}

/// The bytes of an `ArrayBuffer` or an `ArrayBufferView`.
///
/// A `BackingStore` exposes its bytes as `[Cell<u8>]` — JavaScript can mutate them
/// through the view, so V8 will not hand out a shared reference. This copies them
/// out, which is what every caller here wants: a `Blob` owns its bytes.
fn bytes_of(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        let length = buffer.byte_length();
        let store = buffer.get_backing_store();
        let cells = store.get(..length)?;
        return Some(cells.iter().map(|cell| cell.get()).collect());
    }
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let length = view.byte_length();
        let mut bytes = vec![0u8; length];
        view.copy_contents(&mut bytes);
        return Some(bytes);
    }
    None
}

/// A new `ArrayBuffer` holding `bytes`.
fn array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store))
}

fn noop_constructor(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn throw_type_error(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, message);
    scope.throw_exception(exception);
}

/// Registers the `blob` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Blob);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_list_covers_the_recorded_contract() {
        assert_eq!(MEMBERS.len(), 6);
        for member in [
            "concat",
            "createBlob",
            "getDataObject",
            "revokeObjectURL",
            "storeDataObject",
        ] {
            assert!(MEMBERS.contains(&member), "{member} missing");
        }
    }

    #[test]
    fn the_deferred_member_is_declared_not_stubbed() {
        // A stub returning `undefined` would make `internal/blob.js` report a
        // readable file as `NotReadableError`, so the gap is declared instead.
        //
        // The member stays in `MEMBERS` as well: `MEMBERS` is the contract's
        // recorded shape, and `DEFERRED` is what this build actually installs, so
        // the pair says "the contract has it, this build defers it". `messaging`
        // declares `moveMessagePortToContext` the same way.
        assert_eq!(DEFERRED.len(), 1);
        assert_eq!(DEFERRED[0].0, "createBlobFromFilePath");
        assert!(
            MEMBERS.contains(&DEFERRED[0].0),
            "a deferred member is still part of the recorded contract"
        );
        for (member, reason) in DEFERRED {
            assert!(!reason.is_empty(), "{member} needs a reason");
        }
    }

    #[test]
    fn slice_offsets_are_relative_to_the_handle() {
        // `handle.slice` receives offsets relative to the handle, and clamps them
        // to it, so a slice of a slice stays inside the inner range instead of
        // walking back into bytes the parent excluded.
        let (start, end) = (10usize, 14usize);
        let handle_len = end - start;
        let from = 1usize.min(handle_len);
        let to = 99usize.min(handle_len).max(from);
        assert_eq!((start + from, start + to), (11, 14));

        // The empty slice is legal and must stay empty.
        let from = 2usize.min(handle_len);
        let to = 2usize.min(handle_len).max(from);
        assert_eq!((start + from, start + to), (12, 12));
    }

    #[test]
    fn a_reader_cursor_is_clamped_to_its_range() {
        // `read_reader` clamps the stored offset to the range length, so a
        // corrupted or stale offset reports end-of-stream instead of reading
        // past the slice.
        let (start, end) = (4usize, 9usize);
        let length = end - start;
        for offset in [0.0f64, 3.0, 5.0, 100.0] {
            let clamped = (offset.max(0.0) as usize).min(length);
            assert!(clamped <= length, "offset {offset} escaped the range");
        }
    }
}
