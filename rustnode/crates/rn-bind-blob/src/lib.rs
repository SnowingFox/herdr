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
    "getDataObject",
    "revokeObjectURL",
    "storeDataObject",
];

/// Members this build does not install yet.
///
/// `createBlobFromFilePath` is `fs.openAsBlob()`/`fs.openAsBlobSync()`:
/// `lib/fs.js:811,834` call it directly, so those two functions throw
/// `_createBlobFromFilePath is not a function` today.
///
/// The gap is the handle representation, not a missing syscall. A rustnode blob
/// handle is `{ArrayBuffer, start, end}` private properties over one
/// memory-resident `ArrayBuffer` (see the module documentation), so a
/// file-backed part cannot be expressed at all: `slice` would have to read the
/// file, `new Blob([filePart])` would have to copy it, and `pull` has no way to
/// answer "not yet" — which is exactly what `getBlobDataSync` in
/// `lib/internal/blob.js` reads as the signal that a part is file-backed.
/// Implementing it means a second handle kind, a `DataQueue`-shaped part list
/// that can slice across parts, and an asynchronous read path that resumes
/// `pull`; a synchronous stand-in would report a readable file as
/// `NotReadableError`, which is a new divergence rather than a fix.
pub const DEFERRED: &[(&str, &str)] = &[(
    "createBlobFromFilePath",
    "needs a file-backed blob part: a second handle kind, a part list that can \
     slice across parts, and an asynchronous reader whose pull can report \
     STATUS_BLOCK and be woken, none of which a memory-resident ArrayBuffer \
     handle can express; fs.openAsBlob() and fs.openAsBlobSync() throw today",
)];

/// `bob::STATUS_EOS`: the reader reached the end.
const STATUS_EOS: i32 = 0;
/// `bob::STATUS_CONTINUE`: this pull produced bytes and more may follow.
///
/// The status is not a length and must not be confused with one.
/// `internal/blob.js` treats `0` as end-of-stream, a negative value as a read
/// error, `2` (`STATUS_BLOCK`) as "no data yet, wait for the wakeup", and any
/// other value as "this response carried bytes, pull again". Returning the
/// chunk length therefore happens to work for every length except `0` and `2`,
/// where it silently reports end-of-stream or a blocked read instead of data.
const STATUS_CONTINUE: i32 = 1;

/// Names of the private properties that carry a handle's state.
///
/// Private properties are per-object and invisible to JavaScript, so a `Blob`
/// cannot be talked into reading another one's bytes, and a foreign object
/// passed where a handle is expected has none of these and is rejected.
const KEY_BYTES: &str = "rn-blob-bytes";
const KEY_START: &str = "rn-blob-start";
const KEY_END: &str = "rn-blob-end";
const KEY_OFFSET: &str = "rn-blob-offset";
/// Cumulative end offset of each source part, as an array of numbers.
///
/// Node's handle is a `DataQueue` of parts and its `Pull` hands back one part
/// per call, so `new Blob(Array(10).fill('hello')).stream()` yields ten 5-byte
/// chunks. A handle here holds one contiguous `ArrayBuffer`, so without this the
/// same blob streamed as a single 50-byte chunk — correct in total size and
/// wrong in every boundary a consumer can observe.
const KEY_PARTS: &str = "rn-blob-parts";

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
    parts: v8::Global<v8::Private>,
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
        parts: make(scope, KEY_PARTS)?,
    };
    KEYS.with(|slot| *slot.borrow_mut() = Some(keys));
    Ok(())
}

/// Builds the handle and reader templates for this isolate.
fn install_templates(scope: &mut v8::PinScope) -> Result<(), String> {
    if TEMPLATES.with(|slot| slot.borrow().is_some()) {
        return Ok(());
    }

    let handle = rn_core::class(noop_constructor).build(scope);
    let name = v8::String::new(scope, "BlobHandle").ok_or("cannot name the handle")?;
    handle.set_class_name(name);
    let proto = handle.prototype_template(scope);
    set_method(
        scope,
        proto,
        "slice",
        rn_core::class(handle_slice).build(scope),
    )?;
    set_method(
        scope,
        proto,
        "getReader",
        rn_core::class(handle_get_reader).build(scope),
    )?;

    let reader = rn_core::class(noop_constructor).build(scope);
    let name = v8::String::new(scope, "BlobReader").ok_or("cannot name the reader")?;
    reader.set_class_name(name);
    let reader_proto = reader.prototype_template(scope);
    set_method(
        scope,
        reader_proto,
        "pull",
        rn_core::class(reader_pull).build(scope),
    )?;
    set_method(
        scope,
        reader_proto,
        "setWakeup",
        rn_core::class(reader_set_wakeup).build(scope),
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
    // Each source contributes one part, and the boundaries are what a reader
    // hands out one at a time. Empty sources are skipped: a part of zero bytes
    // would otherwise make `pull` answer `STATUS_CONTINUE` with an empty buffer
    // and never advance, which is an infinite read rather than a shorter blob.
    let mut parts: Vec<usize> = Vec::new();
    let length = sources.length();
    for index in 0..length {
        let Some(source) = sources.get_index(scope, index) else {
            continue;
        };
        if let Some(range) = read_handle(scope, source) {
            bytes.extend_from_slice(&range);
            if !range.is_empty() {
                parts.push(bytes.len());
            }
            continue;
        }
        if let Some(chunk) = bytes_of(source) {
            bytes.extend_from_slice(&chunk);
            if !chunk.is_empty() {
                parts.push(bytes.len());
            }
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

    match new_handle_with_parts(scope, &bytes, 0, bytes.len(), &parts) {
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

/// The object-url id in `blob:nodedata:<id>`, if `url` is that shape.
///
/// `internal/blob.js`'s `resolveObjectURL` parses the URL and splits its
/// **pathname** on `:` into at most three parts, requiring exactly two; this is
/// the same rule over the string `internal/url.js` hands to `revokeObjectURL`.
///
/// The id is the *second* segment, not the first. `storeDataObject` keys its map
/// on the bare UUID that `createObjectURL` generated, so the segment after
/// `blob:` is the literal `nodedata` and treating it as the id removes nothing
/// while reporting success — which is exactly what this did before
/// `test-webworker-importscripts-conversion.js` needed a `blob:` URL to stop
/// resolving after `revokeObjectURL`.
fn object_url_id(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once(':')?;
    if scheme != "blob" {
        return None;
    }
    // A query or fragment is not part of the pathname, so it cannot contribute a
    // segment. Node reaches the pathname through `new URL`, which drops both.
    let path = rest.split(['?', '#']).next()?;
    let mut parts = path.splitn(3, ':');
    let base = parts.next()?;
    let id = parts.next()?;
    if base != "nodedata" || parts.next().is_some() || id.is_empty() {
        return None;
    }
    Some(id)
}

/// `revokeObjectURL(url)`: forgets the object URL's stored blob.
///
/// A URL that is not a `blob:nodedata:<id>` shape is ignored rather than
/// reported; Node's own implementation returns nothing either way.
fn revoke_object_url(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(url) = args.get(0).to_string(scope) else {
        return;
    };
    let url = url.to_rust_string_lossy(scope);
    let Some(id) = object_url_id(&url) else {
        return;
    };
    let id = id.to_string();
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
    // The handle's boundaries are absolute in its own buffer; the reader's are
    // relative to its `start`, and `reader_pull` adds `start` back before
    // comparing, so they are rebased here rather than at each read.
    let parts = read_handle_parts(scope, this.into())
        .map(|parts| {
            parts
                .into_iter()
                .filter(|boundary| *boundary > start && *boundary <= end)
                .map(|boundary| boundary - start)
                .collect::<Vec<usize>>()
        })
        .unwrap_or_default();
    match new_reader(scope, &bytes, start, end, &parts) {
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
///
/// Node's `Pull` answers `STATUS_CONTINUE` for a chunk and `STATUS_EOS` at the
/// end; the status is a `bob::Status`, not a byte count. See
/// [`STATUS_CONTINUE`] for what returning a length breaks.
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

    let ReaderState {
        bytes,
        start,
        end,
        offset,
        parts,
    } = state;
    let absolute = start.saturating_add(offset);
    let remaining = end.saturating_sub(absolute);
    // One part per pull, as Node's `DataQueue::Pull` does: the next boundary at
    // or after the cursor ends the chunk, so a blob built from ten sources
    // streams as ten reads rather than one. With no boundaries recorded the only
    // boundary is `end`, which keeps a single-source blob and a slice reading as
    // one chunk.
    let limit = parts
        .iter()
        .copied()
        .find(|boundary| *boundary > absolute)
        .map_or(end, |boundary| boundary.min(end));
    let (status, buffer) = if remaining == 0 {
        (STATUS_EOS, v8::undefined(scope).into())
    } else {
        let chunk = bytes.get(absolute..limit).unwrap_or_default().to_vec();
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
                (pull_status(remaining), buffer.into())
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

/// The `bob::Status` a pull reports for a chunk with `remaining` bytes left.
///
/// This is a `bob::Status`, not a byte count. `internal/blob.js` switches on it:
/// `0` closes the stream, a negative value rejects, `2` (`STATUS_BLOCK`) waits
/// for a wakeup that a memory-resident reader never sends, and anything else
/// means "this response carried bytes, pull again".
///
/// Returning `remaining` here — which is what this crate used to do — is
/// therefore right for every length except `0` and `2`: a two-byte chunk
/// reports `STATUS_BLOCK` and stalls the read forever, and an empty one reports
/// end-of-stream. `Blob#arrayBuffer()`, `.bytes()`, `.text()` and
/// `new Response(blob)` all go through this, so a two-byte blob body hung.
fn pull_status(remaining: usize) -> i32 {
    if remaining == 0 {
        STATUS_EOS
    } else {
        STATUS_CONTINUE
    }
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

/// [`new_handle_with_parts`] for a handle with no part boundaries.
///
/// A slice of an existing blob is one contiguous part, which is what Node's
/// `Blob::Slice` produces, so the boundaries it had are no longer meaningful.
fn new_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Option<v8::Local<'s, v8::Object>> {
    new_handle_with_parts(scope, bytes, start, end, &[])
}

/// Builds one handle object over `bytes[start..end]`, with part boundaries.
///
/// `parts` holds cumulative end offsets within the same range; an empty list
/// means "one part", which is what a slice or a single-source blob is.
fn new_handle_with_parts<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    start: usize,
    end: usize,
    parts: &[usize],
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
    // The part boundaries, as a plain array of numbers. A handle with none set
    // reads back as one part covering the whole range.
    if !parts.is_empty() {
        let list: Vec<v8::Local<'_, v8::Value>> = parts
            .iter()
            .map(|offset| v8::Number::new(scope, *offset as f64).into())
            .collect();
        let array = v8::Array::new_with_elements(scope, &list);
        if !set_private(scope, object, keys.parts, array.into())? {
            return None;
        }
    }
    // Marked so `structuredClone` rebuilds it through [`BlobHandleClone`] rather
    // than treating it as a plain object, which would drop the prototype's
    // `slice` and `getReader` and leave a clone that cannot be read.
    rn_core::host_object::mark(scope, object, BLOB_HANDLE_KIND);
    Some(object)
}

/// Builds one reader object positioned at `start`.
fn new_reader<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
    start: usize,
    end: usize,
    parts: &[usize],
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
    if !parts.is_empty() {
        let list: Vec<v8::Local<'_, v8::Value>> = parts
            .iter()
            .map(|boundary| v8::Number::new(scope, *boundary as f64).into())
            .collect();
        let array = v8::Array::new_with_elements(scope, &list);
        if !set_private(scope, object, keys.parts, array.into())? {
            return None;
        }
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
) -> Option<ReaderState> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let (bytes, start, end) = read_range(scope, value)?;
    let keys = current_keys(scope)?;
    let offset = object
        .get_private(scope, keys.offset)
        .and_then(|offset| offset.number_value(scope))
        .unwrap_or(0.0);
    let offset = (offset.max(0.0) as usize).min(end.saturating_sub(start));
    // The boundaries ride on the handle; a reader created from a handle that has
    // none reports an empty list, which `reader_pull` reads as "one part".
    let parts = read_handle_parts(scope, value)
        .map(|parts| {
            parts
                .into_iter()
                .map(|boundary| boundary.saturating_sub(start))
                .collect::<Vec<usize>>()
        })
        .unwrap_or_default();
    Some(ReaderState {
        bytes,
        start,
        end,
        offset,
        parts,
    })
}

/// What a reader object carries: the bytes, its range, its cursor and the part
/// boundaries relative to `start`.
struct ReaderState {
    bytes: Vec<u8>,
    start: usize,
    end: usize,
    offset: usize,
    parts: Vec<usize>,
}

/// The part boundaries recorded on a handle or reader, or `None` when it has none.
fn read_handle_parts(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<Vec<usize>> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let keys = current_keys(scope)?;
    let array = v8::Local::<v8::Array>::try_from(object.get_private(scope, keys.parts)?).ok()?;
    Some(
        (0..array.length())
            .filter_map(|index| array.get_index(scope, index))
            .filter_map(|item| item.number_value(scope))
            .map(|number| number.max(0.0) as usize)
            .collect(),
    )
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
            parts: v8::Local::new(scope, &keys.parts),
        })
    })
}

/// The private keys bound to one scope.
struct LocalKeys<'s> {
    parts: v8::Local<'s, v8::Private>,
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
    Ok(rn_core::named_method(scope, name, callback)?.into())
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
    // A blob *handle* is a host object, so `structuredClone` can rebuild it.
    // Without this the serialiser treats it as a plain object and the clone comes
    // back with the private byte range but none of the prototype's methods, so
    // `structuredClone(blob).text()` threw `getReader is not a function`.
    //
    // The reader is not marked: it is short-lived state a `Blob` creates on
    // demand, never something a user holds across a message.
    rn_core::host_object::register_kind(BLOB_HANDLE_KIND, blob_handle_clone);
}

/// The `host_object` kind name for a blob handle.
const BLOB_HANDLE_KIND: &str = "BlobHandle";

/// `Blob::CloneForMessaging`, which copies the handle's byte range.
///
/// Node's returns a `TransferData` that owns a `shared_ptr` to the same source
/// blob, so the clone reads the same bytes without copying them. [`BlobHandleClone`]
/// carries the range instead, which is what a rustnode handle is: no part list to
/// share, and the bytes already live in one `ArrayBuffer` the clone can point at.
fn blob_handle_clone<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<std::sync::Arc<dyn rn_core::host_object::TransferData>> {
    let (bytes, start, end) = read_range(scope, object.into())?;
    Some(std::sync::Arc::new(BlobHandleClone { bytes, start, end }))
}

/// The receiving half of a blob handle clone.
struct BlobHandleClone {
    bytes: Vec<u8>,
    start: usize,
    end: usize,
}

impl rn_core::host_object::TransferData for BlobHandleClone {
    fn rebuild<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _target: v8::Local<'s, v8::Context>,
    ) -> Option<v8::Local<'s, v8::Object>> {
        let object = new_handle(scope, &self.bytes, self.start, self.end)?;
        rn_core::host_object::mark(scope, object, BLOB_HANDLE_KIND);
        Some(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_list_covers_the_recorded_contract_without_the_deferral() {
        assert_eq!(MEMBERS.len(), 5);
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
    fn the_deferred_member_is_declared_not_claimed() {
        // A stub returning `undefined` would make `internal/blob.js` report a
        // readable file as `NotReadableError`, so the gap is declared instead.
        //
        // The member must not also be in `MEMBERS`. This test used to assert the
        // opposite — that a deferred member "is still part of the recorded
        // contract" and so belongs in both lists. That is the self-cancelling
        // claim `sqlite.backup` shipped: `MEMBERS` means "this crate installs it",
        // so a name in both lists removes itself from the contract subtraction and
        // every declaration-only check reports the namespace clean while `lib/**`
        // reads `undefined`. The contract records the member; `DEFERRED` is where a
        // build that cannot install it says so.
        assert_eq!(DEFERRED.len(), 1);
        assert_eq!(DEFERRED[0].0, "createBlobFromFilePath");
        assert!(
            !MEMBERS.contains(&DEFERRED[0].0),
            "a deferred member must not also be claimed as installed"
        );
        for (member, reason) in DEFERRED {
            assert!(!reason.is_empty(), "{member} needs a reason");
        }
    }

    #[test]
    fn object_url_id_is_the_segment_after_nodedata() {
        // `storeDataObject` keys on the bare UUID, so this is the id that has to
        // come back out. Reading the first segment instead yields `nodedata`,
        // which is not a key, and the revoke then silently does nothing.
        assert_eq!(
            object_url_id("blob:nodedata:0f8a1c2e-1111-4222-8333-444455556666"),
            Some("0f8a1c2e-1111-4222-8333-444455556666")
        );
        // A query or fragment is not part of the pathname, so it cannot become
        // part of the id or add a segment.
        assert_eq!(object_url_id("blob:nodedata:abc?x=1"), Some("abc"));
        assert_eq!(object_url_id("blob:nodedata:abc#frag"), Some("abc"));
    }

    #[test]
    fn object_url_id_rejects_shapes_it_cannot_have_written() {
        for url in [
            // Not a blob: URL at all.
            "https://example.com/nodedata:abc",
            "file:///tmp/nodedata:abc",
            // Right scheme, wrong store prefix.
            "blob:other:abc",
            // The bare scheme, no store segment, and an empty id.
            "blob:",
            "blob:nodedata:",
            "blob:nodedata",
            // Three segments: `resolveObjectURL` requires exactly two.
            "blob:nodedata:a:b",
            // No scheme.
            "nodedata:abc",
        ] {
            assert_eq!(object_url_id(url), None, "{url} should not parse");
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

    #[test]
    fn the_pull_status_is_a_bob_status_and_not_a_length() {
        // `internal/blob.js` switches on the status: `0` is end-of-stream, a
        // negative value is a read error, `2` is "no data yet, wait for the
        // wakeup", and anything else means "this response carried bytes".
        //
        // Returning the chunk length therefore reads as end-of-stream for an
        // empty chunk and as a blocked read for a two-byte one, which is why
        // `Blob#text()` and `new Response(blob).text()` used to hang on a
        // two-byte body and work on every other length.
        assert_eq!(STATUS_EOS, 0);
        assert_eq!(STATUS_CONTINUE, 1);
        assert_ne!(
            STATUS_CONTINUE, 2,
            "2 is STATUS_BLOCK, which blob.js answers with a wakeup instead of the bytes"
        );

        // The status depends on whether bytes are left, never on how many.
        assert_eq!(pull_status(0), STATUS_EOS);
        for remaining in [1usize, 2, 3, 4, 4096, 1 << 20] {
            assert_eq!(
                pull_status(remaining),
                STATUS_CONTINUE,
                "{remaining} bytes left must report STATUS_CONTINUE, not {remaining}"
            );
        }

        // The exact shape of the old defect: `2` used to be both a legal status
        // and a legal length.
        assert_ne!(pull_status(2), 2);
    }
}
