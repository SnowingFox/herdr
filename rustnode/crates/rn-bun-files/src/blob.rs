//! The file-backed blob handle, and `Bun.file` itself.
//!
//! # The protocol this implements
//!
//! `internal/blob.js` drives any `Blob` through a native handle with four
//! operations:
//!
//! | operation | called by |
//! | --- | --- |
//! | `handle.slice(start, end)` | `Blob.prototype.slice` |
//! | `handle.getReader()` | `stream`, `textStream`, `bytes`, `arrayBuffer`, `text` |
//! | `reader.pull(cb)` | the reader loop, `cb(status, buffer?)` |
//! | `reader.setWakeup(fn)` | the stream path, for a pull that blocked |
//!
//! `rn-bind-blob` implements this over an in-memory byte range. This module
//! implements it over a *file*, which is what makes `Bun.file` a real `Blob`
//! without reimplementing `Blob`. Every part of the Blob contract that is
//! observable — `instanceof`, the prototype identity, `[Symbol.toStringTag]`,
//! `size`, `slice` — comes from Node's JavaScript, because the Blob is built by
//! calling Node's own `createBlob`.
//!
//! # Why `pull` answers synchronously
//!
//! Node's `getBlobDataSync` reads a Blob through `pull` and treats "the callback
//! did not run synchronously" as "this part is not memory resident". Rustnode has
//! no asynchronous blob read path (`fs.openAsBlob` is deferred in `rn-bind-blob`
//! for exactly that reason), so a blocking `pread` inside `pull` is the honest
//! implementation: it is synchronous, it returns the same bytes Node's memory
//! reader would, and the file is closed before `pull` returns.
//!
//! Blocking on `bun run`'s main thread is not a new capability question for
//! `Bun.file` — Bun itself reads the file synchronously from `pull` — but it is
//! worth stating: `text()`/`bytes()`/`arrayBuffer()` resolve *without* an event
//! loop turn, so a script that awaits one has already done its I/O by the time
//! the microtask runs.
//!
//! # The chunk size
//!
//! Bun reads a whole file in one `pull` (measured: a 200 KiB file produces one
//! 204800-byte chunk from `stream()`), so this does too. That keeps the `stream()`
//! observable identical, and it is why the reader needs no `STATUS_BLOCK` path.

use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rn_core::hook_slot;
use rn_v8_sys::v8;

use crate::error::{self, SyscallError};

/// `bob::STATUS_EOS`: the reader reached the end.
const STATUS_EOS: i32 = 0;
/// `bob::STATUS_CONTINUE`: this pull produced a chunk; pull again.
///
/// The value is a status, not a length. `internal/blob.js` reads `0` as
/// end-of-stream and any negative value as a failed read, so returning the chunk
/// length works for every length except `0` and would silently close a stream
/// that still had bytes in it.
const STATUS_CONTINUE: i32 = 1;
/// `bob::STATUS_LAST`-adjacent: any negative value is a failed read.
///
/// `internal/blob.js` only test `status < 0`, so the exact number is unread; `-1`
/// is used because it is the conventional EOF/error value and cannot be confused
/// with a length.
const STATUS_FAILED: i32 = -1;

thread_local! {
    /// The handle and reader templates, built once per isolate.
    ///
    /// `ObjectTemplate`s are isolate-bound, so this is a per-isolate cache and
    /// not a `static`. A missing entry means [`install`] has not run, which is
    /// reported rather than crashing.
    static TEMPLATES: RefCell<Option<Templates>> = const { RefCell::new(None) };
}

struct Templates {
    handle: v8::Global<v8::ObjectTemplate>,
    reader: v8::Global<v8::ObjectTemplate>,
}

/// One file-backed part: the path and the byte range inside it.
///
/// `path` is the path *as given*, which matters twice: a relative path is
/// resolved against the working directory at read time (measured — a Blob built
/// for `zz.txt` reads `ENOENT` after a `chdir` to a directory without it), and
/// `Bun.file(...).name` returns the string that was passed rather than the path
/// it resolved to.
#[derive(Debug, Clone)]
struct Part {
    path: String,
    start: usize,
    end: usize,
}

/// Builds the handle and reader templates and creates `Bun.file`.
///
/// Called from [`crate::entry::install`], which is what the `Bun` crate reaches.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    if TEMPLATES.with(|slot| slot.borrow().is_none()) {
        let handle = rn_core::class(noop_constructor).build(scope);
        handle.set_class_name(v8::String::new(scope, "BlobHandle").ok_or("cannot name handle")?);
        let handle_proto = handle.prototype_template(scope);
        set_template_method(
            scope,
            handle_proto,
            "slice",
            rn_core::class(handle_slice).build(scope),
        )?;
        set_template_method(
            scope,
            handle_proto,
            "getReader",
            rn_core::class(handle_get_reader).build(scope),
        )?;

        let reader = rn_core::class(noop_constructor).build(scope);
        reader.set_class_name(v8::String::new(scope, "BlobReader").ok_or("cannot name reader")?);
        let reader_proto = reader.prototype_template(scope);
        set_template_method(
            scope,
            reader_proto,
            "pull",
            rn_core::class(reader_pull).build(scope),
        )?;
        set_template_method(
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
    }

    // `length` is 1: measured, `Bun.file.length` is 1. `set_method` publishes 0
    // because that is Node's `SetMethod` rule, which does not apply to `Bun`.
    rn_core::set_named_method_with_length(scope, target, "file", 1, crate::entry::bun_file)?;
    Ok(())
}

/// Adds a `FunctionTemplate` to an `ObjectTemplate`.
///
/// `Template::Set` rejects an instantiated function, so the template itself goes
/// in rather than `get_function`'s result.
fn set_template_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
    name: &str,
    function: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot name {name}"))?;
    prototype.set(key.into(), function.into());
    Ok(())
}

/// Constructs nothing; the handle objects are built from a template.
fn noop_constructor(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
}

/// One handle object per Blob, carrying its part in a private property.
///
/// A `v8::Private` is invisible to JavaScript and cannot be forged, so a
/// `Blob` cannot be talked into reading another's file, and no own property
/// appears on the handle — which is what keeps
/// `Object.getOwnPropertyNames(Bun.file(...))` empty.
const KEY_PART: &str = "rn-bun-file-part";

fn key_part<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Private>> {
    let name = v8::String::new(scope, KEY_PART)?;
    Some(v8::Private::for_api(scope, Some(name)))
}

/// Stores the part on a handle object.
fn store_part<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    part: Part,
) -> Option<()> {
    let path = v8::String::new(scope, &part.path)?;
    let packed = v8::Array::new(scope, 3);
    packed.set_index(scope, 0, path.into())?;
    let start = v8::Number::new(scope, part.start as f64);
    packed.set_index(scope, 1, start.into())?;
    let end = v8::Number::new(scope, part.end as f64);
    packed.set_index(scope, 2, end.into())?;
    let key = key_part(scope)?;
    object.set_private(scope, key, packed.into())?;
    Some(())
}

/// Reads the part back off a handle object.
fn read_part<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Part> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let key = key_part(scope)?;
    let packed = object.get_private(scope, key)?;
    let packed = v8::Local::<v8::Array>::try_from(packed).ok()?;
    let path = packed
        .get_index(scope, 0)?
        .to_string(scope)?
        .to_rust_string_lossy(scope);
    let start = packed.get_index(scope, 1)?.number_value(scope)? as usize;
    let end = packed.get_index(scope, 2)?.number_value(scope)? as usize;
    Some(Part { path, start, end })
}

/// `handle.slice(start, end)`: a new handle over the same file.
fn handle_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(part) = read_part(scope, args.this().into()) else {
        error::throw_type_error(scope, "slice must be called on a blob handle");
        return;
    };
    let start = args.get(0).uint32_value(scope).unwrap_or(0) as usize;
    let end = args.get(1).uint32_value(scope).unwrap_or(0) as usize;
    // `internal/blob.js` computes the absolute bounds in *Blob* offsets and
    // passes them through unchanged, so they are absolute for this part too.
    let sliced = Part {
        path: part.path,
        start: part.start.saturating_add(start),
        end: part.start.saturating_add(end),
    };
    match new_handle(scope, sliced) {
        Some(handle) => rv.set(handle.into()),
        None => error::throw_type_error(scope, "cannot create a blob handle"),
    }
}

/// `handle.getReader()`: a fresh reader over this handle's range.
///
/// The reader gets its **own** object and its own zero offset. Node's
/// `internal/blob.js` builds readers as independent pullers, and measured
/// behaviour is that `text()` is repeatable — so an offset stored on the handle
/// would make the second read return nothing, which is exactly the bug this
/// shape avoids.
fn handle_get_reader<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(part) = read_part(scope, args.this().into()) else {
        error::throw_type_error(scope, "getReader must be called on a blob handle");
        return;
    };
    match new_reader(scope, part) {
        Some(reader) => rv.set(reader.into()),
        None => error::throw_type_error(scope, "cannot create a blob reader"),
    }
}

/// `reader.pull(callback)`.
///
/// Reads the range in one go and reports `STATUS_EOS` on the next pull. The
/// status is also returned, which Node's contract allows even though
/// `internal/blob.js` uses the callback.
fn reader_pull<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let this = args.this();
    let Some(part) = read_part(scope, this.into()) else {
        error::throw_type_error(scope, "pull must be called on a blob reader");
        return;
    };
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        error::throw_type_error(scope, "pull expects a callback");
        return;
    };

    let offset = read_offset(scope, this.into()).unwrap_or(0);
    if offset > 0 {
        // Every chunk was already handed over; nothing left to read.
        let status = v8::Integer::new(scope, STATUS_EOS);
        let _ = callback.call(
            scope,
            v8::undefined(scope).into(),
            &[status.into(), v8::undefined(scope).into()],
        );
        rv.set(status.into());
        return;
    }

    // The file is touched even for a zero-length range, because a *missing* file
    // has `size` 0 as well — and measured, its first read rejects with `ENOENT`
    // rather than producing an empty result. Opening before the length check is
    // what distinguishes "an empty file" from "no file", and returning EOS early
    // for a zero length silently turned the second into the first.
    // A failure is reported as a **negative status**, not a throw:
    // `internal/blob.js`'s reader loop reads `status < 0` as "this pull failed"
    // and `status === 0` as end-of-stream, and a throwing pull escapes the loop
    // entirely — which surfaced a missing file as an *uncaught exception* rather
    // than a rejected `text()`. The detail of the failure carries in a field the
    // loop does not read, which is why the message is also recorded on the reader
    // for [`crate::bprototype`] to surface through the overridden read methods.
    let bytes = match read_range(scope, &part) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            store_failure(
                scope,
                this.into(),
                "EISDIR",
                "Directories cannot be read like files",
            );
            let status = v8::Integer::new(scope, STATUS_FAILED);
            let _ = callback.call(
                scope,
                v8::undefined(scope).into(),
                &[status.into(), v8::undefined(scope).into()],
            );
            rv.set(status.into());
            return;
        }
        Err(failure) => {
            store_failure(scope, this.into(), failure.code, &failure.message);
            let status = v8::Integer::new(scope, STATUS_FAILED);
            let _ = callback.call(
                scope,
                v8::undefined(scope).into(),
                &[status.into(), v8::undefined(scope).into()],
            );
            rv.set(status.into());
            return;
        }
    };

    // `internal/blob.js` treats a thrown pull as a failed read and rejects the
    // promise the reader is serving, which is how a missing file reaches
    // `text()` as `ENOENT`.
    if bytes.is_empty() {
        write_offset(scope, this.into(), 0);
        // Report the bytes (none) and then EOS, in one step: a first pull that
        // says EOS keeps `getBlobDataSync` on its synchronous path.
        let _ = callback.call(
            scope,
            v8::undefined(scope).into(),
            &[
                v8::Integer::new(scope, STATUS_EOS).into(),
                v8::undefined(scope).into(),
            ],
        );
        rv.set(v8::Integer::new(scope, STATUS_EOS).into());
        return;
    }

    match array_buffer(scope, &bytes) {
        Some(buffer) => {
            write_offset(scope, this.into(), bytes.len());
            let status = v8::Integer::new(scope, STATUS_CONTINUE);
            let _ = callback.call(
                scope,
                v8::undefined(scope).into(),
                &[status.into(), buffer.into()],
            );
            rv.set(status.into());
        }
        None => error::throw_type_error(scope, "cannot allocate a read buffer"),
    }
}

/// `reader.setWakeup(callback)`.
///
/// A file-backed reader never blocks — `pull` returns the whole range — so there
/// is nothing to wake. The method exists because `internal/blob.js` installs it
/// on every stream's reader, and a missing method would throw from inside a
/// stream pull.
fn reader_set_wakeup<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s, v8::Value>,
) {
    if read_part(scope, args.this().into()).is_none() {
        error::throw_type_error(scope, "setWakeup must be called on a blob reader");
    }
}

const KEY_OFFSET: &str = "rn-bun-file-offset";

/// The private key under which a failed pull records its reason.
pub const KEY_FAILURE: &str = "rn-bun-file-failure";

/// Records `code` and `message` on the reader so a caller can re-raise them.
fn store_failure(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
    code: &str,
    message: &str,
) {
    let Some(object) = v8::Local::<v8::Object>::try_from(value).ok() else {
        return;
    };
    let Some(name) = v8::String::new(scope, KEY_FAILURE) else {
        return;
    };
    let key = v8::Private::for_api(scope, Some(name));
    let (Some(text), Some(reason)) = (
        v8::String::new(scope, code),
        v8::String::new(scope, message),
    ) else {
        return;
    };
    let packed = v8::Array::new(scope, 2);
    let _ = packed.set_index(scope, 0, text.into());
    let _ = packed.set_index(scope, 1, reason.into());
    let _ = object.set_private(scope, key, packed.into());
}

fn read_offset<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<usize> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let name = v8::String::new(scope, KEY_OFFSET)?;
    let key = v8::Private::for_api(scope, Some(name));
    let offset = object.get_private(scope, key)?;
    Some(offset.number_value(scope)? as usize)
}

fn write_offset(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>, length: usize) {
    let Some(object) = v8::Local::<v8::Object>::try_from(value).ok() else {
        return;
    };
    let Some(name) = v8::String::new(scope, KEY_OFFSET) else {
        return;
    };
    let key = v8::Private::for_api(scope, Some(name));
    let next = v8::Number::new(scope, length as f64);
    let _ = object.set_private(scope, key, next.into());
}

/// Builds a handle object for `part`.
fn new_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    part: Part,
) -> Option<v8::Local<'s, v8::Object>> {
    let template = TEMPLATES.with(|slot| slot.borrow().as_ref().map(|t| t.handle.clone()))?;
    let template = v8::Local::new(scope, template);
    let object = template.new_instance(scope)?;
    store_part(scope, object, part)?;
    Some(object)
}

/// Builds a reader object for `part`.
fn new_reader<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    part: Part,
) -> Option<v8::Local<'s, v8::Object>> {
    let template = TEMPLATES.with(|slot| slot.borrow().as_ref().map(|t| t.reader.clone()))?;
    let template = v8::Local::new(scope, template);
    let object = template.new_instance(scope)?;
    store_part(scope, object, part)?;
    Some(object)
}

/// Reads `part`'s bytes.
///
/// `Ok(None)` is the directory case, which is `EISDIR` with Bun's own message
/// rather than Node's. The distinction is made before the open so a directory
/// never reaches `File::open`'s platform error text.
fn read_range(
    _scope: &mut v8::PinScope<'_, '_>,
    part: &Part,
) -> Result<Option<Vec<u8>>, SyscallError> {
    let path = Path::new(&part.path);
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(None),
        Ok(_) => {}
        Err(cause) => return Err(SyscallError::new(&cause, "open", &part.path)),
    }

    let mut file =
        std::fs::File::open(path).map_err(|cause| SyscallError::new(&cause, "open", &part.path))?;
    if part.start > 0 {
        file.seek(SeekFrom::Start(part.start as u64))
            .map_err(|cause| SyscallError::new(&cause, "open", &part.path))?;
    }
    let length = part.end.saturating_sub(part.start);
    let mut bytes = vec![0u8; length];
    match file.read_exact(&mut bytes) {
        Ok(()) => Ok(Some(bytes)),
        // A short read means the file is shorter than the Blob's recorded size,
        // which is what a truncated file looks like. Bun returns what is there
        // rather than failing, so the tail is zero-trimmed by reading the
        // available bytes instead of the declared count.
        Err(cause) if cause.kind() == std::io::ErrorKind::UnexpectedEof => {
            let mut available = Vec::new();
            file.seek(SeekFrom::Start(part.start as u64))
                .map_err(|cause| SyscallError::new(&cause, "open", &part.path))?;
            file.read_to_end(&mut available)
                .map_err(|cause| SyscallError::new(&cause, "open", &part.path))?;
            available.truncate(length);
            Ok(Some(available))
        }
        Err(cause) => Err(SyscallError::new(&cause, "read", &part.path)),
    }
}

/// One `ArrayBuffer` holding a copy of `bytes`.
///
/// A copy rather than a view over the read buffer, because `internal/blob.js`
/// concatenates the chunks it receives and may hold them past this call.
fn array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    let store = v8::ArrayBuffer::new_backing_store_from_bytes(bytes.to_vec()).make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store))
}

/// Why a whole-file read failed.
pub enum ReadFailure {
    /// The path names a directory, which is `EISDIR` with Bun's own message.
    Directory,
    /// A syscall failed; delivered as the `Error` shape Bun uses.
    Syscall(SyscallError),
}

/// Reads `path`'s whole contents, for the prototype's read methods.
///
/// A directory is distinguished before the open so it never reaches the
/// platform's error text: Bun says `Directories cannot be read like files`, where
/// Node says `EISDIR: illegal operation on a directory, read`.
pub fn read_whole_file(path: &str) -> Result<Vec<u8>, ReadFailure> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Err(ReadFailure::Directory),
        Ok(_) => {}
        Err(cause) => {
            return Err(ReadFailure::Syscall(SyscallError::new(
                &cause, "open", path,
            )));
        }
    }
    std::fs::read(path)
        .map_err(|cause| ReadFailure::Syscall(SyscallError::new(&cause, "open", path)))
}

/// An `ArrayBuffer` holding a copy of `bytes`.
pub fn array_buffer_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::ArrayBuffer>> {
    let store = v8::ArrayBuffer::new_backing_store_from_bytes(bytes.to_vec()).make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store))
}

/// Builds the `Blob` for `part` using Node's own `createBlob`.
///
/// This is the whole point of the module: the returned object is Node's `Blob`,
/// so `instanceof Blob`, the prototype identity and every prototype member are
/// inherited rather than reimplemented.
pub fn create_file_blob<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    path: &str,
    type_name: &str,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let size = stat_size(path);
    let part = Part {
        path: path.to_string(),
        start: 0,
        end: size,
    };
    let handle = new_handle(scope, part).ok_or("cannot create the file blob handle")?;
    let length = v8::Number::new(scope, size as f64);
    let type_value = v8::String::new(scope, type_name).ok_or("cannot allocate the blob type")?;

    let create = internal_blob_create()?;
    let create = v8::Local::new(scope, create);
    let result = create
        .call(
            scope,
            v8::undefined(scope).into(),
            &[handle.into(), length.into(), type_value.into()],
        )
        .ok_or("internal/blob createBlob threw")?;
    Ok(result)
}

/// `internal/blob`'s `createBlob`, resolved through the realm's `require`.
fn internal_blob_create() -> Result<v8::Global<v8::Function>, String> {
    CREATE.with(|slot| {
        if let Some(cached) = slot.borrow().as_ref() {
            return Ok(cached.clone());
        }
        Err("internal/blob has not been resolved".to_string())
    })
}

thread_local! {
    /// The `createBlob` function `internal/blob` exports.
    ///
    /// Resolved once, on the first `Bun.file` call, because the realm's `require`
    /// does not exist when [`install`] runs — `Bun` is installed before the
    /// realm bootstrap. A `Global` is isolate-scoped, so this is per isolate;
    /// [`clear`] drops it when a worker's realm ends.
    static CREATE: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
}

/// Resolves `internal/blob`'s `createBlob` if it is not already cached.
///
/// Returns `Err` with a reason a caller can report rather than panicking, so a
/// realm without the blob module fails at `Bun.file(...)` with a message instead
/// of a crash.
pub fn resolve_create<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<(), String> {
    if CREATE.with(|slot| slot.borrow().is_some()) {
        return Ok(());
    }
    let require = hook_slot::require(scope)
        .ok_or("the realm bootstrap has not installed require, so internal/blob is unreachable")?;
    let id = v8::String::new(scope, "internal/blob").ok_or("cannot allocate the module id")?;
    let module = require
        .call(scope, v8::undefined(scope).into(), &[id.into()])
        .ok_or("internal/blob did not load")?;
    let module =
        v8::Local::<v8::Object>::try_from(module).map_err(|_| "internal/blob is not an object")?;
    let key = v8::String::new(scope, "createBlob").ok_or("cannot allocate createBlob")?;
    let create = module
        .get(scope, key.into())
        .ok_or("internal/blob has no createBlob")?;
    let create =
        v8::Local::<v8::Function>::try_from(create).map_err(|_| "createBlob is not a function")?;
    CREATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, create)));
    Ok(())
}

/// Drops the cached `createBlob` and handle templates.
///
/// A worker's realm ends with its isolate, and a `Global` from a dead isolate
/// must not be handed to the next one. `rn-bun` calls this from its realm
/// teardown; it has no in-crate caller, which is why it is allowed dead here.
#[allow(dead_code)]
///
/// A worker's realm ends with its isolate, and a `Global` from a dead isolate
/// must not be handed to the next one.
pub fn clear() {
    CREATE.with(|slot| *slot.borrow_mut() = None);
    TEMPLATES.with(|slot| *slot.borrow_mut() = None);
}

/// `stat`'s size for `path`, or 0 when it cannot be read.
///
/// Measured: a missing path reports `size: 0` and does **not** throw, and a
/// directory reports its own size (4096 on ext4) rather than 0.
fn stat_size(path: &str) -> usize {
    std::fs::metadata(path)
        .map(|metadata| metadata.len() as usize)
        .unwrap_or(0)
}

/// Writes `bytes` to `path`, creating parent directories.
///
/// Reused by `Bun.file(...).write(...)` and `Bun.write(Bun.file(...), ...)`,
/// both of which were measured to create the parents.
pub fn write_file(path: &str, bytes: &[u8]) -> Result<usize, SyscallError> {
    let target = PathBuf::from(path);
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(cause) = std::fs::create_dir_all(parent) {
                return Err(SyscallError::new(&cause, "open", path));
            }
        }
    }
    let mut file =
        std::fs::File::create(&target).map_err(|cause| SyscallError::new(&cause, "open", path))?;
    file.write_all(bytes)
        .map_err(|cause| SyscallError::new(&cause, "write", path))?;
    Ok(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_values_are_bob_statuses_not_lengths() {
        // `internal/blob.js` reads 0 as end-of-stream and a negative value as a
        // failure, so STATUS_CONTINUE must not be a length.
        assert_eq!(STATUS_EOS, 0);
        assert_eq!(STATUS_CONTINUE, 1);
    }

    #[test]
    fn a_missing_path_reports_size_zero_instead_of_throwing() {
        // Measured: `Bun.file("nope.txt").size` is 0 and does not throw. This is
        // the whole reason `size` stats eagerly rather than on access.
        assert_eq!(stat_size("/definitely/not/here/at-all"), 0);
    }

    #[test]
    fn a_directory_reports_its_own_size_rather_than_zero() {
        let size = stat_size(".");
        assert!(size > 0, "a directory reported {size}");
    }
}
