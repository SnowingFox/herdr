//! Installing the `fs` namespace object.
//!
//! Every member here exists because some line of `lib/fs.js`,
//! `lib/internal/fs/**` or `lib/internal/modules/**` reads it. The list was
//! derived from those call sites and then diffed against the names
//! `src/node_file.cc` registers with `SetMethod`: it is exactly that set minus
//! four documented deferrals, plus `FSReqCallback` and `kUsePromises`.
//!
//! The deferrals are `cpSyncCheckPaths`, `cpSyncCopyDir`, `cpSyncOverrideFile`
//! and `openFileHandle`. The first three are `fs.cp` fast paths that only matter
//! when no `filter` callback is supplied, and `openFileHandle` needs the
//! `FileHandle` handle type. `README.md` explains each one. A test in
//! `tests/js_contract.rs` pins the set so it cannot drift silently.
//!
//! Argument order is copied from the JS call sites verbatim, including the
//! trailing "request" slot whose meaning `request::classify` decides.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;
use rn_v8_sys::v8::Local;

use crate::args::Encoding;
use crate::complete::{deliver_to_callback, deliver_to_promise, Completion, Payload};
use crate::error::FsError;
use crate::fsops::{self, TimeSpec};
use crate::request::{classify, install_sentinel, throw_error, Delivery};
use crate::stats::{Follow, StatFields, StatFsFields};

/// Binds a Rust callback as a namespace function.
macro_rules! mkfn {
    ($installer:expr, $name:expr, $callback:expr) => {{
        let template = v8::FunctionTemplate::builder($callback).build($installer.scope);
        let function = template
            .get_function($installer.scope)
            .ok_or_else(|| format!("cannot allocate fs.{}", $name))?;
        $installer.define($name, function.into())?;
    }};
}

/// Delivers a finished operation according to the trailing-argument mode.
///
/// Expanded inline in each binding so the callback's own lifetimes apply; a
/// generic helper would have to unify three independent V8 lifetimes and cannot.
macro_rules! conclude {
    ($scope:expr, $args:expr, $rv:expr, $completion:expr) => {{
        let completion = $completion;
        let (mode, request) = classify($scope, tail(&$args));
        match mode {
            Delivery::Sync => match completion.payload {
                Ok(Payload::Unit) => $rv.set_undefined(),
                Ok(Payload::Value(value)) => $rv.set(value),
                Ok(Payload::Pair(first, second)) => {
                    let array = v8::Array::new_with_elements($scope, &[first, second]);
                    $rv.set(array.into());
                }
                Err(error) => throw_error($scope, &error),
            },
            Delivery::Callback => {
                if let Some(request) = request {
                    deliver_to_callback($scope, request, completion);
                }
                $rv.set_undefined();
            }
            Delivery::Promise => match deliver_to_promise($scope, completion) {
                Some(promise) => $rv.set(promise.into()),
                None => $rv.set_undefined(),
            },
        }
    }};
}

/// The `internalBinding('fs')` namespace.
pub struct Fs;

impl BindingModule for Fs {
    fn namespace(&self) -> &'static str {
        "fs"
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
    ) -> Result<Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        install_sentinel(scope, object).ok_or("cannot allocate the kUsePromises symbol")?;

        let mut installer = Installer { scope, object };
        installer.install_all()?;
        Ok(installer.object)
    }
}

/// Members the `fs` namespace needs but this crate does not install yet.
///
/// Nothing here is installed, so `lib/fs` reaches `undefined` for it. Each
/// entry says why it waits, and `rn-compat` fails the build when a recorded
/// member is neither installed nor listed here.
pub const DEFERRED: &[(&str, &str)] = &[
    ("CpDirJob", "cp -r recursion lives in the lib/ JS layer; the C++ job wrapper is not needed until the copy fast path lands"),
    ("FileHandle", "native FileHandle wrapper; lib/ uses the JS FileHandle over numeric fds for now"),
    ("ReadFileJob", "batched read job; reads go through read/readv until batching is measured as needed"),
    ("StatWatcher", "fs.watchFile polling handle, needs the timer loop"),
    ("WriteFileJob", "batched write job; writes go through write/writev until batching is measured as needed"),
    ("bigintStatFsValues", "bigint view of statfs fields, follows the BigInt stat surface"),
    ("bigintStatValues", "bigint view of stat fields, follows the BigInt stat surface"),
    ("cpSyncCopyDir", "cp -r directory recursion, lands with cp -r"),
    ("cpSyncOverrideFile", "cp -r overwrite rule, lands with cp -r"),
    ("getFormatOfExtensionlessFile", "ESM format sniffing for extensionless files, owned by the ESM loader"),
    ("kFsStatsFieldsNumber", "internal field-count constant used only by the native stats layout"),
    ("legacyMainResolve", "deprecated main resolution kept for compatibility, owned by the CJS loader"),
    ("openFileHandle", "native FileHandle construction, same blocker as FileHandle"),
    ("statFsValues", "statfs field layout, lands with the statfs member"),
    ("statValues", "stat field layout, lands with the native stats layout"),
];

/// Members exposed on the namespace object.
pub const MEMBERS: &[&str] = &[
    // Descriptor and byte-stream operations.
    "open",
    "close",
    "read",
    "readBuffers",
    "writeBuffer",
    "writeBuffers",
    "writeString",
    "ftruncate",
    "fsync",
    "fdatasync",
    // Metadata.
    "fstat",
    "stat",
    "lstat",
    "statfs",
    // Directory operations.
    "readdir",
    "readdirRecursive",
    // Path operations.
    "rename",
    "rmdir",
    "unlink",
    "mkdir",
    "link",
    "symlink",
    "readlink",
    "realpath",
    "access",
    "copyFile",
    "cpSyncCheckPaths",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "utimes",
    "futimes",
    "lutimes",
    // Temporary names.
    "mkdtemp",
    "mkstemp",
    "rmSync",
    // Fast paths and helpers.
    "existsSync",
    "readFileUtf8",
    "writeFileUtf8",
    "internalModuleStat",
    "handleToFd",
    // Request constructor.
    "FSReqCallback",
    "kUsePromises",
];

struct Installer<'a, 's, 'i> {
    scope: &'a mut v8::PinScope<'s, 'i>,
    object: Local<'s, v8::Object>,
}

impl<'a, 's, 'i> Installer<'a, 's, 'i> {
    fn install_all(&mut self) -> Result<(), String> {
        mkfn!(self, "cpSyncCheckPaths", cp_sync_check_paths_binding);
        mkfn!(self, "open", open_binding);
        mkfn!(self, "close", close_binding);
        mkfn!(self, "read", read_binding);
        mkfn!(self, "readBuffers", read_buffers_binding);
        mkfn!(self, "writeBuffer", write_buffer_binding);
        mkfn!(self, "writeBuffers", write_buffers_binding);
        mkfn!(self, "writeString", write_string_binding);
        mkfn!(self, "ftruncate", ftruncate_binding);
        mkfn!(self, "fsync", fsync_binding);
        mkfn!(self, "fdatasync", fdatasync_binding);
        mkfn!(self, "fstat", fstat_binding);
        mkfn!(self, "stat", stat_binding);
        mkfn!(self, "lstat", lstat_binding);
        mkfn!(self, "statfs", statfs_binding);
        mkfn!(self, "readdir", readdir_binding);
        mkfn!(self, "readdirRecursive", readdir_recursive_binding);
        mkfn!(self, "rename", rename_binding);
        mkfn!(self, "rmdir", rmdir_binding);
        mkfn!(self, "unlink", unlink_binding);
        mkfn!(self, "mkdir", mkdir_binding);
        mkfn!(self, "link", link_binding);
        mkfn!(self, "symlink", symlink_binding);
        mkfn!(self, "readlink", readlink_binding);
        mkfn!(self, "realpath", realpath_binding);
        mkfn!(self, "access", access_binding);
        mkfn!(self, "copyFile", copy_file_binding);
        mkfn!(self, "chmod", chmod_binding);
        mkfn!(self, "fchmod", fchmod_binding);
        mkfn!(self, "chown", chown_binding);
        mkfn!(self, "fchown", fchown_binding);
        mkfn!(self, "lchown", lchown_binding);
        mkfn!(self, "utimes", utimes_binding);
        mkfn!(self, "futimes", futimes_binding);
        mkfn!(self, "lutimes", lutimes_binding);
        mkfn!(self, "mkdtemp", mkdtemp_binding);
        mkfn!(self, "mkstemp", mkstemp_binding);
        mkfn!(self, "rmSync", rm_sync_binding);
        mkfn!(self, "existsSync", exists_sync_binding);
        mkfn!(self, "readFileUtf8", read_file_utf8_binding);
        mkfn!(self, "writeFileUtf8", write_file_utf8_binding);
        mkfn!(self, "internalModuleStat", internal_module_stat_binding);
        mkfn!(self, "handleToFd", handle_to_fd_binding);
        self.fs_req_callback()?;
        Ok(())
    }

    fn define(&mut self, name: &str, value: Local<'s, v8::Value>) -> Result<(), String> {
        let key = v8::String::new(self.scope, name)
            .ok_or_else(|| format!("cannot allocate name for fs.{name}"))?;
        self.object
            .set(self.scope, key.into(), value)
            .ok_or_else(|| format!("cannot define fs.{name}"))?;
        Ok(())
    }

    /// Defines the `FSReqCallback` constructor.
    ///
    /// `lib/fs.js` and `lib/internal/fs/read/context.js` do
    /// `new FSReqCallback()` / `new FSReqCallback(bigint)` and then assign
    /// `oncomplete` and `context` on the instance. The constructor therefore has
    /// to produce a plain, extensible object; all the binding needs from it later
    /// is the `oncomplete` property.
    fn fs_req_callback(&mut self) -> Result<(), String> {
        let template = v8::FunctionTemplate::builder(fs_req_callback_ctor).build(self.scope);
        let function = template
            .get_function(self.scope)
            .ok_or("cannot allocate fs.FSReqCallback")?;
        self.define("FSReqCallback", function.into())
    }
}

/// `new FSReqCallback(useBigint)`.
fn fs_req_callback_ctor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let instance = args.this();
    let bigint = args.length() > 0 && args.get(0).boolean_value(scope);
    if let Some(key) = v8::String::new(scope, "useBigint") {
        let value = v8::Boolean::new(scope, bigint);
        instance.set(scope, key.into(), value.into());
    }
    rv.set(instance.into());
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The trailing argument of a call, which selects the delivery mode.
fn tail<'s>(args: &v8::FunctionCallbackArguments<'s>) -> Option<Local<'s, v8::Value>> {
    if args.length() <= 0 {
        None
    } else {
        Some(args.get(args.length() - 1))
    }
}

/// Reads a required path argument, reporting `EINVAL` when it is neither a
/// string nor an array-buffer view.
fn required_path<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    index: i32,
    syscall: &'static str,
) -> Option<Vec<u8>> {
    match crate::args::path_bytes(scope, args.get(index)) {
        Some(path) => Some(path),
        None => {
            throw_error(scope, &FsError::from_errno(syscall, libc::EINVAL));
            None
        }
    }
}

/// Wraps stat slots as the typed array the JS unpacks.
///
/// `lib/internal/fs/utils.js` chooses `Stats` versus `BigIntStats` by testing
/// the array type, so the choice here is functional, not cosmetic.
fn stats_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    fields: StatFields,
    bigint: bool,
) -> Option<Local<'s, v8::Value>> {
    if bigint {
        let slots = fields.to_i64_slots();
        let bytes: Vec<u8> = slots.iter().flat_map(|slot| slot.to_ne_bytes()).collect();
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let array = v8::BigInt64Array::new(scope, array_buffer, 0, slots.len())?;
        Some(array.into())
    } else {
        let slots = fields.to_f64_slots();
        let bytes: Vec<u8> = slots.iter().flat_map(|slot| slot.to_ne_bytes()).collect();
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let array = v8::Float64Array::new(scope, array_buffer, 0, slots.len())?;
        Some(array.into())
    }
}

/// Wraps statfs slots the same way.
fn statfs_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    fields: StatFsFields,
    bigint: bool,
) -> Option<Local<'s, v8::Value>> {
    if bigint {
        let slots = fields.to_i64_slots();
        let bytes: Vec<u8> = slots.iter().flat_map(|slot| slot.to_ne_bytes()).collect();
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let array = v8::BigInt64Array::new(scope, array_buffer, 0, slots.len())?;
        Some(array.into())
    } else {
        let slots = fields.to_f64_slots();
        let bytes: Vec<u8> = slots.iter().flat_map(|slot| slot.to_ne_bytes()).collect();
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let array = v8::Float64Array::new(scope, array_buffer, 0, slots.len())?;
        Some(array.into())
    }
}

/// Turns an entry name into the JS value the requested encoding implies.
///
/// `encoding: 'buffer'` must produce a `Buffer`; `lib/fs.js` only depends on it
/// being an array-buffer view that `Buffer.isBuffer` accepts, and in this runtime
/// a `Uint8Array` is what `Buffer` is.
fn name_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &[u8],
    encoding: Encoding,
) -> Option<Local<'s, v8::Value>> {
    if encoding == Encoding::Buffer {
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(name.to_vec()).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let view = v8::Uint8Array::new(scope, array_buffer, 0, name.len())?;
        return Some(view.into());
    }
    let string = v8::String::new_from_utf8(scope, name, v8::NewStringType::Normal)?;
    Some(string.into())
}

/// Builds the `[names, types]` pair `getDirents` destructures.
fn dirent_pair<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[crate::dirent::DirentEntry],
    encoding: Encoding,
) -> Option<Local<'s, v8::Value>> {
    let names = v8::Array::new(scope, entries.len() as i32);
    let types = v8::Array::new(scope, entries.len() as i32);
    for (index, entry) in entries.iter().enumerate() {
        let name = name_value(scope, &entry.name, encoding)?;
        names.set_index(scope, index as u32, name)?;
        let kind = v8::Number::new(scope, f64::from(entry.kind));
        types.set_index(scope, index as u32, kind.into())?;
    }
    let pair = v8::Array::new_with_elements(scope, &[names.into(), types.into()]);
    Some(pair.into())
}

/// Builds the four parallel arrays `getRecursiveDirents` destructures.
fn recursive_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    listing: &fsops::RecursiveListing,
    encoding: Encoding,
) -> Option<Local<'s, v8::Value>> {
    let names = v8::Array::new(scope, listing.names.len() as i32);
    for (index, name) in listing.names.iter().enumerate() {
        let value = name_value(scope, name, encoding)?;
        names.set_index(scope, index as u32, value)?;
    }
    let types = v8::Array::new(scope, listing.types.len() as i32);
    for (index, kind) in listing.types.iter().enumerate() {
        let value = v8::Number::new(scope, f64::from(*kind));
        types.set_index(scope, index as u32, value.into())?;
    }
    let counts = v8::Array::new(scope, listing.counts.len() as i32);
    for (index, count) in listing.counts.iter().enumerate() {
        let value = v8::Number::new(scope, *count as f64);
        counts.set_index(scope, index as u32, value.into())?;
    }
    let dirs = v8::Array::new(scope, listing.dirs.len() as i32);
    for (index, dir) in listing.dirs.iter().enumerate() {
        let value = name_value(scope, dir, encoding)?;
        dirs.set_index(scope, index as u32, value)?;
    }
    let tuple = v8::Array::new_with_elements(
        scope,
        &[names.into(), types.into(), counts.into(), dirs.into()],
    );
    Some(tuple.into())
}

/// Reads a JS array of array-buffer views into `Global` handles.
///
/// `Global` rather than `Local` because the completion may be delivered after
/// this native frame returns, when the caller's handle scope has popped.
fn view_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: Local<'s, v8::Value>,
) -> Option<Vec<v8::Global<v8::ArrayBufferView>>> {
    let array = Local::<v8::Array>::try_from(value).ok()?;
    let length = array.length();
    let mut views = Vec::with_capacity(length as usize);
    for index in 0..length {
        let element = array.get_index(scope, index)?;
        let view = Local::<v8::ArrayBufferView>::try_from(element).ok()?;
        views.push(v8::Global::new(&*scope, view));
    }
    Some(views)
}

/// Borrows the bytes of a view for the duration of a syscall.
///
/// # Safety
///
/// The caller must ensure `offset + length <= view.byte_length()` and that the
/// view's backing store stays alive for the whole call. In every use here the JS
/// layer owns the buffer and holds a reference across the native call, and the
/// bounds are checked immediately before.
unsafe fn view_slice_mut<'a>(
    view: Local<v8::ArrayBufferView>,
    offset: usize,
    length: usize,
) -> &'a mut [u8] {
    let data = view.data().cast::<u8>();
    // SAFETY: guaranteed by the caller per this function's contract; see above.
    unsafe { std::slice::from_raw_parts_mut(data.add(offset), length) }
}

/// Shared immutable counterpart of [`view_slice_mut`].
///
/// # Safety
///
/// Same contract as [`view_slice_mut`].
unsafe fn view_slice<'a>(view: Local<v8::ArrayBufferView>, length: usize) -> &'a [u8] {
    let data = view.data().cast::<u8>();
    // SAFETY: guaranteed by the caller; the slice covers exactly the view.
    unsafe { std::slice::from_raw_parts(data, length) }
}

// ---------------------------------------------------------------------------
// Descriptor and byte-stream members
// ---------------------------------------------------------------------------

/// `open(path, flags, mode, [req])`.
fn open_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let flags = crate::args::int32(scope, args.get(1)).unwrap_or(0);
    let mode = crate::args::uint32(scope, args.get(2)).unwrap_or(0o666);
    let Some(path) = required_path(scope, &args, 0, "open") else {
        return;
    };
    let completion = match fsops::open(&path, flags, mode) {
        Ok(fd) => Completion::value(v8::Number::new(scope, f64::from(fd)).into()),
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `close(fd, [req])`.
fn close_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let completion = Completion::from_result(fsops::close(fd));
    conclude!(scope, args, rv, completion);
}

/// `read(fd, buffer, offset, length, position, [req])`.
///
/// The buffer is filled in place; no copy crosses the boundary on the way out.
fn read_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let offset = crate::args::int64(scope, args.get(2)).unwrap_or(0).max(0) as usize;
    let length = crate::args::int64(scope, args.get(3)).unwrap_or(0).max(0) as usize;
    let position = crate::args::position(scope, args.get(4));

    let Ok(view) = Local::<v8::ArrayBufferView>::try_from(args.get(1)) else {
        throw_error(scope, &FsError::from_errno("read", libc::EINVAL));
        return;
    };
    let capacity = view.byte_length();
    if offset.saturating_add(length) > capacity {
        throw_error(scope, &FsError::from_errno("read", libc::EINVAL));
        return;
    }
    // SAFETY: `offset + length <= capacity` was checked, so the slice lies
    // entirely inside the view's backing store. The JS layer owns the buffer and
    // keeps it reachable through `args` for the whole call.
    let slice = unsafe { view_slice_mut(view, offset, length) };

    let completion = match fsops::read(fd, slice, position) {
        Ok(count) => Completion::value(v8::Number::new(scope, count as f64).into()),
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `readBuffers(fd, buffers, position, [req])`.
fn read_buffers_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let position = crate::args::position(scope, args.get(2));
    let Some(buffers) = view_array(scope, args.get(1)) else {
        throw_error(scope, &FsError::from_errno("read", libc::EINVAL));
        return;
    };

    let mut total = 0usize;
    let mut failure = None;
    for buffer in &buffers {
        let view: Local<v8::ArrayBufferView> = Local::new(scope, buffer);
        let capacity = view.byte_length();
        if capacity == 0 {
            continue;
        }
        // SAFETY: the slice covers exactly the view's bytes, and the view is
        // rooted by `buffers` for the whole loop.
        let slice = unsafe { view_slice_mut(view, 0, capacity) };
        let at = if position < 0 {
            -1
        } else {
            position + total as i64
        };
        match fsops::read(fd, slice, at) {
            Ok(count) => {
                total += count;
                if count < capacity {
                    break;
                }
            }
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }

    let completion = match failure {
        Some(error) => Completion::failed(error),
        None => Completion::value(v8::Number::new(scope, total as f64).into()),
    };
    conclude!(scope, args, rv, completion);
}

/// `writeBuffer(fd, buffer, offset, length, position, [req])`.
fn write_buffer_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let offset = crate::args::int64(scope, args.get(2)).unwrap_or(0).max(0) as usize;
    let length = crate::args::int64(scope, args.get(3)).unwrap_or(0).max(0) as usize;
    let position = crate::args::position(scope, args.get(4));

    let Ok(view) = Local::<v8::ArrayBufferView>::try_from(args.get(1)) else {
        throw_error(scope, &FsError::from_errno("write", libc::EINVAL));
        return;
    };
    let capacity = view.byte_length();
    if offset.saturating_add(length) > capacity {
        throw_error(scope, &FsError::from_errno("write", libc::EINVAL));
        return;
    }
    // SAFETY: `offset + length <= capacity`, so the slice is inside the view,
    // which stays reachable through `args` for the whole call.
    let slice = unsafe { view_slice(view, length) };

    let completion = match fsops::write(fd, slice, position) {
        Ok(count) => Completion::value(v8::Number::new(scope, count as f64).into()),
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `writeBuffers(fd, buffers, position, [req])`.
fn write_buffers_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let position = crate::args::position(scope, args.get(2));
    let Some(buffers) = view_array(scope, args.get(1)) else {
        throw_error(scope, &FsError::from_errno("write", libc::EINVAL));
        return;
    };

    let mut total = 0usize;
    let mut failure = None;
    for buffer in &buffers {
        let view: Local<v8::ArrayBufferView> = Local::new(scope, buffer);
        let capacity = view.byte_length();
        if capacity == 0 {
            continue;
        }
        // SAFETY: the slice covers exactly the view's bytes and the view is
        // rooted by `buffers` for the whole loop.
        let slice = unsafe { view_slice(view, capacity) };
        let at = if position < 0 {
            -1
        } else {
            position + total as i64
        };
        match fsops::write(fd, slice, at) {
            Ok(count) => {
                total += count;
                if count < capacity {
                    break;
                }
            }
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }

    let completion = match failure {
        Some(error) => Completion::failed(error),
        None => Completion::value(v8::Number::new(scope, total as f64).into()),
    };
    conclude!(scope, args, rv, completion);
}

/// `writeString(fd, string, position, encoding, [req])`.
fn write_string_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let position = crate::args::int64(scope, args.get(2)).unwrap_or(-1);
    let encoding = crate::args::Encoding::from_value(Some(args.get(3)), scope);
    let Ok(string) = Local::<v8::String>::try_from(args.get(1)) else {
        throw_error(scope, &FsError::from_errno("write", libc::EINVAL));
        return;
    };
    let Some(bytes) = crate::args::encode_string_with(scope, string, encoding) else {
        throw_error(scope, &FsError::from_errno("write", libc::EINVAL));
        return;
    };

    let completion = match fsops::write(fd, &bytes, position) {
        Ok(count) => Completion::value(v8::Number::new(scope, count as f64).into()),
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `ftruncate(fd, length, [req])`.
fn ftruncate_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let length = crate::args::int64(scope, args.get(1)).unwrap_or(0).max(0);
    let completion = Completion::from_result(fsops::ftruncate(fd, length));
    conclude!(scope, args, rv, completion);
}

/// `fsync(fd, [req])`.
fn fsync_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let completion = Completion::from_result(fsops::fsync(fd));
    conclude!(scope, args, rv, completion);
}

/// `fdatasync(fd, [req])`.
fn fdatasync_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let completion = Completion::from_result(fsops::fdatasync(fd));
    conclude!(scope, args, rv, completion);
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// `stat(path, useBigint, [req], [throwIfNoEntry])`.
fn stat_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    stat_like(scope, args, rv, Follow::Yes, "stat");
}

/// `lstat(path, useBigint, [req])`.
fn lstat_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    stat_like(scope, args, rv, Follow::No, "lstat");
}

fn stat_like<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    follow: Follow,
    syscall: &'static str,
) {
    let bigint = args.length() > 1 && args.get(1).boolean_value(scope);
    let no_entry_is_ok = args.length() > 3 && args.get(3).is_false();
    let Some(path) = required_path(scope, &args, 0, syscall) else {
        return;
    };

    let completion = match StatFields::for_path(&path, follow) {
        Ok(fields) => match stats_value(scope, fields, bigint) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno(syscall, libc::ENOMEM)),
        },
        // Both mean "nothing there" for the no-throw form, matching
        // `is_uv_error_except_no_entry_dir`.
        Err(error) if no_entry_is_ok && matches!(error.code(), "ENOENT" | "ENOTDIR") => {
            Completion::value(v8::undefined(scope).into())
        }
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `fstat(fd, useBigint, [req], [shouldNotThrow])`.
fn fstat_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let bigint = args.length() > 1 && args.get(1).boolean_value(scope);
    let suppress = args.length() > 3 && args.get(3).is_true();

    let completion = match StatFields::for_fd(fd) {
        Ok(fields) => match stats_value(scope, fields, bigint) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno("fstat", libc::ENOMEM)),
        },
        Err(_) if suppress => Completion::value(v8::undefined(scope).into()),
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `statfs(path, useBigint, [req])`.
fn statfs_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let bigint = args.length() > 1 && args.get(1).boolean_value(scope);
    let Some(path) = required_path(scope, &args, 0, "statfs") else {
        return;
    };

    let completion = match StatFsFields::for_path(&path) {
        Ok(fields) => match statfs_value(scope, fields, bigint) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno("statfs", libc::ENOMEM)),
        },
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

/// `readdir(path, encoding, withFileTypes, [req])`.
fn readdir_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let encoding = Encoding::from_value(Some(args.get(1)), scope);
    let with_types = args.length() > 2 && args.get(2).is_true();
    let Some(path) = required_path(scope, &args, 0, "scandir") else {
        return;
    };

    let completion = match fsops::readdir(&path) {
        Ok(entries) => {
            if with_types {
                match dirent_pair(scope, &entries, encoding) {
                    Some(value) => Completion::value(value),
                    None => Completion::failed(FsError::from_errno("scandir", libc::ENOMEM)),
                }
            } else {
                match name_array(
                    scope,
                    entries.iter().map(|entry| entry.name.as_slice()),
                    encoding,
                ) {
                    Some(value) => Completion::value(value),
                    None => Completion::failed(FsError::from_errno("scandir", libc::ENOMEM)),
                }
            }
        }
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `readdirRecursive(path, encoding, withFileTypes, [req])`.
fn readdir_recursive_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let encoding = Encoding::from_value(Some(args.get(1)), scope);
    let with_types = args.length() > 2 && args.get(2).is_true();
    let Some(path) = required_path(scope, &args, 0, "scandir") else {
        return;
    };

    let completion = match fsops::readdir_recursive(&path, "scandir") {
        Ok(listing) => {
            if with_types {
                match recursive_value(scope, &listing, encoding) {
                    Some(value) => Completion::value(value),
                    None => Completion::failed(FsError::from_errno("scandir", libc::ENOMEM)),
                }
            } else {
                match name_array(scope, listing.names.iter().map(Vec::as_slice), encoding) {
                    Some(value) => Completion::value(value),
                    None => Completion::failed(FsError::from_errno("scandir", libc::ENOMEM)),
                }
            }
        }
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// Builds a JS array of names in the requested encoding.
fn name_array<'s, 'iter>(
    scope: &mut v8::PinScope<'s, '_>,
    names: impl Iterator<Item = &'iter [u8]>,
    encoding: Encoding,
) -> Option<Local<'s, v8::Value>> {
    let names: Vec<&[u8]> = names.collect();
    let array = v8::Array::new(scope, names.len() as i32);
    for (index, name) in names.iter().enumerate() {
        let value = name_value(scope, name, encoding)?;
        array.set_index(scope, index as u32, value)?;
    }
    Some(array.into())
}

// ---------------------------------------------------------------------------
// Path members with one operand
// ---------------------------------------------------------------------------

/// Implements the common `member(path, [req])` shape.
fn unary_path_member<'a, 's, 'i, F>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
    syscall: &'static str,
    operation: F,
) where
    F: FnOnce(&[u8]) -> Result<(), FsError>,
{
    let Some(path) = required_path(scope, &args, 0, syscall) else {
        return;
    };
    let completion = Completion::from_result(operation(&path));
    conclude!(scope, args, rv, completion);
}

/// `rename(oldPath, newPath, [req])`.
fn rename_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(from) = required_path(scope, &args, 0, "rename") else {
        return;
    };
    let Some(to) = required_path(scope, &args, 1, "rename") else {
        return;
    };
    let completion = Completion::from_result(fsops::rename(&from, &to));
    conclude!(scope, args, rv, completion);
}

/// `rmdir(path, [req])`.
fn rmdir_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    unary_path_member(scope, args, rv, "rmdir", fsops::rmdir);
}

/// `unlink(path, [req])`.
fn unlink_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue<'s>,
) {
    unary_path_member(scope, args, rv, "unlink", fsops::unlink);
}

/// `mkdir(path, mode, recursive, [req])`.
///
/// The recursive form returns the first directory actually created, which
/// `fs.mkdirSync` returns and the callback form ignores.
fn mkdir_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let mode = crate::args::uint32(scope, args.get(1)).unwrap_or(0o777);
    let recursive = args.length() > 2 && args.get(2).is_true();
    let Some(path) = required_path(scope, &args, 0, "mkdir") else {
        return;
    };

    let completion = match fsops::mkdir(&path, mode, recursive) {
        Ok(Some(created)) => match name_value(scope, &created, Encoding::Utf8) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno("mkdir", libc::ENOMEM)),
        },
        Ok(None) => Completion::unit(),
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `link(existingPath, newPath, [req])`.
fn link_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(existing) = required_path(scope, &args, 0, "link") else {
        return;
    };
    let Some(new_path) = required_path(scope, &args, 1, "link") else {
        return;
    };
    let completion = Completion::from_result(fsops::link(&existing, &new_path));
    conclude!(scope, args, rv, completion);
}

/// `symlink(target, path, type, [req])`.
///
/// The `type` argument is Windows-only and ignored by `uv_fs_symlink` on Unix.
fn symlink_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(target) = required_path(scope, &args, 0, "symlink") else {
        return;
    };
    let Some(link_path) = required_path(scope, &args, 1, "symlink") else {
        return;
    };
    let completion = Completion::from_result(fsops::symlink(&target, &link_path));
    conclude!(scope, args, rv, completion);
}

/// `readlink(path, encoding, [req])`.
fn readlink_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let encoding = Encoding::from_value(Some(args.get(1)), scope);
    let Some(path) = required_path(scope, &args, 0, "readlink") else {
        return;
    };

    let completion = match fsops::readlink(&path) {
        Ok(target) => match name_value(scope, &target, encoding) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno("readlink", libc::ENOMEM)),
        },
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `cpSyncCheckPaths(src, dest, dereference, recursive)`.
///
/// `lib/internal/fs/cp/cp-sync.js` calls this once before it walks anything;
/// everything else about `cpSync` is JavaScript over the other `fs` members.
/// Without it every `fs.cpSync` call threw
/// `fsBinding.cpSyncCheckPaths is not a function`.
fn cp_sync_check_paths_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(src) = crate::args::path_bytes(scope, args.get(0)) else {
        throw_error(scope, &FsError::from_errno("cp", libc::EINVAL));
        return;
    };
    let Some(dest) = crate::args::path_bytes(scope, args.get(1)) else {
        throw_error(scope, &FsError::from_errno("cp", libc::EINVAL));
        return;
    };
    let dereference = args.get(2).is_true();
    let recursive = args.get(3).is_true();

    let src_path = path_from_bytes(&src);
    let dest_path = path_from_bytes(&dest);
    // The C++ stats `src` first and throws on failure, so a missing source is
    // reported before anything is compared.
    if std::fs::symlink_metadata(&src_path).is_err() {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOENT);
        throw_error(scope, &FsError::from_errno("stat", errno));
        return;
    }

    if let Some(error) = crate::cp::check_paths(&src_path, &dest_path, dereference, recursive) {
        crate::cp::throw_cp_error(
            scope,
            &error,
            &src_path.to_string_lossy(),
            &dest_path.to_string_lossy(),
        );
    }
}

/// A byte path as a `Path`, matching how the rest of this crate handles paths.
fn path_from_bytes(bytes: &[u8]) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

/// `realpath(path, encoding, [req])`.
fn realpath_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let encoding = Encoding::from_value(Some(args.get(1)), scope);
    let Some(path) = required_path(scope, &args, 0, "realpath") else {
        return;
    };

    let completion = match fsops::realpath(&path) {
        Ok(resolved) => match name_value(scope, &resolved, encoding) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno("realpath", libc::ENOMEM)),
        },
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `access(path, mode, [req])`.
fn access_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let mode = crate::args::int32(scope, args.get(1)).unwrap_or(libc::F_OK);
    let Some(path) = required_path(scope, &args, 0, "access") else {
        return;
    };
    let completion = Completion::from_result(fsops::access(&path, mode));
    conclude!(scope, args, rv, completion);
}

/// `copyFile(src, dest, mode, [req])`.
fn copy_file_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let mode = crate::args::int32(scope, args.get(2)).unwrap_or(0);
    let Some(source) = required_path(scope, &args, 0, "copyfile") else {
        return;
    };
    let Some(destination) = required_path(scope, &args, 1, "copyfile") else {
        return;
    };
    let completion = Completion::from_result(fsops::copy_file(&source, &destination, mode));
    conclude!(scope, args, rv, completion);
}

/// `chmod(path, mode, [req])`.
fn chmod_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let mode = crate::args::uint32(scope, args.get(1)).unwrap_or(0o666);
    let Some(path) = required_path(scope, &args, 0, "chmod") else {
        return;
    };
    let completion = Completion::from_result(fsops::chmod(&path, mode));
    conclude!(scope, args, rv, completion);
}

/// `fchmod(fd, mode, [req])`.
fn fchmod_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let mode = crate::args::uint32(scope, args.get(1)).unwrap_or(0o666);
    let completion = Completion::from_result(fsops::fchmod(fd, mode));
    conclude!(scope, args, rv, completion);
}

/// `chown(path, uid, gid, [req])`.
fn chown_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let uid = crate::args::uint32(scope, args.get(1)).unwrap_or(0);
    let gid = crate::args::uint32(scope, args.get(2)).unwrap_or(0);
    let Some(path) = required_path(scope, &args, 0, "chown") else {
        return;
    };
    let completion = Completion::from_result(fsops::chown(&path, uid, gid));
    conclude!(scope, args, rv, completion);
}

/// `lchown(path, uid, gid, [req])`.
fn lchown_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let uid = crate::args::uint32(scope, args.get(1)).unwrap_or(0);
    let gid = crate::args::uint32(scope, args.get(2)).unwrap_or(0);
    let Some(path) = required_path(scope, &args, 0, "lchown") else {
        return;
    };
    let completion = Completion::from_result(fsops::lchown(&path, uid, gid));
    conclude!(scope, args, rv, completion);
}

/// `fchown(fd, uid, gid, [req])`.
fn fchown_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let uid = crate::args::uint32(scope, args.get(1)).unwrap_or(0);
    let gid = crate::args::uint32(scope, args.get(2)).unwrap_or(0);
    let completion = Completion::from_result(fsops::fchown(fd, uid, gid));
    conclude!(scope, args, rv, completion);
}

/// Reads a `[seconds, nanoseconds]` timestamp argument.
///
/// `fs.utimes` normalises `Date` and numeric forms in JS before calling, so both
/// entries are always numbers here.
fn time_spec(scope: &mut v8::PinScope<'_, '_>, value: Local<v8::Value>) -> TimeSpec {
    let Ok(array) = Local::<v8::Array>::try_from(value) else {
        return TimeSpec::new(0, 0);
    };
    let seconds = array
        .get_index(scope, 0)
        .and_then(|value| crate::args::int64(scope, value))
        .unwrap_or(0);
    let nanos = array
        .get_index(scope, 1)
        .and_then(|value| crate::args::int64(scope, value))
        .unwrap_or(0);
    TimeSpec::new(seconds, nanos)
}

/// `utimes(path, atime, mtime, [req])`.
fn utimes_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let atime = time_spec(scope, args.get(1));
    let mtime = time_spec(scope, args.get(2));
    let Some(path) = required_path(scope, &args, 0, "utimes") else {
        return;
    };
    let completion = Completion::from_result(fsops::utimes(&path, atime, mtime, true, "utimes"));
    conclude!(scope, args, rv, completion);
}

/// `lutimes(path, atime, mtime, [req])`.
fn lutimes_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let atime = time_spec(scope, args.get(1));
    let mtime = time_spec(scope, args.get(2));
    let Some(path) = required_path(scope, &args, 0, "lutimes") else {
        return;
    };
    let completion = Completion::from_result(fsops::utimes(&path, atime, mtime, false, "lutimes"));
    conclude!(scope, args, rv, completion);
}

/// `futimes(fd, atime, mtime, [req])`.
fn futimes_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let fd = crate::args::int32(scope, args.get(0)).unwrap_or(-1);
    let atime = time_spec(scope, args.get(1));
    let mtime = time_spec(scope, args.get(2));
    let completion = Completion::from_result(fsops::futimes(fd, atime, mtime));
    conclude!(scope, args, rv, completion);
}

/// `mkdtemp(prefix, encoding, [req])`.
fn mkdtemp_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let encoding = Encoding::from_value(Some(args.get(1)), scope);
    let Some(prefix) = required_path(scope, &args, 0, "mkdtemp") else {
        return;
    };
    let completion = match fsops::mkdtemp(&prefix, 0o700) {
        Ok(created) => match name_value(scope, &created, encoding) {
            Some(value) => Completion::value(value),
            None => Completion::failed(FsError::from_errno("mkdtemp", libc::ENOMEM)),
        },
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

/// `mkstemp(prefix, encoding, [req])`.
///
/// Callbacks receive `[path, fd]`, which `fs.mkstemp` destructures.
fn mkstemp_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let encoding = Encoding::from_value(Some(args.get(1)), scope);
    let Some(prefix) = required_path(scope, &args, 0, "mkstemp") else {
        return;
    };
    let completion = match fsops::mkstemp(&prefix) {
        Ok((created, fd)) => match name_value(scope, &created, encoding) {
            Some(path) => Completion::pair(path, v8::Number::new(scope, f64::from(fd)).into()),
            None => Completion::failed(FsError::from_errno("mkstemp", libc::ENOMEM)),
        },
        Err(error) => Completion::failed(error),
    };
    conclude!(scope, args, rv, completion);
}

// ---------------------------------------------------------------------------
// Fast paths
// ---------------------------------------------------------------------------

/// `rmSync(path, maxRetries, recursive, retryDelay)`.
///
/// Synchronous only: `lib/fs.js` never passes a request object here, so there is
/// no delivery mode to dispatch on.
fn rm_sync_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let max_retries = crate::args::int32(scope, args.get(1)).unwrap_or(0);
    let recursive = args.length() > 2 && args.get(2).is_true();
    let retry_delay = crate::args::int32(scope, args.get(3)).unwrap_or(100);
    let Some(path) = required_path(scope, &args, 0, "rm") else {
        return;
    };
    match fsops::rm_sync(&path, max_retries, recursive, retry_delay) {
        Ok(()) => rv.set_undefined(),
        Err(error) => throw_error(scope, &error),
    }
}

/// `existsSync(path)`: a boolean, never an error.
fn exists_sync_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let found = match crate::args::path_bytes(scope, args.get(0)) {
        Some(path) => fsops::exists(&path),
        None => false,
    };
    rv.set(v8::Boolean::new(scope, found).into());
}

/// `readFileUtf8(path, flags)`: the synchronous fast path behind
/// `readFileSync(path, 'utf8')`.
fn read_file_utf8_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let flags = crate::args::int32(scope, args.get(1)).unwrap_or(0);
    let Some(path) = required_path(scope, &args, 0, "open") else {
        return;
    };
    match fsops::read_file_utf8(&path, flags) {
        Ok(text) => {
            if let Some(value) = v8::String::new(scope, &text) {
                rv.set(value.into());
            }
        }
        Err(error) => throw_error(scope, &error),
    }
}

/// `writeFileUtf8(path, data, flags, mode)`.
fn write_file_utf8_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let flags = crate::args::int32(scope, args.get(2)).unwrap_or(1);
    let mode = crate::args::uint32(scope, args.get(3)).unwrap_or(0o666);
    let Some(path) = required_path(scope, &args, 0, "open") else {
        return;
    };
    let Ok(text) = Local::<v8::String>::try_from(args.get(1)) else {
        throw_error(scope, &FsError::from_errno("write", libc::EINVAL));
        return;
    };
    let text = text.to_rust_string_lossy(scope);
    match fsops::write_file_utf8(&path, &text, flags, mode) {
        Ok(()) => rv.set_undefined(),
        Err(error) => throw_error(scope, &error),
    }
}

/// `internalModuleStat(path)`: `0` file, `1` directory, `< 0` errno.
fn internal_module_stat_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let result = match crate::args::path_bytes(scope, args.get(0)) {
        Some(path) => fsops::internal_module_stat(&path),
        None => -libc::EINVAL,
    };
    rv.set(v8::Number::new(scope, f64::from(result)).into());
}

/// `handleToFd(handle, flags)`: Windows-only in Node.
///
/// `lib/internal/fs/streams.js` throws `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM`
/// before calling this on Unix, so reporting the same unsupported condition is
/// the only correct behaviour.
fn handle_to_fd_binding<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    match fsops::handle_to_fd() {
        Ok(fd) => rv.set(v8::Number::new(scope, f64::from(fd)).into()),
        Err(error) => throw_error(scope, &error),
    }
}
