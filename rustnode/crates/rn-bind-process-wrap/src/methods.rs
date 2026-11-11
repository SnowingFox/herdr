//! The methods on the `Process` prototype, plus `getEnvPairs`.
//!
//! `Spawn` is `src/process_wrap.cc`'s `Spawn` transcribed: it builds a
//! `uv_process_options_t` out of eight JavaScript arguments, calls `uv_spawn`,
//! and — on success — writes the assigned pid onto the object as `.pid`. Every
//! step that can fail returns a negative libuv status, which
//! `lib/internal/child_process.js` turns into an `'error'` event or a throw
//! depending on the code.
//!
//! # The stdio array
//!
//! `options.stdio` is an array of objects, one per descriptor, each naming what
//! that descriptor should be:
//!
//! | `type` | libuv flags |
//! | --- | --- |
//! | `'ignore'` | `UV_IGNORE` |
//! | `'pipe'` | `UV_CREATE_PIPE \| UV_READABLE_PIPE \| UV_WRITABLE_PIPE` |
//! | `'overlapped'` | the pipe flags plus `UV_OVERLAPPED_PIPE` |
//! | `'wrap'` | `UV_INHERIT_STREAM`, the stream taken from `handle` |
//! | anything else | `UV_INHERIT_FD`, the descriptor from `fd` |
//!
//! The pipe and wrap cases carry a `Pipe`/`TTY`/`TCP` handle, and libuv needs the
//! `uv_stream_t` inside it. That is exactly what [`rn_uv::streams`] exists for:
//! `process_wrap` cannot read another binding's private allocation, so the
//! bindings record their handles there and this looks them up by identity.

use std::ffi::{c_char, c_void, CString};
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use crate::handle::{self as process, ProcessHandle};

/// `HandleWrap::Close`.
pub fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    process::with_handle(object, |handle| {
        // `HandleWrap::Close` returns silently for a handle that is not
        // initialised. A `Process` is initialised by `uv_spawn`, so a handle that
        // never spawned has nothing for libuv to release — but its wrapper is
        // going away, so the rooted object and the box go with it.
        if !handle.is_initialised() {
            if handle.closing {
                return;
            }
            if let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) {
                if let Some(key) = v8::String::new(scope, "onclose") {
                    object.set(scope, key.into(), function.into());
                }
            }
            handle.closing = true;
            // `uv_spawn` never initialised the handle, so no libuv callback can
            // reference it and the box is released here. Clearing the wrapper's
            // field is what stops the finalizer from freeing it a second time.
            if let Some(pointer) = process::raw_handle(object) {
                object.set_aligned_pointer_in_internal_field(0, std::ptr::null::<c_void>(), 0);
                // SAFETY: `pointer` came from `Box::into_raw` in the constructor
                // and nothing else has freed it, because `spawned` is false.
                drop(unsafe { Box::from_raw(pointer) });
            }
            return;
        }
        if let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) {
            if let Some(key) = v8::String::new(scope, "onclose") {
                object.set(scope, key.into(), function.into());
            }
        }
        handle.closing = true;
        let Some(raw) = handle.raw() else {
            return;
        };
        // SAFETY: the handle is initialised and not already closing.
        unsafe { uv::uv_close(crate::as_handle(raw), Some(after_close)) };
    });
}

/// libuv's close completion.
///
/// The box is released here whenever no live wrapper owns it — which is the case
/// after a spawn whose object was collected — because libuv reads `handle->data`
/// up to and including this callback.
///
/// # Safety
///
/// Called by libuv with a handle this crate spawned.
pub unsafe extern "C" fn after_close(handle_pointer: *mut uv::uv_handle_t) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `handle_pointer` is the `uv_process_t` inside a `ProcessHandle`,
    // and its `data` is the owner pointer the constructor stored.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    let pointer = data.cast::<ProcessHandle>();
    // SAFETY: the pointer came from `Box::into_raw` and only this callback or the
    // finalizer frees it, and the two cannot both run.
    let handle = unsafe { &mut *pointer };
    handle.closing = true;

    handle.closed = true;

    let Some(owner) = handle.owner_object.clone() else {
        // The wrapper was collected while the child ran; nothing is left to
        // notify, so the box goes now.
        // SAFETY: as above; libuv is finished with the handle.
        drop(unsafe { Box::from_raw(pointer) });
        return;
    };

    rn_uv::callback::with_context(|scope| {
        let object: v8::Local<v8::Object> = v8::Local::new(scope, &owner);
        rn_uv::stream_base::call_onclose_unscoped(scope, object);
    });

    // `HandleWrap::OnClose` releases the wrap's reference to the object once
    // `onclose` has run. Dropping the root is what lets the wrapper become
    // garbage, which is when the finalizer frees the box.
    handle.owner_object = None;
}

/// `HandleWrap::Ref`.
pub fn reference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    process::with_handle(args.this(), |handle| {
        if let Some(raw) = handle.raw() {
            // SAFETY: the handle is initialised.
            unsafe { uv::uv_ref(crate::as_handle(raw)) };
        }
    });
}

/// `HandleWrap::Unref`.
pub fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    process::with_handle(args.this(), |handle| {
        if let Some(raw) = handle.raw() {
            // SAFETY: the handle is initialised.
            unsafe { uv::uv_unref(crate::as_handle(raw)) };
        }
    });
}

/// `HandleWrap::HasRef`: `IsAlive(wrap) && uv_has_ref(handle)`.
pub fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = process::with_handle(args.this(), |handle| {
        handle.raw().is_some_and(|raw| {
            // SAFETY: the handle is initialised.
            unsafe { uv::uv_has_ref(crate::as_handle(raw)) != 0 }
        })
    })
    .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// `ProcessWrap::Kill`.
///
/// A handle `uv_spawn` never initialised reports `UV_ESRCH`: there is no pid to
/// signal, and `kill(0, signal)` would signal the whole process group.
pub fn kill(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(signal) = args.get(0).int32_value(scope) else {
        return;
    };
    let status = process::with_handle(args.this(), |handle| match handle.raw() {
        // SAFETY: the handle is initialised, and `pid > 0` is what `uv_spawn`
        // assigned.
        Some(raw) if unsafe { (*raw).pid } > 0 => unsafe { uv::uv_process_kill(raw, signal) },
        // `ProcessWrap::Kill` returns `UV_ESRCH` rather than signalling pid 0,
        // which would reach every process in this one's group.
        _ => uv::uv_errno_t_UV_ESRCH,
    })
    .unwrap_or(uv::uv_errno_t_UV_ESRCH);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `ProcessWrap::GetEnvPairs` — the environment as `['KEY=value', …]`.
///
/// This is what a `spawn()` with no `env` option inherits. Node builds it from
/// `env->env_vars()->Pairs()`, an interceptor over the live environment block;
/// rustnode has no `process.env` interceptor yet, so the process' own block is
/// read directly. The two agree in the case that matters — a child inherits what
/// the parent started with — and differ only when user code assigned to
/// `process.env` without passing `options.env`.
pub fn get_env_pairs(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let pairs = environment_pairs();
    let array = v8::Array::new(scope, pairs.len() as i32);
    for (index, pair) in pairs.iter().enumerate() {
        let Some(value) = v8::String::new(scope, pair) else {
            continue;
        };
        array.set_index(scope, index as u32, value.into());
    }
    rv.set(array.into());
}

/// The process' environment as `KEY=value` strings.
#[cfg(unix)]
fn environment_pairs() -> Vec<String> {
    extern "C" {
        /// The process' environment block: a NULL-terminated array of
        /// NUL-terminated `KEY=value` strings.
        static environ: *const *const c_char;
    }

    let mut pairs = Vec::new();
    // SAFETY: `environ` is the C runtime's own environment block, and both it and
    // its strings are NUL-terminated and live for the process' life.
    unsafe {
        if environ.is_null() {
            return pairs;
        }
        let mut entry = environ;
        while !(*entry).is_null() {
            if let Ok(text) = std::ffi::CStr::from_ptr(*entry).to_str() {
                pairs.push(text.to_string());
            }
            entry = entry.add(1);
        }
    }
    pairs
}

/// The process' environment as `KEY=value` strings.
#[cfg(windows)]
fn environment_pairs() -> Vec<String> {
    std::env::vars()
        .map(|(name, value)| format!("{name}={value}"))
        .collect()
}

/// Everything `spawn`'s `uv_process_options_t` points at.
///
/// The options struct holds raw pointers into these `Vec`s, so this type has to
/// outlive the `uv_spawn` call and is what keeps the strings alive.
struct Options {
    file: CString,
    /// The NUL-terminated argument strings `arg_pointers` names.
    ///
    /// They are never read directly: their only job is to keep the memory
    /// `uv_spawn` walks alive for the duration of the call.
    #[allow(dead_code)]
    argv: Vec<CString>,
    arg_pointers: Vec<*mut c_char>,
    /// Whether `spawn`'s argv argument was an array.
    ///
    /// Node leaves `options.args` null when it is not, which tells libuv to build
    /// an argv from the file alone; a terminated array would instead run the
    /// child with an empty argv.
    has_argv: bool,
    /// The environment strings `env_pointers` names, kept alive the same way.
    #[allow(dead_code)]
    env: Vec<CString>,
    env_pointers: Vec<*mut c_char>,
    /// Whether `spawn`'s environment argument was an array. A null `env` inherits
    /// the parent's, so the distinction is observable.
    has_env: bool,
    cwd: Option<CString>,
    stdio: Vec<uv::uv_stdio_container_t>,
}

/// Why `spawn` stopped before libuv ran.
enum SpawnFailure {
    /// Report this libuv status; the caller writes it into the return value.
    Status(i32),
    /// An exception is already pending, so nothing is returned.
    Thrown,
}

impl Options {
    /// Builds the libuv options from the eight arguments `spawn` receives.
    ///
    /// `args[0]` file, `args[1]` argv, `args[2]` cwd, `args[3]` environment,
    /// `args[4]` stdio, `args[5]` flag bits, `args[6]` uid, `args[7]` gid.
    fn build(
        scope: &mut v8::PinScope<'_, '_>,
        args: &v8::FunctionCallbackArguments<'_>,
    ) -> Result<Self, SpawnFailure> {
        let Some(file) = crate::arg_string(scope, args, 0) else {
            // `CHECK(args[0]->IsString())`.
            return Err(SpawnFailure::Status(crate::EINVAL));
        };
        let Ok(file) = CString::new(file) else {
            return Err(SpawnFailure::Status(crate::EINVAL));
        };

        let mut argv = Vec::new();
        let has_argv = args.get(1).is_array();
        if let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(1)) {
            for index in 0..array.length() {
                let Some(value) = array.get_index(scope, index) else {
                    return Err(SpawnFailure::Thrown);
                };
                let Some(text) = value.to_string(scope) else {
                    return Err(SpawnFailure::Thrown);
                };
                let text = text.to_rust_string_lossy(scope);
                let Ok(text) = CString::new(text) else {
                    return Err(SpawnFailure::Status(crate::EINVAL));
                };
                argv.push(text);
            }
        }
        // libuv walks `argv` until a null entry, so an empty argv still needs the
        // terminator — which is also what `options.args.resize(len + 1)` does.
        let mut arg_pointers: Vec<*mut c_char> = argv
            .iter()
            .map(|argument| argument.as_ptr() as *mut c_char)
            .collect();
        arg_pointers.push(ptr::null_mut());

        // `node::Utf8Value cwd(...)`: an absent cwd leaves libuv to inherit this
        // process' own working directory, and an empty string does the same.
        let cwd = if args.get(2).is_string() {
            match crate::arg_string(scope, args, 2).and_then(|text| CString::new(text).ok()) {
                Some(cwd) if !cwd.as_bytes().is_empty() => Some(cwd),
                Some(_) => None,
                None => return Err(SpawnFailure::Status(crate::EINVAL)),
            }
        } else {
            None
        };

        let mut env = Vec::new();
        let has_env = args.get(3).is_array();
        if let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(3)) {
            for index in 0..array.length() {
                let Some(value) = array.get_index(scope, index) else {
                    return Err(SpawnFailure::Thrown);
                };
                let Some(text) = value.to_string(scope) else {
                    return Err(SpawnFailure::Thrown);
                };
                let text = text.to_rust_string_lossy(scope);
                let Ok(text) = CString::new(text) else {
                    return Err(SpawnFailure::Status(crate::EINVAL));
                };
                env.push(text);
            }
        }
        let mut env_pointers: Vec<*mut c_char> = env
            .iter()
            .map(|pair| pair.as_ptr() as *mut c_char)
            .collect();
        // A null `env` inherits the parent's; a terminated empty array gives the
        // child no environment at all, which is what `env: {}` asks for.
        if !env_pointers.is_empty() {
            env_pointers.push(ptr::null_mut());
        }

        let Some(stdio) = stdio_options(scope, args.get(4)) else {
            return Err(SpawnFailure::Thrown);
        };

        Ok(Self {
            file,
            argv,
            arg_pointers,
            has_argv,
            env,
            env_pointers,
            has_env,
            cwd,
            stdio,
        })
    }

    /// Fills a `uv_process_options_t` that borrows from this struct.
    ///
    /// `&mut self` because libuv takes the argv, env and stdio arrays as mutable
    /// pointers, and handing out `as_mut_ptr()` from a shared borrow would let two
    /// live pointers alias one allocation.
    ///
    /// `#[allow]` rather than a signature change: the `to_*` naming lint wants
    /// `&self`, which cannot satisfy that requirement.
    #[allow(clippy::wrong_self_convention)]
    fn to_libuv(
        &mut self,
        flags: u32,
        uid: Option<i32>,
        gid: Option<i32>,
    ) -> uv::uv_process_options_t {
        let mut options = uv::uv_process_options_t {
            exit_cb: Some(crate::handle::after_exit),
            file: self.file.as_ptr(),
            args: if self.has_argv {
                self.arg_pointers.as_mut_ptr()
            } else {
                ptr::null_mut()
            },
            env: if self.has_env && !self.env_pointers.is_empty() {
                self.env_pointers.as_mut_ptr()
            } else {
                ptr::null_mut()
            },
            cwd: self.cwd.as_ref().map_or(ptr::null(), |cwd| cwd.as_ptr()),
            flags,
            stdio_count: self.stdio.len() as i32,
            stdio: if self.stdio.is_empty() {
                ptr::null_mut()
            } else {
                self.stdio.as_mut_ptr()
            },
            uid: 0,
            gid: 0,
        };
        if let Some(uid) = uid {
            options.flags |= uv::uv_process_flags_UV_PROCESS_SETUID;
            options.uid = uid as uv::uv_uid_t;
        }
        if let Some(gid) = gid {
            options.flags |= uv::uv_process_flags_UV_PROCESS_SETGID;
            options.gid = gid as uv::uv_gid_t;
        }
        options
    }
}

/// `ParseStdioOptions`: turns `options.stdio` into libuv's containers.
///
/// Returns `None` after throwing when the value is not an array of objects, which
/// is `THROW_ERR_INVALID_ARG_TYPE(env, "options.stdio must be an array")`.
fn stdio_options(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<Vec<uv::uv_stdio_container_t>> {
    if !value.is_array() {
        crate::throw_type_error(scope, "options.stdio must be an array");
        return None;
    }
    let array = v8::Local::<v8::Array>::try_from(value).ok()?;
    let mut containers = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let entry = array.get_index(scope, index)?;
        let Ok(entry) = v8::Local::<v8::Object>::try_from(entry) else {
            crate::throw_type_error(scope, "options.stdio must be an array of objects");
            return None;
        };
        let kind = property(scope, entry, "type")
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_default();

        let mut container = uv::uv_stdio_container_t {
            flags: uv::uv_stdio_flags_UV_IGNORE,
            // SAFETY: the `stdio` union's variants are a pointer and an `int`,
            // and this writes the pointer variant; both are plain data.
            data: unsafe { std::mem::zeroed() },
        };
        match kind.as_str() {
            "ignore" => container.flags = uv::uv_stdio_flags_UV_IGNORE,
            "pipe" | "overlapped" => {
                container.flags = uv::uv_stdio_flags_UV_CREATE_PIPE
                    | uv::uv_stdio_flags_UV_READABLE_PIPE
                    | uv::uv_stdio_flags_UV_WRITABLE_PIPE;
                if kind == "overlapped" {
                    container.flags |= uv::uv_stdio_flags_UV_OVERLAPPED_PIPE;
                }
                container.data.stream = stdio_stream(scope, entry)?;
            }
            "wrap" => {
                container.flags = uv::uv_stdio_flags_UV_INHERIT_STREAM;
                container.data.stream = stdio_stream(scope, entry)?;
            }
            _ => {
                let fd = property(scope, entry, "fd").and_then(|value| value.int32_value(scope));
                let Some(fd) = fd else {
                    crate::throw_type_error(scope, "options.stdio entry needs an fd");
                    return None;
                };
                container.flags = uv::uv_stdio_flags_UV_INHERIT_FD;
                container.data.fd = fd;
            }
        }
        containers.push(container);
    }
    Some(containers)
}

/// The `uv_stream_t` a stdio entry's `handle` property names.
///
/// Every value in this table came from another binding, so the stream is resolved
/// through the shared [`rn_uv::streams`] registry rather than any private field.
fn stdio_stream(
    scope: &mut v8::PinScope<'_, '_>,
    entry: v8::Local<v8::Object>,
) -> Option<*mut uv::uv_stream_t> {
    let handle = property(scope, entry, "handle")?;
    let handle = v8::Local::<v8::Object>::try_from(handle).ok()?;
    // SAFETY: the pointer is used only for the duration of this `uv_spawn` call,
    // and a handle cannot close while JavaScript is calling `spawn`.
    match unsafe { rn_uv::streams::stream_of(scope, handle) } {
        Some(stream) => Some(stream),
        None => {
            // `CHECK_NOT_NULL(stream)` in `StreamForWrap`. A handle no binding
            // registered is a bug rather than a user error, so it is reported
            // instead of silently inheriting an unrelated descriptor.
            crate::throw_error(scope, "options.stdio handle is not a Rust stream");
            None
        }
    }
}

/// Reads a named property, if it exists.
fn property<'s>(
    scope: &v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// `ProcessWrap::Spawn`.
pub fn spawn(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `ASSIGN_OR_RETURN_UNWRAP(&wrap, args.This())` has no reported status: a
    // receiver that is not a `Process` leaves the return value unset.
    if process::raw_handle(args.this()).is_none() {
        return;
    }

    // `THROW_IF_INSUFFICIENT_PERMISSIONS(…kChildProcess, file…)` runs as soon as
    // the file argument has been read, before any of the spawn options are
    // interpreted, so a denial wins over a malformed stdio table. The resource
    // is the executable as written: `lib/child_process.js` looks the program up
    // and passes the resolved path, and Node reports exactly that string.
    if let Some(file) = crate::arg_string(scope, &args, 0) {
        if let Some(denied) = rn_permission::runtime::deny_child_process(&file) {
            denied.throw(scope);
            return;
        }
    }

    let mut options = match Options::build(scope, &args) {
        Ok(options) => options,
        Err(SpawnFailure::Status(status)) => {
            rv.set(v8::Integer::new(scope, status).into());
            return;
        }
        Err(SpawnFailure::Thrown) => return,
    };

    let spawn_flags = args.get(5).uint32_value(scope).unwrap_or(0);
    let uid = optional_int32(scope, &args, 6);
    let gid = optional_int32(scope, &args, 7);

    let mut libuv_flags = 0u32;
    if spawn_flags & crate::constants::PROCESS_FLAG_WINDOWS_HIDE as u32 != 0 {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_WINDOWS_HIDE;
    }
    if spawn_flags & crate::constants::PROCESS_FLAG_WINDOWS_VERBATIM_ARGUMENTS as u32 != 0 {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS;
    }
    if spawn_flags & crate::constants::PROCESS_FLAG_DETACHED as u32 != 0 {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_DETACHED;
    }

    let object = args.this();
    let status = process::with_handle(object, |handle| {
        if handle.spawned {
            // `uv_spawn` initialises the handle in place, so a second spawn would
            // register it with the loop twice.
            return uv::uv_errno_t_UV_EEXIST;
        }
        let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
            return uv::uv_errno_t_UV_ENOMEM;
        };
        let native = options.to_libuv(libuv_flags, uid, gid);
        // SAFETY: `handle.process` is a live, zeroed `uv_process_t` that has
        // never been initialised, and `native` borrows from `options`, which
        // outlives the call.
        let status = unsafe { uv::uv_spawn(loop_pointer, handle.process.as_mut_ptr(), &native) };
        if status == 0 {
            // `uv_spawn` calls `uv__handle_init`, which registers the handle with
            // the loop; `data` is overwritten here because the constructor stored
            // it before the handle was valid.
            let raw = handle.process.as_mut_ptr();
            // SAFETY: `uv_spawn` returned success, so the handle is initialised.
            unsafe { (*raw).data = std::ptr::from_mut(handle).cast() };
        }
        status
    })
    .unwrap_or(uv::uv_errno_t_UV_EBADF);

    if status != 0 {
        // A failed `uv_spawn` leaves the handle uninitialised, which is exactly
        // the state `close()` expects for a process that never ran.
        rv.set(v8::Integer::new(scope, status).into());
        return;
    }

    let pid = process::with_handle(object, |handle| {
        handle.spawned = true;
        // The wrapper is rooted from here on: the exit callback has to reach it,
        // and the JavaScript object may otherwise be collected while the child
        // still runs.
        handle.owner_object = Some(v8::Global::new(scope.as_ref(), object));
        // SAFETY: `uv_spawn` returned success.
        unsafe { (*handle.process.as_mut_ptr()).pid }
    })
    .unwrap_or(0);

    // `wrap->object()->Set(context, env->pid_string(), …)`:
    // `lib/internal/child_process.js` reads `this._handle.pid` immediately after a
    // successful spawn, and a pid of 0 there means the child never started.
    if let Some(key) = v8::String::new(scope, "pid") {
        object.set(scope, key.into(), v8::Integer::new(scope, pid).into());
    }
    rv.set(v8::Integer::new(scope, status).into());
}

/// Reads an optional `Int32` argument, treating `undefined`/`null` as absent.
fn optional_int32(
    scope: &v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<i32> {
    let value = args.get(index);
    if value.is_undefined() || value.is_null() {
        return None;
    }
    value.int32_value(scope)
}
