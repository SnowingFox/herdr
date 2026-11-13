//! The `Process` constructor and its prototype.
//!
//! Node builds `Process` from `HandleWrap` plus two methods — `spawn` and
//! `kill` — and `lib/internal/child_process.js` uses it exactly that way: it
//! constructs one per `ChildProcess`, assigns `onexit`, calls `spawn(...)`,
//! reads `.pid`, and eventually calls `close()`.
//!
//! # Per-handle native state
//!
//! Each instance owns one `uv_process_t`. It starts *uninitialised*:
//! `ProcessWrap`'s constructor runs `MarkAsUninitialized()`, and it is
//! `uv_spawn` that initialises the handle. That matters because `uv_spawn`
//! calls `uv__handle_init` itself, so a handle that had already been initialised
//! would corrupt the loop's handle queue.
//!
//! # Lifetime
//!
//! The boxed state outlives both the wrapper and the exit callback: libuv reads
//! `handle->data` from inside `uv_run` when the child is reaped, and the
//! wrapper may be collected earlier (a `ChildProcess` that dropped its
//! reference while the child still ran). The finalizer therefore only frees the
//! box once the handle has been closed, and closing before the exit is the
//! JavaScript side's own contract — `close()` runs from the `onexit` handler.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

/// The internal field holding the `*mut ProcessHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `Process` instance owns.
pub struct ProcessHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    ///
    /// `uv_spawn` initialises it in place, so the storage is zeroed here and
    /// handed to `uv_spawn` unchanged.
    pub process: Box<std::mem::MaybeUninit<uv::uv_process_t>>,
    /// Whether `uv_spawn` has initialised the handle, mirroring
    /// `HandleWrap::State`.
    ///
    /// It starts false: `ProcessWrap`'s constructor calls
    /// `MarkAsUninitialized()`, and `uv_spawn` is what registers the handle with
    /// the loop.
    pub spawned: bool,
    /// `uv_close` has been called.
    pub closing: bool,
    /// `uv_close`'s callback has run, so libuv will not touch this handle again.
    ///
    /// Only `closed` or "never spawned" allows the box to be freed; `closing`
    /// alone still has a libuv callback pending that reads `handle->data`.
    pub closed: bool,
    /// The object this handle belongs to, rooted so the exit callback can call
    /// `onexit` on it.
    pub owner_object: Option<v8::Global<v8::Object>>,
    /// The finalizer registration, parked here so it lives as long as the
    /// handle.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl ProcessHandle {
    /// Allocates a zeroed `uv_process_t` without initialising it.
    pub fn new() -> Box<Self> {
        Box::new(Self {
            process: Box::new(std::mem::MaybeUninit::zeroed()),
            spawned: false,
            closing: false,
            closed: false,
            owner_object: None,
            weak: None,
        })
    }

    /// The initialised handle, once `uv_spawn` has succeeded.
    pub fn raw(&mut self) -> Option<*mut uv::uv_process_t> {
        if !self.spawned {
            return None;
        }
        // SAFETY: `spawned` is only set after `uv_spawn` returned success, which
        // is what initialises the storage.
        Some(unsafe { self.process.as_mut_ptr().as_mut()? })
    }

    /// Whether the handle can still be closed.
    pub fn is_initialised(&self) -> bool {
        self.spawned && !self.closing
    }
}

/// The raw handle behind a `Process` object, or `None` when it is not one.
pub fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut ProcessHandle> {
    // SAFETY: the field only ever holds a pointer produced by `install`, and the
    // object is a live local so the allocation has not been freed.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut ProcessHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `Process` object.
///
/// Returns `None` for a non-`Process` receiver, which is what
/// `ASSIGN_OR_RETURN_UNWRAP` reports.
pub fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut ProcessHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live, and every borrow is scoped
    // to one callback.
    Some(body(unsafe { &mut *pointer }))
}

/// Builds the `Process` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).length(0).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);

    // `SetProtoMethod(isolate, constructor, "spawn", Spawn)` and `"kill"`.
    let spawn = v8::FunctionTemplate::builder(crate::methods::spawn)
        .length(8)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "spawn")?.into(), spawn.into());
    let kill = v8::FunctionTemplate::builder(crate::methods::kill)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set(crate::key(scope, "kill")?.into(), kill.into());

    // `HandleWrap`: `close`, `ref`, `unref`, `hasRef`.
    for (name, arity) in [("close", 0), ("ref", 0), ("unref", 0), ("hasRef", 0)] {
        let template = match name {
            "close" => v8::FunctionTemplate::builder(crate::methods::close),
            "ref" => v8::FunctionTemplate::builder(crate::methods::reference),
            "unref" => v8::FunctionTemplate::builder(crate::methods::unreference),
            _ => v8::FunctionTemplate::builder(crate::methods::has_reference),
        };
        let template = template
            .length(arity)
            .constructor_behavior(v8::ConstructorBehavior::Throw)
            .build(scope);
        prototype.set(crate::key(scope, name)?.into(), template.into());
    }

    let Some(name) = v8::String::new(scope, "Process") else {
        return Err("cannot allocate the Process class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate Process")?;
    function.set_name(name);
    Ok(function.into())
}

/// The `Process` constructor: `new Process()`.
///
/// `src/process_wrap.cc` asserts the call is a `new` and reads no arguments.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        // `src/process_wrap.cc` `CHECK(args.IsConstructCall())`.
        crate::throw_type_error(scope, "Process cannot be invoked without 'new'");
        return;
    }

    let object = args.this();
    install(scope, object, ProcessHandle::new());
    rv.set(object.into());
}

/// Installs a handle's native state and finalizer on a `Process` object.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mut handle: Box<ProcessHandle>,
) {
    handle.owner_object = Some(v8::Global::new(scope.as_ref(), object));

    let pointer = Box::into_raw(handle);
    object.set_aligned_pointer_in_internal_field(
        HANDLE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    install_finalizer(scope, object, pointer);
}

/// Registers the finalizer that retires a handle when V8 collects its wrapper.
///
/// The finalizer only frees the allocation when nothing is left to happen: a
/// spawned process may still be running, and libuv reads `handle->data` when it
/// reaps it. Until that has happened the box has to survive, so a wrapper that
/// is collected while the child runs leaves the state for the exit callback to
/// release.
fn install_finalizer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    pointer: *mut ProcessHandle,
) {
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut ProcessHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `install` and this
            // finalizer runs exactly once.
            let handle = unsafe { &mut *pointer };
            if handle.spawned && !handle.closed {
                // The child is still running, or its close is. libuv will call
                // back with this handle's `data`, so closing now would drop the
                // exit notification and free `data` while libuv still holds it.
                // The box is deliberately kept: the close callback releases it.
                handle.owner_object = None;
                handle.weak = None;
                return;
            }
            // SAFETY: no libuv callback can reach this handle any more.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );

    // The `Weak` has to outlive the registration or the finalizer is cancelled,
    // so it is parked in the allocation it finalizes.
    // SAFETY: `pointer` was just created and is not aliased yet.
    unsafe {
        (*pointer).weak = Some(weak);
    }
}

/// `ProcessWrap::OnExit`: `handle.onexit(exit_status, term_signal)`.
///
/// `lib/internal/child_process.js`'s handler reads both: a non-zero signal
/// becomes `signalCode`, otherwise `exitCode`. The signal is reported as a *name*
/// (`'SIGTERM'`) rather than a number, which is what `signo_string` produces and
/// what `child.signalCode` shows.
///
/// # Safety
///
/// Called by libuv with a handle this crate spawned.
pub unsafe extern "C" fn after_exit(
    handle_pointer: *mut uv::uv_process_t,
    exit_status: i64,
    term_signal: i32,
) {
    // SAFETY: the handle libuv passes is the one `uv_spawn` initialised, and its
    // `data` is the owning `ProcessHandle`.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    let pointer = data.cast::<ProcessHandle>();
    // SAFETY: the pointer came from `Box::into_raw` and neither the finalizer nor
    // `after_close` frees it while the child is still running.
    let handle = unsafe { &mut *pointer };

    // The child has been reaped, so the handle no longer needs libuv's process
    // queue. Node closes it from the JavaScript side, but a wrapper that was
    // collected never can, so the close is started here when nothing will.
    if handle.owner_object.is_none() && !handle.closing {
        handle.closing = true;
        // SAFETY: the handle is live and not closing.
        unsafe {
            uv::uv_close(
                crate::as_handle(handle_pointer),
                Some(crate::methods::after_close),
            )
        };
        return;
    }
    if handle.owner_object.is_none() {
        return;
    }

    let signal = term_signal_name(term_signal);
    rn_uv::callback::with_context(|scope| {
        let Some(object) = handle
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        let Some(key) = v8::String::new(scope, "onexit") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        let status_value: v8::Local<v8::Value> = v8::Number::new(scope, exit_status as f64).into();
        // `OneByteString(env->isolate(), signo_string(term_signal))`, which is the
        // empty string for a process that exited normally.
        let signal_value: v8::Local<v8::Value> = v8::String::new(scope, signal)
            .map(Into::into)
            .unwrap_or_else(|| v8::undefined(scope).into());
        let receiver: v8::Local<v8::Value> = object.into();
        // A throw from `'exit'` is uncaught: the process handle completed inside
        // `uv_run`, where nothing above it can handle one. `MakeCallback` catches
        // it and routes it through `TriggerUncaughtException`; ignoring the
        // result prints the error and still exits 0.
        let caught = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
            let inner = &mut try_catch.init();
            let _ = callback.call(inner, receiver, &[status_value, signal_value]);
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception))
        };
        if let Some(caught) = caught {
            let exception = v8::Local::new(&*scope, &caught);
            rn_errors::report_uncaught_exception(scope, exception);
        }
    });
}

/// `signo_string`'s answer for a terminating signal.
///
/// Node reports the signal's *name*, and an empty string for a normal exit, which
/// `lib/internal/child_process.js` treats as falsy and so stores `exitCode`
/// instead of `signalCode`.
fn term_signal_name(signal: i32) -> &'static str {
    signal_name(signal).unwrap_or("")
}

/// The `SIG*` name of a signal number, or `None` for "no signal".
#[cfg(unix)]
fn signal_name(signal: i32) -> Option<&'static str> {
    // The names libuv's `signo_string` reports, which are Node's own spellings.
    let name = match signal {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGURG => "SIGURG",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGVTALRM => "SIGVTALRM",
        libc::SIGPROF => "SIGPROF",
        libc::SIGWINCH => "SIGWINCH",
        libc::SIGIO => "SIGIO",
        libc::SIGSYS => "SIGSYS",
        _ => return None,
    };
    Some(name)
}

/// The `SIG*` name of a signal number.
#[cfg(windows)]
fn signal_name(signal: i32) -> Option<&'static str> {
    // Windows has no signals; libuv synthesises a termination status and Node
    // reports no name for it.
    let _ = signal;
    None
}
