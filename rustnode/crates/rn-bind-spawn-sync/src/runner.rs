//! `SyncProcessRunner`: the blocking spawn behind `spawn_sync.spawn(options)`.
//!
//! This is `src/spawn_sync.cc` transcribed. The shape that matters:
//!
//! 1. Create a **private** `uv_loop_t`. Sharing the process' loop would run every
//!    queued timer and socket callback while `spawnSync` blocks.
//! 2. Build a `uv_process_options_t` from `options`, one `uv_pipe_t` per stdio
//!    that is a pipe.
//! 3. `uv_spawn`, start the pipes and the timeout timer, then `uv_run` that loop
//!    until it has nothing left.
//! 4. Close every handle, close the loop, and build `{ status, signal, output,
//!    pid }` from what the callbacks recorded.
//!
//! # Why the pipe writes its input before it reads
//!
//! `SyncProcessStdioPipe::Start` writes `input_buffer_` and then shuts the write
//! side down *before* it starts reading. A child that echoes its input would
//! otherwise fill the pipe while this side is still writing, and both ends would
//! wait for each other. `lib/internal/child_process.js` passes the `input` option
//! straight through, so the ordering is observable.

use std::ffi::{c_char, c_void, CString};
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

/// One 64 KiB chunk of a child's output, matching `SyncProcessOutputBuffer`.
const CHUNK_SIZE: usize = 64 * 1024;

/// `SIGTERM`, the default `killSignal`.
const SIGTERM: i32 = 15;

/// Output accumulated from one pipe.
///
/// A `Vec` of fixed-size chunks rather than one growing `Vec<u8>`: the child
/// writes through libuv into a stable allocation, and appending to one `Vec` while
/// libuv holds a pointer into it would invalidate that pointer mid-read.
struct Output {
    chunks: Vec<Box<[u8; CHUNK_SIZE]>>,
    /// Bytes used in the last chunk.
    used: usize,
}

impl Output {
    fn new() -> Self {
        Self {
            chunks: Vec::new(),
            used: CHUNK_SIZE,
        }
    }

    /// The writable region for the next read, or `None` when the current chunk is
    /// full and a new one is needed.
    fn tail(&mut self) -> &mut [u8] {
        if self.chunks.is_empty() || self.used == CHUNK_SIZE {
            self.chunks.push(Box::new([0u8; CHUNK_SIZE]));
            self.used = 0;
        }
        let last = self.chunks.len() - 1;
        &mut self.chunks[last][self.used..]
    }

    /// Records `count` bytes written into the region [`Output::tail`] handed out.
    fn advance(&mut self, count: usize) {
        self.used = (self.used + count).min(CHUNK_SIZE);
        // A chunk that filled up is complete; the next `tail` starts a new one.
        if self.used == CHUNK_SIZE {
            self.chunks.push(Box::new([0u8; CHUNK_SIZE]));
            self.used = 0;
            // The extra empty chunk is dropped by `len`/`copy_to`, which only
            // count filled chunks.
            self.used = 0;
        }
    }

    /// Total bytes collected.
    fn len(&self) -> usize {
        let filled = self.chunks.len();
        match filled {
            0 => 0,
            _ => (filled - 1) * CHUNK_SIZE + self.used,
        }
    }

    /// Copies the collected bytes into `destination`.
    fn copy_to(&self, destination: &mut [u8]) {
        let mut offset = 0;
        for (index, chunk) in self.chunks.iter().enumerate() {
            let take = if index + 1 == self.chunks.len() {
                self.used
            } else {
                CHUNK_SIZE
            };
            if take == 0 {
                continue;
            }
            destination[offset..offset + take].copy_from_slice(&chunk[..take]);
            offset += take;
        }
    }
}

/// One stdio descriptor the child inherits as a pipe.
struct StdioPipe {
    /// libuv's `uv_pipe_t`, only meaningful while the loop is alive.
    pipe: Box<uv::uv_pipe_t>,
    /// Whether this end of the pipe is read from the child.
    readable: bool,
    /// Whether this end is written to the child.
    writable: bool,
    /// The `input` option's bytes, written before the pipe shuts down.
    input: Vec<u8>,
    /// Bytes the child produced.
    output: Output,
    /// libuv's status for this pipe, or 0.
    error: i32,
    /// The runner this pipe belongs to, so a read can report to its `maxBuffer`
    /// accounting as it happens.
    ///
    /// `src/spawn_sync.cc` keeps the back-pointer (`process_handler_`) for exactly
    /// this: a child that prints without bound has to be killed while it is still
    /// running, not after it exits.
    runner: *mut Runner,
    /// The pipe's lifecycle, mirroring `SyncProcessStdioPipe::Lifecycle`.
    state: PipeState,
    /// Whether `uv_pipe_init` actually initialised the handle.
    ///
    /// `PipeState::Initialized` is the *pre-init* state, which is the state a
    /// pipe is left in when `uv_pipe_init` fails. libuv cannot close a handle
    /// it never initialised — `uv_close` dispatches on `handle->type`, which is
    /// still zero — so closing has to be decided by this flag rather than by the
    /// lifecycle alone.
    initialised: bool,
    /// The write request issued for `input`.
    write_request: Box<std::mem::MaybeUninit<uv::uv_write_t>>,
    /// The shutdown request issued after the input.
    shutdown_request: Box<std::mem::MaybeUninit<uv::uv_shutdown_t>>,
}

/// `SyncProcessStdioPipe::Lifecycle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipeState {
    Initialized,
    Started,
    Closing,
    Closed,
}

impl StdioPipe {
    fn new(readable: bool, writable: bool, input: Vec<u8>) -> Self {
        Self {
            pipe: Box::new(unsafe {
                // SAFETY: `uv_pipe_t` is plain C data, and `uv_pipe_init` fills it
                // before it is used.
                std::mem::zeroed()
            }),
            readable,
            writable,
            input,
            output: Output::new(),
            error: 0,
            runner: std::ptr::null_mut(),
            state: PipeState::Initialized,
            initialised: false,
            write_request: Box::new(std::mem::MaybeUninit::zeroed()),
            shutdown_request: Box::new(std::mem::MaybeUninit::zeroed()),
        }
    }

    fn raw(&mut self) -> *mut uv::uv_pipe_t {
        &mut *self.pipe as *mut uv::uv_pipe_t
    }

    fn stream(&mut self) -> *mut uv::uv_stream_t {
        self.raw().cast()
    }
}

/// The runner's phase, mirroring `SyncProcessRunner::Lifecycle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Uninitialized,
    Initialized,
    HandlesClosed,
}

/// Everything a synchronous spawn owns for its lifetime.
struct Runner {
    /// The private loop, valid from `run` until `close_handles`.
    loop_pointer: *mut uv::uv_loop_t,
    /// libuv's process handle; only spawned into when the options parsed.
    ///
    /// `uv_spawn` initialises this in place, and it registers the handle on the
    /// loop even when the child never starts: the `exec()` failure path returns
    /// before `uv__handle_start` but after `uv__handle_init`, so the handle is
    /// still in `loop->handle_queue` and its loop-level `child_watcher` has
    /// already been started. Both have to be closed before the loop can be
    /// released; see [`Runner::close_handles`].
    process: Box<std::mem::MaybeUninit<uv::uv_process_t>>,
    /// Whether `uv_spawn` returned success, so the child really ran.
    spawned: bool,
    /// Whether `uv_spawn` registered the handle on the loop at all.
    ///
    /// True whenever `uv_spawn` was reached, including the `exec()` failure
    /// case where `spawned` stays false. The distinction is what lets
    /// `close_handles` tell "never touched libuv" (nothing to close) apart from
    /// "libuv knows about this handle but there is no child" (must close).
    process_registered: bool,
    /// Whether `uv_close` has been called on the process handle.
    process_closing: bool,
    /// Whether `close_handles` actually released the private loop.
    ///
    /// False when libuv refused to close it, which only happens if a handle was
    /// left unclosed. Recorded so a test can assert the loop was released rather
    /// than inferring it from the absence of a crash.
    loop_released: bool,
    /// The pipes, one entry per stdio descriptor (null for ignore/inherit).
    stdio: Vec<Option<Box<StdioPipe>>>,
    /// The `killSignal`, used by the timeout.
    kill_signal: i32,
    /// The `maxBuffer` limit; 0 means unlimited.
    max_buffer: usize,
    /// Total bytes buffered so far.
    buffered: usize,
    /// libuv's status for the run, or 0.
    error: i32,
    /// libuv's status from a pipe, or 0.
    pipe_error: i32,
    /// The child's exit status, or -1 when it never ran.
    exit_status: i64,
    /// The signal that terminated the child, or -1.
    term_signal: i32,
    /// Whether `kill` has run.
    killed: bool,
    /// The timeout timer, when `options.timeout` was set.
    timer: Option<Box<uv::uv_timer_t>>,
    /// The run's phase.
    lifecycle: Lifecycle,
}

/// What `spawn` returns.
struct Outcome {
    /// libuv's status, when not zero.
    error: i32,
    /// The child's exit status, or -1.
    status: i64,
    /// The terminating signal, or -1.
    signal: i32,
    /// The child's pid.
    pid: i32,
    /// One entry per stdio: the collected bytes, or `None` when not a pipe this
    /// side reads.
    output: Vec<Option<Vec<u8>>>,
}

/// `SyncProcessRunner::Spawn`.
pub fn spawn(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(options) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        crate::throw_type_error(scope, "options must be an object");
        return;
    };

    let outcome = match run(scope, options) {
        Some(outcome) => outcome,
        // The option parsing already threw.
        None => return,
    };

    let result = v8::Object::new(scope);
    if outcome.error != 0 {
        if let Some(key) = v8::String::new(scope, "error") {
            result.set(
                scope,
                key.into(),
                v8::Integer::new(scope, outcome.error).into(),
            );
        }
    }
    // `status`: the exit code, `null` when a signal terminated the child, and
    // `null` when the process never started.
    let status: v8::Local<v8::Value> = if outcome.status >= 0 && outcome.signal <= 0 {
        v8::Number::new(scope, outcome.status as f64).into()
    } else {
        v8::null(scope).into()
    };
    if let Some(key) = v8::String::new(scope, "status") {
        result.set(scope, key.into(), status);
    }
    // `signal`: the signal's name, or `null`.
    let signal: v8::Local<v8::Value> = match signal_name(outcome.signal) {
        Some(name) => v8::String::new(scope, name)
            .map(Into::into)
            .unwrap_or_else(|| v8::null(scope).into()),
        None => v8::null(scope).into(),
    };
    if let Some(key) = v8::String::new(scope, "signal") {
        result.set(scope, key.into(), signal);
    }
    // `output`: one entry per stdio, `null` where this side does not read.
    if outcome.status >= 0 {
        let output = v8::Array::new(scope, outcome.output.len() as i32);
        for (index, entry) in outcome.output.iter().enumerate() {
            let value: v8::Local<v8::Value> = match entry {
                Some(bytes) => match buffer_from(scope, bytes) {
                    Some(value) => value,
                    None => v8::null(scope).into(),
                },
                None => v8::null(scope).into(),
            };
            output.set_index(scope, index as u32, value);
        }
        if let Some(key) = v8::String::new(scope, "output") {
            result.set(scope, key.into(), output.into());
        }
    } else if let Some(key) = v8::String::new(scope, "output") {
        result.set(scope, key.into(), v8::null(scope).into());
    }
    if let Some(key) = v8::String::new(scope, "pid") {
        result.set(
            scope,
            key.into(),
            v8::Number::new(scope, f64::from(outcome.pid)).into(),
        );
    }
    rv.set(result.into());
}

/// Builds a `Buffer` over `bytes`.
///
/// `lib/child_process.js` reads `result.output` and hands each entry to
/// `Buffer.concat` or straight to the caller, so it has to be a real `Buffer`
/// (`Buffer.isBuffer` true) rather than a `Uint8Array`.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, bytes.len())?;
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
    let prototype = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// The `SIG*` name of a signal number, or `None` for "no signal".
#[cfg(unix)]
fn signal_name(signal: i32) -> Option<&'static str> {
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
    let _ = signal;
    None
}

/// Reads `options` into a `Runner` and executes it.
///
/// Returns `None` when the options named something Node would throw for; the
/// exception is already pending in that case.
fn run(scope: &mut v8::PinScope<'_, '_>, options: v8::Local<v8::Object>) -> Option<Outcome> {
    let file = crate::property(scope, options, "file")
        .and_then(|value| v8::Local::<v8::String>::try_from(value).ok())
        .or_else(|| {
            crate::throw_type_error(scope, "options.file must be a string");
            None
        })?;
    let file = file.to_rust_string_lossy(scope);
    let Ok(file) = CString::new(file) else {
        crate::throw_type_error(scope, "options.file must not contain a NUL byte");
        return None;
    };

    let mut argv = Vec::new();
    let has_argv = crate::property(scope, options, "args").is_some_and(|value| value.is_array());
    if has_argv {
        let value = crate::property(scope, options, "args")?;
        let array = v8::Local::<v8::Array>::try_from(value).ok()?;
        for index in 0..array.length() {
            let entry = array.get_index(scope, index)?;
            let text = entry.to_string(scope)?;
            let text = text.to_rust_string_lossy(scope);
            let Ok(text) = CString::new(text) else {
                crate::throw_type_error(scope, "options.args must not contain a NUL byte");
                return None;
            };
            argv.push(text);
        }
    }
    let mut arg_pointers: Vec<*mut c_char> = argv
        .iter()
        .map(|argument| argument.as_ptr() as *mut c_char)
        .collect();
    arg_pointers.push(ptr::null_mut());

    // `options.cwd`: absent means "inherit this process' directory".
    let cwd = match crate::property(scope, options, "cwd") {
        Some(value) if !value.is_null() && !value.is_undefined() => {
            let text = value.to_string(scope)?;
            let text = text.to_rust_string_lossy(scope);
            let Ok(cwd) = CString::new(text) else {
                crate::throw_type_error(scope, "options.cwd must not contain a NUL byte");
                return None;
            };
            Some(cwd)
        }
        _ => None,
    };

    // `options.envPairs`: absent means "inherit this process' environment".
    let mut env = Vec::new();
    let has_env = crate::property(scope, options, "envPairs").is_some_and(|value| value.is_array());
    if has_env {
        let value = crate::property(scope, options, "envPairs")?;
        let array = v8::Local::<v8::Array>::try_from(value).ok()?;
        for index in 0..array.length() {
            let entry = array.get_index(scope, index)?;
            let text = entry.to_string(scope)?;
            let text = text.to_rust_string_lossy(scope);
            let Ok(text) = CString::new(text) else {
                crate::throw_type_error(scope, "options.envPairs must not contain a NUL byte");
                return None;
            };
            env.push(text);
        }
    }
    let mut env_pointers: Vec<*mut c_char> = env
        .iter()
        .map(|pair| pair.as_ptr() as *mut c_char)
        .collect();
    if !env_pointers.is_empty() {
        env_pointers.push(ptr::null_mut());
    }

    // The optional numeric and boolean options.
    let mut libuv_flags = 0u32;
    let uid = int32_option(scope, options, "uid")?;
    let gid = int32_option(scope, options, "gid")?;
    if uid.is_some() {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_SETUID;
    }
    if gid.is_some() {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_SETGID;
    }
    if bool_option(scope, options, "detached") {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_DETACHED;
    }
    if bool_option(scope, options, "windowsHide") {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_WINDOWS_HIDE;
    }
    if bool_option(scope, options, "windowsVerbatimArguments") {
        libuv_flags |= uv::uv_process_flags_UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS;
    }
    let kill_signal = int32_option(scope, options, "killSignal")?.unwrap_or(SIGTERM);
    let max_buffer = number_option(scope, options, "maxBuffer")?.unwrap_or(0.0) as usize;
    let timeout = number_option(scope, options, "timeout")?
        .unwrap_or(0.0)
        .max(0.0) as u64;

    // The stdio array, which decides both the libuv containers and the pipes.
    let stdio_array = crate::property(scope, options, "stdio")
        .and_then(|value| v8::Local::<v8::Array>::try_from(value).ok())
        .or_else(|| {
            crate::throw_type_error(scope, "options.stdio must be an array");
            None
        })?;
    let mut containers = Vec::with_capacity(stdio_array.length() as usize);
    let mut pipes: Vec<Option<Box<StdioPipe>>> = Vec::with_capacity(stdio_array.length() as usize);
    for index in 0..stdio_array.length() {
        let entry = stdio_array.get_index(scope, index)?;
        let entry = v8::Local::<v8::Object>::try_from(entry).ok().or_else(|| {
            crate::throw_type_error(scope, "options.stdio must be an array of objects");
            None
        })?;
        let kind = crate::property(scope, entry, "type")
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_default();

        let mut container = uv::uv_stdio_container_t {
            flags: uv::uv_stdio_flags_UV_IGNORE,
            // SAFETY: the `stdio` union's variants are a pointer and an `int`,
            // both plain data; this writes the pointer variant.
            data: unsafe { std::mem::zeroed() },
        };
        match kind.as_str() {
            "ignore" => {}
            "pipe" => {
                let readable = bool_option(scope, entry, "readable");
                let writable = bool_option(scope, entry, "writable");
                if !readable && !writable {
                    crate::throw_type_error(
                        scope,
                        "options.stdio pipe must be readable or writable",
                    );
                    return None;
                }
                // `input` has to be a buffer: Node rejects anything else because it
                // cannot free a converted string afterwards.
                let mut input = Vec::new();
                if readable {
                    if let Some(value) = crate::property(scope, entry, "input") {
                        if !value.is_null() && !value.is_undefined() {
                            // SAFETY: `lib/internal/child_process.js` keeps the
                            // buffer alive for the call.
                            input = unsafe { view_bytes(value) }.or_else(|| {
                                crate::throw_type_error(
                                    scope,
                                    "options.stdio input must be a Buffer",
                                );
                                None
                            })?;
                        }
                    }
                }
                let mut flags = uv::uv_stdio_flags_UV_CREATE_PIPE;
                if readable {
                    flags |= uv::uv_stdio_flags_UV_READABLE_PIPE;
                }
                if writable {
                    flags |= uv::uv_stdio_flags_UV_WRITABLE_PIPE;
                }
                container.flags = flags;
                pipes.push(Some(Box::new(StdioPipe::new(readable, writable, input))));
                containers.push(container);
                continue;
            }
            "inherit" | "fd" => {
                let fd = crate::property(scope, entry, "fd")
                    .and_then(|value| value.int32_value(scope))
                    .unwrap_or(-1);
                container.flags = uv::uv_stdio_flags_UV_INHERIT_FD;
                container.data.fd = fd;
            }
            other => {
                crate::throw_type_error(scope, &format!("invalid child stdio type: {other}"));
                return None;
            }
        }
        pipes.push(None);
        containers.push(container);
    }

    let mut runner = Runner {
        loop_pointer: ptr::null_mut(),
        process: Box::new(std::mem::MaybeUninit::zeroed()),
        spawned: false,
        process_registered: false,
        process_closing: false,
        loop_released: false,
        stdio: pipes,
        kill_signal,
        max_buffer,
        buffered: 0,
        error: 0,
        pipe_error: 0,
        exit_status: -1,
        term_signal: -1,
        killed: false,
        timer: None,
        lifecycle: Lifecycle::Uninitialized,
    };

    let mut native = uv::uv_process_options_t {
        exit_cb: Some(exit_callback),
        file: file.as_ptr(),
        args: if has_argv {
            arg_pointers.as_mut_ptr()
        } else {
            ptr::null_mut()
        },
        env: if has_env && !env_pointers.is_empty() {
            env_pointers.as_mut_ptr()
        } else {
            ptr::null_mut()
        },
        cwd: cwd.as_ref().map_or(ptr::null(), |cwd| cwd.as_ptr()),
        flags: libuv_flags,
        stdio_count: containers.len() as i32,
        stdio: containers.as_mut_ptr(),
        uid: uid.unwrap_or(0) as uv::uv_uid_t,
        gid: gid.unwrap_or(0) as uv::uv_gid_t,
    };

    let outcome = runner.execute(&mut native, timeout);
    // `argv`, `env`, `cwd` and `containers` are still borrowed by `native`, so
    // they stay alive until here — which is past the run.
    drop((argv, env, cwd, containers, arg_pointers, env_pointers));
    Some(outcome)
}

impl Runner {
    /// A runner with nothing but the option-independent defaults set.
    ///
    /// Test-only: production code builds this through [`run`] from JavaScript
    /// options. This exists so the native close path can be tested without an
    /// isolate.
    #[cfg(test)]
    fn test_runner(stdio: Vec<Option<Box<StdioPipe>>>) -> Self {
        Self {
            loop_pointer: ptr::null_mut(),
            process: Box::new(std::mem::MaybeUninit::zeroed()),
            spawned: false,
            process_registered: false,
            process_closing: false,
            loop_released: false,
            stdio,
            kill_signal: SIGTERM,
            max_buffer: 0,
            buffered: 0,
            error: 0,
            pipe_error: 0,
            exit_status: -1,
            term_signal: -1,
            killed: false,
            timer: None,
            lifecycle: Lifecycle::Uninitialized,
        }
    }

    /// `SyncProcessRunner::TryInitializeAndRunLoop` plus the close/collect tail.
    fn execute(&mut self, native: &mut uv::uv_process_options_t, timeout: u64) -> Outcome {
        let loop_pointer = Box::into_raw(Box::new(unsafe {
            // SAFETY: `uv_loop_t` is plain C data, and `uv_loop_init` fills it.
            std::mem::zeroed::<uv::uv_loop_t>()
        }));
        // SAFETY: `loop_pointer` is a live, zeroed `uv_loop_t`.
        let status = unsafe { uv::uv_loop_init(loop_pointer) };
        if status != 0 {
            // SAFETY: `uv_loop_init` failed, so the loop was never registered.
            drop(unsafe { Box::from_raw(loop_pointer) });
            self.error = status;
            return Outcome {
                error: status,
                status: -1,
                signal: -1,
                pid: 0,
                output: Vec::new(),
            };
        }
        self.loop_pointer = loop_pointer;
        self.lifecycle = Lifecycle::Initialized;
        // The pipes report their reads to this runner, which is what enforces
        // `maxBuffer` while the child is still running.
        let runner = std::ptr::from_mut(self);
        for pipe in self.stdio.iter_mut().flatten() {
            pipe.runner = runner;
        }

        // Every pipe is initialised on the private loop before the spawn, because
        // `uv_spawn` needs the stream pointers in its stdio containers.
        for pipe in self.stdio.iter_mut().flatten() {
            pipe.pipe.data = ptr::from_mut(&mut **pipe).cast::<c_void>();
            // SAFETY: the loop is live and the pipe storage is a live, zeroed
            // `uv_pipe_t`.
            let status = unsafe { uv::uv_pipe_init(loop_pointer, pipe.raw(), 0) };
            if status != 0 {
                self.set_error(status);
                break;
            }
            pipe.initialised = true;
        }
        // The containers hold raw stream pointers, so they are filled directly
        // rather than through a helper that would need `self` borrowed twice.
        if !native.stdio.is_null() {
            for index in 0..native.stdio_count.max(0) as usize {
                let Some(Some(pipe)) = self.stdio.get_mut(index) else {
                    continue;
                };
                // SAFETY: `native.stdio` points at `stdio_count` live containers,
                // which `run` keeps alive for the call.
                let container = unsafe { &mut *native.stdio.add(index) };
                container.data.stream = pipe.stream();
            }
        }

        // `options.timeout` arms a timer on the private loop; it is unref'd so it
        // cannot keep the loop alive on its own.
        if timeout > 0 {
            let mut timer = Box::new(unsafe {
                // SAFETY: `uv_timer_t` is plain C data.
                std::mem::zeroed::<uv::uv_timer_t>()
            });
            // SAFETY: the loop is live and the timer storage is a live, zeroed
            // `uv_timer_t`.
            let status = unsafe { uv::uv_timer_init(loop_pointer, &mut *timer) };
            if status == 0 {
                timer.data = ptr::from_mut(self).cast::<c_void>();
                // SAFETY: the timer is live.
                unsafe {
                    let raw = (&mut *timer as *mut uv::uv_timer_t).cast::<uv::uv_handle_t>();
                    uv::uv_unref(raw);
                    uv::uv_timer_start(&mut *timer, Some(kill_timer_callback), timeout, 0);
                }
                self.timer = Some(timer);
            } else {
                self.set_error(status);
            }
        }

        if self.error == 0 {
            // SAFETY: the loop is live, the handle storage is a zeroed
            // `uv_process_t`, and `native` points at live option data.
            let status = unsafe { uv::uv_spawn(loop_pointer, self.process.as_mut_ptr(), native) };
            // `uv_spawn` calls `uv__handle_init` before it does anything that can
            // fail, so the handle is on the loop's `handle_queue` from this point
            // on whether or not the child started. A failed `exec()` is the case
            // that matters: the call returns `UV_ENOENT` (or similar) after
            // registering the handle *and* starting the loop's internal
            // `child_watcher` for `SIGCHLD`, which `uv__process_close` is what
            // stops. Leaving both behind is what makes `uv_loop_close` refuse the
            // loop, and a refused loop that is freed anyway leaves a dangling
            // node in libuv's process-global signal tree for the next
            // `uv_signal_start` to walk.
            self.process_registered = true;
            if status != 0 {
                self.set_error(status);
            } else {
                self.spawned = true;
                // SAFETY: `uv_spawn` succeeded, so the handle is initialised.
                if let Some(raw) = unsafe { self.process.as_mut_ptr().as_mut() } {
                    raw.data = ptr::from_mut(self).cast();
                }
                for pipe in self.stdio.iter_mut().flatten() {
                    if let Err(status) = start_pipe(pipe) {
                        if self.pipe_error == 0 {
                            self.pipe_error = status;
                        }
                    }
                }
            }
        }

        if self.spawned {
            // SAFETY: the loop is live and nothing else is running on it.
            unsafe { uv::uv_run(loop_pointer, uv::uv_run_mode_UV_RUN_DEFAULT) };
        }

        self.close_handles();

        let output = self
            .stdio
            .iter_mut()
            .map(|pipe| match pipe {
                Some(pipe) if pipe.writable => {
                    let length = pipe.output.len();
                    let mut bytes = vec![0u8; length];
                    pipe.output.copy_to(&mut bytes);
                    Some(bytes)
                }
                _ => None,
            })
            .collect();

        Outcome {
            error: self.get_error(),
            status: self.exit_status,
            signal: self.term_signal,
            // `uv_process_t::pid` is the child's pid, retained after the handle is
            // closed, and 0 when the spawn never ran.
            pid: if self.spawned {
                // SAFETY: `spawned` is only set after `uv_spawn` returned success,
                // which is what initialises the storage.
                unsafe { self.process.as_ptr().as_ref() }.map_or(0, |process| process.pid)
            } else {
                0
            },
            output,
        }
    }

    /// `SyncProcessRunner::CloseHandlesAndDeleteLoop`.
    fn close_handles(&mut self) {
        if self.lifecycle != Lifecycle::Initialized || self.loop_pointer.is_null() {
            self.lifecycle = Lifecycle::HandlesClosed;
            return;
        }

        for pipe in self.stdio.iter_mut().flatten() {
            if pipe.initialised && matches!(pipe.state, PipeState::Initialized | PipeState::Started)
            {
                pipe.state = PipeState::Closing;
                // SAFETY: `uv_pipe_init` succeeded and the pipe is not closing.
                unsafe { uv::uv_close(pipe.stream().cast(), Some(pipe_close_callback)) };
            }
        }

        if let Some(timer) = self.timer.take() {
            // `CloseKillTimer` refs the timer before closing it so the close
            // callback is delivered even though the timer was unref'd.
            // SAFETY: the timer is live and not closing.
            unsafe {
                let raw = Box::into_raw(timer);
                let handle = raw.cast::<uv::uv_handle_t>();
                uv::uv_ref(handle);
                uv::uv_close(handle, Some(timer_close_callback));
            }
        }

        if self.process_registered && !self.process_closing {
            // `uv_spawn` registered this handle on the loop even when the child
            // never ran, so it must be closed either way. Closing a handle whose
            // `exec()` failed is also what stops the loop's internal
            // `child_watcher`, because `uv__process_close` sees the loop's
            // process queue empty and calls `uv_signal_stop` on it. Without that
            // the `SIGCHLD` watcher stays linked in libuv's process-global signal
            // tree, `uv_loop_close` answers `UV_EBUSY`, and the tree is left
            // holding a pointer into this loop's freed storage.
            self.process_closing = true;
            // SAFETY: `uv_spawn` was reached, so the handle is initialised.
            unsafe {
                let handle = self.process.as_mut_ptr().cast::<uv::uv_handle_t>();
                // Not every `uv_spawn` failure leaves the handle queued: the
                // stdio-open path calls `uv__queue_remove` itself, and closing a
                // handle that is no longer in `handle_queue` would corrupt the
                // loop's lists. `uv__handle_init` links the handle to itself when
                // it is not in a queue, so a self-linked `handle_queue` is the
                // test for "already detached".
                if is_still_queued(handle) {
                    uv::uv_close(handle, None);
                }
            }
        }

        // `CloseHandlesAndDeleteLoop` runs the loop again so every close callback
        // fires before the loop is released.
        // SAFETY: the loop is live and nothing else is running on it.
        unsafe { uv::uv_run(self.loop_pointer, uv::uv_run_mode_UV_RUN_DEFAULT) };
        // The loop cannot be released while any handle is still queued on it, and
        // `uv_loop_close` reports that as `UV_EBUSY` rather than releasing it. The
        // answer is checked rather than ignored: freeing a loop libuv refused to
        // close is precisely how a dangling signal-tree node outlives this call.
        // SAFETY: every handle on the loop has been closed and run to completion.
        let status = unsafe { uv::uv_loop_close(self.loop_pointer) };
        if status != 0 {
            // Nothing here can clean the loop up: a second close attempt would
            // make the same checks fail. The storage is deliberately leaked so
            // libuv's own bookkeeping stays consistent — a few hundred bytes once
            // per failed run is far cheaper than a use-after-free in a
            // process-global structure, and the alternative is a crash in an
            // unrelated part of the process later.
            tracing::error!(
                status,
                "spawn_sync: uv_loop_close refused the private loop; leaking it"
            );
            self.loop_pointer = ptr::null_mut();
            self.lifecycle = Lifecycle::HandlesClosed;
            return;
        }
        // SAFETY: the loop is closed and nothing else refers to it.
        drop(unsafe { Box::from_raw(self.loop_pointer) });
        self.loop_pointer = ptr::null_mut();
        self.lifecycle = Lifecycle::HandlesClosed;
        self.loop_released = true;
    }

    fn set_error(&mut self, error: i32) {
        if self.error == 0 {
            self.error = error;
        }
    }

    fn get_error(&self) -> i32 {
        if self.error != 0 {
            self.error
        } else {
            self.pipe_error
        }
    }

    /// `SyncProcessRunner::IncrementBufferSizeAndCheckOverflow`.
    fn account_output(&mut self, length: usize) {
        self.buffered += length;
        if self.max_buffer > 0 && self.buffered > self.max_buffer {
            self.set_error(uv::uv_errno_t_UV_ENOBUFS);
            self.kill();
        }
    }

    /// `SyncProcessRunner::Kill`.
    fn kill(&mut self) {
        if self.killed {
            return;
        }
        self.killed = true;

        if self.exit_status < 0 && self.spawned {
            // SAFETY: `spawned` means `uv_spawn` succeeded, so the handle is
            // initialised and points at a live child.
            if let Some(process) = unsafe { self.process.as_mut_ptr().as_mut() } {
                let status = unsafe { uv::uv_process_kill(process, self.kill_signal) };
                if status < 0 && status != uv::uv_errno_t_UV_ESRCH {
                    self.set_error(status);
                    // SAFETY: as above. The result is deliberately ignored: there
                    // may be no privilege to signal the child.
                    unsafe { uv::uv_process_kill(process, libc::SIGKILL) };
                }
            }
        }
        // Closing the pipes is what lets the loop finish when the child spawned a
        // grandchild that inherited them.
        for pipe in self.stdio.iter_mut().flatten() {
            if pipe.initialised && matches!(pipe.state, PipeState::Initialized | PipeState::Started)
            {
                pipe.state = PipeState::Closing;
                // SAFETY: `uv_pipe_init` succeeded and the pipe is not closing.
                unsafe { uv::uv_close(pipe.stream().cast(), Some(pipe_close_callback)) };
            }
        }
    }
}

/// `SyncProcessStdioPipe::Start`.
fn start_pipe(pipe: &mut StdioPipe) -> Result<(), i32> {
    pipe.state = PipeState::Started;
    if pipe.readable && !pipe.input.is_empty() {
        let base = pipe.input.as_mut_ptr();
        let length = pipe.input.len();
        let buffer = uv::uv_buf_t {
            base: base.cast(),
            len: length,
        };
        let request = pipe.write_request.as_mut_ptr();
        // SAFETY: the pipe is live, the input buffer outlives the write because
        // it is owned by the pipe, and the request storage is live.
        let status =
            unsafe { uv::uv_write(request, pipe.stream(), &buffer, 1, Some(write_callback)) };
        if status < 0 {
            return Err(status);
        }
    }
    if pipe.readable {
        let request = pipe.shutdown_request.as_mut_ptr();
        // SAFETY: the pipe is live and the request storage is live.
        let status = unsafe { uv::uv_shutdown(request, pipe.stream(), Some(shutdown_callback)) };
        if status < 0 && status != uv::uv_errno_t_UV_ENOTCONN {
            return Err(status);
        }
    }
    if pipe.writable {
        // SAFETY: the pipe is live and both callbacks read the owner through
        // `pipe.data`.
        let status =
            unsafe { uv::uv_read_start(pipe.stream(), Some(alloc_callback), Some(read_callback)) };
        if status < 0 {
            return Err(status);
        }
    }
    Ok(())
}

/// The pipe behind a callback's handle.
///
/// # Safety
///
/// `handle` must be a pipe this crate initialised, whose `data` is its
/// `StdioPipe`.
unsafe fn pipe_of(handle: *mut uv::uv_stream_t) -> Option<&'static mut StdioPipe> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the handle is one of ours.
    let data = unsafe { (*handle).data };
    if data.is_null() {
        None
    } else {
        // SAFETY: `data` is the `StdioPipe` pointer `execute` stored.
        Some(unsafe { &mut *data.cast::<StdioPipe>() })
    }
}

/// libuv's pipe allocator.
///
/// # Safety
///
/// Called by libuv with a live pipe.
unsafe extern "C" fn alloc_callback(
    handle: *mut uv::uv_handle_t,
    _suggested_size: usize,
    buffer: *mut uv::uv_buf_t,
) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: the handle is the pipe libuv is reading from.
    let Some(pipe) = (unsafe { pipe_of(handle.cast()) }) else {
        // SAFETY: `buffer` is libuv's out-parameter; a zero length tells it the
        // allocation failed.
        unsafe {
            (*buffer).base = ptr::null_mut();
            (*buffer).len = 0;
        }
        return;
    };
    let tail = pipe.output.tail();
    // SAFETY: `buffer` is libuv's out-parameter and `tail` points into a chunk the
    // pipe owns.
    unsafe {
        (*buffer).base = tail.as_mut_ptr().cast();
        (*buffer).len = tail.len();
    }
}

/// libuv's pipe read completion.
///
/// # Safety
///
/// Called by libuv with a live pipe.
unsafe extern "C" fn read_callback(
    handle: *mut uv::uv_stream_t,
    nread: isize,
    _buffer: *const uv::uv_buf_t,
) {
    // SAFETY: the handle is the pipe libuv is reading from.
    let Some(pipe) = (unsafe { pipe_of(handle) }) else {
        return;
    };
    if nread < 0 {
        // `UV_EOF` is the normal end of a child's output; anything else is a real
        // error.
        if nread != uv::uv_errno_t_UV_EOF as isize && pipe.error == 0 {
            pipe.error = nread as i32;
        }
        // SAFETY: the pipe is live.
        unsafe { uv::uv_read_stop(handle) };
        return;
    }
    let count = nread as usize;
    pipe.output.advance(count);
    if !pipe.runner.is_null() {
        // SAFETY: the runner owns this pipe and outlives the whole run.
        let runner = unsafe { &mut *pipe.runner };
        runner.account_output(count);
    }
}

/// libuv's write completion for a pipe's `input`.
///
/// # Safety
///
/// Called by libuv with the `uv_write_t` [`start_pipe`] issued.
unsafe extern "C" fn write_callback(request: *mut uv::uv_write_t, status: i32) {
    if request.is_null() || status >= 0 {
        return;
    }
    // SAFETY: `uv_write_t` leads with `data`, which libuv copies from the stream.
    let Some(pipe) = (unsafe { pipe_of((*request).handle) }) else {
        return;
    };
    if pipe.error == 0 {
        pipe.error = status;
    }
}

/// libuv's shutdown completion for a pipe's `input`.
///
/// # Safety
///
/// Called by libuv with the `uv_shutdown_t` [`start_pipe`] issued.
unsafe extern "C" fn shutdown_callback(request: *mut uv::uv_shutdown_t, status: i32) {
    if request.is_null() || status >= 0 {
        return;
    }
    // SAFETY: the request is the one `start_pipe` issued for one of our pipes.
    let Some(pipe) = (unsafe { pipe_of((*request).handle) }) else {
        return;
    };
    if pipe.error == 0 {
        pipe.error = status;
    }
}

/// libuv's pipe close completion.
///
/// # Safety
///
/// Called by libuv with a pipe this crate initialised.
unsafe extern "C" fn pipe_close_callback(handle: *mut uv::uv_handle_t) {
    // SAFETY: the handle is one of ours.
    if let Some(pipe) = unsafe { pipe_of(handle.cast()) } {
        pipe.state = PipeState::Closed;
    }
}

/// libuv's timer close completion.
///
/// # Safety
///
/// Called by libuv with the timer [`Runner::close_handles`] closed.
unsafe extern "C" fn timer_close_callback(handle: *mut uv::uv_handle_t) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the handle is the `uv_timer_t` `close_handles` leaked from its box
    // specifically so this callback could free it.
    drop(unsafe { Box::from_raw(handle.cast::<uv::uv_timer_t>()) });
}

/// libuv's process exit completion.
///
/// # Safety
///
/// Called by libuv with the handle the spawn initialised.
unsafe extern "C" fn exit_callback(
    handle: *mut uv::uv_process_t,
    exit_status: i64,
    term_signal: i32,
) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `data` is the `Runner` pointer `execute` stored.
    let data = unsafe { (*handle).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the runner is alive for the whole run.
    let runner = unsafe { &mut *data.cast::<Runner>() };
    if exit_status < 0 {
        runner.set_error(exit_status as i32);
        return;
    }
    runner.exit_status = exit_status;
    runner.term_signal = term_signal;
}

/// `SyncProcessRunner::KillTimerCallback`.
///
/// # Safety
///
/// Called by libuv with the timer [`Runner::execute`] initialised.
unsafe extern "C" fn kill_timer_callback(timer: *mut uv::uv_timer_t) {
    if timer.is_null() {
        return;
    }
    // SAFETY: `data` is the `Runner` pointer `execute` stored.
    let data = unsafe { (*timer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the runner is alive for the whole run.
    let runner = unsafe { &mut *data.cast::<Runner>() };
    runner.set_error(uv::uv_errno_t_UV_ETIMEDOUT);
    runner.kill();
}

/// The bytes of an `ArrayBufferView`, as a copy.
///
/// # Safety
///
/// The view's backing store must stay alive until this returns, which it does
/// because `lib/internal/child_process.js` holds the caller's buffer.
pub unsafe fn view_bytes(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() {
        return if length == 0 { Some(Vec::new()) } else { None };
    }
    // SAFETY: the caller guarantees the view's bytes are live for this call.
    Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

/// Reads an optional `Int32` option, throwing when the type is wrong.
fn int32_option(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> Option<Option<i32>> {
    match crate::property(scope, object, name) {
        Some(value) if !value.is_null() && !value.is_undefined() => {
            if !value.is_int32() {
                crate::throw_type_error(
                    scope,
                    &format!("options.{name} must be a 32-bit signed integer"),
                );
                return None;
            }
            Some(value.int32_value(scope))
        }
        _ => Some(None),
    }
}

/// Reads an optional number option, throwing when the type is wrong.
fn number_option(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> Option<Option<f64>> {
    match crate::property(scope, object, name) {
        Some(value) if !value.is_null() && !value.is_undefined() => {
            if !value.is_number() {
                crate::throw_type_error(scope, &format!("options.{name} must be a number"));
                return None;
            }
            Some(value.number_value(scope))
        }
        _ => Some(None),
    }
}

/// Whether libuv's own `handle_queue` still links a handle into the loop.
///
/// `uv__handle_init` inserts the handle into `loop->handle_queue`. Two failure
/// paths in `uv_spawn` take it back out again (`uv__queue_remove`), which leaves
/// the node pointing at itself rather than at neighbours. Closing a handle in
/// that state would make `uv__queue_remove` write through the handle's own
/// address and corrupt the loop, so the queue linkage is checked first.
///
/// # Safety
///
/// `handle` must be a handle `uv_spawn` initialised, so its `handle_queue` is
/// readable and either self-linked or linked into a live loop.
unsafe fn is_still_queued(handle: *mut uv::uv_handle_t) -> bool {
    if handle.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees the handle is initialised.
    let node = unsafe { &(*handle).handle_queue };
    let address = std::ptr::from_ref(node);
    node.next != address.cast_mut() || node.prev != address.cast_mut()
}

/// Reads a boolean option, defaulting to false.
fn bool_option(scope: &v8::PinScope<'_, '_>, object: v8::Local<v8::Object>, name: &str) -> bool {
    let _ = scope;
    crate::property(scope, object, name).is_some_and(|value| {
        value.is_true() || {
            // `BooleanValue(isolate)` converts, so a truthy non-boolean counts too.
            !value.is_null() && !value.is_undefined() && !value.is_false()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed `exec()` still registers the process handle, so the private loop
    /// must be closable afterwards.
    ///
    /// This is the invariant the SIGSEGV came from: `uv_spawn` initialises the
    /// `uv_process_t` and starts the loop's `SIGCHLD` `child_watcher` before it
    /// tries `exec()`, and only `uv__process_close` undoes both. `uv_loop_close`
    /// reports a loop that still has such a handle as `UV_EBUSY`; freeing it
    /// anyway leaves a node in libuv's process-global signal tree that the next
    /// `uv_signal_start` walks and dereferences.
    ///
    /// The assertions are on [`Runner`]'s own bookkeeping, so they fail if
    /// `close_handles` stops closing a handle that `uv_spawn` registered — which
    /// is exactly the regression this pins.
    #[test]
    fn a_failed_spawn_leaves_the_private_loop_closable() {
        let missing = CString::new("/nonexistent/rustnode-test-binary").expect("no NUL here");
        let mut argv = vec![missing.as_ptr() as *mut c_char, ptr::null_mut()];
        let mut containers = vec![
            uv::uv_stdio_container_t {
                flags: uv::uv_stdio_flags_UV_IGNORE,
                // SAFETY: the union's variants are plain data.
                data: unsafe { std::mem::zeroed() },
            };
            3
        ];
        let mut native = uv::uv_process_options_t {
            exit_cb: Some(exit_callback),
            file: missing.as_ptr(),
            args: argv.as_mut_ptr(),
            env: ptr::null_mut(),
            cwd: ptr::null(),
            flags: 0,
            stdio_count: containers.len() as i32,
            stdio: containers.as_mut_ptr(),
            uid: 0,
            gid: 0,
        };

        let mut runner = Runner::test_runner(Vec::new());
        let outcome = runner.execute(&mut native, 0);

        assert_eq!(
            outcome.error,
            uv::uv_errno_t_UV_ENOENT,
            "a missing binary must report ENOENT"
        );
        assert!(
            runner.process_registered,
            "uv_spawn registers the handle even when exec() fails"
        );
        assert!(
            !runner.spawned,
            "there is no child, so the handle must not be treated as alive"
        );
        assert!(
            runner.process_closing,
            "the registered handle must be closed or libuv keeps its SIGCHLD watcher"
        );
        assert!(
            runner.loop_released,
            "the private loop must be released; a refused loop is leaked, not freed"
        );
    }
}
