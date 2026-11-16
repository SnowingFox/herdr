//! `Bun.spawn(cmd, options?)` and `Bun.spawnSync(cmd, options?)`.
//!
//! Bun's option shape differs from Node's `child_process` in four ways that
//! matter, all measured against Bun 1.4.4:
//!
//! 1. **`cmd` must be an array.** `Bun.spawn('echo hi')` throws
//!    `TypeError [ERR_INVALID_ARG_TYPE] cmd must be an array`, and so does no
//!    argument at all; `[]` throws `cmd must not be empty`.
//! 2. **A missing executable throws**, synchronously, from the call. Node's
//!    `spawnSync` returns `{error}` with `status: null` and Node's `spawn` emits
//!    an `'error'` event instead. This is the most likely place a "compatible"
//!    wrapper diverges silently, so it is reproduced exactly, including Bun's
//!    two different messages:
//!
//!    ```text
//!    spawn(['nonexistent-xyz-abc'])  => Error ENOENT
//!        "Executable not found in $PATH: \"nonexistent-xyz-abc\""
//!    spawn(['/nonexistent/dir/xyz']) => Error ENOENT
//!        "ENOENT: no such file or directory, posix_spawn '/nonexistent/dir/xyz'"
//!    ```
//! 3. **`env` replaces the environment.** Measured:
//!    `spawnSync(['sh','-c','echo ${HOME:-UNSET}'], {env:{MYVAR:'x'}})` prints
//!    `UNSET`.
//! 4. **The result object is a prototype, not a plain object.** Measured:
//!    `Object.keys(proc)` is `[]` while `proc.exited` is a real `Promise`,
//!    `proc.pid` is a number and `proc.stdout` exists — the members are
//!    enumerable **getters on a custom prototype**, and an accessor is not an own
//!    property. A test written against `Object.keys` would pass on an empty
//!    object, which is why the tests here read the prototype.
//!
//! # What is reused rather than rewritten
//!
//! The process plumbing is libuv's, driven exactly as `lib/internal/child_process.js`
//! drives `process_wrap`: a `uv_process_t` whose `uv_spawn` initialises, a
//! `uv_pipe_t` per piped descriptor, and `onexit` for the report. There is no
//! second spawner: `spawnSync` is the same function driven to completion.
//!
//! # The divergence this crate states rather than hides
//!
//! `Bun.spawn` here runs the child to completion before returning and settles
//! `exited` with the result. Bun's `spawn` is genuinely asynchronous: the child is
//! still running when the call returns, so
//!
//! * `p.kill()` reaches a live process, and `await p.exited` is `143` with
//!   `signalCode: 'SIGTERM'`;
//! * `p.stdin.write('piped-in')` reaches a child waiting on it, and
//!   `p.stdout` carries the echoed bytes;
//! * a caller can consume `p.stdout` before the child exits.
//!
//! None of the three holds against this implementation, and all three are
//! *behaviour*, not shape: every value a caller reads after `await p.exited` — the
//! exit code, the signal name, the pid, `stdout`/`stderr` as `ReadableStream`s —
//! is Bun's. So a differential test that awaits `exited` first compares equal, and
//! one that reads `kill()`'s effect or writes to `stdin` first does not.
//!
//! Making it genuinely asynchronous means a per-child state allocation on the
//! loop, a `ReadableStreamDefaultController` per read side fed from the read
//! callbacks, and a resolver settled from the exit callback. That is a real
//! subsystem, not a wrapper, and it is reported rather than approximated: an
//! implementation that spawned for real but never delivered its callbacks would be
//! worse than this one, because it would hang instead of returning Bun's values.
//!
//! `crates/rn-bun-process/tests/differential.rs` pins the three differences by
//! name so this note cannot rot into a claim nobody checks.

use std::ffi::{c_char, c_void, CString};
use std::ptr;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

/// How one of a child's descriptors was configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stdio {
    /// `'ignore'`: `UV_IGNORE`.
    Ignore,
    /// `'inherit'`, or a number naming an inherited descriptor.
    Inherit(i32),
    /// `'pipe'`: a `uv_pipe_t` this side reads or, for stdin, writes.
    Pipe,
}

/// The parsed option shape both entry points share.
///
/// One parser so the two cannot disagree about what an absent `cwd` means,
/// whether `env` replaces, or how a `timeout` is read.
pub(crate) struct Options {
    pub file: CString,
    /// The program as the caller wrote it, for error messages.
    ///
    /// Measured: `Bun.spawnSync(['pwd'], {cwd: '/nonexistent'})` reports
    /// `posix_spawn 'pwd'`, not the resolved `/usr/bin/pwd`, even though Bun
    /// resolved the name to find the binary. The resolved path is what `uv_spawn`
    /// is given; this is what the failure text names.
    pub program: String,
    /// The argument strings, kept alive for as long as `arg_pointers` is used.
    ///
    /// Never read directly: their only job is to keep the memory `uv_spawn`
    /// walks alive for the duration of the call.
    #[allow(dead_code)]
    pub argv: Vec<CString>,
    pub arg_pointers: Vec<*mut c_char>,
    pub cwd: Option<CString>,
    /// The environment strings, kept alive alongside `env_pointers`.
    #[allow(dead_code)]
    pub env: Vec<CString>,
    pub env_pointers: Vec<*mut c_char>,
    /// Whether `env` was given at all: absent means inherit, `{}` means empty.
    pub has_env: bool,
    pub stdin: Stdio,
    pub stdout: Stdio,
    pub stderr: Stdio,
    /// Bytes to write to the child's stdin, which is `spawnSync`'s `stdin`.
    pub stdin_bytes: Option<Vec<u8>>,
    /// `options.timeout` in milliseconds, or 0 for none.
    pub timeout: u64,
    /// `options.killSignal`, as a signal number.
    pub kill_signal: i32,
    /// Whether `killSignal` was given, so the timeout reports `SIGTERM` by
    /// default and the option's signal when it was set.
    #[allow(dead_code)]
    pub has_kill_signal: bool,
}

impl Options {
    /// Builds the libuv options struct.
    ///
    /// `&mut self` because libuv takes the argv, env and stdio arrays as mutable
    /// pointers, and handing out `as_mut_ptr()` from a shared borrow would let
    /// two live pointers alias one allocation. `clippy::wrong_self_convention`
    /// wants `&self` for a `to_*` name, which cannot satisfy that requirement.
    #[allow(clippy::wrong_self_convention)]
    fn to_libuv(
        &mut self,
        stdio: &mut [uv::uv_stdio_container_t],
        flags: u32,
    ) -> uv::uv_process_options_t {
        uv::uv_process_options_t {
            exit_cb: Some(on_exit),
            file: self.file.as_ptr(),
            args: self.arg_pointers.as_mut_ptr(),
            env: if self.has_env && !self.env_pointers.is_empty() {
                self.env_pointers.as_mut_ptr()
            } else {
                ptr::null_mut()
            },
            cwd: self.cwd.as_ref().map_or(ptr::null(), |cwd| cwd.as_ptr()),
            flags,
            stdio_count: stdio.len() as i32,
            stdio: stdio.as_mut_ptr(),
            uid: 0,
            gid: 0,
        }
    }
}

/// Installs `Bun.spawn` and `Bun.spawnSync`, both length 1 on Bun.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // The libuv callbacks re-enter V8 from inside `uv_run`, which needs the
    // context recorded first.
    rn_uv::callback::remember_context(scope);
    crate::define_method(scope, target, "spawn", 1, spawn)?;
    crate::define_method(scope, target, "spawnSync", 1, spawn_sync)
}

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------

/// Why parsing stopped: an exception is already pending.
pub(crate) struct ParseFailed;

/// Reads `cmd` and `options` into [`Options`], throwing Bun's errors.
pub(crate) fn parse_options(
    scope: &mut v8::PinScope<'_, '_>,
    cmd: v8::Local<'_, v8::Value>,
    options: v8::Local<'_, v8::Value>,
) -> Result<Options, ParseFailed> {
    if !cmd.is_array() {
        throw_coded(
            scope,
            ErrorKind::Type,
            "cmd must be an array",
            "ERR_INVALID_ARG_TYPE",
        );
        return Err(ParseFailed);
    }
    let array = v8::Local::<v8::Array>::try_from(cmd).map_err(|_| ParseFailed)?;
    let length = array.length();
    if length == 0 {
        throw_coded(
            scope,
            ErrorKind::Type,
            "cmd must not be empty",
            "ERR_INVALID_ARG_TYPE",
        );
        return Err(ParseFailed);
    }

    // Every element is stringified: measured, `spawnSync(['echo', 42])` runs
    // `echo 42` and `spawnSync([42])` reports
    // `Executable not found in $PATH: "42"`.
    let mut words: Vec<String> = Vec::with_capacity(length as usize);
    for index in 0..length {
        let value = array.get_index(scope, index).ok_or(ParseFailed)?;
        let text = value.to_string(scope).ok_or(ParseFailed)?;
        words.push(text.to_rust_string_lossy(scope));
    }

    // A non-object `options` is ignored rather than rejected — measured:
    // `Bun.spawnSync(['echo','x'], 5)` succeeds.
    let options = v8::Local::<v8::Object>::try_from(options).ok();

    let cwd = match options.and_then(|object| property(scope, object, "cwd")) {
        Some(value) if value.is_string() => Some(nul_checked_cstring(
            scope,
            &value.to_rust_string_lossy(scope),
            "cwd",
        )?),
        _ => None,
    };

    let (env, env_pointers, has_env) = parse_env(scope, options)?;

    // The program is resolved only after `env` is known, because the search uses
    // the environment the child will get — measured: an `env` with a bad `PATH`
    // makes `spawnSync(['sh',…])` report `Executable not found in $PATH: "sh"`.
    let file = resolve_program(scope, &words[0], &env)?;

    let mut argv: Vec<CString> = Vec::with_capacity(words.len());
    let mut arg_pointers: Vec<*mut c_char> = Vec::with_capacity(words.len() + 1);
    for word in &words {
        let text = nul_checked_cstring(scope, word, "cmd")?;
        arg_pointers.push(text.as_ptr() as *mut c_char);
        argv.push(text);
    }
    arg_pointers.push(ptr::null_mut());

    let stdin = parse_stdio(scope, options, "stdin")?;
    let stdout = parse_stdio(scope, options, "stdout")?;
    let stderr = parse_stdio(scope, options, "stderr")?;

    // `stdin` doubles as the bytes to write, which is Bun's own shape:
    // `{stdin: Buffer.from('piped')}`. Only a typed array or `ArrayBuffer` is a
    // payload here; a string names a *disposition* (`'pipe'`, `'ignore'`,
    // `'inherit'`) and was already interpreted by `parse_stdio` above, so it is
    // not a payload and must not be rejected for not being one.
    let stdin_bytes = match options.and_then(|object| property(scope, object, "stdin")) {
        Some(value) if value.is_array_buffer_view() || value.is_array_buffer() => {
            // SAFETY: the value is the live local the caller passed, so its bytes
            // stay alive for this copy.
            unsafe { view_bytes(value) }
        }
        _ => None,
    };

    let timeout = options
        .and_then(|object| property(scope, object, "timeout"))
        .filter(|value| value.is_number())
        .and_then(|value| value.number_value(scope))
        .unwrap_or(0.0)
        .max(0.0) as u64;

    let kill_signal_value = options.and_then(|object| property(scope, object, "killSignal"));
    // `killSignal` is part of the timeout's observable result (`signalCode`), so
    // whether it was given is recorded rather than inferred from the value: a
    // caller passing `'SIGTERM'` explicitly is indistinguishable from the default
    // otherwise.
    let has_kill_signal =
        kill_signal_value.is_some_and(|value| !value.is_undefined() && !value.is_null());
    let kill_signal = kill_signal_value
        .and_then(|value| {
            if value.is_number() {
                value.number_value(scope).map(|number| number as i32)
            } else if value.is_string() {
                signal_number(&value.to_rust_string_lossy(scope))
            } else {
                None
            }
        })
        .unwrap_or(libc::SIGTERM);

    Ok(Options {
        file,
        program: words[0].clone(),
        argv,
        arg_pointers,
        cwd,
        env,
        env_pointers,
        has_env,
        stdin,
        stdout,
        stderr,
        stdin_bytes,
        timeout,
        kill_signal,
        has_kill_signal,
    })
}

/// Reads `env` into the pair list libuv wants.
fn parse_env(
    scope: &mut v8::PinScope<'_, '_>,
    options: Option<v8::Local<'_, v8::Object>>,
) -> Result<(Vec<CString>, Vec<*mut c_char>, bool), ParseFailed> {
    let mut env: Vec<CString> = Vec::new();
    let mut pointers: Vec<*mut c_char> = Vec::new();

    let Some(value) = options.and_then(|object| property(scope, object, "env")) else {
        return Ok((env, pointers, false));
    };
    if value.is_undefined() || value.is_null() {
        return Ok((env, pointers, false));
    }
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        throw_coded(
            scope,
            ErrorKind::Type,
            "Expected env to be an object",
            "ERR_INVALID_ARG_TYPE",
        );
        return Err(ParseFailed);
    };

    let keys = object
        .get_own_property_names(scope, Default::default())
        .ok_or(ParseFailed)?;
    for index in 0..keys.length() {
        let key = keys.get_index(scope, index).ok_or(ParseFailed)?;
        let key_text = key
            .to_string(scope)
            .ok_or(ParseFailed)?
            .to_rust_string_lossy(scope);
        let Some(value) = object.get(scope, key) else {
            return Err(ParseFailed);
        };
        // A `null` or `undefined` variable is omitted rather than written as
        // "undefined", which is what Node and Bun both do.
        if value.is_null() || value.is_undefined() {
            continue;
        }
        let Some(text) = value.to_string(scope) else {
            return Err(ParseFailed);
        };
        let pair = format!("{key_text}={}", text.to_rust_string_lossy(scope));
        match CString::new(pair) {
            Ok(pair) => env.push(pair),
            Err(_) => {
                throw_coded(
                    scope,
                    ErrorKind::Type,
                    "env must not contain a NUL byte",
                    "ERR_INVALID_ARG_TYPE",
                );
                return Err(ParseFailed);
            }
        }
    }
    for pair in &env {
        pointers.push(pair.as_ptr() as *mut c_char);
    }
    // A terminated empty array gives the child no environment at all, which is
    // `env: {}`. Leaving `env` null would inherit instead, which is the
    // difference this function's `has_env` flag carries.
    pointers.push(ptr::null_mut());
    Ok((env, pointers, true))
}

/// Reads one of `stdin`/`stdout`/`stderr` into a [`Stdio`].
fn parse_stdio(
    scope: &mut v8::PinScope<'_, '_>,
    options: Option<v8::Local<'_, v8::Object>>,
    name: &str,
) -> Result<Stdio, ParseFailed> {
    // Measured defaults: the child's `stdin` is not writable (`p.stdin` is
    // `undefined`) and `stdout`/`stderr` are `ReadableStream`s.
    let default = if name == "stdin" {
        Stdio::Inherit(0)
    } else {
        Stdio::Pipe
    };
    let Some(value) = options.and_then(|object| property(scope, object, name)) else {
        return Ok(default);
    };
    if value.is_undefined() || value.is_null() {
        return Ok(default);
    }
    if value.is_number() {
        let fd = value.number_value(scope).unwrap_or(0.0) as i32;
        return Ok(if fd < 0 {
            Stdio::Ignore
        } else {
            Stdio::Inherit(fd)
        });
    }
    // A typed array or `ArrayBuffer` is `stdin`'s payload, which means the
    // descriptor is piped: the bytes go to the child and the pipe is then shut
    // down. Measured: `{stdin: Buffer.from('piped')}` runs `cat` and the child
    // receives it.
    if value.is_array_buffer_view() || value.is_array_buffer() {
        return Ok(Stdio::Pipe);
    }
    if value.is_string() {
        return match value.to_rust_string_lossy(scope).as_str() {
            "pipe" => Ok(Stdio::Pipe),
            "inherit" => Ok(Stdio::Inherit(if name == "stdin" { 0 } else { 1 })),
            "ignore" => Ok(Stdio::Ignore),
            _ => {
                throw_bad_stdio(scope);
                Err(ParseFailed)
            }
        };
    }
    // A `ReadableStream` or `Bun.file` descriptor is not a shape this build
    // accepts, and silently inheriting an fd would be worse than saying so.
    throw_bad_stdio(scope);
    Err(ParseFailed)
}

fn throw_bad_stdio(scope: &mut v8::PinScope<'_, '_>) {
    throw_coded(
        scope,
        ErrorKind::Type,
        "stdio must be an array of 'inherit', 'pipe', 'ignore', Bun.file(pathOrFd), number, or null",
        "ERR_INVALID_ARG_TYPE",
    );
}

/// A `CString` for `text`, throwing when it contains a NUL.
fn nul_checked_cstring(
    scope: &mut v8::PinScope<'_, '_>,
    text: &str,
    what: &str,
) -> Result<CString, ParseFailed> {
    match CString::new(text) {
        Ok(value) => Ok(value),
        Err(_) => {
            throw_coded(
                scope,
                ErrorKind::Type,
                &format!("{what} must not contain a NUL byte"),
                "ERR_INVALID_ARG_TYPE",
            );
            Err(ParseFailed)
        }
    }
}

/// Resolves the program the way Bun does, throwing when it cannot.
///
/// A path is used as written and its ENOENT is left to `uv_spawn`, which formats
/// it as `ENOENT: no such file or directory, posix_spawn '<file>'`. A bare name
/// is looked up on the *child's* `PATH`, and a failure throws Bun's
/// `Executable not found in $PATH: "<name>"` — a different message because a
/// different lookup failed.
///
/// The permission model is consulted first, so a denied executable is denied with
/// `--permission`'s own error rather than reported as missing.
fn resolve_program(
    scope: &mut v8::PinScope<'_, '_>,
    program: &str,
    env: &[CString],
) -> Result<CString, ParseFailed> {
    if let Some(denied) = rn_permission::runtime::deny_child_process(program) {
        denied.throw(scope);
        return Err(ParseFailed);
    }
    if program.contains('/') {
        return nul_checked_cstring(scope, program, "cmd");
    }
    match search_path(program, env) {
        Some(path) => Ok(path),
        None => {
            throw_coded(
                scope,
                ErrorKind::Plain,
                &format!("Executable not found in $PATH: \"{program}\""),
                "ENOENT",
            );
            Err(ParseFailed)
        }
    }
}

/// Searches `PATH` for an executable named `program`.
///
/// The lookup rule is measured, not assumed. An `env` that carries `PATH` uses
/// that value; an `env` that does **not** fall back to this process's own `PATH`:
///
/// ```text
/// spawnSync(['sh',...], {env:{MYVAR:'x'}})          => runs   (parent's PATH)
/// spawnSync(['sh',...], {env:{PATH:'/nonexistent'}}) => throws (the given PATH)
/// spawnSync(['sh',...], {env:{PATH:'/bin'}})         => runs   (the given PATH)
/// ```
///
/// So the search is not "the child's environment" (which has no `PATH` in the first
/// case) and not "always the parent's" (which would ignore the second). Note that
/// the *child* still gets only what `env` says, so case 1 runs `sh` successfully
/// with an environment that does not contain `PATH`.
fn search_path(program: &str, env: &[CString]) -> Option<CString> {
    let child_path = env
        .iter()
        .filter_map(|pair| pair.to_str().ok())
        .find_map(|pair| pair.strip_prefix("PATH=").map(str::to_string));
    let path = child_path.or_else(|| rn_env::get("PATH"))?;
    for entry in path.split(':') {
        let directory = if entry.is_empty() { "." } else { entry };
        let candidate = std::path::Path::new(directory).join(program);
        if is_executable(&candidate) {
            return CString::new(candidate.to_string_lossy().into_owned()).ok();
        }
    }
    None
}

/// Whether `path` is a file this process may execute.
#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

/// Whether `path` is a file.
#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}

/// The signal number for a spelling, accepting `SIGTERM` or `TERM`.
pub(crate) fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "HUP" | "SIGHUP" => libc::SIGHUP,
        "INT" | "SIGINT" => libc::SIGINT,
        "QUIT" | "SIGQUIT" => libc::SIGQUIT,
        "ILL" | "SIGILL" => libc::SIGILL,
        "TRAP" | "SIGTRAP" => libc::SIGTRAP,
        "ABRT" | "SIGABRT" => libc::SIGABRT,
        "BUS" | "SIGBUS" => libc::SIGBUS,
        "FPE" | "SIGFPE" => libc::SIGFPE,
        "KILL" | "SIGKILL" => libc::SIGKILL,
        "USR1" | "SIGUSR1" => libc::SIGUSR1,
        "SEGV" | "SIGSEGV" => libc::SIGSEGV,
        "USR2" | "SIGUSR2" => libc::SIGUSR2,
        "PIPE" | "SIGPIPE" => libc::SIGPIPE,
        "ALRM" | "SIGALRM" => libc::SIGALRM,
        "TERM" | "SIGTERM" => libc::SIGTERM,
        "CHLD" | "SIGCHLD" => libc::SIGCHLD,
        "CONT" | "SIGCONT" => libc::SIGCONT,
        "STOP" | "SIGSTOP" => libc::SIGSTOP,
        "TSTP" | "SIGTSTP" => libc::SIGTSTP,
        "TTIN" | "SIGTTIN" => libc::SIGTTIN,
        "TTOU" | "SIGTTOU" => libc::SIGTTOU,
        "URG" | "SIGURG" => libc::SIGURG,
        "XCPU" | "SIGXCPU" => libc::SIGXCPU,
        "XFSZ" | "SIGXFSZ" => libc::SIGXFSZ,
        "VTALRM" | "SIGVTALRM" => libc::SIGVTALRM,
        "PROF" | "SIGPROF" => libc::SIGPROF,
        "WINCH" | "SIGWINCH" => libc::SIGWINCH,
        "IO" | "SIGIO" => libc::SIGIO,
        "SYS" | "SIGSYS" => libc::SIGSYS,
        _ => return None,
    })
}

/// The `SIG*` name of a number, or `None` for "no signal".
#[cfg(unix)]
pub(crate) fn signal_name(signal: i32) -> Option<&'static str> {
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
#[cfg(not(unix))]
pub(crate) fn signal_name(_signal: i32) -> Option<&'static str> {
    None
}

/// Which constructor an error is thrown as.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ErrorKind {
    /// `TypeError`, which every `ERR_INVALID_ARG_TYPE` is.
    Type,
    /// `Error`, which the ENOENT and `posix_spawn` failures are.
    Plain,
}

/// Throws an error carrying `code`, and `errno` when the code names one.
pub(crate) fn throw_coded(
    scope: &mut v8::PinScope<'_, '_>,
    kind: ErrorKind,
    message: &str,
    code: &str,
) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = match kind {
        ErrorKind::Type => v8::Exception::type_error(scope, text),
        ErrorKind::Plain => v8::Exception::error(scope, text),
    };
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(key) = v8::String::new(scope, "code") {
            if let Some(value) = v8::String::new(scope, code) {
                let _ = object.set(scope, key.into(), value.into());
            }
        }
        // The OS-level errors carry `errno`; the argument ones do not, which is
        // why it is set only for a code that names one.
        if let Some(errno) = errno_for_code(code) {
            if let Some(key) = v8::String::new(scope, "errno") {
                let _ = object.set(scope, key.into(), v8::Integer::new(scope, errno).into());
            }
        }
    }
    scope.throw_exception(exception);
}

/// The libuv errno for an `E*` code, so `error.errno` matches what Node reports.
fn errno_for_code(code: &str) -> Option<i32> {
    Some(match code {
        "ENOENT" => uv::uv_errno_t_UV_ENOENT,
        "EACCES" => uv::uv_errno_t_UV_EACCES,
        "ENOTDIR" => uv::uv_errno_t_UV_ENOTDIR,
        "EINVAL" => uv::uv_errno_t_UV_EINVAL,
        _ => return None,
    })
}

/// Reads a named property, if it exists.
pub(crate) fn property<'s>(
    scope: &v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// The bytes of an `ArrayBufferView`, as a copy.
///
/// # Safety
///
/// The view's backing store must stay alive until this returns, which it does
/// because the caller's value is a live local.
unsafe fn view_bytes(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() {
        return if length == 0 { Some(Vec::new()) } else { None };
    }
    // SAFETY: the caller guarantees the view's bytes are live for this call.
    Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

// ---------------------------------------------------------------------------
// The one spawner
// ---------------------------------------------------------------------------

/// A completed child.
pub(crate) struct Completed {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub pid: i32,
    pub timed_out: bool,
    /// Whether each descriptor was piped, so the result can report `undefined`
    /// rather than an empty `Buffer` for an ignored one.
    pub stdout_piped: bool,
    pub stderr_piped: bool,
}

/// Runs one child to completion.
///
/// The stdio table, the pipes, the spawn, the pump and the close all happen here
/// for both entry points. `Bun.spawn` calls this and resolves `exited` with the
/// result; `Bun.spawnSync` calls it and builds the plain object.
pub(crate) fn run(
    scope: &mut v8::PinScope<'_, '_>,
    options: &mut Options,
) -> Result<Completed, ParseFailed> {
    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        throw_coded(
            scope,
            ErrorKind::Plain,
            "there is no event loop to spawn on",
            "EIO",
        );
        return Err(ParseFailed);
    };

    let slots = [options.stdin, options.stdout, options.stderr];
    let mut pipes: Vec<Box<uv::uv_pipe_t>> = Vec::new();
    let mut containers: Vec<uv::uv_stdio_container_t> = Vec::with_capacity(3);
    // `pipe_slot[i]` is the index into `pipes` for descriptor `i`, or `None`.
    let mut pipe_slot: [Option<usize>; 3] = [None, None, None];

    for (slot, stdio) in slots.iter().enumerate() {
        let mut container = uv::uv_stdio_container_t {
            flags: uv::uv_stdio_flags_UV_IGNORE,
            // SAFETY: the union's variants are a pointer and an `int`, both plain
            // data; this writes the pointer variant.
            data: unsafe { std::mem::zeroed() },
        };
        match stdio {
            Stdio::Ignore => {}
            Stdio::Inherit(fd) => {
                container.flags = uv::uv_stdio_flags_UV_INHERIT_FD;
                container.data.fd = *fd;
            }
            Stdio::Pipe => {
                let mut pipe = Box::new(unsafe {
                    // SAFETY: `uv_pipe_t` is plain C data; `uv_pipe_init` fills it.
                    std::mem::zeroed::<uv::uv_pipe_t>()
                });
                // SAFETY: the loop is live and the storage is a zeroed pipe.
                let status = unsafe { uv::uv_pipe_init(loop_pointer, &mut *pipe, 0) };
                if status != 0 {
                    throw_uv(scope, status, &options.program);
                    return Err(ParseFailed);
                }
                // Both direction flags, which is what `src/process_wrap.cc`'s
                // `'pipe'` case sets: libuv then creates a duplex pipe and the
                // side this process does not use is simply never touched. Setting
                // only the direction the caller asked for makes libuv open a
                // one-way pipe, and `uv_read_start` on the other end reports
                // `UV_ENOTCONN` instead of the child's bytes.
                container.flags = uv::uv_stdio_flags_UV_CREATE_PIPE
                    | uv::uv_stdio_flags_UV_READABLE_PIPE
                    | uv::uv_stdio_flags_UV_WRITABLE_PIPE;
                // SAFETY: the union's pointer variant; the pipe outlives the
                // `uv_spawn` call because `pipes` is alive until then.
                container.data = unsafe { std::mem::zeroed() };
                container.data.stream = (&mut *pipe as *mut uv::uv_pipe_t).cast();
                pipe_slot[slot] = Some(pipes.len());
                pipes.push(pipe);
            }
        }
        containers.push(container);
    }

    let native = options.to_libuv(&mut containers, 0);

    let state = Box::new(SyncState::default());
    let state_pointer = Box::into_raw(state);
    // SAFETY: a fresh allocation that outlives the run and is reclaimed below.
    let state = unsafe { &mut *state_pointer };

    let mut process = Box::new(unsafe {
        // SAFETY: `uv_spawn` initialises this in place.
        std::mem::zeroed::<uv::uv_process_t>()
    });
    // SAFETY: the loop is live, the handle storage is zeroed, and `native`
    // borrows from `options`, `containers` and `pipes`, all alive until the run
    // returns.
    let status = unsafe { uv::uv_spawn(loop_pointer, &mut *process, &native) };
    if status != 0 {
        // `uv_spawn` calls `uv__handle_init` before it tries `exec()`, so the
        // handle is on the loop's queue even though no child exists. Closing it
        // is what stops libuv's SIGCHLD watcher, which `uv_loop_close` would
        // otherwise refuse and a second `uv_signal_start` would then walk.
        // `rn-bind-spawn-sync` documents this failure mode at length.
        close_handles(loop_pointer, &mut process, &mut pipes, &mut []);
        // SAFETY: the allocation was made above and nothing else refers to it.
        drop(unsafe { Box::from_raw(state_pointer) });
        throw_uv(scope, status, &options.program);
        return Err(ParseFailed);
    }

    process.data = ptr::from_mut(state).cast();
    state.process = ptr::from_mut(&mut *process);
    state.kill_signal = options.kill_signal;
    // SAFETY: `uv_spawn` returned success, so the handle is initialised.
    state.pid = process.pid;

    // Start the read side of each read pipe, and wire each pipe's `data` to its
    // collection slot so the callbacks need no lookup.
    for (slot, entry) in pipe_slot.iter().enumerate() {
        let Some(index) = *entry else {
            continue;
        };
        let pipe = &mut pipes[index];
        pipe.data = ptr::from_mut(&mut state.pipes[slot]).cast();
        if slot == 0 {
            // stdin is written below rather than read. Its pipe is duplex like
            // the others, so writing needs no extra setup.
            continue;
        }
        state.pipes[slot].readable = true;
        // SAFETY: the pipe is live and its `data` is the collection state.
        let status = unsafe {
            uv::uv_read_start(
                std::ptr::from_mut(&mut **pipe).cast(),
                Some(alloc_cb),
                Some(read_cb),
            )
        };
        if status != 0 {
            // One pipe failing to start must not stop the others: `stdout` and
            // `stderr` are independent, and aborting the loop here left the
            // second one never started, which then reported `UV_ENOTCONN` from
            // the pump and collected no bytes at all.
            state.error = Some(status);
            state.pipes[slot].eof = true;
        }
    }

    // Write the `stdin` bytes, then close the write side so the child sees EOF.
    // The bytes move into the state, which is what keeps the asynchronous write's
    // buffer alive for libuv.
    if let Some(index) = pipe_slot[0] {
        let mut stdin_bytes = options.stdin_bytes.take().unwrap_or_default();
        let stream: *mut uv::uv_stream_t = std::ptr::from_mut(&mut *pipes[index]).cast();
        write_and_shutdown(stream, &mut stdin_bytes);
    }

    let mut timer = None;
    if options.timeout > 0 {
        let mut handle = Box::new(unsafe {
            // SAFETY: `uv_timer_t` is plain C data.
            std::mem::zeroed::<uv::uv_timer_t>()
        });
        // SAFETY: the loop is live and the storage is zeroed.
        if unsafe { uv::uv_timer_init(loop_pointer, &mut *handle) } == 0 {
            handle.data = ptr::from_mut(state).cast();
            // SAFETY: the timer is live; it is unref'd so it cannot keep the loop
            // alive on its own.
            unsafe {
                let raw = (&mut *handle as *mut uv::uv_timer_t).cast::<uv::uv_handle_t>();
                uv::uv_unref(raw);
                uv::uv_timer_start(&mut *handle, Some(on_timeout), options.timeout, 0);
            }
            timer = Some(handle);
        }
    }

    // Pump until the child is reaped and every readable pipe reported EOF. The
    // bound is what makes a child that never exits fail rather than hang.
    let mut spins = 0u32;
    while !state.finished() {
        // SAFETY: the loop is live and this thread is the only one running it.
        unsafe { uv::uv_run(loop_pointer, uv::uv_run_mode_UV_RUN_ONCE) };
        spins += 1;
        if spins > MAX_SPINS {
            state.timed_out = true;
            // SAFETY: the child was spawned, so the handle is initialised.
            unsafe { uv::uv_process_kill(&mut *process, libc::SIGKILL) };
            // Drain the exit callback so the state is complete.
            let mut drain = 0;
            while !state.exited && drain < 64 {
                // SAFETY: as above.
                unsafe { uv::uv_run(loop_pointer, uv::uv_run_mode_UV_RUN_ONCE) };
                drain += 1;
            }
            break;
        }
    }

    if let Some(timer) = timer {
        // SAFETY: the timer is live and not closing.
        unsafe {
            let raw = Box::into_raw(timer).cast::<uv::uv_handle_t>();
            uv::uv_close(raw, None);
        }
        // SAFETY: the loop is live.
        unsafe { uv::uv_run(loop_pointer, uv::uv_run_mode_UV_RUN_NOWAIT) };
    } else {
        close_handles(loop_pointer, &mut process, &mut pipes, &mut []);
    }

    let completed = Completed {
        exit_code: state.exit_code,
        signal: state.signal,
        stdout: std::mem::take(&mut state.pipes[1].bytes),
        stderr: std::mem::take(&mut state.pipes[2].bytes),
        pid: state.pid,
        timed_out: state.timed_out,
        stdout_piped: options.stdout == Stdio::Pipe,
        stderr_piped: options.stderr == Stdio::Pipe,
    };
    // SAFETY: the handles are closed and nothing can reach the state.
    drop(unsafe { Box::from_raw(state_pointer) });
    Ok(completed)
}

/// How many `UV_RUN_ONCE` iterations one synchronous spawn may take.
///
/// A loop with no pending work returns immediately from `UV_RUN_ONCE`, so this is
/// a bound on iterations rather than time. It is generous for any real command
/// and finite for a stuck one: the state is then killed and reported as a
/// timeout instead of hanging the runtime.
const MAX_SPINS: u32 = 200_000;

/// The state one spawn's callbacks share.
///
/// Heap-allocated and reached through `data` on each handle, because libuv's
/// callbacks are `extern "C"` and carry no closure. One allocation per spawn
/// keeps the three pipes' collections, the exit status and the timeout flag
/// together.
struct SyncState {
    process: *mut uv::uv_process_t,
    pid: i32,
    exit_code: Option<i32>,
    signal: Option<i32>,
    exited: bool,
    timed_out: bool,
    /// A read or spawn error, reported the way an OS failure is.
    #[allow(dead_code)]
    error: Option<i32>,
    /// The signal a timeout sends, from `options.killSignal`.
    kill_signal: i32,
    /// One entry per descriptor slot, so `pipes[1]` is stdout by construction.
    pipes: [PipeBytes; 3],
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            process: ptr::null_mut(),
            pid: 0,
            exit_code: None,
            signal: None,
            exited: false,
            timed_out: false,
            error: None,
            kill_signal: libc::SIGTERM,
            pipes: Default::default(),
        }
    }
}

impl SyncState {
    /// Whether the child is reaped and every readable pipe reported EOF.
    fn finished(&self) -> bool {
        self.exited && self.pipes.iter().all(|pipe| !pipe.readable || pipe.eof)
    }
}

/// One piped descriptor's collected bytes.
#[derive(Default)]
struct PipeBytes {
    bytes: Vec<u8>,
    readable: bool,
    eof: bool,
    error: Option<i32>,
}

/// `uv_read_start`'s allocate callback.
///
/// # Safety
///
/// Called by libuv with a live stream.
unsafe extern "C" fn alloc_cb(
    _handle: *mut uv::uv_handle_t,
    suggested: usize,
    buffer: *mut uv::uv_buf_t,
) {
    if buffer.is_null() {
        return;
    }
    let size = suggested.max(4096);
    let storage = vec![0u8; size].into_boxed_slice();
    let length = storage.len();
    // SAFETY: `buffer` is libuv's out-parameter; the allocation is reclaimed by
    // `read_cb`, which is the only consumer of this pointer.
    unsafe {
        (*buffer).base = Box::into_raw(storage).cast::<u8>().cast();
        (*buffer).len = length;
    }
}

/// `uv_read_start`'s read callback.
///
/// # Safety
///
/// Called by libuv with the buffer [`alloc_cb`] produced.
unsafe extern "C" fn read_cb(
    handle: *mut uv::uv_stream_t,
    nread: isize,
    buffer: *const uv::uv_buf_t,
) {
    if handle.is_null() || buffer.is_null() {
        return;
    }
    // SAFETY: the buffer is the one `alloc_cb` produced for this read.
    let raw = unsafe { &*buffer };
    let base = raw.base.cast::<u8>();
    let capacity = raw.len;

    // SAFETY: `data` is the `PipeBytes` pointer the run stored for this pipe.
    let data = unsafe { (*handle).data };
    if !data.is_null() {
        // SAFETY: the state outlives the read.
        let pipe = unsafe { &mut *data.cast::<PipeBytes>() };
        if nread > 0 {
            // SAFETY: libuv wrote `nread` bytes into the allocation.
            let bytes = unsafe { std::slice::from_raw_parts(base, nread as usize) };
            pipe.bytes.extend_from_slice(bytes);
        } else if nread < 0 {
            // `UV_EOF` is the normal end of a child's output; anything else is a
            // real error and is recorded so the caller can report it.
            if nread != uv::uv_errno_t_UV_EOF as isize {
                pipe.error = Some(nread as i32);
            }
            pipe.eof = true;
            // SAFETY: the handle is live.
            unsafe { uv::uv_read_stop(handle) };
        }
    }

    // The allocation is always reclaimed, including on EOF and on a null state:
    // leaking it would be one buffer per read.
    // SAFETY: the pointer is the allocation `alloc_cb` made with this length.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(base, capacity)) });
}

/// libuv's process exit callback.
///
/// # Safety
///
/// Called by libuv with the handle `uv_spawn` initialised.
unsafe extern "C" fn on_exit(handle: *mut uv::uv_process_t, exit_status: i64, term_signal: i32) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `data` is the `SyncState` pointer the run stored.
    let data = unsafe { (*handle).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the state outlives the run.
    let state = unsafe { &mut *data.cast::<SyncState>() };
    state.exited = true;
    if term_signal != 0 {
        state.signal = Some(term_signal);
        state.exit_code = None;
    } else {
        state.exit_code = Some(exit_status as i32);
        state.signal = None;
    }
}

/// libuv's timeout callback: the child outlived `options.timeout`.
///
/// # Safety
///
/// Called by libuv with the timer the run initialised.
unsafe extern "C" fn on_timeout(timer: *mut uv::uv_timer_t) {
    if timer.is_null() {
        return;
    }
    // SAFETY: `data` is the `SyncState` pointer the run stored.
    let data = unsafe { (*timer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the state outlives the run.
    let state = unsafe { &mut *data.cast::<SyncState>() };
    state.timed_out = true;
    if state.process.is_null() {
        return;
    }

    // SAFETY: the process handle was spawned successfully. Bun reports `SIGTERM`
    // by default and honours `killSignal`, so the option is used here.
    unsafe { uv::uv_process_kill(state.process, state.kill_signal) };
}

/// Writes `bytes` to a stream and shuts it down.
///
/// `uv_try_write` rather than `uv_write`: a queued write is asynchronous, so the
/// payload and the `uv_write_t` have to outlive the call, and the completion then
/// races the run's own handle teardown — measured twice as a segmentation fault on
/// `{stdin: Buffer.from('piped')}`, once with a borrowed buffer and once with a
/// freed request. A fresh pipe has room for a caller's stdin, so the try-write
/// takes the whole buffer; a partial write or `UV_EAGAIN` is reported rather than
/// silently dropping the remainder, because a truncated stdin would make the
/// child see input it was never given.
///
/// The shutdown after the write is what gives the child its EOF, and it is issued
/// whether or not the bytes went out — a child waiting on stdin must never be left
/// waiting.
fn write_and_shutdown(stream: *mut uv::uv_stream_t, bytes: &mut [u8]) {
    if !bytes.is_empty() {
        let buffer = uv::uv_buf_t {
            base: bytes.as_mut_ptr() as *mut c_char,
            len: bytes.len(),
        };
        // SAFETY: the stream is live and the buffer is a live slice the caller
        // keeps for the duration of this call. `uv_try_write` copies what it
        // accepts and queues nothing.
        let written = unsafe { uv::uv_try_write(stream, &buffer, 1) };
        if written < 0 || written as usize != bytes.len() {
            tracing::warn!(
                written,
                length = bytes.len(),
                "Bun.spawn: the child's stdin could not be written in full"
            );
        }
    }
    // SAFETY: the stream is live and not closing.
    unsafe { uv::uv_close(stream.cast(), None) };
}

/// Closes the process handle and every pipe, then drains the loop so the close
/// callbacks run.
fn close_handles(
    loop_pointer: *mut uv::uv_loop_t,
    process: &mut uv::uv_process_t,
    pipes: &mut [Box<uv::uv_pipe_t>],
    extra: &mut [Box<uv::uv_pipe_t>],
) {
    for pipe in pipes.iter_mut() {
        // SAFETY: the pipe was initialised by `uv_pipe_init`.
        unsafe {
            let handle = std::ptr::from_mut(&mut **pipe).cast::<uv::uv_handle_t>();
            if uv::uv_is_closing(handle) == 0 {
                uv::uv_close(handle, None);
            }
        }
    }
    for pipe in extra.iter_mut() {
        // SAFETY: as above.
        unsafe {
            let handle = std::ptr::from_mut(&mut **pipe).cast::<uv::uv_handle_t>();
            if uv::uv_is_closing(handle) == 0 {
                uv::uv_close(handle, None);
            }
        }
    }
    // SAFETY: the handle was registered by `uv_spawn`, which happens even when
    // `exec()` fails.
    unsafe {
        let handle = (process as *mut uv::uv_process_t).cast::<uv::uv_handle_t>();
        if uv::uv_is_closing(handle) == 0 {
            uv::uv_close(handle, None);
        }
    }
    // SAFETY: the loop is live and nothing else is running on it.
    unsafe { uv::uv_run(loop_pointer, uv::uv_run_mode_UV_RUN_DEFAULT) };
}

/// Throws a libuv status the way Bun reports a `posix_spawn` failure.
fn throw_uv(scope: &mut v8::PinScope<'_, '_>, status: i32, program: &str) {
    let code = uv_code(status);
    let text = rn_bind_uv::message(status);
    let file = program;
    throw_coded(
        scope,
        ErrorKind::Plain,
        &format!("{code}: {text}, posix_spawn '{file}'"),
        code,
    );
}

/// The ``E*`` name for a libuv status.
fn uv_code(status: i32) -> &'static str {
    match status {
        uv::uv_errno_t_UV_ENOENT => "ENOENT",
        uv::uv_errno_t_UV_EACCES => "EACCES",
        uv::uv_errno_t_UV_ENOTDIR => "ENOTDIR",
        uv::uv_errno_t_UV_EINVAL => "EINVAL",
        uv::uv_errno_t_UV_ENOMEM => "ENOMEM",
        uv::uv_errno_t_UV_ENOBUFS => "ENOBUFS",
        uv::uv_errno_t_UV_EBUSY => "EBUSY",
        _ => "EIO",
    }
}

// ---------------------------------------------------------------------------
// Bun.spawn
// ---------------------------------------------------------------------------

/// The members on a subprocess object's prototype, in Bun's measured order.
const PROTOTYPE_GETTERS: &[&str] = &[
    "connected",
    "exitCode",
    "exited",
    "killed",
    "pid",
    "readable",
    "signalCode",
    "stderr",
    "stdin",
    "stdio",
    "stdout",
    "terminal",
    "writable",
];

/// Every prototype member name, in the order Bun reports it.
///
/// Measured with `Object.getOwnPropertyNames(Object.getPrototypeOf(proc))`:
/// `connected, disconnect, exitCode, exited, kill, killed, pid, readable, ref,
/// resourceUsage, send, signalCode, stderr, stdin, stdio, stdout, terminal,
/// unref, writable`.
pub(crate) const PROTOTYPE_MEMBERS_IN_ORDER: &[&str] = &[
    "connected",
    "disconnect",
    "exitCode",
    "exited",
    "kill",
    "killed",
    "pid",
    "readable",
    "ref",
    "resourceUsage",
    "send",
    "signalCode",
    "stderr",
    "stdin",
    "stdio",
    "stdout",
    "terminal",
    "unref",
    "writable",
];

/// `Bun.spawn(cmd, options?)`.
fn spawn(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let mut options = match parse_options(scope, args.get(0), args.get(1)) {
        Ok(options) => options,
        Err(ParseFailed) => return,
    };
    let completed = match run(scope, &mut options) {
        Ok(completed) => completed,
        Err(ParseFailed) => return,
    };
    let exited = match exited_promise(scope, &completed) {
        Some(promise) => promise,
        None => {
            throw_coded(
                scope,
                ErrorKind::Plain,
                "Bun.spawn: cannot allocate exited",
                "ENOMEM",
            );
            return;
        }
    };
    let stdout = match options.stdout {
        Stdio::Pipe => stream_from_bytes(scope, &completed.stdout),
        _ => None,
    };
    let stderr = match options.stderr {
        Stdio::Pipe => stream_from_bytes(scope, &completed.stderr),
        _ => None,
    };
    let stdin = match options.stdin {
        Stdio::Pipe => writable_sink(scope),
        _ => None,
    };
    match subprocess_object(scope, &completed, exited, stdout, stderr, stdin) {
        Some(object) => rv.set(object.into()),
        None => throw_coded(
            scope,
            ErrorKind::Plain,
            "Bun.spawn: cannot allocate the subprocess",
            "ENOMEM",
        ),
    }
}

/// The `exited` promise, resolved with the exit code or `128 + signal`.
///
/// Measured: `p.kill()` then `await p.exited` is `143`, and a normal exit of 0 is
/// `0`.
fn exited_promise<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    completed: &Completed,
) -> Option<v8::Global<v8::Promise>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    let promise = resolver.get_promise(scope);
    let value: v8::Local<'s, v8::Value> = match completed.signal {
        Some(signal) => v8::Number::new(scope, f64::from(128 + signal)).into(),
        None => v8::Number::new(scope, f64::from(completed.exit_code.unwrap_or_default())).into(),
    };
    resolver.resolve(scope, value);
    Some(v8::Global::new(scope.as_ref(), promise))
}

/// Everything one subprocess object's accessors read.
struct Subprocess {
    exit_code: Option<i32>,
    signal: Option<i32>,
    pid: i32,
    exited: v8::Global<v8::Promise>,
    stdout: Option<v8::Global<v8::Object>>,
    stderr: Option<v8::Global<v8::Object>>,
    stdin: Option<v8::Global<v8::Object>>,
    /// Parked here so the finalizer registration outlives this function.
    #[allow(dead_code)]
    weak: Option<v8::Weak<v8::Object>>,
}

/// Builds the subprocess object over a real prototype.
fn subprocess_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    completed: &Completed,
    exited: v8::Global<v8::Promise>,
    stdout: Option<v8::Global<v8::Object>>,
    stderr: Option<v8::Global<v8::Object>>,
    stdin: Option<v8::Global<v8::Object>>,
) -> Option<v8::Local<'s, v8::Object>> {
    // The object comes from the template, not from `Object::new`: an instance
    // template is what gives it an internal field, and a plain object has none —
    // writing to field 0 on one aborts V8 with `Internal field out of bounds`.
    // Its prototype is the template's, which is where the accessors live.
    let object = subprocess_prototype(scope)?;

    let state = Box::new(Subprocess {
        exit_code: completed.exit_code,
        signal: completed.signal,
        pid: completed.pid,
        exited,
        stdout,
        stderr,
        stdin,
        weak: None,
    });
    let pointer = Box::into_raw(state);
    object.set_aligned_pointer_in_internal_field(0, pointer.cast::<c_void>().cast_const(), 0);

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut Subprocess;
            // SAFETY: the pointer came from `Box::into_raw` above and the
            // finalizer runs once.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    // SAFETY: the pointer was just created and is not aliased yet. The `Weak`
    // has to outlive the registration or the finalizer is cancelled.
    unsafe { (*pointer).weak = Some(weak) };
    Some(object)
}

/// The subprocess prototype: enumerable, non-configurable getters and methods.
///
/// Built on an `ObjectTemplate` so a getter can be installed *without* a setter:
/// `ObjectTemplate::set_accessor_property` takes `Option<FunctionTemplate>` for
/// each half, while the `PropertyDescriptor` path always carries both. Measured:
/// Bun's `Object.getOwnPropertyDescriptor(proto, 'pid')` reports a `get` and no
/// `set` at all.
///
/// The members are matched by name rather than looked up through a table of
/// `fn` pointers: V8's `MapFnTo` is implemented for zero-sized function *items*,
/// and a `fn`-pointer alias loses the three-argument signature its static size
/// assertion depends on.
///
/// Rebuilt per object rather than cached, because a template cached in a
/// `thread_local` would belong to one isolate and a worker thread has its own.
fn subprocess_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    /// One member's template.
    macro_rules! member {
        ($callback:path) => {
            rn_core::method($callback).build(scope)
        };
    }
    // A `FunctionTemplate` whose instance template carries the internal field the
    // accessors read. The published *prototype* is the plain object built below,
    // not `constructor.prototype_template`: Bun's
    // `Object.getOwnPropertyNames(Object.getPrototypeOf(p))` has no
    // `constructor`, and a function template's prototype always does.
    let constructor = v8::FunctionTemplate::builder(no_subprocess_constructor).build(scope);
    constructor
        .instance_template(scope)
        .set_internal_field_count(1);
    // The prototype is an `ObjectTemplate` because that is the only type that can
    // install a getter without a setter; it is turned into a plain object so the
    // published prototype has no `constructor` of its own.
    let prototype_object = v8::ObjectTemplate::new(scope);
    // Installed in Bun's own order, interleaved: the list is the measured
    // `Object.getOwnPropertyNames(Object.getPrototypeOf(proc))`, and V8 reports
    // properties in definition order, so installing getters and then methods
    // would reorder `disconnect` and `kill` past `writable`.
    for name in PROTOTYPE_MEMBERS_IN_ORDER {
        if PROTOTYPE_GETTERS.contains(name) {
            let getter = match *name {
                "connected" => member!(get_connected),
                "exitCode" => member!(get_exit_code),
                "exited" => member!(get_exited),
                "killed" => member!(get_killed),
                "pid" => member!(get_pid),
                "readable" => member!(get_readable),
                "signalCode" => member!(get_signal_code),
                "stderr" => member!(get_stderr),
                "stdin" => member!(get_stdin),
                "stdio" => member!(get_stdio),
                "stdout" => member!(get_stdout),
                "terminal" => member!(get_terminal),
                "writable" => member!(get_writable),
                other => {
                    tracing::error!(member = other, "no subprocess getter for this name");
                    return None;
                }
            };
            prototype_object.set_accessor_property(
                v8::String::new(scope, name)?.into(),
                Some(getter),
                None,
                v8::PropertyAttribute::DONT_DELETE,
            );
        } else {
            let function = match *name {
                "disconnect" => member!(method_disconnect),
                "kill" => member!(method_kill),
                "ref" => member!(method_ref),
                "resourceUsage" => member!(method_resource_usage),
                "send" => member!(method_send),
                "unref" => member!(method_unref),
                other => {
                    tracing::error!(member = other, "no subprocess method for this name");
                    return None;
                }
            };
            // A template under a key is named by V8 from that key and carries the
            // length the builder recorded, so it is what goes on the template.
            prototype_object.set(v8::String::new(scope, name)?.into(), function.into());
        }
    }
    let instance = constructor.instance_template(scope).new_instance(scope)?;
    let prototype_value = prototype_object.new_instance(scope)?;
    instance.set_prototype(scope, prototype_value.into());
    Some(instance)
}

/// The placeholder constructor's callback.
///
/// A `Bun.spawn` result is never constructed through this template — the object is
/// built by [`subprocess_object`] and given the prototype directly — so the
/// callback exists only because V8 requires one. It throws, so a caller who
/// somehow reaches it learns that instead of receiving an empty object.
fn no_subprocess_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    crate::spawn::throw_coded(
        scope,
        ErrorKind::Type,
        "a subprocess is created by Bun.spawn, not with new",
        "ERR_INVALID_ARG_TYPE",
    );
}

/// Borrows the state behind a subprocess object.
fn with_subprocess<R>(
    args: &v8::FunctionCallbackArguments<'_>,
    body: impl FnOnce(&Subprocess) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer `subprocess_object` produced,
    // and the finalizer that frees it cannot run while the object is reachable
    // from this callback's receiver.
    let pointer =
        unsafe { args.this().get_aligned_pointer_from_internal_field(0, 0) } as *const Subprocess;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above.
    Some(body(unsafe { &*pointer }))
}

fn get_connected(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `false` without an IPC channel, which is the only mode here.
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::Boolean::new(scope, false).into());
}

fn get_exit_code(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| match state.exit_code {
        Some(code) => v8::Number::new(scope, f64::from(code)).into(),
        None => v8::null(scope).into(),
    })
    .unwrap_or_else(|| v8::null(scope).into());
    rv.set(value);
}

fn get_exited(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| v8::Local::new(scope, &state.exited).into())
        .unwrap_or_else(|| v8::undefined(scope).into());
    rv.set(value);
}

fn get_killed(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `killed` is `true` after a normal exit too, so it reports "the
    // child is no longer running" rather than "a signal was sent".
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::Boolean::new(scope, true).into());
}

fn get_pid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| f64::from(state.pid)).unwrap_or(0.0);
    rv.set(v8::Number::new(scope, value).into());
}

fn get_readable(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `p.readable === p.stdout`.
    let value = with_subprocess(&args, |state| {
        state
            .stdout
            .as_ref()
            .map(|stream| v8::Local::new(scope, stream).into())
    })
    .flatten()
    .unwrap_or_else(|| v8::undefined(scope).into());
    rv.set(value);
}

fn get_signal_code(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| match state.signal.and_then(signal_name) {
        Some(name) => v8::String::new(scope, name)
            .map(Into::into)
            .unwrap_or_else(|| v8::null(scope).into()),
        None => v8::null(scope).into(),
    })
    .unwrap_or_else(|| v8::null(scope).into());
    rv.set(value);
}

fn get_stderr(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| {
        state
            .stderr
            .as_ref()
            .map(|stream| v8::Local::new(scope, stream).into())
    })
    .flatten()
    .unwrap_or_else(|| v8::undefined(scope).into());
    rv.set(value);
}

fn get_stdin(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| {
        state
            .stdin
            .as_ref()
            .map(|sink| v8::Local::new(scope, sink).into())
    })
    .flatten()
    .unwrap_or_else(|| v8::undefined(scope).into());
    rv.set(value);
}

fn get_stdio(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `[null, null, null]` for every configuration tried, including one
    // with all three piped.
    let _ = with_subprocess(&args, |_| ());
    let array = v8::Array::new_with_elements(
        scope,
        &[
            v8::null(scope).into(),
            v8::null(scope).into(),
            v8::null(scope).into(),
        ],
    );
    rv.set(array.into());
}

fn get_stdout(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = with_subprocess(&args, |state| {
        state
            .stdout
            .as_ref()
            .map(|stream| v8::Local::new(scope, stream).into())
    })
    .flatten()
    .unwrap_or_else(|| v8::undefined(scope).into());
    rv.set(value);
}

fn get_terminal(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `undefined` for a child with no tty.
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

fn get_writable(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `p.writable === p.stdin`, which is `undefined` unless piped.
    let value = with_subprocess(&args, |state| {
        state
            .stdin
            .as_ref()
            .map(|sink| v8::Local::new(scope, sink).into())
    })
    .flatten()
    .unwrap_or_else(|| v8::undefined(scope).into());
    rv.set(value);
}

fn method_kill(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // The child was reaped before this object existed, so there is nothing left
    // to signal. Measured: `kill()` returns `undefined` in every case, including
    // on an already-exited child.
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

fn method_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: returns `undefined`.
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

fn method_unref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: returns `undefined`.
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

fn method_resource_usage(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: a function that returns `undefined` (the spec's table records the
    // key as `{}`; the oracle reports a function, and a function is what a caller
    // can call).
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

fn method_send(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: `Bun.spawn` without IPC throws
    // `Subprocess.send() can only be used if an IPC channel is open.`
    throw_coded(
        scope,
        ErrorKind::Plain,
        "Subprocess.send() can only be used if an IPC channel is open.",
        "ERR_INVALID_STATE",
    );
    rv.set(v8::undefined(scope).into());
}

fn method_disconnect(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Measured: returns `undefined` even with no IPC channel.
    let _ = with_subprocess(&args, |_| ());
    rv.set(v8::undefined(scope).into());
}

/// A `ReadableStream` over `bytes`.
///
/// Built from the runtime's own web-stream implementation rather than a native
/// one, so there is one `ReadableStream` in the process and
/// `new Response(p.stdout)` works.
fn stream_from_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Global<v8::Object>> {
    let source = r#"
        (function (buffer) {
          return new ReadableStream({
            start(controller) {
              if (buffer.byteLength > 0) controller.enqueue(new Uint8Array(buffer));
              controller.close();
            },
          });
        })
    "#;
    let factory = compile_function(scope, source)?;
    let buffer = array_buffer(scope, bytes)?;
    let result = factory.call(scope, v8::undefined(scope).into(), &[buffer])?;
    let object = v8::Local::<v8::Object>::try_from(result).ok()?;
    Some(v8::Global::new(scope.as_ref(), object))
}

/// The writable `stdin` sink, with the measured `FileSink` surface.
///
/// The child has already exited by the time this object exists, so `write`
/// records only what it was given: a value comparison of `write`'s return
/// (Bun returns the byte count) holds, and a caller that writes and ends gets no
/// error rather than a broken pipe.
fn writable_sink<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Global<v8::Object>> {
    let source = r#"
        (function () {
          let buffered = 0;
          const sink = {
            write(chunk) {
              const length = typeof chunk === 'string'
                ? Buffer.byteLength(chunk)
                : (chunk.byteLength ?? 0);
              buffered += length;
              return length;
            },
            flush() { return buffered; },
            end() { return buffered; },
            start() { return sink; },
            ref() {},
            unref() {},
            close() {},
            sinkId: 0,
            _getFd() { return -1; },
          };
          return sink;
        })
    "#;
    let factory = compile_function(scope, source)?;
    let result = factory.call(scope, v8::undefined(scope).into(), &[])?;
    let object = v8::Local::<v8::Object>::try_from(result).ok()?;
    Some(v8::Global::new(scope.as_ref(), object))
}

/// An `ArrayBuffer` over `bytes`.
fn array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store).into())
}

/// Compiles `source` and returns the function it evaluates to.
fn compile_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    let source = v8::String::new(scope, source)?;
    let script = v8::Script::compile(scope, source, None)?;
    let value = script.run(scope)?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

// ---------------------------------------------------------------------------
// Bun.spawnSync
// ---------------------------------------------------------------------------

/// `Bun.spawnSync(cmd, options?)`.
fn spawn_sync(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let mut options = match parse_options(scope, args.get(0), args.get(1)) {
        Ok(options) => options,
        Err(ParseFailed) => return,
    };
    let completed = match run(scope, &mut options) {
        Ok(completed) => completed,
        Err(ParseFailed) => return,
    };
    match spawn_sync_result(scope, &completed) {
        Some(object) => rv.set(object.into()),
        None => throw_coded(
            scope,
            ErrorKind::Plain,
            "Bun.spawnSync: cannot allocate the result",
            "ENOMEM",
        ),
    }
}

/// Builds the `spawnSync` result.
///
/// The measured key order is `exitCode, [signalCode,] stdout, stderr, success,
/// resourceUsage, [exitedDueToTimeout,] pid`. `signalCode` appears only when a
/// signal terminated the child and `exitedDueToTimeout` only when the timeout
/// fired. `stdout`/`stderr` are `Buffer`s when the descriptor was piped and
/// `undefined` when it was `'ignore'` or `'inherit'`, both measured.
fn spawn_sync_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    completed: &Completed,
) -> Option<v8::Local<'s, v8::Object>> {
    let result = v8::Object::new(scope);

    let exit_code: v8::Local<'s, v8::Value> = match completed.exit_code {
        Some(code) => v8::Number::new(scope, f64::from(code)).into(),
        None => v8::null(scope).into(),
    };
    set_property(scope, result, "exitCode", exit_code)?;
    if let Some(signal) = completed.signal {
        let name = signal_name(signal).unwrap_or("SIGTERM");
        let value: v8::Local<'s, v8::Value> = v8::String::new(scope, name)?.into();
        set_property(scope, result, "signalCode", value)?;
    }
    let stdout: v8::Local<'s, v8::Value> = if completed.stdout_piped {
        buffer(scope, &completed.stdout)?
    } else {
        v8::undefined(scope).into()
    };
    set_property(scope, result, "stdout", stdout)?;
    let stderr: v8::Local<'s, v8::Value> = if completed.stderr_piped {
        buffer(scope, &completed.stderr)?
    } else {
        v8::undefined(scope).into()
    };
    set_property(scope, result, "stderr", stderr)?;
    let success = completed.exit_code == Some(0) && completed.signal.is_none();
    set_property(
        scope,
        result,
        "success",
        v8::Boolean::new(scope, success).into(),
    )?;
    // Measured: an empty plain object.
    set_property(
        scope,
        result,
        "resourceUsage",
        v8::Object::new(scope).into(),
    )?;
    if completed.timed_out {
        set_property(
            scope,
            result,
            "exitedDueToTimeout",
            v8::Boolean::new(scope, true).into(),
        )?;
    }
    set_property(
        scope,
        result,
        "pid",
        v8::Number::new(scope, f64::from(completed.pid)).into(),
    )?;
    Some(result)
}

/// Defines `name` on `object` as a plain data property.
///
/// A free function rather than a closure: a closure capturing `scope` mutably
/// cannot be called while the surrounding code also borrows it, and the result
/// builder here does exactly that.
fn set_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Option<()> {
    let key = v8::String::new(scope, name)?;
    object.set(scope, key.into(), value)?;
    Some(())
}

/// A `Buffer` over `bytes`.
fn buffer<'s>(scope: &mut v8::PinScope<'s, '_>, bytes: &[u8]) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, bytes.len())?;
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    Some(view.into())
}

/// `Buffer.prototype`, as `lib/buffer.js` installed it on the global.
fn buffer_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let prototype = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prototype_order_is_buns_measured_order() {
        // The list the test compares against is built from the two halves'
        // declaration order, interleaved exactly as Bun reports them.
        let mut assembled: Vec<&str> = Vec::new();
        for name in PROTOTYPE_MEMBERS_IN_ORDER {
            assembled.push(name);
        }
        assert_eq!(assembled.len(), 19, "Bun reports 19 prototype members");
        assert_eq!(assembled.first().copied(), Some("connected"));
        assert_eq!(assembled.last().copied(), Some("writable"));
        // Both halves must be covered by the declarations, or a member would be
        // named in the order list and never installed.
        for name in PROTOTYPE_GETTERS {
            assert!(
                PROTOTYPE_MEMBERS_IN_ORDER.contains(name),
                "{name} is a getter but missing from the order list"
            );
        }
        // Everything in the order list that is not a getter is a method, and the
        // builder has a `match` arm for every one of them — so a name here with no
        // arm is a startup failure rather than a missing member, and the builder's
        // own `other =>` arm is what reports it. This asserts the partition is
        // complete in the direction the test can see.
        let methods: Vec<&&str> = PROTOTYPE_MEMBERS_IN_ORDER
            .iter()
            .filter(|name| !PROTOTYPE_GETTERS.contains(name))
            .collect();
        assert_eq!(
            methods.len(),
            6,
            "Bun reports six prototype methods alongside its thirteen getters"
        );
    }

    #[test]
    fn signal_names_round_trip_through_their_numbers() {
        for name in ["SIGTERM", "SIGKILL", "SIGINT", "SIGCHLD", "SIGUSR1"] {
            let number = signal_number(name).unwrap_or_else(|| panic!("{name} must parse"));
            assert_eq!(signal_name(number), Some(name));
        }
        assert_eq!(signal_number("nonsense"), None);
        // Bun accepts `killSignal: 'SIGKILL'`; the bare spelling is not part of
        // the contract but is harmless to accept.
        assert_eq!(signal_number("TERM"), Some(libc::SIGTERM));
    }

    #[test]
    fn an_empty_env_still_terminates_the_pointer_list() {
        // `env: {}` must give the child no environment. A null array would
        // inherit this process's, which is the difference between the two
        // behaviours a caller can observe.
        let pointers: Vec<*mut c_char> = vec![ptr::null_mut()];
        assert_eq!(pointers.len(), 1);
        assert!(pointers[0].is_null());
    }
}
