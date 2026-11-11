//! Driving the event loop from the CLI, over V8 and Node's own timer code.
//!
//! Everything the loop needs from JavaScript already exists in
//! `vendor/libnode-js/lib/**`. This module only installs it and answers the
//! loop's questions, which is what keeps rustnode from growing a second timers
//! implementation:
//!
//! * `internal/process/task_queues.js` owns `process.nextTick` and
//!   `queueMicrotask`. Its `setupTaskQueue()` returns the tick pair and installs
//!   the tick callback V8 runs as part of a microtask checkpoint.
//! * `internal/timers.js` owns the timer lists and returns the two callbacks
//!   `setupTimers()` hands to the native side. Those callbacks are what the
//!   libuv timer and check handles run.
//! * `internal/bootstrap/web/exposed-window-or-worker.js` is where Node installs
//!   `setTimeout`, `setInterval`, `setImmediate`, their `clear` counterparts and
//!   `queueMicrotask` as globals, so that file is what this reproduces rather
//!   than a hand-written list.
//!
//! # Why the globals are installed here and not by `node.js`
//!
//! `internal/bootstrap/node.js` is the file Node itself uses, and it cannot run
//! yet: it reads `config`, `util`'s private symbols, `process.hrtime` and half a
//! dozen namespaces that have not landed. The narrow installer is the same
//! pattern `install_early_globals` already uses for `Buffer`,
//! `structuredClone` and `TextEncoder`: run the vendored module, take the
//! exports, and put them on the global where `exposed-window-or-worker.js` puts
//! them.
//!
//! # Ordering
//!
//! The phases belong to libuv, which `rn-io` drives one iteration at a time.
//! What stays here is the drain: Node checks the tick and microtask queues after
//! every JavaScript callback, and the one point where the loop can be asked to
//! do that is between two iterations. The script body is drained once before the
//! loop starts, which is why a `.then` scheduled in the script runs before the
//! process exits and why `process.nextTick` beats both a promise and a 0ms timer.

use rn_io::{Loop, Scheduler, StopReason};
use rn_v8_sys::v8;

/// The JavaScript entry points the loop calls every turn.
///
/// Held as `Global`s because a `Scheduler` outlives any one `HandleScope`: the
/// functions are reached from a fresh scope on each phase.
pub struct Runtime {
    run_next_ticks: v8::Global<v8::Function>,
}

impl Runtime {
    /// Installs the task queue, the timer callbacks and the timer globals.
    ///
    /// Returns `Err` with the reason when the vendored modules cannot be loaded,
    /// so the caller can say why asynchronous code will not run rather than
    /// letting every script fail later with a `TypeError`.
    pub fn install<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        require: v8::Local<'s, v8::Function>,
    ) -> Result<Self, String> {
        // `internal/util/debuglog.js` throws from `debuglog()` until this runs.
        // Node calls it in `pre_execution.js` before any user code; `timers`
        // reaches `debuglog` on its first call, so without it every timer dies
        // with `testEnabled is not a function`.
        initialize_debug_env(scope, require)?;

        let task_queues = call_require(scope, require, "internal/process/task_queues")
            .ok_or("internal/process/task_queues could not be loaded")?;
        let setup_task_queue = function_property(scope, task_queues, "setupTaskQueue")
            .ok_or("internal/process/task_queues has no setupTaskQueue")?;
        let queue_pair = setup_task_queue
            .call(scope, v8::undefined(scope).into(), &[])
            .ok_or("setupTaskQueue threw")?;
        let next_tick =
            get(scope, queue_pair, "nextTick").ok_or("setupTaskQueue did not return nextTick")?;
        let run_next_ticks = function_property(scope, queue_pair, "runNextTicks")
            .ok_or("setupTaskQueue did not return runNextTicks")?;

        // `process.nextTick` is what `dns.lookup` and most of `lib/**` reach for.
        // Installing Node's own function means the tick queue, the async hooks
        // and the `_exiting` check all behave as Node's do.
        let global = scope.get_current_context().global(scope);
        let process = get(scope, global.into(), "process")
            .ok_or("there is no process object to install nextTick on")?;
        set(scope, process, "nextTick", next_tick)?;
        // `process._tickCallback` is the manual tick the module loader and
        // `lib/internal/process/execution.js` call between scripts.
        set(scope, process, "_tickCallback", run_next_ticks.into())?;

        let internal_timers = call_require(scope, require, "internal/timers")
            .ok_or("internal/timers could not be loaded")?;
        let get_timer_callbacks = function_property(scope, internal_timers, "getTimerCallbacks")
            .ok_or("internal/timers has no getTimerCallbacks")?;
        let timer_callbacks = get_timer_callbacks
            .call(scope, v8::undefined(scope).into(), &[run_next_ticks.into()])
            .ok_or("getTimerCallbacks threw")?;
        let process_immediate = get(scope, timer_callbacks, "processImmediate")
            .ok_or("getTimerCallbacks did not return processImmediate")?;
        let process_timers = get(scope, timer_callbacks, "processTimers")
            .ok_or("getTimerCallbacks did not return processTimers")?;

        let binding = internal_binding(scope, require, "timers")
            .ok_or("internalBinding('timers') is not available")?;
        let setup_timers = function_property(scope, binding, "setupTimers")
            .ok_or("the timers binding has no setupTimers")?;
        setup_timers
            .call(scope, binding, &[process_immediate, process_timers])
            .ok_or("setupTimers rejected its callbacks")?;

        if !rn_bind_timers::timers_installed() {
            return Err("setupTimers did not store the timer callbacks".to_string());
        }

        install_timer_globals(scope, require)?;
        install_message_port_delivery(scope)?;
        // The check phase carries more than `setImmediate`: a `MessagePort` is
        // delivered from it, and a ref'd port keeps the process alive without
        // owning a libuv handle of its own. Both facts live in
        // `rn-bind-messaging`, so the owner of the phase is told about them.
        //
        // This has to happen here, at install time, and not when the loop starts:
        // `postMessage()` from the script body queues a delivery *before* the
        // loop exists, and it is `schedule` that arms the check handle. Wiring
        // these up lazily left the first message unarmed, so the loop saw no
        // work and exited.
        rn_bind_timers::set_check_phase_hook(|scope| {
            let _ = rn_bind_messaging::run_message_ports(scope);
        });
        rn_bind_timers::set_check_phase_pending(rn_bind_messaging::has_delivery_pending);
        rn_bind_messaging::set_check_phase_armed(rn_bind_timers::arm_check_phase);
        Ok(Self {
            run_next_ticks: v8::Global::new(scope, run_next_ticks),
        })
    }

    /// The `runNextTicks` function, as a local handle for `scope`.
    fn run_next_ticks<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Function> {
        v8::Local::new(scope, &self.run_next_ticks)
    }

    /// Drains ticks and microtasks once, outside a loop turn.
    ///
    /// Node does this right after the script body, before the loop starts, which
    /// is why `process.nextTick` and `queueMicrotask` callbacks from the script
    /// run before a 0ms timer.
    pub fn drain(&self, scope: &mut v8::PinScope) {
        let run_next_ticks = self.run_next_ticks(scope);
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let _ = run_next_ticks.call(scope, v8::undefined(scope).into(), &[]);
        if scope.has_caught() {
            // A terminated isolate reports `has_caught()` with no exception: V8
            // aborts the call at a safepoint, which is what
            // `worker.terminate()` produces, and it is not an error the realm
            // should report. Treating it as one posted a serialized `null` to the
            // parent, which surfaced as `Uncaught null: null` and an
            // `ERR_UNHANDLED_ERROR` from `Worker.emit` — after a terminate that
            // had worked perfectly. Node distinguishes the two with
            // `TryCatchScope::HasTerminated`.
            if scope.has_terminated() {
                return;
            }
            if let Some(exception) = scope.exception() {
                report_uncaught(scope, exception);
            }
        }
    }
}

/// Reports an uncaught exception and asks the process to exit non-zero.
///
/// A callback that throws is a candidate for `process.setUncaughtExceptionCaptureCallback`
/// and for an `uncaughtException` listener, so the report goes through Node's
/// own order (`process._fatalException` first) rather than printing directly.
/// When nothing handles it, the print-and-exit path still runs unchanged.
fn report_uncaught(scope: &mut v8::PinScope, exception: v8::Local<v8::Value>) {
    rn_errors::report_uncaught_exception(scope, exception);
}

/// Runs `internal/util/debuglog`'s `initializeDebugEnv`, which Node's
/// `pre_execution.js` does before any user code.
///
/// Without it `debuglog()` throws from `timers`' first call —
/// `internal/timers.js`'s `debug()` included — which makes every timer fail with
/// `testEnabled is not a function`. It takes `process.env.NODE_DEBUG`, which a
/// script is entitled to set.
fn initialize_debug_env<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) -> Result<(), String> {
    let debuglog = call_require(scope, require, "internal/util/debuglog")
        .ok_or("internal/util/debuglog could not be loaded")?;
    let initialize = function_property(scope, debuglog, "initializeDebugEnv")
        .ok_or("internal/util/debuglog has no initializeDebugEnv")?;
    let global = scope.get_current_context().global(scope);
    let process = get(scope, global.into(), "process").ok_or("there is no process object")?;
    let env = get(scope, process, "env").unwrap_or_else(|| v8::undefined(scope).into());
    let node_debug = if env.is_object() {
        get(scope, env, "NODE_DEBUG").unwrap_or_else(|| v8::undefined(scope).into())
    } else {
        v8::undefined(scope).into()
    };
    initialize
        .call(scope, debuglog, &[node_debug])
        .ok_or("initializeDebugEnv threw")?;
    Ok(())
}

/// Installs Node's eval-mode builtin globals.
///
/// `node -e` and `node --eval` expose every requireable builtin as a lazy global
/// (`lib/internal/main/eval_string.js` calls `addBuiltinLibsToObject` for exactly
/// this reason), so `net.createServer()` works without a `require`. A script file
/// does not get them, which is why this is separate from [`install_timer_globals`]
/// and only called for `-e`.
///
/// A failure is reported rather than fatal: the globals are a convenience, and a
/// script that does its own `require` still works without them.
pub fn install_eval_builtins<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) -> Result<(), String> {
    let helpers = call_require(scope, require, "internal/modules/helpers")
        .ok_or("internal/modules/helpers could not be loaded")?;
    let add = function_property(scope, helpers, "addBuiltinLibsToObject")
        .ok_or("internal/modules/helpers has no addBuiltinLibsToObject")?;
    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "<eval>").ok_or("cannot allocate the eval module name")?;
    add.call(scope, helpers, &[global.into(), name.into()])
        .ok_or("addBuiltinLibsToObject threw")?;
    Ok(())
}

/// Installs the timer globals the way Node's `exposed-window-or-worker.js` does.
///
/// `timers` is `require('timers')`, so the globals are the module's own
/// functions and `require('timers').setTimeout === setTimeout` holds, which is
/// observable and is what `lib/net.js` relies on.
fn install_timer_globals<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) -> Result<(), String> {
    let timers = call_require(scope, require, "timers").ok_or("the timers module is missing")?;
    let global = scope.get_current_context().global(scope);
    for name in [
        "clearImmediate",
        "clearInterval",
        "clearTimeout",
        "setImmediate",
        "setInterval",
        "setTimeout",
    ] {
        let value =
            get(scope, timers, name).ok_or_else(|| format!("the timers module has no {name}"))?;
        define_global(scope, global, name, value)?;
    }

    let task_queues = call_require(scope, require, "internal/process/task_queues")
        .ok_or("internal/process/task_queues could not be loaded")?;
    let queue_microtask = get(scope, task_queues, "queueMicrotask")
        .ok_or("internal/process/task_queues has no queueMicrotask")?;
    define_global(scope, global, "queueMicrotask", queue_microtask)?;
    Ok(())
}

/// Installs the `emitMessage` function a `MessagePort` delivers through.
///
/// `lib/internal/worker/io.js` builds its ports on top of
/// `internal/per_context/messageport`'s `emitMessage`, which Node's
/// `GetEmitMessageFunction` looks up on the per-context exports object. That
/// object does not exist here, so the builtin is compiled once and the function
/// it produces is rooted by the messaging binding.
///
/// A failure is reported rather than fatal, for the same reason a missing timer
/// is: a script that never creates a port runs fine, and saying why delivery
/// will not happen is more useful than refusing to start.
fn install_message_port_delivery(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    // `internal/per_context/messageport` is a per-context script, so it compiles
    // as a function taking `(exports, primordials, privateSymbols,
    // perIsolateSymbols)`. `rn-builtins::compile` is what applies that kind's
    // parameter names.
    let result = rn_bind_messaging::install_emit_message(scope, |scope| {
        let builtin = rn_js2c::builtin_by_id("internal/per_context/messageport")?;
        rn_builtins::compile(scope, builtin.id(), builtin.source(), builtin.kind())
    });
    result
}

/// Defines `name` on the global object as a writable, enumerable, configurable
/// data property, matching `defineOperation` in `internal/util.js`.
fn define_global(
    scope: &mut v8::PinScope,
    global: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a global name")?;
    if global
        .define_own_property(scope, key.into(), value, v8::PropertyAttribute::NONE)
        .is_none()
    {
        return Err(format!("cannot define the global {name}"));
    }
    Ok(())
}

/// The scheduler the loop drives: V8's microtask checkpoint and the exit flag.
///
/// The timers themselves are not here. They are libuv handles
/// (`rn_bind_timers`), so `uv_run` runs them; this type exists for the two
/// questions libuv cannot answer — "drain the JavaScript queues" and "did the
/// script ask to exit".
pub struct V8Scheduler<'a, 's, 'i> {
    scope: &'a mut v8::PinScope<'s, 'i>,
    hooks: &'a Runtime,
}

impl<'a, 's, 'i> V8Scheduler<'a, 's, 'i> {
    pub fn new(scope: &'a mut v8::PinScope<'s, 'i>, hooks: &'a Runtime) -> Self {
        Self { scope, hooks }
    }

    /// Calls `callable`, converting a throw into an exit request.
    ///
    /// The result is dropped rather than returned because a `Local` from inside
    /// the `TryCatch` scope cannot escape it. No phase needs the value back,
    /// which keeps everything they observe in this scheduler's own scope.
    fn call_catching(&mut self, callable: v8::Local<v8::Function>) {
        let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *self.scope));
        let scope = &mut try_catch.init();
        let _ = callable.call(scope, v8::undefined(scope).into(), &[]);
        if scope.has_caught() {
            if let Some(exception) = scope.exception() {
                report_uncaught(scope, exception);
            }
        }
    }
}

impl Scheduler for V8Scheduler<'_, '_, '_> {
    fn drain(&mut self) {
        // The inspector's reader threads queue CDP messages and ask for a check phase
        // through `native_immediates`, but the immediate only runs if the loop reaches
        // the check phase — which it will not when a debugger is the only thing
        // keeping the process alive. Draining here means a message is dispatched on the
        // first turn after it arrives either way.
        //
        // Before the ticks, because `Runtime.runIfWaitingForDebugger` may queue work
        // that a tick callback would otherwise run first, and Node dispatches protocol
        // messages before running the queues.
        rn_bind_inspector::drain_attached(self.scope);

        let run_next_ticks = self.hooks.run_next_ticks(self.scope);
        self.call_catching(run_next_ticks);
    }

    fn exit_requested(&self) -> bool {
        rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED)
    }

    fn has_external_work(&self) -> bool {
        // A ref'd receiving `MessagePort` pins the process open in Node even
        // though it owns no libuv handle, so libuv's own liveness answer is
        // incomplete without it.
        if rn_bind_messaging::has_message_port_work() {
            return true;
        }
        // A debugger being attached keeps `node --inspect` alive after the script
        // finishes, which is what lets a client evaluate in a process that has already
        // run its entry point. Node's `Agent::IsActive` does the same.
        if rn_bind_inspector::is_attached() || rn_bind_inspector::has_pending_messages() {
            return true;
        }
        // A running `Worker` has its own loop on another thread, so nothing on
        // this loop is ref'd while it runs. Without this the parent returned
        // idle the moment the script ended, before a worker had printed anything.
        rn_bind_timers::has_external_work()
    }

    fn before_exit(&mut self) -> bool {
        emit_before_exit(self.scope, self.hooks) == Settled::Revived
    }
}

/// Runs the loop until nothing is left and returns why it stopped.
pub fn run_loop<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    hooks: &Runtime,
) -> Result<StopReason, String> {
    let mut event_loop = Loop::new(rn_io::Backend::Libuv)?;
    let mut scheduler = V8Scheduler::new(scope, hooks);
    Ok(event_loop.run(&mut scheduler, u32::MAX))
}

/// Whether the loop still has work after an idle `beforeExit` was emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// Nothing was scheduled: the process may run its `exit` sequence.
    Idle,
    /// A handler scheduled work, so the loop has to run again.
    Revived,
}

/// Emits `beforeExit` once and reports whether it left work behind.
///
/// This is Node's `EmitProcessBeforeExit` (`src/api/hooks.cc`), called from the
/// place `SpinEventLoopInternal` (`src/api/embed_helpers.cc`) calls it: after the
/// loop has run dry, and again after every idle the loop reaches. A handler that
/// schedules a timer, an immediate or a listening socket keeps the process alive
/// past the point where it would otherwise stop — that is the documented
/// contract, not an edge case. `internal/test_runner/harness.js` is built on it
/// (its `exitHandler` waits for pending subtests from `beforeExit`), and
/// `test/parallel/test-process-beforeexit.js` exists to pin the revive-and-repeat
/// behaviour.
///
/// The handler's argument is the code the process would exit with right now,
/// which is what Node passes.
///
/// Liveness is re-read after the emit, exactly as Node does, because scheduling
/// work from the handler is only observable that way. A `nextTick` or a
/// microtask does not count: Node runs those during the emit's own checkpoint and
/// still exits, which is why `test-process-beforeexit.js` expects a `nextTick`
/// alone to end the process.
///
/// An emit that throws settles the loop rather than reviving it, which is what
/// Node's `IsNothing()` branch does: it breaks out to the exit sequence. The
/// exception has already gone through the fatal path, so by the time the caller
/// reaches `exit` the status is 1 and `exit` has usually been emitted already.
pub fn emit_before_exit(scope: &mut v8::PinScope, hooks: &Runtime) -> Settled {
    let emitted = match process_object(scope) {
        Some(process) => match function_property(scope, process.into(), "emit") {
            Some(emit) => emit_event(scope, process, emit, "beforeExit"),
            None => false,
        },
        None => false,
    };

    // Node drains the platform's queued callbacks between the emit and the
    // liveness check. Draining here also gives a handler's promises and ticks
    // the checkpoint they would get in Node, so a harness that awaits pending
    // subtests from `beforeExit` finishes before this decision is made.
    hooks.drain(scope);

    if !emitted {
        return Settled::Idle;
    }
    if rn_uv::uv_loop::is_active() || rn_bind_messaging::has_message_port_work() {
        Settled::Revived
    } else {
        Settled::Idle
    }
}

/// Runs Node's exit sequence and returns the status to terminate with.
///
/// This is `EmitProcessExitInternal` (`src/api/hooks.cc`): mark the process as
/// exiting, emit `exit` with the current code, then re-read the code because a
/// handler is allowed to change it.
///
/// The emit goes through `process.emit` rather than `process.exit`, and that
/// distinction is observable. `internal/process/per_thread.js`'s `exit` wrapper
/// also calls `process.reallyExit` after emitting, so reaching it here would run
/// a user-patched `reallyExit` a second time: Node runs it once, from the
/// explicit `process.exit()` call, and the natural exit terminates from C++
/// without going through it again.
///
/// `_exiting` is set first, exactly as `env->set_exiting(true)` does, so an
/// `exit` listener that calls `process.exit()` cannot make the event fire twice.
///
/// `when_unset` is the status Node would report if `process.exitCode` is unset:
/// `0` for a normal finish. An uncaught exception instead *overwrites*
/// `process.exitCode` with 1 before emitting, which is [`emit_exit_after_failure`].
///
/// A handler that throws is reported through Node's fatal-exception path rather
/// than swallowed. Node leaves the status alone in that case, which is why the
/// code is only defaulted to 1 when nothing set one.
pub fn emit_exit(scope: &mut v8::PinScope, when_unset: i32) -> i32 {
    let Some(process) = process_object(scope) else {
        return when_unset;
    };
    // `_exiting` is Node's own "the exit sequence already ran" flag. The fatal
    // paths set it before they emit: `internal/process/execution.js` does it
    // when an uncaught exception reaches `onGlobalUncaughtException`, and
    // `per_thread.js` does it for an explicit `process.exit()`. Node then
    // terminates from C++ without ever reaching `EmitProcessExitInternal`, so a
    // process that is already exiting must not emit again here.
    if exiting(scope, process) {
        return read_exit_code(scope).unwrap_or(when_unset);
    }
    let _ = set(
        scope,
        process.into(),
        "_exiting",
        v8::Boolean::new(scope, true).into(),
    );

    let code = read_exit_code(scope).unwrap_or(when_unset);
    let Some(emit) = function_property(scope, process.into(), "emit") else {
        return read_exit_code(scope).unwrap_or(code);
    };

    // The emit runs in its own scope: a listener's throw must not leave a
    // pending exception behind for the caller's scope to trip over.
    let threw = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let Some(name) = v8::String::new(scope, "exit") else {
            return when_unset;
        };
        let code_value = v8::Integer::new(scope, code);
        let _ = emit.call(scope, process.into(), &[name.into(), code_value.into()]);
        if scope.has_caught() {
            if let Some(exception) = scope.exception() {
                report_uncaught(scope, exception);
            }
            true
        } else {
            false
        }
    };

    match read_exit_code(scope) {
        Some(code) => code,
        None if threw => 1,
        None => when_unset,
    }
}

/// Runs the exit sequence after an uncaught exception.
///
/// This is `internal/process/execution.js`'s handler, which does not merely
/// default the status: it writes `kGenericUserError` over whatever the script
/// had put in `process.exitCode` before emitting, so `process.exitCode = 3;
/// throw new Error()` exits 1 in Node rather than 3. The handler still runs, and
/// a code it sets is what the process ends with.
pub fn emit_exit_after_failure(scope: &mut v8::PinScope) -> i32 {
    if let Some(process) = process_object(scope) {
        let _ = set(
            scope,
            process.into(),
            "exitCode",
            v8::Integer::new(scope, 1).into(),
        );
    }
    emit_exit(scope, 1)
}

/// Whether `process._exiting` says the exit sequence already ran.
fn exiting<'s>(scope: &mut v8::PinScope<'s, '_>, process: v8::Local<'s, v8::Object>) -> bool {
    get(scope, process.into(), "_exiting").is_some_and(|value| value.is_true())
}
/// The `process` object, when the realm bootstrap installed one.
fn process_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let process = get(scope, global.into(), "process")?;
    v8::Local::<v8::Object>::try_from(process).ok()
}

/// `process.exitCode`, or `None` when it is unset.
fn read_exit_code(scope: &mut v8::PinScope) -> Option<i32> {
    let process = process_object(scope)?;
    let code = get(scope, process.into(), "exitCode")?;
    if code.is_undefined() || code.is_null() {
        return None;
    }
    code.integer_value(scope).map(|code| code as i32)
}

/// Emits one process-lifecycle event with its status argument.
///
/// Returns whether the emit completed. A handler's throw is handed to Node's
/// fatal-exception path rather than escaping into the caller: `beforeExit` is
/// not inside any `try` the user wrote, so the exception is uncaught there just
/// as it is in Node, which prints it and decides the exit status.
fn emit_event(
    scope: &mut v8::PinScope,
    process: v8::Local<v8::Object>,
    emit: v8::Local<v8::Function>,
    event: &str,
) -> bool {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let Some(name) = v8::String::new(scope, event) else {
        return false;
    };
    let code = read_exit_code(scope).unwrap_or(0);
    let code = v8::Integer::new(scope, code);
    let _ = emit.call(scope, process.into(), &[name.into(), code.into()]);
    if scope.has_caught() {
        if let Some(exception) = scope.exception() {
            report_uncaught(scope, exception);
        }
        return false;
    }
    true
}

fn call_require<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    id: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let id = v8::String::new(scope, id)?;
    require
        .call(scope, v8::undefined(scope).into(), &[id.into()])
        .filter(|value| !value.is_undefined())
}

fn internal_binding<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let realm = call_require(scope, require, "internal/bootstrap/realm")?;
    let binding = get(scope, realm, "internalBinding")?;
    let binding = v8::Local::<v8::Function>::try_from(binding).ok()?;
    let name = v8::String::new(scope, name)?;
    binding.call(scope, v8::undefined(scope).into(), &[name.into()])
}

fn get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Value>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let object = v8::Local::<v8::Object>::try_from(object).ok()?;
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

fn function_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Value>,
    name: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    v8::Local::<v8::Function>::try_from(get(scope, object, name)?).ok()
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Value>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let object = v8::Local::<v8::Object>::try_from(object)
        .map_err(|_| format!("{name} cannot be set on a non-object"))?;
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

thread_local! {
    /// The runtime installed on this thread.
    ///
    /// `Runtime::install` returns the value for a caller that wants to hold it,
    /// but the worker's loop needs it after the install call has returned and a
    /// `Scheduler` cannot own it (the `Scheduler` is created per run). Recording
    /// it here is the same arrangement `rn_bind_options::parsed` uses for the
    /// option store: one per thread, replaced rather than accumulated.
    static INSTALLED: std::cell::RefCell<Option<Runtime>> = const { std::cell::RefCell::new(None) };
}

/// Installs the runtime and records it for this thread.
///
/// This is what a realm that drives its own loop calls. The CLI keeps the
/// returned value instead, because it constructs the loop itself.
pub fn install_runtime<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    require: v8::Local<'s, v8::Function>,
) -> Result<(), String> {
    let runtime = Runtime::install(scope, require)?;
    INSTALLED.with(|slot| *slot.borrow_mut() = Some(runtime));
    Ok(())
}

/// Runs `body` with the runtime installed on this thread, or returns `None`.
///
/// The worker's loop needs the runtime after `install_runtime` has returned, and
/// a `Scheduler` cannot own it because the `Scheduler` is created per run.
/// Recording it per thread is the same arrangement `rn_bind_options::parsed`
/// uses for the option store.
pub fn with_runtime<R>(body: impl FnOnce(&Runtime) -> R) -> Option<R> {
    INSTALLED.with(|slot| slot.borrow().as_ref().map(body))
}

/// Whether the recorded runtime says the loop should stop.
///
/// This is the `Scheduler` answer without a `Scheduler`, for a caller that is
/// between two runs.
#[must_use]
pub fn runtime_exit_requested() -> bool {
    rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED)
}

/// Whether the recorded runtime has work outside libuv.
///
/// A ref'd receiving `MessagePort` pins a loop open in Node even though it owns
/// no libuv handle, so libuv's own liveness answer is incomplete without it.
#[must_use]
pub fn runtime_has_external_work() -> bool {
    rn_bind_messaging::has_message_port_work()
}

/// Clears the recorded runtime, so a new realm on this thread cannot inherit the
/// hooks of the isolate that ran before it.
pub fn clear_runtime() {
    INSTALLED.with(|slot| *slot.borrow_mut() = None);
}
