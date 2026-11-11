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
pub struct RuntimeHooks {
    run_next_ticks: v8::Global<v8::Function>,
}

impl RuntimeHooks {
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
    hooks: &'a RuntimeHooks,
}

impl<'a, 's, 'i> V8Scheduler<'a, 's, 'i> {
    pub fn new(scope: &'a mut v8::PinScope<'s, 'i>, hooks: &'a RuntimeHooks) -> Self {
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
        rn_bind_inspector::is_attached() || rn_bind_inspector::has_pending_messages()
    }
}

/// Runs the loop until nothing is left and returns why it stopped.
pub fn run_loop<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    hooks: &RuntimeHooks,
) -> Result<StopReason, String> {
    let mut event_loop = Loop::new(rn_io::Backend::Libuv)?;
    let mut scheduler = V8Scheduler::new(scope, hooks);
    Ok(event_loop.run(&mut scheduler, u32::MAX))
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
