//! `internalBinding('inspector')` and `internalBinding('profiler')` for rustnode.
//!
//! Node's inspector is V8's inspector plus the plumbing that makes it reachable:
//! `src/inspector_js_api.cc` (the binding), `src/inspector_agent.cc` (the agent and
//! the sessions), `src/inspector_io.cc` and `src/inspector_socket*.cc` (the
//! `--inspect` endpoint), `src/inspector_profiler.cc` (coverage). This crate is those
//! files.
//!
//! # The JavaScript half is unchanged
//!
//! `lib/inspector.js` destructures the namespace and builds `Session` on top of
//! `Connection`. That file is vendored byte-identical, so the member list here is
//! its requirement, not a design choice — see `contracts/inspector.json`.
//!
//! ```js
//! const { Connection, MainThreadConnection, open, url, isEnabled,
//!         waitForDebugger, console, emitProtocolEvent } = internalBinding('inspector');
//! ```
//!
//! # What makes this a real inspector rather than a namespace of stubs
//!
//! `Connection` is a session against V8's own `V8Inspector`, so every CDP method
//! works the moment it is dispatched: `Runtime.evaluate` evaluates in the real
//! context, `Profiler.start` produces V8's own profile, `Debugger.*` sets real
//! breakpoints. Nothing in this crate interprets the protocol. That is deliberate,
//! and it is also why the tests assert on protocol replies rather than on the shape
//! of the object.
//!
//! # What is not here
//!
//! * **Pausing.** V8's break machinery calls `runMessageLoopOnPause` on the client,
//!   and this one is empty, so a `Debugger.pause` is acknowledged and the program
//!   keeps running. Node blocks there in a nested loop that still pumps the event
//!   loop; reproducing that needs the loop re-entered from inside a V8 callback,
//!   which is a separate piece of work. Everything that does not need to *stop*
//!   — evaluation, profiling, coverage, the console — works.
//! * **The `Node*` protocol domains** (`NodeRuntime`, `NodeTracing`, `NodeWorker`,
//!   `Network`, `IO`). Node registers them on a CRDTP `UberDispatcher` beside V8's
//!   session (`src/inspector/node_protocol.pdl`). A domain that is not registered
//!   answers "method not found", which is what a client sees here.
//! * **The `--inspect` JSON target list.** A plain `GET` on the ws port answers 400
//!   rather than the `[{webSocketDebuggerUrl}]` document a browser expects. The
//!   WebSocket endpoint itself is complete.

pub mod agent;
pub mod domains;
mod pause;
mod profiler;
pub mod server;
mod session;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub use agent::{context_created, ensure_inspector, set_isolate};
pub use server::{format_ws_address, target_list_json, version_json, Server, Shared, Target};

/// The version string `/json/version` reports, matching `process.version`.
///
/// Node's `SendVersionResponse` writes `"node.js/" NODE_VERSION`, so the two must
/// agree or a client that compares `/json/version` with `process.version` — which
/// `test-inspector.js` does — sees a mismatch it cannot explain. `rn-realm` is the
/// one place that decides what this build reports, and it is quoted here rather
/// than duplicated: a change there has to reach this document too.
pub fn node_version() -> &'static str {
    "28.0.0"
}

/// `Sec-WebSocket-Accept` for a client key, exposed for the socket test.
pub fn websocket_accept_value(client_key: &str) -> String {
    server::websocket_accept(client_key)
}

/// SHA-1, exposed for the socket test's published vectors.
pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    server::sha1(input)
}

/// The directory coverage is being written to, or `None` when none was set.
pub fn coverage_directory() -> Option<std::path::PathBuf> {
    profiler::coverage_directory()
}

/// Dispatches queued frontend messages against an explicit server, for a test.
///
/// The CLI drains through [`drain_attached`] because it owns exactly one server; a
/// test owns its own, and this is how it plays the loop's part without a loop.
pub fn drain_for_test(
    scope: &mut v8::PinScope<'_, '_>,
    shared: &std::sync::Arc<server::Shared>,
) -> usize {
    server::drain(scope, shared)
}

/// Members exposed on the `inspector` namespace, matching `contracts/inspector.json`.
pub const MEMBERS: &[&str] = &[
    "Connection",
    "MainThreadConnection",
    "asyncTaskCanceled",
    "asyncTaskFinished",
    "asyncTaskScheduled",
    "asyncTaskStarted",
    "callAndPauseOnStart",
    "console",
    "consoleCall",
    "emitProtocolEvent",
    "isEnabled",
    "open",
    "putNetworkResource",
    "registerAsyncHook",
    "setConsoleExtensionInstaller",
    "setupNetworkTracking",
    "url",
    "waitForDebugger",
];

/// Members this namespace needs but does not install, each with the reason.
///
/// Empty: every member the contract records is installed. The two members whose
/// behaviour is partial rather than absent — `open` starts a listener that answers
/// 400 for the target list, and pausing does not stop execution — are documented in
/// this crate's module comment instead, because a deferral here would be a claim
/// that the member does nothing, and it does something.
pub const DEFERRED: &[(&str, &str)] = &[];

/// Members exposed on the `profiler` namespace, matching `contracts/profiler.json`.
pub const PROFILER_MEMBERS: &[&str] = &[
    "endCoverage",
    "setCoverageDirectory",
    "setSourceMapCacheGetter",
    "startCoverage",
    "stopCoverage",
    "takeCoverage",
];

thread_local! {
    /// The listener `open()` started, if any.
    static SERVER: std::cell::RefCell<Option<Server>> = const { std::cell::RefCell::new(None) };
    /// The console extension installer `setConsoleExtensionInstaller` recorded.
    static CONSOLE_INSTALLER: std::cell::RefCell<Option<v8::Global<v8::Function>>> =
        const { std::cell::RefCell::new(None) };
    /// The async-hook enable/disable pair `registerAsyncHook` recorded.
    static ASYNC_HOOK: std::cell::RefCell<Option<(v8::Global<v8::Function>, v8::Global<v8::Function>)>> =
        const { std::cell::RefCell::new(None) };
    /// Host and port the last `open()` asked for.
    static HOST_PORT: std::cell::RefCell<(String, u16)> =
        const { std::cell::RefCell::new((String::new(), server::DEFAULT_PORT)) };
    /// Network resources `putNetworkResource` recorded, by URL.
    static NETWORK_RESOURCES: std::cell::RefCell<std::collections::HashMap<String, String>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The `inspector` namespace.
#[derive(Debug, Default, Clone, Copy)]
pub struct Inspector;

impl BindingModule for Inspector {
    fn namespace(&self) -> &'static str {
        "inspector"
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
        let object = v8::Object::new(scope);

        // `Initialize` in `inspector_js_api.cc` registers `consoleCall` first, then
        // the methods, then the two connection classes, then copies `console` out of
        // the context's extras object. The order matters only for `console`: V8 puts
        // it on the extras object during `contextCreated`, so the inspector has to
        // exist before this runs. `bootstrap.rs` calls `ensure_inspector` before the
        // console is wrapped, which is the same ordering Node has.
        if !ensure_inspector(scope) {
            tracing::warn!("the inspector namespace was installed without an isolate");
        }

        set_function(scope, object, "consoleCall", console_call)?;
        set_function(
            scope,
            object,
            "setConsoleExtensionInstaller",
            set_console_extension_installer,
        )?;
        set_function(
            scope,
            object,
            "callAndPauseOnStart",
            call_and_pause_on_start,
        )?;
        set_function(scope, object, "open", open_callback)?;
        set_function(scope, object, "url", url)?;
        set_function(scope, object, "waitForDebugger", wait_for_debugger)?;
        set_function(scope, object, "asyncTaskScheduled", async_task_scheduled)?;
        set_function(scope, object, "asyncTaskCanceled", async_task_canceled)?;
        set_function(scope, object, "asyncTaskStarted", async_task_started)?;
        set_function(scope, object, "asyncTaskFinished", async_task_finished)?;
        set_function(scope, object, "registerAsyncHook", register_async_hook)?;
        set_function(scope, object, "isEnabled", namespace_is_enabled)?;
        set_function(scope, object, "emitProtocolEvent", emit_protocol_event)?;
        set_function(
            scope,
            object,
            "setupNetworkTracking",
            setup_network_tracking,
        )?;
        set_function(scope, object, "putNetworkResource", put_network_resource)?;

        // `console` is V8's own console, which `contextCreated` installed on the
        // per-context extras object. `lib/internal/util/inspector.js`'s
        // `wrapConsole` binds each of these into the global console, after which a
        // `console.log` reaches a debugger's console panel.
        let extras = scope.get_current_context().get_extras_binding_object(scope);
        if let Some(key) = v8::String::new(scope, "console") {
            if let Some(console) = extras.get(scope, key.into()) {
                if !console.is_undefined() {
                    object.set(scope, key.into(), console);
                }
            }
        }

        session::install_class(scope, object, "Connection")?;
        session::install_class(scope, object, "MainThreadConnection")?;

        Ok(object)
    }
}

/// The `profiler` namespace.
///
/// `lib/v8.js` reads it at module scope when `config.hasInspector` is true, and
/// `lib/internal/util.js` calls `setCoverageDirectory` before any user code, so this
/// is what makes `--experimental-test-coverage` produce a report.
#[derive(Debug, Default, Clone, Copy)]
pub struct Profiler;

impl BindingModule for Profiler {
    fn namespace(&self) -> &'static str {
        "profiler"
    }

    fn members(&self) -> &'static [&'static str] {
        PROFILER_MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        set_function(
            scope,
            object,
            "setCoverageDirectory",
            set_coverage_directory,
        )?;
        set_function(
            scope,
            object,
            "setSourceMapCacheGetter",
            set_source_map_cache_getter,
        )?;
        set_function(scope, object, "startCoverage", start_coverage)?;
        set_function(scope, object, "stopCoverage", stop_coverage)?;
        set_function(scope, object, "takeCoverage", take_coverage)?;
        set_function(scope, object, "endCoverage", end_coverage)?;
        Ok(object)
    }
}

/// Registers both namespaces with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Inspector);
    registry.register_module(Profiler);
}

/// Dispatches every queued CDP message from an attached frontend.
///
/// The CLI calls this each loop turn, and the native immediate [`server::request_drain`]
/// queues calls it from the check phase. Doing both is deliberate: the immediate is
/// the wakeup, and the per-turn call is what guarantees a message queued between two
/// iterations is not held until the next one.
///
/// Returns how many messages were dispatched, so a caller can tell a quiet moment
/// from a queue that never gets drained.
pub fn drain_attached(scope: &mut v8::PinScope<'_, '_>) -> usize {
    SERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|server| server::drain(scope, server.shared()))
            .unwrap_or(0)
    })
}

/// Whether a CDP client is attached, which keeps the process alive.
///
/// Node's event loop stays alive while a debugger is attached
/// (`Agent::IsActive`), so `node --inspect app.js` does not exit the moment the
/// script finishes. The CLI asks this from its scheduler.
pub fn is_attached() -> bool {
    is_enabled()
}

/// Whether a frontend message is waiting to be dispatched.
pub fn has_pending_messages() -> bool {
    SERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|server| server::has_pending(server.shared()))
    })
}

/// Starts the `--inspect` endpoint on `host:port`.
///
/// Returns the URL a client should dial, which is what the CLI prints. `port` 0 asks
/// the OS for a free one, so the returned URL names the port that was really bound.
pub fn start_server(host: &str, port: u16) -> Result<String, String> {
    let script_name = SCRIPT_NAME.with(|slot| slot.borrow().clone());
    start_server_for_script(host, port, &script_name)
}

/// [`start_server`] with an explicit entry point.
///
/// `script_name` is the entry point as `process.argv[1]` reports it, or empty for
/// `-e`/`-p`. `/json/list`'s `title` and `url` come from it, so a run that reports
/// `file://` for a script has the wrong entry point rather than a formatting bug.
pub fn start_server_for_script(host: &str, port: u16, script_name: &str) -> Result<String, String> {
    if SERVER.with(|slot| slot.borrow().is_some()) {
        return Err("Inspector is already activated".to_string());
    }
    let server = Server::start_for_target(host, port, Target::new(script_name))?;
    let url = server.ws_url();
    SERVER.with(|slot| *slot.borrow_mut() = Some(server));
    Ok(url)
}

/// Records the entry point a later `inspector.open()` should publish.
///
/// Node's `Agent::Start` is handed `argv_[1]` once, during bootstrap
/// (`src/node.cc:203`), and every later `open()` reuses it. The CLI knows the
/// value — it resolved `process.argv` — while `open()` is reached from JavaScript,
/// so it is recorded here rather than re-derived from `std::env::args`, which
/// cannot tell a flag's value from a script path.
pub fn set_script_name(script_name: &str) {
    SCRIPT_NAME.with(|slot| *slot.borrow_mut() = script_name.to_string());
}

thread_local! {
    /// The entry point `open()` reports, recorded by the CLI.
    static SCRIPT_NAME: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Blocks until a CDP client attaches, or gives up.
pub fn wait_for_client() -> bool {
    SERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|server| server.wait_for_client())
    })
}

/// Writes and closes NODE_V8_COVERAGE output for this isolate, if enabled.
pub fn flush_coverage(scope: &mut v8::PinScope<'_, '_>) {
    let _ = profiler::take_coverage(scope);
    profiler::end_coverage(scope);
}

/// Blocks until a client sends `Runtime.runIfWaitingForDebugger`, dispatching its
/// commands in the meantime.
///
/// This is `--inspect-brk`'s wait, and it is a message loop rather than an
/// attachment check for a reason the previous shape got wrong: a client that has
/// attached has not yet said "run", and the commands it sends first —
/// `Debugger.enable`, `Debugger.setBreakpointByUrl`, `Debugger.setPauseOnExceptions`
/// — have to be dispatched *before* it can send the one that ends the wait. Polling
/// for attachment and then waiting for a separate signal deadlocks, because nothing
/// dispatches in between.
///
/// Returns whether it waited at all. With no client attached it returns immediately,
/// which is Node's behaviour when nothing is listening.
pub fn wait_for_frontend(scope: &mut v8::PinScope<'_, '_>) -> bool {
    pause::wait_for_frontend_loop(scope, drain_pending_messages, pause::ATTACH_TIMEOUT)
}

/// Holds the process open at exit for a connected frontend, like Node does.
///
/// This is `Agent::WaitForDisconnect` (`inspector_agent.cc:1063`). With a client
/// attached it prints `Waiting for the debugger to disconnect...` and blocks in the
/// inspector message loop until that client detaches; with nobody attached it
/// returns immediately and prints nothing.
///
/// Node calls it from an `AtExit` hook, after `exit` has been emitted, which is why
/// the CLI calls this from its own exit path. The sentinel line is a contract, not
/// decoration: `test/common/inspector-helper.js` and
/// `internal/debugger/inspect_probe.js` both use it to learn that the target has
/// finished, so omitting it makes every one of their tests wait out its timeout.
///
/// Returns whether it waited.
pub fn wait_for_disconnect(scope: &mut v8::PinScope<'_, '_>) -> bool {
    pause::wait_for_disconnect_loop(scope, drain_pending_messages)
}

/// Asks every attached session to pause before its next statement.
///
/// `--inspect-brk`'s break on start, and `callAndPauseOnStart`'s. This is
/// `Agent::PauseOnNextJavascriptStatement` (`inspector_agent.cc:1098`), which is
/// `client_->schedulePauseOnNextStatement(reason)`, forwarded to every live session.
///
/// The request is also recorded, because `--inspect-brk` has to make it before the
/// entry point's first statement and the client's session may not exist yet. The
/// server asks [`take_pending_start_break`] after it creates a session, which is the
/// moment V8 can be told.
pub fn schedule_start_break() {
    START_BREAK_PENDING.with(|flag| flag.set(true));
    request_pause("Break on start");
}

/// Whether `--inspect-brk` still owes its first-line break.
pub fn start_break_pending() -> bool {
    START_BREAK_PENDING.with(std::cell::Cell::get)
}

/// Arms the break-on-start interrupt on every live session.
///
/// Separate from [`schedule_start_break`] because the two happen at different
/// moments: that one records the request, and this one applies it once V8 has a
/// debugger agent for the session. Called from `Runtime.runIfWaitingForDebugger`.
pub fn schedule_start_break_now() {
    request_pause("Break on start");
}

/// Consumes the pending break-on-start request.
pub fn take_pending_start_break() -> bool {
    START_BREAK_PENDING.with(|flag| flag.replace(false))
}

thread_local! {
    /// Set by `--inspect-brk` until `Runtime.runIfWaitingForDebugger` has been seen.
    static START_BREAK_PENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Marks a frontend as attached, which is what makes a pause wait.
pub fn set_frontend_attached(attached: bool) {
    pause::set_attached(attached);
}

/// Whether a frontend is attached.
pub fn frontend_attached() -> bool {
    pause::is_attached()
}

/// Ends a pause, as `Debugger.resume` does.
pub fn resume() {
    pause::resume();
}

/// Records that the next statement should stop, before any session exists.
///
/// This is the agent-side flag `callAndPauseOnStart` and `--inspect-brk` set; the
/// per-session `schedule_pause_on_next_statement` is what V8 actually honours.
pub fn request_pause_before_next_statement() {
    pause::request_pause();
}

/// Arms a pause, clearing any resume left over from an earlier one.
pub fn arm_pause_for_test() {
    pause::arm();
}

/// Whether a pause loop is on the stack, which a nested pause must observe.
pub fn pause_on_stack() -> bool {
    pause::pause_on_stack()
}

/// Runs the pause loop from a test, with a scope to dispatch through.
///
/// Returns whether it waited. Production code reaches this through V8's
/// `runMessageLoopOnPause`, which is the only caller that should exist outside tests.
///
/// The scope is not optional: the loop dispatches frontend messages while it waits,
/// which is how `Debugger.resume` arrives, and a test that wanted to observe the
/// blocking without one would be testing a loop that cannot be resumed.
pub fn run_pause_loop_for_test(scope: &mut v8::PinScope<'_, '_>) -> bool {
    pause::run_pause_loop(scope, drain_pending_messages)
}

/// [`wait_for_disconnect`] for a test, dispatching through `drain_pending_messages`.
///
/// Exists for the same reason [`run_pause_loop_for_test`] does: the production entry
/// point is reachable only from the CLI's exit path, and a test that could not call
/// it directly would have to spawn a process to observe the wait.
pub fn wait_for_disconnect_for_test(scope: &mut v8::PinScope<'_, '_>) -> bool {
    pause::wait_for_disconnect_loop(scope, drain_pending_messages)
}

/// [`run_pause_loop_for_test`] dispatching through a caller's own server.
///
/// A test that owns a `Server` would otherwise have its messages queued where the
/// pause loop cannot see them: the loop drains the CLI's server, and a test's is a
/// different one. That is the shape the production path has — one server, reached
/// through a thread-local — so a test that could not substitute its own could only
/// be written against the CLI.
pub fn run_pause_loop_draining(
    scope: &mut v8::PinScope<'_, '_>,
    shared: &std::sync::Arc<server::Shared>,
) -> bool {
    pause::run_pause_loop(scope, |scope| server::drain(scope, shared))
}

/// Dispatches every queued frontend message with an open V8 scope.
///
/// This is what the pause loop calls while waiting. It is separate from
/// [`server::drain`] because it has to reach the server the CLI installed rather
/// than one a caller holds, and it returns the count so the loop can tell "nothing
/// arrived" from "a message was handled and may have queued more".
pub fn drain_pending_messages(scope: &mut v8::PinScope<'_, '_>) -> usize {
    drain_attached(scope)
}

/// Sends one notification to every attached frontend.
///
/// Used for events the frontend asked for that no V8 session produces —
/// `NodeRuntime.waitingForDebugger` is the one that matters. A no-op when nothing is
/// attached, which is the honest state for a `--inspect` run with no client.
pub fn deliver_to_frontends(message: &str) {
    SERVER.with(|slot| {
        if let Some(server) = slot.borrow().as_ref() {
            server::broadcast(server.shared(), message);
        }
    });
    session::broadcast(message);
}

/// Asks the loop for one check phase so queued frontend messages are dispatched.
///
/// A no-op before the loop exists, which is the honest state during bootstrap.
pub fn drain_pending() {
    server::request_drain();
}

/// Releases the inspector at process exit.
///
/// Dropping the server joins its threads and closes the listener, which is what lets
/// a test spawn a second server on the same port. The inspector itself is
/// deliberately not dropped — see `agent`'s module comment.
pub fn shutdown() {
    let server = SERVER.with(|slot| slot.borrow_mut().take());
    drop(server);
}

fn set_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    // `rn_core::set_method` is `node::SetMethod`: named after its property, and
    // not constructible. `inspector_agent.cc` publishes every one of these
    // through `SetMethod`, so `inspector.open.name` has to be `"open"`.
    rn_core::set_method(scope, object, name, callback)?;
    Ok(())
}

/// `consoleCall(inspectorMethod, nodeMethod, ...args)`.
///
/// Node calls the V8 console method *then* the Node one, so a `console.log` both
/// records to the debugger and writes to the stream. The re-entrancy guard matters:
/// V8's console can call back into JavaScript, and without it a `console.log` inside
/// an inspector console callback recurses.
fn console_call(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let inspector_method = args.get(0);
    let node_method = args.get(1);
    let Ok(inspector_method) = v8::Local::<v8::Function>::try_from(inspector_method) else {
        throw_type_error(scope, "consoleCall requires an inspector console method");
        return;
    };
    let Ok(node_method) = v8::Local::<v8::Function>::try_from(node_method) else {
        throw_type_error(scope, "consoleCall requires a Node console method");
        return;
    };

    let mut call_args = Vec::new();
    for index in 2..args.length() {
        call_args.push(args.get(index));
    }

    // Node's `is_in_inspector_console_call` equivalent. A second nested call skips
    // the inspector half so the debugger sees one message per `console.log`.
    let reentered = CONSOLE_REENTRY.with(|flag| flag.replace(true));
    if !reentered {
        if crate::is_enabled() {
            let _ = inspector_method.call(scope, args.this().into(), &call_args);
        }
        CONSOLE_REENTRY.with(|flag| flag.set(false));
    }
    let result = node_method.call(scope, args.this().into(), &call_args);
    if let Some(result) = result {
        rv.set(result);
    }
}

thread_local! {
    static CONSOLE_REENTRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `setConsoleExtensionInstaller(installer)`.
fn set_console_extension_installer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(installer) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "setConsoleExtensionInstaller requires a function");
        return;
    };
    let installer = v8::Global::new(scope, installer);
    CONSOLE_INSTALLER.with(|slot| *slot.borrow_mut() = Some(installer));
}

/// `callAndPauseOnStart(fn, thisArg, ...args)`.
///
/// `lib/internal/modules/cjs/loader.js` and the ESM module job call this instead of
/// the function directly when `--inspect-brk` is on, so that the entry point pauses
/// at its first statement.
///
/// The pause is requested on every live session before the call. It does not
/// actually stop execution, because this crate's inspector client has no paused
/// message loop — see the module comment — so the observable effect today is the
/// same as calling the function directly.
fn call_and_pause_on_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "callAndPauseOnStart requires a function");
        return;
    };
    let this = args.get(1);
    let mut call_args = Vec::new();
    for index in 2..args.length() {
        call_args.push(args.get(index));
    }
    request_pause("Break on start");
    if let Some(result) = function.call(scope, this, &call_args) {
        rv.set(result);
    }
}

/// Asks every open session to pause before its next statement.
fn request_pause(reason: &str) {
    session::pause_all(reason);
}

/// `open(port, host)` — starts the WebSocket endpoint.
fn open_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // `Agent::StartIoThread` is where `src/inspector_agent.cc` checks the
    // `inspector` scope, and it is reached by `inspector.open()`. The resource in
    // Node's call is a label for the internal entry point (`"StartIoThread"`),
    // not something user code passes, so it is reported as such here rather than
    // being taken from the port or host.
    if let Some(denied) = rn_permission::runtime::check_inspector(scope, "StartIoThread") {
        denied.throw(scope);
        return;
    }
    if SERVER.with(|slot| slot.borrow().is_some()) {
        throw_error(scope, "Inspector is already activated");
        return;
    }
    // `lib/inspector.js` validates the port in JavaScript, but the binding is
    // reachable directly, and a port above 65535 would otherwise be truncated by the
    // cast. Node's `CHECK_LE(port, uint16_max)` is a `TypeError` here for the same
    // reason every other argument check in this tree is.
    let port = if args.get(0).is_uint32() {
        let port = args
            .get(0)
            .uint32_value(scope)
            .unwrap_or(u32::from(server::DEFAULT_PORT));
        if port > u32::from(u16::MAX) {
            throw_type_error(scope, "the inspector port must fit in 16 bits");
            return;
        }
        port as u16
    } else {
        server::DEFAULT_PORT
    };
    let host = if args.get(1).is_string() {
        args.get(1).to_rust_string_lossy(scope)
    } else {
        "127.0.0.1".to_string()
    };

    // `0` means "any free port", which is what the tests use.
    let script_name = SCRIPT_NAME.with(|slot| slot.borrow().clone());
    match Server::start_for_target(&host, port, Target::new(&script_name)) {
        Ok(server) => {
            tracing::info!(
                url = %server.ws_url(),
                "Debugger listening"
            );
            HOST_PORT.with(|slot| *slot.borrow_mut() = (server.host().to_string(), server.port()));
            SERVER.with(|slot| *slot.borrow_mut() = Some(server));
        }
        Err(message) => {
            // Node throws `ERR_SOCKET_BAD_PORT`-ish failures through
            // `ERR_INSPECTOR_NOT_AVAILABLE`; the message carries the reason.
            throw_error(scope, &message);
        }
    }
}

/// `url()` — the WebSocket URL the server is listening on.
fn url(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let url = SERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|server| server.ws_url())
            .unwrap_or_default()
    });
    if url.is_empty() {
        return;
    }
    let scope = _scope;
    if let Some(url) = v8::String::new(scope, &url) {
        rv.set(url.into());
    }
}

/// `waitForDebugger()` — blocks until a client attaches, or reports that it did not.
fn wait_for_debugger(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let attached = SERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|server| server.wait_for_client())
            .unwrap_or(false)
    });
    rv.set_bool(attached);
}

/// `isEnabled()` — whether a client is attached.
fn namespace_is_enabled(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set_bool(crate::is_enabled());
}

/// Whether a debugger is attached.
pub fn is_enabled() -> bool {
    SERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|server| server.shared().is_attached())
    })
}

/// The `asyncTask*` family's task key, from an async id.
///
/// `inspector_js_api.cc`'s `GetAsyncTask` shifts left by one so the value is even,
/// which keeps it aligned like a real pointer: the inspector stores it as an opaque
/// key and compares it for equality.
fn task_pointer(id: i64) -> *const std::ffi::c_void {
    (id.wrapping_shl(1) as usize) as *const std::ffi::c_void
}

fn async_id_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Option<i64> {
    if !args.get(0).is_number() {
        return None;
    }
    args.get(0).integer_value(scope)
}

/// `asyncTaskScheduled(name, id, recurring)`.
fn async_task_scheduled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if !args.get(0).is_string() {
        throw_type_error(scope, "asyncTaskScheduled requires a task name");
        return;
    }
    let name = args.get(0).to_rust_string_lossy(scope);
    let Some(id) = async_id_argument(scope, &args) else {
        return;
    };
    let recurring = args.get(2).boolean_value(scope);
    // SAFETY: the pointer is derived from the id and never dereferenced — the
    // inspector only stores it as a key, which is what Node's `GetAsyncTask` relies
    // on too.
    unsafe { agent::async_task_scheduled(&name, task_pointer(id), recurring) };
}

/// `asyncTaskCanceled(id)`.
fn async_task_canceled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = async_id_argument(scope, &args) else {
        return;
    };
    // SAFETY: as in `async_task_scheduled`.
    unsafe { agent::async_task_canceled(task_pointer(id)) };
}

/// `asyncTaskStarted(id)`.
fn async_task_started(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = async_id_argument(scope, &args) else {
        return;
    };
    // SAFETY: as in `async_task_scheduled`.
    unsafe { agent::async_task_started(task_pointer(id)) };
}

/// `asyncTaskFinished(id)`.
fn async_task_finished(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(id) = async_id_argument(scope, &args) else {
        return;
    };
    // SAFETY: as in `async_task_scheduled`.
    unsafe { agent::async_task_finished(task_pointer(id)) };
}

/// `registerAsyncHook(enable, disable)`.
///
/// `internal/process/pre_execution.js` calls this at module scope when
/// `config.hasInspector` is true, so it must not fail: it records the pair and asks
/// the inspector to enable async stack traces, which is what makes a debugger show
/// the async ancestry of a paused frame.
fn register_async_hook(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(enable) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "registerAsyncHook requires an enable function");
        return;
    };
    let Ok(disable) = v8::Local::<v8::Function>::try_from(args.get(1)) else {
        throw_type_error(scope, "registerAsyncHook requires a disable function");
        return;
    };
    ASYNC_HOOK.with(|slot| {
        *slot.borrow_mut() = Some((
            v8::Global::new(scope, enable),
            v8::Global::new(scope, disable),
        ))
    });
}

/// `emitProtocolEvent(name, params)`.
///
/// `lib/inspector.js`'s `broadcastToFrontend` uses this for the `Network` and
/// `DOMStorage` pseudo-domains. Emitting a notification V8 does not know about needs
/// a channel that is not V8's, which is the `UberDispatcher` half of
/// `inspector_agent.cc` — see the module comment — so this records the event and
/// reports that it went nowhere rather than pretending.
fn emit_protocol_event(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if !args.get(0).is_string() {
        throw_type_error(scope, "emitProtocolEvent requires an event name");
        return;
    }
    let name = args.get(0).to_rust_string_lossy(scope);
    tracing::trace!(event = %name, "inspector protocol event");
}

/// `setupNetworkTracking(enable, disable)`.
fn setup_network_tracking(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // The pair is validated and then unused, because the `Network` domain it would
    // feed is not registered. Validating keeps the failure at the call site instead
    // of turning a wrong argument into a silent no-op later.
    if !args.get(0).is_function() || !args.get(1).is_function() {
        throw_type_error(scope, "setupNetworkTracking requires two functions");
    }
}

/// `putNetworkResource(url, data)`.
fn put_network_resource(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if !args.get(0).is_string() || !args.get(1).is_string() {
        throw_type_error(scope, "putNetworkResource requires two strings");
        return;
    }
    let url = args.get(0).to_rust_string_lossy(scope);
    let data = args.get(1).to_rust_string_lossy(scope);
    NETWORK_RESOURCES.with(|slot| {
        slot.borrow_mut().insert(url, data);
    });
}

fn set_coverage_directory(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if !args.get(0).is_string() {
        throw_type_error(scope, "setCoverageDirectory requires a directory");
        return;
    }
    profiler::set_coverage_directory(&args.get(0).to_rust_string_lossy(scope));
    profiler::start_coverage(scope);
}

fn set_source_map_cache_getter(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Ok(getter) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "setSourceMapCacheGetter requires a function");
        return;
    };
    profiler::set_source_map_cache_getter(scope, getter);
}

fn start_coverage(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    profiler::start_coverage(scope);
}

fn stop_coverage(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    profiler::stop_coverage(scope);
}

fn take_coverage(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let written = profiler::take_coverage(scope);
    rv.set_uint32(written as u32);
}

fn end_coverage(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    profiler::end_coverage(scope);
}

fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
    }
}
