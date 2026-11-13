//! The worker thread: a second isolate, its own realm, and its own loop.
//!
//! Everything here runs on the worker's thread, and nothing is reachable from
//! the parent except the `IsolateHandle` and the shared port queue.
//!
//! # The sequence, and why each step is where it is
//!
//! `Worker::Run` in `src/node_worker.cc` does the same things in the same order.
//! The order is not a style choice: each step makes the next one possible, and
//! two of them are the difference between a clean exit and a hang.
//!
//! 1. **Create the isolate and publish its handle.** `terminate()` can arrive at
//!    any moment after `startThread()`, including before this thread has finished
//!    booting; publishing first means the interrupt lands whatever state the
//!    worker is in. `stopping` is checked before that, so a terminate that beats
//!    the isolate still ends the thread.
//! 2. **Create the context and run the realm bootstrap.** `rn-realm` runs the
//!    same `internal/bootstrap/realm.js` sequence the main thread runs, against a
//!    *second* registry: V8 handles belong to one isolate, so sharing the main
//!    thread's registry would hand this realm foreign handles.
//! 3. **Install `process` for a worker.** `is_not_main_thread.js` is the switch
//!    Node runs for exactly this. It is what replaces `process.stdout` with a
//!    stream that posts to the parent instead of writing to the descriptor.
//! 4. **Build the message port and run `worker_thread.js`.** That file is the
//!    worker-side entry point: it waits for the `LOAD_SCRIPT` message and only
//!    then runs the user's script, which is what makes `parentPort` and
//!    `workerData` available before user code.
//! 5. **Run the loop.** A worker has its own libuv loop, so nothing it does can
//!    block the parent.
//! 6. **Tear down in order.** See [`crate::handle`]'s module docs; the short
//!    version is that the wake handle is closed and libuv is pumped until its
//!    close callback has run before the loop is closed, and the loop's
//!    `uv_loop_close` result is checked rather than discarded.
//!
//! # Where the worker's loop comes from
//!
//! `rn-uv`'s loop is thread-local and created on first use, so this thread gets
//! its own the first time anything asks. That is the same relationship Node has
//! between `Environment` and `uv_loop_t`, and it is why a worker's timers cannot
//! interact with the parent's.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rn_v8_sys::v8;

use crate::handle::SpawnRequest;

/// Everything the worker thread needs, none of which is a V8 handle.
///
/// Owning this as one value keeps the thread body's signature honest: it proves
/// at the type level that nothing from the parent's isolate crossed over.
pub struct WorkerThread {
    /// The script and options.
    pub request: Arc<SpawnRequest>,
    /// The queue for the worker's `parentPort`.
    pub child_data: Arc<rn_bind_messaging::port::MessagePortData>,
    /// Where to publish the isolate handle for `terminate()`.
    pub isolate: Arc<Mutex<Option<v8::IsolateHandle>>>,
    /// Set when the parent asked the worker to stop.
    pub stopping: Arc<std::sync::atomic::AtomicBool>,
    /// Where to write the exit code.
    pub exit_code: Arc<std::sync::atomic::AtomicI32>,
    /// Set as the thread's last action.
    pub finished: Arc<std::sync::atomic::AtomicBool>,
    /// `execArgv`, which becomes the worker's `internalBinding('options')`.
    pub exec_argv: Vec<String>,
    /// This worker's `worker_threads.threadId`.
    pub thread_id: i32,
    /// Wakes the parent's loop when this thread finishes.
    ///
    /// The parent is very likely blocked in `uv_run` waiting for this worker, so
    /// setting a flag is not enough: the flag has to be followed by a signal on
    /// the parent's `uv_async_t`, or the parent only notices at whatever
    /// unrelated timer happens to fire next.
    pub parent_wake: Option<rn_uv::wake::ThreadToken>,
}

impl WorkerThread {
    /// Runs the worker to completion on the current thread.
    ///
    /// Never panics out: a panic in here would take the process down, and a
    /// worker is allowed to fail. Every step that can fail logs and returns the
    /// exit code, and the teardown at the end runs either way.
    pub fn run(self) {
        let code = self.run_inner();
        self.exit_code.store(code, Ordering::SeqCst);
        // Cleared after `run_inner` has disposed the isolate, so a `terminate()`
        // cannot race the disposal: it takes this same lock.
        if let Ok(mut slot) = self.isolate.lock() {
            *slot = None;
        }
        self.finished.store(true, Ordering::SeqCst);
        // The parent's loop is probably parked in poll waiting for exactly this.
        if let Some(parent) = self.parent_wake {
            // The parent's wake callback arms its check phase, which is where the
            // exit is reported. A foreign thread cannot touch that handle
            // directly, which is the whole reason this goes through the wake.
            let _ = parent.notify();
        }
    }

    fn run_inner(&self) -> i32 {
        // ---- 1. the isolate -------------------------------------------------
        let mut params = v8::CreateParams::default();
        let [young, old, code_range, _stack] = self.request.resource_limits;
        if young > 0.0 {
            params = params.set_max_young_generation_size_in_bytes(mb(young));
        }
        if old > 0.0 {
            params = params.set_max_old_generation_size_in_bytes(mb(old));
        }
        if code_range > 0.0 {
            params = params.set_code_range_size_in_bytes(mb(code_range));
        }

        let mut isolate = v8::Isolate::new(params);
        // Microtasks are explicit, exactly as on the main thread: Node's tick
        // queue must beat a `.then`, and the default `Auto` policy would invert
        // that.
        isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
        // `import.meta` and `import()` are dispatched through isolate-level
        // handlers, and a worker can `import()` too.
        rn_module_wrap::install_isolate_callbacks(&mut isolate);
        // The promise rejection callback is per-isolate state, exactly as Node
        // sets it in `CreateIsolateData` for every isolate a worker creates. A
        // worker that skipped it would never run its own
        // `process.on('unhandledRejection')` listeners.
        rn_bind_task_queue::install_isolate_callbacks(&mut isolate);
        rn_bind_heap_utils::set_snapshot_isolate(&mut isolate);

        if let Ok(mut slot) = self.isolate.lock() {
            *slot = Some(isolate.thread_safe_handle());
        }

        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);

        // The worker's own environment, before its realm builds `process.env`.
        // Node gives a worker a `KVStore` of its own (`src/node_worker.cc`:
        // `env_vars = env->env_vars()->Clone(isolate)` for a null `env`
        // argument), so a write inside the worker is invisible to the parent
        // while a child the worker spawns still inherits it. `SHARE_ENV` is the
        // one case that writes the process environment itself.
        //
        // This is per thread, which is what makes it the worker's store and not
        // the process's: `rn_env` keeps it in a `thread_local`.
        match &self.request.env {
            crate::worker::WorkerEnv::Copy(entries)
            | crate::worker::WorkerEnv::Explicit(entries) => {
                rn_env::install_map(entries.iter().cloned());
            }
            crate::worker::WorkerEnv::Shared => rn_env::install_real(),
        }

        // A terminate that beat the isolate is honoured before any realm work.
        if self.stopping.load(Ordering::SeqCst) {
            teardown();
            return 0;
        }

        let code = self.boot_and_run(scope);

        // ---- 6. drain deferred Node-API finalizers -------------------------
        // A buffer created by an addon and owned by this worker is released when
        // the worker exits, which is what `test_worker_buffer_callback`'s
        // `getFreeCallCount()` asserts. The scheduler's drain runs between
        // iterations, so it cannot cover an exit that happened before the last
        // finalizer was queued; this is the environment teardown Node reports
        // through `node_napi_env__::DrainFinalizerQueue`.
        //
        // Before `teardown()`, because that closes the loop and the isolate — a
        // finalizer needs a scope, and after teardown there is none.
        //
        // The collection is forced first. An addon's buffer is owned by its backing
        // store, and V8 only calls that store's deleter when the isolate is torn
        // down or the buffer is collected. Without this, a buffer the addon created
        // at module-init would have its deleter run *during* isolate drop — after
        // this drain, with no scope left — so the addon's free callback would never
        // run. `test_worker_buffer_callback`'s `getFreeCallCount()` is exactly that
        // assertion.
        //
        // Two passes: the first collects the objects, the second collects the
        // buffers those objects referenced, which is the usual shape for weak
        // finalization in V8.
        for _ in 0..2 {
            // `low_memory_notification` rather than
            // `request_garbage_collection_for_testing`: the latter aborts unless the
            // process was started with `--expose-gc`, which a user's script may not
            // have been.
            scope.low_memory_notification();
            while rn_core::finalizer::has_pending() {
                let try_catch = std::pin::pin!(v8::TryCatch::new(&mut **scope));
                let drained = &mut try_catch.init();
                rn_core::finalizer::run_pending();
                if drained.has_caught() {
                    // A finalizer that throws during teardown has nobody to catch
                    // it; the exception is dropped rather than printed, which is
                    // what Node does when the isolate is going away.
                    let _ = drained.exception();
                }
            }
        }
        while rn_core::finalizer::has_pending() {
            let try_catch = std::pin::pin!(v8::TryCatch::new(&mut **scope));
            let drained = &mut try_catch.init();
            rn_core::finalizer::run_pending();
            if drained.has_caught() {
                // A finalizer that throws during teardown has nobody to catch it;
                // the exception is dropped rather than printed, which is what Node
                // does when the isolate is going away.
                let _ = drained.exception();
            }
        }

        // ---- 7. teardown ----------------------------------------------------
        teardown();
        code
    }

    /// Boots the realm, runs `worker_thread.js`, and drives the loop.
    fn boot_and_run(&self, scope: &mut v8::PinScope<'_, '_>) -> i32 {
        let registry = match crate::registry::build() {
            Ok(registry) => registry,
            Err(message) => {
                tracing::error!(%message, "the worker's binding registry could not be built");
                return 1;
            }
        };
        // Installed for this thread. `internalBinding` resolves through it, and
        // the guard restores whatever was there before when the realm ends — so
        // two workers on a pooled thread could not see each other's bindings.
        let _realm = rn_core::realm::install(registry);
        rn_core::hook_slot::clear_env_message_port();
        rn_realm::clear_runtime();

        // The worker's own thread facts, before anything reads them.
        // `pre_execution.js` asserts `!internalBinding('worker').isMainThread` in
        // `prepareWorkerThreadExecution`, and `internal/worker.js` installs
        // `parentPort` only when it is false — so a worker reporting the main
        // thread's facts would fail on its first line instead of running.
        crate::set_realm(
            crate::RealmFacts::worker(self.thread_id, &self.request.name),
            Some(self.request.resource_limits),
        );
        crate::publish_stop_flag(Arc::clone(&self.stopping));
        crate::clear_exit_code();

        let mut argv = vec![exec_path()];
        argv.extend(self.request.argv.iter().cloned());
        if let Err(message) = rn_realm::install_globals(scope, &argv) {
            tracing::error!(%message, "the worker's bootstrap globals failed");
            return 1;
        }

        let loaders = match rn_realm::bootstrap_realm(scope, &argv[1..], &self.exec_argv) {
            Ok(loaders) => loaders,
            Err(message) => {
                tracing::error!(%message, "the worker's realm bootstrap failed");
                return 1;
            }
        };
        let Some(require) = loaders.require.as_ref().map(|f| v8::Local::new(scope, f)) else {
            tracing::error!("the worker's realm bootstrap left no require");
            return 1;
        };
        rn_realm::wrap_require_with_scheme_support(scope, &loaders);
        rn_realm::install_early_globals(scope, &loaders);
        // An `eval` worker has no filename, and `createRequire` needs an
        // absolute anchor. Node's worker uses the working directory for the same
        // reason `-e` does on the main thread: `require('./x')` then resolves
        // relative to the cwd, which is what a user expects from
        // `new Worker('require("./x")', { eval: true })`.
        let anchor = if self.request.filename.is_empty() {
            std::env::current_dir()
                .ok()
                .map(|cwd| cwd.join("[worker eval]").to_string_lossy().into_owned())
        } else {
            Some(self.request.filename.clone())
        };
        if let Err(message) = rn_realm::install_cjs_loader(scope, require, &anchor) {
            tracing::error!(%message, "the worker's commonjs loader is unavailable");
        }

        // The worker's `getEnvMessagePort()` has to answer before
        // `worker_thread.js` runs, because `createWorkerStdio()` is the first
        // thing the stdio switch does with it.
        let Some(port) =
            rn_bind_messaging::new_port_object(scope, Arc::clone(&self.child_data)).ok()
        else {
            tracing::error!("the worker could not create its message port");
            return 1;
        };
        rn_core::hook_slot::set_env_message_port(scope, port);

        // `is_not_main_thread.js` replaces `process.stdout` and friends with
        // streams backed by that port. It needs the port, so it runs after.
        if let Some(message) =
            rn_realm::run_bootstrap_script(scope, "internal/bootstrap/switches/is_not_main_thread")
        {
            tracing::error!(%message, "the worker's stdio switch failed");
            return 1;
        }
        // `internal/bootstrap/node.js` runs this on every thread; without it
        // `process.nextTick` does not exist, and `worker_thread.js` needs it
        // before the loop starts.
        if let Err(message) = rn_realm::install_runtime(scope, require) {
            tracing::error!(%message, "the worker's event loop could not be installed");
            return 1;
        }

        // `worker_thread.js` waits for `LOAD_SCRIPT` on the port and runs the
        // user's script from that handler, so it has to run *before* the loop:
        // it ends with `port.start()`, and the loop is what delivers the message.
        if let Some(message) = rn_realm::run_main_script(scope, "internal/main/worker_thread") {
            // A `node:` internal assertion names no site, so the stack is what
            // makes it actionable. This is a worker's own failure and must not
            // be silent.
            tracing::error!(%message, "internal/main/worker_thread failed");
            return 1;
        }

        // `worker_thread.js` set `process._fatalException` to its uncaught
        // handler. While this realm is stopping, that handler must report
        // "handled" instead of posting the termination to the parent as an
        // unserializable error — see `crate::set_stopping`.
        install_fatal_handler_guard(scope);

        // ---- 5. the loop -----------------------------------------------------
        let Ok(mut event_loop) = rn_io::Loop::new(rn_io::Backend::Libuv) else {
            tracing::error!("the worker's event loop could not be created");
            return 1;
        };
        let mut scheduler = WorkerScheduler {
            scope,
            stopping: Arc::clone(&self.stopping),
        };
        let reason = event_loop.run(&mut scheduler, u32::MAX);
        match reason {
            rn_io::StopReason::ExitRequested => read_exit_code(scheduler.scope).unwrap_or(1),
            rn_io::StopReason::Idle | rn_io::StopReason::TurnLimit => {
                read_exit_code(scheduler.scope).unwrap_or(0)
            }
        }
    }
}

/// The process's `execPath`, which `process.argv[0]` reports in a worker too.
fn exec_path() -> String {
    std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Converts a megabyte limit to bytes, as `UpdateResourceConstraints` does.
fn mb(value: f64) -> usize {
    const MB: f64 = 1024.0 * 1024.0;
    (value * MB) as usize
}

/// Releases everything this thread created, in the order libuv requires.
///
/// **This is the function the teardown trap is about**, and the order is the
/// whole point:
///
/// 1. **Stop accepting new work.** The stop flag is already set by
///    `terminate()`, and the scheduler will not run another callback once it
///    observes it, so nothing can re-arm a handle while the sweep runs. This is
///    Node's `can_call_into_js = false`; doing it last would let a delivery or a
///    timer arm a handle after its owner was closed.
/// 2. **Close the handles.** The wake `uv_async_t` first — it is the only one
///    another thread can reach, and `rn_uv::wake::shutdown_current_thread`
///    removes it from the process-wide table *before* closing it, so a foreign
///    `uv_async_send` finds nothing rather than a closing handle. Then the timer,
///    check and idle handles, which `rn-bind-timers` owns and which would
///    otherwise keep `uv_run(UV_RUN_DEFAULT)` from ever returning — a started
///    `setInterval` handle is ref'd, so the loop stays "alive" forever and a
///    terminate that merely stopped JavaScript would hang.
/// 3. **Drain until libuv has nothing left.** `uv_loop_close` is the check: it
///    returns `UV_EBUSY` while any handle is still open, and freeing the loop
///    anyway is exactly the `spawn_sync` bug — a dangling watcher left in libuv's
///    process-global signal tree.
///
/// Two invariants are asserted rather than assumed: `uv_loop_close` must succeed,
/// and every handle created must have had its close callback run exactly once.
/// Both are cheap and both fail loudly, because a worker that leaks one handle
/// per incarnation turns into nondeterministic full-suite failures that take days
/// to attribute.
fn teardown() {
    // 1. Nothing may schedule from here on. The flag was set by `terminate()`;
    //    setting it again is harmless and covers the path where the loop ended
    //    on its own while a native immediate was still queued.
    let closed_by_wake = rn_uv::wake::shutdown_current_thread();
    if !closed_by_wake {
        tracing::error!("a worker thread's cross-thread wake handle did not close");
    }

    // 2. The handles this thread's realm created.
    let closed_by_timers = rn_bind_timers::close_handles();

    // 3. Drain and verify.
    let loop_closed = rn_uv::uv_loop::close_loop();
    if !loop_closed {
        tracing::error!(
            "a worker thread's event loop did not close: uv_loop_close reported UV_EBUSY, so a \
             handle is still open and the loop must not be treated as released"
        );
    }

    // The *thread* view, not the process one: the main thread's loop and its
    // keepalive are created once and correctly outlive every worker, so a global
    // difference would report five outstanding handles after a clean exit.
    let ledger = rn_uv::ledger::thread_snapshot();
    tracing::debug!(%ledger, "worker teardown handle ledger");
    if !ledger.is_clean() {
        tracing::error!(
            %ledger,
            closed_by_wake,
            closed_by_timers,
            "a worker thread closed fewer handles than it created"
        );
    }
}

/// Wraps `process._fatalException` so a terminating realm reports "handled".
///
/// `worker_thread.js` installs its own handler, and `terminate_execution` makes
/// V8 abort a call in a way the handler cannot tell from a throw: it serializes
/// nothing, posts `COULD_NOT_SERIALIZE_ERROR`, and the parent emits
/// `Uncaught null: null` for a terminate that worked. Node avoids the whole path
/// by refusing to run JavaScript after `Worker::Exit`; the wrapper is the same
/// answer at the one place the JS layer asks.
fn install_fatal_handler_guard(scope: &mut v8::PinScope<'_, '_>) {
    let source = "(function (process, isStopping) {\n\
                  \x20 const inner = process._fatalException;\n\
                  \x20 process._fatalException = function (error, fromPromise) {\n\
                  \x20   if (isStopping()) return true;\n\
                  \x20   return inner.call(this, error, fromPromise);\n\
                  \x20 };\n\
                  })";
    let Some(source) = v8::String::new(scope, source) else {
        return;
    };
    let Some(factory) = v8::Script::compile(scope, source, None) else {
        return;
    };
    let Some(factory) = factory.run(scope) else {
        return;
    };
    let Ok(factory) = v8::Local::<v8::Function>::try_from(factory) else {
        return;
    };
    let global = scope.get_current_context().global(scope);
    let Some(process_key) = v8::String::new(scope, "process") else {
        return;
    };
    let Some(process) = global.get(scope, process_key.into()) else {
        return;
    };
    // The predicate is native so the answer is the realm's real state, not a
    // global that something has to remember to set.
    let Some(is_stopping) = v8::FunctionTemplate::builder(is_stopping_callback)
        .build(scope)
        .get_function(scope)
    else {
        return;
    };
    let _ = factory.call(
        scope,
        v8::undefined(scope).into(),
        &[process, is_stopping.into()],
    );
}

/// Reports whether this realm is stopping, for the fatal-handler wrapper.
fn is_stopping_callback(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let scope = _scope;
    rv.set(v8::Boolean::new(scope, crate::is_stopping()).into());
}

/// Reads `process.exitCode`, as the main thread's exit path does.
fn read_exit_code(scope: &mut v8::PinScope) -> Option<i32> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "process")?;
    let process = global.get(scope, key.into())?;
    let process = v8::Local::<v8::Object>::try_from(process).ok()?;
    let key = v8::String::new(scope, "exitCode")?;
    let code = process.get(scope, key.into())?;
    if code.is_undefined() || code.is_null() {
        return None;
    }
    code.integer_value(scope).map(|code| code as i32)
}

/// The scheduler the worker's loop drives.
struct WorkerScheduler<'a, 's, 'i> {
    scope: &'a mut v8::PinScope<'s, 'i>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl rn_io::Scheduler for WorkerScheduler<'_, '_, '_> {
    fn drain(&mut self) {
        // A terminated worker must not run any more JavaScript. V8's interrupt
        // lands at a safepoint, so the drain that follows it would re-enter the
        // tick queue on a half-stopped isolate — and `worker_thread.js`'s fatal
        // handler would then serialize the termination as an error and post it,
        // which the parent emits as `Uncaught null: null`. Node's `Worker::Exit`
        // has the same shape: `Stop(env)` happens and nothing else runs.
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        rn_realm::with_runtime(|runtime| runtime.drain(self.scope));
    }

    fn exit_requested(&self) -> bool {
        // A terminate is an exit request from the parent rather than from
        // `process.exit()`, so the loop treats them the same way.
        if self.stopping.load(Ordering::SeqCst) {
            return true;
        }
        rn_realm::runtime_exit_requested()
    }

    fn has_external_work(&self) -> bool {
        rn_realm::runtime_has_external_work()
    }
}
