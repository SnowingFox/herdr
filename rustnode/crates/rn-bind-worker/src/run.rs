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
    /// Set by the near-heap-limit callback, so the parent raises
    /// `ERR_WORKER_OUT_OF_MEMORY` for this worker.
    pub out_of_memory: Arc<std::sync::atomic::AtomicBool>,
    /// Where this thread records an `ERR_WORKER_INIT_FAILED` it hit while setting
    /// itself up.
    ///
    /// `WorkerThreadData`'s constructor and `Worker::Run` both `Exit` with this
    /// error before returning, which is what makes a worker that could not build
    /// its loop or its realm raise `error` on the parent side instead of ending
    /// silently. The slot is the handle's, so the parent's check phase reads what
    /// this thread wrote.
    pub init_failure: Arc<std::sync::Mutex<Option<crate::handle::WorkerInitFailure>>>,
}

/// The diagnostic options a worker was started with.
///
/// Resolved once in [`WorkerThread::run_inner`], before the isolate exists,
/// because `--trace-uncaught` has to be registered on `&mut Isolate` while
/// `--trace-exit` and `--stack-trace-limit` are read later by the exit path.
/// Node keeps the same three on `EnvironmentOptions` and reads them at the same
/// two points (`WorkerThreadData`'s constructor for the capture,
/// `Environment::Exit` for the warning).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerDiagnostics {
    /// `--trace-exit`, for the environment-exit warning.
    pub trace_exit: bool,
    /// `--trace-uncaught`, for both the V8 capture and the `Thrown at:` block.
    pub trace_uncaught: bool,
    /// `--stack-trace-limit`, which both of the above use for their frame count.
    pub stack_trace_limit: i32,
    /// `--zero-fill-buffers`, for every buffer this worker allocates.
    pub zero_fill_buffers: bool,
}

impl WorkerDiagnostics {
    /// Reads the three options out of a parsed store.
    ///
    /// The store is the worker's own `execArgv` — either the explicit list the
    /// constructor was given or the parent's, which
    /// `src/node_worker.cc:701` inherits when `options.execArgv` was absent.
    #[must_use]
    pub fn from_store(store: &rn_bind_options::Store) -> Self {
        let flag = |name: &str| {
            matches!(
                store.value_of(name),
                Some(rn_bind_options::ParsedValue::Bool(true))
            )
        };
        // `--stack-trace-limit` is an `int64` option and V8 takes an `i32`, so
        // the conversion saturates rather than truncating: a limit beyond
        // `i32::MAX` asks for everything, and a negative one asks for nothing.
        let stack_trace_limit = match store.value_of("--stack-trace-limit") {
            Some(rn_bind_options::ParsedValue::Int(value)) => {
                i32::try_from(value).unwrap_or(if value < 0 { i32::MIN } else { i32::MAX })
            }
            Some(_) | None => 10,
        };
        Self {
            trace_exit: flag("--trace-exit"),
            trace_uncaught: flag("--trace-uncaught"),
            stack_trace_limit,
            zero_fill_buffers: flag("--zero-fill-buffers"),
        }
    }
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

    /// Records an `ERR_WORKER_INIT_FAILED` for the parent to raise.
    ///
    /// `w->Exit(ExitCode::kGenericUserError, "ERR_WORKER_INIT_FAILED", reason)` in
    /// `src/node_worker.cc` does exactly two things this needs: it records the
    /// custom error and exits with code 1. The exit code is the caller's return
    /// value; the record is this, and the parent's check phase turns it into the
    /// `error` event.
    fn record_init_failure(&self, failure: crate::handle::WorkerInitFailure) {
        match self.init_failure.lock() {
            Ok(mut slot) => {
                if slot.is_none() {
                    *slot = Some(failure);
                }
            }
            // A poisoned lock means the worker thread panicked while recording a
            // failure, which is a bug in this module rather than in the worker.
            // Losing the message is the only remaining option, so it is logged.
            Err(_) => tracing::error!("a worker's init failure could not be recorded"),
        }
    }

    /// [`Self::record_init_failure`] for a setup step that can lose a race with
    /// `terminate()`.
    ///
    /// A `terminate()` during startup is not an initialization failure: Node's
    /// `Worker` reports the termination and nothing else, because
    /// `test-worker-message-port-transfer-terminate.js` creates ten workers and
    /// terminates each one on the next `setImmediate`, which regularly lands
    /// mid-bootstrap. Recording the failure there turned a requested shutdown
    /// into an `error` event carrying `ERR_WORKER_INIT_FAILED`, and that test
    /// asserts the process does not crash on it.
    fn record_init_failure_unless_stopping(&self, failure: crate::handle::WorkerInitFailure) {
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        self.record_init_failure(failure);
    }

    fn run_inner(&self) -> i32 {
        // `src/node_worker.cc:701`: when `options.execArgv` was not an array,
        // the worker inherits the parent's `env->exec_argv()`, and
        // `per_isolate_opts` is the parent's clone. rustnode records the parent's
        // list in the hook slot for exactly this.
        //
        // Resolved here, before the isolate exists, because two of the values
        // are isolate-level: `--trace-uncaught` turns on V8's capture of the
        // stack behind an uncaught exception, which can only be set on
        // `&mut Isolate`. Node makes the same decision at the same point, in
        // `WorkerThreadData`'s constructor before `NewIsolate`.
        // The list was resolved on the creating thread, which is the one that
        // owns `env->exec_argv()` for this worker: `WorkerImpl` inherits the
        // creator's list when `options.execArgv` was absent, so `self.exec_argv`
        // is already the answer and an empty list here means the creator really
        // had no flags. Re-reading the hook slot from *this* thread would look up
        // the wrong environment's list — the worker thread starts with empty
        // thread-locals, so the lookup could only ever find the process's.
        let exec_argv = self.exec_argv.clone();
        // The inherited list is re-parsed with the real option parser rather
        // than scanned, so `--no-trace-exit` after `--trace-exit` keeps its
        // meaning and a worker cannot end up with a value the parent's own
        // parser disagreed with.
        let worker_options = rn_bind_options::Store::parse(&exec_argv);
        // The parse above is what `internalBinding('options')` has to answer
        // from, not a local used only for the diagnostics read below it. Node
        // gives every worker its own `PerIsolateOptions` built from this list
        // (`src/node_worker.cc`), and `pre_execution.js` consults that store for
        // every `--experimental-*` gate. Leaving it uninstalled meant a worker
        // built its options from the *parent's* `internalBinding('options')`, so
        // `new Worker(..., { execArgv: ['--experimental-web-worker'] })` reported
        // `getOptionValue('--experimental-web-worker') === false` and
        // `pre_execution` deleted the `Worker` global that
        // `exposed-window-or-worker` had just defined. That is what
        // `test-common-wpt-backends.js` trips over: its runner passes the flag
        // through `execArgv` only, so the WPT worker thread had no `Worker`.
        //
        // This runs on the worker's own thread, before the isolate exists, and
        // `install` publishes a thread-local as well as the process-wide handle,
        // so the worker sees its own list while the parent keeps its own.
        //
        // The *inherited* case is not re-parsed: `src/node_worker.cc:702-704`
        // copies the parent's `exec_argv` and **clones the parent's
        // `per_isolate_opts`**, so a worker sees the values this process already
        // holds — including the ones `main` corrected after parsing. A worker
        // that re-parsed the raw list would put `--strip-types` back to `true`
        // for a build with no amaro, which is exactly what
        // `rn-cli`'s `a_worker_reads_the_option_values_this_process_was_started_with`
        // pins.
        if self.request.exec_argv_inherited {
            match self.request.inherited_store.as_ref() {
                Some(parent) => rn_bind_options::parsed::install((**parent).clone()),
                None => rn_bind_options::parsed::install(worker_options.clone()),
            }
        } else {
            rn_bind_options::parsed::install(worker_options.clone());
        }
        // A worker's `env->exec_argv()` is its *own* list, and the workers it
        // creates inherit that one rather than the process's. Recording it on
        // this thread is what makes the inheritance per-environment, the way
        // Node's field is; without it a nested worker read the CLI's list from
        // the process-wide slot and lost whatever `execArgv` its parent was
        // given.
        rn_core::hook_slot::set_thread_exec_argv(exec_argv.clone());
        let diagnostics = WorkerDiagnostics::from_store(&worker_options);
        let worker_trace_uncaught = diagnostics.trace_uncaught;
        let worker_stack_trace_limit = diagnostics.stack_trace_limit;

        // ---- 1. the isolate -------------------------------------------------
        // `WorkerThreadData` calls `SetIsolateCreateParamsForNode` and then
        // `UpdateResourceConstraints` (`src/node_worker.cc:180-182`), in that
        // order and for a reason: the machine's memory configures only the
        // limits `resourceLimits` did not name, so a worker asking for
        // `maxOldGenerationSizeMb: 16` keeps 16 MB of old generation while its
        // young generation still comes from the machine.
        //
        // Leaving the first call out is what made
        // `test-worker-resource-limits` abort: the 16 MB old generation was
        // honoured against V8's browser semi-space, and the heap floor that
        // leaves is above what the test allocates.
        let mut params = rn_core::set_isolate_create_params_for_node(
            v8::CreateParams::default(),
            rn_uv::memory::constrained_memory(),
            rn_uv::memory::total_memory(),
        );
        let limits = self.request.resource_limits;
        let [young, old, code_range, _stack] = limits;
        let stack_limit = crate::stack::stack_limit(limits);
        // `Worker::UpdateResourceConstraints` sets `constraints->set_stack_limit`
        // from the worker thread's own stack base before creating the isolate.
        // This pointer is into the current thread's stack and remains valid for
        // the isolate's lifetime because the isolate is owned and dropped on this
        // same thread.
        params = unsafe { params.set_stack_limit(stack_limit) };
        if young > 0.0 {
            params = params.set_max_young_generation_size_in_bytes(mb(young));
        }
        if old > 0.0 {
            params = params.set_max_old_generation_size_in_bytes(mb(old));
        }
        if code_range > 0.0 {
            params = params.set_code_range_size_in_bytes(mb(code_range));
        }

        // Every isolate gets its own counting allocator, not just the main one:
        // `arrayBuffers` is per `Environment` in Node, and the pinned oracle
        // reports a worker's own buffers (`0.13` for an empty worker while the
        // parent holds 64 MiB) rather than the process total. Creating this
        // isolate without one would leave `process.memoryUsage().arrayBuffers`
        // reading zero inside every worker.
        let mut isolate = v8::Isolate::new(rn_core::with_counted_array_buffer_allocator(params));
        // The first isolate enter recomputes stack limits from V8 flags.
        // `Worker::Run` resets the worker-specific limit immediately after.
        unsafe { rn_v8_sys::set_isolate_stack_limit(&isolate, stack_limit as usize) };
        // Microtasks are explicit, exactly as on the main thread: Node's tick
        // queue must beat a `.then`, and the default `Auto` policy would invert
        // that.
        isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
        // `Environment::InitializeDiagnostics` for this environment: the same
        // capture the main thread's isolate gets, driven by the worker's own
        // `--trace-uncaught` rather than the parent's. A worker started with
        // `execArgv: ['--trace-uncaught']` under a parent that lacks it must
        // still trace, and the reverse must not.
        if worker_trace_uncaught {
            isolate.set_capture_stack_trace_for_uncaught_exceptions(true, worker_stack_trace_limit);
        }
        // `import.meta` and `import()` are dispatched through isolate-level
        // handlers, and a worker can `import()` too.
        rn_module_wrap::install_isolate_callbacks(&mut isolate);
        // A worker's isolate needs its own `new ShadowRealm()` hook for the same
        // reason it needs its own ESM handlers: the callback is isolate-level, so a
        // worker that skipped this would answer every `new ShadowRealm()` with
        // V8's bare `Not supported`. `test-shadow-realm-gc.js` constructs a realm
        // on the worker thread and asserts the worker exits 0.
        rn_realm::shadow_realm::install_callback(&mut isolate);
        // The promise rejection callback is per-isolate state, exactly as Node
        // sets it in `CreateIsolateData` for every isolate a worker creates. A
        // worker that skipped it would never run its own
        // `process.on('unhandledRejection')` listeners.
        rn_bind_task_queue::install_isolate_callbacks(&mut isolate);
        rn_bind_heap_utils::set_snapshot_isolate(&mut isolate);
        // A worker's snapshot must report the worker's own ports, so the walk is
        // registered against this isolate exactly as the CLI does for the main
        // thread's. Node reaches the same set through the worker's own
        // `Environment`. See `rn_bind_messaging::add_embedder_nodes`.
        let registered = unsafe {
            rn_v8_sys::register_embedder_graph(
                &isolate,
                rn_v8_sys::EmbedderGraphCallback {
                    build: Box::new(|graph| rn_bind_messaging::add_embedder_nodes(&graph)),
                },
            )
        };
        if !registered {
            tracing::debug!("worker isolate has no heap profiler; snapshots have no ports");
        }
        // Node's inspector is one `V8Inspector` per isolate, and
        // `inspector.Session()` connects to *this* isolate's inspector. The CLI
        // records the main thread's isolate for the same reason
        // (`rn_bind_inspector::set_isolate` in `main.rs`); a worker creates its own
        // isolate here, so it has to record it here. Without this the worker's
        // namespace install found no isolate, warned, and every
        // `new inspector.Session(); session.connect()` in a worker threw
        // "The inspector is not available: no isolate was recorded".
        rn_bind_inspector::set_isolate(&mut isolate);

        // `Worker::NearHeapLimit` (`src/node_worker.cc:272`). Without it a heap
        // overflow inside a worker ends in V8's own `Fatal JavaScript out of
        // memory` abort, which takes the *process* down: `test-worker-resource-
        // limits` allocates past a 16 MB old generation on purpose and expects
        // the worker to fail with `ERR_WORKER_OUT_OF_MEMORY` while the parent
        // survives and joins it.
        //
        // The callback raises the limit by 16 MB so the collection already in
        // progress can finish, records the error the parent will raise, and
        // stops the worker the way `Worker::Exit` does — which is what makes the
        // terminate land at the next safepoint instead of letting the allocation
        // continue into the allowance it just granted.
        isolate.add_near_heap_limit_callback(near_heap_limit, std::ptr::null_mut());

        if let Ok(mut slot) = self.isolate.lock() {
            *slot = Some(isolate.thread_safe_handle());
        }
        // The same handle, for the near-heap-limit callback: it runs on this
        // thread with only a data pointer, and the terminate `Worker::Exit`
        // performs has to be reachable from there. Published *before* the
        // callback can fire, which is why this comes before the realm starts.
        crate::publish_stop_handle(
            isolate.thread_safe_handle(),
            Arc::clone(&self.out_of_memory),
        );

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

        let code = self.boot_and_run(scope, &diagnostics, &exec_argv);

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
    ///
    /// `diagnostics` and `exec_argv` are resolved by [`Self::run_inner`] before
    /// the isolate exists, because one of those options is an isolate-level V8
    /// setting; passing them in keeps that ordering explicit rather than having
    /// this method re-read the environment.
    fn boot_and_run(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        diagnostics: &WorkerDiagnostics,
        exec_argv: &[String],
    ) -> i32 {
        let registry = match crate::registry::build() {
            Ok(registry) => registry,
            Err(message) => {
                tracing::error!(%message, "the worker's binding registry could not be built");
                self.record_init_failure_unless_stopping(crate::handle::WorkerInitFailure::new(
                    REGISTRY_INIT_FAILURE_REASON,
                ));
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
        // `(node:PID)` versus `(node:PID, thread:N)` is the one observable
        // difference between a main-thread and a worker `--trace-exit` warning,
        // and `test-trace-exit.js` matches the second shape for its worker
        // cases. Node reads `is_main_thread()` off the `Environment` at exit
        // time, so this has to be recorded on the thread that exits.
        rn_core::exit_state::set_environment_identity(rn_core::exit_state::EnvironmentIdentity {
            is_main_thread: false,
            thread_id: self.thread_id,
        });

        // The per-thread trace state, before the realm bootstrap reads it. The
        // isolate-level half was already set in `run_inner`; these are the two
        // flags the exit and report paths read.
        rn_core::hook_slot::set_trace_exit(diagnostics.trace_exit);
        rn_core::hook_slot::set_trace_uncaught(diagnostics.trace_uncaught);
        rn_core::hook_slot::set_stack_trace_limit(i64::from(diagnostics.stack_trace_limit));
        rn_core::hook_slot::set_zero_fill_buffers(diagnostics.zero_fill_buffers);

        let mut argv = vec![exec_path()];
        argv.extend(self.request.argv.iter().cloned());
        if let Err(message) = rn_realm::install_globals(scope, &argv) {
            tracing::error!(%message, "the worker's bootstrap globals failed");
            self.record_init_failure_unless_stopping(crate::handle::WorkerInitFailure::new(
                BOOTSTRAP_FAILURE_REASON,
            ));
            return 1;
        }

        let loaders = match rn_realm::bootstrap_realm(
            scope,
            &argv[1..],
            exec_argv,
            rn_realm::ProcessState::worker(),
        ) {
            Ok(loaders) => loaders,
            Err(message) => {
                tracing::error!(%message, "the worker's realm bootstrap failed");
                self.record_init_failure_unless_stopping(crate::handle::WorkerInitFailure::new(
                    BOOTSTRAP_FAILURE_REASON,
                ));
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
        // `install_cjs_loader` publishes a global `require` because the realm
        // bootstrap has to hand its loader to user code before the entry kind is
        // known. On the main thread the CLI deletes it again for a file entry
        // point; a worker has to do the same, and Node's answer differs by kind:
        //
        //   worker_threads eval worker      globalThis.require is a function
        //   worker_threads file worker      undefined
        //   web Worker, classic, file: URL  a function, from
        //                                   `installDedicatedWorkerGlobalScope`
        //   web Worker, module or data: URL undefined
        //
        // Each of those then arrives from the place Node gets it. `evalScript`
        // assigns `globalThis.require` for an eval worker, and
        // `internal/webworker`'s `installDedicatedWorkerGlobalScope` calls
        // `Module.createRequire(locationURL)` for a classic file worker. Leaving
        // this copy in place made all four cases report a function, which
        // `test-worker-spec-differences.js` pins as a spec difference.
        //
        // Deleting is safe for `worker_threads` because `webWorkerData` is only
        // set on the web Worker path: a plain thread never re-adds it, which is
        // exactly Node's behaviour.
        rn_realm::delete_require_global(scope);

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

        // The same wiring the main thread gets, and for the same reason: this
        // thread now runs a loop of its own, so it needs a `uv_async_t` another
        // thread can signal. Without it a `postMessage` from the parent into a port
        // this thread owns is queued and never delivered — the sender's
        // `ThreadToken::notify` finds no handle and gives up — so a worker's
        // `BroadcastChannel` never saw a post from the main thread.
        //
        // Safe on a thread that already has the handle: the second call replaces
        // the wake closure and returns the existing token.
        //
        // A failure here is a failed worker, not a warning: without this thread's
        // `uv_async_t`, `ThreadToken::notify` from the parent finds nothing, so the
        // `LOAD_SCRIPT` message the parent has already posted can never wake this
        // loop. Before this was reported, the port's queue stayed non-empty while
        // the loop spun in `has_external_work` with nothing able to drain it — the
        // fd-exhaustion repro hung for exactly this reason, because the handle is
        // created from a fresh pipe and there were none left.
        if !crate::install_check_phase() {
            tracing::error!(
                thread_id = self.thread_id,
                "the worker's cross-thread wake handle could not be created"
            );
            self.record_init_failure(crate::handle::WorkerInitFailure::new(
                WAKE_INIT_FAILURE_REASON,
            ));
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
        // `WorkerThreadData`'s constructor starts with `uv_loop_init`, and a
        // failure there is `w->Exit(kGenericUserError, "ERR_WORKER_INIT_FAILED",
        // uv_err_name_r(ret))` rather than a silent return — which is what makes a
        // worker that cannot allocate a loop (every fd in use, so libuv cannot
        // create its async pipe) raise `error` on the parent instead of hanging
        // it. `test-worker-init-failure` is the case: at `ulimit -n 128` most
        // workers in a 256-worker batch fail exactly here.
        let event_loop = match rn_io::Loop::new(rn_io::Backend::Libuv) {
            Ok(event_loop) => event_loop,
            Err(message) => {
                tracing::error!(%message, "the worker's event loop could not be created");
                self.record_init_failure(crate::handle::WorkerInitFailure::new(
                    LOOP_INIT_FAILURE_REASON,
                ));
                return 1;
            }
        };
        let mut event_loop = event_loop;
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
/// The reason a worker reports when its own event loop could not be created.
///
/// `WorkerThreadData`'s constructor reports `uv_err_name_r(ret)` here, which for
/// an exhausted fd table is `EMFILE`. rustnode's `Loop::new` reports its failure
/// as a message rather than a status, and the status is not one of the names
/// `test-worker-init-failure` accepts, so the honest answer is the code that
/// describes what happened: the loop is the platform setup that failed.
const LOOP_INIT_FAILURE_REASON: &str = "Failed to initialize the worker's event loop";

/// The reason a worker reports when its binding registry could not be built.
///
/// `internalBinding` is what every builtin module in the worker's realm resolves
/// through, so a worker that cannot build it cannot run JavaScript at all. Node
/// has no direct equivalent — its registry is built once per process — so the
/// text is rustnode's own, but the code is the one Node uses for a worker that
/// never got as far as running.
const REGISTRY_INIT_FAILURE_REASON: &str = "Failed to create the worker's binding registry";

/// The reason a worker reports when its realm bootstrap failed.
///
/// This is `Worker::Run`'s `"Failed to create new Context"` case in
/// `src/node_worker.cc:378`: the isolate exists but the realm on top of it does
/// not. rustnode's bootstrap covers the context and the registry together, so one
/// constant covers both of its failure sites.
const BOOTSTRAP_FAILURE_REASON: &str = "Failed to create new Context";

/// The reason a worker reports when its cross-thread wake handle could not be
/// created.
///
/// Node has no equivalent: a port's `uv_async_t` is created in `Worker::New` on
/// the parent's loop, and a failure there is reported through
/// `THROW_ERR_WORKER_INIT_FAILED` with the libuv name — `EMFILE` when the fd
/// table is full, which is the case the fd-exhaustion repro exercises. The
/// handle here is per thread rather than per port, so the failure lands on the
/// worker's own thread instead, but the meaning to the caller is the same: this
/// worker cannot receive anything.
const WAKE_INIT_FAILURE_REASON: &str = "Failed to initialize the worker's message channel";

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

/// `Worker::NearHeapLimit` (`src/node_worker.cc:272`).
///
/// V8 calls this when the old generation has reached its limit. Node's answer
/// is to grant 16 MB so the collection in progress can finish, remember the
/// error the parent should raise, and stop the worker; the allocation that
/// tripped the limit then fails against a heap that is closing rather than
/// aborting the process through `FatalProcessOutOfMemory`.
///
/// # Safety
///
/// Called by V8 on the worker's own thread with the `data` this was registered
/// with, which is null: the state it needs is the thread-local realm record, and
/// a pointer would have to outlive the isolate.
unsafe extern "C" fn near_heap_limit(
    _data: *mut std::ffi::c_void,
    current_heap_limit: usize,
    _initial_heap_limit: usize,
) -> usize {
    const EXTRA_HEAP_ALLOWANCE: usize = 16 * 1024 * 1024;
    // `Worker::Exit(kGenericUserError, "ERR_WORKER_OUT_OF_MEMORY",
    // "JS heap out of memory")`. The exit code and the two strings are what
    // `kOnExit` in `lib/internal/worker.js` turns into the `error` event.
    crate::record_out_of_memory();
    current_heap_limit + EXTRA_HEAP_ALLOWANCE
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
    // 0. Everything this realm registered as "must run when I go away", which is
    //    Node's `RunCleanup`. A `navigator.locks` request queued in the
    //    process-wide lock manager is the case that needs it: its environment is
    //    about to stop existing, and leaving the request (or a held lock) behind
    //    would block every other environment that asked for the same resource
    //    forever. Runs first because later steps close the handles a hook may
    //    need, and because releasing a lock can wake another thread's loop.
    //
    //    The hooks themselves are not cleared: a worker thread is one-shot, and
    //    each hook clears its own realm state, so a cleared list buys nothing and
    //    would also drop the hooks other producers registered here.
    rn_core::hook_slot::run_teardown_hooks();

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
///
/// The same condition covers a worker's own `process.exit()`. `per_thread.js`
/// sets `process._exiting` before calling `reallyExit`, and `reallyExit` then
/// terminates the isolate so the frame that called it unwinds — that is what
/// makes a second `process.exit()` unreachable rather than merely ignored, and
/// what `test-worker-voluntarily-exit-followed-by-addition.js` and
/// `-followed-by-throw.js` require. The termination surfaces here as a caught
/// callback, and without this the worker posted an unserializable "error" for an
/// exit that had already succeeded, which the parent raised as
/// `Uncaught null: null` / `ERR_UNHANDLED_ERROR`.
///
/// Both predicates are native, so the answer is the realm's real state rather
/// than a flag something has to remember to set.
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
    let Some(is_stopping) = rn_core::class(is_stopping_callback)
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
///
/// "Stopping" covers two things, both of which mean the worker may not run more
/// JavaScript: the parent asked for a terminate (`is_stopping`), and this
/// environment is already exiting — `process._exiting`, which `per_thread.js`
/// sets before `reallyExit` and which `worker_thread.js`'s own uncaught path
/// sets before its `process.exit()`. The second is what makes the termination
/// `reallyExit` raises on the way out land here instead of being reported to the
/// parent as an unserializable error.
fn is_stopping_callback(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let scope = _scope;
    let stopping = crate::is_stopping() || rn_core::exit_state::exiting();
    rv.set(v8::Boolean::new(scope, stopping).into());
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
