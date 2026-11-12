//! The second isolate, its thread, and the lifecycle that has to be clean.
//!
//! This is `Worker` from `src/node_worker.cc` reduced to what rustnode can
//! honestly support, and the reduction is deliberate: every field exists either
//! because something reads it or because leaving it out would leak.
//!
//! # Ownership
//!
//! Three things are created per worker and each has exactly one owner:
//!
//! | thing | owned by | released by |
//! | --- | --- | --- |
//! | the OS thread | [`WorkerHandle`], joined by the parent | `join`, from the parent's check phase |
//! | the V8 isolate | the worker thread's own stack | dropping it at the end of `run_worker` |
//! | the parent-side port | the `MessagePort` object `lib/internal/worker.js` reads | the JS layer's `kDispose` |
//!
//! The parent never touches the isolate. It has an `IsolateHandle`, which is
//! V8's thread-safe handle and the only API that is legal from another thread;
//! `terminate_execution` through it is what `worker.terminate()` does.
//!
//! # The trap: teardown has to be provable, not likely
//!
//! A worker thread holds an isolate, a queue and a wake handle, and this project
//! has already been bitten by a handle that outlived the loop it was on. So
//! teardown is an ordered sequence with a test for each step, and the ordering is
//! the point:
//!
//! 1. the worker's loop stops (nothing left to run, or `terminate`),
//! 2. the wake handle is closed *and* the loop pumped until libuv has run the
//!    close callback, so `uv_loop_close` cannot return `UV_EBUSY`,
//! 3. `uv_loop_close` is called and its result is *checked*, never ignored,
//! 4. the isolate is dropped, which is the last thing that can touch a V8 heap,
//! 5. the thread exits, and the parent joins it.
//!
//! A step that fails is logged and the rest still runs, because a worker that
//! cannot clean up must not take the process with it. What must never happen is
//! a step being *skipped*: that is what leaves the dangling watcher.
//!
//! # Why there is no shared exit struct
//!
//! Node signals the parent with `SetImmediateThreadsafe` over a mutex-protected
//! `exit_code_`. Here the parent polls a flag and joins, on its own thread, in
//! its own check phase — which cannot race, because a joined thread is finished
//! by definition. The only thing that has to cross is the exit code, and that is
//! one `AtomicI32`.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use rn_v8_sys::v8;

/// How long the parent waits for the worker thread to stop after asking.
///
/// `terminate()` is expected to complete in milliseconds; this bound exists so a
/// worker that ignores a terminate fails visibly instead of hanging the parent's
/// loop forever. Node has no such bound because its `Stop(env_)` interrupts the
/// isolate, and the equivalent here is `terminate_execution`, which only takes
/// effect at a safepoint and is not guaranteed to reach one.
pub const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The request a `new Worker(...)` call carries, resolved from its arguments.
///
/// Shared with the thread through an `Arc`, because the worker needs the script
/// and the parent needs the limits back for `worker.resourceLimits`.
#[derive(Debug, Clone)]
pub struct SpawnRequest {
    /// The script: source text when `eval`, a filename otherwise.
    pub filename: String,
    /// Whether `filename` is source text rather than a path.
    pub eval: bool,
    /// `threadName`.
    pub name: String,
    /// `execArgv`, forwarded as the worker's own flags.
    pub exec_argv: Vec<String>,
    /// The resource limits, in the order `node_worker.h` declares them.
    ///
    /// `-1` for a limit the caller did not set, which is what
    /// `parseResourceLimits` in `lib/internal/worker.js` produces.
    pub resource_limits: [f64; 4],
    /// `process.argv` entries the worker appends after its own.
    pub argv: Vec<String>,
    /// The environment the worker's `process.env` starts from.
    ///
    /// Node gives each worker its own `KVStore`, so a worker's writes are its own
    /// while a child process it spawns still inherits them. `SHARE_ENV` is the
    /// exception: that worker writes the process environment directly.
    pub env: crate::worker::WorkerEnv,
}

/// One worker, as the parent thread sees it.
///
/// Created by the constructor and started by `startThread()`, matching Node's
/// two-step `Worker::New` / `Worker::StartThread`. The split matters because
/// `lib/internal/worker.js` sets `onexit` and reads `messagePort` between the
/// two calls, so the thread must not be running yet.
pub struct WorkerHandle {
    /// The OS thread, once started. Taken by [`WorkerHandle::join`], so a second
    /// join finds nothing rather than joining twice, which is undefined.
    thread: RefCell<Option<std::thread::JoinHandle<()>>>,
    /// V8's thread-safe handle to the worker's isolate.
    ///
    /// The only thing the parent may call into. `None` until the worker thread
    /// creates its isolate, and cleared *before* the isolate is disposed under
    /// this same lock, so a `terminate()` racing a worker that is already gone
    /// finds nothing rather than a stale pointer.
    isolate: Arc<Mutex<Option<v8::IsolateHandle>>>,
    /// Set by `stopThread`, read by the worker's loop and by `run_worker`
    /// before the realm exists.
    stopping: Arc<AtomicBool>,
    /// The worker's exit code, written by the worker and read by the parent.
    exit_code: Arc<AtomicI32>,
    /// Set by the worker thread as its very last action.
    ///
    /// The parent polls this instead of blocking in `join`, because a blocking
    /// join from inside the check phase would stall the parent's whole loop.
    finished: Arc<AtomicBool>,
    /// The parent-side port object.
    parent_port: RefCell<Option<v8::Global<v8::Object>>>,
    /// The worker-side queue for the same channel, handed to the thread.
    ///
    /// `Arc<MessagePortData>` and not an object, because the worker has no
    /// isolate until it starts: `CreateEnvMessagePort` builds the object around
    /// this queue on the worker's own thread.
    child_data: RefCell<Option<Arc<rn_bind_messaging::port::MessagePortData>>>,
    /// The request, shared with the thread.
    request: Arc<SpawnRequest>,
    /// The `worker_threads.threadId` both sides report.
    thread_id: i32,
    /// Whether the parent's `Worker` object counts as a ref'd handle.
    has_ref: Cell<bool>,
    /// Whether the exit has been reported, so it is reported exactly once.
    reported: Cell<bool>,
    /// The `WorkerImpl` object, weakly.
    ///
    /// The report comes from the parent's check phase, which needs the object to
    /// read `onexit` off — `lib/internal/worker.js` assigns it as a property
    /// between `new WorkerImpl` and `startThread`, so the object is the only
    /// place it exists. Weak so a worker that the script dropped can still be
    /// collected once its thread is done.
    object: RefCell<Option<v8::Weak<v8::Object>>>,
}

impl WorkerHandle {
    /// Builds the parent side of a worker that has not started yet.
    pub fn new(
        request: SpawnRequest,
        parent_port: v8::Global<v8::Object>,
        child_data: Arc<rn_bind_messaging::port::MessagePortData>,
    ) -> Self {
        Self {
            thread: RefCell::new(None),
            isolate: Arc::new(Mutex::new(None)),
            stopping: Arc::new(AtomicBool::new(false)),
            exit_code: Arc::new(AtomicI32::new(0)),
            finished: Arc::new(AtomicBool::new(true)),
            parent_port: RefCell::new(Some(parent_port)),
            child_data: RefCell::new(Some(child_data)),
            request: Arc::new(request),
            thread_id: next_thread_id(),
            has_ref: Cell::new(true),
            reported: Cell::new(false),
            object: RefCell::new(None),
        }
    }

    /// The request this worker was created with.
    #[must_use]
    pub fn request(&self) -> Arc<SpawnRequest> {
        Arc::clone(&self.request)
    }

    /// The `worker_threads.threadId` both sides report.
    #[must_use]
    pub fn thread_id(&self) -> i32 {
        self.thread_id
    }

    /// Records the `WorkerImpl` object, so the report can read `onexit` off it.
    pub fn attach_object(&self, weak: v8::Weak<v8::Object>) {
        *self.object.borrow_mut() = Some(weak);
    }

    /// The `onexit` callback `lib/internal/worker.js` assigned, if any.
    ///
    /// Read off the object rather than stored: the JS layer owns it and assigns
    /// `null` on dispose, so a copy here would be a second source of truth.
    pub fn onexit<'s>(&self, scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
        let object = self.object.borrow().as_ref()?.to_local(scope)?;
        let key = v8::String::new(scope, "onexit")?;
        let value = object.get(scope, key.into())?;
        v8::Local::<v8::Function>::try_from(value).ok()
    }

    /// The parent-side port object.
    pub fn parent_port<'s>(
        &self,
        scope: &v8::PinScope<'s, '_>,
    ) -> Option<v8::Local<'s, v8::Object>> {
        self.parent_port
            .borrow()
            .as_ref()
            .map(|port| v8::Local::new(scope, port))
    }

    /// Drops the parent-side port, which `kDispose` does after `exit`.
    pub fn clear_parent_port(&self) {
        *self.parent_port.borrow_mut() = None;
    }

    /// Takes the queue the worker thread will build its port around.
    ///
    /// Taken once: a second start has nothing to hand over, which is why
    /// [`WorkerHandle::start`] refuses a second call.
    pub fn take_child_data(&self) -> Option<Arc<rn_bind_messaging::port::MessagePortData>> {
        self.child_data.borrow_mut().take()
    }

    /// Whether `startThread` has run.
    #[must_use]
    pub fn started(&self) -> bool {
        self.thread.borrow().is_some()
    }

    /// Whether the worker thread has finished.
    #[must_use]
    pub fn exited(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }

    /// Whether the parent's loop should stay alive for this worker.
    ///
    /// `ref()` and `unref()` set the ref bit, and a worker that has finished no
    /// longer pins anything — *except* that its exit has still to be reported.
    /// The report runs in the check phase, so the loop has to survive one more
    /// iteration after the thread stops, or the process exits with `onexit`
    /// never called and `worker.on('exit')` never firing.
    ///
    /// This is `Worker::has_ref` plus the `has_ref_ && stopped_` test that
    /// decides whether the parent's environment drops a ref, extended by the
    /// outstanding report.
    #[must_use]
    pub fn keeps_loop_alive(&self) -> bool {
        if !self.started() {
            return false;
        }
        if !self.exited() {
            return self.has_ref.get();
        }
        // Finished but not yet reported: the loop still owes one check phase.
        !self.reported.get()
    }

    /// Whether the exit has already been reported.
    #[must_use]
    pub fn reported(&self) -> bool {
        self.reported.get()
    }

    /// Marks the exit as reported, returning false if it already was.
    pub fn claim_report(&self) -> bool {
        !self.reported.replace(true)
    }

    /// The exit code the worker reported, or 0 before it finished.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::SeqCst)
    }

    /// Asks the worker's isolate to stop executing.
    ///
    /// This is `Worker::Exit` reaching `env->Stop()`: `terminate_execution` is
    /// V8's own interrupt, so a worker spinning in a loop returns from it at the
    /// next safepoint instead of waiting for its next turn of the loop.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let Ok(guard) = self.isolate.lock() else {
            return;
        };
        if let Some(handle) = guard.as_ref() {
            handle.terminate_execution();
        }
    }

    /// Joins the worker thread, with a bound.
    ///
    /// Returns whether the thread is gone. A timeout leaves it running
    /// *detached* — dropping a `JoinHandle` does that rather than killing
    /// anything — and is logged, because a worker that ignores a terminate is a
    /// bug in that worker and must not become a hang in the parent.
    #[must_use]
    pub fn join(&self) -> bool {
        let Some(handle) = self.thread.borrow_mut().take() else {
            return true;
        };
        if self.finished.load(Ordering::SeqCst) {
            return handle.join().is_ok();
        }
        let started = std::time::Instant::now();
        while !self.finished.load(Ordering::SeqCst) {
            if started.elapsed() > JOIN_TIMEOUT {
                tracing::error!(
                    "worker {:?} did not stop within {:?}; detaching its thread",
                    self.request.name,
                    JOIN_TIMEOUT
                );
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        handle.join().is_ok()
    }

    /// `ref()`: the parent's loop waits for this worker.
    pub fn ref_worker(&self) {
        self.has_ref.set(true);
    }

    /// `unref()`: the parent's loop may exit without this worker.
    pub fn unref_worker(&self) {
        self.has_ref.set(false);
    }

    /// Whether the parent's `Worker` object still counts as a ref'd handle.
    #[must_use]
    pub fn has_ref(&self) -> bool {
        self.has_ref.get()
    }

    /// The shared "worker asked to stop" flag, for the worker thread to poll.
    pub(crate) fn stopping_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stopping)
    }

    /// The isolate slot, for the worker thread to publish its handle into.
    pub(crate) fn isolate_slot(&self) -> Arc<Mutex<Option<v8::IsolateHandle>>> {
        Arc::clone(&self.isolate)
    }

    /// The exit-code slot, for the worker thread to write.
    pub(crate) fn exit_slot(&self) -> Arc<AtomicI32> {
        Arc::clone(&self.exit_code)
    }

    /// The finished flag, for the worker thread to set on its way out.
    pub(crate) fn finished_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.finished)
    }

    /// Starts the worker thread with `run` as its body.
    pub fn start(&self, run: impl FnOnce() + Send + 'static) -> Result<(), String> {
        if self.thread.borrow().is_some() {
            return Err("the worker thread has already been started".to_string());
        }
        self.finished.store(false, Ordering::SeqCst);
        let name = self.request.name.clone();
        let handle = std::thread::Builder::new()
            .name(name)
            .spawn(run)
            .map_err(|error| format!("cannot start the worker thread: {error}"))?;
        *self.thread.borrow_mut() = Some(handle);
        Ok(())
    }
}

/// The thread ids Node hands out, in the order it hands them out.
///
/// `AllocateEnvironmentThreadId()` starts at 0 for the main environment, so the
/// first worker is 1. A per-process counter matches that, and `threadId` is
/// observable through `worker_threads.threadId` on both sides.
pub fn next_thread_id() -> i32 {
    static NEXT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
