//! `v8::Isolate::TerminateExecution` after a deadline, from another thread.
//!
//! Node's `Watchdog` (`src/node_watchdog.{h,cc}`), reduced to what
//! `ModuleWrap::Evaluate` and `Script::RunInContext` need. Both are reachable
//! from `lib/**` and both are otherwise able to run unbounded user code, so the
//! machinery lives here rather than in either binding crate: `rn-core` is what
//! both already depend on, and a second copy is how the two would drift.

use rn_v8_sys::v8;

/// Arms `isolate->TerminateExecution()` after `timeout_ms`, from another thread.
///
/// This is Node's `Watchdog` (`src/node_watchdog.{h,cc}`) reduced to what
/// `ModuleWrap::Evaluate` uses: a thread that sleeps for the deadline and then
/// terminates the isolate. Node runs a libuv loop on that thread so the timer can
/// be cancelled early; here the deadline is only ever waited out or cancelled, so
/// a parked thread with a `Condvar` does the same job without a second loop, and
/// [`Drop`] is what stops it when evaluation finishes first.
///
/// The isolate handle is the thread-safe one (`IsolateHandle` is `Send + Sync` by
/// its own documentation), because `TerminateExecution` is explicitly allowed from
/// a thread that does not hold the V8 lock while the running thread does.
///
/// `fired` is how the caller learns whether the termination it is about to
/// observe came from *this* watchdog rather than from an outer one: Node checks
/// the same flag before converting the termination into
/// `ERR_SCRIPT_EXECUTION_TIMEOUT` (`src/module_wrap.cc:855`), because a nested
/// timeout must not be re-reported as this one's.
pub struct Watchdog {
    /// Set by the thread when the deadline passes before the guard is dropped.
    fired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set once evaluation is finished, so the thread can stop waiting.
    finished: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl Watchdog {
    /// Arms the watchdog for `timeout_ms` milliseconds.
    pub fn arm(isolate: &v8::Isolate, timeout_ms: u64) -> Self {
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let handle = isolate.thread_safe_handle();
        let thread_fired = std::sync::Arc::clone(&fired);
        let thread_finished = std::sync::Arc::clone(&finished);

        // A thread that cannot be spawned leaves the guard armed but never firing,
        // so evaluation runs without a deadline rather than failing to start. That
        // is the same outcome as Node's `uv_thread_create` failure path, which also
        // proceeds.
        std::thread::Builder::new()
            .name("rn-evaluate-watchdog".to_string())
            .spawn(move || {
                let (lock, ready) = &*thread_finished;
                let Ok(guard) = lock.lock() else {
                    return;
                };
                let Ok((guard, _)) =
                    ready.wait_timeout(guard, std::time::Duration::from_millis(timeout_ms))
                else {
                    return;
                };
                // Signalled by `Drop` before the deadline: evaluation finished.
                if *guard {
                    return;
                }
                drop(guard);
                thread_fired.store(true, std::sync::atomic::Ordering::SeqCst);
                handle.terminate_execution();
            })
            .ok();

        Self { fired, finished }
    }

    /// Whether this watchdog is what terminated the isolate.
    pub fn fired(&self) -> bool {
        self.fired.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        let (lock, ready) = &*self.finished;
        if let Ok(mut finished) = lock.lock() {
            *finished = true;
            ready.notify_all();
        }
    }
}
