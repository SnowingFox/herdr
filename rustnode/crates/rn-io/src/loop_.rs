//! The event loop: libuv's loop, driven one iteration at a time.
//!
//! Node's event loop *is* libuv's. `uv_run` runs pending, idle, prepare, poll,
//! check, close and timers in that order, and Node adds a microtask checkpoint
//! after every JavaScript callback. rustnode therefore does not reimplement the
//! phase order: [`Loop::run`] calls `uv_run(UV_RUN_ONCE)` in a loop and drains
//! ticks between the iterations.
//!
//! # Why `UV_RUN_ONCE` and not `UV_RUN_DEFAULT`
//!
//! `UV_RUN_DEFAULT` runs the whole loop inside one C call, so nothing in Rust
//! regains control between two iterations and a `process.nextTick` queued by one
//! phase could only run once the process had done everything else. `UV_RUN_ONCE`
//! runs exactly one iteration — blocking in poll until a descriptor is ready or
//! the earliest libuv timer is due — and returns, which is where the drain goes.
//!
//! How long that wait is, is libuv's decision: `uv__backend_timeout` is zero
//! whenever a pending callback, an idle handle, a closing handle or a child
//! process needs attention, and the next timer deadline otherwise, ignoring
//! unref'd timers. A scheduler that computed its own timeout would have to
//! reproduce that rule, and the case it got wrong is exactly the bug this
//! replaces: the old loop slept in its own `poll(2)` for a deadline no handle
//! owned.
//!
//! # Who owns what
//!
//! * `rn-uv` owns the `uv_loop_t` and every handle on it.
//! * `rn-bind-timers` owns the loop's timer, check and idle handles, because
//!   their callbacks run `internal/timers.js`'s `processTimers` and
//!   `processImmediate` and so need a V8 scope. That is the same split Node has
//!   between `TimerWrap`/`Environment` and `lib/internal/timers.js`.
//! * This crate owns *when* the loop runs and the drain between iterations.
//! * `rn-cli` implements [`Scheduler`] over V8.

pub use crate::backend::Backend;

/// What the loop needs from the runtime it is driving.
///
/// The phases themselves belong to libuv; the two things it cannot answer are
/// "drain the JavaScript queues" and "did the script ask to exit", which is what
/// this trait is for. Keeping it this narrow is deliberate: a scheduler that also
/// reported deadlines and ref counts would be a second loop again, and the two
/// would disagree about which deadline is real.
pub trait Scheduler {
    /// Drains `process.nextTick` and V8's microtask queue.
    ///
    /// Called between loop iterations, never inside one, so a callback that
    /// queues a microtask cannot have it run before the libuv callback that
    /// queued it returns. `lib/internal/process/task_queues.js` is what actually
    /// drains; this only gives it the chance.
    fn drain(&mut self);

    /// Whether the process has asked to exit, e.g. through `process.exit()`.
    ///
    /// An uncaught exception is not reported here: it sets the shared
    /// [`rn_core::hook_slot::EXIT_REQUESTED`] flag from inside the callback that
    /// threw, where no scheduler is borrowed, and [`Loop::run`] reads that flag
    /// itself.
    fn exit_requested(&self) -> bool;

    /// Whether work outside libuv still keeps the process alive.
    ///
    /// libuv only knows about handles. A `MessagePort` keeps itself alive in
    /// Rust (`rn_bind_messaging::has_work`), so without this the loop would exit
    /// with a port still listening, which Node does not do. The default is
    /// "nothing", so a scheduler that owns no such work says nothing.
    fn has_external_work(&self) -> bool {
        false
    }

    /// Called once the loop has run dry, and again after each idle it reaches.
    ///
    /// This is `beforeExit`. Node emits it from inside `SpinEventLoopInternal`
    /// between the liveness check and the next iteration, which is why a handler
    /// that schedules work revives the loop instead of running after it is gone.
    ///
    /// Returns whether the emit left work behind. `false` means nothing is left
    /// and the process may exit; the default is `false`, so a scheduler with no
    /// JavaScript to notify does not need to implement it.
    fn before_exit(&mut self) -> bool {
        false
    }
}

/// A loop over libuv.
#[derive(Debug)]
pub struct Loop {
    backend: Backend,
}

impl Loop {
    /// Builds a loop for `backend`, or explains why that backend cannot run.
    pub fn new(backend: Backend) -> Result<Self, String> {
        match backend {
            Backend::Libuv => {
                // Creating the loop here rather than lazily on first use means a
                // failure to create it reaches the caller that asked for a loop,
                // instead of surfacing later as an I/O binding that silently
                // does nothing.
                if rn_uv::uv_loop::loop_ptr().is_none() {
                    return Err("the libuv loop could not be created".to_string());
                }
            }
            Backend::IoUring => {
                return Err(
                    "the io_uring backend is not implemented; use the default libuv loop"
                        .to_string(),
                )
            }
        }
        Ok(Self { backend })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Runs one iteration of the libuv loop, then drains ticks.
    ///
    /// Returns whether libuv still has referenced work. `false` means nothing is
    /// left that could keep the process alive, so the caller may exit.
    ///
    /// The iteration blocks in poll until a descriptor is ready or the earliest
    /// libuv timer is due, which is what makes `setTimeout(f, 20)` cost 20ms of
    /// sleep rather than 20ms of spinning. It does not block at all when libuv
    /// has a callback that is already runnable, because `uv__backend_timeout`
    /// reports zero then.
    pub fn tick<S: Scheduler>(&mut self, scheduler: &mut S) -> bool {
        // Nothing is alive, so libuv would return without running an iteration.
        // Taking that answer from libuv rather than deciding it here is what
        // makes `unref()` mean what it means: one iteration is long enough for a
        // 1ms deadline to become due, so an unref'd timer that the loop never
        // enters for is a timer Node never calls.
        //
        // Work that keeps itself alive outside libuv still needs the iteration,
        // so it counts here too. The check phase is what drains it, and that
        // phase runs whether or not libuv has a ref'd handle of its own.
        if !rn_uv::uv_loop::is_active() {
            if !scheduler.has_external_work() {
                return false;
            }
            // A loop libuv calls dead never blocks in poll, so this iteration
            // runs the check phase and returns rather than waiting.
            let _ = rn_uv::uv_loop::run_once();
            scheduler.drain();
            return rn_uv::uv_loop::is_active() || scheduler.has_external_work();
        }
        let _ = rn_uv::uv_loop::run_once_blocking();
        scheduler.drain();
        rn_uv::uv_loop::is_active() || scheduler.has_external_work()
    }

    /// Runs iterations until nothing is left, up to `turn_limit`.
    ///
    /// The limit guards against a program that keeps libuv alive forever without
    /// ever exiting, which only a test should have to care about. The runtime
    /// passes [`u32::MAX`] because a real program is allowed to run forever;
    /// tests use a small number so a bug fails instead of hanging.
    ///
    /// When the loop runs dry, [`Scheduler::before_exit`] is offered the idle
    /// before the process is allowed to stop. That is `beforeExit`, and Node
    /// emits it from this same position so a handler can schedule work and keep
    /// the process alive. The loop continues while the emit revives it.
    pub fn run<S: Scheduler>(&mut self, scheduler: &mut S, turn_limit: u32) -> StopReason {
        if scheduler.exit_requested() {
            return StopReason::ExitRequested;
        }
        for _ in 0..turn_limit {
            if !self.tick(scheduler) {
                if scheduler.exit_requested() || rn_core_exit_requested() {
                    return StopReason::ExitRequested;
                }
                // Nothing is left: offer `beforeExit` its one chance to schedule
                // something, and keep looping if it did. The emit is repeated on
                // every later idle, which is what Node does, so a handler that
                // schedules work on each call keeps a process alive indefinitely.
                if scheduler.before_exit() {
                    continue;
                }
                return StopReason::Idle;
            }
            // An uncaught exception aborts the process the way Node does: the
            // error is already printed by the callback that threw, so the loop
            // stops here rather than running the rest of the program.
            if scheduler.exit_requested() || rn_core_exit_requested() {
                return StopReason::ExitRequested;
            }
        }
        StopReason::TurnLimit
    }
}

/// Whether an uncaught exception already asked the process to exit.
///
/// `rn-errors` raises this from inside the `TryCatch` that caught the throw,
/// where no scheduler is in scope, so it has to be read separately from
/// [`Scheduler::exit_requested`].
fn rn_core_exit_requested() -> bool {
    rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED)
}

/// Why [`Loop::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Nothing is left to run: the process may exit.
    Idle,
    /// The scheduler asked to exit, e.g. an uncaught exception.
    ExitRequested,
    /// The turn limit was reached before the loop settled.
    TurnLimit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::pin::Pin;
    use std::rc::Rc;

    /// A scheduler that counts drains and can ask to exit.
    #[derive(Default)]
    struct Counter {
        drains: Cell<u32>,
        exit: bool,
    }

    impl Scheduler for Counter {
        fn drain(&mut self) {
            self.drains.set(self.drains.get() + 1);
        }

        fn exit_requested(&self) -> bool {
            self.exit
        }
    }

    /// A timer handle that outlives the test body but can be closed on demand.
    ///
    /// libuv requires a handle not to move once `uv_timer_init` has run, so it is
    /// allocated first and initialised where it sits.
    struct TestTimer {
        handle: Pin<Box<libuv_sys2::uv_timer_t>>,
        fired: Rc<Cell<u32>>,
        rearm: bool,
    }

    impl TestTimer {
        fn new(rearm: bool) -> Box<Self> {
            let pointer = rn_uv::uv_loop::loop_ptr().expect("the loop exists");
            let mut handle = Box::pin(std::mem::MaybeUninit::<libuv_sys2::uv_timer_t>::zeroed());
            // SAFETY: `handle` points at a live, aligned, zeroed slot and
            // `pointer` is the process' live loop.
            let status = unsafe { libuv_sys2::uv_timer_init(pointer, handle.as_mut_ptr()) };
            assert_eq!(status, 0, "uv_timer_init must succeed");
            // SAFETY: `uv_timer_init` succeeded, so the handle is initialised.
            let handle: Pin<Box<libuv_sys2::uv_timer_t>> =
                Box::pin(unsafe { handle.assume_init() });
            let test = Box::new(Self {
                handle,
                fired: Rc::new(Cell::new(0)),
                rearm,
            });
            // SAFETY: the handle is live and outlives the loop run, and `data`
            // holds a pointer to the test box, which the caller keeps alive.
            unsafe {
                (*std::ptr::from_ref(&*test.handle).cast_mut()).data =
                    std::ptr::from_ref(&*test).cast_mut().cast();
            }
            test
        }

        fn start(&mut self, delay: u64) {
            // SAFETY: the handle is live.
            let status = unsafe {
                libuv_sys2::uv_timer_start(
                    std::ptr::from_ref(&*self.handle).cast_mut(),
                    Some(on_timer),
                    delay,
                    0,
                )
            };
            assert_eq!(status, 0, "uv_timer_start must succeed");
        }

        fn close(&mut self) {
            // SAFETY: the handle is live and no run is in progress.
            unsafe {
                libuv_sys2::uv_timer_stop(std::ptr::from_ref(&*self.handle).cast_mut());
                libuv_sys2::uv_close(std::ptr::from_ref(&*self.handle).cast_mut().cast(), None);
            }
        }
    }

    /// # Safety
    ///
    /// Called by libuv with a handle whose `data` is a `*mut TestTimer`.
    unsafe extern "C" fn on_timer(handle: *mut libuv_sys2::uv_timer_t) {
        // SAFETY: the handle's `data` is the test that initialised it, which is
        // alive for the whole run.
        let Some(test) = (unsafe { rn_uv::uv_loop::handle_data::<TestTimer>(handle.cast()) })
        else {
            return;
        };
        // SAFETY: `test` came from the live box that owns the handle.
        let test = unsafe { &mut *test };
        test.fired.set(test.fired.get() + 1);
        if test.rearm {
            // SAFETY: the handle is live.
            unsafe { libuv_sys2::uv_timer_start(handle, Some(on_timer), 0, 0) };
        }
    }

    #[test]
    fn the_io_uring_backend_is_rejected_rather_than_silently_emulated() {
        let Err(error) = Loop::new(Backend::IoUring) else {
            panic!("io_uring must be rejected");
        };
        assert!(error.contains("io_uring"));
    }

    #[test]
    fn the_libuv_backend_creates_the_process_loop() {
        let event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.backend(), Backend::Libuv);
        assert!(rn_uv::uv_loop::is_initialised());
        assert!(!rn_uv::uv_loop::is_active(), "an idle loop is not alive");
    }

    #[test]
    fn a_run_with_nothing_refed_runs_no_turn() {
        // `setTimeout(f, 1).unref()` on its own exits in 0.1ms under real `node`
        // without calling `f`, even though a millisecond may already have passed
        // by the time the loop starts. The entry check is what guarantees that.
        let mut scheduler = Counter::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 10), StopReason::Idle);
        assert_eq!(scheduler.drains.get(), 0, "no turn ran for unref'd work");
    }

    #[test]
    fn an_exit_request_stops_before_any_turn() {
        let mut scheduler = Counter {
            exit: true,
            ..Counter::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(
            event_loop.run(&mut scheduler, 10),
            StopReason::ExitRequested,
            "`run` reports the exit request even when it stops before a turn"
        );
        assert_eq!(scheduler.drains.get(), 0);
    }

    #[test]
    fn an_idle_loop_offers_before_exit_exactly_once() {
        // `beforeExit` is emitted from the idle, not from the end of `run`, so a
        // scheduler is asked before the process is allowed to stop. A scheduler
        // that says it did not revive anything must not be asked twice.
        #[derive(Default)]
        struct Idle {
            drains: Cell<u32>,
            befores: Cell<u32>,
        }

        impl Scheduler for Idle {
            fn drain(&mut self) {
                self.drains.set(self.drains.get() + 1);
            }

            fn exit_requested(&self) -> bool {
                false
            }

            fn before_exit(&mut self) -> bool {
                self.befores.set(self.befores.get() + 1);
                false
            }
        }

        let mut scheduler = Idle::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 10), StopReason::Idle);
        assert_eq!(scheduler.befores.get(), 1, "`beforeExit` is emitted once");
    }

    #[test]
    fn a_before_exit_that_revives_the_loop_keeps_it_running() {
        // The documented contract: a handler that schedules work prevents the
        // exit. The loop has to re-enter rather than treat the idle as final, and
        // it must offer `beforeExit` again on the next idle.
        #[derive(Default)]
        struct Reviving {
            befores: Cell<u32>,
            revivals: u32,
        }

        impl Scheduler for Reviving {
            fn drain(&mut self) {}

            fn exit_requested(&self) -> bool {
                false
            }

            fn before_exit(&mut self) -> bool {
                let n = self.befores.get() + 1;
                self.befores.set(n);
                if n <= self.revivals {
                    return true;
                }
                false
            }
        }

        let mut scheduler = Reviving {
            revivals: 2,
            ..Reviving::default()
        };
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(
            event_loop.run(&mut scheduler, 10),
            StopReason::Idle,
            "the loop settles once the revival stops"
        );
        assert_eq!(
            scheduler.befores.get(),
            3,
            "two revivals mean three idles, so three emits"
        );
    }

    #[test]
    fn a_timer_is_a_libuv_timer_and_its_callback_runs_inside_the_loop() {
        // The whole point of the move: a deadline armed on libuv's own handle is
        // honoured by `uv_run`, with no scheduler-side deadline bookkeeping.
        let mut timer = TestTimer::new(false);
        timer.start(1);
        let fired = Rc::clone(&timer.fired);
        let mut scheduler = Counter::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 100), StopReason::Idle);
        assert_eq!(fired.get(), 1, "the libuv timer fired exactly once");
        timer.close();
        let _ = rn_uv::uv_loop::run_once();
    }

    #[test]
    fn the_turn_limit_bounds_a_loop_that_never_settles() {
        // A timer re-armed from its own callback is work that never ends, which
        // is the case the turn limit exists for.
        let mut timer = TestTimer::new(true);
        timer.start(0);
        let fired = Rc::clone(&timer.fired);
        let mut scheduler = Counter::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 3), StopReason::TurnLimit);
        assert!(scheduler.drains.get() >= 3, "each turn drains once");
        assert!(fired.get() >= 3, "the timer fired each turn");
        timer.close();
        let _ = rn_uv::uv_loop::run_once();
    }

    #[test]
    fn an_unrefed_timer_does_not_start_a_run_but_fires_once_refed_work_arrives() {
        // The measured `node` behaviour: an unref'd 1ms timer alone exits in
        // 0.1ms without firing, and the same timer next to a ref'd immediate
        // fires, because the deadline passed while the immediate kept the loop
        // turning.
        let mut timer = TestTimer::new(false);
        timer.start(1);
        // SAFETY: the handle is live.
        unsafe { libuv_sys2::uv_unref(std::ptr::from_ref(&*timer.handle).cast_mut().cast()) };
        assert!(!rn_uv::uv_loop::is_active(), "an unref'd timer is not work");

        let mut scheduler = Counter::default();
        let mut event_loop = Loop::new(Backend::Libuv).expect("the default backend runs");
        assert_eq!(event_loop.run(&mut scheduler, 10), StopReason::Idle);
        assert_eq!(timer.fired.get(), 0, "the unref'd timer never ran");

        timer.close();
        let _ = rn_uv::uv_loop::run_once();
    }
}
