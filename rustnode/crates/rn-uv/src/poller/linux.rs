//! Installing a readiness backend on a libuv loop, and serving the wait.
//!
//! # What a backend has to do
//!
//! libuv's `uv__io_poll` owns the readiness bookkeeping: `loop->watchers[fd]`
//! names the `uv__io_t` interested in a descriptor, and `loop->nfds`,
//! `loop->watchers` and `loop->watcher_queue` say which descriptors are being
//! watched. All of that stays libuv's. This module *reads* it after libuv has
//! registered the turn's changes with epoll, and mirrors the same descriptor set
//! into a ring, so the ring and libuv's table agree about what is watched.
//!
//! Mirroring after registration is what makes it exact rather than
//! approximately right: `uv__io_start` has already inserted new descriptors into
//! `loop->watchers`, `uv__io_stop` has already cleared the ones that left, and
//! `w->pevents` holds the mask libuv asked the kernel for. Whatever libuv told
//! epoll is therefore in the ring, and nothing else is.
//!
//! # Fallback
//!
//! [`Installed::install`] probes once. Any failure — no syscall, no permission,
//! no memory, no descriptor — leaves [`Installed::Epoll`] in place, which is the
//! backend that shipped before this module existed. The reason is logged at
//! `warn` and never surfaced as an error, because a runtime must not fail a user
//! program over an optional accelerator.

use std::cell::RefCell;
use std::collections::HashMap;

use libuv_sys2 as uv;

use super::uring::{Ready, Ring};
use super::Poller;

/// A loop's readiness backend.
pub enum Installed {
    /// libuv's own `epoll_pwait`, untouched.
    Epoll,
    /// A ring mirroring the descriptors libuv watches.
    ///
    /// The target itself lives in [`REGISTRY`], which is its only owner while
    /// the loop runs; this variant records which descriptor identifies it, so
    /// dropping this value can deregister it and ask for its polls to be
    /// cancelled.
    IoUring { backend_fd: i32 },
}

/// The ring plus the loop it serves.
pub struct PollTarget {
    /// The loop's epoll descriptor, which identifies the loop in the registry.
    ///
    /// Kept because the registry key is what the interposed wait is looked up
    /// by, and a target that could not name its own loop would be impossible to
    /// match against the descriptor libuv passed.
    backend_fd: i32,
    /// The loop the ring mirrors, so `sync` can read its watcher table.
    loop_pointer: *mut uv::uv_loop_t,
    ring: Ring,
    /// The loop's async eventfd, once libuv has created it.
    ///
    /// Read from the loop rather than cached at install time because libuv
    /// creates it lazily: a loop with no `uv_async_t` yet has no eventfd, and
    /// `uv__async_start` is what gives it one.
    wakeup_fd: i32,
}

impl PollTarget {
    /// Mirrors libuv's watcher table into the ring.
    ///
    /// Called from the interposed wait *after* libuv's registration loop, so the
    /// table describes exactly what epoll was told this turn.
    pub fn sync(&mut self) {
        let pointer = self.loop_pointer;
        if pointer.is_null() {
            return;
        }
        // SAFETY: `pointer` is the live loop this target was installed for.
        // `watchers` names `nwatchers` slots, each either null or a live
        // `uv__io_t` belonging to a handle on that loop, which is the same table
        // libuv's own wait walks at this point in the iteration.
        let (watchers, nwatchers, wakeup) = unsafe {
            (
                (*pointer).watchers,
                (*pointer).nwatchers,
                // SAFETY: as above; the async watcher is a field of the loop.
                (*pointer).async_io_watcher.fd,
            )
        };
        self.wakeup_fd = wakeup;

        let mut watched: Vec<i32> = Vec::new();
        if !watchers.is_null() {
            for index in 0..nwatchers as usize {
                // SAFETY: `index` is inside the table.
                let watcher = unsafe { *watchers.add(index) };
                if watcher.is_null() {
                    continue;
                }
                // SAFETY: `watcher` is a live `uv__io_t` owned by this loop.
                let (fd, pevents) = unsafe { ((*watcher).fd, (*watcher).pevents) };
                if fd < 0 || pevents == 0 {
                    continue;
                }
                watched.push(fd);
                self.ring.arm(fd, pevents);
            }
        }

        // A descriptor libuv stopped watching is gone from its table, which is
        // what drives the cancellation. Collected first so the map is not
        // mutated while it is being walked.
        let stale: Vec<i32> = self
            .ring
            .armed_descriptors()
            .filter(|fd| !watched.contains(fd))
            .collect();
        for fd in stale {
            self.ring.cancel_armed(fd);
        }
    }

    /// Waits for readiness, following `epoll_pwait`'s timeout convention.
    ///
    /// # The wakeup descriptor
    ///
    /// libuv's async eventfd is reported to libuv rather than swallowed, because
    /// the event is what makes `uv__async_io` run and dispatch every handle with
    /// its `pending` flag set. Dropping it strands those handles forever: the
    /// counter is the only thing that would report again, and draining without
    /// dispatching leaves nothing to report.
    ///
    /// The counter *is* drained first. libuv registers this descriptor
    /// edge-triggered and, on Linux, deliberately never reads it — `uv__async_io`
    /// relies on the per-handle flag, not the count. Under a level-triggered poll
    /// an undrained eventfd reports forever, so the count has to go, but the
    /// event itself is kept so the dispatch still happens.
    pub fn wait(&mut self, timeout_ms: i32) -> std::io::Result<Ready> {
        let ready = self.ring.wait(timeout_ms)?;
        // Every reported descriptor was armed one-shot, so its poll is spent.
        // Retiring it here lets the next `sync` re-submit it, which is what gives
        // libuv the level-triggered re-report it expects. See `Ring::arm`.
        for (descriptor, _) in &ready.events {
            self.ring.needs_rearm(*descriptor);
        }
        if self.wakeup_fd >= 0 && ready.events.iter().any(|(fd, _)| *fd == self.wakeup_fd) {
            self.ring.drain_wakeup(self.wakeup_fd);
        }
        if ready.timed_out {
            // A deadline expired with nothing ready. libuv treats a zero-event
            // wait as "check your timers", which is exactly what this is; tracing
            // it keeps a loop that wakes for no reason diagnosable.
            tracing::trace!(timeout_ms, "io_uring wait reached its deadline");
        }
        Ok(ready)
    }

    /// The number of descriptors with a poll armed.
    pub fn armed_count(&self) -> usize {
        self.ring.armed_count()
    }
}

impl Installed {
    /// Installs the readiness backend for `loop_pointer`.
    pub fn install(requested: Poller, loop_pointer: *mut uv::uv_loop_t) -> Self {
        if requested == Poller::Epoll {
            return Self::Epoll;
        }
        if loop_pointer.is_null() {
            tracing::warn!("io_uring requested but there is no loop yet; using epoll");
            return Self::Epoll;
        }
        // SAFETY: `loop_pointer` is the process' live loop.
        let backend_fd = unsafe { uv::uv_backend_fd(loop_pointer) };
        if backend_fd < 0 {
            tracing::warn!("io_uring requested but the loop has no epoll descriptor; using epoll");
            return Self::Epoll;
        }

        let ring = match Ring::new() {
            Ok(ring) => ring,
            Err(error) => {
                // `ENOSYS`, `EPERM`, `ENOMEM` and friends all land here. None is
                // fatal: epoll is the backend everything ran on before this
                // module existed.
                tracing::warn!(%error, "io_uring is unavailable; using epoll");
                return Self::Epoll;
            }
        };
        let ring_descriptor = ring.raw_descriptor();
        let target = Box::new(PollTarget {
            backend_fd,
            loop_pointer,
            ring,
            wakeup_fd: -1,
        });
        REGISTRY.with(|registry| {
            registry.borrow_mut().insert(backend_fd, target);
        });
        tracing::debug!(backend_fd, ring_descriptor, "readiness backend: io_uring");
        Self::IoUring { backend_fd }
    }

    /// The backend in use.
    pub fn poller(&self) -> Poller {
        match self {
            Self::Epoll => Poller::Epoll,
            Self::IoUring { .. } => Poller::IoUring,
        }
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        if let Self::IoUring { backend_fd } = self {
            // Removing the target drops the ring, which unmaps it and closes its
            // descriptor; the kernel cancels whatever polls were still armed, so
            // there is nothing to wait for here.
            REGISTRY.with(|registry| {
                registry.borrow_mut().remove(backend_fd);
            });
        }
    }
}

thread_local! {
    /// The ring targets this thread installed, by loop descriptor.
    ///
    /// Thread-local because a loop belongs to one thread and its ring may only be
    /// waited on by that thread: a worker's ring must not be reachable from the
    /// main thread's `uv_run`, and two loops must never share one.
    ///
    /// The value is the target itself rather than a pointer into `Installed`, so
    /// the registry has sole ownership while the loop runs. `Installed` keeps a
    /// second `Box` only so `poller()` can answer without the registry; the ring
    /// lives in the registry's copy.
    static REGISTRY: RefCell<HashMap<i32, Box<PollTarget>>> = RefCell::new(HashMap::new());
}

/// Whether a ring serves `backend_fd` on this thread.
pub fn has_ring(backend_fd: i32) -> bool {
    REGISTRY.with(|registry| registry.borrow().contains_key(&backend_fd))
}

/// Runs `body` with the target serving `backend_fd`, if there is one.
///
/// This is the only place a ring is borrowed mutably. It is called from inside
/// the interposed `epoll_pwait`, which is itself inside `uv_run` on the loop's
/// own thread, so nothing else can reach the target while the borrow is held.
pub fn with_target<R>(backend_fd: i32, body: impl FnOnce(&mut PollTarget) -> R) -> Option<R> {
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let target = registry.get_mut(&backend_fd)?;
        // The registry is keyed by the loop's epoll descriptor, so a mismatch
        // would mean one loop's ring was serving another's wait.
        debug_assert_eq!(target.backend_fd, backend_fd);
        Some(body(target))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is per thread, so a descriptor known to one worker is not
    /// visible to another. That is what keeps two workers' loops from finding
    /// each other's rings.
    #[test]
    fn the_registry_is_thread_local() {
        assert!(!has_ring(4242));
        let other = std::thread::spawn(|| has_ring(4242)).join();
        assert!(!other.expect("the worker ran"));
    }
}
