//! The readiness backend the one libuv loop waits on.
//!
//! There is still exactly one loop: `uv_run` decides the phase order, how long
//! to wait, and which callbacks run. What changes between backends is *how that
//! wait is performed* — `epoll_pwait(2)` on the epoll backend, a kernel
//! `io_uring` submission queue on the io_uring backend.
//!
//! # Why this is a poller and not a second loop
//!
//! `crates/rn-io/src/loop_.rs` documents at length why the phase order is not
//! reimplemented: Node's ordering guarantees are statements about `uv_run`, and
//! a second loop disagrees with it about which deadline is real. The same
//! reasoning applies here. Both backends are entered from the *same* place —
//! the single `epoll_pwait` call libuv makes inside `uv__io_poll` — so the
//! pending, idle, prepare, check, close and timer phases above and below it are
//! literally the same code. A completion produced by io_uring is handed back as
//! the same `epoll_event` an epoll wait would produce, and libuv decodes and
//! dispatches it through the identical `uv__io_cb` path, which is what makes
//! "the same completions the epoll path produces" true by construction rather
//! than by imitation.
//!
//! # How the wait is redirected
//!
//! libuv's `linux.c` calls `epoll_pwait`, and that symbol is *undefined* in the
//! static archive libuv-sys2 builds: libuv expects libc to provide it. A
//! definition supplied by this crate therefore satisfies the reference when the
//! archive is linked, with no build-script flags and no patch to vendored
//! source. [`interpose::epoll_pwait`] is that definition.
//!
//! It is a pass-through to the same syscall unless a ring was installed for
//! *this* epoll descriptor, so a loop running on epoll reaches the kernel by
//! exactly the route it always did; the epoll path is unchanged apart from one
//! non-inlined call.
//!
//! # What this backend covers
//!
//! First slice only: socket read readiness, write readiness, and accept. The
//! kernel performs no reads or writes here — it reports readiness exactly as
//! epoll does, and libuv's own `uv__stream_io` / `uv__server_io` then issue the
//! non-blocking `read(2)` / `writev(2)` / `accept4(2)` on the ready descriptor.
//! Keeping the completion a *readiness* event rather than a byte count is what
//! keeps the JavaScript-visible behaviour identical, and it is why timers,
//! signals and threadpool work are untouched: they are phases of `uv_run` that
//! this module never enters.
//!
//! # Runtime detection, and why nothing aborts
//!
//! [`Poller::from_env`] reads the switch. [`Readiness::install`] then probes
//! `io_uring_setup(2)` once. `ENOSYS` (no syscall), `EPERM` (a seccomp filter,
//! or `/proc/sys/kernel/io_uring_disabled`), `ENOMEM`/`EMFILE`/`ENFILE` (no room
//! for a ring) and every other failure fall back to epoll with a
//! `tracing::warn!`. A user program is never aborted because the kernel would
//! not give us a ring; the worst outcome is the backend it was already using.

#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
pub mod interpose;
#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
mod linux;
#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
mod uring;

use libuv_sys2 as uv;

/// Which readiness backend a loop waits with.
///
/// `Epoll` is what every loop uses unless `HERDR_URING=1` asked for io_uring and
/// the kernel granted a ring. The choice is made once, at loop start, and never
/// changes for the life of that loop: a loop that switched backend midway would
/// have two sources of readiness for the same descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Poller {
    /// `epoll_pwait(2)`, libuv's own path.
    #[default]
    Epoll,
    /// A kernel `io_uring` submission queue.
    IoUring,
}

impl Poller {
    /// The backend the environment asked for, before any probe.
    ///
    /// Only `HERDR_URING=1` (or `true`) enables io_uring. Any other value —
    /// unset, `0`, empty, anything else — leaves the default, so an unset
    /// environment is exactly the epoll path users already run.
    pub fn from_env() -> Self {
        match std::env::var_os(crate::ENV_URING) {
            Some(value)
                if value == std::ffi::OsStr::new("1") || value == std::ffi::OsStr::new("true") =>
            {
                Self::IoUring
            }
            _ => Self::Epoll,
        }
    }

    /// The backend's name, for logs and test output.
    pub fn name(self) -> &'static str {
        match self {
            Self::Epoll => "epoll",
            Self::IoUring => "io_uring",
        }
    }
}

/// A loop's readiness backend, installed once the loop exists.
///
/// Dropping this deregisters the backend and releases the ring, which is what
/// makes a worker thread's teardown not leak its rings.
pub struct Readiness {
    #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
    backend: linux::Installed,
}

impl std::fmt::Debug for Readiness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Readiness")
            .field("poller", &self.poller())
            .finish()
    }
}

impl Readiness {
    /// Installs the readiness backend for `loop_pointer`.
    ///
    /// Returns the backend actually in use. A failure to set up io_uring is not
    /// an error for the caller: it is reported through `tracing` and epoll is
    /// installed instead, because a runtime must not abort a user program over
    /// an unavailable syscall.
    pub fn install(requested: Poller, loop_pointer: *mut uv::uv_loop_t) -> Self {
        #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
        {
            Self {
                backend: linux::Installed::install(requested, loop_pointer),
            }
        }
        #[cfg(not(all(target_os = "linux", not(target_arch = "wasm32"))))]
        {
            let _ = loop_pointer;
            // Only Linux can provide io_uring; anywhere else the request is
            // refused up front by `Poller::from_env`'s caller, and epoll (or the
            // platform's own poller) is what libuv runs regardless.
            let _ = requested;
            Self {}
        }
    }

    /// The backend in use.
    pub fn poller(&self) -> Poller {
        #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
        {
            self.backend.poller()
        }
        #[cfg(not(all(target_os = "linux", not(target_arch = "wasm32"))))]
        {
            Poller::Epoll
        }
    }
}

/// The backend the last `Readiness::install` on this thread really installed.
///
/// [`Poller::from_env`] answers a different question: it reports what the
/// environment *requested*. `install` silently falls back to [`Poller::Epoll`]
/// when the kernel, a seccomp filter, a missing loop descriptor or a failed
/// `io_uring_setup(2)` prevents a ring, so the two can disagree and the request
/// is not evidence about the installed backend. A test that asks `from_env()`
/// when it means "what is the loop waiting with" compares the request against
/// itself and passes even when the fallback happened.
///
/// Returns `None` before any loop has installed a backend on this thread.
pub fn installed_backend() -> Option<Poller> {
    #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
    {
        linux::installed_backend()
    }
    #[cfg(not(all(target_os = "linux", not(target_arch = "wasm32"))))]
    {
        // Only Linux installs a readiness backend; everywhere else the platform's
        // own poller runs and `install` was never called.
        None
    }
}
