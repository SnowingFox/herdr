//! The `epoll_pwait` libuv's loop calls, with a ring behind it when one exists.
//!
//! # Why defining this symbol works
//!
//! libuv's `linux.c` calls `epoll_pwait`, and `epoll_pwait` is *undefined* in the
//! static archive `libuv-sys2` builds: libuv expects libc to provide it. A
//! definition in an object that is already part of the link therefore satisfies
//! libuv's reference, which is the whole mechanism — no patched vendored source,
//! no linker flag in a build script that some other binary would miss, and no
//! second event loop.
//!
//! The function below is a pass-through to the identical syscall unless a ring
//! was installed for *this* epoll descriptor, so the epoll path reaches the
//! kernel exactly the way it did before this module existed. The only difference
//! on that path is one comparison against a thread-local map.
//!
//! # Why the fallback is always available
//!
//! libuv maintains its epoll set unconditionally: `EPOLL_CTL_ADD` and
//! `EPOLL_CTL_MOD` go through libuv's own small io_uring `EPOLL_CTL` ring, and
//! `EPOLL_CTL_DEL` is a direct `epoll_ctl`. So the epoll set is complete at every
//! point this function can be called, which means falling back to the real wait
//! is always correct rather than merely usually correct. That is what makes the
//! degradation paths here safe: a ring that is full, or an iteration where
//! nothing could be armed, simply waits with epoll.

use std::ffi::c_void;

use super::linux;

/// `struct epoll_event`, matching the kernel's layout for this target.
///
/// Declared here rather than taken from `libc` so the signature below is exactly
/// the C one, which is `int epoll_pwait(int, struct epoll_event *,
/// int, int, const sigset_t *)`. `libc::epoll_event` is `#[repr(packed)]` on
/// x86-64, so it is not interchangeable with a pointer type in a signature that
/// another compilation unit calls.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct EpollEvent {
    /// The `poll(2)` mask the kernel reported.
    pub events: u32,
    /// Opaque payload; libuv stores the descriptor in the low 32 bits.
    pub data: u64,
}

impl EpollEvent {
    /// Builds an event naming `descriptor` as ready for `mask`.
    fn new(descriptor: i32, mask: u32) -> Self {
        Self {
            events: mask,
            // libuv's `uv__io_poll` reads `pe->data.fd`, the low 32 bits of the
            // 64-bit payload. Zero-extending the descriptor matches what the
            // kernel itself produces for an `epoll_ctl` registration whose
            // `data.fd` was set.
            data: descriptor as u32 as u64,
        }
    }
}

/// The `epoll_pwait` libuv's loop calls.
///
/// # Safety
///
/// Called by libuv with the arguments it would pass to `epoll_pwait`: a valid
/// epoll descriptor, a writable array of at least `maxevents` events, and either
/// a null signal mask or one valid for the duration of the call. The function
/// upholds libc's contract: it returns the number of events written, `0` on
/// timeout, or `-1` with `errno` set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_pwait(
    epoll_fd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: i32,
    sigmask: *const c_void,
) -> i32 {
    // A ring serves this loop only when one was installed on this thread, which
    // is the fast path out for every process that did not ask for io_uring.
    if linux::has_ring(epoll_fd) {
        // SAFETY: the caller guarantees the arguments are libuv's own, and
        // `serve` upholds the same contract this function promises.
        if let Some(result) = unsafe { serve(epoll_fd, events, maxevents, timeout) } {
            return result;
        }
    }
    // SAFETY: forwarding the caller's arguments unchanged to the syscall libc
    // would have made.
    unsafe { real_epoll_pwait(epoll_fd, events, maxevents, timeout, sigmask) }
}

/// Runs one wait on the ring serving `epoll_fd`.
///
/// Returns `None` when the epoll path should handle this call instead: no
/// target, nothing armed, or a ring error. Every one of those is a normal
/// condition and none of them is reported as an error to libuv, because libuv's
/// epoll set is complete and its own wait is always a correct answer.
///
/// # Safety
///
/// As for [`epoll_pwait`]: `events` must name `maxevents` writable entries.
unsafe fn serve(
    epoll_fd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: i32,
) -> Option<i32> {
    if events.is_null() || maxevents <= 0 {
        return None;
    }

    // The wait happens inside `with_target` so the ring is borrowed for exactly
    // one call and the registry is not held across a blocking syscall.
    let outcome = linux::with_target(epoll_fd, |target| {
        target.sync();
        // Nothing armed means this iteration would wait for a completion that
        // can never arrive, so epoll answers instead. In particular libuv never
        // calls this with an empty watcher set, but a full submission ring can
        // still leave nothing armed.
        if target.armed_count() == 0 {
            return None;
        }
        Some(target.wait(timeout))
    })?;

    let ready = match outcome {
        Some(Ok(ready)) => ready,
        Some(Err(error)) => {
            // A ring that fails here is not worth failing the program over: the
            // epoll set is intact, so the caller's fallback is correct.
            tracing::debug!(%error, "io_uring wait failed; falling back to epoll");
            return None;
        }
        // Nothing is armed on this loop, so there is no completion to wait for.
        // libuv's epoll set is complete, so its own wait answers instead.
        None => return None,
    };

    let capacity = maxevents as usize;
    let mut written = 0usize;
    for (descriptor, mask) in ready.events.iter().take(capacity) {
        // SAFETY: `written` stays below `maxevents`, so this addresses one of
        // the caller's writable entries.
        unsafe {
            events
                .add(written)
                .write(EpollEvent::new(*descriptor, *mask));
        }
        written += 1;
    }

    if written == 0 {
        // `timed_out` and "nothing ready" are the same answer to libuv: zero
        // events, which its poll loop treats as a deadline or a spurious
        // wakeup and handles identically to epoll's.
        return Some(0);
    }
    Some(written as i32)
}

/// The real `epoll_pwait`, bypassing this module's definition.
///
/// Calling `libc::epoll_pwait` here would recurse into the function above, since
/// the two names refer to one symbol. The syscall is issued directly instead,
/// which is the same request libc would make.
///
/// # Safety
///
/// As for [`epoll_pwait`].
unsafe fn real_epoll_pwait(
    epoll_fd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: i32,
    sigmask: *const c_void,
) -> i32 {
    // `epoll_pwait` takes the signal-set size as its sixth argument, which is
    // what libc passes: `sizeof(sigset_t)`, 8 on this target's kernel ABI.
    // SAFETY: the caller guarantees the arguments; a null `sigmask` makes the
    // size irrelevant, which is what libuv always passes here.
    let status = unsafe {
        libc::syscall(
            libc::SYS_epoll_pwait,
            epoll_fd,
            events,
            maxevents,
            timeout,
            sigmask,
            size_of_sigset(),
        )
    };
    status as i32
}

/// `sizeof(kernel_sigset_t)`, which is what `epoll_pwait` expects.
const fn size_of_sigset() -> usize {
    8
}
