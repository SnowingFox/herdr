//! The readiness poller under the loop's poll phase.
//!
//! Node's poll phase is `uv_run`'s `UV_RUN_ONCE`: block until a descriptor is
//! ready or the next timer deadline passes, whichever comes first. rustnode uses
//! `poll(2)` for it rather than `epoll`: the handle counts a single-threaded
//! runtime has fit in one array without a tree, `poll` is what libuv itself uses
//! as its fallback backend, and it needs no new dependency because `libc`
//! already wraps it.
//!
//! `poll` with no descriptors is defined to sleep for the timeout, which is
//! exactly what the loop wants while no binding has registered one: a
//! `setTimeout(f, 20)` must take 20ms, not spin. Registering the first socket is
//! a push onto the descriptor list and nothing above this file changes.
//!
//! Windows has no `poll`; the loop's wait becomes a sleep there, which keeps the
//! same timing contract with no descriptors to report readiness for.

use std::time::Duration;

/// One descriptor the loop is waiting on.
///
/// Nothing registers one yet: every binding that touches the OS (`fs`, `uv`)
/// currently wraps the synchronous libc call. The type exists so the poller's
/// shape does not change when the first asynchronous socket lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    /// The OS file descriptor.
    pub fd: i32,
    /// Whether the loop is waiting for the descriptor to become readable.
    pub readable: bool,
    /// Whether the loop is waiting for it to become writable.
    pub writable: bool,
}

/// Which registered descriptors the last wait found ready.
#[derive(Debug, Default, Clone)]
pub struct Ready {
    /// The descriptors reported ready, in registration order.
    descriptors: Vec<i32>,
}

impl Ready {
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// The ready descriptors.
    pub fn descriptors(&self) -> &[i32] {
        &self.descriptors
    }
}

/// The set of descriptors the loop waits on.
#[derive(Debug, Default)]
pub struct Poller {
    watchers: Vec<Descriptor>,
}

impl Poller {
    pub fn new() -> Result<Self, String> {
        Ok(Self::default())
    }

    /// Adds a descriptor to the wait set.
    ///
    /// Registering the same descriptor twice replaces the earlier interest,
    /// which is how `poll` itself behaves: one entry per fd.
    pub fn register(&mut self, descriptor: Descriptor) {
        match self
            .watchers
            .iter_mut()
            .find(|existing| existing.fd == descriptor.fd)
        {
            Some(existing) => *existing = descriptor,
            None => self.watchers.push(descriptor),
        }
    }

    /// Removes a descriptor from the wait set, if it is there.
    pub fn deregister(&mut self, fd: i32) {
        self.watchers.retain(|descriptor| descriptor.fd != fd);
    }

    /// How many descriptors are being waited on.
    pub fn registered(&self) -> usize {
        self.watchers.len()
    }

    /// Waits up to `timeout` for any registered descriptor.
    ///
    /// `None` means block indefinitely, which the loop never asks for while
    /// nothing is registered because there would be no way to wake.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Ready {
        if self.watchers.is_empty() {
            // No descriptor can become ready, so the deadline is the only thing
            // the phase can wait for. `poll` with an empty set does exactly
            // this, but going through it would need a zero-length valid pointer;
            // sleeping is the same wait with none of that.
            if let Some(timeout) = timeout {
                if !timeout.is_zero() {
                    std::thread::sleep(timeout);
                }
            }
            return Ready::default();
        }
        wait_on(&self.watchers, timeout)
    }
}

/// Waits on `watchers` with `poll(2)`.
///
/// A negative timeout is `poll`'s spelling of "wait forever", which is what
/// `None` becomes.
#[cfg(unix)]
fn wait_on(watchers: &[Descriptor], timeout: Option<Duration>) -> Ready {
    use std::os::raw::c_int;

    let mut descriptors: Vec<libc::pollfd> = watchers
        .iter()
        .map(|watcher| libc::pollfd {
            fd: watcher.fd,
            events: events_for(watcher),
            revents: 0,
        })
        .collect();

    // `poll` takes whole milliseconds and reports -1 for an error. A timeout
    // beyond `c_int` is clamped rather than wrapped: a multi-day wait is the
    // same as forever for this loop.
    let timeout_ms: c_int = match timeout {
        None => -1,
        Some(timeout) => {
            let millis = timeout.as_millis().min(c_int::MAX as u128);
            c_int::try_from(millis).unwrap_or(c_int::MAX)
        }
    };

    // SAFETY: `descriptors` is a valid, writable slice of `pollfd` and its
    // length is passed alongside it, which is the contract `poll` documents.
    let ready = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout_ms,
        )
    };
    if ready <= 0 {
        // 0 is the timeout expiring and -1 is an interrupted or failed wait.
        // Neither reports a descriptor, and the loop re-checks its deadlines on
        // the next turn either way.
        return Ready::default();
    }

    Ready {
        descriptors: descriptors
            .iter()
            .filter(|descriptor| descriptor.revents != 0)
            .map(|descriptor| descriptor.fd)
            .collect(),
    }
}

/// Sleeps on a platform with no `poll`, for a poller with descriptors.
///
/// Unreachable today because nothing registers a descriptor; it exists so the
/// Windows build compiles and so the first descriptor registration is a
/// deliberate change rather than a silent no-op.
#[cfg(not(unix))]
fn wait_on(_watchers: &[Descriptor], timeout: Option<Duration>) -> Ready {
    if let Some(timeout) = timeout {
        std::thread::sleep(timeout);
    }
    Ready::default()
}

/// The `poll` event mask for one watcher.
#[cfg(unix)]
fn events_for(watcher: &Descriptor) -> libc::c_short {
    let mut events = 0;
    if watcher.readable {
        events |= libc::POLLIN;
    }
    if watcher.writable {
        events |= libc::POLLOUT;
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_zero_timeout_returns_immediately() {
        let mut poller = Poller::new().expect("a poller can be built");
        let start = Instant::now();
        assert!(poller.wait(Some(Duration::ZERO)).is_empty());
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn a_timeout_with_nothing_registered_sleeps_for_it() {
        // This is what turns a timer deadline into a real delay rather than a
        // busy loop.
        let mut poller = Poller::new().expect("a poller can be built");
        let start = Instant::now();
        assert!(poller.wait(Some(Duration::from_millis(10))).is_empty());
        assert!(start.elapsed() >= Duration::from_millis(9));
    }

    #[test]
    fn an_unbounded_wait_with_nothing_registered_does_not_hang() {
        let mut poller = Poller::new().expect("a poller can be built");
        let start = Instant::now();
        assert!(poller.wait(None).is_empty());
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn registering_the_same_descriptor_twice_replaces_it() {
        let mut poller = Poller::new().expect("a poller can be built");
        poller.register(Descriptor {
            fd: 3,
            readable: true,
            writable: false,
        });
        poller.register(Descriptor {
            fd: 3,
            readable: false,
            writable: true,
        });
        assert_eq!(poller.registered(), 1);
        poller.deregister(3);
        assert_eq!(poller.registered(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_registered_pipe_reports_readiness() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

        // A pipe with a byte in it is readable, which proves the wait reaches
        // the kernel rather than always timing out.
        let mut pipe_fds: [RawFd; 2] = [0; 2];
        // SAFETY: `pipe_fds` has exactly the two elements `pipe` writes.
        let created = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(created, 0, "pipe(2) must succeed");
        // SAFETY: both descriptors came from `pipe(2)` and are owned here, so
        // wrapping them transfers that ownership and closes them on drop.
        let (reader, writer): (OwnedFd, OwnedFd) = unsafe {
            (
                OwnedFd::from_raw_fd(pipe_fds[0]),
                OwnedFd::from_raw_fd(pipe_fds[1]),
            )
        };
        let mut writer = std::fs::File::from(writer);
        let reader_fd = reader.as_raw_fd();

        let mut poller = Poller::new().expect("a poller can be built");
        poller.register(Descriptor {
            fd: reader_fd,
            readable: true,
            writable: false,
        });
        writer.write_all(b"x").expect("the pipe accepts a byte");

        let ready = poller.wait(Some(Duration::from_millis(500)));
        assert_eq!(ready.descriptors(), &[reader_fd]);
    }

    #[cfg(unix)]
    #[test]
    fn an_idle_descriptor_does_not_report_readiness() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

        let mut pipe_fds: [RawFd; 2] = [0; 2];
        // SAFETY: `pipe_fds` has exactly the two elements `pipe` writes.
        let created = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(created, 0, "pipe(2) must succeed");
        // SAFETY: both descriptors are owned here after this point.
        let (reader, _writer): (OwnedFd, OwnedFd) = unsafe {
            (
                OwnedFd::from_raw_fd(pipe_fds[0]),
                OwnedFd::from_raw_fd(pipe_fds[1]),
            )
        };

        let mut poller = Poller::new().expect("a poller can be built");
        poller.register(Descriptor {
            fd: reader.as_raw_fd(),
            readable: true,
            writable: false,
        });
        // Nothing was written, so the wait must time out with nothing ready.
        assert!(poller.wait(Some(Duration::from_millis(5))).is_empty());
    }
}
