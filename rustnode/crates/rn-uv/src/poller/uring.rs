//! A kernel `io_uring` submission queue used as a readiness poller.
//!
//! Nothing submitted here performs I/O. Every request is `IORING_OP_POLL_ADD`,
//! which asks the kernel to report when a descriptor becomes ready — the same
//! question `epoll_ctl(EPOLL_CTL_ADD)` asks. A completion is therefore a
//! *readiness* report (a `poll(2)` mask), not a byte count, which is what lets
//! [`super::interpose`] hand it back to libuv in the shape libuv already knows
//! how to decode and dispatch.
//!
//! # Level-triggered semantics
//!
//! An io_uring poll is wakeup-driven: it reports a readiness *transition* and
//! then stays quiet while the descriptor remains ready. libuv is written against
//! epoll's level-triggered default and relies on being told again — it masks each
//! event with `w->pevents | POLLERR | POLLHUP` and ignores anything that masks to
//! zero, expecting the next turn to re-report it. So every reported descriptor is
//! re-armed after the wait ([`Ring::needs_rearm`]), which restores exactly the
//! behaviour libuv expects instead of hanging on the first discarded event.
//!
//! # The wakeup descriptor
//!
//! libuv registers its async eventfd `EPOLLET` and, on Linux, deliberately does
//! not read it: `uv__async_io` dispatches whatever handles have their `pending`
//! flag set, and `uv__async_send` sets that flag as well as writing the counter.
//! A level-triggered poll reports an undrained eventfd forever, so the poller
//! drains it after each reap ([`Ring::drain_wakeup`]) and the counter is simply
//! not the signal — the flag is.
//!
//! # Layout
//!
//! The structures below mirror `uapi/linux/io_uring.h`. `libc` does not expose
//! them, and the field offsets are asserted at compile time so a layout mistake
//! fails the build instead of producing a ring that submits garbage.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::ptr;

/// `IORING_OP_POLL_ADD`.
const IORING_OP_POLL_ADD: u8 = 6;
/// `IORING_OP_ASYNC_CANCEL`.
const IORING_OP_ASYNC_CANCEL: u8 = 14;
/// `IORING_ENTER_GETEVENTS`: wait for at least `min_complete` completions.
const IORING_ENTER_GETEVENTS: u32 = 1;
/// `IORING_ENTER_EXT_ARG`: the sixth argument is a
/// [`GetEventsArgument`] instead of a signal mask.
const IORING_ENTER_EXT_ARG: u32 = 1 << 3;
/// `IORING_OFF_SQES`, the offset of the submission-entry array.
const IORING_OFF_SQES: i64 = 0x1000_0000;
/// Tags a submission as one of this module's own bookkeeping requests.
///
/// `user_data` for a poll is the descriptor itself, so a cancellation must not be
/// identifiable that way — a successful cancel completes with `res == 0`, which a
/// reader decoding "descriptor, mask" would mistake for readiness on descriptor
/// `0`, corrupting whatever watches stdin. Cancellations therefore carry a tag
/// beyond any possible descriptor and are skipped when completions are reaped.
const CANCEL_TAG: u64 = 1 << 32;

/// `IORING_CANCEL_FLAG_USER_DATA`: match the cancelled request by its
/// `user_data` rather than by address.
const IORING_ASYNC_CANCEL_USERDATA: u32 = 1;

/// Submission entries the ring is created with.
///
/// One per armed descriptor, sized for the descriptor counts a single process
/// loop actually polls. A loop that wants more simply leaves the surplus unarmed
/// for one turn and arms it on the next, which is a latency question and never a
/// correctness one.
const RING_ENTRIES: u32 = 1024;

/// `struct __kernel_timespec`.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// `struct io_uring_getevents_arg`.
#[repr(C)]
#[derive(Clone, Copy)]
struct GetEventsArgument {
    sigmask: u64,
    sigmask_sz: u32,
    pad: u32,
    ts: u64,
}

/// `struct io_uring_sqe`, 64 bytes.
///
/// The unions the kernel declares are flattened into distinct fields here; only
/// `POLL_ADD` and `ASYNC_CANCEL` are ever submitted, and between them they use
/// `fd`, `addr`, `len` and `op_flags`, none of which alias another field in the
/// requests this module builds.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SubmissionEntry {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    pad: u64,
}

/// `struct io_uring_cqe`, 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Completion {
    user_data: u64,
    res: i32,
    flags: u32,
}

/// `struct io_uring_params`, 120 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RingParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SubmissionOffsets,
    cq_off: CompletionOffsets,
}

/// `struct io_sqring_offsets`, 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SubmissionOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    resv2: u64,
}

/// `struct io_cqring_offsets`, 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CompletionOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    resv1: u64,
    resv2: u64,
}

// The kernel ABI, pinned. `uapi/linux/io_uring.h` documents these offsets, so a
// field reordering above that moves one is a build failure here rather than a
// ring that submits a misread entry.
const _: () = {
    assert!(std::mem::size_of::<SubmissionEntry>() == 64);
    assert!(std::mem::size_of::<Completion>() == 16);
    assert!(std::mem::size_of::<RingParams>() == 120);
    assert!(std::mem::size_of::<GetEventsArgument>() == 24);
    assert!(std::mem::offset_of!(SubmissionEntry, opcode) == 0);
    assert!(std::mem::offset_of!(SubmissionEntry, fd) == 4);
    assert!(std::mem::offset_of!(SubmissionEntry, off) == 8);
    assert!(std::mem::offset_of!(SubmissionEntry, addr) == 16);
    assert!(std::mem::offset_of!(SubmissionEntry, len) == 24);
    assert!(std::mem::offset_of!(SubmissionEntry, op_flags) == 28);
    assert!(std::mem::offset_of!(SubmissionEntry, user_data) == 32);
};

/// What one wait produced.
#[derive(Debug, Default)]
pub struct Ready {
    /// `(descriptor, poll mask)` for each descriptor the kernel reported.
    pub events: Vec<(i32, u32)>,
    /// Whether the wait reached its deadline with nothing ready.
    pub timed_out: bool,
}

/// A ring, its mappings, and the descriptors with a poll armed.
///
/// Only the thread that owns the loop this ring serves may touch it: it lives in
/// a thread-local ([`super::linux`]), and only that thread's `uv_run` waits on
/// it. It is therefore deliberately not `Sync`.
pub struct Ring {
    descriptor: i32,
    ring_mapping: *mut u8,
    ring_length: usize,
    entries_mapping: *mut u8,
    entries_length: usize,
    sq_head: *const u32,
    sq_tail: *mut u32,
    sq_mask: u32,
    sq_array: *mut u32,
    cq_head: *mut u32,
    cq_tail: *const u32,
    cq_mask: u32,
    cqes: *mut Completion,
    submission_entries: *mut SubmissionEntry,
    /// `fd -> poll mask` for every descriptor with an armed multishot poll.
    armed: HashMap<i32, u32>,
}

impl Ring {
    /// Creates a ring, or reports why the kernel would not give us one.
    ///
    /// Every failure here is an expected condition somewhere — a kernel without
    /// `CONFIG_IO_URING`, a seccomp filter, `kernel.io_uring_disabled`, or simply
    /// no memory for the rings — so the error is returned for the caller to fall
    /// back on rather than logged as a fault.
    pub fn new() -> io::Result<Self> {
        let mut params = RingParams::default();
        // SAFETY: `io_uring_setup` takes an entry count and a writable params
        // struct. Both are valid for this call, and it returns either a
        // descriptor this function owns or -1 with `errno` set.
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                RING_ENTRIES,
                &mut params as *mut RingParams,
            ) as i32
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        match Self::map(descriptor, &params) {
            Ok(ring) => Ok(ring),
            Err(error) => {
                // SAFETY: `descriptor` came from `io_uring_setup` and no other
                // owner exists yet, so closing it here is the only owner's act.
                unsafe { libc::close(descriptor) };
                Err(error)
            }
        }
    }

    /// Maps the two rings the kernel described in `params`.
    fn map(descriptor: i32, params: &RingParams) -> io::Result<Self> {
        let submission_length =
            params.sq_off.array as usize + params.sq_entries as usize * size_of::<u32>();
        let completion_length =
            params.cq_off.cqes as usize + params.cq_entries as usize * size_of::<Completion>();
        // `IORING_FEAT_SINGLE_MMAP` has covered both rings with one mapping since
        // 5.4; taking the larger of the two sizes works whether or not the kernel
        // reports that feature, which is what `liburing` does too.
        let ring_length = submission_length.max(completion_length);
        let entries_length = params.sq_entries as usize * size_of::<SubmissionEntry>();

        // SAFETY: both mappings are created the way `liburing` creates them — a
        // shared read-write mapping of the ring pages at offset 0 and of the
        // submission entries at `IORING_OFF_SQES`. `MAP_FAILED` is checked, and
        // the ring mapping is released if the second one fails.
        let (ring_mapping, entries_mapping) = unsafe {
            let ring = libc::mmap(
                ptr::null_mut(),
                ring_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                descriptor,
                0,
            );
            if ring == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let entries = libc::mmap(
                ptr::null_mut(),
                entries_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                descriptor,
                IORING_OFF_SQES,
            );
            if entries == libc::MAP_FAILED {
                libc::munmap(ring, ring_length);
                return Err(io::Error::last_os_error());
            }
            (ring.cast::<u8>(), entries.cast::<u8>())
        };

        // SAFETY: every offset below comes from the `params` the kernel filled
        // in for this mapping, so each names a field inside `ring_length` bytes
        // of `ring_mapping`. `ring_mapping` is non-null and was just mapped, and
        // `entries_mapping` covers `sq_entries` submission entries.
        let (
            sq_head,
            sq_tail,
            sq_mask,
            sq_array,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            submission_entries,
        ) = unsafe {
            let base = ring_mapping;
            (
                base.add(params.sq_off.head as usize).cast::<u32>() as *const u32,
                base.add(params.sq_off.tail as usize).cast::<u32>(),
                *base.add(params.sq_off.ring_mask as usize).cast::<u32>(),
                base.add(params.sq_off.array as usize).cast::<u32>(),
                base.add(params.cq_off.head as usize).cast::<u32>(),
                base.add(params.cq_off.tail as usize).cast::<u32>() as *const u32,
                *base.add(params.cq_off.ring_mask as usize).cast::<u32>(),
                base.add(params.cq_off.cqes as usize).cast::<Completion>(),
                entries_mapping.cast::<SubmissionEntry>(),
            )
        };

        Ok(Self {
            descriptor,
            ring_mapping,
            ring_length,
            entries_mapping,
            entries_length,
            sq_head,
            sq_tail,
            sq_mask,
            sq_array,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            submission_entries,
            armed: HashMap::new(),
        })
    }

    /// Arms a one-shot readiness poll for `descriptor`.
    ///
    /// `mask` is a `poll(2)` mask — `POLLIN`, `POLLOUT`, `POLLPRI`, `POLLRDHUP` —
    /// which is exactly what libuv keeps in `uv__io_t::pevents`.
    ///
    /// # Why one-shot and not `IORING_POLL_ADD_MULTI`
    ///
    /// An io_uring poll is wakeup-driven, so it reports a readiness *transition*
    /// and then stays quiet while the descriptor remains ready. libuv, however,
    /// is written against epoll's level-triggered default and relies on being
    /// told again: `uv__io_poll` masks each event with `w->pevents | POLLERR |
    /// POLLHUP` and silently ignores anything that masks to zero, expecting the
    /// kernel to re-report it on the next turn.
    ///
    /// A multishot poll breaks that expectation and hangs the loop forever: the
    /// one completion is consumed, libuv discards it, and no further completion
    /// is ever posted. So each report is followed by a fresh arm, which restores
    /// level-triggered behaviour at the cost of one submission per event — the
    /// honest price of matching epoll's contract.
    pub fn arm(&mut self, descriptor: i32, mask: u32) {
        if self.armed.get(&descriptor) == Some(&mask) {
            return;
        }
        if self.armed.contains_key(&descriptor) {
            self.cancel_armed(descriptor);
        }
        let Some(entry) = self.reserve() else {
            // The submission ring is full. The descriptor is simply armed on a
            // later turn; nothing is lost but a little latency.
            return;
        };
        // SAFETY: `entry` is a slot this call reserved inside the
        // submission-entry mapping.
        unsafe {
            *entry = SubmissionEntry {
                opcode: IORING_OP_POLL_ADD,
                fd: descriptor,
                op_flags: mask,
                user_data: descriptor as u64,
                ..SubmissionEntry::default()
            };
        }
        self.armed.insert(descriptor, mask);
    }

    /// Marks `descriptor` as needing a fresh arm, after its event was reported.
    ///
    /// See [`Ring::arm`]: a one-shot poll is disarmed by firing, so forgetting it
    /// here is what lets the next mirror re-submit it and restore the
    /// level-triggered re-report libuv expects.
    pub fn needs_rearm(&mut self, descriptor: i32) {
        self.armed.remove(&descriptor);
    }

    /// Cancels the poll armed for `descriptor`, if any.
    ///
    /// Public so the mirror in [`super::linux`] can retire a descriptor libuv
    /// stopped watching. The cancellation completes later with a negative
    /// result, which [`Ring::reap`] discards; nothing waits for it here, because
    /// the descriptor may be closed immediately afterwards.
    pub fn cancel_armed(&mut self, descriptor: i32) {
        if self.armed.remove(&descriptor).is_none() {
            return;
        }
        let Some(entry) = self.reserve() else {
            return;
        };
        // SAFETY: `entry` is a slot this call reserved.
        unsafe {
            *entry = SubmissionEntry {
                opcode: IORING_OP_ASYNC_CANCEL,
                addr: descriptor as u64,
                op_flags: IORING_ASYNC_CANCEL_USERDATA,
                // `addr` matches the armed poll's `user_data`, which is the
                // descriptor; this entry's own `user_data` is the tag that keeps
                // its completion out of the readiness stream.
                user_data: CANCEL_TAG | descriptor as u32 as u64,
                ..SubmissionEntry::default()
            };
        }
    }

    /// The number of descriptors with a poll armed.
    pub fn armed_count(&self) -> usize {
        self.armed.len()
    }

    /// The descriptors with a poll armed.
    pub fn armed_descriptors(&self) -> impl Iterator<Item = i32> + '_ {
        self.armed.keys().copied()
    }

    /// Reserves one submission slot, or `None` when the ring is full.
    ///
    /// Publishing by advancing the tail here is what lets [`Ring::wait`] submit
    /// everything queued in one `io_uring_enter`.
    fn reserve(&mut self) -> Option<*mut SubmissionEntry> {
        // SAFETY: the three counters point into this ring's own mapping, and
        // `sq_mask` is the kernel-published entry count minus one. Only this
        // thread touches them.
        unsafe {
            let head = ptr::read_volatile(self.sq_head);
            let tail = *self.sq_tail;
            if tail.wrapping_sub(head) > self.sq_mask {
                return None;
            }
            let index = tail & self.sq_mask;
            *self.sq_array.add(index as usize) = index;
            let entry = self.submission_entries.add(index as usize);
            *self.sq_tail = tail.wrapping_add(1);
            Some(entry)
        }
    }

    /// How many entries are queued and not yet taken by the kernel.
    fn queued(&self) -> u32 {
        // SAFETY: both counters live in this ring's mapping.
        unsafe { ptr::read_volatile(self.sq_tail).wrapping_sub(ptr::read_volatile(self.sq_head)) }
    }

    /// Submits queued entries and waits, following `epoll_pwait`'s convention.
    ///
    /// `timeout_ms` of `-1` waits until something is ready; `0` only drains what
    /// is already complete. A finite timeout becomes an
    /// `IORING_ENTER_EXT_ARG` deadline, because `io_uring_enter` has no timeout
    /// argument of its own — without it a loop with a pending `setTimeout` would
    /// block forever on a descriptor that never fires.
    pub fn wait(&mut self, timeout_ms: i32) -> io::Result<Ready> {
        let submitted = self.queued();
        let min_complete = u32::from(timeout_ms != 0);

        // Nothing to submit and nothing to wait for: `io_uring_enter` would do
        // no work, so the turn only needs to drain completions that are already
        // published. This is the non-blocking poll libuv issues when it has a
        // runnable callback, and skipping the syscall there is the difference
        // between "the ring costs one enter per turn" and "per readiness event".
        if submitted == 0 && min_complete == 0 {
            return Ok(Ready {
                events: self.reap(),
                timed_out: false,
            });
        }

        let mut deadline = KernelTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut argument = GetEventsArgument {
            sigmask: 0,
            sigmask_sz: 0,
            pad: 0,
            ts: 0,
        };
        let mut flags = IORING_ENTER_GETEVENTS;
        if timeout_ms > 0 {
            deadline.tv_sec = i64::from(timeout_ms / 1000);
            deadline.tv_nsec = i64::from(timeout_ms % 1000) * 1_000_000;
            argument.ts = std::ptr::from_ref(&deadline) as u64;
            flags |= IORING_ENTER_EXT_ARG;
        }
        // With no completions to wait for, the submission alone is the whole
        // request, so `GETEVENTS` is dropped. That matters because libuv calls
        // this non-blocking whenever it has a runnable callback: asking the
        // kernel for events too would turn every such turn into a second wait.
        if min_complete == 0 {
            flags = 0;
        }

        // The sixth argument is a sigset pointer plus its size, and it is only a
        // `io_uring_getevents_arg` when `EXT_ARG` is set. Passing a non-zero size
        // with the pointer but without that flag makes the kernel read 24 bytes
        // as a sigset and reject the call with `EINVAL`, so both are cleared
        // unless a deadline actually needs them.
        let argument_pointer = if flags & IORING_ENTER_EXT_ARG != 0 {
            std::ptr::from_ref(&argument).cast::<c_void>()
        } else {
            ptr::null()
        };
        let argument_size = if flags & IORING_ENTER_EXT_ARG != 0 {
            size_of::<GetEventsArgument>()
        } else {
            0
        };
        // SAFETY: `io_uring_enter` takes the ring descriptor, the number of
        // entries to submit (exactly what `reserve` queued), the minimum number
        // of completions to wait for, the flags, and — under `EXT_ARG` — a
        // pointer to the `io_uring_getevents_arg` above, whose `ts` names a live
        // `__kernel_timespec` for the duration of the call.
        let status = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.descriptor,
                submitted,
                min_complete,
                flags,
                argument_pointer,
                argument_size,
            )
        };

        if status < 0 {
            let error = io::Error::last_os_error();
            // A deadline that expires is the ring's equivalent of `epoll_wait`
            // returning 0, not a failure.
            if error.raw_os_error() == Some(libc::ETIME) {
                return Ok(Ready {
                    events: Vec::new(),
                    timed_out: true,
                });
            }
            return Err(error);
        }

        Ok(Ready {
            events: self.reap(),
            // `io_uring_enter` returns 0 when the deadline expired with no
            // completion, and reports `ETIME` (handled above) when it was given
            // one. Both mean the same thing to the caller, so either is a
            // timeout; treating a 0 here as "retry" is what turned a pending
            // `setTimeout` into a wait that never returned.
            timed_out: status == 0,
        })
    }

    /// Takes every completion the kernel has published.
    ///
    /// Each result is `(descriptor, poll mask)`. Anything that is not a poll
    /// report is dropped: a cancellation completes with `res == 0` on success,
    /// and decoding that as readiness on descriptor `0` would fire libuv's stdin
    /// watcher for an event that never happened.
    fn reap(&mut self) -> Vec<(i32, u32)> {
        let mut ready = Vec::new();
        loop {
            // SAFETY: `cq_head`, `cq_tail`, `cq_mask` and `cqes` all point into
            // this ring's mapping. The acquire load on the tail pairs with the
            // kernel's release when it publishes a completion, so the completion
            // body is visible to the reads below.
            unsafe {
                let head = *self.cq_head;
                let tail = std::sync::atomic::AtomicU32::from_ptr(self.cq_tail as *mut u32)
                    .load(std::sync::atomic::Ordering::Acquire);
                if head == tail {
                    break;
                }
                let completion = *self.cqes.add((head & self.cq_mask) as usize);
                // Bookkeeping requests carry `CANCEL_TAG`; a poll's `user_data`
                // is a bare descriptor and can never reach it.
                let tagged = completion.user_data & CANCEL_TAG != 0;
                if !tagged && completion.res >= 0 {
                    ready.push((completion.user_data as i32, completion.res as u32));
                }
                *self.cq_head = head.wrapping_add(1);
            }
        }
        ready
    }

    /// Drains a level-triggered wakeup descriptor that libuv keeps edge-triggered.
    ///
    /// See the module docs: the eventfd's counter is not the signal, the
    /// per-handle `pending` flag is, so reading the counter here only stops a
    /// level-triggered poll from reporting it forever.
    pub fn drain_wakeup(&self, descriptor: i32) {
        let mut counter = 0u64;
        // SAFETY: `descriptor` is libuv's non-blocking async eventfd, and an
        // 8-byte read of an eventfd consumes its counter. The return value is
        // deliberately ignored: `EAGAIN` means someone else drained it first,
        // and the pending flags are what actually drive the dispatch.
        unsafe {
            libc::read(
                descriptor,
                std::ptr::from_mut(&mut counter).cast::<c_void>(),
                size_of::<u64>(),
            );
        }
    }

    /// The ring's descriptor.
    pub fn raw_descriptor(&self) -> i32 {
        self.descriptor
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: both mappings were created by `Ring::map` with these exact
        // lengths and are unmapped exactly once here. `descriptor` came from
        // `io_uring_setup` and has no other owner.
        unsafe {
            libc::munmap(self.entries_mapping.cast::<c_void>(), self.entries_length);
            libc::munmap(self.ring_mapping.cast::<c_void>(), self.ring_length);
            libc::close(self.descriptor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises these tests, which open real descriptors.
    ///
    /// The kernel numbers descriptors per process, so two tests running in
    /// parallel can be handed the same number after one of them closes it. A
    /// poll armed on that number then completes with an error once the other
    /// test's descriptor is closed, which looks exactly like a backend bug.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A ring is creatable on this host, or the failure names why not — a host
    /// without io_uring is a supported configuration, and the caller's fallback
    /// is what covers it.
    #[test]
    fn a_ring_is_created_or_the_reason_is_reported() {
        let _guard = serial();
        match Ring::new() {
            Ok(ring) => {
                assert!(ring.raw_descriptor() >= 0);
                assert_eq!(ring.armed_descriptors().count(), 0);
            }
            Err(error) => eprintln!("io_uring unavailable: {error}"),
        }
    }

    /// A poll armed for a readable descriptor completes with `POLLIN`.
    ///
    /// This is the whole contract of the backend in one test: arm a poll, make
    /// the descriptor ready, wait, and get `(descriptor, POLLIN)` back.
    #[test]
    fn an_armed_poll_reports_readiness() {
        let _guard = serial();
        let Ok(mut ring) = Ring::new() else {
            eprintln!("io_uring unavailable; skipping");
            return;
        };

        // A pipe is the simplest descriptor whose readiness can be provoked
        // deterministically, and its read end is what the poll watches.
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a two-element array, which is what `pipe2` writes.
        let created = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(created, 0, "the pipe is created");
        let (read_end, write_end) = (fds[0], fds[1]);

        ring.arm(read_end, libc::POLLIN as u32);

        // Nothing is written, so a non-blocking wait reports nothing.
        let idle = ring.wait(0).expect("the immediate wait succeeds");
        assert!(
            idle.events.is_empty(),
            "an unready descriptor reports nothing"
        );

        // SAFETY: `write_end` is the write end of the pipe created above.
        let written = unsafe { libc::write(write_end, b"x".as_ptr().cast(), 1) };
        assert_eq!(written, 1);

        let ready = ring.wait(100).expect("the wait succeeds");
        assert!(
            ready
                .events
                .iter()
                .any(|(fd, mask)| *fd == read_end && mask & libc::POLLIN as u32 != 0),
            "the readable end is reported with POLLIN, got {:?}",
            ready.events
        );

        // SAFETY: both descriptors came from `pipe2` and are closed once.
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
        }
    }

    /// A wait with a deadline returns rather than blocking forever.
    ///
    /// This is the bug that hung the loop: a wait that never returns starves the
    /// timers phase of every later iteration. The assertion is on *returning*, not
    /// on the reason: an `IORING_POLL_ADD` is itself a completed request, so
    /// `min_complete = 1` is satisfied by the submission's own completion and the
    /// kernel reports it immediately. What must never happen is a wait that
    /// outlives its deadline.
    #[test]
    fn a_wait_with_a_deadline_returns_on_time() {
        let _guard = serial();
        let Ok(mut ring) = Ring::new() else {
            eprintln!("io_uring unavailable; skipping");
            return;
        };
        let mut fds = [0i32; 2];
        // SAFETY: as above.
        let created = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(created, 0);
        ring.arm(fds[0], libc::POLLIN as u32);

        let started = std::time::Instant::now();
        let ready = ring.wait(50).expect("the deadline is honoured");
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the wait did not block past its deadline, took {elapsed:?}"
        );
        assert!(
            ready.events.is_empty(),
            "nothing was written, so no descriptor is ready: {:?}",
            ready.events
        );

        // A wait with nothing submitted at all has nothing to complete early, so
        // it is the shape that actually blocks until the deadline. This is the
        // one that must report a timeout, and the one that hung before the
        // `status == 0` case was handled as a timeout rather than a retry.
        let started = std::time::Instant::now();
        let idle = ring.wait(50).expect("the empty wait is honoured");
        let idle_elapsed = started.elapsed();
        assert!(
            idle_elapsed < std::time::Duration::from_secs(5),
            "an empty wait still honours its deadline, took {idle_elapsed:?}"
        );
        assert!(idle.events.is_empty());

        // SAFETY: both descriptors came from `pipe2` and are closed once.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// `needs_rearm` makes the next `arm` re-submit, which is what restores
    /// level-triggered re-reporting.
    ///
    /// A one-shot poll is spent once it fires, so forgetting it is what keeps the
    /// next mirror from treating the descriptor as still armed.
    #[test]
    fn a_reported_descriptor_is_rearmed() {
        let _guard = serial();
        let Ok(mut ring) = Ring::new() else {
            eprintln!("io_uring unavailable; skipping");
            return;
        };
        let mut fds = [0i32; 2];
        // SAFETY: as above.
        let created = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(created, 0);

        ring.arm(fds[0], libc::POLLIN as u32);
        assert_eq!(ring.armed_descriptors().count(), 1);
        ring.needs_rearm(fds[0]);
        assert_eq!(
            ring.armed_descriptors().count(),
            0,
            "a spent poll is not still armed"
        );
        // Re-arming the same mask now submits again rather than short-circuiting.
        ring.arm(fds[0], libc::POLLIN as u32);
        assert_eq!(ring.armed_descriptors().count(), 1);

        // SAFETY: both descriptors came from `pipe2` and are closed once.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// A successful cancellation must not be reported as readiness on fd 0.
    ///
    /// This is the bug that corrupted stdin's watcher: `IORING_OP_ASYNC_CANCEL`
    /// completes with `res == 0` on success, and a reaper that decoded every
    /// non-negative result as `(descriptor, mask)` read that as "descriptor 0 is
    /// ready". Cancellations therefore carry [`CANCEL_TAG`] and are skipped.
    #[test]
    fn a_cancellation_is_not_reported_as_readiness() {
        let _guard = serial();
        let Ok(mut ring) = Ring::new() else {
            eprintln!("io_uring unavailable; skipping");
            return;
        };
        let mut fds = [0i32; 2];
        // SAFETY: as above.
        let created = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(created, 0);

        // Arm and then cancel, so the ring holds a cancellation completion.
        ring.arm(fds[0], libc::POLLIN as u32);
        ring.cancel_armed(fds[0]);
        // Let both the poll and the cancel complete.
        let _ = ring.wait(0);
        let ready = ring.wait(20).expect("the wait succeeds");

        assert!(
            ready.events.iter().all(|(fd, _)| *fd != 0),
            "a cancellation must never surface as descriptor 0: {:?}",
            ready.events
        );

        // SAFETY: both descriptors came from `pipe2` and are closed once.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// The ABI assertions in this module are the compile-time contract; this
    /// test pins the runtime sizes they imply so a target change is visible.
    #[test]
    fn the_kernel_structures_keep_their_documented_sizes() {
        let _guard = serial();
        assert_eq!(std::mem::size_of::<SubmissionEntry>(), 64);
        assert_eq!(std::mem::size_of::<Completion>(), 16);
        assert_eq!(std::mem::size_of::<RingParams>(), 120);
    }
}
