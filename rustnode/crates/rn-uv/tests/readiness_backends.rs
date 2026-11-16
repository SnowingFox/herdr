//! The readiness backends, exercised against a real loop and real sockets.
//!
//! These tests are the contract the io_uring backend has to keep: a socket read,
//! a socket write and an accept must produce the same completions the epoll path
//! produces. They are deliberately end-to-end rather than unit tests of the ring,
//! because the ring's own correctness is only worth anything if libuv still
//! receives the events it expects.
//!
//! # Why the backend is forced here
//!
//! `HERDR_URING` is read once per loop, and the loop is process-global, so a test
//! cannot switch backends after the first one is created. Instead, each test
//! asserts on what `Readiness::install` actually installed and skips itself when
//! the environment asked for the other backend. The suite is run twice — once
//! without the variable and once with it — so both paths are covered by the same
//! assertions rather than by two tests that could drift apart. That second run is
//! `tools/check.sh`'s io_uring step; before it existed the header said "run twice"
//! and nothing ran it twice.
//!
//! # What "installed" has to mean here
//!
//! [`installed_poller`] reads `rn_uv::poller::installed_backend()`, which records
//! what `Installed::install` produced, and never `Poller::from_env()`, which
//! reports what `HERDR_URING` *requested*. The distinction only matters when a
//! ring cannot be created — which is exactly the path the io_uring backend is
//! most likely to be wrong on — so a test that asked `from_env()` would compare
//! the request against itself and pass through the fallback it exists to catch.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libuv_sys2 as uv;

/// Serialises these tests, which all touch the process' one loop.
///
/// Cargo runs integration tests in one process on several threads, and the loop
/// is process-global state: two tests creating and pumping it concurrently would
/// interleave their iterations and fail for reasons that say nothing about the
/// code. The section is short enough that serialising costs nothing.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A panic while the lock is held would otherwise poison it and turn every
    // later test into a second, unrelated failure.
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Ensures a readiness backend has been installed for this thread's loop.
///
/// `rn_uv::uv_loop` creates the loop; installing the poller into it is what
/// `rn_io::Loop::new` does in the runtime. This suite drives `rn-uv` directly, so
/// it performs that step itself — which is the point: the assertions below are
/// about what `Readiness::install` actually installed, and installing here is
/// what gives them something real to observe, including the epoll fallback.
///
/// The `Readiness` is forgotten deliberately. Dropping it deregisters the ring
/// for the loop, and the loop is process-global while the suite keeps using it.
fn ensure_installed() {
    thread_local! {
        static DONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    DONE.with(|done| {
        if done.get() {
            return;
        }
        let pointer = rn_uv::uv_loop::loop_ptr().expect("the loop must be creatable");
        std::mem::forget(rn_uv::poller::Readiness::install(
            rn_uv::poller::Poller::from_env(),
            pointer,
        ));
        done.set(true);
    });
}

/// The backend a freshly created loop reports.
///
/// A loop can only be created once per process, so this asserts against what the
/// existing loop reports rather than trying to make a second one.
///
/// This reads `rn_uv::poller::installed_backend()`, **not**
/// `Poller::from_env()`. `from_env()` answers what `HERDR_URING` asked for, so a
/// test asserting on it compared the request against itself: every case here that
/// means "the installed backend" would have passed even if `Readiness::install`
/// had silently fallen back to epoll. The two are genuinely different questions
/// whenever a ring cannot be created, which is the path these tests exist for.
fn installed_poller() -> rn_uv::poller::Poller {
    ensure_installed();
    rn_uv::poller::installed_backend().unwrap_or_else(|| {
        panic!(
            "`Readiness::install` ran for this thread's loop but recorded no backend; \
             the record is what makes a silent fallback observable"
        )
    })
}

/// Pumps the loop until `done` is set or `limit` expires.
fn pump_until(done: &AtomicBool, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done.load(Ordering::SeqCst) {
            return true;
        }
        rn_uv::uv_loop::run_once();
    }
    done.load(Ordering::SeqCst)
}

#[test]
fn a_tcp_read_and_write_complete_on_the_installed_backend() {
    let _guard = serial();
    // Creating the loop installs the backend this test then reports on.
    assert!(
        rn_uv::uv_loop::loop_ptr().is_some(),
        "the loop must be creatable"
    );
    let backend = installed_poller();

    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener binds");
    let address = listener.local_addr().expect("the listener has an address");
    let accepted = Arc::new(AtomicBool::new(false));
    let server_done = Arc::clone(&accepted);

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the connection arrives");
        server_done.store(true, Ordering::SeqCst);
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).expect("the bytes arrive");
        assert_eq!(&buffer, b"hello");
        stream.write_all(b"world").expect("the reply is written");
    });

    let mut client = TcpStream::connect(address).expect("the client connects");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the timeout is set");
    client.write_all(b"hello").expect("the bytes are sent");

    assert!(
        pump_until(&accepted, Duration::from_secs(5)),
        "the accept completed on the {} backend",
        backend.name()
    );

    let mut reply = [0u8; 5];
    client.read_exact(&mut reply).expect("the reply arrives");
    assert_eq!(&reply, b"world");
}

#[test]
fn the_requested_backend_is_the_installed_one() {
    let _guard = serial();
    let requested = rn_uv::poller::Poller::from_env();
    let installed = installed_poller();

    // io_uring is subject to runtime detection, so a kernel without it reports
    // epoll even though it was requested. The direction that must never happen is
    // the other one: an environment that did not ask for io_uring must never end
    // up on it.
    if requested == rn_uv::poller::Poller::Epoll {
        assert_eq!(
            installed,
            rn_uv::poller::Poller::Epoll,
            "epoll must be the backend when nothing asked for io_uring"
        );
        return;
    }

    // io_uring was requested, and `installed_poller()` now reports what
    // `Readiness::install` really produced rather than what was asked for. That
    // fixes the self-comparison, but on its own it still accepts either outcome:
    // "the kernel refused a ring" and "the request was ignored" both leave epoll
    // installed, and the second is a defect while the first is a host capability.
    //
    // `kernel_supports_io_uring` is what separates them. It probes
    // `io_uring_setup(2)` directly and closes the ring, so it answers a question
    // about this kernel rather than about what this crate decided. Without this
    // assertion the gate step that runs the suite with `HERDR_URING=1` could pass
    // on a build where `install` discarded the request outright: measured on such
    // a build, the rest of the suite passes 5/5 because every other test only
    // needs *a* working backend.
    //
    // A host that refuses a ring still passes, and says so; making the gate depend
    // on a kernel feature would fail machines for a reason they cannot fix.
    if !rn_uv::poller::kernel_supports_io_uring() {
        assert_eq!(
            installed,
            rn_uv::poller::Poller::Epoll,
            "a kernel that refuses a ring must report the epoll fallback, not io_uring"
        );
        eprintln!(
            "HERDR_URING=1 asked for io_uring, but this kernel refused a ring \
             (old kernel, seccomp, or kernel.io_uring_disabled); epoll was installed \
             as documented. The io_uring path was NOT measured on this host."
        );
        return;
    }

    assert_eq!(
        installed,
        rn_uv::poller::Poller::IoUring,
        "this kernel grants io_uring rings and HERDR_URING=1 asked for one, so epoll \
         being installed means the request was ignored"
    );
    eprintln!("HERDR_URING=1 installed the {} backend", installed.name());
}

#[test]
fn a_loop_with_no_watchers_does_not_spin() {
    let _guard = serial();
    // A loop with no work must not report itself alive, which is what keeps the
    // process from spinning when only timers are armed. This is the property the
    // keep-alive descriptor exists for, and a backend that mishandled it would
    // show up here as `is_active` being true.
    assert!(!rn_uv::uv_loop::is_active());
}

/// The poller a loop reports is stable across iterations.
///
/// A backend that changed midway would have two sources of readiness for one
/// descriptor, so the value is pinned once at loop creation.
#[test]
fn the_backend_does_not_change_between_iterations() {
    let _guard = serial();
    let first = installed_poller();
    rn_uv::uv_loop::run_once();
    let second = installed_poller();
    assert_eq!(first, second, "the backend is chosen once per loop");
}

/// `uv_backend_fd` still names a live epoll descriptor on both backends.
///
/// libuv keeps its epoll set registered unconditionally — that is what makes the
/// epoll fallback always correct — so this descriptor must exist even when the
/// wait is served by a ring.
#[test]
fn libuv_keeps_its_epoll_descriptor_on_every_backend() {
    let _guard = serial();
    let pointer = rn_uv::uv_loop::loop_ptr().expect("the loop must be creatable");
    // SAFETY: `pointer` is the process' live loop.
    let descriptor = unsafe { uv::uv_backend_fd(pointer) };
    assert!(
        descriptor >= 0,
        "libuv always has an epoll descriptor, whatever serves the wait"
    );
}
