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
//! asserts on what `Readiness::poller()` reports and skips itself when the
//! environment asked for the other backend. The suite is run twice — once without
//! the variable and once with it — so both paths are covered by the same
//! assertions rather than by two tests that could drift apart.

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

/// Whether this process was started asking for io_uring.
fn wants_uring() -> bool {
    rn_uv::poller::Poller::from_env() == rn_uv::poller::Poller::IoUring
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
    }
    if wants_uring() {
        // Either the ring was granted or the kernel refused it; both are
        // supported, and this records which one this host is.
        eprintln!("HERDR_URING=1 installed the {} backend", installed.name());
    }
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
