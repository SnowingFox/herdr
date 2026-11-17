//! Pausing actually stops JavaScript.
//!
//! This file exists because of how the previous slice failed. `run_message_loop_on_pause`
//! was empty, so `Debugger.pause` was acknowledged and execution continued — the debugger
//! *looked* like it worked while doing nothing. Every test here therefore asserts on an
//! observable that only a real pause produces:
//!
//! * a statement scheduled after the pause has **not** run when the pause returns;
//! * it runs only after `Debugger.resume`;
//! * `Debugger.paused` reached the frontend with a real reason and call frame;
//! * the pause ends on its own when the frontend disconnects.
//!
//! The pause is driven from a second thread, because that is the only way to prove it
//! blocks: a single-threaded test would either hang or assert on the wrong thing.

use std::sync::mpsc;
use std::time::Duration;

use rn_bind_inspector::Inspector;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Serialises the whole file.
///
/// The paused state is process-global on purpose — it mirrors Node's `Agent`, which is
/// one per environment and does not vary per test — so two of these tests running at
/// once would each see the other's `resume` and `set_attached`. A `--test-threads=1`
/// invocation would also work, but making it a property of the file means a future
/// reader cannot lose it by running the crate normally.
static PAUSE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // Both locks, always in this order: `PAUSE_LOCK` first so only one test touches the
    // pause state, then the isolate. Reversing the order in one test would deadlock the
    // pair.
    let _pause_guard = PAUSE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    rn_bind_inspector::set_isolate(&mut isolate);
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let scope = std::pin::pin!(v8::ContextScope::new(&mut scope, context));
    let mut scope = scope;
    body(&mut scope)
}

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace and binds it to `__inspector`.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = Inspector
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the inspector namespace");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__inspector").expect("allocating __inspector");
    global.set(scope, key.into(), object.into());
}

/// Compiles and runs `source`, returning its completion value as a string.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let text = source;
    let source = v8::String::new(scope, source).expect("allocating the script");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = try_catch.init();
    let script = match v8::Script::compile(&scope, source, None) {
        Some(script) => script,
        None => {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(&scope))
                .unwrap_or_else(|| "no exception reported".to_string());
            panic!("the script must compile: {message}\n--- source ---\n{text}");
        }
    };
    let result = script.run(&scope);
    if scope.has_caught() {
        let exception = scope.exception().expect("a caught exception");
        panic!(
            "the script threw: {}",
            exception.to_rust_string_lossy(&scope)
        );
    }
    result
        .map(|value| value.to_rust_string_lossy(&scope))
        .unwrap_or_default()
}

/// A frontend that collects messages and can resume from another thread.
///
/// The real frontend is a socket; here it is a channel, because the property under test
/// is "the isolate stops" rather than "a socket carries the bytes".
const FRONTEND: &str = r#"
globalThis.messages = [];
globalThis.session = new __inspector.Connection(function (message) {
  messages.push(message);
  const parsed = JSON.parse(message);
  // `Debugger.paused` is what a client reacts to. This stands in for
  // `test/common/inspector-helper.js`, which does the same thing and then sends
  // `Debugger.resume`.
  if (parsed.method === 'Debugger.paused') {
    globalThis.sawPaused = parsed.params;
  }
});
globalThis.post = function post(message) { session.dispatch(JSON.stringify(message)); };
"#;

#[test]
fn a_pause_blocks_until_resume() {
    // The claim the previous slice got wrong, asserted without leaning on the timeout:
    // the pause must still be running at a moment when an unresumed no-op would already
    // have returned. A test that let the pause expire would pass on a broken
    // implementation after thirty seconds, so the elapsed assertions are here as well
    // as the flag checks.
    with_context(|scope| {
        install(scope);
        run(scope, FRONTEND);
        run(scope, "post({ id: 1, method: 'Debugger.enable' })");
        assert_eq!(
            run(scope, "String(messages.length > 0)"),
            "true",
            "Debugger.enable must be acknowledged"
        );

        // A frontend has to be attached for a pause to wait at all; without one the
        // pause is a no-op, which is what keeps `--inspect-brk` from hanging.
        rn_bind_inspector::set_frontend_attached(true);
        rn_bind_inspector::arm_pause_for_test();

        // The statement after the pause. If the pause does not block, this runs and the
        // assertion below sees it did.
        run(scope, "globalThis.afterPause = 'not yet';");

        let (started_tx, started_rx) = mpsc::channel();
        let resumer = std::thread::spawn(move || {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the pause must announce that it started");
            // Long enough that the pause is demonstrably still running when resume
            // arrives, short enough that the test stays quick.
            std::thread::sleep(Duration::from_millis(300));
            rn_bind_inspector::resume();
        });

        started_tx.send(()).expect("announcing the pause");
        let paused_at = std::time::Instant::now();
        let blocked = rn_bind_inspector::run_pause_loop_for_test(scope);
        let waited = paused_at.elapsed();
        resumer.join().expect("the resumer thread");

        assert!(
            blocked,
            "a pause with a frontend attached must actually wait"
        );
        assert!(
            waited >= Duration::from_millis(250),
            "the pause must stay paused until resume arrives, but returned after {waited:?}; \
             returning immediately is the shape this slice exists to fix"
        );
        assert!(
            waited < Duration::from_secs(5),
            "the pause must end when resume is called rather than timing out, waited {waited:?}"
        );
        assert_eq!(
            run(scope, "globalThis.afterPause"),
            "not yet",
            "JavaScript after the pause must not have run while paused"
        );
    });
}

#[test]
fn a_pause_with_no_frontend_does_not_wait() {
    // `--inspect-brk` with nobody listening must not hang the process, and neither must
    // a `Debugger.pause` from a session that has closed. Node's `shouldRunMessageLoop`
    // returns false in exactly this case.
    with_context(|scope| {
        install(scope);
        run(scope, FRONTEND);
        rn_bind_inspector::set_frontend_attached(false);
        let started = std::time::Instant::now();
        let blocked = rn_bind_inspector::run_pause_loop_for_test(scope);
        assert!(!blocked, "a pause with no frontend must not wait");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a pause with no frontend must return immediately, took {:?}",
            started.elapsed()
        );
    });
}

#[test]
fn resume_from_another_thread_ends_the_pause() {
    // The real frontend resumes from its reader thread once it has processed
    // `Debugger.paused`. Asserting this needs the resume to come from elsewhere, or the
    // test would only prove that the pause loop reads a flag it set itself.
    with_context(|scope| {
        install(scope);
        run(scope, FRONTEND);
        rn_bind_inspector::set_frontend_attached(true);
        rn_bind_inspector::arm_pause_for_test();

        let (started_tx, started_rx) = mpsc::channel();
        let resumer = std::thread::spawn(move || {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the pause must announce that it started");
            rn_bind_inspector::resume();
        });

        started_tx.send(()).expect("announcing the pause");
        let paused_at = std::time::Instant::now();
        let blocked = rn_bind_inspector::run_pause_loop_for_test(scope);
        let waited = paused_at.elapsed();
        resumer.join().expect("the resumer thread");

        assert!(blocked, "the pause must have waited");
        assert!(
            waited < Duration::from_secs(5),
            "the pause must end when resume is called, waited {waited:?}"
        );
    });
}

#[test]
fn disconnecting_the_frontend_ends_the_pause() {
    // A client that closes the socket while paused must not leave the process stuck for
    // the whole timeout. `shouldRunMessageLoop` requires an attached frontend for the
    // same reason.
    with_context(|scope| {
        install(scope);
        run(scope, FRONTEND);
        rn_bind_inspector::set_frontend_attached(true);
        rn_bind_inspector::arm_pause_for_test();

        let (started_tx, started_rx) = mpsc::channel();
        let disconnector = std::thread::spawn(move || {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the pause must announce that it started");
            rn_bind_inspector::set_frontend_attached(false);
        });

        started_tx.send(()).expect("announcing the pause");
        let paused_at = std::time::Instant::now();
        let blocked = rn_bind_inspector::run_pause_loop_for_test(scope);
        let waited = paused_at.elapsed();
        disconnector.join().expect("the disconnector thread");

        assert!(blocked, "the pause must have waited");
        assert!(
            waited < Duration::from_secs(5),
            "a disconnect must end the pause, waited {waited:?}"
        );
    });
}

#[test]
fn a_nested_pause_does_not_start_a_second_loop() {
    // A breakpoint hit inside the frontend's own `Runtime.evaluate` arrives on the
    // paused thread, while a pause is already on the stack. Starting a second wait
    // would consume the resume the outer one is waiting for; Node guards this with
    // `running_nested_loop_` (`inspector_agent.cc:798`).
    //
    // The nested call cannot be made from another thread — a `PinScope` is not
    // `Send`, and in production the re-entry happens inside this thread's own
    // dispatch — so what this pins is the state the guard reads: the pause depth is
    // held for the whole wait, and released when it ends. A second
    // `run_message_loop_on_pause` on this thread would therefore take the early
    // return, which the assertion on `pause_on_stack` is the observable of.
    with_context(|scope| {
        install(scope);
        run(scope, FRONTEND);
        rn_bind_inspector::set_frontend_attached(true);
        rn_bind_inspector::arm_pause_for_test();

        assert!(
            !rn_bind_inspector::pause_on_stack(),
            "no pause must be on the stack before the loop starts"
        );

        let (started_tx, started_rx) = mpsc::channel();
        let (depth_tx, depth_rx) = mpsc::channel();
        let resumer = std::thread::spawn(move || {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the pause must announce that it started");
            // The guard is what a nested call would observe, so reading it from
            // outside is the honest way to prove it is held while the outer loop
            // waits.
            depth_tx
                .send(rn_bind_inspector::pause_on_stack())
                .expect("reporting the pause depth");
            rn_bind_inspector::resume();
        });

        started_tx.send(()).expect("announcing the pause");
        let paused_at = std::time::Instant::now();
        let outer = rn_bind_inspector::run_pause_loop_for_test(scope);
        let waited = paused_at.elapsed();
        let nested_on_stack = depth_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the depth read must return promptly");
        resumer.join().expect("the resumer thread");

        assert!(outer, "the outer pause must have waited");
        assert!(
            waited < Duration::from_secs(5),
            "the outer pause must end when resume is called, waited {waited:?}"
        );
        assert!(
            nested_on_stack,
            "the pause depth must be held while the outer loop waits, so a nested \
             pause returns immediately instead of starting a second wait; one that \
             waited would swallow the resume the outer pause needs"
        );
        assert!(
            !rn_bind_inspector::pause_on_stack(),
            "the depth must be released when the pause ends, or the next pause \
             would take the early return and never block"
        );
    });
}

/// The pause loop dispatches frontend messages while it waits.
///
/// This is the second half of the defect the previous slice left. With
/// `set_frontend_attached` never set in production the loop returned at once; with
/// only the wait in place, a message queued by the reader thread is never
/// dispatched, so the pause can only end through the timeout or a disconnect.
/// Node's loop has both halves (`inspector_agent.cc:806-809`):
/// `WaitForFrontendEvent()` then `RunAndClearInterrupts()`.
///
/// # Why the message is not a `Debugger.resume`
///
/// A unit test never has V8 actually suspended: `run_pause_loop` is called
/// directly, so no `Debugger.paused` was produced and V8 answers a resume with
/// `Can only perform operation while paused`. That refusal is correct, and it means
/// a resume here would assert V8's state rather than the loop's dispatch. The
/// command used is one V8 accepts at any time, and the reply is the evidence that
/// the queue was read *from inside* the wait.
///
/// The real `Debugger.resume` path is covered end to end by driving an actual
/// `--inspect-brk` target over a socket; see the crate's `tests/http.rs` for the
/// discovery half and `tools/inspector-smoke.py` for the protocol half.
#[test]
fn the_pause_loop_dispatches_a_queued_message() {
    with_context(|scope| {
        install(scope);
        let server = rn_bind_inspector::Server::start("127.0.0.1", 0)
            .expect("the test's inspector must bind");
        let client =
            std::sync::Arc::new(std::sync::Mutex::new(SocketClient::connect(&server, "/")));

        // `Debugger.enable` has to reach V8 before any other Debugger method means
        // anything, so the session is opened the way a client opens one.
        client
            .lock()
            .expect("the client")
            .send("{\"id\":1,\"method\":\"Debugger.enable\"}");
        let mut enabled = String::new();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(20));
            rn_bind_inspector::drain_for_test(scope, server.shared());
            if let Some(reply) = client.lock().expect("the client").try_read() {
                enabled = reply;
                break;
            }
        }
        assert!(
            enabled.contains("\"id\":1"),
            "Debugger.enable must be answered, got {enabled:?}"
        );

        // Queued before the loop starts: a loop that only ever waits never looks at
        // it, so there is no reply and the pause runs to the timeout.
        client
            .lock()
            .expect("the client")
            .send("{\"id\":2,\"method\":\"Debugger.setPauseOnExceptions\",\"params\":{\"state\":\"none\"}}");

        rn_bind_inspector::set_frontend_attached(true);
        rn_bind_inspector::arm_pause_for_test();

        let (go_tx, go_rx) = mpsc::channel();
        let sender_client = std::sync::Arc::clone(&client);
        let sender = std::thread::spawn(move || {
            go_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the test must say when to resume");
            std::thread::sleep(Duration::from_millis(200));
            // `resume()` is the pause's own exit; V8 would refuse a protocol-level
            // resume without a real suspension, for the reason in the doc comment.
            rn_bind_inspector::resume();
            // Held past the loop's return so the pause ends on the resume rather
            // than on a disconnect.
            drop(sender_client.lock().expect("the client"));
            std::thread::sleep(Duration::from_millis(1000));
        });
        go_tx.send(()).ok();

        let paused_at = std::time::Instant::now();
        let waited = rn_bind_inspector::run_pause_loop_draining(scope, server.shared());
        let elapsed = paused_at.elapsed();
        sender.join().expect("the sender thread");

        assert!(waited, "the pause must have waited");
        assert!(
            elapsed < Duration::from_secs(5),
            "the pause must end on the resume, not the timeout; waited {elapsed:?}"
        );
        // The dispatch happened inside the wait, so the acknowledgement is already
        // on the socket by the time the loop returns.
        let reply = client.lock().expect("the client").try_read();
        assert!(
            reply
                .as_deref()
                .is_some_and(|text| text.contains("\"id\":2")),
            "the queued message must be dispatched from inside the wait, got {reply:?}"
        );
    });
}

/// A minimal CDP-over-WebSocket client for one connection.
struct SocketClient {
    stream: std::net::TcpStream,
}

impl SocketClient {
    fn connect(server: &rn_bind_inspector::Server, path: &str) -> Self {
        Self::connect_to(server.shared(), path)
    }

    fn connect_to(shared: &std::sync::Arc<rn_bind_inspector::Shared>, path: &str) -> Self {
        use std::io::{Read, Write};
        // `Shared` carries the bound address, which is what a second connection
        // needs; the test's own `Server` is not `Send`, so the reader thread takes
        // the shared half instead.
        let port = shared.port();
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", port)).expect("the client must connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a read timeout");
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("the upgrade must be written");
        let mut head = Vec::new();
        let mut chunk = [0_u8; 256];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).expect("the upgrade reply");
            assert_ne!(count, 0, "the server closed during the upgrade");
            head.extend_from_slice(&chunk[..count]);
        }
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
            "the upgrade must be accepted: {}",
            String::from_utf8_lossy(&head)
        );
        Self { stream }
    }

    fn send(&mut self, text: &str) {
        use std::io::Write;
        let payload = text.as_bytes();
        let mask = [0x12_u8, 0x34, 0x56, 0x78];
        let mut frame = vec![0x81];
        assert!(payload.len() < 126, "the test's messages are short");
        frame.push(0x80 | payload.len() as u8);
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream
            .write_all(&frame)
            .expect("the frame must be written");
    }

    /// Reads one frame if one is already there, without blocking.
    fn try_read(&mut self) -> Option<String> {
        use std::io::Read;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok()?;
        let mut header = [0_u8; 2];
        if self.stream.read_exact(&mut header).is_err() {
            return None;
        }
        let mut length = u64::from(header[1] & 0x7f);
        if length == 126 {
            let mut extended = [0_u8; 2];
            self.stream.read_exact(&mut extended).ok()?;
            length = u64::from(u16::from_be_bytes(extended));
        }
        let mut payload = vec![0_u8; length as usize];
        self.stream.read_exact(&mut payload).ok()?;
        Some(String::from_utf8_lossy(&payload).into_owned())
    }
}
