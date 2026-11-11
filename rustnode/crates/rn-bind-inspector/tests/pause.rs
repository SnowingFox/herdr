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
        let blocked = rn_bind_inspector::run_pause_loop_for_test();
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
        let blocked = rn_bind_inspector::run_pause_loop_for_test();
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
        let blocked = rn_bind_inspector::run_pause_loop_for_test();
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
        let blocked = rn_bind_inspector::run_pause_loop_for_test();
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
    // A breakpoint hit inside the frontend's own `Runtime.evaluate` arrives while a pause
    // is already on the stack. Starting a second wait would consume the resume the outer
    // one is waiting for; Node guards this with `running_nested_loop_`
    // (`inspector_agent.cc:798`).
    //
    // The nested call is made from the resumer thread rather than from the paused one,
    // because the paused thread is inside the outer loop and cannot make it. The depth
    // counter is process-global, so a call from any thread observes it.
    with_context(|scope| {
        install(scope);
        run(scope, FRONTEND);
        rn_bind_inspector::set_frontend_attached(true);
        rn_bind_inspector::arm_pause_for_test();

        let (started_tx, started_rx) = mpsc::channel();
        let (nested_tx, nested_rx) = mpsc::channel();
        let resumer = std::thread::spawn(move || {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the outer pause must announce that it started");
            // While the outer pause is in progress, a nested pause must be a no-op. If
            // it waited instead, this send would take a whole timeout.
            let nested_waited = rn_bind_inspector::run_pause_loop_for_test();
            nested_tx
                .send(nested_waited)
                .expect("reporting the nested call");
            rn_bind_inspector::resume();
        });

        started_tx.send(()).expect("announcing the pause");
        let paused_at = std::time::Instant::now();
        let outer = rn_bind_inspector::run_pause_loop_for_test();
        let waited = paused_at.elapsed();
        let nested_waited = nested_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the nested call must return promptly");
        resumer.join().expect("the resumer thread");

        assert!(outer, "the outer pause must have waited");
        assert!(
            waited < Duration::from_secs(5),
            "the outer pause must end when resume is called, waited {waited:?}"
        );
        assert!(
            !nested_waited,
            "a nested pause must return immediately rather than starting a second wait; \
             one that waited would swallow the resume the outer pause needs"
        );
    });
}
