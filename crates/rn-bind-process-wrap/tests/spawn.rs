//! A real child process: spawn it, reap it, and check the exit status.
//!
//! The contract test in `tests/contract.rs` proves the shapes; this proves the
//! behaviour. `/bin/sh -c 'exit 7'` is spawned through `handle.spawn(...)`, the
//! loop is pumped until `onexit` fires, and the reported exit code has to be 7 —
//! which is what `child_process.spawn(...).on('exit')` sees in Node.
//!
//! The exit callback runs inside `uv_run`, so this pumps `rn_uv::uv_loop` the way
//! the CLI will: a bounded loop rather than `run()`, so a callback that never
//! fires fails the test instead of hanging the suite.

use std::sync::atomic::{AtomicI64, Ordering};

use rn_bind_process_wrap::ProcessWrap;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The exit status `onexit` reported, or `-1` before it runs.
static EXIT_STATUS: AtomicI64 = AtomicI64::new(-1);
/// How many times `onexit` fired.
static EXIT_CALLS: AtomicI64 = AtomicI64::new(0);

#[test]
fn a_child_process_reports_its_exit_code() {
    with_context(|scope| {
        install(scope);

        // Spawn `/bin/sh -c 'exit 7'` with all three descriptors ignored, which is
        // `stdio: 'ignore'` in `child_process` terms. `args[0]` is the program
        // name: `lib/child_process.js` unshifts `file` onto the caller's array
        // before handing it to `spawn`, so argv as libuv sees it starts there.
        run(
            scope,
            r#"
            globalThis.__handle = new __proc.Process();
            globalThis.__handle.onexit = globalThis.__onexit;
            globalThis.__status = __handle.spawn(
              '/bin/sh', ['/bin/sh', '-c', 'exit 7'], undefined, [], [
                { type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' },
              ], 0, undefined, undefined);
            "#,
        );

        assert_eq!(run(scope, "__status"), "0", "spawn must succeed");
        let pid = run(scope, "__handle.pid");
        assert_ne!(pid, "0", "a successful spawn writes the child's pid");
        assert_ne!(
            pid, "undefined",
            "a successful spawn writes the child's pid"
        );

        pump_until(|| EXIT_CALLS.load(Ordering::SeqCst) > 0);

        assert_eq!(
            EXIT_STATUS.load(Ordering::SeqCst),
            7,
            "the reported exit code must be the child's own status"
        );

        // `lib/internal/child_process.js` closes the handle from `onexit`, and the
        // loop must then drain.
        run(
            scope,
            r#"
            __handle.close();
            'ok'
            "#,
        );
    });
}

#[test]
fn a_child_killed_by_a_signal_reports_the_signal_name() {
    with_context(|scope| {
        install(scope);

        run(
            scope,
            r#"
            globalThis.__handle = new __proc.Process();
            globalThis.__handle.onexit = globalThis.__onexit;
            globalThis.__status = __handle.spawn(
              '/bin/sh', ['/bin/sh', '-c', 'kill -TERM $$'], undefined, [], [
                { type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' },
              ], 0, undefined, undefined);
            "#,
        );
        assert_eq!(run(scope, "__status"), "0", "spawn must succeed");
        pump_until(|| EXIT_CALLS.load(Ordering::SeqCst) > 0);
        let signal = SIGNAL
            .lock()
            .expect("the signal slot must not be poisoned")
            .clone();
        assert_eq!(
            signal.as_deref(),
            Some("SIGTERM"),
            "a signalled child reports the signal's name, which is what child.signalCode shows"
        );
        run(scope, "__handle.close(); 'ok'");
    });
}

/// The signal name the callback saw, or `None` for a normal exit.
static SIGNAL: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    // Each test starts from a clean slate: the statics are process-wide.
    EXIT_STATUS.store(-1, Ordering::SeqCst);
    EXIT_CALLS.store(0, Ordering::SeqCst);
    *SIGNAL.lock().expect("the signal slot must not be poisoned") = None;
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
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
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs `process_wrap` and the `onexit` callback it calls back through.
fn install(scope: &mut v8::PinScope<'_, '_>) {
    let object = ProcessWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the process_wrap namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__proc").expect("allocating __proc");
    global.set(scope, key.into(), object.into());

    // `onexit(exitCode, signalCode)`, exactly as `lib/internal/child_process.js`
    // declares it.
    run(
        scope,
        r#"
        globalThis.__onexit = function (exitCode, signalCode) {
          globalThis.__reportExit(Math.trunc(exitCode), signalCode === undefined ? '' : String(signalCode));
        };
        "#,
    );

    let template = v8::FunctionTemplate::builder(report_exit).build(scope);
    let report = template
        .get_function(scope)
        .expect("allocating the report function");
    let key = v8::String::new(scope, "__reportExit").expect("allocating the report key");
    global.set(scope, key.into(), report.into());
}

/// `__reportExit(exitCode, signalCode)`.
fn report_exit(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let status = args.get(0).integer_value(scope).unwrap_or(-1);
    let signal = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    EXIT_STATUS.store(status, Ordering::SeqCst);
    *SIGNAL.lock().expect("the signal slot must not be poisoned") =
        Some(signal).filter(|signal| !signal.is_empty());
    EXIT_CALLS.fetch_add(1, Ordering::SeqCst);
}

/// Evaluates `source`, panicking on a throw.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let source = v8::String::new(scope, source).expect("allocating the probe");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
    match script.run(scope) {
        Some(result) => result.to_rust_string_lossy(scope),
        None => {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown".to_string());
            panic!("the probe threw: {message}");
        }
    }
}

/// Pumps the loop until `done` reports true, or fails the test after a bound.
fn pump_until(done: impl Fn() -> bool) {
    // A bounded pump rather than `run()`: a callback that never fires would
    // otherwise block the suite instead of failing it.
    let mut spun = 0;
    while spun < 5000 && !done() {
        rn_uv::uv_loop::run_once();
        spun += 1;
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(done(), "the loop must reap the child within {spun} spins");
}
