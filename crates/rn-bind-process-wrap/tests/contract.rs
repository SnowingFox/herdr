//! The `process_wrap` contract, checked through a real V8 isolate.
//!
//! `lib/internal/child_process.js` is unchanged Node code, so the shapes here are
//! the ones it reads: the three constant values, the `Process` constructor,
//! `spawn`/`kill`, and `getEnvPairs`.
//!
//! The real spawn-and-reap test lives in `tests/spawn.rs`, which pumps the loop.
//! Everything here is what can be proved without pumping it.

use rn_bind_process_wrap::{constants::PROCESS_FLAG_DETACHED, ProcessWrap};
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
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

/// Installs the namespace and binds it to `__proc` in the global object.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
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
}

/// Evaluates `source` with `__proc` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        run(scope, source)
    })
}

/// Evaluates `source` in an already-installed scope.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let source = v8::String::new(scope, source).expect("allocating the probe");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let compiled = v8::Script::compile(scope, source, None);
    let Some(script) = compiled else {
        let message = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "unknown".to_string());
        return format!("threw: {message}");
    };
    match script.run(scope) {
        Some(result) => result.to_rust_string_lossy(scope),
        None => {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown".to_string());
            format!("threw: {message}")
        }
    }
}

/// The three members `contracts/process_wrap.json` records.
#[test]
fn the_namespace_publishes_exactly_the_recorded_members() {
    assert_eq!(
        eval("Object.keys(__proc).sort().join(',')"),
        "Process,constants,getEnvPairs"
    );
}

/// The flag values are `ProcessFlags` bits, not libuv's `UV_PROCESS_*` numbers.
///
/// `lib/internal/child_process.js` ORs these into `spawnFlags` and `spawn` maps
/// each onto the libuv bit, so a namespace that published libuv's values instead
/// would silently detach nothing.
#[test]
fn the_constants_are_the_process_flag_bits() {
    let report = eval(
        r#"
        const c = __proc.constants;
        [
          c.kProcessFlagDetached,
          c.kProcessFlagWindowsHide,
          c.kProcessFlagWindowsVerbatimArguments,
        ].join(',')
        "#,
    );
    assert_eq!(report, "1,2,4");
    assert_eq!(PROCESS_FLAG_DETACHED, 1);
}

/// `Process` is a constructor with no arguments.
#[test]
fn process_is_a_no_argument_constructor() {
    let report = eval(
        r#"
        const results = [];
        try { __proc.Process(); results.push('no-new'); }
        catch (error) { results.push('no-new:' + error.constructor.name); }
        results.push(typeof new __proc.Process());
        results.push(__proc.Process.name);
        results.join(',')
        "#,
    );
    assert_eq!(report, "no-new:TypeError,object,Process");
}

/// The handle surface `lib/internal/child_process.js` uses.
#[test]
fn a_process_handle_exposes_every_method_the_js_uses() {
    let report = eval(
        r#"
        const handle = new __proc.Process();
        ['spawn', 'kill', 'close', 'ref', 'unref', 'hasRef']
          .filter((name) => typeof handle[name] !== 'function')
        "#,
    );
    assert_eq!(report, "");
}

/// A `Process` that never spawned has no pid, and `kill` reports `ESRCH` rather
/// than signalling the whole process group.
#[test]
fn an_unspawned_process_has_no_pid_and_cannot_be_killed() {
    let report = eval(
        r#"
        const handle = new __proc.Process();
        const pid = handle.pid;
        const killed = handle.kill(15);
        handle.close();
        [pid === undefined, killed < 0].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true",
        "no pid is written before a successful spawn, and kill reports an error"
    );
}

/// A spawn of a missing binary reports `ENOENT` rather than throwing, which is
/// what `lib/internal/child_process.js` turns into an `'error'` event.
#[test]
fn spawning_a_missing_binary_reports_enoent() {
    let report = eval(
        r#"
        const handle = new __proc.Process();
        const stdio = [
          { type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' },
        ];
        const status = handle.spawn(
          '/nonexistent/rustnode-test-binary', ['x'], undefined, [], stdio, 0,
          undefined, undefined);
        handle.close();
        status
        "#,
    );
    // `UV_ENOENT` is -2 on every platform libuv supports.
    assert_eq!(report, "-2", "a missing binary must report ENOENT");
}

/// `getEnvPairs` returns `['KEY=value', …]` covering the real environment.
#[test]
fn get_env_pairs_reports_the_process_environment() {
    let report = eval(
        r#"
        const pairs = __proc.getEnvPairs();
        const path = pairs.find((pair) => pair.startsWith('PATH='));
        [Array.isArray(pairs), pairs.length > 0, path !== undefined,
         pairs.every((pair) => typeof pair === 'string' && pair.includes('='))].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true,true,true",
        "the environment must be non-empty and every entry a KEY=value string"
    );
}

/// Closing twice is harmless, which is `HandleWrap::Close`'s state guard.
#[test]
fn closing_twice_is_harmless() {
    let report = eval(
        r#"
        const handle = new __proc.Process();
        handle.close();
        handle.close();
        'ok'
        "#,
    );
    assert_eq!(report, "ok");
}

/// `hasRef` is false on a handle `uv_spawn` never initialised.
#[test]
fn an_unspawned_handle_is_not_referenced() {
    let report = eval(
        r#"
        const handle = new __proc.Process();
        const referenced = handle.hasRef();
        handle.close();
        referenced
        "#,
    );
    assert_eq!(report, "false");
}

/// The module declares exactly what it installs.
#[test]
fn the_module_declares_exactly_what_it_installs() {
    assert_eq!(ProcessWrap.namespace(), "process_wrap");
    assert_eq!(ProcessWrap.members(), rn_bind_process_wrap::MEMBERS);
    assert!(
        ProcessWrap.deferred().is_empty(),
        "every recorded member is installed, so nothing is deferred"
    );
}
