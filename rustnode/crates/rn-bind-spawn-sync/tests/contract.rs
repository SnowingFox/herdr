//! The `spawn_sync` contract, checked through a real V8 isolate and a real child.
//!
//! `lib/internal/child_process.js` is unchanged Node code, so the shapes here are
//! the ones it reads: `spawn(options)` returning
//! `{ status, signal, output, pid, error? }`. Every case really spawns a process,
//! because the whole point of this namespace is that the result is complete by the
//! time it returns.

use rn_bind_spawn_sync::SpawnSync;
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

/// Installs the namespace and binds it to `__spawnSync` in the global object.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = SpawnSync
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the spawn_sync namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__spawnSync").expect("allocating __spawnSync");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` with `__spawnSync` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        // Every probe may read a delivered buffer, and a bare isolate has no
        // `Buffer` global, so the bytes are read out of the typed array directly.
        run(
            scope,
            r#"
            globalThis.text = (view) => {
              let out = '';
              for (let i = 0; i < view.length; i++) out += String.fromCharCode(view[i]);
              return out;
            };
            "#,
        );
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

/// The one member `contracts/spawn_sync.json` records.
#[test]
fn the_namespace_publishes_exactly_the_recorded_members() {
    assert_eq!(eval("Object.keys(__spawnSync).join(',')"), "spawn");
}

/// A successful run reports the exit code, `null` signal, and a pid.
#[test]
fn a_child_reports_its_exit_code_and_pid() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'exit 3'],
          stdio: [{ type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' }],
        });
        [result.status, result.signal === null, result.pid > 0, result.error === undefined].join(',')
        "#,
    );
    assert_eq!(
        report, "3,true,true,true",
        "status is the exit code, signal is null, and the child has a pid"
    );
}

/// The child's stdout is collected, because `execSync` returns it.
#[test]
fn the_child_s_stdout_is_collected() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'printf hello'],
          stdio: [
            { type: 'pipe', readable: true, writable: false },
            { type: 'pipe', readable: false, writable: true },
            { type: 'ignore' },
          ],
        });
        [result.status, result.output.length, result.output[0] === null,
         result.output[1] instanceof Uint8Array, globalThis.text(result.output[1])].join(',')
        "#,
    );
    assert_eq!(
        report, "0,3,true,true,hello",
        "stdout is a Buffer holding what the child printed, and stdin is null"
    );
}

/// A non-zero status still returns the output, which is what `execSync` throws on.
#[test]
fn output_is_collected_even_when_the_child_fails() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'printf boom; exit 1'],
          stdio: [
            { type: 'ignore' },
            { type: 'pipe', readable: false, writable: true },
            { type: 'ignore' },
          ],
        });
        [result.status, globalThis.text(result.output[1])].join(',')
        "#,
    );
    assert_eq!(report, "1,boom");
}

/// A signalled child reports a `null` status and the signal's name.
#[test]
fn a_signalled_child_reports_the_signal_name() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'kill -TERM $$'],
          stdio: [{ type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' }],
        });
        [result.status === null, result.signal].join(',')
        "#,
    );
    assert_eq!(
        report, "true,SIGTERM",
        "a signalled child reports status null and the signal's name"
    );
}

/// A missing binary reports `ENOENT` and `null` for the exit facts.
#[test]
fn a_missing_binary_reports_enoent() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/nonexistent/rustnode-test-binary',
          args: ['x'],
          stdio: [{ type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' }],
        });
        [result.error, result.status === null, result.signal === null, result.output === null].join(',')
        "#,
    );
    // `UV_ENOENT` is -2 on every platform libuv supports.
    assert_eq!(report, "-2,true,true,true");
}

/// `options.input` is written to the child's stdin before the pipe shuts down.
#[test]
fn the_input_option_reaches_the_child() {
    let report = eval(
        r#"
        const input = new Uint8Array([104, 105, 10]);
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'cat'],
          stdio: [
            { type: 'pipe', readable: true, writable: false, input },
            { type: 'pipe', readable: false, writable: true },
            { type: 'ignore' },
          ],
        });
        [result.status, globalThis.text(result.output[1])].join(',')
        "#,
    );
    assert_eq!(
        report, "0,hi\n",
        "the child must receive the input and echo it back"
    );
}

/// `options.cwd` really changes the child's working directory.
#[test]
fn the_cwd_option_changes_the_working_directory() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'pwd'],
          cwd: '/tmp',
          stdio: [
            { type: 'ignore' },
            { type: 'pipe', readable: false, writable: true },
            { type: 'ignore' },
          ],
        });
        [result.status, globalThis.text(result.output[1])].join(',')
        "#,
    );
    assert_eq!(report, "0,/tmp\n");
}

/// `options.envPairs` replaces the child's environment.
#[test]
fn the_env_pairs_option_replaces_the_environment() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'printf "%s" "$RUSTNODE_TEST_VAR"'],
          envPairs: ['RUSTNODE_TEST_VAR=present'],
          stdio: [
            { type: 'ignore' },
            { type: 'pipe', readable: false, writable: true },
            { type: 'ignore' },
          ],
        });
        [result.status, globalThis.text(result.output[1])].join(',')
        "#,
    );
    assert_eq!(report, "0,present");
}

/// A `timeout` kills the child and reports `ETIMEDOUT`, which is what
/// `execSync({ timeout })` relies on.
#[test]
fn a_timeout_kills_the_child() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'sleep 5'],
          timeout: 50,
          stdio: [{ type: 'ignore' }, { type: 'ignore' }, { type: 'ignore' }],
        });
        [result.error, result.signal].join(',')
        "#,
    );
    // `UV_ETIMEDOUT` is -110.
    assert_eq!(
        report, "-110,SIGTERM",
        "the timeout reports ETIMEDOUT and the default killSignal"
    );
}

/// `maxBuffer` limits the output, and exceeding it is an error rather than silent
/// truncation.
#[test]
fn max_buffer_limits_the_output() {
    let report = eval(
        r#"
        const result = __spawnSync.spawn({
          file: '/bin/sh',
          args: ['/bin/sh', '-c', 'yes | head -c 200000'],
          maxBuffer: 1000,
          stdio: [
            { type: 'ignore' },
            { type: 'pipe', readable: false, writable: true },
            { type: 'ignore' },
          ],
        });
        [result.error !== undefined, result.error < 0].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true",
        "exceeding maxBuffer must report an error, as Node's ENOBUFS does"
    );
}

/// A non-array `stdio` throws rather than returning a bogus result.
#[test]
fn a_non_array_stdio_throws() {
    let report = eval(
        r#"
        try {
          __spawnSync.spawn({ file: '/bin/sh', args: [], stdio: 'ignore' });
          'no-throw'
        } catch (error) {
          'threw:' + error.constructor.name
        }
        "#,
    );
    assert_eq!(report, "threw:TypeError");
}

/// The module declares exactly what it installs.
#[test]
fn the_module_declares_exactly_what_it_installs() {
    assert_eq!(SpawnSync.namespace(), "spawn_sync");
    assert_eq!(SpawnSync.members(), rn_bind_spawn_sync::MEMBERS);
    assert!(
        SpawnSync.deferred().is_empty(),
        "the one recorded member is installed, so nothing is deferred"
    );
}
