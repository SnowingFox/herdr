//! `process.env` as an interceptor over the real environment.
//!
//! Everything here is observable from JavaScript and was measured on a real Node
//! 28 binary before being written down. The point of running the built binary
//! rather than unit-testing the handlers is that the interceptors only exist
//! inside a live isolate: `rn-realm`'s `process_env` hands them to V8, and only
//! V8 can say whether a handler was consulted, whether a miss fell through, or
//! whether a write reached the environment block a child process copies.

use std::process::Command;

/// Runs `source` under the built binary with `env` added to the environment.
fn run_with(source: &str, env: &[(&str, &str)]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustnode"));
    command.args(["-e", source]);
    for (name, value) in env {
        command.env(name, value);
    }
    let out = command.output().expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run(source: &str) -> (i32, String, String) {
    run_with(source, &[])
}

/// Asserts the script printed `expected` and exited 0.
fn expect(source: &str, expected: &str) {
    let (code, stdout, stderr) = run(source);
    assert_eq!(
        stdout.trim(),
        expected,
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

/// The last non-empty line of `text`.
///
/// The runtime's own `tracing` diagnostics share stdout with a script's
/// `console.log`, so a test that spawns a worker asserts on the final line
/// rather than the whole stream.
fn last_line(text: &str) -> &str {
    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
}

#[test]
fn a_number_assigned_to_a_variable_is_stored_as_a_string() {
    // `EnvSetter` coerces with `ToString` before storing, so `typeof` is
    // `'string'` and the value is `"42"`. A plain object keeps the number.
    expect(
        "process.env.RN_TEST_NUM = 42; console.log(typeof process.env.RN_TEST_NUM, JSON.stringify(process.env.RN_TEST_NUM));",
        "string \"42\"",
    );
}

#[test]
fn an_object_assigned_to_a_variable_is_stored_as_its_to_string_result() {
    expect(
        "process.env.RN_TEST_OBJ = { toString() { return 'objstr'; } }; \
         console.log(typeof process.env.RN_TEST_OBJ, JSON.stringify(process.env.RN_TEST_OBJ));",
        "string \"objstr\"",
    );
}

#[test]
fn undefined_is_stored_as_the_string_undefined() {
    // `test-process-env-deprecation.js` asserts this exact line, and it is the
    // case a "skip non-strings" implementation gets wrong by leaving the
    // previous value in place.
    expect(
        "process.env.RN_TEST_UNDEF = undefined; console.log(JSON.stringify(process.env.RN_TEST_UNDEF));",
        "\"undefined\"",
    );
}

#[test]
fn an_assigned_variable_reaches_a_child_process() {
    // The observable the bug was reported through: storage is `uv_os_setenv`,
    // so `spawn` copies the value. A plain object is visible only to the
    // JavaScript that assigned to it.
    let (code, stdout, stderr) = run(
        "const { spawnSync } = require('child_process'); \
         process.env.RN_TEST_CHILD = 'set-by-parent'; \
         const r = spawnSync(process.execPath, ['-e', 'console.log(process.env.RN_TEST_CHILD)'], { encoding: 'utf8' }); \
         console.log(r.stdout.trim());",
    );
    assert_eq!(stdout.trim(), "set-by-parent", "stderr: {stderr}");
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn a_deleted_variable_is_absent_from_a_child_process() {
    // The asymmetry the report called out: `delete` already worked through the
    // plain object, and has to keep working through the interceptor.
    let (code, stdout, stderr) = run(
        "const { spawnSync } = require('child_process'); \
         process.env.RN_TEST_GONE = 'x'; delete process.env.RN_TEST_GONE; \
         const r = spawnSync(process.execPath, ['-e', 'console.log(process.env.RN_TEST_GONE)'], { encoding: 'utf8' }); \
         console.log(r.stdout.trim());",
    );
    assert_eq!(stdout.trim(), "undefined", "stderr: {stderr}");
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn a_numeric_key_names_the_variable_of_that_number() {
    // `process.env[42]` reaches the indexed handler, not the named one.
    // `test-process-env.js:32` asserts this, and a named-only interceptor
    // silently answers `undefined` for it.
    expect(
        "process.env[42] = 'forty-two'; \
         console.log(process.env[42], process.env['42'], Object.hasOwn(process.env, '42'));",
        "forty-two forty-two true",
    );
}

#[test]
fn an_absent_variable_falls_through_to_the_prototype() {
    // A miss is `Intercepted::kNo`, so ordinary lookup answers — which is what
    // makes `process.env.hasOwnProperty` the real one until it is assigned.
    expect(
        "console.log(typeof process.env.RN_TEST_NEVER_SET, \
           process.env.hasOwnProperty === Object.prototype.hasOwnProperty, \
           Object.hasOwn(process.env, 'hasOwnProperty'));",
        "undefined true false",
    );
}

#[test]
fn assigning_a_name_that_exists_on_the_prototype_shadows_it() {
    // `test-process-env.js` does exactly this and then asserts the child sees
    // it, so the value has to both shadow the prototype method and be a real
    // variable.
    expect(
        "process.env.hasOwnProperty = 'asdf'; \
         console.log(process.env.hasOwnProperty, Object.hasOwn(process.env, 'hasOwnProperty'));",
        "asdf true",
    );
}

#[test]
fn a_variable_reports_a_plain_writable_enumerable_configurable_descriptor() {
    // `EnvQuery` answers with `v8::None` for a variable that exists, so the
    // descriptor carries all three flags rather than `undefined`.
    expect(
        "process.env.RN_TEST_DESC = 'v'; \
         const d = Object.getOwnPropertyDescriptor(process.env, 'RN_TEST_DESC'); \
         console.log(d.value, d.writable, d.enumerable, d.configurable);",
        "v true true true",
    );
}

#[test]
fn membership_and_deletion_agree_with_node() {
    expect(
        "process.env.RN_TEST_IN = 'v'; \
         console.log('RN_TEST_IN' in process.env, delete process.env.RN_TEST_IN, \
           'RN_TEST_IN' in process.env, delete process.env.RN_TEST_NEVER_SET);",
        "true true false true",
    );
}

#[test]
fn define_property_accepts_a_plain_data_descriptor() {
    // `EnvDefiner` forwards a configurable/writable/enumerable descriptor to
    // `EnvSetter`, so `defineProperty` is a second way to write a variable.
    expect(
        "Object.defineProperty(process.env, 'RN_TEST_DEFINED', { value: 42, writable: true, enumerable: true, configurable: true }); \
         console.log(process.env.RN_TEST_DEFINED);",
        "42",
    );
}

#[test]
fn define_property_rejects_a_partial_descriptor() {
    // The default `writable`/`enumerable`/`configurable` are all false, so this
    // is Node's `ERR_INVALID_OBJECT_DEFINE_PROPERTY` case.
    // `test-worker-process-env.js` asserts the same call from inside a worker.
    expect(
        "try { Object.defineProperty(process.env, 'RN_TEST_BAD', { value: 42 }); } \
         catch (e) { console.log(e.name, e.code, JSON.stringify(e.message)); }",
        "TypeError ERR_INVALID_OBJECT_DEFINE_PROPERTY \"'process.env' only accepts a configurable, writable, and enumerable data descriptor\"",
    );
}

#[test]
fn define_property_rejects_an_accessor() {
    expect(
        "try { Object.defineProperty(process.env, 'RN_TEST_ACCESSOR', { get() { return 1; } }); } \
         catch (e) { console.log(e.name, e.code, JSON.stringify(e.message)); }",
        "TypeError ERR_INVALID_OBJECT_DEFINE_PROPERTY \"'process.env' does not accept an accessor(getter/setter) descriptor\"",
    );
}

#[test]
fn the_object_has_the_ordinary_object_prototype() {
    // Verified from Node's source rather than asserted from memory: the
    // instance comes from an `ObjectTemplate` built on a `FunctionTemplate`, so
    // it has `Object.prototype`'s methods and is *not* the null-prototype object
    // `Object.create(null)` produces. This build reproduced the measured shape
    // before the assertion was written.
    expect(
        "const p = Object.getPrototypeOf(process.env); \
         console.log(p === null, p === Object.prototype, typeof p.hasOwnProperty, \
           Object.getPrototypeOf(p) === Object.prototype);",
        "false false function true",
    );
}

#[test]
fn enumeration_includes_a_variable_written_a_moment_ago() {
    // The key list comes from libuv's enumeration of the block, so it is not a
    // snapshot taken at startup.
    expect(
        "process.env.RN_TEST_ENUM = 'v'; \
         console.log(Object.keys(process.env).includes('RN_TEST_ENUM'), \
           Object.keys(process.env).length > 0);",
        "true true",
    );
}

#[test]
fn a_spread_copy_is_a_plain_object_holding_the_variables() {
    expect(
        "process.env.RN_TEST_SPREAD = 'v'; \
         const copy = { ...process.env }; \
         console.log(copy.RN_TEST_SPREAD, Object.getPrototypeOf(copy) === Object.prototype);",
        "v true",
    );
}

#[test]
fn structured_clone_copies_the_variables_as_a_plain_object() {
    // Node recognises `process.env` by template identity and serialises
    // `env_vars()->AssignToObject()`; without that, V8 refuses the proxy with
    // `DataCloneError` because it is not a clonable host object.
    // `test-process-env.js` asserts `deepEqual(structuredClone(process.env),
    // process.env)`.
    expect(
        "process.env.RN_TEST_CLONE = 'v'; \
         const copy = structuredClone(process.env); \
         console.log(copy.RN_TEST_CLONE, Object.getPrototypeOf(copy) === Object.prototype, \
           JSON.stringify(copy) === JSON.stringify({ ...process.env }));",
        "v true true",
    );
}

#[test]
fn an_empty_name_is_not_a_variable() {
    // `test-process-env.js` ends with this case, citing nodejs/node#32920.
    expect(
        "process.env[''] = ''; console.log(process.env['']);",
        "undefined",
    );
}

#[test]
fn names_are_case_sensitive_on_unix() {
    // `test-process-env.js` checks both a mixed-case and a lower-case spelling,
    // so a case-folding implementation cannot pass by accident.
    expect(
        "process.env.TEST = 'test'; \
         console.log(process.env.TEST, process.env.test, process.env.teST);",
        "test undefined undefined",
    );
}

#[test]
fn os_tmpdir_reads_what_javascript_assigned() {
    // `lib/os.js`'s `tmpdir()` is `getTempDir() || '/tmp'`, and `getTempDir`
    // lives in the `credentials` binding rather than `os`. It reads through the
    // same store, which is what makes this work at all;
    // `test/parallel/test-os.js` opens with this sequence.
    expect(
        "const os = require('os'); \
         process.env.TMPDIR = '/tmpdir'; process.env.TMP = '/tmp'; process.env.TEMP = '/temp'; \
         const first = os.tmpdir(); \
         process.env.TMPDIR = ''; const second = os.tmpdir(); \
         process.env.TMP = ''; const third = os.tmpdir(); \
         process.env.TMPDIR = '/tmpdir/'; const fourth = os.tmpdir(); \
         console.log(first, second, third, fourth);",
        "/tmpdir /tmp /temp /tmpdir",
    );
}

#[test]
fn os_homedir_falls_back_to_passwd_when_home_is_deleted() {
    // `uv_os_homedir` checks `HOME` and then the passwd entry, and
    // `test/parallel/test-os.js` deletes `HOME` to exercise the fallback.
    expect(
        "const os = require('os'); \
         const before = os.homedir(); \
         const saved = process.env.HOME; delete process.env.HOME; \
         const after = os.homedir(); \
         process.env.HOME = saved; \
         console.log(before === saved, after.length > 0, os.homedir() === saved);",
        "true true true",
    );
}

#[test]
fn a_worker_gets_its_own_copy_of_the_environment() {
    // `test/parallel/test-worker-process-env.js`: a worker inherits what the
    // parent had when the `Worker` was constructed, its own writes stay in the
    // worker, and a variable the parent adds afterwards is not inherited.
    let source = r#"
        const { Worker } = require('worker_threads');
        process.env.RN_TEST_BEFORE = 'before';
        const w = new Worker(`
            const { parentPort } = require('worker_threads');
            process.env.RN_TEST_WORKER = 'worker';
            parentPort.postMessage([process.env.RN_TEST_BEFORE, process.env.RN_TEST_AFTER]);
        `, { eval: true });
        process.env.RN_TEST_AFTER = 'after';
        w.on('message', ([before, after]) => {
            console.log(JSON.stringify([before, after, process.env.RN_TEST_WORKER]));
        });
    "#;
    let (code, stdout, stderr) = run(source);
    // The runtime's own diagnostics (the inspector namespace warning) also reach
    // stdout, so the assertion is on the last line rather than the whole stream.
    assert_eq!(
        last_line(&stdout),
        r#"["before",null,null]"#,
        "stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn an_explicit_worker_env_replaces_the_inherited_one() {
    // `options.env` builds a fresh store rather than a copy, so a variable the
    // parent has is absent unless the caller passes it.
    let source = r#"
        const { Worker } = require('worker_threads');
        process.env.RN_TEST_PARENT_ONLY = 'parent';
        const w = new Worker(`
            const { parentPort } = require('worker_threads');
            parentPort.postMessage([process.env.RN_TEST_ONLY, process.env.RN_TEST_PARENT_ONLY]);
        `, { eval: true, env: { RN_TEST_ONLY: 1 } });
        w.on('message', (message) => console.log(JSON.stringify(message)));
    "#;
    let (code, stdout, stderr) = run(source);
    // The value was a number in the options object and arrives as a string, which
    // is `lib/internal/worker.js`'s `${value}` plus `EnvSetter`'s `ToString`.
    assert_eq!(last_line(&stdout), r#"["1",null]"#, "stderr: {stderr}");
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn load_env_file_writes_through_to_the_environment_block() {
    // `process.loadEnvFile()` calls `Dotenv::SetEnvironment`, which writes
    // through the environment store, so the value is visible to `process.env`
    // and to a child process alike.
    let path = std::env::temp_dir().join(format!("rn-load-env-{}.env", std::process::id()));
    std::fs::write(&path, "RN_TEST_DOTENV=from-file\n").expect("write the .env fixture");
    let source = format!(
        "const {{ spawnSync }} = require('child_process'); \
         process.loadEnvFile({path:?}); \
         const r = spawnSync(process.execPath, ['-e', 'console.log(process.env.RN_TEST_DOTENV)'], {{ encoding: 'utf8' }}); \
         console.log(process.env.RN_TEST_DOTENV, r.stdout.trim());",
        path = path.to_string_lossy()
    );
    let (code, stdout, stderr) = run(&source);
    let _ = std::fs::remove_file(&path);
    assert_eq!(stdout.trim(), "from-file from-file", "stderr: {stderr}");
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn load_env_file_does_not_overwrite_an_existing_variable() {
    // `Dotenv::SetEnvironment` skips a name the environment already has, so the
    // parent's value wins over the file's.
    let path = std::env::temp_dir().join(format!("rn-load-env-pin-{}.env", std::process::id()));
    std::fs::write(&path, "RN_TEST_DOTENV_PIN=from-file\n").expect("write the .env fixture");
    let source = format!(
        "process.env.RN_TEST_DOTENV_PIN = 'from-parent'; \
         process.loadEnvFile({path:?}); \
         console.log(process.env.RN_TEST_DOTENV_PIN);",
        path = path.to_string_lossy()
    );
    let (code, stdout, stderr) = run(&source);
    let _ = std::fs::remove_file(&path);
    assert_eq!(stdout.trim(), "from-parent", "stderr: {stderr}");
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn load_env_file_throws_enoent_for_a_missing_file() {
    // `LoadEnvFile` reports `ThrowUVException(UV_ENOENT, "open", ...)`, so a
    // missing file throws rather than reading as empty.
    expect(
        "try { process.loadEnvFile('/definitely/not/a/real/file.env'); } \
         catch (e) { console.log(e.code, e.syscall, e.path); }",
        "ENOENT open /definitely/not/a/real/file.env",
    );
}

#[test]
fn a_variable_from_the_process_environment_is_readable() {
    // The interceptor reads the block rather than a snapshot, so a variable the
    // *launcher* set is visible too. This is the case the old plain object got
    // right, and pinning it keeps the interceptor from breaking it.
    let (code, stdout, stderr) = run_with(
        "console.log(process.env.RN_TEST_FROM_LAUNCHER);",
        &[("RN_TEST_FROM_LAUNCHER", "visible")],
    );
    assert_eq!(stdout.trim(), "visible", "stderr: {stderr}");
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn a_tz_write_redetects_the_time_zone() {
    // `DateTimeConfigurationChangeNotification`: V8 caches the detected zone, so
    // without the notification a `Date` formatted after `process.env.TZ = ...`
    // keeps the old one. Node calls `tzset()` then notifies the isolate.
    expect(
        "process.env.TZ = 'UTC'; \
         const winter = new Date('2020-01-01T00:00:00Z'); \
         const utc = winter.getHours(); \
         process.env.TZ = 'Europe/Amsterdam'; \
         console.log(utc, winter.getHours());",
        "0 1",
    );
}

#[test]
fn a_removed_variable_reads_as_absent_under_permission() {
    // `EnvGetter` returns `Intercepted::kNo` for a variable the startup scrub
    // removed, so `process.env.X` is `undefined` *and* `'X' in process.env` is
    // false, even though the scrub is what made it absent. Enforcing a read is
    // about the value, never about throwing.
    let source = "console.log(process.env.RN_TEST_SECRET, 'RN_TEST_SECRET' in process.env);";

    // Without the model the launcher's value is visible, so the assertion below
    // is about the scrub and not about the variable being absent for some other
    // reason.
    let plain = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["-e", source])
        .env("RN_TEST_SECRET", "secret")
        .output()
        .expect("rustnode runs");
    assert_eq!(
        String::from_utf8_lossy(&plain.stdout).trim(),
        "secret true",
        "stderr: {}",
        String::from_utf8_lossy(&plain.stderr)
    );

    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--permission", "--no-warnings", "-e", source])
        .env("RN_TEST_SECRET", "secret")
        .output()
        .expect("rustnode runs");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "undefined false",
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_read_of_a_scrubbed_variable_is_published_to_the_env_channel() {
    // `EnvGetter` and `EnvQuery` publish to `node:permission-model:env`, and
    // `ReportRemovedEnvVar` warns once. The counts are what
    // `test-permission-env-warning.js` asserts: three publications for two reads
    // and one membership test, and one warning naming only the removed
    // variable.
    let source = r#"
        const dc = require('diagnostics_channel');
        const events = [];
        dc.subscribe('node:permission-model:env', (message) => {
            events.push([message.permission, message.resource]);
        });
        process.env.RN_TEST_SECRET;
        process.env.RN_TEST_SECRET;
        ('RN_TEST_SECRET' in process.env);
        // A variable that was never set is not reported.
        process.env.RN_TEST_NEVER_SET;
        console.log(JSON.stringify(events));
    "#;
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--permission", "-e", source])
        .env("RN_TEST_SECRET", "secret")
        .output()
        .expect("rustnode runs");
    // The publications are observed by the subscriber in the script, so the
    // stdout line is the event list itself.
    assert_eq!(
        last_line(&String::from_utf8_lossy(&out.stdout)),
        r#"[["Env","RN_TEST_SECRET"],["Env","RN_TEST_SECRET"],["Env","RN_TEST_SECRET"]]"#,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .matches("removed the environment variable \"RN_TEST_SECRET\"")
            .count(),
        1,
        "the warning must fire exactly once: {stderr}"
    );
}
