//! `util.parseEnv` and `util.inspect` through a proxy, as JavaScript sees them.
//!
//! Both were reviewed as findings (F7 and F8 in the storage/engine cluster
//! report) and both are fixed in the `util` binding. The expectations here were
//! measured on the pinned Node 28 nightly
//! (`v28.0.0-nightly20261111e8c1160d20`), not on whatever `node` is on `PATH`.
//!
//! These run the built binary rather than calling the handlers because the
//! failure modes are JavaScript-side: `util.parseEnv` throws
//! `binding.parseEnv is not a function` because `lib/util.js` reaches a missing
//! member, and a revoked proxy threw from inside `internal/util/inspect.js`
//! because `getProxyDetails` answered "no proxy here". Neither is visible from
//! a Rust unit test of the namespace object.

use std::process::Command;

/// Runs `source` under the built binary and returns `(code, stdout, stderr)`.
fn run(source: &str) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["-e", source])
        .output()
        .expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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

/// [`expect`] for a script that reaches `internal/*`, which needs
/// `--expose-internals` exactly as it does in Node.
///
/// The flag is a command-line flag rather than something the eval path grants:
/// `BuiltinModule.normalizeRequirableId` refuses every `internal/` id without it,
/// and the oracle refuses them the same way, so a test that reached them through
/// `-e` alone was relying on a permissive global `require` that rustnode no
/// longer has.
fn expect_exposed(source: &str, expected: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--expose-internals", "-e", source])
        .output()
        .expect("rustnode runs");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        stdout.trim(),
        expected,
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

// ------------------------------------------------------------- util.parseEnv --

#[test]
fn parse_env_returns_a_null_prototype_object_of_the_pairs() {
    // `Dotenv::ToObject` builds the object with `Null` as its prototype, which
    // is observable and which `test-util-parse-env.js` asserts.
    expect(
        "const env = require('util').parseEnv('A=1\\nB=two');\
         console.log(JSON.stringify(env), Object.getPrototypeOf(env));",
        r#"{"A":"1","B":"two"} null"#,
    );
}

#[test]
fn parse_env_keys_are_sorted_and_not_in_file_order() {
    // The store is a `std::map` in Node, so `Object.keys` is byte order: `"B"`
    // before `"a"`, and `"1"` before both because integer-like keys lead.
    expect(
        "console.log(JSON.stringify(Object.keys(require('util').parseEnv('b=1\\na=2\\nB=3\\n1=4'))));",
        r#"["1","B","a","b"]"#,
    );
}

#[test]
fn parse_env_handles_comments_quotes_and_the_export_prefix() {
    expect(
        "const env = require('util').parseEnv(\
           '# comment\\n\\nexport FOO=bar\\nSPACED = x \\nQ=\"a b\"\\nS=\\'c d\\'\\nEMPTY=\\nZ=1#tail\\n');\
         console.log(JSON.stringify(env));",
        r#"{"EMPTY":"","FOO":"bar","Q":"a b","S":"c d","SPACED":"x","Z":"1"}"#,
    );
}

#[test]
fn parse_env_reproduces_the_trim_that_swallows_the_next_line() {
    // Upstream's `content.empty() || content.front() == '\n'` branch stores and
    // continues before re-trimming, so a value that is only whitespace leaves
    // the rest of the document glued to it. Node 28 prints `{"A":"B=2"}` here;
    // "fixing" it would make rustnode disagree with the runtime it mirrors.
    expect(
        "console.log(JSON.stringify(require('util').parseEnv('A=   \\nB=2\\n')));",
        r#"{"A":"B=2"}"#,
    );
}

#[test]
fn parse_env_rejects_a_non_string_with_the_js_error() {
    // The public `parseEnv` validates with `validateString` before the binding
    // is reached, so a number fails with Node's own `ERR_INVALID_ARG_TYPE`
    // rather than a Rust-side coercion or a panic.
    expect(
        "try { require('util').parseEnv(1); } catch (e) { console.log(e.code); }",
        "ERR_INVALID_ARG_TYPE",
    );
}

#[test]
fn parse_env_is_installed_on_the_binding() {
    // The contract check trusts `MEMBERS` and subtracts `DEFERRED` without
    // looking at the object, so the member being *callable* is the fact worth
    // pinning. `parseEnv` used to be deferred with a reason naming
    // `NODE_OPTIONS`, which is parsed in C++ and never calls this binding.
    expect_exposed(
        "const { internalBinding } = require('internal/test/binding');\
         const binding = internalBinding('util');\
         console.log(typeof binding.parseEnv, typeof binding.getProxyDetails);",
        "function function",
    );
}

// -------------------------------------------------------- util.inspect proxy --

#[test]
fn inspect_prints_a_proxy_as_a_proxy() {
    // Without `showProxy` the target is printed wrapped in `Proxy(...)`, which
    // is what `formatValue`'s unwrapping loop builds from `getProxyDetails`.
    expect(
        "const util = require('util');\
         console.log(util.inspect(new Proxy({ a: 1 }, {})));",
        "Proxy({ a: 1 })",
    );
}

#[test]
fn inspect_with_show_proxy_prints_the_target_and_handler() {
    expect(
        "const util = require('util');\
         console.log(util.inspect(new Proxy({ a: 1 }, {}), { showProxy: true }));",
        "Proxy [ { a: 1 }, {} ]",
    );
}

#[test]
fn inspect_of_a_revoked_proxy_prints_the_marker_instead_of_throwing() {
    // The F8 symptom: `getProxyDetails` returned `undefined` for every proxy, so
    // `inspect.js` treated a revoked proxy as an ordinary object and reading a
    // property threw `Cannot perform 'get' on a proxy that has been revoked`.
    // A revoked proxy's target slot is the null oddball, which is exactly what
    // `formatValue` turns into `<Revoked Proxy>`.
    expect(
        "const util = require('util');\
         const r = Proxy.revocable({ x: 1 }, {});\
         r.revoke();\
         console.log(util.inspect(r.proxy));",
        "<Revoked Proxy>",
    );
}

#[test]
fn a_revoked_proxy_survives_console_log_and_nested_inspection() {
    // `console.log` is `util.format`, and a nested value goes through the same
    // `formatValue`. Both used to abort the program, so reaching the three
    // lines at all is most of the assertion.
    expect(
        "const inspect = require('util').inspect;\
         const r = Proxy.revocable({ x: 1 }, {});\
         r.revoke();\
         console.log('value:', r.proxy);\
         console.log(inspect({ k: [r.proxy] }));",
        "value: <Revoked Proxy>\n{ k: [ <Revoked Proxy> ] }",
    );
}

#[test]
fn inspecting_a_proxy_never_runs_its_traps() {
    // `inspect.js` reads a proxy's target and handler from the internal slots
    // through `getProxyDetails` precisely so that no trap fires. Coercing the
    // proxy or reading a property off it would throw here.
    expect(
        "const util = require('util');\
         const proxy = new Proxy({ a: 1 }, {\
           get() { throw new Error('get trap'); },\
           ownKeys() { throw new Error('ownKeys trap'); },\
           getOwnPropertyDescriptor() { throw new Error('descriptor trap'); },\
         });\
         console.log(util.inspect(proxy));",
        "Proxy({ a: 1 })",
    );
}

#[test]
fn inspect_unwraps_a_proxy_of_a_proxy() {
    // The unwrapping loop calls `getProxyDetails(value, false)` for every layer,
    // so it depends on the target-only form returning the target rather than a
    // pair. Two `Proxy(` wrappers is the observable consequence.
    expect(
        "const util = require('util');\
         const inner = new Proxy({ a: 1 }, { get() { return 2; } });\
         const outer = new Proxy(inner, { get() { return 3; } });\
         console.log(util.inspect(outer));",
        "Proxy(Proxy({ a: 1 }))",
    );
}

#[test]
fn get_proxy_details_answers_each_arity_the_way_the_js_layer_reads_it() {
    // The three shapes `internal/util/inspect.js` depends on: one argument is a
    // pair, `true` is a pair, anything else is the target alone. A revoked
    // proxy's target is `null` in both forms.
    expect_exposed(
        "const { internalBinding } = require('internal/test/binding');\
         const get = internalBinding('util').getProxyDetails;\
         const live = new Proxy({ a: 1 }, {});\
         const revoked = Proxy.revocable({ x: 1 }, {});\
         revoked.revoke();\
         const shape = (value) => Array.isArray(value)\
           ? `${value.length}:${value[0] === null ? 'null' : typeof value[0]}`\
           : value === null ? 'null' : String(typeof value);\
         console.log(\
           shape(get(live)),\
           shape(get(live, false)),\
           shape(get({})),\
           shape(get(revoked.proxy)),\
           shape(get(revoked.proxy, false)));",
        "2:object object undefined 2:null null",
    );
}
