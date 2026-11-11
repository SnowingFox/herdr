//! The `inspector` namespace, driven through a real V8 isolate.
//!
//! These tests are the ones that matter, and the reason is the failure mode this
//! namespace is most likely to have: an object with the right member names whose
//! `Connection` cannot actually evaluate anything. The contract check would pass, the
//! namespace would load, and `session.post('Runtime.evaluate', ...)` would answer
//! nothing. So every test here goes through the real protocol:
//!
//! * `Runtime.evaluate` returns the value the expression produced, as CDP encodes it.
//! * `Profiler.start`/`Profiler.stop` produces a profile with real call frames.
//! * `Runtime.getProperties` resolves an `objectId` that a previous `evaluate`
//!   returned, which is what proves the session keeps V8 state between messages.
//!
//! Nothing here asserts that a member exists. `tests/namespace.rs` does that, and it
//! is the weaker test.

use rn_bind_inspector::Inspector;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
///
/// V8's platform and initialisation are process-global, so the tests serialise on a
/// mutex rather than each calling `V8::initialize`.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // The guard outlives the isolate: dropping it first would let a second test
    // enter `V8::initialize` concurrently.
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    // The inspector is created against this pointer, which is the same arrangement
    // the CLI has: record the isolate, then install the namespaces.
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
        // `setFlagsFromString` — reached through `lib/v8.js` — aborts inside V8 once
        // the flag list is frozen, which happens during `V8::Initialize`. The CLI
        // disables the freeze for the same reason.
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace and binds it to `__inspector` on the global object.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = Inspector
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the inspector namespace must not fail");
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

/// Collects every message a session produced.
///
/// `lib/inspector.js` parses a message and looks for `id` or `method`, so a test that
/// wanted to behave like that file would. These tests drive the same `Connection`
/// object the file does, but keep the raw strings so a failure can quote the reply.
const COLLECTOR: &str = r#"
globalThis.collect = function collect(messages) {
  // The callback `Connection` takes. `lib/inspector.js` parses and dispatches; here
  // the raw text is pushed so a test can inspect the protocol's own words.
  return function (message) { messages.push(message); };
};

/// The reply with a given `id`, parsed, or null while it has not arrived.
globalThis.reply = function reply(messages, id) {
  for (const message of messages) {
    const parsed = JSON.parse(message);
    if (parsed.id === id) return parsed;
  }
  return null;
};
"#;

#[test]
fn runtime_evaluate_returns_the_value_the_expression_produced() {
    with_context(|scope| {
        install(scope);
        run(scope, COLLECTOR);
        run(scope, "globalThis.messages = []; globalThis.session = new __inspector.Connection(collect(messages));");

        // The whole point of the namespace: a real expression evaluated in the real
        // context, with the result coming back through the protocol.
        run(
            scope,
            r#"session.dispatch('{"id":1,"method":"Runtime.enable"}')"#,
        );
        run(
            scope,
            r#"session.dispatch('{"id":2,"method":"Runtime.evaluate","params":{"expression":"6 * 7","returnByValue":true}}')"#,
        );

        let reply = run(scope, "JSON.stringify(reply(messages, 2))");
        let parsed: serde_json::Value =
            serde_json::from_str(&reply).expect("the reply must be JSON");
        assert_eq!(
            parsed["result"]["result"]["value"],
            serde_json::json!(42),
            "Runtime.evaluate must return the value of `6 * 7`; reply was {reply}"
        );
        assert_eq!(
            parsed["result"]["result"]["type"], "number",
            "the remote object must be typed; reply was {reply}"
        );
    });
}

#[test]
fn runtime_evaluate_sees_the_javascript_the_isolate_has_run() {
    with_context(|scope| {
        install(scope);
        run(scope, COLLECTOR);
        run(scope, "globalThis.messages = []; globalThis.session = new __inspector.Connection(collect(messages));");
        // State written by ordinary JavaScript, before the evaluate. An evaluate that
        // ran in a fresh context — the classic way to get this wrong by creating a
        // second `Context` for the session — would report `undefined` here.
        run(scope, "globalThis.shared = { answer: 41 };");
        run(
            scope,
            r#"session.dispatch('{"id":1,"method":"Runtime.evaluate","params":{"expression":"shared.answer + 1","returnByValue":true}}')"#,
        );

        let reply = run(scope, "JSON.stringify(reply(messages, 1))");
        let parsed: serde_json::Value =
            serde_json::from_str(&reply).expect("the reply must be JSON");
        assert_eq!(
            parsed["result"]["result"]["value"],
            serde_json::json!(42),
            "the session must evaluate in the context that created it; reply was {reply}"
        );
    });
}

#[test]
fn runtime_get_properties_resolves_an_object_id_from_an_earlier_evaluate() {
    with_context(|scope| {
        install(scope);
        run(scope, COLLECTOR);
        run(scope, "globalThis.messages = []; globalThis.session = new __inspector.Connection(collect(messages));");
        // Built with `JSON.stringify` rather than pasted, so a quote inside the
        // expression cannot turn into a syntax error here — which it did.
        run(
            scope,
            "session.dispatch(JSON.stringify({ id: 1, method: 'Runtime.evaluate', \
               params: { expression: '({a: 1, b: \"two\"})', objectGroup: 'test' } }));",
        );
        // The object id only exists if the session kept the wrapped object alive
        // between two dispatches, which is the state a naive implementation loses.
        let object_id = run(scope, "reply(messages, 1).result.result.objectId");
        assert!(
            !object_id.is_empty() && object_id != "undefined",
            "evaluate must return an objectId for an object result; reply was {}",
            run(scope, "JSON.stringify(reply(messages, 1))")
        );
        // Built in JavaScript so the id is JSON-encoded by the same engine that
        // produced it, instead of being pasted into a string here where a quote or a
        // backslash in it would be a syntax error.
        run(
            scope,
            "globalThis.objectId = reply(messages, 1).result.result.objectId; \
             session.dispatch(JSON.stringify({ id: 2, method: 'Runtime.getProperties', \
               params: { objectId: objectId, ownProperties: true } }));",
        );

        let reply = run(scope, "JSON.stringify(reply(messages, 2))");
        let parsed: serde_json::Value =
            serde_json::from_str(&reply).expect("the reply must be JSON");
        let properties = parsed["result"]["result"]
            .as_array()
            .unwrap_or_else(|| panic!("getProperties must return an array; reply was {reply}"));
        let names: Vec<&str> = properties
            .iter()
            .filter_map(|property| property["name"].as_str())
            .collect();
        assert!(
            names.contains(&"a") && names.contains(&"b"),
            "getProperties must resolve the object the evaluate returned; got {names:?}"
        );
    });
}

#[test]
fn profiler_start_and_stop_produce_a_profile_with_call_frames() {
    with_context(|scope| {
        install(scope);
        run(scope, COLLECTOR);
        run(scope, "globalThis.messages = []; globalThis.session = new __inspector.Connection(collect(messages));");
        run(
            scope,
            r#"session.dispatch('{"id":1,"method":"Profiler.enable"}')"#,
        );
        run(
            scope,
            r#"session.dispatch('{"id":2,"method":"Profiler.start","params":{"interval":100}}')"#,
        );
        // Something for the sampler to see. A profile of an idle isolate is legitimately
        // empty, so a test that started and stopped with nothing in between would pass
        // on a broken implementation.
        run(
            scope,
            "function busy() { let total = 0; for (let index = 0; index < 300000; index++) total += index; return total; } busy();",
        );
        run(
            scope,
            r#"session.dispatch('{"id":3,"method":"Profiler.stop"}')"#,
        );

        let reply = run(scope, "JSON.stringify(reply(messages, 3))");
        let parsed: serde_json::Value =
            serde_json::from_str(&reply).expect("the reply must be JSON");
        let profile = &parsed["result"]["profile"];
        assert!(
            profile.is_object(),
            "Profiler.stop must return a profile object; reply was {reply}"
        );
        let nodes = profile["nodes"]
            .as_array()
            .unwrap_or_else(|| panic!("the profile must have nodes; reply was {reply}"));
        assert!(
            !nodes.is_empty(),
            "the profile must contain at least one call frame; reply was {reply}"
        );
        // A profile whose start and end times are both zero is the shape a stub
        // produces; V8 sets them from the sampler's clock.
        let start = profile["startTime"].as_f64().unwrap_or(0.0);
        let end = profile["endTime"].as_f64().unwrap_or(0.0);
        assert!(
            end > start,
            "the profile must span real time; start={start} end={end}"
        );
    });
}

#[test]
fn a_second_session_is_independent_of_the_first() {
    with_context(|scope| {
        install(scope);
        run(scope, COLLECTOR);
        run(
            scope,
            "globalThis.one = []; globalThis.two = []; \
             globalThis.first = new __inspector.Connection(collect(one)); \
             globalThis.second = new __inspector.Connection(collect(two));",
        );
        run(
            scope,
            r#"first.dispatch('{"id":1,"method":"Runtime.evaluate","params":{"expression":"1 + 1","returnByValue":true}}')"#,
        );
        run(
            scope,
            r#"second.dispatch('{"id":7,"method":"Runtime.evaluate","params":{"expression":"2 + 2","returnByValue":true}}')"#,
        );

        assert_eq!(
            run(scope, "one.length"),
            "1",
            "the first session must receive its own reply"
        );
        assert_eq!(
            run(scope, "two.length"),
            "1",
            "the second session must receive its own reply"
        );
        let second = run(scope, "JSON.stringify(reply(two, 7))");
        let parsed: serde_json::Value =
            serde_json::from_str(&second).expect("the reply must be JSON");
        assert_eq!(
            parsed["result"]["result"]["value"],
            serde_json::json!(4),
            "the second session's evaluate must not answer the first's id; reply was {second}"
        );
    });
}

#[test]
fn disconnect_stops_replies_reaching_the_callback() {
    with_context(|scope| {
        install(scope);
        run(scope, COLLECTOR);
        run(
            scope,
            "globalThis.messages = []; globalThis.session = new __inspector.Connection(collect(messages));",
        );
        run(
            scope,
            r#"session.dispatch('{"id":1,"method":"Runtime.evaluate","params":{"expression":"1","returnByValue":true}}')"#,
        );
        assert_eq!(run(scope, "messages.length"), "1");
        run(scope, "session.disconnect();");
        // `lib/inspector.js` throws `ERR_INSPECTOR_NOT_CONNECTED` before it gets here,
        // but the binding is reachable directly and a closed connection must not
        // resurrect a session.
        run(
            scope,
            r#"try { session.dispatch('{"id":2,"method":"Runtime.evaluate","params":{"expression":"2"}}'); } catch {}"#,
        );
        assert_eq!(
            run(scope, "messages.length"),
            "1",
            "a dispatched message after disconnect must not produce a reply"
        );
    });
}

#[test]
fn the_namespace_carries_v8s_console() {
    with_context(|scope| {
        install(scope);
        // `wrapConsole` in `lib/internal/util/inspector.js` reads this member and
        // copies each of its functions onto the global console. `undefined` here means
        // no `console.log` ever reaches a debugger.
        let kind = run(scope, "typeof __inspector.console");
        assert_eq!(
            kind, "object",
            "the namespace must expose V8's console object"
        );
        let log = run(scope, "typeof __inspector.console.log");
        assert_eq!(log, "function", "V8's console must have a log method");
    });
}
