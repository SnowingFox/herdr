//! The Node-specific protocol domains: `NodeRuntime`, `NodeTracing`, `NodeWorker`.
//!
//! The failure these prevent is the one a missing domain causes: `post()` throws before
//! any debugging happens, so the file fails on a protocol error rather than on the
//! thing it was testing. `test-inspector-debug-brk-flag.js` sent
//! `NodeRuntime.enable` and waited for a `NodeRuntime.waitingForDebugger` notification
//! that could never arrive, because there was no such domain.
//!
//! Every test here asserts on the *reply the frontend receives*, not on a handler being
//! registered, because a domain that answers `{}` and is never wired to anything is
//! exactly the shape of a false pass.

use rn_bind_inspector::domains;

#[test]
fn node_runtime_enable_is_acknowledged() {
    let reply = domains::dispatch(r#"{"id":1,"method":"NodeRuntime.enable"}"#)
        .expect("NodeRuntime is one of this module's domains");
    assert_eq!(reply.id, serde_json::json!(1));
    assert!(
        reply.result.is_some(),
        "NodeRuntime.enable must succeed, not error: {:?}",
        reply.error
    );
    assert!(
        domains::runtime_events_enabled(),
        "enable must record that the frontend wants NodeRuntime events; without this \
         waitingForDebugger is never emitted and the test that waits for it hangs"
    );
}

#[test]
fn node_runtime_disable_turns_the_events_off() {
    domains::dispatch(r#"{"id":1,"method":"NodeRuntime.enable"}"#).expect("enable");
    domains::dispatch(r#"{"id":2,"method":"NodeRuntime.disable"}"#).expect("disable");
    assert!(
        !domains::runtime_events_enabled(),
        "disable must clear the flag"
    );
}

#[test]
fn notify_when_waiting_for_disconnect_is_recorded() {
    let reply = domains::dispatch(
        r#"{"id":1,"method":"NodeRuntime.notifyWhenWaitingForDisconnect","params":{"enabled":true}}"#,
    )
    .expect("a NodeRuntime method");
    assert!(reply.result.is_some(), "the command must be accepted");
    assert!(
        domains::notify_when_waiting(),
        "the flag must be recorded; a client that asked for it and never gets the event \
         waits forever"
    );
}

#[test]
fn node_tracing_reports_real_categories() {
    let reply = domains::dispatch(r#"{"id":1,"method":"NodeTracing.getCategories"}"#)
        .expect("a NodeTracing method");
    let categories = reply
        .result
        .as_ref()
        .and_then(|result| result.get("categories"))
        .and_then(serde_json::Value::as_array)
        .expect("getCategories must return a categories array");
    assert!(
        !categories.is_empty(),
        "an empty category list is what a stub returns; the tracing binding has categories"
    );
    let named: Vec<&str> = categories
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert!(
        named.contains(&"v8"),
        "the `v8` category must be offered: {named:?}"
    );
}

#[test]
fn node_tracing_stop_emits_the_terminator_events() {
    // A `stop` that answers `{}` and never emits `tracingComplete` leaves the client's
    // promise pending forever. That is the failure mode this asserts against.
    domains::dispatch(r#"{"id":1,"method":"NodeTracing.start"}"#).expect("start");
    let reply =
        domains::dispatch(r#"{"id":2,"method":"NodeTracing.stop"}"#).expect("a NodeTracing method");
    assert!(reply.result.is_some(), "stop must succeed");
    let methods: Vec<&str> = reply
        .notifications
        .iter()
        .map(|(method, _)| method.as_str())
        .collect();
    assert!(
        methods.contains(&"NodeTracing.dataCollected"),
        "a client needs dataCollected before tracingComplete; got {methods:?}"
    );
    assert!(
        methods.contains(&"NodeTracing.tracingComplete"),
        "a client's `stop` promise resolves on tracingComplete; got {methods:?}"
    );
}

#[test]
fn node_worker_enable_attaches_to_nothing_and_says_so() {
    // There is no `Worker` in this build, so the honest answer is "enabled, no workers".
    // Emitting an `attachedToWorker` for a worker that does not exist would be worse
    // than emitting none.
    let reply = domains::dispatch(
        r#"{"id":1,"method":"NodeWorker.enable","params":{"waitForDebuggerOnStart":false}}"#,
    )
    .expect("a NodeWorker method");
    assert!(reply.result.is_some(), "enable must succeed");
    assert!(domains::workers_enabled(), "the flag must be recorded");
    assert!(
        reply.notifications.is_empty(),
        "no worker exists, so no attachedToWorker may be emitted; got {:?}",
        reply.notifications
    );
}

#[test]
fn a_worker_message_without_a_session_is_an_error_not_a_silent_success() {
    // `sendMessageToWorker` for an unknown session must fail the way Node does. Answering
    // `{}` would leave a caller believing its message was delivered.
    let reply = domains::dispatch(
        r#"{"id":1,"method":"NodeWorker.sendMessageToWorker","params":{"message":"{}","sessionId":"9"}}"#,
    )
    .expect("a NodeWorker method");
    assert!(
        reply.error.is_some(),
        "an unknown session must be an error, got {:?}",
        reply.result
    );
}

#[test]
fn v8_domains_are_not_intercepted() {
    // The whole two-stage dispatch depends on this: a `Debugger.*` or `Runtime.*` method
    // that this module claimed would never reach V8, and the debugger would stop working
    // while the domain handlers looked correct.
    for method in [
        "Runtime.evaluate",
        "Debugger.enable",
        "Debugger.setBreakpointByUrl",
        "Profiler.start",
        "HeapProfiler.takeHeapSnapshot",
        "Console.enable",
        "Schema.getDomains",
    ] {
        assert!(
            !domains::owns(method),
            "{method} belongs to V8 and must be handed to its session"
        );
        assert!(
            domains::dispatch(&format!(r#"{{"id":1,"method":"{method}"}}"#)).is_none(),
            "{method} must fall through, not be answered here"
        );
    }
}

#[test]
fn an_unknown_method_in_a_known_domain_is_a_protocol_error() {
    // A domain this module claims but does not implement. `method not found` would tell
    // the client the domain is absent; an error result lets it report the specific gap.
    let reply = domains::dispatch(r#"{"id":1,"method":"NodeRuntime.nonexistent"}"#)
        .expect("NodeRuntime is claimed");
    let (code, message) = reply.error.expect("an unknown method must error");
    assert_eq!(code, -32601, "the code must be `method not found`");
    assert!(
        message.contains("NodeRuntime.nonexistent"),
        "the message must name the method: {message}"
    );
}

#[test]
fn a_message_without_a_method_is_not_claimed() {
    // A malformed message must reach V8 and let it answer, rather than being treated as
    // one of ours and dropped.
    assert!(domains::dispatch("{}").is_none());
    assert!(domains::dispatch("not json").is_none());
}
