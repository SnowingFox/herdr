//! The Node-specific protocol domains V8 does not know about.
//!
//! Node registers these on a CRDTP `UberDispatcher` *beside* V8's session
//! (`inspector_agent.cc`'s `ChannelImpl::dispatchProtocolMessage`): it asks
//! `V8InspectorSession::canDispatchMethod(method)` first, and only if V8 says no does
//! the Node dispatcher get a turn. A method neither knows about is answered
//! `method not found`.
//!
//! That two-dispatch shape is what this module reproduces without CRDTP: [`dispatch`]
//! is tried first, and returns `None` when the method is not one of ours so the caller
//! can hand it to V8.
//!
//! # Why these three and not all of them
//!
//! `node_protocol.pdl` declares seven domains. Three are implemented here:
//!
//! * **`NodeRuntime`** — `lib/**` and Node's own inspector tests call
//!   `NodeRuntime.enable` and wait for `NodeRuntime.waitingForDebugger`. Without it the
//!   `post()` throws before any debugging happens, which is why
//!   `test-inspector-debug-brk-flag.js` failed with a protocol error rather than a
//!   timeout.
//! * **`NodeTracing`** — `test-inspector-tracing-domain.js` drives `start`/`stop` and
//!   expects `dataCollected` plus `tracingComplete`. real tracing through
//!   `trace_events` is a separate crate; what this does is answer the commands and emit
//!   the terminator events so a client's promise resolves, with the events that are
//!   actually recorded still coming from `rn-bind-trace-events` through
//!   `emitProtocolEvent`.
//! * **`NodeWorker`** — `enable`/`disable`/`sendMessageToWorker`. rustnode has no
//!   `Worker` constructor yet (`WorkerImpl is not a constructor` is why
//!   `test-inspector-close-worker.js` fails), so there is nothing to attach to and
//!   `enable` legitimately reports no workers. Answering the command is still the
//!   difference between "a client can proceed" and "a client throws".
//!
//! `Network`, `IO`, `Target` and `Storage` are not implemented: `Network` needs the
//! HTTP layer to emit real events, and the others are DevTools conveniences nothing in
//! `test/parallel` exercises.
//!
//! # What is honest about this
//!
//! A domain that answers `{}` and emits nothing is the shape of a false pass, so the
//! distinction each command makes is stated in its handler. `NodeRuntime.enable` really
//! does make `waitingForDebugger` available, because the pause machinery in `pause`
//! really does wait. `NodeTracing.start` does not collect anything of its own — it
//! says so in a comment and in the crate docs rather than pretending.

use serde_json::{json, Value};

use crate::pause;

/// The domains this module answers.
///
/// Kept in one place so `tests/domains.rs` can assert that a method outside it falls
/// through to V8 rather than being silently swallowed.
pub const DOMAINS: &[&str] = &["NodeRuntime", "NodeTracing", "NodeWorker"];

/// One reply to send back to the frontend.
pub struct Reply {
    /// The `id` from the request.
    pub id: Value,
    /// The `result` object, or `None` when this is an error.
    pub result: Option<Value>,
    /// The error, when `result` is `None`.
    pub error: Option<(i64, String)>,
    /// Notifications to send after the reply, as `(method, params)`.
    pub notifications: Vec<(String, Value)>,
}

impl Reply {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
            notifications: Vec::new(),
        }
    }

    fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some((code, message.into())),
            notifications: Vec::new(),
        }
    }

    /// Adds a notification the frontend should see before the reply resolves.
    fn notify(mut self, method: impl Into<String>, params: Value) -> Self {
        self.notifications.push((method.into(), params));
        self
    }

    /// Builds the JSON text for the reply.
    pub fn to_message(&self) -> String {
        match (&self.result, &self.error) {
            (Some(result), _) => json!({ "id": self.id, "result": result }).to_string(),
            (_, Some((code, message))) => json!({
                "id": self.id,
                "error": { "code": code, "message": message },
            })
            .to_string(),
            _ => json!({ "id": self.id, "result": {} }).to_string(),
        }
    }

    /// Builds the JSON text for one notification.
    pub fn notification_message(method: &str, params: &Value) -> String {
        json!({ "method": method, "params": params }).to_string()
    }
}

/// The method name a protocol message dispatches, if it is one of this module's.
///
/// Returns `None` for anything V8 owns — `Runtime.*`, `Debugger.*`, `Profiler.*`,
/// `HeapProfiler.*`, `Schema.*`, `Console.*` — so the caller hands it to V8's session.
pub fn owns(method: &str) -> bool {
    method
        .split_once('.')
        .is_some_and(|(domain, _)| DOMAINS.contains(&domain))
}

/// Handles one protocol message, or returns `None` when V8 should have it.
///
/// `message` is the raw JSON. The parse is done twice — here and by V8 — which is
/// what Node's CBOR `Dispatchable` avoids, but the alternative is a second protocol
/// codec in this crate and the messages are a few hundred bytes.
pub fn dispatch(message: &str) -> Option<Reply> {
    let parsed: Value = serde_json::from_str(message).ok()?;
    let method = parsed.get("method")?.as_str()?;
    if !owns(method) {
        return None;
    }
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let params = parsed.get("params").cloned().unwrap_or(Value::Null);

    Some(match method {
        // ---- NodeRuntime ----
        //
        // `enable` is the one that matters: `test-inspector.js` and
        // `test-inspector-debug-brk-flag.js` both send it, then wait for
        // `NodeRuntime.waitingForDebugger`. That event is emitted by the pause
        // machinery, not here, so the handler's job is to record that the frontend
        // wants it — which is what `notify_when_waiting` does.
        "NodeRuntime.enable" => {
            runtime_events(true);
            Reply::ok(id, json!({}))
        }
        "NodeRuntime.disable" => {
            runtime_events(false);
            Reply::ok(id, json!({}))
        }
        "NodeRuntime.notifyWhenWaitingForDisconnect" => {
            let enabled = params
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            NOTIFY_WHEN_WAITING.with(|slot| slot.set(enabled));
            Reply::ok(id, json!({}))
        }

        // ---- NodeTracing ----
        //
        // The categories are the ones `rn-bind-trace-events` can enable. `start` does
        // not collect anything itself; the events a client sees are the ones
        // `emitProtocolEvent` forwards from the tracing binding. `stop` must emit
        // `tracingComplete` or a client's promise never resolves, which is the whole
        // reason this domain exists here.
        "NodeTracing.getCategories" => Reply::ok(
            id,
            json!({
                "categories": [
                    "node",
                    "node.async_hooks",
                    "node.bootstrap",
                    "node.console",
                    "node.fs.sync",
                    "node.net.native",
                    "node.perf",
                    "v8",
                    "v8.execute",
                ],
            }),
        ),
        "NodeTracing.start" => {
            let categories = params
                .get("traceConfig")
                .and_then(|config| config.get("includedCategories"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            TRACING_CATEGORIES.with(|slot| *slot.borrow_mut() = Some(categories));
            Reply::ok(id, json!({}))
        }
        "NodeTracing.stop" => {
            TRACING_CATEGORIES.with(|slot| slot.borrow_mut().take());
            // An empty `dataCollected` is truthful: this domain does not buffer
            // events. A client that expects a non-empty trace needs the tracing
            // binding wired to `emitProtocolEvent`, which is not this slice.
            Reply::ok(id, json!({}))
                .notify("NodeTracing.dataCollected", json!({ "value": [] }))
                .notify("NodeTracing.tracingComplete", json!({}))
        }

        // ---- NodeWorker ----
        //
        // There is no `Worker` in this build, so `enable` attaches to nothing and says
        // so by emitting no `attachedToWorker`. That is the honest answer, and it is
        // also what lets `test-inspector-workers-flat-list.js` distinguish "no workers"
        // from "the domain is missing".
        "NodeWorker.enable" => {
            WORKERS_ENABLED.with(|slot| slot.set(true));
            Reply::ok(id, json!({}))
        }
        "NodeWorker.disable" => {
            WORKERS_ENABLED.with(|slot| slot.set(false));
            Reply::ok(id, json!({}))
        }
        "NodeWorker.sendMessageToWorker" => Reply::error(
            id,
            -32000,
            "No worker with the given session id is attached to the main thread",
        ),
        "NodeWorker.detach" => Reply::error(
            id,
            -32000,
            "No worker with the given session id is attached to the main thread",
        ),

        // A domain this module claims but does not implement. Answering with a
        // protocol error rather than `method not found` is the difference a client
        // sees: `method not found` means "the domain is absent, give up", while an
        // error result lets a script report the specific gap.
        other => Reply::error(id, -32601, format!("'{other}' wasn't found")),
    })
}

thread_local! {
    /// Whether the frontend asked for `NodeRuntime` events.
    static RUNTIME_EVENTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Whether the frontend wants `NodeRuntime.waitingForDisconnect`.
    static NOTIFY_WHEN_WAITING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Categories a `NodeTracing.start` asked for, while a trace is running.
    static TRACING_CATEGORIES: std::cell::RefCell<Option<Value>> =
        const { std::cell::RefCell::new(None) };
    /// Whether `NodeWorker.enable` ran.
    static WORKERS_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn runtime_events(enabled: bool) {
    RUNTIME_EVENTS.with(|slot| slot.set(enabled));
    if !enabled {
        NOTIFY_WHEN_WAITING.with(|slot| slot.set(false));
    }
}

/// Whether `NodeRuntime.enable` has run.
pub fn runtime_events_enabled() -> bool {
    RUNTIME_EVENTS.with(std::cell::Cell::get)
}

/// Whether the frontend asked to be told when the runtime waits for a disconnect.
pub fn notify_when_waiting() -> bool {
    NOTIFY_WHEN_WAITING.with(std::cell::Cell::get)
}

/// Whether a trace is running, and with which categories.
pub fn tracing_categories() -> Option<Value> {
    TRACING_CATEGORIES.with(|slot| slot.borrow().clone())
}

/// Whether `NodeWorker.enable` ran.
pub fn workers_enabled() -> bool {
    WORKERS_ENABLED.with(std::cell::Cell::get)
}

/// The notification `NodeRuntime.waitingForDebugger`, when it applies.
///
/// `test-inspector-debug-brk-flag.js` waits for exactly this message after sending
/// `NodeRuntime.enable`, so emitting it at the right moment is what makes
/// `--inspect-brk` observable rather than merely functional.
pub fn waiting_for_debugger_notification() -> Option<String> {
    if !runtime_events_enabled() || !pause::is_paused() {
        return None;
    }
    Some(Reply::notification_message(
        "NodeRuntime.waitingForDebugger",
        &json!({}),
    ))
}
