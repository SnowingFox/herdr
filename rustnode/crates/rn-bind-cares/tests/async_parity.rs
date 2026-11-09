//! Parity for the asynchronous members, against the same `node` recording.
//!
//! `node_expected_async.json` was produced by `node_probe_async.js` under a real
//! `node --expose-internals`. It records, for thirteen queries, the exact
//! `(status, result)` pairs the request wraps deliver.
//!
//! The probe cannot be replayed here unchanged: a real completion is queued on
//! the microtask queue and only runs when the isolate drains it, which the test
//! drives with `perform_microtask_checkpoint`. That is the whole point of the
//! test — it exercises the delivery path, not just the resolver.
//!
//! What the recording pins that hand-written expectations would not:
//!
//! * `family: 4` for `localhost` answers `['127.0.0.1', '127.0.0.1']` on this
//!   machine, because `/etc/hosts` names the address twice and neither libuv nor
//!   Node deduplicates.
//! * A failed lookup reports `-3008` (`UV_EAI_NONAME`) with `null` for the
//!   result, and `DNSException` turns that into `ENOTFOUND`.
//! * `lookupService` reports the `/etc/services` name for the port, so 80 is
//!   `http` and 54321 is `54321`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_cares::CaresWrap;

/// `node_probe_async.js`'s recording, one `[label, status, result...]` per query.
const RECORDED: &str = include_str!("node_expected_async.json");

/// The probe that produced it, so the live check runs the same queries.
const PROBE: &str = include_str!("node_probe_async.js");

/// One query the recording covers.
struct Query {
    label: &'static str,
    host: &'static str,
    family: i32,
    hints: i32,
    order: i32,
}

/// The forward lookups, in the order `node_probe_async.js` dispatches them.
const LOOKUPS: &[Query] = &[
    Query {
        label: "localhost_unspec_verbatim",
        host: "localhost",
        family: 0,
        hints: 0,
        order: 0,
    },
    Query {
        label: "localhost_unspec_v4first",
        host: "localhost",
        family: 0,
        hints: 0,
        order: 1,
    },
    Query {
        label: "localhost_unspec_v6first",
        host: "localhost",
        family: 0,
        hints: 0,
        order: 2,
    },
    Query {
        label: "localhost_v4",
        host: "localhost",
        family: 4,
        hints: 0,
        order: 0,
    },
    Query {
        label: "localhost_v6",
        host: "localhost",
        family: 6,
        hints: 0,
        order: 0,
    },
    Query {
        label: "localhost_addrconfig",
        host: "localhost",
        family: 0,
        hints: 32,
        order: 0,
    },
    Query {
        label: "ipv4_literal",
        host: "127.0.0.1",
        family: 0,
        hints: 0,
        order: 0,
    },
    Query {
        label: "ipv6_literal",
        host: "::1",
        family: 0,
        hints: 0,
        order: 0,
    },
    Query {
        label: "nonexistent",
        host: "no-such-host.invalid",
        family: 0,
        hints: 0,
        order: 0,
    },
];

/// The reverse lookups, in the same order.
const REVERSE: &[(&str, &str, u32)] = &[
    ("nameinfo_v4", "127.0.0.1", 80),
    ("nameinfo_v6", "::1", 80),
    ("nameinfo_ssh", "127.0.0.1", 22),
    ("nameinfo_unassigned", "127.0.0.1", 54321),
];

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Runs every recorded query in-process and returns the answers keyed by label.
///
/// The results come out of the JavaScript side rather than from the Rust
/// resolver, so a bug in the delivery path shows up here: the probe reads
/// `__results`, which only `oncomplete` fills.
fn ours() -> BTreeMap<String, serde_json::Value> {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = std::pin::pin!(v8::ContextScope::new(scope, context));
    let scope = &mut context_scope;

    let mut async_ids = rn_core::AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = CaresWrap
        .install(scope, &mut ctx)
        .expect("install cares_wrap");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__cares").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set");

    // The probe records into `globalThis.__results` as a JSON string; that keeps
    // the comparison in one format on both sides.
    let mut script = String::from(
        r#"
        globalThis.__results = {};
        (function run() {
          const binding = globalThis.__cares;
        "#,
    );
    for query in LOOKUPS {
        script.push_str(&format!(
            r#"
            {{
              const req = new binding.GetAddrInfoReqWrap();
              req.__label = {label:?};
              req.oncomplete = function(status, addresses) {{
                globalThis.__results[this.__label] = [status,
                  addresses === null ? null : Array.from(addresses)];
              }};
              const status = binding.getaddrinfo(req, {host:?}, {family}, {hints}, {order});
              if (status) globalThis.__results[req.__label] = ['sync', status];
            }}
            "#,
            label = query.label,
            host = query.host,
            family = query.family,
            hints = query.hints,
            order = query.order,
        ));
    }
    for (label, address, port) in REVERSE {
        script.push_str(&format!(
            r#"
            {{
              const req = new binding.GetNameInfoReqWrap();
              req.__label = {label:?};
              req.oncomplete = function(status, hostname, service) {{
                globalThis.__results[this.__label] = [status, hostname, service];
              }};
              const status = binding.getnameinfo(req, {address:?}, {port});
              if (status) globalThis.__results[req.__label] = ['sync', status];
            }}
            "#,
        ));
    }
    script.push_str("})();");

    let source = v8::String::new(scope, &script).expect("source");
    v8::Script::compile(scope, source, None)
        .expect("compiles")
        .run(scope)
        .expect("runs");

    // Deliver every completion. `lib/dns.js` depends on this being after the
    // dispatch loop rather than inline, which `deliver::tests` pins separately.
    scope.as_mut().perform_microtask_checkpoint();

    let results_key = v8::String::new(scope, "__results").expect("key");
    let results = global.get(scope, results_key.into()).expect("results");
    // Re-serialise through JSON so keys become strings, as they are in the
    // recording.
    let json_key = v8::String::new(scope, "JSON").expect("key");
    let json = global.get(scope, json_key.into()).expect("JSON");
    let stringify_key = v8::String::new(scope, "stringify").expect("key");
    let stringify: v8::Local<v8::Function> = json
        .to_object(scope)
        .expect("JSON object")
        .get(scope, stringify_key.into())
        .expect("stringify")
        .try_into()
        .expect("function");
    let text = stringify
        .call(scope, json, &[results])
        .expect("stringify call")
        .to_rust_string_lossy(scope);
    serde_json::from_str(&text).expect("JSON object")
}

/// The recording, keyed the same way.
fn recorded() -> BTreeMap<String, serde_json::Value> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(RECORDED).expect("recorded is a JSON array");
    let mut map = BTreeMap::new();
    for entry in entries {
        let array = entry.as_array().expect("an array");
        let label = array[0].as_str().expect("label").to_string();
        let rest: Vec<serde_json::Value> = array[1..].to_vec();
        map.insert(label, serde_json::Value::Array(rest));
    }
    map
}

#[test]
fn the_async_answers_match_the_recorded_node_answers() {
    let expected = recorded();
    let actual = ours();

    for (label, value) in &expected {
        let Some(ours) = actual.get(label) else {
            panic!("{label} was never delivered");
        };
        assert_eq!(ours, value, "{label} disagrees with the recording");
    }
    assert_eq!(
        actual.len(),
        expected.len(),
        "the binding answered {} queries but the recording has {}",
        actual.len(),
        expected.len()
    );
}

/// The recording has to keep covering the cases that make it worth keeping.
#[test]
fn the_recording_covers_the_interesting_cases() {
    let expected = recorded();
    assert_eq!(expected.len(), 13);

    // A failed lookup reports a libuv code and a null result.
    let not_found = expected["nonexistent"].as_array().expect("array");
    assert_eq!(not_found[0], -3008.0, "UV_EAI_NONAME");
    assert!(not_found[1].is_null());

    // The duplicate `127.0.0.1` is the fixture's most surprising entry.
    let v4 = expected["localhost_v4"].as_array().expect("array");
    let addresses = v4[1].as_array().expect("array");
    assert_eq!(
        addresses.len(),
        2,
        "recorded from this machine's /etc/hosts"
    );
    assert_eq!(addresses[0], "127.0.0.1");
    assert_eq!(addresses[1], "127.0.0.1");

    // Order actually reorders, which is the only reason `order` is an argument.
    let v4first = expected["localhost_unspec_v4first"]
        .as_array()
        .expect("array");
    let v4first = v4first[1].as_array().expect("array");
    assert_eq!(v4first[0], "127.0.0.1");
    let v6first = expected["localhost_unspec_v6first"]
        .as_array()
        .expect("array");
    let v6first = v6first[1].as_array().expect("array");
    assert_eq!(v6first[0], "::1");

    // Services come from /etc/services.
    let http = expected["nameinfo_v4"].as_array().expect("array");
    assert_eq!(http[1], "localhost");
    assert_eq!(http[2], "http");
    let unassigned = expected["nameinfo_unassigned"].as_array().expect("array");
    assert_eq!(unassigned[2], "54321");
}

/// Replays the probe under a live `node` so the fixture cannot drift from the
/// binary. Skipped silently when there is no `node` or it cannot run the probe.
#[test]
fn the_live_node_binary_agrees_with_the_async_recording() {
    let Some(node) = node_binary() else {
        return;
    };
    let path = std::env::temp_dir().join(format!("rn-cares-async-probe-{}.js", std::process::id()));
    if std::fs::write(&path, PROBE).is_err() {
        return;
    }
    let output = Command::new(node)
        .arg("--expose-internals")
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    let Ok(output) = output else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(start) = stdout.find('[') else {
        return;
    };
    let fresh: Vec<serde_json::Value> =
        serde_json::from_str(&stdout[start..]).expect("live node printed JSON");
    let recorded: Vec<serde_json::Value> =
        serde_json::from_str(RECORDED).expect("recorded is JSON");
    assert_eq!(fresh, recorded, "the recording has drifted from node");
}

fn node_binary() -> Option<PathBuf> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("command -v node")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}
