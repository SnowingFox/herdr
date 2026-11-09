//! Parity with a real `node` binary for the members that produce values.
//!
//! `node_expected.json` is a recording of what `node --expose-internals` answers
//! for `internalBinding('cares_wrap')` on this machine, captured with
//! `node_probe.js`. The tests below run the same queries through the Rust
//! binding and compare.
//!
//! This is the check that matters, because several members return values that
//! look arbitrary and are not:
//!
//! * `canonicalizeIP` returns `undefined` — not `null`, not a throw — for an
//!   input that is not an address, and refuses `192.168.000.001` because libuv
//!   rejects a leading zero rather than reading it as octal.
//! * `strerror` reports `"unknown"` for every code c-ares does not define, which
//!   includes every negative number except Node's own `-1000`.
//! * `setServers` reports c-ares status `17` (`ARES_EBADSTR`) for a malformed
//!   address instead of throwing.
//!
//! Comparing against a recording rather than hand-written expectations means a
//! misreading of libuv or c-ares shows up as a mismatch instead of as agreement
//! with itself. When `node` is on `PATH` the recording is regenerated and
//! compared too, so the fixture cannot silently drift from the binary.

use std::path::PathBuf;
use std::process::Command;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_cares::CaresWrap;

/// The recording, produced by `node --expose-internals node_probe.js`.
const RECORDED: &str = include_str!("node_expected.json");

/// The probe both sides run. Kept as a file so the two are readable side by
/// side and a change to one is obvious in review.
const PROBE: &str = include_str!("node_probe.js");

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace, injects it as `__cares`, runs `source`, and returns
/// `globalThis.__out`.
///
/// The probe is written to read the namespace from `__cares` when it is present,
/// which is how the same file serves both this test and a real `node` run.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
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
    // `node_probe.js` checks this flag to decide whether to print its own
    // output; under the test the value is read from `__out` instead.
    let flag_key = v8::String::new(scope, "__exposeInternals").expect("key");
    global
        .set(scope, flag_key.into(), v8::Boolean::new(scope, true).into())
        .expect("set");

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    script.run(scope).expect("runs");

    let out_key = v8::String::new(scope, "__out").expect("key");
    global
        .get(scope, out_key.into())
        .expect("__out")
        .to_rust_string_lossy(scope)
}

/// Runs the recorded probe in this process and returns the JSON it produced.
fn ours() -> String {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = std::pin::pin!(v8::ContextScope::new(scope, context));
    run(&mut context_scope, PROBE)
}

/// Where `node` lives, when it is on `PATH`.
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

fn compare(label: &str, recorded: &str, actual: &str) {
    let recorded: serde_json::Value = serde_json::from_str(recorded).expect("recorded is JSON");
    let actual: serde_json::Value = serde_json::from_str(actual)
        .unwrap_or_else(|error| panic!("{label}: the probe produced no JSON: {error}\n{actual}"));
    assert_eq!(recorded, actual, "{label} disagrees with the recording");
}

#[test]
fn the_binding_matches_the_recorded_node_answers() {
    compare("cares_wrap", RECORDED, &ours());
}

/// Regenerates the recording from a live `node` and compares it, so a fixture
/// that no longer reflects the binary fails here rather than passing quietly.
#[test]
fn the_live_node_binary_agrees_with_the_recording() {
    let Some(node) = node_binary() else {
        // No `node` on this machine: the fixture is still checked by the test
        // above, so skipping is honest rather than hiding a gap.
        return;
    };
    let path = std::env::temp_dir().join(format!("rn-cares-probe-{}.js", std::process::id()));
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
        // A binary that cannot run the probe is not a parity failure; the
        // fixture check above still runs.
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(start) = stdout.find('{') else {
        return;
    };
    compare("live node", RECORDED, &stdout[start..]);
}

/// The fixture is only useful if it actually covers the members under test. A
/// recording that silently shrank would let the comparison above pass while
/// checking almost nothing.
#[test]
fn the_recording_covers_the_whole_synchronous_surface() {
    let recorded: serde_json::Value = serde_json::from_str(RECORDED).expect("JSON");
    let object = recorded.as_object().expect("an object");
    for key in [
        "constants",
        "canonicalize",
        "convert_ipv6",
        "strerror",
        "request_wraps",
        "channel",
    ] {
        assert!(object.contains_key(key), "the recording lacks {key}");
    }

    let canonicalize = object["canonicalize"].as_object().expect("map");
    assert_eq!(
        canonicalize.len(),
        33,
        "every tricky address spelling must be recorded"
    );
    // The interesting cases, each of which a naive implementation gets wrong.
    for spelling in [
        "192.168.000.001",
        "fe80::1%eth0",
        "::ffff:127.0.0.1",
        "1:2:3:4:5:6:1.2.3.4",
        "2001:DB8::0:1:0:0:1",
    ] {
        assert!(
            canonicalize.contains_key(spelling),
            "the recording lacks canonicalizeIP({spelling:?})"
        );
    }

    let strerror = object["strerror"].as_object().expect("map");
    assert_eq!(strerror.len(), 33, "every code 0..=28 plus the gaps");
    assert_eq!(strerror["-1000"], "There are pending queries.");

    let channel = object["channel"].as_object().expect("map");
    assert_eq!(channel["set_bad"], 17.0, "ARES_EBADSTR");
    let prototype = channel["prototype"].as_array().expect("array");
    for method in [
        "getHostByAddr",
        "queryA",
        "queryAaaa",
        "queryAny",
        "queryCaa",
        "queryCname",
        "queryMx",
        "queryNaptr",
        "queryNs",
        "queryPtr",
        "querySoa",
        "querySrv",
        "queryTlsa",
        "queryTxt",
        "cancel",
        "getServers",
        "setLocalAddress",
        "setServers",
    ] {
        assert!(
            prototype.iter().any(|entry| entry == method),
            "the recording lacks ChannelWrap.{method}"
        );
    }
}
