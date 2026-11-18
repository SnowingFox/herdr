//! `Bun.nanoseconds` compared against Bun 1.4.4, and against Node.
//!
//! Two questions, and they are separate:
//!
//! * **Does the member exist and behave like Bun's?** The differential half runs
//!   one script under both runtimes and compares the invariants that can be
//!   compared. The value itself cannot: two processes start at different times, so
//!   `Bun.nanoseconds()` is never equal across them. What *is* comparable is the
//!   shape — a non-negative safe integer, monotonic within a process, `name` and
//!   `length`, and `new` throwing.
//! * **Does installing it break Node?** The second half runs under the pinned Node
//!   oracle and requires `globalThis.Bun` to be absent there, because `Bun` is a
//!   rustnode addition and an enumerable global is what would break
//!   `common/index.js`'s globals audit.
//!
//! The Bun binary comes from `RUSTNODE_BUN_ORACLE` (default
//! `/tmp/bun-dl/bun-linux-x64/bun`). When it is absent the differential half skips
//! with a printed reason rather than passing silently — this project has paid for
//! silent skips twice, so an unmeasured comparison is never reported as a pass.

use std::process::Command;

/// Where the Bun oracle lives, or the reason this test cannot compare.
fn bun_oracle() -> Option<String> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    if std::path::Path::new(&path).is_file() {
        Some(path)
    } else {
        eprintln!(
            "skipped: no Bun oracle at {path}; set RUSTNODE_BUN_ORACLE to compare. \
             This is a skip, not a pass: the member was not compared against Bun."
        );
        None
    }
}

/// Runs `script` under `binary` and returns trimmed stdout, failing on non-zero.
fn run(binary: &std::path::Path, script: &str) -> String {
    let out = Command::new(binary)
        .args(["-e", script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        out.status.success(),
        "{} failed ({}): {}",
        binary.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The built runtime, the same way every other crate's integration test finds it.
///
/// `CARGO_BIN_EXE_rustnode` is only defined for the crate that declares the
/// binary, so a dependent crate cannot use it; `tools/check.sh` builds
/// `target/debug/rustnode` before the test sweep for exactly this reason.
fn rustnode() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// The probe: everything about `Bun.nanoseconds` that two processes can agree on.
///
/// `setTimeout` rather than `await Bun.sleep`, because rustnode has no
/// `Bun.sleep` yet and the probe must run unmodified under both runtimes to be a
/// comparison at all. `setTimeout` exists in both.
const PROBE: &str = r#"
const first = Bun.nanoseconds();
const shape = {
  typeof: typeof first,
  integer: Number.isInteger(first),
  safe: Number.isSafeInteger(first),
  nonNegative: first >= 0,
  name: Bun.nanoseconds.name,
  length: Bun.nanoseconds.length,
  throwsOnNew: (() => { try { new Bun.nanoseconds(); return false; } catch { return true; } })(),
  ignoresArguments: typeof Bun.nanoseconds('ignored', 1) === 'number',
  ownKey: Object.getOwnPropertyNames(Bun).includes('nanoseconds'),
};
setTimeout(() => {
  const second = Bun.nanoseconds();
  shape.monotonic = second > first;
  // ~20 ms of timers; require the clock to have moved by a plausible amount so a
  // member returning a constant, or seconds instead of nanoseconds, fails here.
  const deltaMs = (second - first) / 1e6;
  shape.plausibleDelta = deltaMs > 5 && deltaMs < 5000;
  process.stdout.write(JSON.stringify(shape));
}, 20);
"#;

#[test]
fn nanoseconds_has_the_same_shape_as_buns() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours = run(&rustnode(), PROBE);
    let theirs = run(std::path::Path::new(&oracle), PROBE);
    assert_eq!(
        ours, theirs,
        "Bun.nanoseconds differs from Bun 1.4.4.\n  rustnode: {ours}\n  bun:      {theirs}"
    );
    // The probe is only meaningful if every field it claims to measure was set.
    // A probe that silently produced `false` for everything would compare equal
    // against itself under both runtimes, which is the "probe being wrong" trap.
    let parsed: serde_json::Value = serde_json::from_str(&ours).expect("the probe emits JSON");
    for field in [
        "integer",
        "safe",
        "nonNegative",
        "throwsOnNew",
        "ignoresArguments",
        "ownKey",
        "monotonic",
        "plausibleDelta",
    ] {
        assert_eq!(
            parsed[field], true,
            "the probe field {field} is not true on rustnode, so this comparison \
             measured nothing about it: {ours}"
        );
    }
}

/// `Bun` must not exist under Node, and must exist under rustnode.
///
/// This is the "it cannot break Node" half. `Bun` is rustnode's addition; Node has
/// no such global, and a script written for Node must not see one it did not
/// install. The pinned Node oracle is used rather than any `node` on `PATH`
/// because the question is about the Node this runtime targets.
#[test]
fn node_has_no_bun_global_and_rustnode_does() {
    let script = "process.stdout.write(String(typeof globalThis.Bun))";
    let ours = run(&rustnode(), script);
    assert_eq!(ours, "object", "rustnode must expose a Bun global");

    let Some(oracle) = rn_node_oracle::require_oracle("the Bun global is rustnode-only") else {
        return;
    };
    let theirs = run(std::path::Path::new(oracle.reference_path()), script);
    assert_eq!(
        theirs, "undefined",
        "the Node oracle has a Bun global, so this comparison is about the wrong \
         runtime or something installed it there"
    );
}

/// `Bun` is non-enumerable, and the enumerable global set is unchanged.
///
/// `common/index.js` walks `Object.keys(globalThis)` and fails a test for any name
/// it does not recognise. Installing `Bun` as an enumerable global would reintroduce
/// the defect that cost 388 files, so this pins the property rather than trusting
/// the comment in `rn-bun`.
#[test]
fn the_bun_global_is_not_an_enumerable_global() {
    let script = r#"
const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'Bun');
process.stdout.write(JSON.stringify({
  enumerable: descriptor ? descriptor.enumerable : null,
  inKeys: Object.keys(globalThis).includes('Bun'),
  inOwnNames: Object.getOwnPropertyNames(globalThis).includes('Bun'),
  enumerableCount: Object.keys(globalThis).length,
}));
"#;
    let out = run(&rustnode(), script);
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("the probe emits JSON");
    assert_eq!(
        parsed["enumerable"],
        serde_json::Value::Bool(false),
        "Bun must be non-enumerable: {out}"
    );
    assert_eq!(
        parsed["inKeys"],
        serde_json::Value::Bool(false),
        "Bun must not appear in Object.keys(globalThis): {out}"
    );
    assert_eq!(
        parsed["inOwnNames"],
        serde_json::Value::Bool(true),
        "Bun must still be an own property, discoverable by name: {out}"
    );
    assert_eq!(
        parsed["enumerableCount"],
        serde_json::json!(13),
        "the enumerable global count is a ratchet: 9 always-present globals plus \
         the four `eval_string` defines (`module`, `exports`, `__filename`, \
         `__dirname`). It was pinned at 9 while `-e` compiled a bare \
         `v8::Script` and left those four undefined, which is the bug that made \
         9 correct; the oracle reports 21 for `-e`. The count only guards \
         against a global we invent, so it moves with a fix like this one: {out}"
    );
}

/// The lazy install produces the same members as the eager one.
///
/// `Mode::Lazy` is a real code path rather than dead code, so it has to be the same
/// surface. `RUSTNODE_BUN_EAGER=0` selects it; the object identity, the members and
/// the values have to match, and only the *global's* descriptor differs.
#[test]
fn the_lazy_install_has_the_same_members() {
    let script = r#"
const bun = globalThis.Bun;
const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'Bun');
process.stdout.write(JSON.stringify({
  members: Object.getOwnPropertyNames(bun).sort(),
  sameObjectOnSecondRead: bun === globalThis.Bun,
  descriptorKind: descriptor.get ? 'accessor' : 'data',
  nanosecondsType: typeof bun.nanoseconds,
}));
"#;
    let eager = run(&rustnode(), script);

    let out = Command::new(rustnode())
        .env("RUSTNODE_BUN_EAGER", "0")
        .args(["-e", script])
        .output()
        .expect("rustnode runs");
    assert!(
        out.status.success(),
        "the lazy install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lazy = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let eager: serde_json::Value = serde_json::from_str(&eager).expect("JSON");
    let lazy: serde_json::Value = serde_json::from_str(&lazy).expect("JSON");
    assert_eq!(
        eager["members"], lazy["members"],
        "the lazy install exposes a different member set"
    );
    assert_eq!(
        lazy["sameObjectOnSecondRead"],
        serde_json::Value::Bool(true),
        "a lazy global must cache its object, or two reads would build two Bun objects"
    );
    assert_eq!(eager["descriptorKind"], "data");
    assert_eq!(lazy["descriptorKind"], "accessor");
    assert_eq!(lazy["nanosecondsType"], "function");
}
