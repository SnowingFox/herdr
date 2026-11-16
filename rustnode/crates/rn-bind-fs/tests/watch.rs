//! `fs.watchFile` and `fs.unwatchFile`, driven through the real binary.
//!
//! The `StatWatcher` handle is the one part of the `fs` namespace that cannot be
//! tested in-process: its callback arrives from inside `uv_run` on a libuv
//! `uv_fs_poll_t`, so a bare isolate with a microtask checkpoint has no loop to
//! pump and nothing would ever fire. These tests spawn `target/{debug,release}/rustnode`
//! and run a script against the real event loop, which is the same reason
//! `js_contract.rs`'s job tests do.
//!
//! # Why every wait is a readiness wait
//!
//! A watch test that sleeps for a fixed interval and then asserts nothing
//! arrived passes for exactly the wrong reason when the watch is broken: "no
//! event yet" is indistinguishable from "no event ever". So every phase below
//! polls for the event it needs and treats its own deadline as the failure. The
//! script is the one that reports the timeout, and the test asserts on the
//! verdict line, so a regression appears as `TIMEOUT <phase>` rather than as a
//! green run.
//!
//! # The oracle
//!
//! Every expectation here was recorded from Node, and where the pinned Node
//! binary is available the same script is run through both runtimes and the
//! output compared. The oracle is *never* the `node` on `PATH`: this image's
//! `node` is v22 and disagrees with the pinned v28 nightly often enough to make
//! that comparison meaningless. [`oracle_binary`] takes the path from
//! `RUSTNODE_ORACLE_NODE`, then falls back to the pinned download, then to a
//! `PATH` `node` only if it reports the pinned major version or newer, and skips
//! the differential half when none qualifies. The recorded expectations still
//! run, so the gate proves behaviour without the external binary.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rn_bind_fs::Fs;
use rn_core::BindingModule;

/// The pinned Node nightly this repository compares against.
const PINNED_ORACLE: &str =
    "/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node";

/// The major version the pinned oracle reports.
const PINNED_MAJOR: u32 = 28;

/// `target/{debug,release}/rustnode`, the binary the gate builds first.
fn rustnode_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

/// The pinned Node binary, when this machine has one that is new enough.
///
/// The search order matches `rn-bind-encoding`'s `reference_node` — explicit
/// environment override, then the pinned download, then `PATH` — with one
/// difference that matters here: a `PATH` candidate is only accepted when its
/// major version is at least [`PINNED_MAJOR`]. This image ships v22 on `PATH`,
/// and v22's `fs.watch` reports different event types and file names than the
/// pinned v28 nightly, so comparing against it would fail a correct binding.
/// Refusing it is the honest answer: the recorded expectations below still run.
fn oracle_binary() -> Option<PathBuf> {
    let explicit = std::env::var_os("RUSTNODE_ORACLE_NODE").map(PathBuf::from);
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();
    if let Some(path) = explicit {
        // An explicitly configured oracle is trusted as given.
        candidates.push((path, true));
    }
    // The pinned path and `PATH` have to prove they are new enough.
    candidates.push((PathBuf::from(PINNED_ORACLE), false));
    candidates.push((PathBuf::from("node"), false));

    for (candidate, trusted) in candidates {
        let Ok(output) = Command::new(&candidate).arg("--version").output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        if !trusted {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let major = version
                .trim_start_matches('v')
                .split('.')
                .next()
                .and_then(|part| part.parse::<u32>().ok())
                .unwrap_or(0);
            if major < PINNED_MAJOR {
                continue;
            }
        }
        return Some(candidate);
    }
    None
}

/// A temporary directory that cleans itself up.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rn-bind-fs-watch-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("mkdir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Runs `source` (which receives `dir`) through `binary` and returns stdout.
///
/// `dir` is substituted for `@@DIR@@`, so the script can build its own file
/// names without the test having to escape a Windows-style path.
fn run_script(binary: &std::path::Path, label: &str, source: &str, dir: &TempDir) -> String {
    let script = std::env::temp_dir().join(format!(
        "rn-bind-fs-watch-{label}-{}-{:?}.js",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(
        &script,
        source.replace("@@DIR@@", &dir.path.to_string_lossy()),
    )
    .expect("write the script");

    let started = Instant::now();
    let output = Command::new(binary)
        .arg(&script)
        .output()
        .unwrap_or_else(|error| panic!("{} must be built first: {error}", binary.display()));
    let elapsed = started.elapsed();
    let _ = std::fs::remove_file(&script);

    // The deadline lives in the script, so a hang here means the runtime wedged
    // rather than that an event was late. Reporting both keeps the two apart.
    assert!(
        elapsed < Duration::from_secs(60),
        "{} did not exit within 60s (ran {elapsed:?})",
        binary.display()
    );
    assert!(
        output.status.success(),
        "{label} failed with {:?} after {elapsed:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Runs the script through both runtimes and asserts they agree.
///
/// Returns rustnode's output, so a caller can also assert on it directly. When
/// no pinned oracle is present the differential half is skipped and only the
/// caller's own assertions run.
fn same_as_oracle(label: &str, source: &str, dir: &TempDir) -> String {
    let ours = run_script(&rustnode_binary(), label, source, dir);
    if let Some(oracle) = oracle_binary() {
        let theirs = run_script(&oracle, &format!("{label}-oracle"), source, dir);
        assert_eq!(ours, theirs, "{label}: rustnode disagrees with the oracle");
    }
    ours
}

/// The shared script: one watcher, one deterministic change, then `unwatchFile`.
///
/// The write happens once, at a fixed delay, and is the only mutation before the
/// assertion. That makes `curr.size` a fixed value rather than whichever length a
/// pump loop happened to leave behind — the readiness wait belongs on the
/// *event*, and a test whose expected value depends on how many pumps ran before
/// the first poll would be comparing two unrelated numbers.
///
/// `TIMEOUT` on stdout with a non-zero exit is the failure path: if no event
/// ever arrives, `run_script` fails rather than reading an empty result as a
/// pass.
const CHANGE_THEN_UNWATCH: &str = r#"
const fs = require('fs');
const path = require('path');
const dir = '@@DIR@@';
const file = path.join(dir, 'x.txt');
fs.writeFileSync(file, 'aaaa');

const out = [];
const started = Date.now();

const watcher = fs.watchFile(file, { interval: 20 }, (curr, prev) => {
  if (out.length > 0) return;
  out.push(`sizes:${curr.size}/${prev.size}`);
  out.push(`isFile:${curr.isFile()}:${prev.isFile()}`);
  out.push(`mtimeAdvanced:${curr.mtimeMs >= prev.mtimeMs}`);
  out.push(`birthtimeReported:${prev.birthtimeMs >= 0}`);
  out.push(`handlePresent:${watcher._handle === null ? 'no' : 'yes'}`);
  fs.unwatchFile(file);
  out.push(`afterUnwatch:${watcher._handle === null ? 'null' : 'live'}`);
  // Prove the unwatch took effect rather than merely returning: keep mutating
  // and require silence for a full polling interval plus slack.
  let quiet = 0;
  const again = setInterval(() => {
    fs.writeFileSync(file, 'q'.repeat(2 + (quiet++ % 5)));
  }, 20);
  setTimeout(() => {
    clearInterval(again);
    out.push(`extraEvents:${out.extra || 0}`);
    console.log(out.join(' | '));
    process.exit(0);
  }, 400);
});

// One deterministic mutation: six bytes over the initial four.
setTimeout(() => {
  fs.writeFileSync(file, 'abcdef');
}, 60);

const watch = setInterval(() => {
  if (out.length > 0) { clearInterval(watch); return; }
  if (Date.now() - started > 8000) {
    clearInterval(watch);
    console.log('TIMEOUT first-change');
    process.exit(1);
  }
}, 10);
"#;

#[test]
fn a_change_is_delivered_with_curr_and_prev_then_unwatch_stops_it() {
    // One deterministic mutation, so `curr`/`prev` are fixed values and the two
    // halves prove they are distinct records rather than one value read twice.
    let dir = TempDir::new("change");
    let printed = same_as_oracle("change", CHANGE_THEN_UNWATCH, &dir);
    assert_eq!(
        printed.split(" | ").next(),
        Some("sizes:6/4"),
        "curr is the six bytes written, prev the four bytes created, in {printed:?}"
    );
    assert!(printed.contains("isFile:true:true"), "{printed:?}");
    assert!(printed.contains("mtimeAdvanced:true"), "{printed:?}");
    assert!(printed.contains("birthtimeReported:true"), "{printed:?}");
    assert!(printed.contains("afterUnwatch:null"), "{printed:?}");
    // A single report followed by silence is what proves `unwatchFile` closed
    // the handle rather than only removing the listener.
    assert!(printed.contains("extraEvents:0"), "{printed:?}");
}

#[test]
fn a_missing_path_is_reported_as_an_event_rather_than_thrown() {
    // `fs.watchFile('/nonexistent')` is legal in Node: `uv_fs_poll_start` does
    // not fail for a missing path, and the first poll reports the failed stat as
    // a `change` event. The test above this one asserts that path throws; this
    // one pins the difference from `fs.watch`, which *does* throw ENOENT.
    //
    // It also guards the test shape: a probe that can only wait must be able to
    // report its own timeout, which is why `run_script` turns a non-zero exit
    // into a failure rather than reading whatever stdout arrived first.
    let dir = TempDir::new("missing");
    let source = r#"
        const fs = require('fs');
        const path = require('path');
        const missing = path.join('@@DIR@@', 'never.txt');
        let threw = 'no';
        let calls = 0;
        let watcher;
        try {
          watcher = fs.watchFile(missing, { interval: 20 }, () => { calls++; });
        } catch (error) {
          threw = error.code || error.constructor.name;
        }
        setTimeout(() => {
          console.log(JSON.stringify({ threw, calls, handlePresent: !!watcher._handle }));
          fs.unwatchFile(missing);
          process.exit(0);
        }, 400);
    "#;
    let printed = run_script(&rustnode_binary(), "missing", source, &dir);
    assert_eq!(printed, r#"{"threw":"no","calls":1,"handlePresent":true}"#);
    if let Some(oracle) = oracle_binary() {
        assert_eq!(
            printed,
            run_script(&oracle, "missing-oracle", source, &dir),
            "the missing-path report disagrees with the oracle"
        );
    }
}

/// The StatWatcher shape, read without any filesystem event at all.
///
/// This is the half that fails first when the member is missing: on the tree
/// before this fix, `internalBinding('fs').StatWatcher` was `undefined` and
/// `fs.watchFile` threw `TypeError: _StatWatcher is not a constructor` at
/// `node:internal/fs/watchers:158` before any syscall.
const SHAPE: &str = r#"
const fs = require('fs');
const path = require('path');
const dir = '@@DIR@@';
const file = path.join(dir, 'shape.txt');
fs.writeFileSync(file, 'abcd');

const a = fs.watchFile(file, { interval: 20 }, () => {});
const b = fs.watchFile(file, { interval: 20 }, () => {});
const handle = a._handle;
console.log(JSON.stringify({
  sameWatcher: a === b,
  sameHandle: a._handle === b._handle,
  provider: handle.getProviderType(),
  asyncIdPositive: handle.getAsyncId() > 0,
  hasRef: handle.hasRef(),
  protoMethods: [
    'start', 'close', 'hasRef', 'ref', 'unref',
    'getAsyncId', 'asyncReset', 'getProviderType',
  ].every((name) => typeof Object.getPrototypeOf(handle)[name] === 'function'),
  ctorName: handle.constructor.name,
}));
fs.unwatchFile(file);
"#;

#[test]
fn the_stat_watcher_handle_has_the_async_wrap_shape() {
    let dir = TempDir::new("shape");
    let printed = same_as_oracle("shape", SHAPE, &dir);
    assert_eq!(
        printed,
        r#"{"sameWatcher":true,"sameHandle":true,"provider":38,"asyncIdPositive":true,"hasRef":true,"protoMethods":true,"ctorName":"StatWatcher"}"#
    );
}

/// `bigint: true`, a missing path's first report, and `stop()`'s event.
const BITS: &str = r#"
const fs = require('fs');
const path = require('path');
const dir = '@@DIR@@';
const file = path.join(dir, 'bits.txt');
const missing = path.join(dir, 'absent.txt');
fs.writeFileSync(file, 'xy');

const out = [];
const big = fs.watchFile(file, { interval: 20, bigint: true }, (curr, prev) => {
  if (out.length > 0) return;
  clearInterval(pump);
  out.push(`bigint:${typeof curr.size}/${typeof prev.size}`);
  out.push(`bigintValue:${curr.size === 2n || curr.size === 3n}`);
  fs.unwatchFile(file);
  // A missing path reports the failed stat as a change rather than throwing,
  // and `onchange`'s nlink comparison is what decides whether the listener
  // hears about it. Node delivers it once.
  let missingCalls = 0;
  fs.watchFile(missing, { interval: 20 }, () => { missingCalls++; });
  fs.watchFile(missing, () => {});
  setTimeout(() => {
    out.push(`missingCalls:${missingCalls}`);
    const other = path.join(dir, 'other.txt');
    fs.writeFileSync(other, 'z');
    const watcher = fs.watchFile(other, { interval: 20 }, () => {});
    let stops = 0;
    watcher.on('stop', () => { stops++; });
    watcher.stop();
    out.push(`stopSync:${watcher._handle === null}`);
    setTimeout(() => {
      out.push(`stops:${stops}`);
      fs.unwatchFile(missing);
      console.log(out.join(' | '));
      process.exit(0);
    }, 200);
  }, 250);
});

let ticks = 0;
const pump = setInterval(() => {
  fs.writeFileSync(file, 'b'.repeat(3 + (ticks++ % 4)));
}, 20);

const started = Date.now();
const watch = setInterval(() => {
  if (out.length > 0) { clearInterval(watch); return; }
  if (Date.now() - started > 8000) {
    clearInterval(pump);
    console.log('TIMEOUT first-change');
    process.exit(1);
  }
}, 10);
"#;

#[test]
fn bigint_mode_missing_paths_and_stop_behave_as_node_does() {
    let dir = TempDir::new("bits");
    let printed = same_as_oracle("bits", BITS, &dir);
    assert!(printed.contains("bigint:bigint/bigint"), "{printed:?}");
    assert!(printed.contains("bigintValue:true"), "{printed:?}");
    assert!(printed.contains("stopSync:true"), "{printed:?}");
    assert!(printed.contains("stops:1"), "{printed:?}");
    assert!(printed.contains("missingCalls:1"), "{printed:?}");
}

/// `persistent: false` must not hold the loop open, and the handle must be
/// visible to `async_hooks` under the `STATWATCHER` provider.
const HOOKS: &str = r#"
const fs = require('fs');
const path = require('path');
const async_hooks = require('async_hooks');
const dir = '@@DIR@@';
const file = path.join(dir, 'hooks.txt');
const keepAlive = path.join(dir, 'keep.txt');
fs.writeFileSync(file, 'aaaa');
fs.writeFileSync(keepAlive, 'b');

const seen = [];
const hook = async_hooks.createHook({
  init(id, type) { if (type === 'STATWATCHER') seen.push(`init:${id}`); },
  before(id) { if (seen.some((s) => s === `init:${id}`)) seen.push('before'); },
  after(id) { if (seen.some((s) => s === `init:${id}`)) seen.push('after'); },
});
hook.enable();

const lazy = fs.watchFile(keepAlive, { interval: 10, persistent: false }, () => {});

let changes = 0;
fs.watchFile(file, { interval: 20 }, () => { changes++; });

let ticks = 0;
const pump = setInterval(() => {
  fs.writeFileSync(file, 'a'.repeat(2 + (ticks++ % 5)));
  if (changes === 0) return;
  clearInterval(pump);
  setTimeout(() => {
    console.log(JSON.stringify({
      inits: seen.filter((s) => s.startsWith('init:')).length,
      beforeSeen: seen.includes('before'),
      afterSeen: seen.includes('after'),
      nonPersistentHoldsRef: lazy._handle.hasRef(),
    }));
    lazy.stop();
    process.exit(0);
  }, 100);
}, 20);

setTimeout(() => { console.log('TIMEOUT hooks'); process.exit(1); }, 8000);
"#;

#[test]
fn a_non_persistent_watcher_does_not_hold_the_loop_and_is_visible_to_async_hooks() {
    let dir = TempDir::new("hooks");
    let printed = same_as_oracle("hooks", HOOKS, &dir);
    // Both watchers in the script are constructed while hooks are enabled, so
    // the count is 2 and not 1. Asserting the number the oracle prints is the
    // point: a hardcoded 1 was this test's own bug, and comparing to the oracle
    // is what catches that class of mistake.
    let value: serde_json::Value = serde_json::from_str(&printed).expect("the probe's JSON");
    assert!(value["inits"].as_u64().unwrap_or(0) >= 1, "{printed:?}");
    assert_eq!(
        value["beforeSeen"],
        serde_json::Value::Bool(true),
        "{printed:?}"
    );
    assert_eq!(
        value["afterSeen"],
        serde_json::Value::Bool(true),
        "{printed:?}"
    );
    assert_eq!(
        value["nonPersistentHoldsRef"],
        serde_json::Value::Bool(false),
        "{printed:?}"
    );
}

#[test]
fn the_member_list_now_includes_the_stat_watcher() {
    // The contract check that matters for this fix: `StatWatcher` and
    // `kFsStatsFieldsNumber` are installed rather than deferred, and the
    // deferral list no longer claims a blocker that does not exist.
    assert!(Fs.members().contains(&"StatWatcher"));
    assert!(Fs.members().contains(&"kFsStatsFieldsNumber"));
    let deferred: Vec<&str> = Fs.deferred().iter().map(|(name, _)| *name).collect();
    assert!(!deferred.contains(&"StatWatcher"));
    assert!(!deferred.contains(&"kFsStatsFieldsNumber"));
}
