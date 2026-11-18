//! The teardown `Bun.spawn`/`Bun.spawnSync` performs closes every handle it made.
//!
//! # The defect these pin
//!
//! `spawn::run` had two teardown paths. The ordinary one called `close_handles`,
//! which closes the `uv_process_t` and every `uv_pipe_t`. The path taken when
//! `options.timeout > 0` created a `uv_timer_t` and then closed **only the
//! timer**, returning with the process and pipe handles still linked into the
//! loop's intrusive `handle_queue` while their `Box` storage — and the
//! `SyncState` behind each handle's `data` — was freed.
//!
//! `uv_spawn`, `uv_pipe_init` and `uv_timer_init` all call `uv__handle_init`,
//! which links the handle into that queue, and only `uv_close` unlinks it. So the
//! next `uv_run` walked queue nodes in freed memory. V8 runs a concurrent
//! scavenger on background jobs, so the corruption surfaced on whichever thread
//! reused that storage first: the reported crash was
//! `v8::internal::Scavenger::ScavengePage`, which reads as a V8 race and is not
//! one. `rn-bind-spawn-sync` hit the same defect through its failed-`exec` path,
//! and its own docs name `uv__handle_init` and the process-global signal tree.
//!
//! # What each layer asserts
//!
//! The exact handle accounting is asserted in Rust, by
//! `spawn::tests::the_teardown_closes_the_process_pipes_and_timer_together`,
//! which drives the real `close_handles`/`close_spawn_timer` against real handles
//! on the real loop and reads `rn_uv::ledger`. That is the deterministic statement
//! (`created == closed` for every handle the teardown is given) and it fails on
//! every run when the teardown is reverted, with the same numbers each time.
//!
//! This file is the end-to-end half: it runs the built binary and requires that a
//! process which repeatedly spawns with a timeout — the exact sequence that used
//! to fault — still exits cleanly and reports the same results every time. It
//! cannot see the ledger (that is per-process) and it cannot depend on a crash
//! (a single spawn faults on none of its runs), so it asserts survival and
//! result stability instead: a teardown that leaves handles behind makes the
//! final `process.exit()` walk them, and that is where the reported SIGSEGV
//! appeared.
//!
//! `RUSTNODE_DEBUG_HANDLE_LEDGER` is no longer involved: the ledger is read in
//! Rust where it is available, so no debug hook has to be installed into the
//! runtime's JavaScript surface at all.

use std::path::PathBuf;
use std::process::Command;

/// The built runtime, found the way every other integration test finds it.
fn rustnode() -> PathBuf {
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

/// Runs `source` under the built runtime and returns its trimmed stdout.
///
/// A crash is reported as the failure it is rather than as a mismatch: this file
/// exists because the runtime used to die here, so a non-zero status has to fail
/// with the child's own status and stderr.
fn run(source: &str) -> String {
    let binary = rustnode();
    assert!(
        binary.is_file(),
        "{} does not exist; `cargo build -p rn-cli` builds it",
        binary.display()
    );
    let out = Command::new(&binary)
        .args(["-e", source])
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

/// Repeated timed-out spawns must all report `SIGTERM` and the process must exit
/// cleanly afterwards.
///
/// Repetition is the point. One timed-out spawn leaves one process handle and its
/// pipes on the loop; a single one of those faulted on none of 60 isolated runs,
/// which is exactly why this defect read as "only under the gate". Forty of them
/// in one process faulted on 27 of 60 runs before the fix, so the sequence is the
/// reproduction and the clean exit is the assertion.
#[test]
fn repeated_timed_out_spawns_exit_cleanly() {
    let report = run(r#"
let killed = 0;
for (let i = 0; i < 40; i++) {
  const result = Bun.spawnSync(['sleep', '5'], { timeout: 5 });
  if (String(result.signalCode) === 'SIGTERM') killed++;
  // Churn so storage the spawn freed is reused, which is what makes a dangling
  // queue node fault instead of merely existing.
  let junk = [];
  for (let j = 0; j < 2000; j++) junk.push({ j, s: 'y'.repeat(40) });
  junk.length = 0;
}
// An armed timer makes the loop walk every handle it still holds.
setTimeout(() => {}, 5);
process.stdout.write(JSON.stringify({ killed }));
"#);
    let parsed: serde_json::Value =
        serde_json::from_str(&report).unwrap_or_else(|error| panic!("{error}: {report}"));
    assert_eq!(
        parsed["killed"], 40,
        "every spawn's timeout must have fired SIGTERM, or this case measured \
         something other than the timed-out path: {report}"
    );
}

/// The ordinary and failed-`exec` paths must also leave the process healthy.
///
/// `uv_spawn` calls `uv__handle_init` before it tries `exec()`, so a missing
/// *path* still leaves a registered handle. This is the case #212 was about, kept
/// beside the timer case because both are "the handle exists but there is no
/// child" paths.
///
/// The program is `/nonexistent/dir/xyz` rather than a bare
/// `nonexistent-xyz-abc` on purpose: a bare name is rejected against `PATH`
/// before `uv_spawn` is reached, so it would exercise neither the handle nor the
/// teardown while still passing.
#[test]
fn the_ordinary_and_failed_paths_stay_healthy() {
    let report = run(r#"
let completed = null;
let failed = 'no throw';
let third = null;
for (let i = 0; i < 20; i++) {
  completed = Bun.spawnSync(['true']).exitCode;
  try { Bun.spawnSync(['/nonexistent/dir/xyz']); } catch (error) { failed = error.code; }
  third = Bun.spawnSync(['echo', 'hi']).stdout.toString().trim();
}
process.stdout.write(JSON.stringify({ completed, failed, third }));
"#);
    let parsed: serde_json::Value =
        serde_json::from_str(&report).unwrap_or_else(|error| panic!("{error}: {report}"));
    assert_eq!(
        parsed["completed"], 0,
        "the child must have exited normally: {report}"
    );
    assert_eq!(
        parsed["failed"], "ENOENT",
        "the missing path must fail the way it is specified to: {report}"
    );
    assert_eq!(
        parsed["third"], "hi",
        "a spawn after a failed one must still work: {report}"
    );
}
