//! A promise V8 settles from a *posted task* resolves promptly, not at the next
//! unrelated wake-up.
//!
//! # What was missing
//!
//! `Atomics.waitAsync` does not resolve when the notify happens. It resolves when a
//! foreground task that the notifying thread posted to the waiter's V8 platform
//! queue runs on the waiter's own thread (`futex-emulation.cc` posts it through
//! `node->async_state_->task_runner`). With V8's default platform that task is
//! queued and nothing signals the waiting thread's event loop, so the loop stays
//! blocked in `uv__io_poll` and the task runs only when some other event wakes it.
//!
//! Measured before the fix, on the assignment's own repro:
//!
//! * `postMessageToThread` into a `workerMessage` handler that throws reported
//!   `ERR_WORKER_MESSAGING_ERRORED` after **5011 ms** instead of the oracle's
//!   **13 ms** — it settled on the unrelated 5 s timer, not on the notify.
//! * The same program with only unref'd timers never settled at all.
//! * A cross-thread `Atomics.notify` woke the waiter 2053 ms late (on the next
//!   timer) where the oracle took 111 ms.
//!
//! # Why these tests run the real binary
//!
//! The defect spans the V8 platform, `rn-uv`'s wake handle and the loop's
//! checkpoint. A unit test of any one of them would pass while the composition
//! stayed broken, which is exactly what happened: `pump_foreground_tasks` already
//! existed for `vm.measureMemory`, and it works — it just never gets a turn,
//! because nothing wakes the loop to reach it.
//!
//! # What is asserted
//!
//! Latency, not just the eventual value. A test that waited for the promise
//! without a bound would have passed on the broken build too, 5 seconds later.
//!
//! The third case is the same defect with no other thread in it: an
//! `Atomics.waitAsync` **timeout** is a *delayed* platform task, so libuv never
//! saw its deadline and slept past it. A 300ms timeout next to a 1000ms interval
//! settled at 905ms — the right value at the interval's wake-up — and the fix is
//! an unref'd libuv timer at that deadline, so the paired assertion that a
//! pending timeout does not hold the process open is as load-bearing as the
//! latency one.

use std::process::Command;
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    success: bool,
    elapsed: Duration,
}

/// Runs `script` from a file under `binary`, killing it if it outlives `limit`.
///
/// A file rather than `-e` because these fork or spawn workers that re-exec the
/// same path, and `__filename` is `[eval]` under `-e`.
fn run_script(binary: &str, script: &std::path::Path, limit: Duration) -> Run {
    let started = Instant::now();
    let mut command = Command::new(binary);
    command
        .arg(script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_remove("NODE_DISABLE_COMPILE_CACHE");
    // A worker thread inherits the process group, and a surviving worker holds the
    // pipes open; the limit has to be able to end the whole tree.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("cannot spawn {binary}: {error}"));
    let pid = child.id();

    let mut killed = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => panic!("cannot poll {binary}: {error}"),
        }
        if started.elapsed() > limit {
            killed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let elapsed = started.elapsed();
    // A script that exited on its own may still have left a worker behind, and a
    // surviving worker holds the pipes open, so `wait_with_output` would block
    // forever. Killing the group *after* the exit is what releases them; doing it
    // before would discard the output this test asserts on.
    kill_tree(&mut child, pid);

    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("cannot collect {binary}'s output: {error}"));
    Run {
        stdout: String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_string(),
        stderr: String::from_utf8_lossy(&output.stderr)
            .trim_end()
            .to_string(),
        success: !killed && output.status.success(),
        elapsed,
    }
}

/// Kills the script and everything it forked or spawned.
#[cfg(unix)]
fn kill_tree(child: &mut std::process::Child, pid: u32) {
    // SAFETY: `pid` is this test's own child, and signalling its group is the
    // documented way to reap a forked tree. A failure means it is already gone.
    unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn kill_tree(child: &mut std::process::Child, _pid: u32) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Asserts `script` prints `expected` and that it took under `budget`.
///
/// The budget is the assertion. The broken build produced the same last line,
/// after five seconds, so a value-only check would not have caught it.
fn expect_stdout_within(name: &str, script: &str, expected: &str, budget: Duration) {
    let path = std::env::temp_dir().join(format!("rustnode-posted-task-{name}.js"));
    std::fs::write(&path, script)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    let actual = run_script(
        env!("CARGO_BIN_EXE_rustnode"),
        &path,
        Duration::from_secs(20),
    );
    let _ = std::fs::remove_file(&path);

    assert!(
        actual.success,
        "rustnode did not exit cleanly ({} ms elapsed); stdout: {:?}; stderr: {:?}",
        actual.elapsed.as_millis(),
        actual.stdout,
        actual.stderr
    );
    assert!(
        actual.stdout.starts_with(expected),
        "rustnode printed something unexpected ({} ms elapsed); stdout: {:?}; stderr: {:?}",
        actual.elapsed.as_millis(),
        actual.stdout,
        actual.stderr
    );
    // The script reports its own settle latency, because process lifetime is not
    // the measurement: a worker that is slow to terminate would make a correct
    // runtime look late, which is exactly how this test first misreported.
    let settled_ms: u128 = actual
        .stdout
        .rsplit_once("after ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("no settle latency in {:?}", actual.stdout));
    assert!(
        settled_ms < budget.as_millis(),
        "settled {settled_ms} ms after the notify, which is the unrelated-wakeup \
         path rather than the posted task (budget {} ms)",
        budget.as_millis()
    );
}

/// A `workerMessage` handler that throws must reject the sender's promise.
///
/// This is `test/parallel/test-worker-messaging-errors-handler.js`'s case: the
/// throw is caught by `messaging.js`, `ERR_WORKER_MESSAGING_ERRORED` is what
/// `postMessageToThread` rejects with, and the rejection is only observable once
/// the futex task runs.
#[test]
fn a_throwing_worker_message_handler_rejects_the_senders_promise() {
    expect_stdout_within(
        "messaging-errored",
        r#"
const { Worker, postMessageToThread, workerData } = require('node:worker_threads');
const started = Date.now();
if (!workerData) {
  const w = new Worker(__filename, { workerData: { c: 1 } });
  postMessageToThread(w.threadId).then(
    () => console.log('resolved'),
    (e) => {
      // The latency is part of the line, because the broken build produced the
      // same code after five seconds: it settled on an unrelated timer.
      console.log('rejected:', e.code, 'after', Date.now() - started, 'ms');
      w.terminate().then(() => process.exit(0));
    },
  );
} else {
  process.on('workerMessage', () => { throw new Error('KABOOM'); });
  setTimeout(() => {}, 10000);
}
"#,
        "rejected: ERR_WORKER_MESSAGING_ERRORED after",
        Duration::from_millis(2000),
    );
}

/// A cross-thread `Atomics.notify` settles the waiter's promise on the notify.
///
/// Without the wake the waiter stays blocked and settles when an unrelated timer
/// happens to fire, which is measurable: the loop is kept alive here by a
/// deliberately long timer so a late settle shows as a duration, not a hang.
#[test]
fn a_cross_thread_notify_settles_the_waiter_promptly() {
    expect_stdout_within(
        "atomics-notify",
        r#"
const { Worker, isMainThread, workerData } = require('node:worker_threads');
const started = Date.now();
if (isMainThread) {
  const sab = new SharedArrayBuffer(8);
  const a = new Int32Array(sab);
  const w = new Worker(__filename, { workerData: sab });
  // Longer than the notify, so a settle means the notify woke the loop and a
  // timeout means it did not.
  const r = Atomics.waitAsync(a, 0, 0, 3000);
  r.value.then((v) => {
    console.log('settled:', v, 'after', Date.now() - started, 'ms');
    w.terminate().then(() => process.exit(0));
  });
} else {
  const a = new Int32Array(workerData);
  setTimeout(() => { a[0] = 1; Atomics.notify(a, 0, 1); }, 100);
  setTimeout(() => {}, 2000);
}
"#,
        "settled: ok after",
        Duration::from_millis(1500),
    );
}

/// `Atomics.waitAsync`'s timeout settles at its own deadline, not at the next
/// unrelated wake-up.
///
/// The timeout is a V8 delayed task, so libuv never sees the deadline and sleeps
/// past it: measured before the fix, a 300ms timeout next to a 1000ms interval
/// settled at **905ms**, on the interval's wake-up. The value was right the whole
/// time, which is why only the latency shows the defect.
///
/// The budget is well below the interval and well above the timeout, so a settle
/// either belongs to the deadline or to the interval and there is no window in
/// between where a slow machine could be mistaken for a correct one.
#[test]
fn a_wait_async_timeout_settles_at_its_own_deadline() {
    expect_stdout_within(
        "atomics-timeout-deadline",
        r#"
const sab = new SharedArrayBuffer(4);
const ia = new Int32Array(sab);
const started = Date.now();
const r = Atomics.waitAsync(ia, 0, 0, 300);
r.value.then((v) => {
  console.log('settled:', v, 'after', Date.now() - started, 'ms');
});
const iv = setInterval(() => {}, 1000);
setTimeout(() => { clearInterval(iv); }, 900);
"#,
        "settled: timed-out after",
        Duration::from_millis(700),
    );
}

/// A pending `Atomics.waitAsync` timeout does not keep the process alive.
///
/// This is the other half of the deadline work, and the half a ref'd timer would
/// break: `node -e 'Atomics.waitAsync(...)'` exits immediately, and the promise
/// never settles. Arming the deadline on a ref'd libuv handle would make the
/// process wait out its longest timeout instead, which is why the handle is
/// unref'd and why this is asserted rather than assumed.
#[test]
fn a_pending_wait_async_timeout_does_not_hold_the_process_open() {
    let script = r#"
const ia = new Int32Array(new SharedArrayBuffer(4));
const r = Atomics.waitAsync(ia, 0, 0, 2000);
r.value.then(() => console.log('settled'));
console.log('done');
"#;
    let path = std::env::temp_dir().join("rustnode-posted-task-atomics-unref.js");
    std::fs::write(&path, script)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    let actual = run_script(
        env!("CARGO_BIN_EXE_rustnode"),
        &path,
        Duration::from_secs(20),
    );
    let _ = std::fs::remove_file(&path);

    assert!(
        actual.success,
        "the process did not exit with only a pending waitAsync timeout left \
         ({} ms elapsed); stdout: {:?}; stderr: {:?}",
        actual.elapsed.as_millis(),
        actual.stdout,
        actual.stderr
    );
    assert_eq!(
        actual.stdout, "done",
        "a pending waitAsync timeout settled without anything keeping the loop alive"
    );
    assert!(
        actual.elapsed < Duration::from_secs(2),
        "the pending timeout held the process open for {} ms",
        actual.elapsed.as_millis()
    );
}
