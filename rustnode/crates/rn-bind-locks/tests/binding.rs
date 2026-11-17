//! End-to-end checks that drive `locks` through the CLI.
//!
//! Node's own `test/parallel/test-web-locks*.js` are the specification and they
//! are run separately; what is here pins the properties this crate had to decide
//! for itself — the namespace surface the oracle reports, and the behaviours the
//! C++ gets from sharing one isolate that rustnode has to build explicitly
//! because a worker is a second one.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn rustnode() -> PathBuf {
    // Most crates in this tree hardcode `target/<profile>`, which breaks when
    // `CARGO_TARGET_DIR` is set — the AGENTS note calls that out as a trap
    // because the binary runs from a path the build never wrote. Honouring the
    // variable keeps this test honest in a worktree that redirects the target.
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if let Some(target) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(target).join(profile).join("rustnode");
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(profile);
    path.push("rustnode");
    path
}

fn run(script: &str) -> String {
    // `--expose-internals` comes *before* `-e`: the CLI fix in #187 made flags
    // after `-e` behave as Node does, and relying on any particular ordering of
    // trailing flags is exactly what that commit changed.
    let output = Command::new(rustnode())
        .arg("--expose-internals")
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be built first");
    assert!(
        output.status.success(),
        "script failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Runs a script with a wall-clock limit, failing rather than hanging.
fn run_with_timeout(script: &str, limit: Duration) -> String {
    let mut child = Command::new(rustnode())
        .arg("-e")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the rustnode binary must be built first");
    let deadline = std::time::Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .expect("the child must be readable");
                assert!(
                    status.success(),
                    "script failed:\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the script did not finish within {limit:?}");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => panic!("waiting for the child failed: {error}"),
        }
    }
}

const PRELUDE: &str = "const realm = require('internal/bootstrap/realm');\
const locks = realm.internalBinding('locks');";

#[test]
fn the_namespace_has_the_members_and_attributes_the_oracle_reports() {
    // Measured on the pinned oracle: both methods are plain writable properties
    // with length 0 and their own name, and the three constants are
    // non-writable, non-configurable data properties.
    let output = run(&format!(
        "{PRELUDE}
        console.log(Object.getOwnPropertyNames(locks).sort().join(','));
        console.log(locks.request.length, locks.request.name);
        console.log(locks.query.length, locks.query.name);
        const describe = (name) => {{
          const d = Object.getOwnPropertyDescriptor(locks, name);
          return [d.value, d.writable, d.enumerable, d.configurable].join('|');
        }};
        for (const name of ['LOCK_MODE_SHARED', 'LOCK_MODE_EXCLUSIVE', 'LOCK_STOLEN_ERROR']) {{
          console.log(describe(name));
        }}
        try {{ new locks.request(); }} catch (e) {{ console.log(e.constructor.name); }}"
    ));
    assert_eq!(
        output,
        "LOCK_MODE_EXCLUSIVE,LOCK_MODE_SHARED,LOCK_STOLEN_ERROR,query,request\n\
         0 request\n\
         0 query\n\
         shared|false|true|false\n\
         exclusive|false|true|false\n\
         LOCK_STOLEN|false|true|false\n\
         TypeError"
    );
}

#[test]
fn navigator_locks_loads_without_taking_a_lock() {
    // The defect this crate fixes: `lib/internal/navigator.js` and
    // `lib/worker_threads.js` both require `internal/locks` unconditionally, so
    // loading the namespace threw for files that never took a lock.
    let output = run("console.log(typeof navigator.locks);\n\
         console.log(typeof require('node:worker_threads').locks);");
    assert_eq!(output, "object\nobject");
}

#[test]
fn a_shared_lock_admits_every_holder_and_an_exclusive_one_admits_none() {
    let output = run("(async () => {\n\
           let concurrent = 0, peak = 0;\n\
           const shared = () => navigator.locks.request('r', { mode: 'shared' }, async () => {\n\
             concurrent += 1; peak = Math.max(peak, concurrent);\n\
             await new Promise((done) => setTimeout(done, 20));\n\
             concurrent -= 1;\n\
           });\n\
           await Promise.all([shared(), shared(), shared()]);\n\
           console.log('shared peak', peak);\n\
           const order = [];\n\
           const exclusive = navigator.locks.request('r', async () => {\n\
             order.push('exclusive');\n\
             await new Promise((done) => setTimeout(done, 20));\n\
           });\n\
           const behind = navigator.locks.request('r', { mode: 'shared' }, () => {\n\
             order.push('shared');\n\
           });\n\
           await Promise.all([exclusive, behind]);\n\
           console.log('order', order.join(','));\n\
         })();");
    assert_eq!(output, "shared peak 3\norder exclusive,shared");
}

#[test]
fn requests_are_granted_in_queue_order() {
    let output = run("(async () => {\n\
           const order = [];\n\
           const first = navigator.locks.request('q', async () => {\n\
             order.push('a');\n\
             await new Promise((done) => setTimeout(done, 20));\n\
           });\n\
           const second = navigator.locks.request('q', () => order.push('b'));\n\
           const third = navigator.locks.request('q', () => order.push('c'));\n\
           await Promise.all([first, second, third]);\n\
           console.log(order.join(','));\n\
         })();");
    assert_eq!(output, "a,b,c");
}

#[test]
fn if_available_reports_a_miss_rather_than_waiting() {
    let output = run(
        "(async () => {\n\
           await navigator.locks.request('r', async () => {\n\
             const miss = await navigator.locks.request('r', { ifAvailable: true }, (lock) => lock);\n\
             const free = await navigator.locks.request('other', { ifAvailable: true },\n\
               (lock) => lock !== null);\n\
             console.log('miss', miss, 'free', free);\n\
           });\n\
         })();",
    );
    assert_eq!(output, "miss null free true");
}

#[test]
fn steal_takes_the_lock_and_the_previous_holder_sees_an_abort() {
    let output = run("(async () => {\n\
           let rejection = null;\n\
           const victim = navigator.locks.request('r', async () => {\n\
             await new Promise((done) => setTimeout(done, 50));\n\
             return 'victim-finished';\n\
           }).catch((error) => {\n\
             rejection = error.name + ': ' + error.message;\n\
             return 'victim-rejected';\n\
           });\n\
           const thief = navigator.locks.request('r', { steal: true },\n\
             async (lock) => 'stole ' + lock.name);\n\
           console.log(await thief);\n\
           console.log(await victim);\n\
           console.log(rejection);\n\
         })();");
    assert_eq!(
        output,
        "stole r\nvictim-rejected\nAbortError: The operation was aborted"
    );
}

#[test]
fn query_snapshots_held_and_pending_for_this_environment() {
    let output = run("(async () => {\n\
           await navigator.locks.request('held-name', { mode: 'shared' }, async () => {\n\
             const inner = navigator.locks.request('held-name', async () => {});\n\
             const snapshot = await navigator.locks.query();\n\
             console.log(Object.keys(snapshot).join(','));\n\
             console.log(snapshot.held.map((lock) => lock.name + '/' + lock.mode).join(','));\n\
             console.log(snapshot.pending.map((lock) => lock.name + '/' + lock.mode).join(','));\n\
             console.log(JSON.stringify(Object.keys(snapshot.held[0])));\n\
             await inner;\n\
           });\n\
         })();");
    assert_eq!(
        output,
        "held,pending\n\
         held-name/shared\n\
         held-name/exclusive\n\
         [\"name\",\"mode\",\"clientId\"]"
    );
}

#[test]
fn a_worker_blocks_until_the_parent_releases_and_is_then_woken() {
    // This is the cross-environment wake: a request queued in the worker's
    // environment has to make progress when the parent's environment releases,
    // and the grant has to run on the *worker's* thread because its promises
    // belong to that isolate.
    //
    // The worker holds a `parentPort` listener for its whole life on purpose. A
    // pending lock request alone does **not** keep an environment alive in either
    // runtime — measured on the oracle and here, both exit with code 0 leaving the
    // request unanswered — which is the same caveat Node's own
    // `test-web-locks-no-livelock.js` records in a comment.
    let output = run_with_timeout(
        "const { Worker } = require('node:worker_threads');\n\
         (async () => {\n\
           let release;\n\
           const held = new Promise((done) => { release = done; });\n\
           const parent = navigator.locks.request('cross', async () => { await held; });\n\
           const worker = new Worker(`const { parentPort } = require('worker_threads');\n\
             parentPort.on('message', () => {});\n\
             parentPort.postMessage('queued');\n\
             navigator.locks.request('cross', async (lock) => {\n\
               parentPort.postMessage(lock.name + ':' + lock.mode);\n\
             });`, { eval: true });\n\
           console.log(await new Promise((done) => worker.once('message', done)));\n\
           release();\n\
           await parent;\n\
           console.log(await new Promise((done) => worker.once('message', done)));\n\
           await worker.terminate();\n\
         })();",
        Duration::from_secs(30),
    );
    assert_eq!(output, "queued\ncross:exclusive");
}

#[test]
fn a_terminated_worker_leaves_no_lock_behind() {
    // `LockManager::OnEnvironmentCleanup`. Without it the dead worker's queued
    // request stayed in the process-wide queue, and this request never resolved:
    // measured as a 2000 ms timeout before the cleanup hook existed, and 0 ms
    // after. The oracle resolves it in 1 ms.
    let output = run_with_timeout(
        "const { Worker } = require('node:worker_threads');\n\
         (async () => {\n\
           await navigator.locks.request('gone', async () => {\n\
             const worker = new Worker(`const { parentPort } = require('worker_threads');\n\
               parentPort.postMessage('queued');\n\
               navigator.locks.request('gone', async () => 'never');`,\n\
               { eval: true });\n\
             await new Promise((done) => worker.once('message', done));\n\
             await worker.terminate();\n\
           });\n\
           const granted = await Promise.race([\n\
             navigator.locks.request('gone', async () => 'granted'),\n\
             new Promise((done) => setTimeout(() => done('timed out'), 3000)),\n\
           ]);\n\
           console.log(granted);\n\
         })();",
        Duration::from_secs(30),
    );
    assert_eq!(output, "granted");
}

#[test]
fn an_exclusive_lock_holds_across_four_worker_environments() {
    // The manager is process-wide, so an exclusive lock taken in one worker has
    // to exclude every other one. Uses a `SharedArrayBuffer` because a message
    // round trip would be too slow to catch an overlap.
    let output = run_with_timeout(
        "const { Worker } = require('node:worker_threads');\n\
         const shared = new SharedArrayBuffer(8);\n\
         const view = new Int32Array(shared);\n\
         const source = `const { workerData } = require('worker_threads');\n\
           const v = new Int32Array(workerData);\n\
           const keep = setInterval(() => {}, 1000);\n\
           (async () => {\n\
             for (let i = 0; i < 20; i++) {\n\
               await navigator.locks.request('mutex', async () => {\n\
                 const now = Atomics.add(v, 0, 1) + 1;\n\
                 let seen = Atomics.load(v, 1);\n\
                 while (now > seen) { Atomics.store(v, 1, now); seen = Atomics.load(v, 1); }\n\
                 await new Promise((done) => setTimeout(done, 1));\n\
                 Atomics.sub(v, 0, 1);\n\
               });\n\
             }\n\
             clearInterval(keep);\n\
           })();`;\n\
         (async () => {\n\
           const workers = Array.from({ length: 4 },\n\
             () => new Worker(source, { eval: true, workerData: shared }));\n\
           const peaks = await Promise.all(workers.map((worker) => new Promise((done) => {\n\
             worker.once('exit', () => done(Atomics.load(view, 1)));\n\
           })));\n\
           console.log('peak', Math.max(...peaks));\n\
         })();",
        Duration::from_secs(60),
    );
    assert_eq!(output, "peak 1");
}
