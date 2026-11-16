//! A worker that writes to `process.stdout` must let the process exit.
//!
//! # The defect
//!
//! `process.stdout` in a worker is not a descriptor: `is_not_main_thread.js`
//! replaces it with a `WritableWorkerStdio`, which posts each chunk to the parent
//! as a `stdioPayload` message and leaves the stream `writing` until the parent
//! answers with `stdioWantsMoreData`. That answer arrives over the worker's
//! *environment* message port, and a cross-thread post can only reach that port's
//! thread through the `uv_async_t` token the port recorded when it was attached.
//!
//! The worker's environment port is built before `install_check_phase` creates
//! that token, so the port was attached with `token: None`. The first write still
//! completed — the parent's `_read` was already scheduled by `pipeWithoutWarning`
//! — but the second one needed the parent's answer to wake the worker's loop, and
//! nothing did. Both loops then sat in `epoll_pwait` with
//! `process._getActiveHandles()` empty on each side, and the process hung:
//!
//! ```text
//! N=1   SZ=64    exit 0
//! N=10  SZ=64    hang (timeout), 5/5
//! N=200 SZ=10000 exit 0   -- so it is not buffer pressure
//! ```
//!
//! That `N` threshold is the signature: one write is answered by the `_read` the
//! pipe already scheduled, and only the second needs a cross-thread wake. It is
//! therefore a count, not a byte count.
//!
//! # Why this test is a subprocess
//!
//! A regression here is a hang rather than a wrong value, so the assertion has to
//! be "the process exited on its own inside a bound". Nothing inside one isolate
//! can observe that: each loop is idle and correct on its own, and the defect
//! lives in the handshake between them. The child is killed at the budget so a
//! regression fails this test instead of hanging `cargo test` until the whole job
//! times out with no message.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Long enough for a loaded machine, far below the 60 s harness timeout the real
/// Node test file burns when this regresses.
const KILL_BUDGET: Duration = Duration::from_secs(20);

/// The `rustnode` binary, if it has been built.
///
/// `RUSTNODE_BIN` is honoured first, which is how this test can be pointed at
/// another build. `check.sh` builds `target/debug/rustnode` before running the
/// tests, because several crates' integration tests exec it.
fn rustnode() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTNODE_BIN") {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("rustnode");
    path.exists().then_some(path)
}

/// Runs `script` as a file under rustnode, returning `(stdout, exit_ok, killed)`.
///
/// The child's stdout is a *file*, not a pipe, and the test does not read it while
/// the child runs. That is the shape the defect needs — a worker writing to
/// `process.stdout` that the parent does not drain — without adding a second,
/// unrelated way to hang: a pipe nobody reads fills at 64 KiB and then blocks
/// `write(2)` in the parent, which stalls `N=200 SZ=10000` on real Node too. With a
/// file the child always makes progress, so the only thing this test can detect is
/// the defect it is about.
fn run(name: &str, source: &str) -> Option<(String, bool, bool)> {
    let binary = rustnode()?;
    let dir = std::env::temp_dir().join(format!("rustnode-worker-stdout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp directory for the script");
    let script = dir.join(format!("{name}.js"));
    std::fs::write(&script, source).expect("the script is writable");
    let capture = dir.join(format!("{name}.out"));
    let capture_file = std::fs::File::create(&capture).expect("an output file");

    let started = Instant::now();
    let mut child = Command::new(&binary)
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(capture_file))
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("rustnode starts");

    let status = loop {
        match child.try_wait().expect("rustnode is waitable") {
            Some(status) => break Some(status),
            None if started.elapsed() >= KILL_BUDGET => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    // The worker's payload is one line of `x` per write, which can be megabytes.
    // Only the parent's `MAIN:` line is asserted on, so the tail is what is read.
    let stdout = std::fs::read(&capture)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default();
    let _ = std::fs::remove_file(&script);
    let _ = std::fs::remove_file(&capture);
    Some((
        stdout,
        status.is_some_and(|status| status.success()),
        status.is_none(),
    ))
}

/// The reproducer, with the worker count and line size supplied by the body.
///
/// `new Worker(__filename)` is kept exactly as reported: the defect is about the
/// stdio handshake, so the script has to reach it the way a real one does rather
/// than through an `eval` worker whose setup differs.
fn writer(count: u32, size: u32) -> String {
    format!(
        r#"'use strict';
const {{ Worker, isMainThread }} = require('worker_threads');
if (isMainThread) {{
  const w = new Worker(__filename);
  w.on('exit', (code) => console.log('MAIN: worker exit ' + code));
}} else {{
  const line = 'x'.repeat({size});
  for (let i = 0; i < {count}; ++i) process.stdout.write(line + '\n');
}}
"#
    )
}

#[test]
fn a_worker_stdout_write_lets_the_process_exit() {
    // Two writes is the smallest count that reaches the missing wake; ten is the
    // shape the reported reproducer uses.
    for (label, count, size) in [("two-writes", 2u32, 64u32), ("ten-writes", 10, 64)] {
        let source = writer(count, size);
        let Some((stdout, ok, killed)) = run(label, &source) else {
            eprintln!("skipping: target/debug/rustnode is not built");
            return;
        };
        assert!(
            !killed,
            "a worker writing {count} chunks of {size} bytes left the process running \
             past {KILL_BUDGET:?}; the parent's stdioWantsMoreData answer never woke \
             the worker's loop, so its stdout stream stayed `writing`. stdout was \
             {stdout:?}"
        );
        assert!(
            ok,
            "a worker writing {count} chunks of {size} bytes exited non-zero. stdout \
             was {stdout:?}"
        );
        assert!(
            stdout.contains("MAIN: worker exit 0"),
            "the worker never reported a clean exit; stdout was {stdout:?}"
        );
    }
}

/// The single-write case, which passed before the fix and must keep passing.
///
/// Kept separate because its value is different: it is the control that says the
/// handshake works at all. A regression that broke *every* write would otherwise
/// be indistinguishable from a broken `pipeWithoutWarning`, and the smaller count
/// is what localises it.
#[test]
fn a_single_worker_stdout_write_still_exits() {
    let source = writer(1, 64);
    let Some((stdout, ok, killed)) = run("one-write", &source) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(
        !killed,
        "a single worker stdout write hung the process; stdout was {stdout:?}"
    );
    assert!(ok, "a single worker stdout write exited non-zero");
    assert!(
        stdout.contains("MAIN: worker exit 0"),
        "the worker never reported a clean exit; stdout was {stdout:?}"
    );
}

/// A larger volume, which is the case the reporter found already passing.
///
/// It is here because it names the boundary the diagnosis rests on: if this ever
/// starts failing while the small counts pass, the defect is buffer pressure and
/// not the missing wake, and the two need different fixes.
#[test]
fn a_large_worker_stdout_volume_still_exits() {
    let source = writer(200, 10000);
    let Some((_stdout, ok, killed)) = run("large", &source) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert!(!killed, "a large worker stdout volume hung the process");
    assert!(ok, "a large worker stdout volume exited non-zero");
}
