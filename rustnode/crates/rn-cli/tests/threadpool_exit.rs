//! `process.exit()` must not leave a libuv pool thread running into teardown.
//!
//! # What goes wrong without the drain
//!
//! The C runtime runs `atexit` handlers before `.fini_array` destructors.
//! OpenSSL registers `OPENSSL_cleanup` with `atexit` (`crypto/init.c`), and that
//! handler frees `err_string_lock` (`crypto/err/err.c::err_cleanup`). libuv joins
//! its pool threads from a destructor, so without an explicit drain the join is
//! too late: a worker still inside `EVP_PKEY_keygen` makes an OpenSSL call,
//! lazily initialises the error strings, and unlocks a lock that was freed
//! underneath it. The process dies with SIGSEGV on a `libuv-worker` thread.
//!
//! That is what `process.exit()` did whenever RSA key generation was still in
//! flight, and it is why this test exists: the crash is a race inside the exit
//! sequence, so a single run proves nothing.
//!
//! # Why the iteration count is what it is
//!
//! The bug is a window, not a certainty. Measured on the debug build before the
//! drain existed, an RSA-3072 keygen followed immediately by `process.exit(0)`
//! crashed in 15 of 40 runs, and the rate moved with machine load — 8/10 under
//! load, 4/20 idle. The same script on the fixed build was clean in 40 of 40.
//! Twenty iterations is the acceptance threshold that was measured to fail before
//! the fix and pass after it; it is a regression test, not a proof of absence, and
//! the note is here so the number is not mistaken for a guarantee.
//!
//! # Why it also checks the cost
//!
//! The obvious wrong fix is to wait for the whole threadpool queue, which would
//! turn `process.exit()` from prompt into "however long the backlog takes". Node
//! does not do that: `uv_library_shutdown` posts the pool's exit message, so each
//! worker finishes the item it holds and leaves, and queued requests are dropped.
//! The second test pins that shape — a deep queue must exit in roughly the time
//! of one job, not of all of them — so a future change that waits cannot pass.

use std::process::Command;
use std::time::{Duration, Instant};

/// Builds a script that starts an RSA keygen and exits without waiting for it.
fn keygen_then_exit(bits: u32) -> String {
    format!(
        "const {{ generateKeyPair }} = require('crypto');\n\
         generateKeyPair('rsa', {{ modulusLength: {bits} }}, () => {{}});\n\
         process.exit(0);"
    )
}

/// Runs `script` under the binary under test and reports its exit code.
fn run(script: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(script)
        .output()
        .expect("rustnode runs")
}

/// Twenty immediate exits with a keygen in flight must all exit 0.
///
/// A signal death shows up as no exit code at all, which is asserted separately
/// from the code so a SIGSEGV cannot be mistaken for a non-zero status.
#[test]
fn exiting_with_a_keygen_in_flight_never_dies_on_a_signal() {
    let script = keygen_then_exit(3072);
    let mut failures = Vec::new();
    for iteration in 0..20 {
        let output = run(&script);
        match output.status.code() {
            Some(0) => {}
            Some(code) => failures.push(format!("iteration {iteration}: exit {code}")),
            None => failures.push(format!(
                "iteration {iteration}: terminated by a signal ({})",
                output.status
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "every immediate exit must be clean; failures: {failures:#?}"
    );
}

/// A deep queue must be cancelled, not run, and must not crash.
///
/// `process.exit()` cancels what is queued and joins only the work already
/// running. Two things are asserted, because a deep queue failed both ways before
/// the drain: the process must exit 0 (a signal death here is the same use-after-
/// teardown crash, reached through many jobs instead of one), and it must not
/// wait for the backlog. The time bound is deliberately loose — this is a debug
/// build on a shared machine — but it still separates "one job" from "64 jobs",
/// which is the distinction that decides whether the fix drains or waits.
///
/// Measured on the tree before the drain existed, this exact shape died on a
/// signal in 5 of 6 runs at depth 64 and hung past 60 s in 2 of 6 at depth 256.
#[test]
fn a_deep_threadpool_queue_is_cancelled_rather_than_run() {
    let script = "const { generateKeyPair } = require('crypto');\n\
                  for (let i = 0; i < 64; i++)\n\
                    generateKeyPair('rsa', { modulusLength: 4096 }, () => {});\n\
                  process.exit(0);";
    let start = Instant::now();
    let output = run(script);
    let elapsed = start.elapsed();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Sixty-four queued RSA-4096 keygens are minutes of work. Cancelling leaves
    // one in flight, which is seconds even when it has to be joined.
    assert!(
        elapsed < Duration::from_secs(60),
        "exit took {elapsed:?}; the queue was drained rather than cancelled"
    );
}
