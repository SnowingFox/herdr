//! End-to-end checks that drive `process_methods` through the CLI.
//!
//! These run the real binary rather than a bare isolate, because the point of
//! several members is that they agree with the operating system: `cwd`,
//! `hrtime`, `rss` and `uptime` are only correct if they read the same process
//! the test is running in.

use std::path::PathBuf;
use std::process::Command;

/// The debug binary, which `cargo test` has already built.
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

/// Runs a script through the CLI and returns its stdout.
///
/// `--expose-internals` is required because `internalBinding` is deliberately
/// not a global, exactly as in Node: only builtins reach it.
fn run(script: &str) -> String {
    let output = Command::new(rustnode())
        .arg("--expose-internals")
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be built first");
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

const PRELUDE: &str = "const realm = require('internal/bootstrap/realm');\
const pm = realm.internalBinding('process_methods');";

#[test]
fn cwd_matches_the_directory_the_process_runs_in() {
    let reported = run(&format!("{PRELUDE} console.log(pm.cwd());"));
    let expected = std::env::current_dir()
        .expect("a working directory")
        .to_string_lossy()
        .into_owned();
    assert_eq!(reported, expected);
}

#[test]
fn the_legacy_hrtime_buffer_holds_seconds_and_nanoseconds() {
    // Node's `hrtime()` fills a Uint32Array of three entries: the seconds split
    // into two 32-bit halves, then the nanosecond remainder. `lib/internal/
    // process/per_thread.js` reassembles exactly that, so the shape is the
    // contract.
    let output = run(&format!(
        "{PRELUDE}
        pm.hrtime();
        const [hi, lo, nanos] = [...pm.hrtimeBuffer];
        const seconds = (BigInt(hi) << 32n) + BigInt(lo);
        console.log(seconds >= 0n, nanos < 1000000000, pm.hrtimeBuffer.length);"
    ));
    assert_eq!(output, "true true 3");
}

#[test]
fn the_two_hrtime_forms_read_the_same_clock() {
    // Both write the same buffer, so the BigInt form must never report a time
    // earlier than the legacy form that ran before it.
    let output = run(&format!(
        "{PRELUDE}
        pm.hrtime();
        const [hi, lo, nanos] = [...pm.hrtimeBuffer];
        const legacy = ((BigInt(hi) << 32n) + BigInt(lo)) * 1000000000n + BigInt(nanos);
        pm.hrtimeBigInt();
        const big = new BigUint64Array(pm.hrtimeBuffer.buffer, 0, 1)[0];
        console.log(big >= legacy, big > 0n);"
    ));
    assert_eq!(output, "true true");
}

#[test]
fn uptime_is_a_small_non_negative_number_of_seconds() {
    let output = run(&format!(
        "{PRELUDE}
        const up = pm.uptime();
        console.log(typeof up === 'number', up >= 0, up < 60 * 60);"
    ));
    // The process has just started, so its own uptime is small; that is the
    // difference between `process.uptime()` and `os.uptime()`.
    assert_eq!(output, "true true true");
}

#[test]
fn rss_reports_real_resident_memory() {
    let output = run(&format!(
        "{PRELUDE} console.log(pm.rss() > 0, pm.memoryUsage().rss > 0);"
    ));
    assert_eq!(output, "true true");
}

#[test]
fn cpu_usage_reports_two_counters_and_subtracts_a_previous_reading() {
    let output = run(&format!(
        "{PRELUDE}
        const first = pm.cpuUsage();
        let total = 0;
        for (let i = 0; i < 1000000; i++) total += i;
        const delta = pm.cpuUsage(first);
        console.log(typeof first.user, typeof first.system,
                    delta.user >= 0, delta.system >= 0);"
    ));
    assert_eq!(output, "number number true true");
}

#[test]
fn chdir_returns_zero_then_a_negative_errno() {
    // Node returns the negated errno rather than throwing, because
    // `lib/internal/process/per_thread.js` turns it into the exception itself.
    let output = run(&format!(
        "{PRELUDE}
        const ok = pm.chdir('/tmp');
        const bad = pm.chdir('/definitely/not/a/directory/here');
        console.log(ok, bad < 0, pm.cwd());"
    ));
    assert_eq!(output, "0 true /tmp");
}

#[test]
fn a_deferred_member_is_absent_rather_than_wrong() {
    // `dlopen` needs the addon loader. Reporting the member as present but
    // non-functional would surface much later as a missing addon, so it must be
    // genuinely absent and declared deferred in the contract.
    let output = run(&format!(
        "{PRELUDE} console.log(typeof pm.dlopen, typeof pm.execve);"
    ));
    assert_eq!(output, "undefined undefined");
}

#[test]
fn patching_the_process_object_sets_pid_and_ppid_read_only() {
    let output = run(&format!(
        "{PRELUDE}
        const fake = {{}};
        pm.patchProcessObject(fake);
        const descriptor = Object.getOwnPropertyDescriptor(fake, 'pid');
        console.log(typeof fake.pid, fake.ppid > 0, descriptor.writable);"
    ));
    // A writable `pid` would let user code lie about its own identity.
    assert_eq!(output, "number true false");
}

#[test]
fn raw_debug_writes_to_stderr_not_stdout() {
    let output = Command::new(rustnode())
        .arg("--expose-internals")
        .arg("-e")
        .arg(format!(
            "{PRELUDE} console.log('out'); pm._rawDebug('err');"
        ))
        .output()
        .expect("the rustnode binary must be built first");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "out");
    assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), "err");
}
