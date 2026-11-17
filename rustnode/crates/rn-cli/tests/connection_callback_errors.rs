//! A throw from a server's connection handler must be a fatal uncaught error.
//!
//! # Why this file exists
//!
//! `rn-uv`'s `on_connection` (the `uv_listen` callback behind `TCPWrap::Bind` /
//! `Listen`) and `rn-bind-pipe-wrap`'s counterpart used to call
//! `handle.onconnection` with a bare `let _ = callback.call(..)` inside
//! `callback::with_context`. That scope installs no `TryCatch`, so a throw from
//! `lib/net.js`'s `onconnection` — which runs the application's `'connection'`
//! listener — stayed pending until V8's default reporter saw it at teardown.
//!
//! The observable damage is a fatal error reported as a success:
//!
//! * the message reached **stdout** (`node:internal/tls/wrap:28443: Uncaught
//!   Error: …`), where Node puts uncaught errors on stderr;
//! * the process exited **0**, where an uncaught error must exit 1;
//! * the connection had already been accepted, so a TLS server with an
//!   `'OCSPRequest'` listener completed its handshake while the setup that
//!   listener exists for never ran.
//!
//! Node runs an accepted socket's handler inside the same
//! `InternalCallbackScope` a read uses, so this is the one seam where the two
//! paths must agree. `deliver_connection` is that scope.
//!
//! # Why the assertions are shaped the way they are
//!
//! Exit status alone is not enough here: the defect this file pins exited 1 in
//! some shapes and 0 in others depending on what else the script did, and a
//! test that only checked `rc` would pass against the broken tree whenever
//! nothing else went wrong. Each case therefore asserts all three facts — the
//! process is fatal, stderr carries the error, stdout does not.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
}

/// Runs `script` under `binary`, killing it if it outlives `limit`.
fn run(binary: &str, script: &str, limit: Duration) -> Run {
    let started = Instant::now();
    let mut child = Command::new(binary)
        .arg("-e")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot spawn {binary}: {error}"));

    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => panic!("cannot poll {binary}: {error}"),
        }
        if started.elapsed() > limit {
            timed_out = true;
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(5));
    };

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
        exit_code: status.and_then(|status| status.code()),
        timed_out,
    }
}

/// Runs `script` under rustnode and asserts the three facts above.
fn assert_fatal_uncaught(binary: &str, script: &str, marker: &str) {
    let actual = run(binary, script, Duration::from_secs(20));
    assert!(
        !actual.timed_out,
        "rustnode hung on {script}\nstdout: {}\nstderr: {}",
        actual.stdout, actual.stderr,
    );
    assert_eq!(
        actual.exit_code,
        Some(1),
        "an uncaught error must exit 1, not {:?}\nstdout: {}\nstderr: {}",
        actual.exit_code,
        actual.stdout,
        actual.stderr,
    );
    assert!(
        actual.stderr.contains(marker),
        "the error must reach stderr; it did not.\nstdout: {}\nstderr: {}",
        actual.stdout,
        actual.stderr,
    );
    assert!(
        !actual.stdout.contains("Uncaught"),
        "an uncaught error must not be printed on stdout.\nstdout: {}",
        actual.stdout,
    );
}

/// A `net.Server` whose `'connection'` listener throws.
///
/// This is the plain-`net` shape of the defect, with no TLS involved: the throw
/// happens inside `lib/net.js`'s `onconnection`, which is the function
/// `uv_listen`'s callback calls.
#[test]
fn a_throwing_connection_listener_is_a_fatal_uncaught_error() {
    let script = "\
        const net = require('net');\n\
        const server = net.createServer(() => { throw new Error('handler boom'); });\n\
        server.on('error', () => {});\n\
        server.listen(0, '127.0.0.1', () => {\n\
          require('net').connect(server.address().port, '127.0.0.1')\n\
            .on('error', () => {});\n\
        });\n";
    assert_fatal_uncaught(env!("CARGO_BIN_EXE_rustnode"), script, "handler boom");
}

/// A server that accepts and closes normally still works, so the scope wrapper
/// did not break the common path.
#[test]
fn a_well_behaved_connection_listener_still_runs() {
    let script = "\
        const net = require('net');\n\
        const server = net.createServer((socket) => {\n\
          socket.end('hello');\n\
        });\n\
        server.listen(0, '127.0.0.1', () => {\n\
          const client = net.connect(server.address().port, '127.0.0.1');\n\
          let data = '';\n\
          client.on('data', (chunk) => { data += chunk; });\n\
          client.on('end', () => { console.log(data); server.close(); });\n\
        });\n";
    let actual = run(
        env!("CARGO_BIN_EXE_rustnode"),
        script,
        Duration::from_secs(20),
    );
    assert!(
        !actual.timed_out,
        "rustnode hung\nstdout: {}\nstderr: {}",
        actual.stdout, actual.stderr,
    );
    assert_eq!(actual.exit_code, Some(0), "stderr: {}", actual.stderr);
    assert_eq!(actual.stdout, "hello");
}
