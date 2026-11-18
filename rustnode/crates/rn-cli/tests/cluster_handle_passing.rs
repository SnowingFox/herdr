//! A handle sent over an IPC channel arrives, which is what `cluster` runs on.
//!
//! # What was missing
//!
//! Node's `StreamBase::WriteBuffer` and `StreamBase::WriteString` take a third
//! argument — the descriptor to send — and, when the stream is an IPC pipe, pass
//! it to `uv_write2`. The receiving end of `LibuvStreamWrap::OnUvRead` calls
//! `uv_pipe_pending_count`/`uv_pipe_pending_type`/`uv_accept` and publishes the
//! result on `handle.pendingHandle`, which `lib/internal/child_process.js` reads.
//!
//! rustnode had neither half: `writeBuffer` read only `(req, buffer)`,
//! `uv_write` was called unconditionally, and nothing published `pendingHandle`.
//! A `child.send(msg, socket)` therefore delivered the *message* and silently
//! replaced the handle with `undefined`, and the sender's socket stayed
//! referenced forever with nothing that would ever close it.
//!
//! That is why every `cluster` server test hung with no output: the primary
//! `uv_accept`ed a connection, tried to transfer it to a worker, and the transfer
//! became a plain message. The process had finished its work and could not exit.
//!
//! # Why these tests run the real binary
//!
//! The bug spans four crates and the whole `lib/internal/child_process.js`
//! handshake — `pipe_wrap` reading the argument, `rn_uv::handle_transfer`
//! resolving it, `uv_write2` moving the descriptor, and `rn_uv::handle`
//! publishing `pendingHandle` before `onread` runs. A binding unit test installs
//! one namespace into a bare isolate and cannot see any of that, so these run
//! `-e` scripts that fork a real child and assert on what it received.
//!
//! # The assertion that matters
//!
//! Not "the message arrived" — that worked even when broken, which is what made
//! this hard to see. Each test asserts the child can *use* the handle: read from
//! the transferred socket, or accept on the transferred server. A handle that
//! silently became `undefined` passes the message check and fails these.

use std::process::Command;
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    success: bool,
    elapsed: Duration,
}

/// Runs the script file `script` under `binary`, killing it if it outlives
/// `limit`.
///
/// A leftover handle is the failure mode under test, so a script that finishes
/// its work and stays alive has to be reported as a failure rather than waited
/// out; that is what the limit is for.
///
/// The script is a file rather than `-e` because every one of these forks
/// itself: `child_process.fork` resolves `__filename`, which is `[eval]` under
/// `-e` and so names nothing for the child to load.
fn run_script(binary: &str, script: &std::path::Path, limit: Duration) -> Run {
    let started = Instant::now();
    let mut command = Command::new(binary);
    command
        .arg(script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_remove("NODE_DISABLE_COMPILE_CACHE");
    // Each script forks, and a forked child inherits the group. Killing only the
    // direct child would leave those children running and holding the pipes, so
    // the test would block on `wait_with_output` forever — and a hung *child* is
    // exactly what the defect under test produced, so the limit has to be able to
    // end the whole tree.
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
            kill_tree(&mut child, pid);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // A script that exited on its own may still have left a child behind, which
    // would keep the pipe open; the group is the only handle on it.
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
        elapsed: started.elapsed(),
    }
}

/// Kills the test script and everything it forked.
///
/// `kill` on the direct child is not enough: `fork()`ed workers are in the same
/// process group because the command was spawned with `process_group(0)`, and a
/// surviving worker holds the stdout/stderr pipes open, which is what would make
/// `wait_with_output` block.
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

/// Asserts `script` prints `expected` under the built runtime and exits by itself.
///
/// The exit is half the assertion: the original defect left the process alive
/// with its work done, so a script that printed the right bytes and then hung
/// would still be this bug.
fn expect_stdout(name: &str, script: &str, expected: &str) {
    let path = std::env::temp_dir().join(format!("rustnode-cluster-{name}.js"));
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
    assert_eq!(
        actual.stdout,
        expected,
        "rustnode printed something unexpected ({} ms elapsed); stderr: {:?}",
        actual.elapsed.as_millis(),
        actual.stderr
    );
}

/// A script whose child receives a *socket* and reads from it.
///
/// Before the fix the child's `handle` argument was `undefined`, so it never
/// replied, the parent's client never saw `'end'`, and the test hit its limit.
/// The base binary also prints `SentHandleNotReceivedWarning` here, because the
/// sender retransmits a descriptor that never arrives.
///
/// The client waits a moment before writing. That is not load-bearing for the
/// transfer; it keeps the test about the *handle* rather than about whether a
/// socket that already has unread bytes still delivers them after a handoff,
/// which is a separate question with its own answer.
#[test]
fn a_socket_sent_with_child_send_is_readable_by_the_child() {
    expect_stdout(
        "socket",
        r#"
const { fork } = require('child_process');
const net = require('net');

if (process.argv[2] === 'child') {
  process.on('message', (message, handle) => {
    if (!handle) {
      process.send('no handle');
      return;
    }
    handle.on('data', (chunk) => handle.end('echo:' + chunk));
  });
  process.send('ready');
} else {
  const child = fork(__filename, ['child']);
  const server = net.createServer((socket) => {
    child.send({ act: 'newconn' }, socket);
  });
  server.listen(0, '127.0.0.1', () => {
    const client = net.connect(server.address().port, '127.0.0.1');
    client.on('connect', () => setTimeout(() => client.write('ping'), 200));
    let data = '';
    client.on('data', (chunk) => { data += chunk; });
    client.on('end', () => {
      console.log(data);
      child.kill();
      server.close();
    });
  });
}
"#,
        "echo:ping",
    );
}

/// A script that sends a *listening server* and lets the child accept on it.
///
/// This is `cluster`'s `SCHED_NONE` path: the primary shares the bound listening
/// handle and the worker accepts connections from it. The child has to adopt the
/// handle with `listen(handle)`, which is the `'net.Server'` conversion in
/// `lib/internal/child_process.js`.
#[test]
fn a_listening_server_sent_with_child_send_can_accept() {
    expect_stdout(
        "server",
        r#"
const { fork } = require('child_process');
const net = require('net');

if (process.argv[2] === 'child') {
  process.on('message', (message, handle) => {
    if (!handle) {
      process.send('no handle');
      return;
    }
    const server = net.createServer((socket) => socket.end('from-child'));
    server.listen(handle, () => process.send('listening'));
  });
  process.send('ready');
} else {
  const child = fork(__filename, ['child']);
  child.on('message', (message) => {
    if (message !== 'ready') return;
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      child.send({ act: 'server' }, server);
      // Give the child time to adopt the handle before connecting, so the accept
      // is on the transferred socket rather than on the parent's.
      setTimeout(() => {
        const client = net.connect(port, '127.0.0.1');
        client.on('connect', () => client.write('hello'));
        let data = '';
        client.on('data', (chunk) => { data += chunk; });
        client.on('end', () => {
          console.log(data);
          // The parent's wrapper still holds the transferred listening handle,
          // so it has to be closed for the loop to drain; the child's copy is
          // the one that accepted.
          server.close();
          child.kill();
        });
      }, 300);
    });
  });
}
"#,
        "from-child",
    );
}

/// The default `cluster` round-robin path, end to end.
///
/// This is the shape of `test/parallel/test-cluster-disconnect.js`: two servers
/// in one worker, the primary connects to both, and then `cluster.disconnect()`
/// must let the process exit. It is included here because the JS-level test tree
/// is not part of this crate's suite, so nothing else in `cargo test` covers the
/// handoff that made every cluster test hang.
#[test]
fn cluster_round_robin_serves_and_the_process_exits() {
    expect_stdout(
        "round-robin",
        r#"
const cluster = require('cluster');
const net = require('net');

if (cluster.isWorker) {
  net.createServer((socket) => socket.end('one')).listen(0, '127.0.0.1');
  net.createServer((socket) => socket.end('two')).listen(0, '127.0.0.1');
} else if (cluster.isPrimary) {
  const ports = [];
  const worker = cluster.fork();
  worker.on('listening', (address) => {
    ports.push(address.port);
    if (ports.length < 2) return;
    const replies = [];
    for (const port of ports) {
      const socket = net.connect(port, '127.0.0.1');
      let data = '';
      socket.on('data', (chunk) => { data += chunk; });
      socket.on('end', () => {
        replies.push(data);
        if (replies.length === 2) {
          console.log(replies.sort().join(','));
          cluster.disconnect();
        }
      });
    }
  });
}
"#,
        "one,two",
    );
}
