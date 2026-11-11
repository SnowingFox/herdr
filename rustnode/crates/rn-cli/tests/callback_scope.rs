//! What a native stream callback must do before it runs JavaScript.
//!
//! # Why this file exists
//!
//! `src/stream_base.cc` calls into JavaScript from exactly two places, and both
//! go through `AsyncWrap::MakeCallback`:
//!
//! * `StreamBase::CallJSOnreadMethod` (`src/stream_base.cc:514`) — `onread`.
//! * `ReportWritesToJSStreamListener::OnStreamAfterReqFinished`
//!   (`src/stream_base.cc:860`) — `oncomplete`.
//!
//! `MakeCallback` is not a bare `Function::Call`. It builds an
//! `InternalCallbackScope` (`src/api/callback.cc:70`), which does five things
//! this runtime depends on:
//!
//! 1. `push_async_context(async_id, trigger_async_id, resource)` before the
//!    call and `pop_async_context` after, so `executionAsyncId()` inside the
//!    callback is the resource's.
//! 2. `AsyncWrap::EmitBefore`/`EmitAfter`, so `async_hooks` `before`/`after`
//!    fire for the resource.
//! 3. `async_context_frame::exchange(env, context_frame)` — the frame the
//!    resource captured in its constructor. This is what `AsyncLocalStorage`
//!    reads: `getStore()` consults the continuation-preserved embedder data,
//!    so a callback that does not restore its frame sees whatever the *last*
//!    frame in the process happened to leave behind.
//! 4. A `v8::TryCatch`, with a caught exception handed to
//!    `TriggerUncaughtException` so `process.on('uncaughtException')` runs.
//! 5. The tick and microtask queues drained on exit.
//!
//! rustnode's read and write dispatch did none of these, and the two symptoms
//! are one line apart in the same seam:
//!
//! * `AsyncLocalStorage` state is `undefined` in every socket callback. A test
//!   that asserts on it throws, the throw is swallowed, and the test never
//!   reaches its `server.close()` — which is a 30s timeout, not an assertion
//!   failure.
//! * A throw from `onread`/`oncomplete` never reaches
//!   `process.on('uncaughtException')`, so a handler that closes the server
//!   never runs and the process sits in the loop forever.
//!
//! # Why the assertions are shaped the way they are
//!
//! Every case is compared against real `node`, because the expectation is a
//! statement about Node's semantics rather than about this runtime. A run that
//! hangs is the failure mode being fixed, so each case carries a wall-clock
//! limit and reports a timeout as its own kind of failure instead of turning
//! into a harness timeout nobody can attribute.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed: Duration,
}

impl Run {
    /// Whether the process exited on its own with status 0.
    fn clean(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
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
        elapsed: started.elapsed(),
    }
}

/// Asserts `script` prints `expected` and exits 0 under both runtimes.
///
/// `node` runs first: if the reference disagrees, the expectation written here
/// is wrong, and saying so is more useful than blaming rustnode.
fn same_output_as_node(script: &str, expected: &str) {
    let reference = run("node", script, Duration::from_secs(20));
    assert!(
        reference.clean(),
        "`node` did not exit cleanly on {script}\nstdout: {}\nstderr: {}",
        reference.stdout,
        reference.stderr,
    );
    assert_eq!(
        reference.stdout, expected,
        "`node` printed something unexpected; the expectation in this test is wrong"
    );

    let actual = run(
        env!("CARGO_BIN_EXE_rustnode"),
        script,
        Duration::from_secs(20),
    );
    assert!(
        !actual.timed_out,
        "rustnode hung for {}ms on {script}\nstdout: {}\nstderr: {}",
        actual.elapsed.as_millis(),
        actual.stdout,
        actual.stderr,
    );
    assert!(
        actual.clean(),
        "rustnode exited with {:?} on {script}\nstdout: {}\nstderr: {}",
        actual.exit_code,
        actual.stdout,
        actual.stderr,
    );
    assert_eq!(
        actual.stdout, expected,
        "script was: {script}\nstderr: {}",
        actual.stderr
    );
}

/// A client whose `'data'` handler asserts on the ambient ALS store.
///
/// This is the shape `test-async-local-storage-http-agent.js` and
/// `-multiclients.js` use, minus the HTTP framing: a store created in `run()`
/// has to still be the current store when the response arrives. The second
/// request is the interesting one, because it reuses the pooled socket and so
/// arrives on a *fresh* read callback.
const ALS_SOCKET_SCRIPT: &str = "\
const net = require('net');\n\
const { AsyncLocalStorage } = require('async_hooks');\n\
const cls = new AsyncLocalStorage();\n\
const server = net.createServer((socket) => { socket.on('data', () => socket.end('bye')); });\n\
server.listen(0, () => {\n\
  cls.run('request-store', () => {\n\
    console.log('in run: ' + cls.getStore());\n\
    const client = net.connect(server.address().port, () => client.write('hi'));\n\
    client.on('data', () => {\n\
      console.log('in read: ' + cls.getStore());\n\
      client.end();\n\
    });\n\
    client.on('close', () => server.close());\n\
  });\n\
});";

#[test]
fn async_local_storage_survives_a_socket_read_callback() {
    // `AsyncWrap`'s constructor captures `async_context_frame::current()`, and
    // `InternalCallbackScope` restores it around the callback. Without the
    // capture the read callback runs with whatever frame the process last set,
    // which outside any `run()` is `undefined`.
    same_output_as_node(
        ALS_SOCKET_SCRIPT,
        "in run: request-store\nin read: request-store",
    );
}

#[test]
fn async_local_storage_survives_two_requests_on_one_keep_alive_socket() {
    // The pooled-socket case the failing tests use. The socket is created inside
    // `cls.run('first')`, so the handle captures that frame; the second read
    // arrives after the first response completed and must still see it, because
    // the frame belongs to the socket rather than to whichever callback ran last.
    //
    // This is why the expectation is `first` twice rather than `first`/`second`:
    // creating the connection inside one `run()` and then writing from another
    // does not change the frame the *handle* captured. Asserting otherwise would
    // encode a behaviour Node does not have — the first version of this test did,
    // and `node` itself caught it.
    same_output_as_node(
        "const net = require('net');\n\
         const { AsyncLocalStorage } = require('async_hooks');\n\
         const cls = new AsyncLocalStorage();\n\
         let served = 0;\n\
         const server = net.createServer((socket) => {\n\
           socket.on('data', () => {\n\
             served += 1;\n\
             socket.write('response-' + served);\n\
             if (served === 2) socket.end();\n\
           });\n\
         });\n\
         server.listen(0, () => {\n\
           cls.run('first', () => {\n\
             const client = net.connect(server.address().port);\n\
             client.on('connect', () => client.write('one'));\n\
             client.on('data', (chunk) => {\n\
               console.log('read ' + chunk + ' store ' + cls.getStore());\n\
               if (String(chunk) === 'response-1') {\n\
                 client.write('two');\n\
               } else {\n\
                 client.end();\n\
               }\n\
             });\n\
             client.on('close', () => server.close());\n\
           });\n\
         });",
        "read response-1 store first\nread response-2 store first",
    );
}

#[test]
fn a_store_written_inside_a_callback_does_not_leak_to_the_next_one() {
    // The other direction of the frame exchange. `AsyncContextFrame.exchange`
    // installs the resource's frame on entry; the pair to it is the restore on
    // exit, and without the restore everything that runs afterwards inherits the
    // last callback's frame.
    //
    // The observable consequence is that two interleaved requests each keep their
    // own store. A one-directional fix passes the test above and fails this one.
    same_output_as_node(
        "const net = require('net');\n\
         const { AsyncLocalStorage } = require('async_hooks');\n\
         const cls = new AsyncLocalStorage();\n\
         const server = net.createServer((socket) => socket.end('bye'));\n\
         server.listen(0, () => {\n\
           cls.run('outer', () => {\n\
             const client = net.connect(server.address().port);\n\
             client.on('connect', () => client.write('hi'));\n\
             client.on('data', () => {\n\
               cls.enterWith('mutated-in-callback');\n\
               client.end();\n\
             });\n\
             client.on('close', () => server.close());\n\
           });\n\
           setTimeout(() => {\n\
             console.log('unrelated timer store ' + cls.getStore());\n\
           }, 40);\n\
         });",
        "unrelated timer store undefined",
    );
}

#[test]
fn the_frame_is_in_place_before_the_before_hook_fires() {
    // `InternalCallbackScope`'s constructor exchanges the frame at
    // `src/api/callback.cc:117`, pushes the context at `:124` and emits `before`
    // at `:127` — in that order. So a `before` hook is the one observer that runs
    // inside the scope before any user code, and it must already see the
    // callback's frame.
    //
    // An implementation that pushed the context and emitted `before` first and
    // only then installed the frame would report `before:undefined` followed by
    // `after:outer` for the same callback, which is what this pins against.
    //
    // The trailing unmatched `before` is Node's own: `onclose` runs inside the
    // scope, and the scope's `after` is skipped when the handle is already
    // closing. Both runtimes agree on it, which is why the expectation is this
    // shape rather than a tidy sequence of balanced pairs.
    same_output_as_node(
        "const net = require('net');\n\
         const async_hooks = require('async_hooks');\n\
         const { AsyncLocalStorage } = require('async_hooks');\n\
         const cls = new AsyncLocalStorage();\n\
         const socketId = { value: -1 };\n\
         const seen = [];\n\
         async_hooks.createHook({\n\
           before: (id) => {\n\
             if (id === socketId.value) seen.push('before:' + String(cls.getStore()));\n\
           },\n\
           after: (id) => {\n\
             if (id === socketId.value) seen.push('after:' + String(cls.getStore()));\n\
           },\n\
         }).enable();\n\
         const server = net.createServer((sock) => sock.end('bye'));\n\
         server.listen(0, () => {\n\
           cls.run('outer', () => {\n\
             const client = net.connect(server.address().port);\n\
             socketId.value = client._handle.getAsyncId();\n\
             client.on('connect', () => client.write('hi'));\n\
             client.on('data', () => client.end());\n\
             client.on('close', () => {\n\
               console.log(seen.join(','));\n\
               server.close();\n\
             });\n\
           });\n\
         });",
        "before:outer,after:outer,before:outer,after:outer,before:outer",
    );
}

#[test]
fn a_throwing_callback_reports_before_its_microtasks_run() {
    // The ordering, and it is not the intuitive one.
    // `InternalMakeCallback` sets `MarkAsFailed()` when the callback throws, so
    // `InternalCallbackScope::Close` returns at `if (failed_) return;` and its
    // `PerformCheckpoint` never runs. The uncaught trigger therefore precedes a
    // microtask the throwing callback queued.
    //
    // `crates/rn-napi/tests/addon_e2e.rs` pins the same `callback,listener,microtask`
    // order for thread-safe functions. A fix that drained microtasks around the
    // callback would produce `callback,microtask,listener` and pass any casual
    // smoke test.
    same_output_as_node(
        "const net = require('net');\n\
         const order = [];\n\
         process.on('uncaughtException', () => order.push('listener'));\n\
         const server = net.createServer((socket) => { socket.end('bye'); });\n\
         server.listen(0, () => {\n\
           const client = net.connect(server.address().port);\n\
           client.on('data', () => {\n\
             order.push('callback');\n\
             queueMicrotask(() => order.push('microtask'));\n\
             throw new Error('boom');\n\
           });\n\
           setTimeout(() => {\n\
             console.log(order.join(','));\n\
             server.close();\n\
           }, 60);\n\
         });",
        "callback,listener,microtask",
    );
}

#[test]
fn a_throw_from_a_socket_read_callback_reaches_the_uncaught_handler() {
    // `InternalCallbackScope`'s `TryCatch` plus `TriggerUncaughtException` is
    // the only route from a native callback to `process.on('uncaughtException')`.
    // Without it the throw is dropped: the handler never closes the server, and
    // the process stays alive on the server's ref'd handle forever.
    same_output_as_node(
        "const net = require('net');\n\
         process.once('uncaughtException', (error) => {\n\
           console.log('caught ' + error.message);\n\
           server.close(() => console.log('closed'));\n\
         });\n\
         const server = net.createServer((socket) => { socket.end('bye'); });\n\
         server.listen(0, () => {\n\
           const client = net.connect(server.address().port);\n\
           client.on('data', () => { throw new Error('from-read'); });\n\
         });",
        "caught from-read\nclosed",
    );
}

#[test]
fn a_throw_from_an_http_response_callback_reaches_the_uncaught_handler() {
    // The same seam on the HTTP path, which is where the failing files sit. The
    // important half is that the *process exits*: a handler that does not
    // rethrow must let the loop drain normally if it closed everything it owned.
    same_output_as_node(
        "const http = require('http');\n\
         process.once('uncaughtException', (error) => {\n\
           console.log('caught ' + error.message);\n\
           server.close(() => console.log('closed'));\n\
           agent.destroy();\n\
         });\n\
         const agent = new http.Agent({ keepAlive: true });\n\
         const server = http.createServer((req, res) => res.end('ok'));\n\
         server.listen(0, () => {\n\
           http.get({ port: server.address().port, agent }, () => {\n\
             throw new Error('from-response');\n\
           });\n\
         });",
        "caught from-response\nclosed",
    );
}

#[test]
fn an_uncaught_error_that_nothing_handles_still_exits_non_zero() {
    // The other half of the contract. Reporting an exception must not turn a
    // fatal error into a silent hang: with no listener, Node prints the error
    // and exits 1. A fix that swallowed the throw to make the handlers work
    // would pass every test above and fail this one.
    let script = "const net = require('net');\n\
                  const server = net.createServer((socket) => { socket.end('bye'); });\n\
                  server.listen(0, () => {\n\
                    const client = net.connect(server.address().port);\n\
                    client.on('data', () => { throw new Error('handler-less'); });\n\
                  });";
    let reference = run("node", script, Duration::from_secs(20));
    assert_eq!(
        reference.exit_code,
        Some(1),
        "`node` should exit 1 on an unhandled uncaught exception; stderr: {}",
        reference.stderr
    );
    assert!(
        reference.stderr.contains("handler-less"),
        "`node` should print the error; stderr: {}",
        reference.stderr
    );

    let actual = run(
        env!("CARGO_BIN_EXE_rustnode"),
        script,
        Duration::from_secs(20),
    );
    assert!(
        !actual.timed_out,
        "rustnode hung instead of exiting on an unhandled uncaught exception; \
         stdout: {}\nstderr: {}",
        actual.stdout, actual.stderr
    );
    assert_eq!(
        actual.exit_code,
        Some(1),
        "rustnode should exit 1; stdout: {}\nstderr: {}",
        actual.stdout,
        actual.stderr
    );
    assert!(
        actual.stderr.contains("handler-less"),
        "rustnode should print the error; stdout: {}\nstderr: {}",
        actual.stdout,
        actual.stderr
    );
}
