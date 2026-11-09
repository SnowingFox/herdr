//! `HTTPParser#consume`, checked against real `node` through the whole runtime.
//!
//! # What `consume` is
//!
//! `lib/internal/http/server.js` calls `parser.consume(socket._handle)` once per
//! connection, guarded by `socket._handle.isStreamBase && !socket._handle._consumed`:
//!
//! ```js
//! if (socket._handle?.isStreamBase && !socket._handle._consumed) {
//!   parser._consumed = true;
//!   socket._handle._consumed = true;
//!   parser.consume(socket._handle);
//! }
//! ```
//!
//! In Node that is `stream->PushStreamListener(parser)`, so libuv's reads go
//! straight into `Execute` and the socket's JavaScript `onread` stops running.
//! rustnode's read path has one destination — `handle.onread` — so `consume`
//! records the handle and the existing `onread` path keeps forwarding into
//! `execute`. See `rn_bind_http_parser::parser_consume` for why that is the
//! honest equivalent rather than a silent no-op.
//!
//! # Why these tests run the real binary
//!
//! The binding unit tests install the namespace into a bare isolate, where there
//! is no `tcp_wrap`, no loop and no `lib/net.js`. The thing that can actually
//! break is the handoff between three crates — `tcp_wrap` publishing a stream
//! handle, `rn_uv::streams` resolving it, and the parser accepting it — so the
//! test has to be a real server and a real socket.
//!
//! # What must not happen
//!
//! `consume` throwing aborts `connectionListenerInternal` part-way through, after
//! the socket has had its `'connection'` listeners attached but before the parser
//! is wired to it. The request still arrives (the socket was already readable),
//! so the failure is easy to mistake for success: the response is served and only
//! the bookkeeping is missing. These tests therefore assert on behaviour that
//! only works when the connection setup completed — pipelining, `'data'` not
//! firing on a consumed socket, and `unconsume` being reachable.

use std::process::Command;
use std::time::{Duration, Instant};

/// What running a script produced.
struct Run {
    stdout: String,
    stderr: String,
    success: bool,
    elapsed: Duration,
}

/// Runs `script` under `binary`, killing it if it outlives `limit`.
fn run(binary: &str, script: &str, limit: Duration) -> Run {
    let started = Instant::now();
    let mut child = Command::new(binary)
        .arg("-e")
        .arg(script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot spawn {binary}: {error}"));

    let mut killed = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => panic!("cannot poll {binary}: {error}"),
        }
        if started.elapsed() > limit {
            killed = true;
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

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

/// Asserts `script` prints `expected` under both runtimes and exits cleanly.
///
/// `node` runs first: if the reference disagrees, the expectation in this test is
/// wrong and saying so is more useful than blaming rustnode.
fn same_output_as_node(script: &str, expected: &str) {
    let reference = run("node", script, Duration::from_secs(20));
    assert!(
        reference.success,
        "`node` failed on {script:?}; stderr: {}",
        reference.stderr
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
        actual.success,
        "rustnode exited non-zero ({} elapsed); stderr: {}",
        actual.elapsed.as_millis(),
        actual.stderr
    );
    assert_eq!(
        actual.stdout, expected,
        "script was: {script}\nstderr: {}",
        actual.stderr
    );
    assert!(
        !actual.stderr.contains("consume"),
        "the run reported consume as unavailable: {}",
        actual.stderr
    );
}

#[test]
fn a_keep_alive_request_does_not_report_consume_as_unavailable() {
    // The reported symptom, minus the hang: `consume` is reached on every server
    // connection, so a throwing `consume` surfaced here as an uncaught error
    // printed after the response had already been served.
    same_output_as_node(
        "const http = require('http');\n\
         const s = http.createServer((req, res) => res.end('ok'));\n\
         s.listen(0, () => {\n\
           const p = s.address().port;\n\
           http.get({ port: p, agent: new http.Agent({ keepAlive: true }) }, (res) => {\n\
             res.resume();\n\
             res.on('end', () => { console.log('got ' + res.statusCode); s.close(); });\n\
           });\n\
         });",
        "got 200",
    );
}

#[test]
fn the_server_handle_is_marked_consumed_and_the_parser_agrees() {
    // The bookkeeping `consume` exists to establish. `lib/internal/http/server.js`
    // sets both flags itself before the call, so a `consume` that threw would
    // still leave them set while aborting the rest of the connection setup; that
    // is why this is checked together with real traffic rather than alone.
    same_output_as_node(
        "const http = require('http');\n\
         const s = http.createServer((req, res) => res.end('ok'));\n\
         s.on('connection', (socket) => {\n\
           const handle = socket._handle;\n\
           console.log('streambase ' + handle.isStreamBase +\n\
                       ' consumed ' + handle._consumed +\n\
                       ' parser ' + socket.parser._consumed);\n\
         });\n\
         s.listen(0, () => {\n\
           http.get({ port: s.address().port, agent: false }, (res) => {\n\
             res.resume();\n\
             res.on('end', () => s.close());\n\
           });\n\
         });",
        "streambase true consumed true parser true",
    );
}

#[test]
fn a_consumed_socket_still_delivers_every_pipelined_request() {
    // The contract a silent no-op would break first. `lib/internal/http/server.js`
    // replaces `socket.on` with a wrapper that calls `unconsume` when anyone adds
    // a `'data'` or `'readable'` listener, so a `consume` that did not record the
    // attachment would leave the parser and the socket both reading. Three
    // requests written in one `write()` only all arrive if the parser kept
    // ownership of the stream.
    same_output_as_node(
        "const http = require('http');\n\
         const net = require('net');\n\
         const seen = [];\n\
         const s = http.createServer((req, res) => {\n\
           seen.push(req.url);\n\
           res.end('ok');\n\
           if (seen.length === 3) {\n\
             console.log(seen.join(','));\n\
             s.close();\n\
             process.exit(0);\n\
           }\n\
         });\n\
         s.listen(0, () => {\n\
           const c = net.connect({ port: s.address().port }, () => {\n\
             c.write('GET /1 HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n' +\n\
                     'GET /2 HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n' +\n\
                     'GET /3 HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n');\n\
           });\n\
           c.on('data', () => {});\n\
         });",
        "/1,/2,/3",
    );
}

#[test]
fn a_request_with_a_body_is_parsed_after_consume() {
    // A body spans multiple `execute` calls, so it only works if the same parser
    // stays attached across reads. This is the shape `test-async-hooks-http-agent`
    // uses (a `POST` whose body arrives after the headers).
    same_output_as_node(
        "const http = require('http');\n\
         const s = http.createServer((req, res) => {\n\
           const chunks = [];\n\
           req.on('data', (chunk) => chunks.push(chunk));\n\
           req.on('end', () => {\n\
             console.log('body ' + Buffer.concat(chunks).toString());\n\
             res.end('ok');\n\
           });\n\
         });\n\
         s.listen(0, () => {\n\
           const req = http.request(\n\
             { port: s.address().port, method: 'POST', agent: false },\n\
             (res) => { res.resume(); res.on('end', () => s.close()); });\n\
           req.write('hello ');\n\
           setTimeout(() => req.end('world'), 20);\n\
         });",
        "body hello world",
    );
}
