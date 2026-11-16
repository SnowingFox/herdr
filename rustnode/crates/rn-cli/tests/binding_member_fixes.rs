//! Differential checks for the members this change implemented.
//!
//! Every value in this file was measured on the pinned Node 28 nightly
//! (`v28.0.0-nightly20261111e8c1160d20`, the revision `tools/node-pin.toml`
//! records) and then compared against the built `rustnode` binary. The expected
//! strings are the oracle's output, not a description of what the code does, so a
//! regression here is a divergence a user could hit.
//!
//! These run the built binary rather than calling the handlers because the
//! differences that matter are JavaScript-visible: a function's `name`, `length`
//! and identity, an error's `code` and message, and whether a namespace object
//! carries a property at all.
//!
//! `require('node:internal/test/binding').internalBinding` is what reaches a
//! namespace from user code. That is the same door the reviewers used and the same
//! door Node's own tests use.

use std::process::Command;

/// Runs `source` under the built binary and returns `(code, stdout, stderr)`.
fn run(source: &str) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--expose-internals", "-e", source])
        .output()
        .expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Asserts the script printed `expected` and exited 0.
fn expect(source: &str, expected: &str) {
    let (code, stdout, stderr) = run(source);
    assert_eq!(
        stdout.trim(),
        expected,
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

const BINDING: &str = "const { internalBinding } = \
    require('node:internal/test/binding');";

// ------------------------------------------------- util.getSharedArrayBufferGrowable --

#[test]
fn the_growable_flag_is_v8_own_accessor_not_a_wrapper() {
    // `src/node_util.cc:529-546` republishes the getter it reads off a fresh
    // `SharedArrayBuffer`'s prototype. Identity is the observable consequence: a
    // hand-written Boolean wrapper would answer the same for a real
    // SharedArrayBuffer and differently for everything else, which is the kind of
    // near-miss this namespace has already shipped once.
    expect(
        &format!(
            "{BINDING}
            const g = internalBinding('util').getSharedArrayBufferGrowable;
            const descriptor =
              Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'growable');
            console.log(JSON.stringify(g.name), g.length, g === descriptor.get);
            console.log(String(g.call(new SharedArrayBuffer(8, {{ maxByteLength: 64 }}))),
                        String(g.call(new SharedArrayBuffer(8))));
            try {{ g.call(new ArrayBuffer(8)); }}
            catch (e) {{ console.log(e.name); }}"
        ),
        r#""get growable" 0 true
true false
TypeError"#,
    );
}

// ------------------------------------------------- util.arrayBufferViewHasBuffer --

#[test]
fn every_member_this_change_added_reports_its_own_name() {
    // `SetMethod(context, target, "f", fn)` in `src/node_util.cc` names the
    // function after the property it publishes. `FunctionTemplate::builder` leaves
    // it `""`, so a member built that way reports an empty `f.name` where Node
    // reports `"f"`. That is invisible to any behavioural test — the call still
    // works — and it reaches stack traces and `util.inspect`, which is why it is
    // asserted here per member rather than inferred.
    //
    // The four `process_methods` entries come from one helper that now sets the
    // name, so this covers 30 members while naming the four added by this change.
    expect(
        &format!(
            "{BINDING}
            const util = internalBinding('util');
            const pm = internalBinding('process_methods');
            const cases = [
              ['util', 'arrayBufferViewHasBuffer'], ['util', 'getSharedArrayBufferGrowable'],
              ['pm', 'causeSegfault'], ['pm', 'dlopenBinary'],
              ['pm', 'execve'], ['pm', 'setEmitWarningSync'],
            ];
            const tables = {{ util, pm }};
            for (const [table, member] of cases) {{
              console.log(member, JSON.stringify(tables[table][member].name));
            }}"
        ),
        concat!(
            "arrayBufferViewHasBuffer \"arrayBufferViewHasBuffer\"\n",
            "getSharedArrayBufferGrowable \"get growable\"\n",
            "causeSegfault \"causeSegfault\"\n",
            "dlopenBinary \"dlopenBinary\"\n",
            "execve \"execve\"\n",
            "setEmitWarningSync \"setEmitWarningSync\"",
        ),
    );
}

#[test]
fn an_empty_view_with_no_supplied_buffer_is_the_one_has_buffer_misses() {
    // V8's rule is `!typed_array->is_on_heap()` (`v8/src/api/api.cc:9483`), and a
    // TypedArray created without a supplied buffer keeps its elements on the JS
    // heap while its length is at or below `v8_typed_array_max_size_in_heap`.
    // Node's build sets that to 64; the `v8` crate rustnode links sets it to 0
    // (`v8-152.2.0/.gn:58`), so no view is ever on-heap here and `HasBuffer()` is
    // `true` for every live one.
    //
    // This test exists because the empty case is **not** a separate bug that a
    // length-0 special case could fix. The oracle answers `true` for an empty view
    // that was *given* a buffer and for every DataView, so special-casing length
    // zero would match one input while breaking two. Pinning the whole matrix
    // makes that visible to whoever next reaches for the obvious-looking fix.
    expect(
        &format!(
            "{BINDING}
            const h = internalBinding('util').arrayBufferViewHasBuffer;
            const rows = [
              ['U8(0)',        new Uint8Array(0)],
              ['U8(AB0)',      new Uint8Array(new ArrayBuffer(0))],
              ['DataView(AB0)', new DataView(new ArrayBuffer(0))],
              ['U8(AB8)',      new Uint8Array(new ArrayBuffer(8))],
              ['U8(65)',       new Uint8Array(65)],
            ];
            for (const [label, view] of rows) {{
              console.log(label, String(h.call(null, view)));
            }}"
        ),
        concat!(
            // The first row is the documented divergence; the rest match Node and
            // are what a length-0 special case would break.
            "U8(0) true\n",
            "U8(AB0) true\n",
            "DataView(AB0) true\n",
            "U8(AB8) true\n",
            "U8(65) true",
        ),
    );
}

#[test]
fn a_detached_view_is_the_case_has_buffer_reports() {
    // Measured on the oracle. Note the divergence recorded in `rn-util`'s
    // documentation: the pinned Node keeps a view of at most 64 bytes on the V8
    // heap and answers `false` for it, while rustnode's V8 sets
    // `v8_typed_array_max_size_in_heap = 0` and always allocates a backing store.
    // A buffer that was explicitly allocated is `true` on both, and a detached
    // view stays `true` on both because V8 keeps the (now-length-zero) buffer
    // object rather than dropping it, so those are the cases pinned here.
    expect(
        &format!(
            "{BINDING}
            const h = internalBinding('util').arrayBufferViewHasBuffer;
            console.log(h.length);
            const ab = new ArrayBuffer(0);
            const view = new Uint8Array(ab);
            console.log(String(h.call(null, view)));
            console.log(String(h.call(null, new Uint8Array(1000))));
            structuredClone(ab, {{ transfer: [ab] }});
            console.log(String(h.call(null, view)));"
        ),
        "0\ntrue\ntrue\ntrue",
    );
}

#[test]
fn has_buffer_aborts_on_a_non_view_the_way_node_does() {
    // `src/node_util.cc:186` is `CHECK(args[0]->IsArrayBufferView())`, and `CHECK`
    // aborts. Answering `false` instead would turn a caller's bug into the
    // plausible claim "this view was detached", so the abort is reproduced. The
    // oracle dies on the same call with the same assertion.
    let (code, _stdout, stderr) = run(&format!(
        "{BINDING}
        internalBinding('util').arrayBufferViewHasBuffer({{}});"
    ));
    assert!(
        !stderr.is_empty(),
        "the failing assertion must say so on stderr"
    );
    assert!(
        code != 0,
        "a CHECK failure must end the process; exited {code} with stderr {stderr:?}"
    );
}

// ------------------------------------------------- crypto.isKeyAlgorithmAvailable --

#[test]
fn is_key_algorithm_available_answers_for_a_real_algorithm() {
    // The member was listed in `crypto`'s DEFERRED with a reason claiming it was
    // "deferred with the key surface" while `rn-bind-crypto-keys` had been
    // installing it for as long as the crate existed. `lib/internal/crypto/util.js:488`
    // also calls it at module scope, so the deferral was wrong about reachability
    // as well as about the object.
    expect(
        &format!(
            "{BINDING}
            const c = internalBinding('crypto');
            console.log(typeof c.isKeyAlgorithmAvailable);
            console.log(['Ed25519', 'sha256', 'bogus']
              .map((name) => String(c.isKeyAlgorithmAvailable(name))).join(','));"
        ),
        "function\ntrue,false,false",
    );
}

// ------------------------------------------------- process_methods --

#[test]
fn the_four_process_methods_are_installed_functions() {
    // All four were in `MEMBERS` and `DEFERRED` at once, so the contract
    // subtraction cancelled them and `rn-compat` reported the namespace clean
    // while `lib/**` read `undefined`. `execve` was additionally mis-described:
    // its reason claimed the event loop had to quiesce, which Node's own
    // implementation deliberately does not do (`src/node_process_methods.cc:600`,
    // "we intentionally do not invoke RunAtExit(env) here").
    expect(
        &format!(
            "{BINDING}
            const pm = internalBinding('process_methods');
            console.log(['causeSegfault', 'dlopenBinary', 'execve', 'setEmitWarningSync']
              .map((name) => typeof pm[name]).join(','));
            console.log(String(pm.setEmitWarningSync(() => {{}})));"
        ),
        "function,function,function,function\nundefined",
    );
}

#[test]
fn execve_that_fails_reports_the_errno_shape_node_reports() {
    // `Environment::ThrowErrnoException` builds `code + ", " + strerror(errno)`,
    // then ` + " 'path'"`, with `errno`, `code` and `syscall` as plain data
    // properties. The exact wording matters: user code and `assert.throws`
    // matchers compare against it.
    expect(
        &format!(
            "{BINDING}
            try {{ internalBinding('process_methods')
                     .execve('/definitely/not/here', ['x'], []); }}
            catch (e) {{
              console.log(e.code, e.errno, JSON.stringify(e.syscall));
              console.log(JSON.stringify(e.message));
            }}"
        ),
        "ENOENT 2 \"execve\"\n\"ENOENT, No such file or directory '/definitely/not/here'\"",
    );
}

// ------------------------------------------------- module_wrap.createRequiredModuleFacade --

#[test]
fn requiring_an_es_module_with_a_default_export_works() {
    // `lib/internal/modules/cjs/loader.js:1846` reaches this member for exactly
    // this shape — an ES module with a `default` export and no `__esModule` — and
    // before it was implemented the whole path threw
    // `createRequiredModuleFacade is not implemented yet`. The namespace's three
    // keys and its null prototype are what the oracle prints.
    let dir = std::env::temp_dir().join(format!(
        "rn-require-esm-facade-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::write(
        dir.join("m.mjs"),
        "export default function fn() { return 'called'; }\nexport const x = 2;\n",
    )
    .expect("module source");
    std::fs::write(
        dir.join("c.cjs"),
        "const m = require('./m.mjs');\n\
         console.log(Object.keys(m).sort().join(','));\n\
         console.log(typeof m.default, m.x, m.__esModule,\n\
                     Object.getPrototypeOf(m), m.default());\n",
    )
    .expect("entry source");

    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("c.cjs")
        .current_dir(&dir)
        .output()
        .expect("rustnode runs");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "__esModule,default,x\nfunction 2 true null called"
    );
}

// ------------------------------------------------- http_parser finish after Upgrade --

/// Runs `source` that needs internals and returns its stdout, asserting exit 0.
fn run_exposed(source: &str) -> String {
    let (code, stdout, stderr) = run(source);
    assert_eq!(code, 0, "stderr: {stderr}");
    stdout
}

#[test]
fn finish_after_an_upgrade_handshake_reports_no_error() {
    // `Parser::Execute` guards its whole error branch with `!parser_.upgrade`
    // (`src/node_http_parser.cc:949`): once llhttp is in upgrade mode the bytes
    // after the handshake belong to whoever took the connection, so the parser has
    // no fault to report. Testing only `errno != HPE_OK` made `finish()` manufacture
    // an `HPE_INVALID_EOF_STATE` where Node answers `undefined`.
    //
    // The oracle's answers for all four cases are in this test, because the guard
    // is only correct if it is narrow: `normal` and `bad-chunk` must be unaffected
    // and `truncated` must keep failing loudly.
    let out = run_exposed(&format!(
        "{BINDING}
            const {{ HTTPParser }} = internalBinding('http_parser');
            const cases = {{
              upgrade: 'GET /ws HTTP/1.1\\r\\nHost: h\\r\\nConnection: Upgrade\\r\\n' +
                       'Upgrade: websocket\\r\\n\\r\\n',
              connect: 'CONNECT h:443 HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n',
              normal: 'GET /a HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n',
              // No terminating blank line: never reaches headers-complete, so it
              // never gains the upgrade flag and must still error.
              truncated: 'GET /a HTTP/1.1\\r\\nHost: h\\r\\n',
            }};
            const results = {{}};
            for (const [name, bytes] of Object.entries(cases)) {{
              const p = new HTTPParser();
              p.initialize(HTTPParser.REQUEST, {{}}, 0, 0, undefined, 0);
              p[HTTPParser.kOnHeadersComplete] = () => 0;
              const exec = p.execute(Buffer.from(bytes));
              const fin = p.finish();
              results[name] = [String(exec), fin === undefined ? 'undefined' : fin.code];
            }}
            console.log(JSON.stringify(results));"
    ));
    assert_eq!(
        out.trim(),
        r#"{"upgrade":["70","undefined"],"connect":["35","undefined"],"normal":["28","undefined"],"truncated":["26","HPE_INVALID_EOF_STATE"]}"#
    );
}

#[test]
fn an_http_server_receiving_an_upgrade_request_with_no_listener_is_silent() {
    // The user-visible half of the same bug, through `http`. `socketOnEnd`
    // (`lib/internal/http/server.js:962`) calls `parser.finish()` when the peer
    // half-closes, and turns a returned Error into `clientError`. Node emits
    // nothing here; rustnode emitted `HPE_INVALID_EOF_STATE` for a handshake it had
    // already accepted.
    //
    // The server still serves the request, which is why the clientError emission —
    // not the response — is what this asserts.
    let out = run_exposed(
        "const http = require('node:http');
         const net = require('node:net');
         const errors = [];
         const server = http.createServer((req, res) => res.end('handled'));
         server.on('clientError', (err, socket) => {
           errors.push(err.code);
           if (socket && !socket.destroyed) socket.destroy();
         });
         server.listen(0, () => {
           const socket = net.connect(server.address().port, '127.0.0.1', () => {
             socket.write('GET /ws HTTP/1.1\\r\\nHost: h\\r\\nConnection: Upgrade\\r\\n' +
                          'Upgrade: websocket\\r\\n\\r\\n');
           });
           socket.setEncoding('utf8');
           socket.on('data', () => {});
           socket.on('error', () => {});
           socket.on('connect', () => setTimeout(() => socket.end(), 40));
           setTimeout(() => {
             console.log(JSON.stringify(errors));
             socket.destroy();
             server.close();
             process.exit(0);
           }, 300);
         });",
    );
    assert_eq!(out.trim(), "[]");
}

// ------------------------------------------------- http2 trailers --

#[test]
fn a_server_response_with_wait_for_trailers_delivers_them_to_the_client() {
    // `Http2Stream::OnTrailers` (`src/node_http2.cc:2534`) runs from the DATA
    // provider at EOF when `has_trailers()` is set, and the EOF is reported with
    // `DATA_FLAG_NO_END_STREAM` so the trailer HEADERS frame — not the DATA frame —
    // closes the stream. Neither happened before this fix: `wantTrailers` never
    // fired, so `sendTrailers` was unreachable and the client saw no `trailers`
    // event.
    //
    // The trailer object's shape is asserted, not just its arrival: the event
    // carries a plain object with the keys as sent, and every other surface
    // (`req.trailers`, `stream.trailers` on both sides) is `undefined` on the
    // oracle too, so a fix that populated them would be a second divergence.
    let out = run_exposed(
        "const http2 = require('node:http2');
         const server = http2.createServer();
         server.on('session', (s) => s.on('error', () => {}));
         server.on('stream', (stream) => {
           stream.respond({ ':status': 200 }, { waitForTrailers: true });
           stream.on('wantTrailers', () => stream.sendTrailers({ 'x-t': 'v' }));
           stream.end('body');
         });
         server.listen(0, () => {
           const client = http2.connect('http://localhost:' + server.address().port);
           const req = client.request({ ':path': '/' });
           let body = '';
           req.setEncoding('utf8');
           req.on('data', (c) => { body += c; });
           req.on('trailers', (t) => {
             console.log(JSON.stringify({
               trailers: t,
               keys: Object.keys(t),
               proto: Object.getPrototypeOf(t),
               clientStreamTrailers: String(req.trailers),
             }));
           });
           req.on('end', () => {
             console.log('end ' + body + ' req.trailers=' + String(req.trailers));
           });
           req.on('close', () => { client.close(); server.close(); });
           req.end();
         });",
    );
    assert_eq!(
        out.trim(),
        "{\"trailers\":{\"x-t\":\"v\"},\"keys\":[\"x-t\"],\"proto\":null,\
\"clientStreamTrailers\":\"undefined\"}\n\
end body req.trailers=undefined"
    );
}

#[test]
fn trailers_that_were_not_asked_for_change_nothing() {
    // The control that must not move. A response without `waitForTrailers` keeps
    // ending on its DATA frame, and a stream that sends an empty trailer block
    // (`sendTrailers({})`, and the compat layer with no registered trailers) must
    // produce Node's empty DATA frame rather than an empty HEADERS block — the
    // latter would invent a `trailers` event Node never emits.
    let out = run_exposed(
        "const http2 = require('node:http2');
         const server = http2.createServer();
         server.on('session', (s) => s.on('error', () => {}));
         server.on('stream', (stream, headers) => {
           const mode = headers[':path'];
           if (mode === '/none') {
             stream.respond({ ':status': 200 });
           } else if (mode === '/empty') {
             stream.respond({ ':status': 200 }, { waitForTrailers: true });
             stream.on('wantTrailers', () => stream.sendTrailers({}));
           } else {
             // The HTTP/1 compat layer arms auto-empty trailers and must finish
             // normally when no trailers are registered.
             stream.respond({ ':status': 200 }, { waitForTrailers: true });
           }
           stream.end('body');
         });
         server.listen(0, () => {
           const client = http2.connect('http://localhost:' + server.address().port);
           const paths = ['/none', '/empty', '/auto'];
           let seen = {};
           const next = () => {
             const path = paths.shift();
             if (path === undefined) {
               console.log(JSON.stringify(seen));
               client.close();
               server.close();
               return;
             }
             const req = client.request({ ':path': path });
             const events = [];
             req.setEncoding('utf8');
             req.on('data', () => {});
             req.on('trailers', () => events.push('trailers'));
             req.on('end', () => events.push('end'));
             req.on('close', () => { seen[path] = events; next(); });
             req.end();
           };
           next();
         });",
    );
    assert_eq!(
        out.trim(),
        r#"{"/none":["end"],"/empty":["end"],"/auto":["end"]}"#
    );
}

#[test]
fn the_http1_compat_layer_delivers_trailers_and_keeps_plain_responses_unchanged() {
    // `Http2ServerResponse.addTrailers` reaches the same native path through
    // `onStreamTrailersReady` -> `sendTrailers`, and the streamed case exercises
    // `kDisableAutoTrailers` (headers flushed before `end()`, trailers registered
    // afterwards). Both must deliver; the plain response must not.
    let out = run_exposed(
        "const http2 = require('node:http2');
         const server = http2.createServer();
         server.on('session', (s) => s.on('error', () => {}));
         server.on('request', (req, res) => {
           if (req.url === '/streamed') {
             res.write('part1');
             setTimeout(() => {
               res.addTrailers({ 'x-late': 'late' });
               res.end('part2');
             }, 10);
           } else if (req.url === '/plain') {
             res.end('body');
           } else {
             res.addTrailers({ 'x-t': 'v' });
             res.end('body');
           }
         });
         server.listen(0, () => {
           const client = http2.connect('http://localhost:' + server.address().port);
           const paths = ['/trailers', '/plain', '/streamed'];
           const seen = {};
           const next = () => {
             const path = paths.shift();
             if (path === undefined) {
               console.log(JSON.stringify(seen));
               client.close();
               server.close();
               return;
             }
             const req = client.request({ ':path': path });
             let body = '';
             const events = [];
             req.setEncoding('utf8');
             req.on('data', (c) => { body += c; });
             req.on('trailers', (t) => events.push(['trailers', t]));
             req.on('end', () => events.push(['end']));
             req.on('close', () => { seen[path] = [body, events]; next(); });
             req.end();
           };
           next();
         });",
    );
    assert_eq!(
        out.trim(),
        "{\"/trailers\":[\"body\",[[\"trailers\",{\"x-t\":\"v\"}],[\"end\"]]],\
\"/plain\":[\"body\",[[\"end\"]]],\
\"/streamed\":[\"part1part2\",[[\"trailers\",{\"x-late\":\"late\"}],[\"end\"]]]}"
    );
}

// ------------------------------------------------- messaging.broadcastChannel --

/// Runs `script` as a file under the built binary, so `__filename` and `Worker`
/// can reach it.
///
/// A `-e` script has no path, and both halves of a cross-thread test need the same
/// script named twice — the parent spawns `__filename`, so it has to be a file.
/// `dir` lives for the call and is removed afterwards.
fn run_file(label: &str, script: &str) -> (i32, String, String) {
    run_file_with(label, &[], script)
}

/// [`run_file`] with extra runtime flags.
///
/// Needed for `require('internal/test/binding')`, which resolves only under
/// `--expose-internals`. The handle-level cases need it because
/// `BroadcastChannel.postMessage` forwards a single argument — `io.js:445` calls
/// `this[kHandle].postMessage(message)` — so a transfer list is only reachable
/// through the binding, exactly as it is on Node.
fn run_file_with(label: &str, flags: &[&str], script: &str) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "rn-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let main = dir.join("main.js");
    std::fs::write(&main, script).expect("script source");
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(flags)
        .arg(&main)
        .current_dir(&dir)
        .output()
        .expect("rustnode runs");
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code().unwrap_or(-1),
        strip_tracing(&String::from_utf8_lossy(&out.stdout)),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Drops tracing-format lines (`<rfc3339 timestamp>  LEVEL target: message`).
///
/// A worker thread's bootstrap emits `WARN rn_bind_inspector: the inspector
/// namespace was installed without an isolate` on *stdout* before any JavaScript
/// runs. That is pre-existing and unrelated to this change — the baseline binary
/// prints it too — and it is a defect of its own (a program's stdout is
/// polluted), so the comparison drops exactly that shape rather than loosening
/// itself. `crates/rn-cli/tests/drain_order.rs` strips it for the same reason.
fn strip_tracing(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| {
            let is_log = line.contains(" WARN ") || line.contains(" ERROR ");
            let starts_with_timestamp = line
                .split_once(' ')
                .is_some_and(|(first, _)| first.len() == 27 && first.ends_with('Z'));
            !(is_log && starts_with_timestamp)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runs `script` under a wall-clock limit and reports whether it exited by itself.
///
/// `process.exit()` cannot prove a process exits on its own — it is the one call
/// that guarantees the answer — so a test about loop liveness has to let the
/// script end and watch what happens. A timeout is the only way to tell "exited"
/// from "hung", and the elapsed time is asserted too: a script that is killed at
/// the limit and one that exited after the limit look identical otherwise.
fn run_with_deadline(label: &str, script: &str, limit: std::time::Duration) -> (bool, u128) {
    let dir = std::env::temp_dir().join(format!(
        "rn-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let main = dir.join("main.js");
    std::fs::write(&main, script).expect("script source");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg(&main)
        .current_dir(&dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("rustnode runs");

    let started = std::time::Instant::now();
    let exited = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if started.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
            Err(_) => break false,
        }
    };
    let elapsed = started.elapsed().as_millis();
    let _ = std::fs::remove_dir_all(&dir);
    (exited, elapsed)
}

#[test]
fn broadcast_channel_is_a_global_and_a_worker_threads_export() {
    // `lib/internal/bootstrap/web/exposed-window-or-worker.js:50` publishes it as
    // a global, two lines above `MessageChannel`/`MessagePort`, and
    // `lib/worker_threads.js:23` exports the same class. rustnode installed the
    // class on neither path because the binding member was deferred, and its
    // `install_web_globals` list named only the two neighbours.
    expect(
        "const wt = require('worker_threads');
        console.log(typeof globalThis.BroadcastChannel,
                    typeof wt.BroadcastChannel,
                    globalThis.BroadcastChannel === wt.BroadcastChannel);",
        "function function true",
    );
}

#[test]
fn two_channels_on_one_name_deliver_in_one_thread_and_never_to_the_poster() {
    // The simplest use of the API, and the case the removed deferral reason said
    // could not exist: "with no Worker there is no second participant". Node
    // delivers between two `BroadcastChannel` objects on one name inside one
    // thread, so no second thread is needed for a channel to receive. The poster
    // is excluded, which is `SiblingGroup::Dispatch`'s `port == source` skip.
    let (code, stdout, stderr) = run_file(
        "bc-one-thread",
        "const {BroadcastChannel} = require('worker_threads');
        const seen = {a: [], b: []};
        const a = new BroadcastChannel('bc-one');
        const b = new BroadcastChannel('bc-one');
        a.onmessage = (e) => seen.a.push(e.data);
        b.onmessage = (e) => seen.b.push(e.data);
        console.log(JSON.stringify([a.name, b.name, a instanceof BroadcastChannel]));
        a.postMessage('from-a');
        b.postMessage('from-b');
        setTimeout(() => {
          console.log(JSON.stringify(seen));
          a.close();
          b.close();
        }, 20);
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        concat!(
            r#"["bc-one","bc-one",true]"#,
            "\n",
            r#"{"a":["from-b"],"b":["from-a"]}"#,
        ),
        "each channel must see the other's post and not its own"
    );
}

#[test]
fn a_broadcast_channel_delivers_across_two_threads() {
    // The other half of the scope, and the half a `Worker` is actually needed for.
    //
    // The handshake is not decoration. Main cannot post before the worker has
    // constructed its channel — the worker's channel joins the named group only
    // when it runs — and a post into a group with one member is simply dropped.
    // That makes the naive ordering (main posts from `'online'`) print nothing on
    // the *oracle* too, with exit 0 and no error, so a test without the handshake
    // would pass for the wrong reason on both runtimes.
    let (code, stdout, stderr) = run_file(
        "bc-two-threads",
        "const {isMainThread, parentPort, Worker, BroadcastChannel} =
           require('worker_threads');
        if (isMainThread) {
          const w = new Worker(__filename);
          w.on('message', (m) => {
            if (m !== 'ready') return;
            const c = new BroadcastChannel('t');
            c.onmessage = (e) => {
              console.log('main saw', e.data);
              c.close();
              w.terminate();
            };
            c.postMessage('from-main');
          });
        } else {
          const c = new BroadcastChannel('t');
          c.onmessage = (e) => {
            c.postMessage('worker got:' + e.data);
            c.close();
          };
          parentPort.postMessage('ready');
        }
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "main saw worker got:from-main");
}

#[test]
fn a_channel_carries_a_structured_clone_payload_and_a_message_port() {
    // Structured clone is the payload half of the scope: the same
    // `ValueSerializer` path `postMessage` uses, so a `Map`, a `Date`, a `RegExp`
    // and a typed array all survive. The transferred `MessagePort` is the case
    // that only works if the channel's host-object id space is the message's, and
    // it is reached through the handle because `io.js`'s `BroadcastChannel`
    // `postMessage` forwards a single argument — the same shape the oracle has.
    let (code, stdout, stderr) = run_file_with(
        "bc-clone",
        &["--expose-internals"],
        "require('worker_threads');
        const {internalBinding} = require('internal/test/binding');
        const messaging = internalBinding('messaging');
        const {MessageChannel} = require('worker_threads');
        const a = messaging.broadcastChannel('bc-clone');
        const b = messaging.broadcastChannel('bc-clone');
        const {port1, port2} = new MessageChannel();
        port2.on('message', (m) => console.log('inner peer got', m));
        b.on('message', (payload) => {
          const d = payload.data;
          console.log(JSON.stringify({
            map: d.map instanceof Map && [...d.map],
            set: d.set instanceof Set && [...d.set],
            date: d.date instanceof Date && d.date.toISOString(),
            re: d.re instanceof RegExp && String(d.re),
            u8: d.u8 instanceof Uint8Array && [...d.u8],
          }));
          const port = d.port;
          port.on('message', (m) => console.log('transferred got', m));
          port.postMessage('through-inner');
        });
        a.postMessage({data: {map: new Map([['k', 1]]), set: new Set([2]),
                             date: new Date(0), re: /x/g, u8: new Uint8Array([1, 2, 3]),
                             port: port1}},
                      [port1]);
        setTimeout(() => {
          a.close();
          b.close();
          port2.close();
          console.log('end');
        }, 40);
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        concat!(
            r#"{"map":[["k",1]],"set":[2],"date":"1970-01-01T00:00:00.000Z","re":"/x/g","u8":[1,2,3]}"#,
            "\n",
            "inner peer got through-inner",
            "\n",
            "end",
        ),
    );
}

#[test]
fn a_transfer_list_with_more_than_one_destination_is_refused() {
    // `SiblingGroup::Dispatch` refuses a message with transferables when the group
    // has more than two members (`size() > 2`), because a transfer names one
    // receiver. Node answers `Nothing()`, so `postMessage` returns `undefined` and
    // throws nothing — which is neither the `true` of a delivery nor the `false`
    // that `io.js`'s `BroadcastChannel` turns into "Message could not be posted".
    let (code, stdout, stderr) = run_file_with(
        "bc-three-way-transfer",
        &["--expose-internals"],
        "require('worker_threads');
        const {internalBinding} = require('internal/test/binding');
        const messaging = internalBinding('messaging');
        const a = messaging.broadcastChannel('bc-three');
        const b = messaging.broadcastChannel('bc-three');
        const c = messaging.broadcastChannel('bc-three');
        b.on('message', () => console.log('b got'));
        c.on('message', () => console.log('c got'));
        const {port1} = new (require('worker_threads').MessageChannel)();
        console.log('transfer ->', a.postMessage({p: port1}, [port1]));
        console.log('plain ->', a.postMessage('plain'));
        setTimeout(() => {
          a.close();
          b.close();
          c.close();
          console.log('end');
        }, 40);
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        concat!(
            "transfer -> undefined",
            "\n",
            "plain -> true",
            "\n",
            "b got",
            "\n",
            "c got",
            "\n",
            "end",
        ),
        "the transfer must be refused while the plain message still reaches both"
    );
}

#[test]
fn posting_a_port_to_itself_warns_instead_of_delivering() {
    // `Dispatch` reports a destination that is one of the message's own
    // transferables as a success plus a warning: the port left the group when the
    // transfer list took it, so there is nowhere for the post to go. The message
    // text is Node's, and it reaches the user through the process warning path.
    let (code, stdout, stderr) = run_file_with(
        "bc-self-target",
        &["--expose-internals"],
        "require('worker_threads');
        const {internalBinding} = require('internal/test/binding');
        const messaging = internalBinding('messaging');
        const a = messaging.broadcastChannel('bc-self');
        const b = messaging.broadcastChannel('bc-self');
        b.on('message', () => console.log('b got'));
        console.log('result', a.postMessage({p: b}, [b]));
        setTimeout(() => {
          a.close();
          console.log('end');
        }, 40);
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("result true"),
        "the post reports success, not a delivery: {stdout:?}"
    );
    assert!(
        !stdout.contains("b got"),
        "the transferred destination must not receive the message: {stdout:?}"
    );
    assert!(
        stderr.contains(
            "The target port was posted to itself, and the communication channel was lost"
        ),
        "the warning has to name the lost channel: {stderr:?}"
    );
}

#[test]
fn a_named_group_keeps_its_survivor_open_but_an_anonymous_one_does_not() {
    // `SiblingGroup::Disentangle` closes the last peer only when `name_.empty()`.
    // A `BroadcastChannel` group is named, so closing one member must leave the
    // rest usable — and a name must still deliver after every earlier member on it
    // closed, which is what the second pair proves.
    let (code, stdout, stderr) = run_file(
        "bc-survivor",
        "const {BroadcastChannel} = require('worker_threads');
        const a = new BroadcastChannel('bc-survivor');
        const b = new BroadcastChannel('bc-survivor');
        let aClosed = false;
        let aMessages = [];
        a.onmessage = (e) => aMessages.push(e.data);
        a.addEventListener('close', () => { aClosed = true; });
        b.close();
        setTimeout(() => {
          console.log('a closed after b.close:', aClosed);
          const c = new BroadcastChannel('bc-survivor');
          c.onmessage = (e) => {
            console.log('fresh channel on the reused name saw', e.data);
            a.close();
            c.close();
          };
          a.postMessage('after-reuse');
        }, 20);
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        concat!(
            "a closed after b.close: false",
            "\n",
            "fresh channel on the reused name saw after-reuse",
        ),
    );
}

#[test]
fn posting_on_a_closed_channel_throws_the_state_error_node_throws() {
    // `io.js:444` raises `new DOMException('BroadcastChannel is closed.',
    // 'InvalidStateError')` when its handle is gone, and `undefined` from the
    // handle becomes `new DOMException('Message could not be posted.')`. Both are
    // ordinary state errors rather than crashes, so the class and name are the
    // whole contract.
    expect(
        "const {BroadcastChannel} = require('worker_threads');
        const a = new BroadcastChannel('bc-closed');
        const b = new BroadcastChannel('bc-closed');
        try { a.postMessage('x') } catch (e) { console.log('open:', e.name) }
        a.close();
        try { a.postMessage('y') }
        catch (e) { console.log('closed:', e.name, e.constructor.name,
                               JSON.stringify(e.message)) }
        b.close();",
        "closed: InvalidStateError DOMException \"BroadcastChannel is closed.\"",
    );
}

#[test]
fn a_ref_d_channel_pins_the_process_and_unref_releases_it() {
    // `ref`/`unref` are Node-specific extensions of the standard interface
    // (`io.js:450-479`), and the pair is only observable as a *pair*: asserting
    // just the `unref` half passes on a tree where a channel pins nothing at all,
    // which is the state this member was in while it threw on construction. So
    // both halves are run, and the ref'd one must be killed by the deadline of its
    // own accord.
    //
    // Neither case calls `process.exit()`: a script that does cannot prove the
    // process ended on its own, which is the whole question here.
    let (exited, elapsed) = run_with_deadline(
        "bc-unref",
        "const {BroadcastChannel} = require('worker_threads');
        const c = new BroadcastChannel('bc-unref');
        c.onmessage = () => {};
        c.unref();
        console.log('unrefed');",
        std::time::Duration::from_secs(10),
    );
    assert!(exited, "an unref'd channel must not hold the loop open");
    assert!(
        elapsed < 5_000,
        "it must exit promptly, not at the deadline: {elapsed}ms"
    );

    let (exited, elapsed) = run_with_deadline(
        "bc-ref",
        "const {BroadcastChannel} = require('worker_threads');
        const c = new BroadcastChannel('bc-ref');
        c.onmessage = () => {};
        c.ref();
        console.log('refed');",
        std::time::Duration::from_secs(3),
    );
    assert!(
        !exited,
        "a ref'd channel with a listener pins the loop, so it must not exit; \
         it finished after {elapsed}ms"
    );
}

// ------------------------------------------------- messaging.moveMessagePortToContext --

#[test]
fn move_message_port_to_context_rehomes_the_port_into_the_target_realm() {
    // The member was an exported property whose value was `undefined`, because
    // `lib/worker_threads.js:21` destructures it: so `typeof` feature detection
    // silently took the wrong branch instead of seeing an honest absence.
    //
    // The observable shape is the realm swap. Node builds the new port from
    // *that context's* instance template, so its prototype is the target realm's
    // `MessagePort.prototype` and is therefore not this realm's — that, plus the
    // three own method names, is what the oracle prints.
    expect(
        "const vm = require('vm');
        const {MessageChannel, moveMessagePortToContext, MessagePort} =
          require('worker_threads');
        const context = vm.createContext({});
        const {port1, port2} = new MessageChannel();
        const moved = moveMessagePortToContext(port1, context);
        console.log(typeof moved, moved.constructor.name, moved === port1);
        console.log(JSON.stringify(Object.getOwnPropertyNames(Object.getPrototypeOf(moved))));
        console.log(moved.constructor === MessagePort);
        port1.close();
        port2.close();",
        concat!(
            "object MessagePort false",
            "\n",
            "[\"postMessage\",\"start\",\"constructor\"]",
            "\n",
            "false",
        ),
    );
}

#[test]
fn a_moved_port_keeps_the_queue_and_the_old_handle_goes_inert() {
    // The queue moves with the port, so a message posted to the peer before the
    // move is still readable through the new object. The old handle is *detached*,
    // not closed: `MessagePort::PostMessage` serializes and returns `true` and
    // dispatches nothing, so the peer must not see it. Getting that wrong is
    // silent — the message simply arrives twice, once from each handle.
    let (code, stdout, stderr) = run_file(
        "move-port-queue",
        "const vm = require('vm');
        const {MessageChannel, moveMessagePortToContext, receiveMessageOnPort} =
          require('worker_threads');
        const context = vm.createContext({});
        const {port1, port2} = new MessageChannel();
        port2.postMessage('queued-before');
        const moved = moveMessagePortToContext(port1, context);
        const peerHeard = [];
        port2.on('message', (m) => peerHeard.push(m));
        setTimeout(() => {
          console.log('drained:', JSON.stringify(receiveMessageOnPort(moved)));
          console.log('old handle post:', port1.postMessage('from-old-handle'));
          moved.postMessage('from-moved');
          setTimeout(() => {
            console.log('peer heard:', JSON.stringify(peerHeard));
            moved.close();
            port2.close();
          }, 20);
        }, 20);
        ",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        concat!(
            r#"drained: {"message":"queued-before"}"#,
            "\n",
            "old handle post: true",
            "\n",
            r#"peer heard: ["from-moved"]"#,
        ),
        "the queue must follow the move and the old handle must not deliver"
    );
}

#[test]
fn move_message_port_to_context_validates_its_arguments_as_node_does() {
    // `MessagePort::MoveToContext` throws `ERR_INVALID_ARG_TYPE` for a bad port and
    // for a bad context, and `ERR_CLOSED_MESSAGE_PORT` for a closed one. The codes
    // matter more than the wording: `lib/**` and user `catch` blocks branch on
    // them, and an `undefined` export threw an unrelated
    // `TypeError: moveMessagePortToContext is not a function` instead.
    expect(
        "const vm = require('vm');
        const {MessageChannel, moveMessagePortToContext} = require('worker_threads');
        const context = vm.createContext({});
        const {port1, port2} = new MessageChannel();
        const cases = [
          ['no args', () => moveMessagePortToContext()],
          ['bad port', () => moveMessagePortToContext({}, context)],
          ['bad context', () => moveMessagePortToContext(port1, {})],
          ['no context', () => moveMessagePortToContext(port1)],
        ];
        for (const [label, call] of cases) {
          try { call(); console.log(label, 'did not throw'); }
          catch (e) { console.log(label, e.name, e.code); }
        }
        port1.close();
        try { moveMessagePortToContext(port1, context); }
        catch (e) { console.log('closed port', e.name, e.code); }
        port2.close();",
        concat!(
            "no args TypeError ERR_INVALID_ARG_TYPE\n",
            "bad port TypeError ERR_INVALID_ARG_TYPE\n",
            "bad context TypeError ERR_INVALID_ARG_TYPE\n",
            "no context TypeError ERR_INVALID_ARG_TYPE\n",
            "closed port Error ERR_CLOSED_MESSAGE_PORT",
        ),
    );
}

#[test]
fn a_listener_less_port_keeps_its_queue_for_receive_message_on_port() {
    // Node's `ReceiveMessage` has a `wants_message` gate: a port that is not
    // receiving consumes a queued entry only when the front is a close marker, so
    // anything else stays for `receiveMessageOnPort`. This is not about
    // `BroadcastChannel`, but the move tests depend on it and #148 removed the gate
    // when it rewrote `deliver` — so a port that had never been started silently
    // drained its queue on the next turn, and `receiveMessageOnPort` then answered
    // `undefined` where Node answers with the message.
    expect(
        "const {MessageChannel, receiveMessageOnPort} = require('worker_threads');
        const {port1, port2} = new MessageChannel();
        port1.postMessage('kept');
        console.log('synchronously:', JSON.stringify(receiveMessageOnPort(port2)));
        port1.postMessage('no-listener');
        setTimeout(() => {
          console.log('after a turn:', JSON.stringify(receiveMessageOnPort(port2)));
          port1.close();
          port2.close();
        }, 20);",
        concat!(
            r#"synchronously: {"message":"kept"}"#,
            "\n",
            r#"after a turn: {"message":"no-listener"}"#,
        ),
    );
}
