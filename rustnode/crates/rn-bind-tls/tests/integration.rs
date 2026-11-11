//! End-to-end checks against the real binary.
//!
//! The unit tests in `src/**` cover the state types and the tables. This file is
//! the part they cannot reach: that the namespace is installed in a real isolate,
//! that every name in [`rn_bind_tls::wrap::PROTO_METHODS`] and
//! [`rn_bind_tls::wrap::STREAM_METHODS`] actually landed on the prototype, and
//! that `wrap()` builds a working `TLSWrap` from a real `SecureContext`.
//!
//! It runs `target/debug/rustnode`, which `tools/check.sh` builds before the test
//! sweep for exactly this reason — a stale binary here would test the previous
//! landing.
//!
//! # Every TLS test here also asserts that the process exits
//!
//! An earlier version of this file asserted values and nothing else, and that hid
//! the defect that mattered most: the handshake worked, data crossed, and the
//! process then hung forever. A TLS stack that cannot let a process exit hangs
//! every `test-tls-*` file it would otherwise pass, so `run_tls` bounds the run and
//! every caller checks the exit status. `tools/tls-exit-control.sh` is the same
//! property as a standalone control with a negative case.
//!
//! # Why a subprocess rather than an in-process isolate
//!
//! The binary already owns the whole startup sequence: the builtin loader, the
//! realm, the binding registry. Reproducing it in a unit test would test the test.
//! The acceptance for this increment is stated in terms of what the binary does
//! (`require('tls')` loads, `createSecureContext()` works, a `TLSSocket` reaches a
//! legible failure), so it is checked where it is observable.

use std::process::Command;

/// Runs a TLS script that must exit on its own within a few seconds.
///
/// `run` already bounds the run with `timeout 20`, which is right for the scripted
/// assertions but too generous to distinguish "finished" from "hung". A correct TLS
/// teardown finishes in well under a second, so this insists on it: a process that
/// needs 20 seconds to exit is the bug, not a slow machine.
///
/// Returns `(stdout, stderr, exit_code)`.
fn run_tls(script: &str) -> (String, String, i32) {
    let output = Command::new("timeout")
        .arg("6")
        .arg(binary())
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary runs");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// A self-signed key/certificate pair, generated once per test process.
///
/// Generated rather than committed: a private key in the repository is a secret
/// even when it is a test fixture, and `openssl req` is already a dependency of
/// every environment that builds this crate (it is what `openssl-src` compiles).
/// Written to a temp dir so parallel test binaries do not collide.
fn certificate() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    use std::sync::OnceLock;
    static PATHS: OnceLock<Option<(std::path::PathBuf, std::path::PathBuf)>> = OnceLock::new();
    PATHS
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("rn-bind-tls-{}", std::process::id()));
            std::fs::create_dir_all(&dir).ok()?;
            let key = dir.join("key.pem");
            let cert = dir.join("cert.pem");
            if key.exists() && cert.exists() {
                return Some((key, cert));
            }
            let status = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    key.to_str()?,
                    "-out",
                    cert.to_str()?,
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok()?;
            if status.success() {
                Some((key, cert))
            } else {
                None
            }
        })
        .clone()
}

/// The binary `tools/check.sh` builds before the test sweep.
///
/// `CARGO_BIN_EXE_*` only exists for a binary target of the *same* crate, and
/// `rustnode` belongs to `rn-cli`. The gate builds it explicitly for this reason:
/// several crates' integration tests spawn it, and `cargo test -p <crate>` does
/// not rebuild it. The path is resolved from `CARGO_MANIFEST_DIR` so the test
/// works from any working directory.
fn binary() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/rustnode")
}

/// Runs a script and returns `(stdout, stderr, success)`.
fn run(script: &str) -> (String, String, bool) {
    // A `TLSWrap` that leaves the loop with work to do hangs instead of exiting,
    // which is exactly the R4 failure mode. A timeout turns that into a failed
    // assertion rather than a blocked test suite.
    let output = Command::new("timeout")
        .arg("20")
        .arg(binary())
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary runs");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.success(),
    )
}

/// `require('tls')` completes, which is the acceptance the plan states first.
///
/// Before this crate existed the line threw
/// `internalBinding('tls_wrap'): the namespace has no Rust implementation yet`.
#[test]
fn require_tls_loads() {
    let (stdout, stderr, ok) = run("require('tls'); console.log('loaded');");
    assert!(ok, "require('tls') must succeed; stderr: {stderr}");
    assert!(
        stdout.contains("loaded"),
        "the script must reach its own log; stdout: {stdout}, stderr: {stderr}"
    );
}

/// `tls.createSecureContext()` works, which is the second acceptance.
#[test]
fn create_secure_context_works() {
    let (stdout, stderr, ok) = run("const tls = require('tls'); \
         const c = tls.createSecureContext(); \
         console.log(typeof c.context);");
    assert!(ok, "createSecureContext must succeed; stderr: {stderr}");
    assert!(
        stdout.contains("object"),
        "the native context must be an object; stdout: {stdout}"
    );
}

/// The namespace has exactly the five members `TLSWrap::Initialize` installs.
#[test]
fn the_namespace_has_its_five_members() {
    let (stdout, stderr, ok) = run("const b = process.binding('tls_wrap'); \
         console.log(Object.keys(b).sort().join(','));");
    assert!(ok, "the namespace must install; stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "HAVE_SSL_TRACE,TLSWrap,hasOpenSSLErrorForTesting,injectOpenSSLErrorForTesting,wrap",
        "the member set is Initialize's"
    );
}

/// Every prototype method this crate installs is present, and `wrap.js`'s
/// module-scope assignments succeed.
///
/// `wrap.js` does `tls_wrap.TLSWrap.prototype[proxiedMethod] = ...` and
/// `tls_wrap.TLSWrap.prototype.close = ...` while the module loads, so a
/// prototype that rejected assignment would break `require('tls')` — which the
/// first test already covers. This checks the reverse direction: that the names
/// the C++ list contains are all there.
#[test]
fn the_prototype_carries_every_installed_name() {
    let names = rn_bind_tls::wrap::PROTO_METHODS.join(",");
    let stream_methods = rn_bind_tls::wrap::STREAM_METHODS.join(",");
    let accessors = rn_bind_tls::wrap::STREAM_ACCESSORS.join(",");
    let script = format!(
        "const b = process.binding('tls_wrap'); \
         const p = b.TLSWrap.prototype; \
         const missing = []; \
         for (const n of '{names}'.split(',')) if (typeof p[n] !== 'function') missing.push(n); \
         for (const n of '{stream_methods}'.split(',')) if (typeof p[n] !== 'function') missing.push(n); \
         for (const n of '{accessors}'.split(',')) if (!(n in p)) missing.push(n); \
         if (!('writeQueueSize' in p)) missing.push('writeQueueSize'); \
         if (!('onread' in p)) missing.push('onread'); \
         console.log(missing.length ? 'MISSING:' + missing.join(',') : 'ALL-PRESENT');"
    );
    let (stdout, stderr, ok) = run(&script);
    assert!(ok, "the prototype check must run; stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "ALL-PRESENT",
        "every listed name must be on the prototype; stderr: {stderr}"
    );
}

/// A `TLSWrap` built from a real `TCP` handle and a real `SecureContext` answers
/// the state queries this increment implements.
#[test]
fn wrap_builds_a_working_tls_wrap() {
    let script = "\
        const net = require('net'); \
        const tls = require('tls'); \
        const tcp = process.binding('tcp_wrap'); \
        const h = new tcp.TCP(tcp.constants.SOCKET); \
        const ctx = tls.createSecureContext(); \
        const W = process.binding('tls_wrap'); \
        const res = W.wrap(h, ctx.context, false, false); \
        console.log([ \
          res.isStreamBase === true, \
          res.verifyError() === 0, \
          res.getServername() === null, \
          res.isSessionReused() === false, \
          res.writeQueueSize === 0, \
          typeof res.getProtocol() === 'string', \
          typeof res.destroySSL === 'function', \
        ].join(','));";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "wrap() must succeed on a real handle; stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "true,true,true,true,true,true,true",
        "every answer must match what the state says; stderr: {stderr}"
    );
}

/// `destroySSL` is idempotent, which is what makes it reachable from `close()`,
/// the `'close'` handler and the finalizer without a double free (R1).
#[test]
fn destroy_ssl_is_idempotent() {
    let script = "\
        const tls = require('tls'); \
        const tcp = process.binding('tcp_wrap'); \
        const h = new tcp.TCP(tcp.constants.SOCKET); \
        const ctx = tls.createSecureContext(); \
        const W = process.binding('tls_wrap'); \
        const res = W.wrap(h, ctx.context, false, false); \
        res.destroySSL(); \
        res.destroySSL(); \
        console.log('ok');";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "a second destroySSL must not crash; stderr: {stderr}");
    assert_eq!(stdout.trim(), "ok");
}

/// `wrap()` rejects a context that is not a `SecureContext`, and reports
/// `ERR_TLS_INVALID_CONTEXT` — the code `wrap.js:833` throws for the same case.
#[test]
fn wrap_rejects_a_non_context() {
    let script = "\
        const tcp = process.binding('tcp_wrap'); \
        const h = new tcp.TCP(tcp.constants.SOCKET); \
        const W = process.binding('tls_wrap'); \
        try { W.wrap(h, {}, false, false); } \
        catch (e) { console.log(e.code); }";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "the throw must be catchable; stderr: {stderr}");
    assert_eq!(stdout.trim(), "ERR_TLS_INVALID_CONTEXT");
}

/// A closed `SecureContext` has no `SSL_CTX`, so `wrap()` reports the same code a
/// real `node` does rather than crashing on a freed pointer.
#[test]
fn wrap_rejects_a_closed_context() {
    let script = "\
        const tls = require('tls'); \
        const tcp = process.binding('tcp_wrap'); \
        const h = new tcp.TCP(tcp.constants.SOCKET); \
        const ctx = tls.createSecureContext(); \
        ctx.context.close(); \
        const W = process.binding('tls_wrap'); \
        try { W.wrap(h, ctx.context, false, false); } \
        catch (e) { console.log(e.code); }";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "the throw must be catchable; stderr: {stderr}");
    assert_eq!(stdout.trim(), "ERR_TLS_INVALID_CONTEXT");
}

/// `new tls.TLSSocket()` **constructs**, which increment 3 reached.
///
/// In increment 1 this threw `ERR_TLS_NOT_IMPLEMENTED` naming `setVerifyMode`.
/// Increment 3 implemented that and the handshake, so the constructor now
/// completes and produces a real `TLSWrap` handle.
///
/// The assertion is on the shape rather than on a throw, because "a `TLSSocket`
/// can be built" is the milestone: it is the first thing `lib/tls.js` does, and a
/// throw here made every `test-tls-*` file fail at `tls.connect`.
#[test]
fn a_tls_socket_constructs() {
    let script = "\
        const tls = require('tls'); \
        const s = new tls.TLSSocket(); \
        console.log([ \
          !!s._handle, \
          !!s.ssl, \
          s._handle.isStreamBase === true, \
          typeof s._handle.start === 'function', \
          typeof s._handle.getCipher === 'function', \
        ].join(','));";
    let (stdout, stderr, ok) = run(script);
    assert!(
        ok,
        "constructing a TLSSocket must succeed; stderr: {stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "true,true,true,true,true",
        "a TLSSocket must hold a real TLSWrap; stderr: {stderr}"
    );
}

/// A TLS connection whose `host` is an **IP literal** still does not let the
/// process exit, and this test records that rather than hiding it.
///
/// Every event completes — `secureConnect`, `'data'`, `'end'`, `'close'` and the
/// `server.close()` callback — and the loop still reports a **referenced, active
/// timer** afterwards. Measured with `uv_walk`:
///
/// | `host` | exits | timers after close |
/// | --- | --- | --- |
/// | omitted | yes, ~70ms | all `active=0` |
/// | `'localhost'` | yes, ~85ms | all `active=0` |
/// | `'127.0.0.1'` | **no** | one `active=1` |
///
/// So the difference is the address-literal branch of `net.connect`, not the TLS
/// handshake: an IP skips `dns.lookup` and completes the connect from
/// `_handle.connect` directly. `handshakeTimeout: 0` also makes it exit, which
/// points at the handshake timer being armed a second time on that branch and
/// never cleared, after `_finishInit` cleared the first one.
///
/// The `#[ignore]` is deliberate: the assertion is the *desired* behaviour, and it
/// fails today. Removing the attribute is the definition of done for this gap.
#[test]
#[ignore = "an IP-literal host leaves a referenced timer armed after close; the \
            handshake and all events succeed, the process just never exits"]
fn an_ip_literal_host_lets_the_process_exit() {
    let Some((key, cert)) = certificate() else {
        return;
    };
    let script = format!(
        "\
        const tls = require('tls'); \
        const fs = require('fs'); \
        const opts = {{ \
          key: fs.readFileSync('{key}'), \
          cert: fs.readFileSync('{cert}'), \
        }}; \
        const server = tls.createServer(opts, (sock) => sock.end('x')); \
        server.listen(0, '127.0.0.1', () => {{ \
          const c = tls.connect( \
            {{ port: server.address().port, host: '127.0.0.1', rejectUnauthorized: false }}); \
          c.on('data', () => {{ c.end(); server.close(() => console.log('CLOSED')); }}); \
        }});",
        key = key.display(),
        cert = cert.display()
    );
    let (stdout, _stderr, code) = run_tls(&script);
    assert_eq!(code, 0, "the process must exit; stdout: {stdout}");
    assert!(stdout.contains("CLOSED"), "stdout: {stdout}");
}

/// A TLS connection lets the process exit, and `server.close()` reaches its
/// callback.
///
/// This is the property PR #62 was missing: every other test asserts a value, so a
/// process that decrypts correctly and then hangs forever passed all of them.
///
/// `CLOSED` is printed from inside the `server.close()` callback, so it cannot
/// appear unless the listening handle *and* the accepted socket really closed. An
/// exited-but-not-closed process prints nothing and fails on the code, and a hung
/// one is killed by `run_tls`'s timeout and fails on the code too.
#[test]
fn a_tls_connection_lets_the_process_exit() {
    let Some((key, cert)) = certificate() else {
        return;
    };
    let script = format!(
        "\
        const tls = require('tls'); \
        const fs = require('fs'); \
        const opts = {{ \
          key: fs.readFileSync('{key}'), \
          cert: fs.readFileSync('{cert}'), \
        }}; \
        const server = tls.createServer(opts, (s) => {{ s.end('x'); }}); \
        server.on('tlsClientError', (e) => console.log('S:ERR ' + e.message)); \
        server.listen(0, () => {{ \
          const c = tls.connect( \
            {{ port: server.address().port, rejectUnauthorized: false }}, \
            () => {{ \
              c.on('data', () => {{ \
                c.end(); \
                server.close(() => console.log('CLOSED')); \
              }}); \
            }}); \
          c.on('error', (e) => console.log('C:ERR ' + e.message)); \
        }});",
        key = key.display(),
        cert = cert.display()
    );
    let (stdout, stderr, code) = run_tls(&script);
    assert_eq!(
        code, 0,
        "the process must exit 0 within 6s; got {code}. stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stdout.contains("CLOSED"),
        "server.close() must reach its callback; stdout: {stdout}"
    );
    assert!(
        !stdout.contains("S:ERR") && !stdout.contains("C:ERR"),
        "no side may report an error; stdout: {stdout} stderr: {stderr}"
    );
}

/// A full TLS 1.3 handshake completes between a client and a server in one
/// process, and `secureConnect` fires.
///
/// This is the acceptance the plan sets for the handshake: not a test-file count,
/// but "the handshake actually runs". It is checked end to end because every
/// intermediate step is reachable — the record exchange, the info callback,
/// `getProtocol`, `getCipher` and `getEphemeralKeyInfo` are all on the path, and
/// any one of them throwing stops `secureConnect` after OpenSSL has already
/// finished.
#[test]
fn a_tls13_handshake_completes() {
    let Some((key, cert)) = certificate() else {
        // No `openssl` on the machine: the fixture cannot be built, so the
        // handshake is not asserted here. `tools/check.sh`'s TLS control covers
        // it in an environment that has the tool.
        return;
    };
    let script = format!(
        "\
        const tls = require('tls'); \
        const fs = require('fs'); \
        const opts = {{ \
          key: fs.readFileSync('{key}'), \
          cert: fs.readFileSync('{cert}'), \
        }}; \
        const server = tls.createServer(opts, (sock) => sock.end('x')); \
        server.on('tlsClientError', (e) => console.log('S:ERR ' + e.message)); \
        server.listen(0, '127.0.0.1', () => {{ \
          const c = tls.connect( \
            {{ port: server.address().port, host: 'localhost', rejectUnauthorized: false }}, \
            () => {{ \
              console.log('SECURE:' + c.getProtocol() + ':' + c.getCipher().name); \
            }}); \
          c.on('data', () => {{ c.end(); server.close(() => console.log('CLOSED')); }}); \
          c.on('error', (e) => {{ console.log('C:ERR ' + e.message); server.close(); }}); \
        }});",
        key = key.display(),
        cert = cert.display()
    );
    let (stdout, stderr, code) = run_tls(&script);
    assert_eq!(
        code, 0,
        "the handshake must finish and the process exit; got {code}.\nscript:\n{script}\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("SECURE:TLSv1.3:"),
        "the handshake must complete with a cipher; got {stdout}, stderr: {stderr}"
    );
    assert!(
        !stdout.contains("C:ERR") && !stdout.contains("S:ERR"),
        "no side may report an error; got {stdout}"
    );
}

/// Application data crosses a TLS connection and is decrypted on the server.
///
/// This is the read/write path end to end: `writeBuffer` → `SSL_write` →
/// `EncOut` → the socket → the peer's listener → `ClearOut` → `SSL_read` →
/// `onread`. A one-way check is enough to prove the encryption, the record
/// framing and the listener direction are all correct.
#[test]
fn application_data_crosses_the_connection() {
    let Some((key, cert)) = certificate() else {
        return;
    };
    let script = format!(
        "\
        const tls = require('tls'); \
        const fs = require('fs'); \
        const opts = {{ \
          key: fs.readFileSync('{key}'), \
          cert: fs.readFileSync('{cert}'), \
        }}; \
        const server = tls.createServer(opts, (sock) => {{ \
          sock.on('data', (d) => {{ \
            console.log('GOT:' + d.toString()); \
            sock.end(); \
          }}); \
        }}); \
        server.listen(0, '127.0.0.1', () => {{ \
          const c = tls.connect( \
            {{ port: server.address().port, host: 'localhost', rejectUnauthorized: false }}, \
            () => c.write('hello over tls')); \
          c.on('close', () => server.close()); \
        }});",
        key = key.display(),
        cert = cert.display()
    );
    let (stdout, stderr, code) = run_tls(&script);
    assert_eq!(
        code, 0,
        "the data must cross and the process exit; got {code}. stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stdout.contains("GOT:hello over tls"),
        "the server must decrypt the payload; stdout: {stdout} stderr: {stderr}"
    );
}

/// The two testing hooks behave as the namespace members Node defines.
#[test]
fn the_error_queue_hooks_work() {
    let script = "\
        const W = process.binding('tls_wrap'); \
        W.injectOpenSSLErrorForTesting(); \
        const after = W.hasOpenSSLErrorForTesting(); \
        console.log(after);";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "the hooks must run; stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "true",
        "an injected error must be observable; stderr: {stderr}"
    );
}

/// `readStart` and `readStop` reach the underlying stream (increment 2).
///
/// On an unconnected socket libuv reports `UV_ENOTCONN` (-107), which is the same
/// code a real `node` returns for `readStart` before `connect`. On a connected one
/// it is 0. Both are checked, because the difference between "the method works"
/// and "the method returns a plausible number" is which code comes back where.
#[test]
fn read_start_and_stop_reach_the_underlying_stream() {
    let script = "\
        const tls = require('tls'); \
        const tcp = process.binding('tcp_wrap'); \
        const h = new tcp.TCP(tcp.constants.SOCKET); \
        const ctx = tls.createSecureContext(); \
        const W = process.binding('tls_wrap'); \
        const res = W.wrap(h, ctx.context, false, false); \
        console.log(res.readStart() + ',' + res.readStop()); \
        res.destroySSL();";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "readStart must not throw; stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "-107,0",
        "an unconnected socket reports UV_ENOTCONN from readStart and 0 from \
         readStop; stderr: {stderr}"
    );
}

/// A wrapped **connected** socket reports `0` from `readStart`, and the process
/// exits cleanly afterwards.
///
/// The clean exit is the R4 assertion: a `TLSWrap` with nothing pending must not
/// hold a ref, or the loop never drains and the process hangs — which is the
/// failure `spawn_sync` already paid for.
#[test]
fn a_connected_socket_reads_and_tears_down_cleanly() {
    let script = "\
        const net = require('net'); \
        const tls = require('tls'); \
        const server = net.createServer((sock) => sock.end()); \
        server.listen(0, '127.0.0.1', () => { \
          const port = server.address().port; \
          const s = net.connect(port, '127.0.0.1', () => { \
            const ctx = tls.createSecureContext(); \
            const W = process.binding('tls_wrap'); \
            const res = W.wrap(s._handle, ctx.context, false, false); \
            console.log('start=' + res.readStart()); \
            console.log('queue=' + res.writeQueueSize); \
            res.destroySSL(); \
            s.destroy(); \
            server.close(); \
            console.log('clean'); \
          }); \
        });";
    let (stdout, stderr, ok) = run(script);
    assert!(
        ok,
        "the connected-socket path must succeed; stderr: {stderr}"
    );
    let out = stdout.trim();
    assert!(
        out.contains("start=0"),
        "readStart on a connected socket must be 0; got {out}"
    );
    assert!(out.contains("queue=0"), "nothing is queued; got {out}");
    assert!(
        out.contains("clean"),
        "the process must reach its own last line, which proves the loop \
         drained; got {out}"
    );
}

/// `receive()` injects ciphertext into the wrap without a listener.
///
/// `wrap.js`'s `initRead` uses it for bytes the socket buffered before the wrap
/// existed. On a fresh wrap with no handshake there is nothing to decrypt, so the
/// assertion is that the call is accepted and the state survives it — a throw
/// here would break `initRead` for every socket that arrives with data buffered.
#[test]
fn receive_accepts_injected_ciphertext() {
    let script = "\
        const tls = require('tls'); \
        const tcp = process.binding('tcp_wrap'); \
        const h = new tcp.TCP(tcp.constants.SOCKET); \
        const ctx = tls.createSecureContext(); \
        const W = process.binding('tls_wrap'); \
        const res = W.wrap(h, ctx.context, false, false); \
        res.receive(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05])); \
        console.log('accepted'); \
        res.destroySSL();";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "receive must not throw; stderr: {stderr}");
    assert_eq!(stdout.trim(), "accepted");
}
