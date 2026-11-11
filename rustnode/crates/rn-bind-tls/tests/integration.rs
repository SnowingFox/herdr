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
//! # Why a subprocess rather than an in-process isolate
//!
//! The binary already owns the whole startup sequence: the builtin loader, the
//! realm, the binding registry. Reproducing it in a unit test would test the test.
//! The acceptance for this increment is stated in terms of what the binary does
//! (`require('tls')` loads, `createSecureContext()` works, a `TLSSocket` reaches a
//! legible failure), so it is checked where it is observable.

use std::process::Command;

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
    let output = Command::new(binary())
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

/// `new tls.TLSSocket()` reaches a legible failure naming the increment that will
/// make it work, rather than a missing-binding error.
///
/// This is the third acceptance the plan states, and the shape of the failure is
/// part of it: `ERR_TLS_NOT_IMPLEMENTED` with an increment number is a report, and
/// `internalBinding('tls_wrap'): ...` would be the state before this crate.
#[test]
fn a_tls_socket_fails_legibly() {
    let script = "\
        const tls = require('tls'); \
        try { new tls.TLSSocket(); console.log('CONSTRUCTED'); } \
        catch (e) { console.log(e.code + '|' + e.message); }";
    let (stdout, stderr, ok) = run(script);
    assert!(ok, "the construction must fail catchably; stderr: {stderr}");
    let line = stdout.trim();
    assert!(
        line.starts_with("ERR_TLS_NOT_IMPLEMENTED|"),
        "the failure must name this crate's gap; got {line}"
    );
    assert!(
        line.contains("tls_wrap increment"),
        "the failure must name the increment that lands it; got {line}"
    );
    assert!(
        !line.contains("no Rust implementation"),
        "the missing-binding error must be gone; got {line}"
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
