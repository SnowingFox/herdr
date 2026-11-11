//! End-to-end checks through a real V8 isolate, and the shape of the shell.
//!
//! # Why one test with many cases
//!
//! V8's platform and global state are process-wide and can only be initialised
//! once, so every JavaScript case runs from a single `#[test]`. A second isolate
//! in a second test would panic on the already-initialised platform, which is why
//! `rn-bind-crypto`, `rn-bind-zlib` and `rn-bind-crypto-cipher` are laid out the
//! same way.
//!
//! # What this proves and what it does not
//!
//! It proves the class exists, constructs, is `instanceof`-checkable, has every
//! prototype method Node installs, and that the real methods reach OpenSSL while
//! the stubs throw. It does **not** prove TLS works: there is no handshake here,
//! because `tls_wrap` does not exist yet. The probe script
//! `tools/secure-context-probe.js` makes the same distinction and says so.

use crate::{install_classes, Context, ContextError, MEMBERS, NAMESPACE_STUBS, STUBS};
use rn_v8_sys::v8;

/// Runs `source` in the isolate, returning its value as a string or the thrown
/// exception's message.
///
/// The `TryCatch` is required, not incidental: without one a thrown exception
/// leaves the isolate dirty and every later case fails for an unrelated reason,
/// which would make a single genuine failure look like a cascade.
fn eval(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let Some(text) = v8::String::new(scope, source) else {
        return "<cannot allocate source>".to_string();
    };
    let value = v8::Script::compile(scope, text, None).and_then(|script| script.run(scope));
    if scope.has_caught() || value.is_none() {
        return format!(
            "THREW: {}",
            scope
                .exception()
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "<no exception>".to_string())
        );
    }
    value
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "<not a value>".to_string())
}

#[test]
fn secure_context_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    // The class lands on a plain object here rather than on `rn-bind-crypto`'s
    // namespace, because installing that whole namespace would pull in every
    // other member and make a `SecureContext` failure look like a hashing one.
    let target = v8::Object::new(scope);
    install_classes(scope, target).expect("install SecureContext");

    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "binding").expect("allocate the binding name");
    global.set(scope, name.into(), target.into());

    // A bare isolate has no Node globals. `Buffer` is the only one the cases
    // need, so it is defined here over `Uint8Array` rather than pulling in
    // `lib/buffer.js`: everything under test is the binding.
    let prelude = r#"
        globalThis.Buffer = {
          from(arrayBuffer, offset, length) {
            const view = new Uint8Array(arrayBuffer, offset, length);
            view.toString = function (encoding) {
              if (encoding === 'hex') {
                return Array.from(this, (b) => b.toString(16).padStart(2, '0')).join('');
              }
              return String.fromCharCode.apply(null, this);
            };
            return view;
          },
        };
    "#;
    let _ = eval(scope, prelude);

    // A macro rather than a closure: the closure would have to borrow `failures`
    // mutably and `scope` mutably at the same call site, which cannot work, and
    // threading `failures` through explicitly at ~40 call sites is noise.
    let mut failures: Vec<String> = Vec::new();
    macro_rules! check {
        ($scope:expr, $name:expr, $source:expr, $want:expr $(,)?) => {{
            let got = eval($scope, $source);
            if got != $want {
                failures.push(format!("{}: want {:?}, got {:?}", $name, $want, got));
            }
        }};
    }

    // ---- (1) The class exists, constructs, and is instanceof-checkable -------
    check!(
        scope,
        "constructor exists",
        "typeof binding.SecureContext",
        "function",
    );
    check!(
        scope,
        "class name",
        "binding.SecureContext.name",
        "SecureContext",
    );
    check!(
        scope,
        "constructs",
        "new binding.SecureContext() instanceof binding.SecureContext",
        "true",
    );
    check!(
        scope,
        "independent instances",
        "new binding.SecureContext() instanceof binding.SecureContext && \
         (() => { const a = new binding.SecureContext(); const b = new binding.SecureContext(); \
                  return a !== b; })()",
        "true",
    );

    // Node installs 27 prototype methods plus the `_external` accessor. A
    // missing one makes `configSecureContext` throw
    // `TypeError: context.<x> is not a function`, which is a harder failure to
    // attribute than a stub that names itself.
    let expected_methods = [
        "init",
        "setKey",
        "setCert",
        "addCACert",
        "setAllowPartialTrustChain",
        "addCRL",
        "addRootCerts",
        "setCipherSuites",
        "setCiphers",
        "setSigalgs",
        "setECDHCurve",
        "setDHParam",
        "setMaxProto",
        "setMinProto",
        "getMaxProto",
        "getMinProto",
        "setOptions",
        "setSessionIdContext",
        "setSessionTimeout",
        "setCertificateCompression",
        "close",
        "loadPKCS12",
        "setTicketKeys",
        "enableTicketKeyCallback",
        "getTicketKeys",
        "getCertificate",
        "getIssuer",
    ];
    for method in expected_methods {
        check!(
            scope,
            &format!("method {method}"),
            &format!("typeof binding.SecureContext.prototype.{method}"),
            "function",
        );
    }
    // `_external` is an accessor, not a prototype method: a real `node` reports
    // `{ get, enumerable: true, configurable: false }` and reading it on the
    // prototype itself throws `TypeError` from the `Signature` check. Asserting
    // `typeof ... === 'function'` here would have been asserting a shape Node
    // does not have, which is what the first version of this test did.
    check!(
        scope,
        "_external is an accessor with a getter",
        "(() => { const d = Object.getOwnPropertyDescriptor(            binding.SecureContext.prototype, '_external');            return (typeof d.get) + '|' + d.enumerable + '|' + d.configurable; })()",
        "function|true|false",
    );
    check!(
        scope,
        "_external on the prototype throws (Signature guard)",
        "(() => { try { void binding.SecureContext.prototype._external; return 'no-throw'; }           catch (e) { return e.name; } })()",
        "TypeError",
    );
    check!(
        scope,
        "_external on an instance is an opaque object, as in Node",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0);           const ext = c._external;           return (typeof ext) + '|' + String(ext.constructor); })()",
        "object|undefined",
    );

    // The five ticket-key index constants.
    check!(
        scope,
        "kTicketKeyNameIndex",
        "binding.SecureContext.kTicketKeyNameIndex",
        "3",
    );

    // ---- (2) init on an uninitialised context is a coded error --------------
    check!(
        scope,
        "getMinProto before init",
        "(() => { try { new binding.SecureContext().getMinProto(); return 'no-throw'; } \
          catch (e) { return e.code; } })()",
        "ERR_CRYPTO_INVALID_STATE",
    );

    // ---- (3) init and the protocol range are real --------------------------
    check!(
        scope,
        "init accepts a range",
        "(() => { const c = new binding.SecureContext(); \
                  c.init(undefined, 0x0303, 0x0304); \
                  return c.getMinProto() + ':' + c.getMaxProto(); })()",
        "771:772",
    );
    check!(
        scope,
        "setMinProto/setMaxProto reach OpenSSL",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0x0304); \
                  c.setMinProto(0x0303); return c.getMinProto(); })()",
        "771",
    );
    check!(
        scope,
        "SSLv2 refused with Node's code",
        "(() => { try { new binding.SecureContext().init('SSLv2_method', 0, 0); \
                  return 'no-throw'; } catch (e) { return e.code + '|' + e.message; } })()",
        "ERR_TLS_INVALID_PROTOCOL_METHOD|SSLv2 methods disabled",
    );
    check!(
        scope,
        "unknown method refused",
        "(() => { try { new binding.SecureContext().init('TLSv9_method', 0, 0); \
                  return 'no-throw'; } catch (e) { return e.code + '|' + e.message; } })()",
        "ERR_TLS_INVALID_PROTOCOL_METHOD|Unknown method: TLSv9_method",
    );

    // ---- (4) the cipher and curve surface is real --------------------------
    check!(
        scope,
        "setCiphers/setCipherSuites accept a real list",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  c.setCipherSuites('TLS_AES_128_GCM_SHA256'); \
                  c.setCiphers('DEFAULT'); return 'ok'; })()",
        "ok",
    );
    check!(
        scope,
        "empty cipher list is the TLS1.3-only case",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  c.setCiphers(''); return 'ok'; })()",
        "ok",
    );
    check!(
        scope,
        "unknown cipher list errors",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  try { c.setCiphers('no-such-cipher'); return 'no-throw'; } \
                  catch (e) { return e.code; } })()",
        "ERR_CRYPTO_OPERATION_FAILED",
    );
    check!(
        scope,
        "setECDHCurve accepts auto and a named curve",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  c.setECDHCurve('auto'); c.setECDHCurve('prime256v1'); return 'ok'; })()",
        "ok",
    );
    check!(
        scope,
        "setSigalgs accepts a real algorithm",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  c.setSigalgs('RSA-PSS+SHA256'); return 'ok'; })()",
        "ok",
    );

    // ---- (5) ticket keys are 48 bytes and round-trip -----------------------
    check!(
        scope,
        "ticket keys are 48 bytes",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  return c.getTicketKeys().length; })()",
        "48",
    );
    check!(
        scope,
        "ticket keys round-trip",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  const keys = new Uint8Array(48).fill(0xab); \
                  const result = c.setTicketKeys(keys); \
                  const back = c.getTicketKeys(); \
                  return result + '|' + (back[0] === 0xab && back[47] === 0xab); })()",
        "true|true",
    );
    check!(
        scope,
        "a wrong-length ticket-key buffer is rejected",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  try { c.setTicketKeys(new Uint8Array(47)); return 'no-throw'; } \
                  catch (e) { return e.code; } })()",
        "ERR_INVALID_ARG_VALUE",
    );

    // ---- (6) the stubs throw instead of silently succeeding ----------------
    for (name, _) in STUBS {
        check!(
            scope,
            &format!("stub {name} throws"),
            &format!(
                "(() => {{ const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  try {{ c.{name}({}); return 'no-throw'; }} \
                  catch (e) {{ return e.code; }} }})()",
                stub_argument(name)
            ),
            "ERR_CRYPTO_UNSUPPORTED_OPERATION",
        );
    }

    // The root-certificate-store members are *namespace* functions in Node, not
    // prototype methods, so none of them may appear on the prototype. Asserting
    // absence is what pins the distinction: the first version of this crate
    // installed a throwing prototype method for one of them and this is the
    // check that fails when that comes back.
    for (name, _) in NAMESPACE_STUBS {
        check!(
            scope,
            &format!("{name} is not a prototype method"),
            &format!("typeof binding.SecureContext.prototype.{name}"),
            "undefined",
        );
    }

    // ---- (7) close is idempotent and releases ------------------------------
    check!(
        scope,
        "close twice then a method reports invalid state",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  c.close(); c.close(); \
                  try { c.getMinProto(); return 'no-throw'; } \
                  catch (e) { return e.code; } })()",
        "ERR_CRYPTO_INVALID_STATE",
    );

    // ---- (8) getCertificate/getIssuer are null before a cert is set --------
    check!(
        scope,
        "getCertificate is null without a cert",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  return String(c.getCertificate()); })()",
        "null",
    );
    check!(
        scope,
        "getIssuer is null without a cert",
        "(() => { const c = new binding.SecureContext(); c.init(undefined, 0, 0); \
                  return String(c.getIssuer()); })()",
        "null",
    );

    if !failures.is_empty() {
        panic!(
            "{} SecureContext case(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// The argument each stub takes, so the call reaches the body rather than
/// failing on an arity check.
fn stub_argument(name: &str) -> &'static str {
    match name {
        "setCertificateCompression" => "1",
        "loadPKCS12" => "new Uint8Array(0)",
        _ => "",
    }
}

/// `MEMBERS` is what the parent crate's partition needs, and `STUBS` must be a
/// subset of the members this crate installs.
#[test]
fn members_and_stubs_agree() {
    assert_eq!(MEMBERS, &["SecureContext"]);
    // Every stub is a real method, so a rename cannot silently leave a
    // deferral pointing at nothing.
    for (name, reason) in STUBS {
        assert!(!reason.is_empty(), "the {name} stub needs a written reason");
    }
    for (name, reason) in NAMESPACE_STUBS {
        assert!(
            !reason.is_empty(),
            "the {name} namespace deferral needs a written reason"
        );
    }
    // The two lists must not overlap: a member in both would be claimed as a
    // prototype stub and as a missing namespace member at once, which is the
    // mistake the first version of this crate made with
    // `getBundledRootCertificates`.
    for (name, _) in NAMESPACE_STUBS {
        assert!(
            !STUBS.iter().any(|(stub, _)| stub == name),
            "{name} is listed as both a prototype stub and a namespace deferral"
        );
    }
}

/// The `Context` surface used by the binding is exercised without V8 here, so a
/// failure names the operation rather than a JavaScript expression.
#[test]
fn context_state_machine() {
    let mut context = Context::default();
    assert!(matches!(
        context.ticket_keys(),
        Err(ContextError::NotInitialised)
    ));
    context.init(None, 0, 0).expect("init");
    assert_eq!(context.ticket_keys().expect("keys").len(), 48);
    context.close();
    assert!(matches!(
        context.ticket_keys(),
        Err(ContextError::NotInitialised)
    ));
}
