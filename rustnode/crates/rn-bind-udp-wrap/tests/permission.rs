//! The `net` permission checks `udp_wrap` makes, through a real V8 isolate.
//!
//! `src/udp_wrap.cc` differs from the stream handles in *how* it reports a
//! denial and in one extra gate, so the assertions here are about the shape as
//! much as the denial:
//!
//! * `DoBind` uses `ERR_ACCESS_DENIED_IF_INSUFFICIENT_PERMISSIONS`, so the error
//!   object is the **return value** and `lib/dgram.js` wraps it in an
//!   `ExceptionWithHostPort`;
//! * `DoConnect`, `Open` and `DoSend` use `THROW_IF_INSUFFICIENT_PERMISSIONS`
//!   with `UV_EACCES` as the return value, so the call throws and a caller that
//!   catches it sees a deny;
//! * `RecvStart` gates **once per handle** on `net_permission_granted_`, which a
//!   successful `bind`/`connect`/`open` also sets. A socket already let onto the
//!   network therefore keeps receiving after `process.permission.drop('net')`.

use rn_bind_udp_wrap::UdpWrap;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_permission::{runtime, PermissionConfig, PermissionModel, PermissionScope};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let scope = std::pin::pin!(v8::ContextScope::new(&mut scope, context));
    let mut scope = scope;
    body(&mut scope)
}

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = UdpWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the udp_wrap namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__udp").expect("allocating __udp");
    global.set(scope, key.into(), object.into());
}

fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let source = v8::String::new(scope, source).expect("allocating the probe");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let compiled = v8::Script::compile(scope, source, None);
    let Some(script) = compiled else {
        let message = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "unknown".to_string());
        return format!("threw: {message}");
    };
    match script.run(scope) {
        Some(result) => result.to_rust_string_lossy(scope),
        None => {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown".to_string());
            format!("threw: {message}")
        }
    }
}

fn eval_with(model: Option<PermissionModel>, source: &str) -> String {
    match model {
        Some(model) => {
            runtime::install(model);
        }
        None => runtime::clear(),
    }
    let report = with_context(|scope| {
        install(scope);
        run(scope, source)
    });
    runtime::clear();
    report
}

fn eval(source: &str) -> String {
    eval_with(None, source)
}

fn eval_denied(source: &str) -> String {
    eval_with(Some(PermissionModel::enforcing("/work")), source)
}

fn eval_allowed(source: &str) -> String {
    eval_with(
        Some(PermissionModel::with_cwd(
            "/work",
            PermissionConfig {
                allow_net: true,
                ..PermissionConfig::enforce()
            },
        )),
        source,
    )
}

const DESCRIBE: &str = "\
const describe = (value) => [
  value.code,
  value.permission,
  JSON.stringify(value.resource),
].join(',');\
";

#[test]
fn bind_returns_the_denial_naming_the_address() {
    // The error is the *return value*, not a throw: `lib/dgram.js` does
    // `if (err) { const ex = new ExceptionWithHostPort(err, 'bind', ...) }`.
    let report = eval_denied(&format!(
        r#"
        {DESCRIBE}
        const handle = new __udp.UDP();
        const result = handle.bind('127.0.0.1', 0, 0);
        handle.close();
        typeof result === 'number' ? 'status:' + result : describe(result)
        "#
    ));
    assert_eq!(
        report, r#"ERR_ACCESS_DENIED,Net,"127.0.0.1""#,
        "bind must return the denial object naming the address"
    );
}

#[test]
fn bind6_names_the_ipv6_address() {
    let report = eval_denied(&format!(
        r#"
        {DESCRIBE}
        const handle = new __udp.UDP();
        const result = handle.bind6('::1', 0, 0);
        handle.close();
        typeof result === 'number' ? 'status:' + result : describe(result)
        "#
    ));
    assert_eq!(report, r#"ERR_ACCESS_DENIED,Net,"::1""#);
}

#[test]
fn a_denied_bind_leaves_the_socket_unbound() {
    // The denial must come before `uv_udp_bind`, so `getsockname` still has no
    // port to report.
    let report = eval_denied(
        r#"
        const handle = new __udp.UDP();
        handle.bind('127.0.0.1', 0, 0);
        const name = {};
        handle.getsockname(name);
        handle.close();
        String(name.port === undefined || name.port === 0)
        "#,
    );
    assert_eq!(report, "true");
}

#[test]
fn connect_throws_and_reports_uv_eacces() {
    let report = eval_denied(
        r#"
        const handle = new __udp.UDP();
        let error;
        try {
          handle.connect('127.0.0.1', 9);
        } catch (thrown) {
          error = thrown;
        }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
}

#[test]
fn open_has_no_standard_stream_exemption() {
    // Unlike the stream handles, `UDPWrap::Open` checks unconditionally. A
    // datagram socket cannot adopt fd 1 as stdio, and Node does not pretend it
    // can.
    let report = eval_denied(
        r#"
        const results = [];
        for (const fd of [0, 1, 3]) {
          const handle = new __udp.UDP();
          let error;
          try { handle.open(fd); } catch (thrown) { error = thrown; }
          handle.close();
          results.push(error ? 'denied:' + error.permission : 'attempted');
        }
        results.join(',')
        "#,
    );
    assert_eq!(report, "denied:Net,denied:Net,denied:Net");
}

#[test]
fn send_is_denied_before_it_reads_its_argument_list() {
    // `DoSend` checks before its `CHECK`s, so a malformed argument list still
    // reports the denial rather than a status for the arguments.
    let report = eval_denied(
        r#"
        const handle = new __udp.UDP();
        let error;
        try {
          handle.send({}, 'not-an-array', 0, false);
        } catch (thrown) {
          error = thrown;
        }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
}

#[test]
fn recv_start_is_gated_once_per_handle() {
    // A handle that already bound successfully has `net_permission_granted_`
    // set, so `recvStart` must not re-check it: that is what keeps a socket
    // receiving after `process.permission.drop('net')`, matching
    // `test-permission-net-udp-handle.js`.
    let model = PermissionModel::with_cwd(
        "/work",
        PermissionConfig {
            allow_net: true,
            ..PermissionConfig::enforce()
        },
    );
    runtime::install(model);
    let report = with_context(|scope| {
        install(scope);
        let bound = run(
            scope,
            r#"
            const handle = new __udp.UDP();
            const status = handle.bind('127.0.0.1', 0, 0);
            handle.onmessage = () => {};
            handle.onerror = () => {};
            const started = handle.recvStart();
            handle.recvStop();
            handle.close();
            [status, started].join(',')
            "#,
        );
        bound
    });
    runtime::clear();
    assert_eq!(report, "0,0", "an allowed bind must allow recvStart");
}

#[test]
fn recv_start_is_denied_on_a_handle_that_never_bound() {
    // With no bind behind it there is no grant, so `recvStart` reports the
    // denial. `UDPWrap::RecvStart` returns `UV_EACCES` (-13) alongside the throw,
    // but the throw means JavaScript never sees the status — so what a caller
    // observes is the error, which is what `lib/dgram.js` turns into a
    // `'error'` event. The status is asserted from Rust instead.
    let report = eval_denied(
        r#"
        const handle = new __udp.UDP();
        handle.onmessage = () => {};
        handle.onerror = () => {};
        let error;
        try { handle.recvStart(); } catch (thrown) { error = thrown; }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
}

#[test]
fn dropping_net_stops_the_next_socket_but_not_an_already_granted_one() {
    // The `net_permission_granted_` flag is per handle, so an existing socket
    // keeps its grant while a new handle is denied. That is the behaviour
    // `test-permission-net-udp-handle.js` depends on when it drops `net` in a
    // child that already owns a bound socket.
    let model = runtime::install(PermissionModel::with_cwd(
        "/work",
        PermissionConfig {
            allow_net: true,
            ..PermissionConfig::enforce()
        },
    ));
    let report = with_context(|scope| {
        install(scope);
        // First handle: bind while the scope is granted, which also sets the
        // handle's own flag.
        let first = run(
            scope,
            r#"
            {
              const handle = new __udp.UDP();
              const status = handle.bind('127.0.0.1', 0, 0);
              handle.close();
              globalThis.__firstStatus = String(status);
            }
            __firstStatus
            "#,
        );
        assert_eq!(first, "0", "the first bind must be allowed");

        // Revoke the whole scope from Rust: JavaScript cannot reach this model.
        model.drop_permission(PermissionScope::Net, "");
        assert!(!model.has(PermissionScope::Net, None));

        run(
            scope,
            r#"
            {
              const handle = new __udp.UDP();
              const result = handle.bind('127.0.0.1', 0, 0);
              handle.close();
              globalThis.__secondResult =
                result && result.code ? result.code : 'status:' + result;
            }
            __secondResult
            "#,
        )
    });
    runtime::clear();
    assert_eq!(
        report, "ERR_ACCESS_DENIED",
        "a new socket must be denied after the drop"
    );
}

#[test]
fn nothing_is_denied_without_a_model() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const bound = handle.bind('127.0.0.1', 0, 0);
        handle.close();

        const other = new __udp.UDP();
        let threw = false;
        try { other.connect('127.0.0.1', 9); } catch (error) { threw = true; }
        other.close();
        [bound, threw].join(',')
        "#,
    );
    // A real connect on an unbound datagram socket succeeds, so both are clean.
    assert_eq!(report, "0,false");
}
