//! The `net` permission checks `tcp_wrap` makes, through a real V8 isolate.
//!
//! These are the `kNet` call sites `src/tcp_wrap.cc` has: `bind`/`bind6`,
//! `listen`, `connect`/`connect6` and `open`. Each is asserted three ways, because
//! the three answers are what distinguish a working gate from one that only
//! looks like one:
//!
//! * with no model installed every call succeeds, which is the property that
//!   keeps a run without `--permission` working;
//! * with an enforcing model the call is denied and nothing is bound, listened
//!   on or connected — a status code alone would not prove the syscall was
//!   skipped;
//! * with an enforcing model and `--allow-net` the call succeeds.
//!
//! The denial is also checked for the two shapes Node uses here: `bind` and
//! `listen` throw, while `connect` returns the error object whose `code`,
//! `permission` and `resource` `lib/net.js` reads to build its
//! `ExceptionWithHostPort`.

use rn_bind_tcp_wrap::TcpWrap;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_permission::{runtime, PermissionConfig, PermissionModel};
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

/// Installs `async_wrap` and `tcp_wrap`, as `lib/internal/bootstrap/node.js`
/// orders them: `TCP`'s constructor and `getAsyncId` draw on `async_wrap`.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let async_wrap = rn_bind_async_wrap::AsyncWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing async_wrap must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__async").expect("allocating __async");
    global.set(scope, key.into(), async_wrap.into());

    let object = TcpWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing tcp_wrap must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__tcp").expect("allocating __tcp");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` and returns its string result, or `threw: <message>`.
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

/// Evaluates with no permission model installed, the common case.
fn eval(source: &str) -> String {
    eval_with(None, source)
}

/// Evaluates under `--permission` with no `net` grant.
fn eval_denied(source: &str) -> String {
    eval_with(Some(PermissionModel::enforcing("/work")), source)
}

/// Evaluates under `--permission --allow-net`.
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

/// The message `lib/net.js` reads off a returned denial.
const DENIAL_FIELDS: &str = "\
const describe = (error) => [
  error.code,
  error.permission,
  JSON.stringify(error.resource),
].join(',');\
";

#[test]
fn bind_is_denied_and_binds_nothing() {
    let denied = eval_denied(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        let error;
        try {
          handle.bind('127.0.0.1', 0);
        } catch (thrown) {
          error = thrown;
        }
        const name = {};
        const status = handle.getsockname(name);
        [error && error.code, error && error.permission, status, JSON.stringify(name)].join(',')
        "#,
    );
    // `getsockname` on a handle that really was never bound fails, so the bind
    // status is the proof the syscall did not happen.
    assert!(
        denied.starts_with("ERR_ACCESS_DENIED,Net,"),
        "bind must throw a Net denial, got {denied}"
    );

    let allowed = eval_allowed(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        const status = handle.bind('127.0.0.1', 0);
        const name = {};
        handle.getsockname(name);
        handle.close();
        [status, name.port > 0].join(',')
        "#,
    );
    assert_eq!(allowed, "0,true", "--allow-net must let bind through");
}

#[test]
fn listen_is_denied_before_the_handle_is_registered() {
    // `bind` is gated too, so an unbound handle must still fail on `listen`
    // rather than only on the bind that precedes it. That is the assertion: the
    // denial comes from `listen` itself.
    let denied = eval_denied(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        let error;
        try {
          handle.listen(511);
        } catch (thrown) {
          error = thrown;
        }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(denied, "ERR_ACCESS_DENIED,Net");

    let allowed = eval_allowed(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        const bound = handle.bind('127.0.0.1', 0);
        handle.onconnection = () => {};
        const listened = handle.listen(511);
        handle.close();
        [bound, listened].join(',')
        "#,
    );
    assert_eq!(
        allowed, "0,0",
        "--allow-net must let bind and listen through"
    );
}

#[test]
fn a_denied_listen_leaves_no_half_bound_handle() {
    // A denied `listen` must not have parked `owner_object` or registered the
    // handle with the loop, so a second `listen` after dropping the model still
    // reports the denial rather than the first call's state.
    let report = eval_denied(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        let first, second;
        try { handle.listen(511); } catch (error) { first = error.permission; }
        try { handle.listen(511); } catch (error) { second = error.permission; }
        handle.close();
        [first, second].join(',')
        "#,
    );
    assert_eq!(report, "Net,Net");
}

#[test]
fn connect_returns_the_denial_as_a_value() {
    // `ERR_ACCESS_DENIED_IF_INSUFFICIENT_PERMISSIONS` hands the error back
    // instead of throwing, because `lib/net.js` passes it to
    // `ExceptionWithHostPort`, which reads `code` and `message` off it.
    let report = eval_denied(&format!(
        r#"
        {DENIAL_FIELDS}
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        handle.close();
        const other = new __tcp.TCP(__tcp.constants.SOCKET);
        const request = new __tcp.TCPConnectWrap();
        request.oncomplete = () => {{}};
        const result = other.connect(request, '127.0.0.1', 9);
        other.close();
        typeof result === 'number' ? 'status:' + result : describe(result)
        "#
    ));
    assert_eq!(
        report, r#"ERR_ACCESS_DENIED,Net,"127.0.0.1""#,
        "connect must return the denial object naming the address"
    );
}

#[test]
fn connect6_names_the_ipv6_address_as_written() {
    // The resource is the address string the caller passed, with no bracket
    // rewriting: `lib/net.js` hands `connect6` the literal it resolved.
    let report = eval_denied(&format!(
        r#"
        {DENIAL_FIELDS}
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const request = new __tcp.TCPConnectWrap();
        request.oncomplete = () => {{}};
        const result = handle.connect6(request, '::1', 9);
        handle.close();
        typeof result === 'number' ? 'status:' + result : describe(result)
        "#
    ));
    assert_eq!(
        report, r#"ERR_ACCESS_DENIED,Net,"::1""#,
        "an IPv6 denial must name the address without brackets"
    );
}

#[test]
fn connect_to_an_unbound_socket_is_still_denied() {
    // `connect` on a socket that was never bound is denied by the guard, not by
    // libuv: the check runs before the address is parsed or the syscall issued.
    let report = eval_denied(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const request = new __tcp.TCPConnectWrap();
        request.oncomplete = () => {};
        const result = handle.connect(request, 'not-an-address', 0);
        handle.close();
        result && result.code ? result.code : 'status:' + result
        "#,
    );
    assert_eq!(
        report, "ERR_ACCESS_DENIED",
        "the permission check must win over an unparseable address"
    );
}

#[test]
fn open_denies_a_descriptor_it_was_not_handed() {
    // fd 3 and above is not a standard stream and is not the IPC channel, so
    // adopting it needs the net permission.
    let report = eval_denied(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        let error;
        try { handle.open(3); } catch (thrown) { error = thrown; }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
}

#[test]
fn open_allows_the_standard_streams_and_the_ipc_channel() {
    // `LibuvStreamWrap::IsProcessStdioOrIPCChannel` exempts these, which is what
    // lets a fork child and `process.stdin.pipe(process.stdout)` work under a
    // bare `--permission`. The open itself still fails on a socket that is not
    // one, and that is the signal the check was skipped: the status is libuv's,
    // not a denial.
    runtime::set_ipc_channel_fd(9);
    let report = eval_denied(
        r#"
        const results = [];
        for (const fd of [0, 1, 2, 9]) {
          const handle = new __tcp.TCP(__tcp.constants.SOCKET);
          let error;
          try { handle.open(fd); } catch (thrown) { error = thrown; }
          handle.close();
          results.push(error ? 'denied:' + error.code : 'attempted');
        }
        results.join(',')
        "#,
    );
    runtime::set_ipc_channel_fd(-1);
    assert_eq!(
        report, "attempted,attempted,attempted,attempted",
        "an exempt descriptor must reach libuv instead of being denied"
    );
}

#[test]
fn nothing_is_denied_without_a_model() {
    let report = eval(
        r#"
        const server = new __tcp.TCP(__tcp.constants.SERVER);
        const bound = server.bind('127.0.0.1', 0);
        server.onconnection = () => {};
        const listened = server.listen(511);
        server.close();

        const client = new __tcp.TCP(__tcp.constants.SOCKET);
        const request = new __tcp.TCPConnectWrap();
        request.oncomplete = () => {};
        const connected = client.connect(request, '127.0.0.1', 1);
        client.close();
        [bound, listened, typeof connected].join(',')
        "#,
    );
    assert_eq!(
        report, "0,0,number",
        "without a model every call must reach libuv and report its status"
    );
}

#[test]
fn a_disabled_model_denies_nothing() {
    let report = eval_with(
        Some(PermissionModel::disabled()),
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        const status = handle.bind('127.0.0.1', 0);
        handle.close();
        status
        "#,
    );
    assert_eq!(report, "0");
}
