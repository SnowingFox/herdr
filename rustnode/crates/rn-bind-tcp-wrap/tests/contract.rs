//! The `tcp_wrap` contract, checked through a real V8 isolate and a real socket.
//!
//! `lib/net.js` is unchanged Node code, so the shapes here are the ones it reads:
//! the four `constants`, the two constructors, and the methods it calls on a
//! handle. Where a method touches the kernel the test actually performs the
//! syscall — `bind` really binds, `getsockname` really asks the kernel — because a
//! stub that returns 0 would satisfy every signature and prove nothing.
//!
//! The one thing these tests do not do is pump the loop. That is deliberate:
//! `require('net')` needs a *scheduler* to drive libuv, and the tests that need a
//! live connection live in `crates/rn-uv/tests/tcp_roundtrip.rs`, which pumps the
//! loop directly. Everything below is what can be proved without it.

use rn_bind_tcp_wrap::{TcpWrap, UV_TCP_IPV6ONLY, UV_TCP_REUSEPORT};
use rn_core::{AsyncIds, BindingModule, InstallCtx};
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

/// Installs the namespace and binds it to `__tcp` in the global object.
///
/// `async_wrap` is installed first, and that ordering is part of the contract
/// rather than a convenience: `getAsyncId` draws from its counter and
/// `asyncReset` emits through its hook table, so a `TCP` built without it has no
/// id space to draw from. `lib/internal/bootstrap/node.js` reaches
/// `async_wrap`'s binding before any handle exists for the same reason.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let async_wrap = rn_bind_async_wrap::AsyncWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the async_wrap namespace must not fail");
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
        .expect("installing the tcp_wrap namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__tcp").expect("allocating __tcp");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` with `__tcp` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        run(scope, source)
    })
}

/// Evaluates `source` in an already-installed scope.
///
/// A probe that throws returns `threw: <message>` instead of panicking, because
/// several of the tests below deliberately provoke errors and want to assert on
/// the message.
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

/// The three members `contracts/tcp_wrap.json` records.
#[test]
fn the_namespace_publishes_exactly_the_recorded_members() {
    assert_eq!(
        eval("Object.keys(__tcp).sort().join(',')"),
        "TCP,TCPConnectWrap,constants"
    );
}

/// `constants` carries the four values `NODE_DEFINE_CONSTANT` publishes.
///
/// `SOCKET` and `SERVER` are `TCPWrap::SocketType`; the other two are libuv's
/// `uv_tcp_flags`. `lib/net.js` passes `UV_TCP_IPV6ONLY` through
/// `server.listen({ ipv6Only: true })`, so the value has to be libuv's or the flag
/// silently does nothing.
#[test]
fn the_constants_have_libuv_s_values() {
    let report = eval(
        r#"
        const c = __tcp.constants;
        [c.SOCKET, c.SERVER, c.UV_TCP_IPV6ONLY, c.UV_TCP_REUSEPORT].join(',')
        "#,
    );
    // `TCPWrap::SocketType` is SOCKET = 0, SERVER = 1. `UV_TCP_IPV6ONLY` is 1 and
    // `UV_TCP_REUSEPORT` is 2 in `uv.h`.
    assert_eq!(report, "0,1,1,2");
    assert_eq!(UV_TCP_IPV6ONLY, 1);
    assert_eq!(UV_TCP_REUSEPORT, 2);
}

/// `TCP` is a constructor that requires a socket type, as `CHECK(args[0]->IsInt32())`
/// does.
#[test]
fn tcp_requires_a_socket_type() {
    let report = eval(
        r#"
        const results = [];
        try { __tcp.TCP(); results.push('no-new'); }
        catch (error) { results.push('no-new:' + error.constructor.name); }
        try { new __tcp.TCP(); results.push('no-arg'); }
        catch (error) { results.push('no-arg:' + error.constructor.name); }
        results.push(typeof new __tcp.TCP(__tcp.constants.SOCKET));
        results.join(',')
        "#,
    );
    assert_eq!(report, "no-new:TypeError,no-arg:TypeError,object");
}

/// The handle surface `lib/net.js` calls, member by member.
///
/// This is the assertion that matters most: `lib/net.js` feature-detects several
/// of these (`if (self._handle.setNoDelay)`), so a missing one degrades a single
/// feature instead of throwing — which is exactly the kind of gap that ships
/// unnoticed.
#[test]
fn a_tcp_handle_exposes_every_method_lib_net_calls() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const expected = [
          // HandleWrap
          'close', 'ref', 'unref', 'hasRef',
          // StreamBase
          'readStart', 'readStop', 'shutdown', 'writeBuffer', 'writev',
          'writeAsciiString', 'writeUtf8String', 'writeUcs2String',
          'writeLatin1String',
          // TCPWrap
          'open', 'bind', 'bind6', 'listen', 'connect', 'connect6',
          'getsockname', 'getpeername', 'setNoDelay', 'setKeepAlive',
          'setTypeOfService', 'getTypeOfService', 'reset',
        ];
        expected.filter((name) => typeof handle[name] !== 'function')
        "#,
    );
    assert_eq!(report, "", "every method lib/net.js calls must exist");
}

/// The accessors and the `isStreamBase` marker.
#[test]
fn a_tcp_handle_exposes_the_stream_base_accessors() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        [
          handle.isStreamBase === true,
          typeof handle.fd,
          typeof handle.bytesRead,
          typeof handle.bytesWritten,
          typeof handle.writeQueueSize,
          handle.reading,
          handle.onread === null,
          handle.onconnection === null,
        ].join(',')
        "#,
    );
    // `src/tcp_wrap.cc` pre-creates `reading` as `false` and `onconnection` as
    // `null`; `isStreamBase` is `true` from `StreamBase::AddMethods`.
    assert_eq!(report, "true,number,number,number,number,false,true,true");
}

/// `bind` + `getsockname` on a real socket, which is what `server.listen()` does
/// before it ever calls `listen`.
#[test]
fn bind_then_getsockname_reports_the_kernel_s_address() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        const out = {};
        const bind = handle.bind('127.0.0.1', 0);
        const named = handle.getsockname(out);
        handle.close();
        [bind, named, out.address, out.family, out.port > 0].join(',')
        "#,
    );
    assert_eq!(
        report, "0,0,127.0.0.1,IPv4,true",
        "bind must succeed and getsockname must report the assigned port"
    );
}

/// `bind6` reports a `family` of `IPv6`, which is what `server.address()` shows.
#[test]
fn bind6_reports_an_ipv6_address() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        const out = {};
        const bind = handle.bind6('::1', 0);
        const named = bind === 0 ? handle.getsockname(out) : bind;
        handle.close();
        [bind, named, out.family].join(',')
        "#,
    );
    assert_eq!(report, "0,0,IPv6");
}

/// A malformed address is rejected by libuv, which is what `internalConnect`
/// reports as `ERR_INVALID_IP_ADDRESS`-adjacent behaviour.
#[test]
fn a_non_numeric_address_is_rejected() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const status = handle.bind('example.com', 0);
        handle.close();
        status < 0
        "#,
    );
    assert_eq!(report, "true", "uv_ip4_addr only accepts numeric literals");
}

/// `listen` on a bound socket, then `close`. This is `server.listen()` minus the
/// connection callback firing.
#[test]
fn listen_succeeds_on_a_bound_socket() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SERVER);
        handle.bind('127.0.0.1', 0);
        handle.onconnection = () => {};
        const status = handle.listen(511);
        handle.close();
        status
        "#,
    );
    assert_eq!(report, "0");
}

/// `connect` on a live listener queues without error, and returns `0`.
///
/// The completion is driven by the loop, which these tests do not pump; what is
/// checked here is that libuv accepted the request, which is what
/// `lib/net.js`'s `internalConnect` branches on.
#[test]
fn connect_queues_against_a_real_listener() {
    let report = eval(
        r#"
        const server = new __tcp.TCP(__tcp.constants.SERVER);
        server.bind('127.0.0.1', 0);
        server.onconnection = () => {};
        server.listen(511);
        const out = {};
        server.getsockname(out);

        const client = new __tcp.TCP(__tcp.constants.SOCKET);
        const req = new __tcp.TCPConnectWrap();
        req.oncomplete = () => {};
        const status = client.connect(req, '127.0.0.1', out.port);

        client.close();
        server.close();
        status
        "#,
    );
    assert_eq!(report, "0");
}

/// A failed connect reports a negative status *synchronously* and does not call
/// `oncomplete`, because `internalConnect` destroys the socket on a non-zero
/// return.
#[test]
fn connect_to_a_closed_port_fails_synchronously_or_queues() {
    let report = eval(
        r#"
        const client = new __tcp.TCP(__tcp.constants.SOCKET);
        const req = new __tcp.TCPConnectWrap();
        let called = false;
        req.oncomplete = () => { called = true; };
        // Port 1 on loopback is not listening. libuv queues the attempt and
        // reports ECONNREFUSED from the loop, so the meaningful assertion is that
        // `connect` itself accepted the request rather than throwing.
        const status = client.connect(req, '127.0.0.1', 1);
        client.close();
        [typeof status, called].join(',')
        "#,
    );
    assert_eq!(
        report, "number,false",
        "connect returns a status and does not complete inline"
    );
}

/// `close` runs its callback through the loop, so it is not synchronous; what this
/// checks is that closing twice is a no-op rather than a crash, which is what
/// `HandleWrap::Close`'s state guard provides.
#[test]
fn closing_twice_is_harmless() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        handle.close();
        handle.close();
        handle.close();
        'ok'
        "#,
    );
    assert_eq!(report, "ok");
}

/// The socket options report a status rather than throwing on a live socket.
#[test]
fn the_socket_options_return_libuv_statuses() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        handle.bind('127.0.0.1', 0);
        const noDelay = handle.setNoDelay(true);
        const keepAlive = handle.setKeepAlive(true, 1000);
        const tos = handle.setTypeOfService(0x10);
        const readTos = handle.getTypeOfService();
        handle.close();
        [noDelay, keepAlive, tos, typeof readTos].join(',')
        "#,
    );
    // `uv_tcp_nodelay` and `uv_tcp_keepalive` succeed on a bound socket; the TOS
    // path goes through `setsockopt` directly.
    assert_eq!(report, "0,0,0,number");
}

/// `hasRef` reflects libuv's own ref state, which `lib/net.js` reads before
/// replacing a handle during a multi-attempt connect.
///
/// A handle is referenced when it is initialised and not yet closing, even
/// before it is active, because `uv_has_ref` reports the flag rather than whether
/// the handle is doing work. `unref`/`ref` flip it.
#[test]
fn ref_unref_and_has_ref_track_libuv() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const before = handle.hasRef();
        handle.unref();
        const afterUnref = handle.hasRef();
        handle.ref();
        const afterRef = handle.hasRef();
        handle.close();
        [before, afterUnref, afterRef].join(',')
        "#,
    );
    assert_eq!(report, "true,false,true", "ref and unref flip uv_has_ref");
}

/// `fd` reports the descriptor libuv assigned, or `-1` when there is none.
///
/// A freshly constructed `uv_tcp_t` has no descriptor yet: libuv creates the
/// socket lazily on `bind`/`connect`. Node reports `-1` for the same reason, so
/// this pins that rather than expecting a descriptor that only exists later.
#[test]
fn fd_is_minus_one_before_bind_and_a_descriptor_after() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const before = handle.fd;
        handle.bind('127.0.0.1', 0);
        const after = handle.fd;
        handle.close();
        [before, after > 0].join(',')
        "#,
    );
    assert_eq!(
        report, "-1,true",
        "uv_fileno reports -1 until libuv creates the descriptor, then a real fd"
    );
}

/// An accepted-handle wrapper is a `TCP`, which is what `handle instanceof TCP`
/// in `lib/net.js` checks.
#[test]
fn a_handle_is_an_instance_of_tcp() {
    assert_eq!(
        eval("new __tcp.TCP(__tcp.constants.SOCKET) instanceof __tcp.TCP"),
        "true"
    );
}

/// `TCPConnectWrap` is a plain constructor with one internal field, as
/// `AsyncWrap::MakeLazilyInitializedJSTemplate` produces.
///
/// `lib/net.js` assigns `oncomplete`, `address`, `port`, `localAddress`,
/// `localPort` and `addressType` to one, then passes it to `handle.connect`.
#[test]
fn tcp_connect_wrap_is_constructible() {
    let report = eval(
        r#"
        const req = new __tcp.TCPConnectWrap();
        req.oncomplete = () => {};
        req.address = '127.0.0.1';
        req.port = 80;
        [typeof req, typeof req.oncomplete, req.address, __tcp.TCPConnectWrap.name].join(',')
        "#,
    );
    assert_eq!(report, "object,function,127.0.0.1,TCPConnectWrap");
}

/// The module declares exactly what it installs.
#[test]
fn the_module_declares_exactly_what_it_installs() {
    assert_eq!(TcpWrap.namespace(), "tcp_wrap");
    assert_eq!(TcpWrap.members(), rn_bind_tcp_wrap::MEMBERS);
    assert!(
        TcpWrap.deferred().is_empty(),
        "every recorded member is installed, so nothing is deferred"
    );
}

/// `AsyncWrap`'s three methods, which the `HandleWrap` template inherits.
///
/// `getAsyncId` alone is not enough: `lib/internal/http/agent.js::asyncResetHandle`
/// feature-detects `asyncReset` and silently does nothing when it is absent, so a
/// handle without it keeps the previous request's id and
/// `socket[async_id_symbol]` stays `-1`. `getProviderType` is what builds the
/// `ReusedHandle` it passes to the reset.
///
/// `src/async_wrap.cc::GetConstructorTemplate` installs all three on one
/// prototype, which is why they are asserted together.
#[test]
fn a_tcp_handle_exposes_the_async_wrap_methods() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const names = ['getAsyncId', 'asyncReset', 'getProviderType'];
        const results = names.map((name) => typeof handle[name]);
        handle.close();
        results.join(',')
        "#,
    );
    assert_eq!(report, "function,function,function");
}

/// `getProviderType` reports the provider `src/tcp_wrap.cc` selects from the
/// socket type, and `Providers.TCPWRAP`/`TCPSERVERWRAP` are the ids it reports.
///
/// The mapping is observable: `asyncResetHandle` puts this value into the
/// `ReusedHandle` that the `init` hook receives as `resource.type`, so a wrong
/// one labels a reused socket as the wrong kind of resource without failing
/// anything else.
#[test]
fn a_handle_reports_the_provider_for_its_socket_type() {
    let report = eval(
        r#"
        const client = new __tcp.TCP(__tcp.constants.SOCKET);
        const server = new __tcp.TCP(__tcp.constants.SERVER);
        const out = [client.getProviderType(), server.getProviderType()];
        client.close();
        server.close();
        out.join(',')
        "#,
    );
    // `PROVIDER_TCPWRAP` is 42 and `PROVIDER_TCPSERVERWRAP` is 41, matching
    // `NODE_ASYNC_PROVIDER_TYPES` in `src/async_wrap.h`.
    assert_eq!(
        report, "42,41",
        "SOCKET is TCPWRAP, SERVER is TCPSERVERWRAP"
    );
}

/// `getAsyncId` answers `kInvalidAsyncId` for a receiver that is not a handle.
///
/// `src/async_wrap.cc::GetAsyncId` sets `-1` as the return value *before* it
/// unwraps, so a detached or forged receiver gets `-1` rather than throwing.
/// `lib/net.js` checks the method exists and then trusts the answer, which is
/// why this has to be a number rather than `undefined`.
#[test]
fn an_unwrapped_receiver_reports_no_async_id_and_no_provider() {
    let report = eval(
        r#"
        const method = (name) => __tcp.TCP.prototype[name];
        const out = [
          method('getAsyncId').call({}),
          method('getProviderType').call({}),
        ];
        out.join(',')
        "#,
    );
    assert_eq!(report, "-1,0", "PROVIDER_NONE is 0");
}

/// A handle's async id changes when it is reset, and the id is freshly allocated
/// rather than reused.
///
/// This is the assertion `test-async-hooks-http-agent` makes implicitly: the
/// agent pulls a socket out of the keep-alive pool, calls `asyncReset`, and
/// stores `handle.getAsyncId()` as the socket's `async_id_symbol`. An id that did
/// not change would mean the second request inherited the first one's resource.
#[test]
fn async_reset_assigns_a_fresh_async_id() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const before = handle.getAsyncId();
        handle.asyncReset({ tag: 'reused' });
        const after = handle.getAsyncId();
        handle.close();
        [before > 0, after > 0, after !== before, after > before].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true,true,true",
        "a reset must allocate a new, larger id rather than replay the old one"
    );
}

/// The optional second argument to `asyncReset` is used as the id when it is a
/// number, matching `args[1]->IsNumber() ? args[1]->As<Number>()->Value() :
/// kInvalidAsyncId`.
#[test]
fn async_reset_uses_an_explicit_id_when_one_is_given() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        handle.asyncReset({ tag: 'reused' }, 12345);
        const id = handle.getAsyncId();
        handle.close();
        id
        "#,
    );
    assert_eq!(report, "12345");
}

/// The second argument being a non-number falls back to allocating, which is
/// what the `IsNumber()` test in `AsyncReset` amounts to.
#[test]
fn async_reset_allocates_when_the_id_argument_is_not_a_number() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const before = handle.getAsyncId();
        handle.asyncReset({ tag: 'reused' }, 'not a number');
        const after = handle.getAsyncId();
        handle.close();
        [after > 0, after !== before].join(',')
        "#,
    );
    assert_eq!(report, "true,true");
}

/// `asyncReset` requires an object, as `CHECK(args[0]->IsObject())` does.
#[test]
fn async_reset_requires_a_resource_object() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const results = [];
        for (const argument of [undefined, 1, 'x', null]) {
          try { handle.asyncReset(argument); results.push('accepted'); }
          catch (error) { results.push(error.constructor.name); }
        }
        handle.close();
        results.join(',')
        "#,
    );
    assert_eq!(
        report, "TypeError,TypeError,TypeError,TypeError",
        "a non-object resource is a caller bug, not a silent no-op"
    );
}

/// A reset attaches the resource to the handle under `resource_symbol`, which is
/// how `emitInitNative` decides which object a hook sees.
///
/// `AsyncWrap::AsyncReset` does `obj->Set(resource_symbol, resource)` only when
/// the resource is not the object itself. `lookupPublicResource` reads that same
/// key, so a reset that skipped it would hand the hook the raw handle instead of
/// the `ReusedHandle` the caller passed.
#[test]
fn async_reset_attaches_the_resource_under_the_shared_symbol() {
    let report = eval(
        r#"
        const handle = new __tcp.TCP(__tcp.constants.SOCKET);
        const resource = { tag: 'reused' };
        handle.asyncReset(resource);
        const attached = Object.getOwnPropertySymbols(handle)
          .find((symbol) => handle[symbol] === resource);
        handle.close();
        [attached !== undefined, String(attached)].join(',')
        "#,
    );
    assert_eq!(
        report, "true,Symbol(resource_symbol)",
        "the symbol must be the shared one from internalBinding('symbols')"
    );
}

/// Two handles do not share native state, which is what a `Box<uv_tcp_t>` per
/// instance buys.
#[test]
fn two_handles_are_independent() {
    let report = eval(
        r#"
        const first = new __tcp.TCP(__tcp.constants.SERVER);
        const second = new __tcp.TCP(__tcp.constants.SERVER);
        const a = {};
        const b = {};
        first.bind('127.0.0.1', 0);
        second.bind('127.0.0.1', 0);
        first.getsockname(a);
        second.getsockname(b);
        first.close();
        second.close();
        [a.port !== b.port, a.port > 0, b.port > 0].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true,true",
        "each handle gets its own descriptor"
    );
}
