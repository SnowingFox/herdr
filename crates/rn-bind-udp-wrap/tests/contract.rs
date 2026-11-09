//! The `udp_wrap` contract, checked through a real V8 isolate and a real socket.
//!
//! `lib/dgram.js` is unchanged Node code, so the shapes here are the ones it
//! reads. Where a method touches the kernel the test actually performs the
//! syscall — `bind` really binds and `getsockname` really asks the kernel —
//! because a stub returning 0 would satisfy every signature and prove nothing.
//!
//! The socket round trip lives in `tests/roundtrip.rs`, which pumps the loop.
//! Everything here is what can be proved without pumping it.

use rn_bind_udp_wrap::{UdpWrap, UV_UDP_IPV6ONLY, UV_UDP_REUSEADDR, UV_UDP_REUSEPORT};
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

/// Installs the namespace and binds it to `__udp` in the global object.
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

/// Evaluates `source` with `__udp` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        run(scope, source)
    })
}

/// Evaluates `source` in an already-installed scope.
///
/// A probe that throws returns `threw: <message>` instead of panicking, because
/// several tests below deliberately provoke errors and assert on the message.
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

/// The three members `contracts/udp_wrap.json` records.
#[test]
fn the_namespace_publishes_exactly_the_recorded_members() {
    assert_eq!(
        eval("Object.keys(__udp).sort().join(',')"),
        "SendWrap,UDP,constants"
    );
}

/// `constants` carries libuv's flag values, because `socket.bind()` passes them
/// straight to `uv_udp_bind`.
#[test]
fn the_constants_have_libuv_s_values() {
    let report = eval(
        r#"
        const c = __udp.constants;
        [c.UV_UDP_IPV6ONLY, c.UV_UDP_REUSEADDR, c.UV_UDP_REUSEPORT].join(',')
        "#,
    );
    // `UV_UDP_IPV6ONLY` is 1 and `UV_UDP_REUSEADDR` 4, the two Node has always
    // published; `UV_UDP_REUSEPORT` is 64 in current libuv.
    assert_eq!(report, "1,4,64");
    assert_eq!(UV_UDP_IPV6ONLY, 1);
    assert_eq!(UV_UDP_REUSEADDR, 4);
    assert_eq!(UV_UDP_REUSEPORT, 64);
}

/// `UDP` is a constructor with no arguments, unlike `TCP`.
#[test]
fn udp_is_a_no_argument_constructor() {
    let report = eval(
        r#"
        const results = [];
        try { __udp.UDP(); results.push('no-new'); }
        catch (error) { results.push('no-new:' + error.constructor.name); }
        results.push(typeof new __udp.UDP());
        results.push(__udp.UDP.name);
        results.join(',')
        "#,
    );
    assert_eq!(report, "no-new:TypeError,object,UDP");
}

/// The handle surface `lib/dgram.js` calls, member by member.
///
/// This is the assertion that matters most: every one of these is reached from
/// `lib/dgram.js` or `lib/internal/dgram.js`, and a missing one is a
/// `TypeError` the first time a user touches the corresponding `Socket` method.
#[test]
fn a_udp_handle_exposes_every_method_lib_dgram_calls() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const expected = [
          // HandleWrap / AsyncWrap
          'close', 'ref', 'unref', 'hasRef', 'getAsyncId',
          // UDPWrapBase
          'recvStart', 'recvStop',
          // UDPWrap
          'open', 'bind', 'bind6', 'connect', 'connect6', 'send', 'send6',
          'disconnect', 'getsockname', 'getpeername',
          'addMembership', 'dropMembership',
          'addSourceSpecificMembership', 'dropSourceSpecificMembership',
          'setMulticastInterface', 'setMulticastTTL', 'setMulticastLoopback',
          'setBroadcast', 'setTTL', 'bufferSize',
          'getSendQueueSize', 'getSendQueueCount',
        ];
        expected.filter((name) => typeof handle[name] !== 'function')
        "#,
    );
    assert_eq!(report, "", "every method lib/dgram.js calls must exist");
}

/// `fd` is an accessor reporting the descriptor libuv assigned, or `-1`.
#[test]
fn the_fd_accessor_reports_the_descriptor() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const before = handle.fd;
        const bound = handle.bind('127.0.0.1', 0, 0);
        const after = handle.fd;
        handle.close();
        [before, bound, after > 0].join(',')
        "#,
    );
    assert_eq!(
        report, "-1,0,true",
        "a fresh udp handle has no descriptor; bind creates one"
    );
}

/// `bind` + `getsockname` on a real socket with a kernel-assigned port.
#[test]
fn bind_then_getsockname_reports_the_kernel_s_address() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const out = {};
        const bind = handle.bind('127.0.0.1', 0, 0);
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

/// `bind6` reports a `family` of `IPv6`, which is what `socket.address()` shows.
#[test]
fn bind6_reports_an_ipv6_address() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const out = {};
        const bind = handle.bind6('::1', 0, 0);
        const named = bind === 0 ? handle.getsockname(out) : bind;
        handle.close();
        [bind, named, out.family].join(',')
        "#,
    );
    assert_eq!(report, "0,0,IPv6");
}

/// `UV_UDP_REUSEADDR` really reaches the kernel: two sockets can hold the same
/// port, which is what `bind({ reuseAddr: true })` promises.
#[test]
fn reuse_addr_lets_two_sockets_share_a_port() {
    let report = eval(
        r#"
        const first = new __udp.UDP();
        const out = {};
        const bound = first.bind('127.0.0.1', 0, __udp.constants.UV_UDP_REUSEADDR);
        first.getsockname(out);

        const second = new __udp.UDP();
        const shared = second.bind('127.0.0.1', out.port, __udp.constants.UV_UDP_REUSEADDR);

        const third = new __udp.UDP();
        const conflicting = third.bind('127.0.0.1', out.port, 0);

        first.close();
        second.close();
        third.close();
        [bound, shared, conflicting < 0].join(',')
        "#,
    );
    assert_eq!(
        report, "0,0,true",
        "reuseAddr must bind a taken port and the absence of it must fail"
    );
}

/// A malformed address is rejected by libuv before it reaches the socket, which
/// is what `socket.send()`'s argument validation relies on.
#[test]
fn a_non_numeric_address_is_rejected() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const status = handle.bind('example.com', 0, 0);
        handle.close();
        status < 0
        "#,
    );
    assert_eq!(report, "true", "uv_ip4_addr only accepts numeric literals");
}

/// `connect` on a bound socket records the peer, and `getpeername` reads it back.
#[test]
fn connect_then_getpeername_reports_the_peer() {
    let report = eval(
        r#"
        const server = new __udp.UDP();
        const out = {};
        server.bind('127.0.0.1', 0, 0);
        server.getsockname(out);

        const client = new __udp.UDP();
        const connected = client.connect('127.0.0.1', out.port);
        const peer = {};
        const named = client.getpeername(peer);
        const disconnected = client.disconnect();

        client.close();
        server.close();
        [connected, named, peer.port === out.port, peer.family, disconnected].join(',')
        "#,
    );
    assert_eq!(report, "0,0,true,IPv4,0");
}

/// `getSendQueueSize`/`getSendQueueCount` report libuv's own counters, which are
/// zero on an idle socket.
#[test]
fn the_send_queue_accessors_start_at_zero() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        handle.bind('127.0.0.1', 0, 0);
        const size = handle.getSendQueueSize();
        const count = handle.getSendQueueCount();
        handle.close();
        [size, count].join(',')
        "#,
    );
    assert_eq!(report, "0,0");
}

/// `bufferSize` returns the size the kernel settled on, which is never the value
/// asked for exactly.
#[test]
fn buffer_size_reports_the_kernel_s_value() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        handle.bind('127.0.0.1', 0, 0);
        const ctx = {};
        const recv = handle.bufferSize(65536, true, ctx);
        const send = handle.bufferSize(65536, false, {});
        handle.close();
        [recv > 0, send > 0, Object.keys(ctx).length].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true,0",
        "a successful bufferSize call leaves the error context untouched"
    );
}

/// A refused `bufferSize` fills the context with what `ERR_SOCKET_BUFFER_SIZE`
/// reads, which is the only way the error says anything useful.
#[test]
fn an_unsupported_buffer_size_fills_the_error_context() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        handle.close();
        const ctx = {};
        const result = handle.bufferSize(65536, true, ctx);
        [result === undefined, typeof ctx.code, typeof ctx.message, ctx.syscall].join(',')
        "#,
    );
    assert_eq!(
        report, "true,string,string,uv_recv_buffer_size",
        "a closed handle must report the failure through the context object"
    );
}

/// The multicast and broadcast setters return libuv statuses rather than throwing.
#[test]
fn the_socket_options_return_libuv_statuses() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        handle.bind('127.0.0.1', 0, 0);
        const results = [
          handle.setBroadcast(1),
          handle.setTTL(64),
          handle.setMulticastTTL(1),
          handle.setMulticastLoopback(1),
          handle.setMulticastInterface('127.0.0.1'),
        ];
        handle.close();
        results.every((status) => typeof status === 'number')
        "#,
    );
    assert_eq!(report, "true");
}

/// `recvStart` on a bound socket begins receiving, and `recvStop` ends it.
///
/// `UV_EALREADY` from a second start is reported as success, matching
/// `src/udp_wrap.cc`.
#[test]
fn recv_start_and_stop_report_success() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        handle.bind('127.0.0.1', 0, 0);
        handle.onmessage = () => {};
        handle.onerror = () => {};
        const started = handle.recvStart();
        const again = handle.recvStart();
        const stopped = handle.recvStop();
        handle.close();
        [started, again, stopped].join(',')
        "#,
    );
    assert_eq!(report, "0,0,0");
}

/// `getAsyncId` hands out a real id, which `lib/dgram.js` stores in
/// `async_id_symbol` for every socket.
#[test]
fn a_handle_reports_an_async_id() {
    let report = eval(
        r#"
        const first = new __udp.UDP();
        const second = new __udp.UDP();
        const ids = [first.getAsyncId(), second.getAsyncId()];
        first.close();
        second.close();
        [ids[0] > 0, ids[0] !== ids[1]].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true",
        "async ids are positive and each handle gets its own"
    );
}

/// `hasRef` tracks libuv's own ref state.
#[test]
fn ref_unref_and_has_ref_track_libuv() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        const before = handle.hasRef();
        handle.unref();
        const afterUnref = handle.hasRef();
        handle.ref();
        const afterRef = handle.hasRef();
        handle.close();
        [before, afterUnref, afterRef].join(',')
        "#,
    );
    assert_eq!(report, "true,false,true");
}

/// Closing twice is a no-op rather than a crash, which is
/// `HandleWrap::Close`'s state guard.
#[test]
fn closing_twice_is_harmless() {
    let report = eval(
        r#"
        const handle = new __udp.UDP();
        handle.close();
        handle.close();
        handle.close();
        'ok'
        "#,
    );
    assert_eq!(report, "ok");
}

/// `SendWrap` is a plain constructor with one internal field, as
/// `AsyncWrap::MakeLazilyInitializedJSTemplate` produces.
#[test]
fn send_wrap_is_constructible() {
    let report = eval(
        r#"
        const req = new __udp.SendWrap();
        req.list = [];
        req.address = '127.0.0.1';
        req.port = 80;
        [typeof req, req.address, __udp.SendWrap.name].join(',')
        "#,
    );
    assert_eq!(report, "object,127.0.0.1,SendWrap");
}

/// Two handles do not share native state, which is what a `Box<uv_udp_t>` per
/// instance buys.
#[test]
fn two_handles_are_independent() {
    let report = eval(
        r#"
        const first = new __udp.UDP();
        const second = new __udp.UDP();
        const a = {};
        const b = {};
        first.bind('127.0.0.1', 0, 0);
        second.bind('127.0.0.1', 0, 0);
        first.getsockname(a);
        second.getsockname(b);
        first.close();
        second.close();
        [a.port !== b.port, a.port > 0, b.port > 0].join(',')
        "#,
    );
    assert_eq!(report, "true,true,true");
}

/// The module declares exactly what it installs.
#[test]
fn the_module_declares_exactly_what_it_installs() {
    assert_eq!(UdpWrap.namespace(), "udp_wrap");
    assert_eq!(UdpWrap.members(), rn_bind_udp_wrap::MEMBERS);
    assert!(
        UdpWrap.deferred().is_empty(),
        "every recorded member is installed, so nothing is deferred"
    );
}
