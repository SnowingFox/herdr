//! A real UDP round trip through libuv, driven the way `lib/dgram.js` drives it.
//!
//! The contract test in `tests/contract.rs` proves the shapes; this proves the
//! behaviour. A socket binds on loopback, a second socket sends it a datagram, the
//! first one's `onmessage` sees the bytes and the sender's address, and both close.
//!
//! The receive and send callbacks run inside `uv_run`, so this pumps
//! `rn_uv::uv_loop` the way the CLI will: a bounded loop rather than `run()`, so a
//! callback that never fires fails the test instead of hanging the suite.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rn_bind_udp_wrap::UdpWrap;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// What the receiver saw: `(nread, bytes, address, family, port)`.
type Received = (i64, Vec<u8>, String, String, u16);
/// What the sender's completion reported: `(status, bytes)`.
type Sent = (i64, i64);

static RECEIVED: Mutex<Option<Received>> = Mutex::new(None);
static SENT: Mutex<Option<Sent>> = Mutex::new(None);
/// Set once the receive callback has run, so the pump can stop early.
static RECEIVED_FLAG: AtomicBool = AtomicBool::new(false);
/// Set once the send completion has run.
static SENT_FLAG: AtomicBool = AtomicBool::new(false);

#[test]
fn a_datagram_travels_from_one_socket_to_another() {
    with_context(|scope| {
        install(scope);

        // Bind the receiver first so the sender knows where to aim, then start
        // receiving — the same order `dgram.bind()` uses.
        run(
            scope,
            r#"
            globalThis.__receiver = new __udp.UDP();
            globalThis.__bound = __receiver.bind('127.0.0.1', 0, 0);
            globalThis.__address = {};
            __receiver.getsockname(__address);
            __receiver.onmessage = globalThis.__onmessage;
            __receiver.onerror = (nread, handle, error) => {
              globalThis.__error = String(error);
            };
            globalThis.__recvStarted = __receiver.recvStart();
            "#,
        );
        assert_eq!(run(scope, "__bound"), "0", "the receiver must bind");
        assert_eq!(run(scope, "__recvStarted"), "0", "recvStart must succeed");

        // The sender sends one datagram to the port the kernel assigned. The
        // chunks arrive as a `Buffer`, which is what `dgram.send` passes.
        run(
            scope,
            r#"
            globalThis.__sender = new __udp.UDP();
            globalThis.__senderReq = new __udp.SendWrap();
            globalThis.__senderReq.oncomplete = globalThis.__onsent;
            globalThis.__payload = new Uint8Array([112, 105, 110, 103, 10]);
            globalThis.__sendStatus = __sender.send(
              __senderReq, [__payload], 1, __address.port, '127.0.0.1', true);
            "#,
        );
        let send_status = run(scope, "__sendStatus");
        // Either a synchronous send, reported as `msg_size + 1` (which is what
        // lets `lib/dgram.js` tell a zero-length inline send from a queued one),
        // or a queued send reported as `0`.
        let synchronous = send_status == "6";
        assert!(
            synchronous || send_status == "0",
            "send must report msg_size + 1 for an inline completion or 0 for a queued one, got {send_status}"
        );

        pump_until(|| {
            RECEIVED_FLAG.load(Ordering::SeqCst)
                && (synchronous || SENT_FLAG.load(Ordering::SeqCst))
        });

        let received = RECEIVED
            .lock()
            .expect("the receive slot must not be poisoned")
            .clone();
        let Some((nread, bytes, address, family, port)) = received else {
            panic!("the receiver must have delivered a datagram");
        };
        assert_eq!(nread, 5, "the byte count is the datagram's length");
        assert_eq!(bytes, b"ping\n", "the bytes must arrive unchanged");
        assert_eq!(address, "127.0.0.1", "the sender's address is reported");
        assert_eq!(family, "IPv4");
        assert_ne!(port, 0, "the sender's port is reported");

        if !synchronous {
            let sent = *SENT.lock().expect("the send slot must not be poisoned");
            let Some((status, size)) = sent else {
                panic!("a queued send must complete");
            };
            assert_eq!(status, 0, "the queued send must succeed");
            assert_eq!(size, 5, "the completion reports the message size");
        }

        // Both sockets close, and the loop drains.
        run(
            scope,
            r#"
            __sender.close();
            __receiver.close();
            'ok'
            "#,
        );
        assert_eq!(
            run(scope, "globalThis.__error === undefined"),
            "true",
            "no receive error may be reported"
        );
    });
}

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

/// Installs `udp_wrap` and the two callbacks the receive and send paths need.
///
/// The callbacks are JavaScript functions that record into statics through V8, so
/// the assertions can see what libuv delivered without a second binding.
fn install(scope: &mut v8::PinScope<'_, '_>) {
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

    // `onmessage(nread, handle, buf, rinfo)`, exactly as `lib/dgram.js` reads it.
    run(
        scope,
        r#"
        globalThis.__onmessage = function (nread, handle, buf, rinfo) {
          const bytes = [];
          for (let i = 0; i < buf.length; i++) bytes.push(String.fromCharCode(buf[i]));
          globalThis.__report(nread, bytes.join(''), rinfo.address, rinfo.family, rinfo.port);
        };
        globalThis.__onsent = function (status, size) {
          globalThis.__reportSent(status, size);
        };
        "#,
    );

    let report = record_from_js(scope, report_received);
    global.set(scope, key_report(scope, "__report").into(), report);
    let sent = record_from_js(scope, report_sent);
    global.set(scope, key_report(scope, "__reportSent").into(), sent);
}

fn key_report<'s>(scope: &v8::PinScope<'s, '_>, name: &str) -> v8::Local<'s, v8::String> {
    v8::String::new(scope, name).expect("allocating a report key")
}

fn record_from_js<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::Value> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    template
        .get_function(scope)
        .expect("allocating a report function")
        .into()
}

/// `__report(nread, bytes, address, family, port)`.
fn report_received(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let nread = args.get(0).integer_value(scope).unwrap_or(-1);
    let bytes = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope).into_bytes())
        .unwrap_or_default();
    let address = args
        .get(2)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let family = args
        .get(3)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let port = args.get(4).uint32_value(scope).unwrap_or(0) as u16;

    *RECEIVED
        .lock()
        .expect("the receive slot must not be poisoned") =
        Some((nread, bytes, address, family, port));
    RECEIVED_FLAG.store(true, Ordering::SeqCst);
}

/// `__reportSent(status, size)`.
fn report_sent(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let status = args.get(0).integer_value(scope).unwrap_or(-1);
    let size = args.get(1).integer_value(scope).unwrap_or(-1);
    *SENT.lock().expect("the send slot must not be poisoned") = Some((status, size));
    SENT_FLAG.store(true, Ordering::SeqCst);
}

/// Evaluates `source`, panicking on a throw.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let source = v8::String::new(scope, source).expect("allocating the probe");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
    match script.run(scope) {
        Some(result) => result.to_rust_string_lossy(scope),
        None => {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown".to_string());
            panic!("the probe threw: {message}");
        }
    }
}

/// Pumps the loop until `done` reports true, or fails the test after a bound.
fn pump_until(done: impl Fn() -> bool) {
    // A bounded pump rather than `run()`: a callback that never fires would
    // otherwise block the suite instead of failing it.
    let mut spun = 0;
    while spun < 5000 && !done() {
        rn_uv::uv_loop::run_once();
        spun += 1;
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        done(),
        "the loop must deliver the datagram within {spun} spins"
    );
}
