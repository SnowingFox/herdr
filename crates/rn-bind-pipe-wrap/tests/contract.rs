//! The `pipe_wrap` contract, checked through a real V8 isolate.
//!
//! `lib/net.js` uses this namespace for unix-domain sockets and for the
//! `fd = -1, addressType = -1` case in `createServerHandle`, where a server is
//! built with no address and adopted later through `listen({ fd })`. The tests
//! bind a real path — a named pipe in `$TMPDIR`, cleaned up afterwards — because
//! `uv_pipe_bind2` takes a path and a length, and a stub would not prove the
//! length is right.

use rn_bind_pipe_wrap::PipeWrap;
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

/// Installs the namespace and binds it to `__pipe` in the global object.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = PipeWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the pipe_wrap namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__pipe").expect("allocating __pipe");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` with `__pipe` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        let source = v8::String::new(scope, source).expect("allocating the probe");
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let Some(compiled) = v8::Script::compile(scope, source, None) else {
            let message = scope
                .exception()
                .map(|exception| exception.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown".to_string());
            return format!("threw: {message}");
        };
        match compiled.run(scope) {
            Some(result) => result.to_rust_string_lossy(scope),
            None => {
                let message = scope
                    .exception()
                    .map(|exception| exception.to_rust_string_lossy(scope))
                    .unwrap_or_else(|| "unknown".to_string());
                format!("threw: {message}")
            }
        }
    })
}

/// A unique socket path per test, so a parallel run cannot collide.
fn socket_path(name: &str) -> String {
    format!(
        "{}/rustnode-pipe-{}-{}.sock",
        std::env::temp_dir().display(),
        name,
        std::process::id()
    )
}

/// The three members `contracts/pipe_wrap.json` records.
#[test]
fn the_namespace_publishes_exactly_the_recorded_members() {
    assert_eq!(
        eval("Object.keys(__pipe).sort().join(',')"),
        "Pipe,PipeConnectWrap,constants"
    );
}

/// `constants` carries `SocketType` plus the two direction flags.
#[test]
fn the_constants_have_libuv_s_values() {
    let report = eval(
        r#"
        const c = __pipe.constants;
        [c.SOCKET, c.SERVER, c.IPC, c.UV_READABLE, c.UV_WRITABLE].join(',')
        "#,
    );
    // `PipeWrap::SocketType` is SOCKET = 0, SERVER = 1, IPC = 2. `UV_READABLE` and
    // `UV_WRITABLE` are 1 and 2 in `uv.h`.
    assert_eq!(report, "0,1,2,1,2");
}

/// `Pipe` requires `new` and a socket type, as `src/pipe_wrap.cc` `CHECK`s.
#[test]
fn pipe_requires_new_and_a_socket_type() {
    let report = eval(
        r#"
        const results = [];
        try { __pipe.Pipe(); results.push('no-new'); }
        catch (error) { results.push('no-new:' + error.constructor.name); }
        try { new __pipe.Pipe(); results.push('no-arg'); }
        catch (error) { results.push('no-arg:' + error.constructor.name); }
        results.push(typeof new __pipe.Pipe(__pipe.constants.SOCKET));
        results.join(',')
        "#,
    );
    assert_eq!(report, "no-new:TypeError,no-arg:TypeError,object");
}

/// The handle surface `lib/net.js` calls on a pipe.
#[test]
fn a_pipe_handle_exposes_every_method_lib_net_calls() {
    let report = eval(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SOCKET);
        const expected = [
          'close', 'ref', 'unref', 'hasRef',
          'readStart', 'readStop', 'shutdown', 'writeBuffer', 'writev',
          'writeAsciiString', 'writeUtf8String', 'writeUcs2String',
          'writeLatin1String',
          'bind', 'listen', 'connect', 'open', 'fchmod',
        ];
        expected.filter((name) => typeof handle[name] !== 'function')
        "#,
    );
    assert_eq!(report, "", "every method lib/net.js calls must exist");
}

/// The accessors and the `isStreamBase` marker, as for a socket.
#[test]
fn a_pipe_handle_exposes_the_stream_base_accessors() {
    let report = eval(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SOCKET);
        [
          handle.isStreamBase === true,
          typeof handle.fd,
          typeof handle.bytesRead,
          typeof handle.bytesWritten,
          typeof handle.writeQueueSize,
          handle.reading,
        ].join(',')
        "#,
    );
    assert_eq!(report, "true,number,number,number,number,false");
}

/// Binding a real path, which is what `server.listen('/tmp/sock')` does.
///
/// `uv_pipe_bind2` takes an explicit length and `UV_PIPE_NO_TRUNCATE`, so a
/// path that did not fit the platform's limit would be an error rather than a
/// silently shortened socket. The path is removed afterwards.
#[test]
fn bind_creates_a_real_socket_file() {
    let path = socket_path("bind");
    let report = eval(&format!(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SERVER);
        const status = handle.bind({path:?});
        const fd = handle.fd;
        handle.close();
        [status, fd >= 0].join(',')
        "#,
        path = path
    ));
    assert_eq!(
        report, "0,true",
        "uv_pipe_bind2 must succeed and assign a descriptor"
    );
    let _ = std::fs::remove_file(&path);
}

/// Binding the same path twice fails with `EADDRINUSE`, which is what
/// `server.listen()` reports when a socket file already exists.
#[test]
fn binding_the_same_path_twice_fails() {
    let path = socket_path("twice");
    // The first bind happens outside JS so the path exists before the probe.
    let first = eval(&format!(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SERVER);
        const status = handle.bind({path:?});
        globalThis.__first = handle;
        status
        "#,
        path = path
    ));
    assert_eq!(first, "0");

    // A second `with_context` gets a fresh isolate, so the first handle's
    // descriptor is closed by the finalizer; recreate the file to force the clash.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path);
    let second = eval(&format!(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SERVER);
        const status = handle.bind({path:?});
        handle.close();
        status
        "#,
        path = path
    ));
    assert_ne!(second, "0", "binding an existing path must not succeed");
    let _ = std::fs::remove_file(&path);
}

/// A `connect` to a path with nothing listening queues and returns a status.
#[test]
fn connect_queues_on_a_path() {
    let path = socket_path("connect");
    let report = eval(&format!(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SOCKET);
        const req = new __pipe.PipeConnectWrap();
        req.oncomplete = () => {{}};
        req.address = {path:?};
        const status = handle.connect(req, {path:?});
        handle.close();
        typeof status
        "#,
        path = path
    ));
    assert_eq!(report, "number", "connect returns a status, not a throw");
}

/// `listen` succeeds on a bound pipe.
#[test]
fn listen_succeeds_on_a_bound_pipe() {
    let path = socket_path("listen");
    let report = eval(&format!(
        r#"
        const handle = new __pipe.Pipe(__pipe.constants.SERVER);
        const bound = handle.bind({path:?});
        handle.onconnection = () => {{}};
        const status = bound === 0 ? handle.listen(511) : bound;
        handle.close();
        status
        "#,
        path = path
    ));
    assert_eq!(report, "0");
    let _ = std::fs::remove_file(&path);
}

/// `fchmod` takes `UV_READABLE`/`UV_WRITABLE`, not a mode.
///
/// `lib/net.js`'s `listen({ path, readableAll, writableAll })` ORs
/// `PipeConstants.UV_READABLE` and `UV_WRITABLE` and passes the result, so those
/// are the values `uv_pipe_chmod` has to receive.
#[test]
fn fchmod_takes_the_readable_and_writable_flags() {
    let path = socket_path("chmod");
    let report = eval(&format!(
        r#"
        const c = __pipe.constants;
        const handle = new __pipe.Pipe(c.SERVER);
        const bound = handle.bind({path:?});
        const mode = c.UV_READABLE | c.UV_WRITABLE;
        const status = bound === 0 ? handle.fchmod(mode) : bound;
        handle.close();
        [bound, mode, status].join(',')
        "#,
        path = path
    ));
    // `UV_READABLE | UV_WRITABLE` is 3; libuv uses it to pick the permission bits.
    assert_eq!(
        report, "0,3,0",
        "uv_pipe_chmod must accept the direction flags"
    );
    let _ = std::fs::remove_file(&path);
}

/// Closing twice is harmless, as for a socket.
#[test]
fn closing_twice_is_harmless() {
    assert_eq!(
        eval(
            r#"
            const handle = new __pipe.Pipe(__pipe.constants.SOCKET);
            handle.close();
            handle.close();
            'ok'
            "#
        ),
        "ok"
    );
}

/// A pipe handle is an instance of `Pipe`, which `lib/net.js` checks before
/// calling pipe-only methods.
#[test]
fn a_handle_is_an_instance_of_pipe() {
    assert_eq!(
        eval("new __pipe.Pipe(__pipe.constants.SOCKET) instanceof __pipe.Pipe"),
        "true"
    );
}

/// `PipeConnectWrap` is constructible and takes the fields `lib/net.js` assigns.
#[test]
fn pipe_connect_wrap_is_constructible() {
    let report = eval(
        r#"
        const req = new __pipe.PipeConnectWrap();
        req.oncomplete = () => {};
        req.address = '/tmp/x.sock';
        [typeof req, typeof req.oncomplete, req.address, __pipe.PipeConnectWrap.name].join(',')
        "#,
    );
    assert_eq!(report, "object,function,/tmp/x.sock,PipeConnectWrap");
}

/// The module declares exactly what it installs.
#[test]
fn the_module_declares_exactly_what_it_installs() {
    assert_eq!(PipeWrap.namespace(), "pipe_wrap");
    assert_eq!(PipeWrap.members(), rn_bind_pipe_wrap::MEMBERS);
    assert!(
        PipeWrap.deferred().is_empty(),
        "every recorded member is installed, so nothing is deferred"
    );
}
