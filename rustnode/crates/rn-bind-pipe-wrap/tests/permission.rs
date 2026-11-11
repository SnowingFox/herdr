//! The `net` permission checks `pipe_wrap` makes, through a real V8 isolate.
//!
//! `src/pipe_wrap.cc` gates `bind`, `listen`, `fchmod`, `connect` and `open`.
//! The resource differs by member: `bind` and `connect` name the socket path,
//! while `listen` and `fchmod` pass an empty resource because there is no path
//! in their argument list. `connect` also *returns* its denial rather than
//! throwing, for the same reason `tcp_wrap`'s does: `lib/net.js` feeds the value
//! to `ExceptionWithHostPort`.
//!
//! The important behavioural assertion is that a denied `bind` leaves no socket
//! file behind. `uv_pipe_bind2` creates one, so a check placed after the call
//! would leak a filesystem object into a directory the process was told it could
//! not use.

use std::path::PathBuf;

use rn_bind_pipe_wrap::PipeWrap;
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

/// A socket path unique to this process and test.
///
/// Kept short because a unix socket path is limited to about 108 bytes.
fn socket_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rn-perm-{}-{name}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn describe() -> &'static str {
    "const describe = (value) => [value.code, value.permission, JSON.stringify(value.resource)].join(',');"
}

#[test]
fn bind_is_denied_and_creates_no_socket_file() {
    let path = socket_path("bind");
    let report = eval_denied(&format!(
        r#"
        const handle = new __pipe.Pipe(0);
        let error;
        try {{ handle.bind({path:?}); }} catch (thrown) {{ error = thrown; }}
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
        path = path.to_string_lossy(),
    ));
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
    assert!(
        !path.exists(),
        "a denied bind must not leave a socket file at {}",
        path.display()
    );
}

#[test]
fn bind_names_the_socket_path() {
    let path = socket_path("named");
    let report = eval_denied(&format!(
        r#"
        {describe}
        const handle = new __pipe.Pipe(0);
        let error;
        try {{ handle.bind({path:?}); }} catch (thrown) {{ error = thrown; }}
        handle.close();
        error ? describe(error) : 'no-throw'
        "#,
        describe = describe(),
        path = path.to_string_lossy(),
    ));
    assert_eq!(
        report,
        format!(
            "ERR_ACCESS_DENIED,Net,{}",
            serde_json::to_string(path.to_string_lossy().as_ref()).expect("quote the path")
        ),
        "a pipe bind denial must name the socket path"
    );
}

#[test]
fn bind_and_listen_are_allowed_with_the_grant() {
    // Only the statuses are asserted, not the socket file. `uv_pipe_bind2`
    // records the path and the file itself appears when `uv_listen` completes on
    // the loop, and these tests deliberately do not pump one — a file assertion
    // here would be testing the harness rather than the permission check. The
    // `net-tcp`/`net-uds` Node tests cover the real end-to-end path.
    let path = socket_path("allowed");
    let report = eval_allowed(&format!(
        r#"
        const handle = new __pipe.Pipe(0);
        const status = handle.bind({path:?});
        handle.onconnection = () => {{}};
        const listened = handle.listen(511);
        handle.close();
        [status, listened].join(',')
        "#,
        path = path.to_string_lossy(),
    ));
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        report, "0,0",
        "--allow-net must let bind and listen through"
    );
}

#[test]
fn listen_is_denied() {
    let report = eval_denied(
        r#"
        const handle = new __pipe.Pipe(0);
        let error;
        try { handle.listen(511); } catch (thrown) { error = thrown; }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
}

#[test]
fn fchmod_is_denied() {
    // `PipeWrap::Fchmod` is the other member with an empty resource: it changes
    // the mode of the socket file a bind created.
    let report = eval_denied(
        r#"
        const handle = new __pipe.Pipe(0);
        let error;
        try { handle.fchmod(0o600); } catch (thrown) { error = thrown; }
        handle.close();
        [error && error.code, error && error.permission].join(',')
        "#,
    );
    assert_eq!(report, "ERR_ACCESS_DENIED,Net");
}

#[test]
fn connect_returns_the_denial_naming_the_path() {
    let path = socket_path("connect");
    let report = eval_denied(&format!(
        r#"
        {describe}
        const handle = new __pipe.Pipe(0);
        const request = new __pipe.PipeConnectWrap();
        request.oncomplete = () => {{}};
        const result = handle.connect(request, {path:?});
        handle.close();
        typeof result === 'number' ? 'status:' + result : describe(result)
        "#,
        describe = describe(),
        path = path.to_string_lossy(),
    ));
    assert_eq!(
        report,
        format!(
            "ERR_ACCESS_DENIED,Net,{}",
            serde_json::to_string(path.to_string_lossy().as_ref()).expect("quote the path")
        ),
        "a pipe connect denial must name the socket path and be returned"
    );
}

#[test]
fn open_denies_a_descriptor_it_was_not_handed() {
    let report = eval_denied(
        r#"
        const handle = new __pipe.Pipe(0);
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
    // `lib/internal/child_process.js` opens the IPC channel's `Pipe` by
    // descriptor during pre-execution, so requiring `--allow-net` here would make
    // every fork fail under `--permission` before user code ran.
    runtime::set_ipc_channel_fd(9);
    let report = eval_denied(
        r#"
        const results = [];
        for (const fd of [0, 1, 2, 9]) {
          const handle = new __pipe.Pipe(0);
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
    let path = socket_path("nomodel");
    let report = eval(&format!(
        r#"
        const handle = new __pipe.Pipe(0);
        const bound = handle.bind({path:?});
        handle.onconnection = () => {{}};
        const listened = handle.listen(511);
        handle.close();
        [bound, listened].join(',')
        "#,
        path = path.to_string_lossy(),
    ));
    let _ = std::fs::remove_file(&path);
    assert_eq!(report, "0,0");
}

#[test]
fn a_disabled_model_denies_nothing() {
    let path = socket_path("disabled");
    let report = eval_with(
        Some(PermissionModel::disabled()),
        &format!(
            r#"
            const handle = new __pipe.Pipe(0);
            const status = handle.bind({path:?});
            handle.close();
            String(status)
            "#,
            path = path.to_string_lossy(),
        ),
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(report, "0");
}
