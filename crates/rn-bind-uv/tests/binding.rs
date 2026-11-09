//! Behaviour of the three functions, driven through a real V8 isolate.
//!
//! `lib/internal/errors.js` reaches this namespace through `internalBinding` and
//! reads it in a very specific way: `getErrorMap()` must return a `Map` keyed by
//! *number* whose entries are `[name, message]` pairs, because it destructures
//! `{ 0: code, 1: uvmsg }`. `errname` and `getErrorMessage` must return strings.
//! These tests install the namespace the way the runtime does and read it back
//! from JavaScript, so the shapes are checked rather than assumed.

use rn_bind_uv::{message, name, Uv};
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
///
/// V8's platform and initialization are process-global, so the tests serialize
/// on a mutex instead of each calling `V8::initialize`.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // The guard must outlive the isolate: dropping it would let a second test
    // enter `V8::initialize` concurrently.
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
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

/// Installs the namespace and binds it to `__uv` in the global object.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = Uv
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the uv namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__uv").expect("allocating __uv");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` with `__uv` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        let source = v8::String::new(scope, source).expect("allocating the probe");
        let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
        let result = script.run(scope).expect("running the probe");
        result.to_rust_string_lossy(scope)
    })
}

#[test]
fn errname_returns_libuv_s_names_for_system_errnos() {
    // Values chosen because their meaning is unambiguous and because they are the
    // ones the JavaScript layer compares against: ENOENT and EACCES from fs and
    // child_process, EAGAIN and EINVAL from net and dgram.
    for (errno, expected) in [
        (-libc::ENOENT, "ENOENT"),
        (-libc::EACCES, "EACCES"),
        (-libc::EAGAIN, "EAGAIN"),
        (-libc::EINVAL, "EINVAL"),
        (-libc::EBADF, "EBADF"),
        (-libc::EPIPE, "EPIPE"),
        (-libc::ETIMEDOUT, "ETIMEDOUT"),
    ] {
        assert_eq!(name(errno), expected, "errname({errno})");
    }
}

#[test]
fn errname_returns_the_name_for_libuv_only_errors() {
    // Codes with no system errno: the sentinels Node raises itself.
    assert_eq!(name(-4095), "EOF");
    assert_eq!(name(-4094), "UNKNOWN");
    assert_eq!(name(-3008), "EAI_NONAME");
    assert_eq!(name(-4080), "ECHARSET");
    assert_eq!(name(-4028), "EFTYPE");
}

#[test]
fn errname_falls_back_like_uv_err_name() {
    // `uv__unknown_err_code` is what libuv returns for anything not in the map,
    // and `git`-style callers see this string through
    // `util.getSystemErrorName`'s non-map path.
    assert_eq!(name(-12345), "Unknown system error -12345");
    assert_eq!(name(-1024), "Unknown system error -1024");
    assert_eq!(name(-2147483648), "Unknown system error -2147483648");
    // `uv_err_name` itself returns a bare name here, so the fallback must not
    // accidentally include the `UV_` prefix.
    assert!(!name(-12345).starts_with("UV_"));
}

#[test]
fn get_error_message_returns_libuv_s_text() {
    // These are the exact strings `UVException` puts in `error.message`, so a
    // paraphrase would change every fs and net error message in the runtime.
    for (errno, expected) in [
        (-libc::ENOENT, "no such file or directory"),
        (-libc::EACCES, "permission denied"),
        (-libc::EEXIST, "file already exists"),
        (-libc::ENOTDIR, "not a directory"),
        (-libc::EISDIR, "illegal operation on a directory"),
        (-libc::ENOTEMPTY, "directory not empty"),
        (-libc::EPERM, "operation not permitted"),
        (-libc::EINVAL, "invalid argument"),
        (-4095, "end of file"),
        (-4094, "unknown error"),
        (-3000, "address family not supported"),
    ] {
        assert_eq!(message(errno), expected, "getErrorMessage({errno})");
    }
}

#[test]
fn get_error_message_falls_back_like_uv_strerror() {
    assert_eq!(message(-12345), "Unknown system error -12345");
    assert_eq!(message(-2147483648), "Unknown system error -2147483648");
}

#[test]
fn the_message_for_every_entry_is_the_header_s_message() {
    // `errname`'s fallback and `uv_strerror`'s differ only for codes outside the
    // map; inside it, both come from the same row. This pins that the pair is
    // consistent so `errname` cannot end up returning a message.
    for error in rn_bind_uv::ERRORS {
        assert_eq!(name(error.value), error.name);
        assert_eq!(message(error.value), error.message);
        assert_ne!(error.name, error.message);
    }
}

#[test]
fn the_namespace_exposes_every_contract_member() {
    let count = eval(
        r#"
        const names = Object.getOwnPropertyNames(__uv);
        JSON.stringify({ count: names.length, missing: [] });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&count).expect("valid JSON");
    assert_eq!(
        parsed["count"].as_u64().expect("a count"),
        rn_bind_uv::MEMBERS.len() as u64,
        "the installed object must define exactly the declared members"
    );

    for member in rn_bind_uv::MEMBERS {
        let present = eval(&format!(
            "Object.prototype.hasOwnProperty.call(__uv, {member:?}) ? 'yes' : 'no'"
        ));
        assert_eq!(present, "yes", "{member} is declared but not installed");
    }
}

#[test]
fn constants_carry_their_header_values_into_javascript() {
    let json = eval(
        r#"
        JSON.stringify({
          enoent: __uv.UV_ENOENT,
          eacces: __uv.UV_EACCES,
          eof: __uv.UV_EOF,
          unknown: __uv.UV_UNKNOWN,
          eaiNoname: __uv.UV_EAI_NONAME,
          echarset: __uv.UV_ECHARSET,
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["enoent"], -libc::ENOENT);
    assert_eq!(parsed["eacces"], -libc::EACCES);
    assert_eq!(parsed["eof"], -4095);
    assert_eq!(parsed["unknown"], -4094);
    assert_eq!(parsed["eaiNoname"], -3008);
    assert_eq!(parsed["echarset"], -4080);
}

#[test]
fn constants_are_read_only_and_permanent() {
    // `src/uv.cc` passes `ReadOnly | DontDelete`, so a strict-mode assignment or
    // delete throws and the value never changes. `lib/internal/errors.js`
    // compares against these values, so a writable `UV_ENOENT` would be a real
    // hazard.
    let json = eval(
        r#"
        'use strict';
        const outcome = (action) => {
          try { action(); return 'no-throw'; } catch (e) { return e.constructor.name; }
        };
        const assigned = outcome(() => { __uv.UV_ENOENT = 1; });
        const deleted = outcome(() => { delete __uv.UV_ENOENT; });
        JSON.stringify({ assigned, deleted, value: __uv.UV_ENOENT });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        parsed["assigned"], "TypeError",
        "assignment must throw in strict mode"
    );
    assert_eq!(
        parsed["deleted"], "TypeError",
        "delete must throw in strict mode"
    );
    assert_eq!(parsed["value"], -libc::ENOENT);
}

#[test]
fn get_error_map_is_a_map_of_name_and_message_pairs() {
    let json = eval(
        r#"
        const map = __uv.getErrorMap();
        const entry = map.get(__uv.UV_ENOENT);
        JSON.stringify({
          isMap: map instanceof Map,
          size: map.size,
          entry,
          entryLength: entry.length,
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["isMap"], true, "getErrorMap must return a Map");
    assert_eq!(
        parsed["size"].as_u64().expect("a size"),
        rn_bind_uv::ERRORS.len() as u64
    );
    assert_eq!(parsed["entry"][0], "ENOENT");
    assert_eq!(parsed["entry"][1], "no such file or directory");
    assert_eq!(parsed["entryLength"], 2);
}

#[test]
fn get_error_map_covers_every_error_constant() {
    // `lib/internal/errors.js` builds an error by looking up `ctx.errno` in this
    // map; a missing key there silently degrades to "UNKNOWN: unknown error".
    // Only the `UV_` errno constants are keys: `UV_DIRENT_*` are dirent type
    // codes, not errors, and Node's map does not contain them either.
    let json = eval(
        r#"
        const map = __uv.getErrorMap();
        const missing = [];
        let checked = 0;
        for (const key of Object.getOwnPropertyNames(__uv)) {
          if (!key.startsWith('UV_') || key.startsWith('UV_DIRENT_')) continue;
          checked++;
          if (!map.has(__uv[key])) missing.push(key);
        }
        JSON.stringify({ missing, checked, size: map.size });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        parsed["missing"].as_array().expect("an array").len(),
        0,
        "every UV_ error constant must have an entry in the error map"
    );
    assert_eq!(
        parsed["checked"].as_u64().expect("a count"),
        rn_bind_uv::ERRORS.len() as u64
    );
    assert_eq!(
        parsed["size"].as_u64().expect("a size"),
        rn_bind_uv::ERRORS.len() as u64
    );
}

#[test]
fn get_error_map_returns_a_fresh_map_each_call() {
    // `errors.js` caches the first one as `uvBinding.errmap`, so a shared map
    // would be visible to user code that mutates it. Node builds a new Map per
    // call and so must this.
    let json = eval(
        r#"
        const first = __uv.getErrorMap();
        const second = __uv.getErrorMap();
        first.set(-2, ['MUTATED', 'mutated']);
        JSON.stringify({
          distinct: first !== second,
          secondIsIntact: second.get(-2)[0],
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["distinct"], true);
    assert_eq!(parsed["secondIsIntact"], "ENOENT");
}

#[test]
fn errname_and_get_error_message_work_from_javascript() {
    let json = eval(
        r#"
        JSON.stringify({
          name: __uv.errname(-2),
          message: __uv.getErrorMessage(-2),
          unknownName: __uv.errname(-9999),
          unknownMessage: __uv.getErrorMessage(-9999),
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["name"], "ENOENT");
    assert_eq!(parsed["message"], "no such file or directory");
    assert_eq!(parsed["unknownName"], "Unknown system error -9999");
    assert_eq!(parsed["unknownMessage"], "Unknown system error -9999");
}

#[test]
fn functions_look_like_node_s() {
    // Node creates `errname` with `SetConstructorFunction` and the other two with
    // `SetMethod`, which differ in two observable ways: only the former is
    // constructible, and only the former has a `prototype`.
    let json = eval(
        r#"
        const describe = (fn) => ({
          name: fn.name,
          length: fn.length,
          hasPrototype: fn.prototype !== undefined,
        });
        let constructible;
        try { new __uv.getErrorMap(); constructible = true; } catch { constructible = false; }
        JSON.stringify({
          errname: describe(__uv.errname),
          getErrorMap: describe(__uv.getErrorMap),
          getErrorMessage: describe(__uv.getErrorMessage),
          constructible,
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    for member in ["errname", "getErrorMap", "getErrorMessage"] {
        assert_eq!(parsed[member]["name"], member, "{member}.name");
        assert_eq!(parsed[member]["length"], 0, "{member}.length");
    }
    assert_eq!(
        parsed["errname"]["hasPrototype"], true,
        "errname is registered with SetConstructorFunction and keeps a prototype"
    );
    assert_eq!(parsed["getErrorMap"]["hasPrototype"], false);
    assert_eq!(parsed["getErrorMessage"]["hasPrototype"], false);
    assert_eq!(
        parsed["constructible"], false,
        "SetMethod functions cannot be constructed"
    );
}

#[test]
fn arguments_coerce_the_way_javascript_would() {
    // Node casts with `As<Int32>()`; rustnode converts with `int32_value`, which
    // is what makes these read as the values the range check in
    // `util.getSystemErrorName` would have seen rather than as raw bits.
    let json = eval(
        r#"
        const attempt = (fn) => { try { return fn(); } catch (e) { return e.constructor.name; } };
        JSON.stringify({
          missing: __uv.errname(),
          missingMessage: __uv.getErrorMessage(),
          fraction: __uv.errname(-2.9),
          symbol: attempt(() => __uv.errname(Symbol('x'))),
          recovered: __uv.errname(-2),
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["missing"], "Unknown system error 0");
    assert_eq!(parsed["missingMessage"], "Unknown system error 0");
    assert_eq!(parsed["fraction"], "ENOENT", "-2.9 truncates to -2");
    assert_eq!(
        parsed["symbol"], "TypeError",
        "a Symbol cannot convert to a number"
    );
    assert_eq!(
        parsed["recovered"], "ENOENT",
        "a throw must not corrupt later calls"
    );
}

#[test]
fn the_installed_data_satisfies_the_shape_errors_js_depends_on() {
    // `lib/internal/errors.js` reads `const { 0: code, 1: uvmsg } =
    // uvErrmapGet(ctx.errno) || uvUnmappedError` and builds
    // `${code}: ${ctx.message || uvmsg}, ${ctx.syscall}`. This reproduces that
    // exact expression against the map, so the assertion is about the consumer's
    // contract rather than about our table.
    let json = eval(
        r#"
        const uvUnmappedError = ['UNKNOWN', 'unknown error'];
        const errmap = __uv.getErrorMap();
        const uvErrmapGet = (name) => errmap.get(name);
        const format = (errno, message, syscall) => {
          const { 0: code, 1: uvmsg } = uvErrmapGet(errno) || uvUnmappedError;
          return `${code}: ${message || uvmsg}, ${syscall}`;
        };
        JSON.stringify({
          enoent: format(__uv.UV_ENOENT, '', 'open'),
          eacces: format(__uv.UV_EACCES, '', 'access'),
          custom: format(__uv.UV_ENOENT, 'custom text', 'stat'),
          unmapped: format(-9999, '', 'read'),
        });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["enoent"], "ENOENT: no such file or directory, open");
    assert_eq!(parsed["eacces"], "EACCES: permission denied, access");
    assert_eq!(parsed["custom"], "ENOENT: custom text, stat");
    assert_eq!(parsed["unmapped"], "UNKNOWN: unknown error, read");
}

#[test]
fn errname_is_installed_before_the_constants_like_node() {
    // `Object.keys()` order is the registration order, and `src/uv.cc` installs
    // `errname` first and the two methods last. Nothing in `lib/**` depends on it,
    // but `process.binding('uv')` is user-reachable and the order is stable in
    // Node, so matching it costs nothing.
    let json = eval(
        r#"
        const keys = Object.keys(__uv);
        JSON.stringify({ first: keys[0], lastTwo: keys.slice(-2) });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["first"], "errname");
    assert_eq!(parsed["lastTwo"][0], "getErrorMap");
    assert_eq!(parsed["lastTwo"][1], "getErrorMessage");
}
