//! Installing this crate's members into a bare V8 context, for the tests.
//!
//! `BunModule` is the contract, so a test installs through it rather than
//! through a crate-root shortcut: that keeps the trait object under test instead
//! of a parallel path only the tests use.

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

// Each test binary uses a different subset of these helpers, so an unused
// helper here is expected rather than dead code.
#[allow(dead_code)]
mod _unused_marker {}

/// Runs `body` with a live isolate, scope and bare context.
pub fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

/// Installs the members on a fresh object and returns it.
pub fn install<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Object> {
    let bun = v8::Object::new(scope);
    rn_bun_text::Text
        .install(scope, bun)
        .expect("the text module installs");
    bun
}

/// Installs the members and publishes the object as the global `Bun`.
///
/// Only some of this crate's integration tests reach the global-install path, so
/// the lint fires for the binaries that do not. Per-function, so a real dead
/// helper still reports.
#[allow(dead_code)]
pub fn install_as_global(scope: &mut v8::PinScope<'_, '_>) {
    let bun = install(scope);
    let key = v8::String::new(scope, "Bun").expect("key");
    scope
        .get_current_context()
        .global(scope)
        .set(scope, key.into(), bun.into())
        .expect("publish Bun");
}

/// Installs the members as a `__bun` global, for scripts that prefer a private
/// name over the realm's real `Bun`.
///
/// `common` is compiled into every integration test binary in this crate, and
/// only `buffers_parity` uses this one, so the lint fires for the others. The
/// allowance is per-function rather than crate-wide so a genuinely unused
/// helper still reports.
#[allow(dead_code)]
pub fn install_as_private_global(scope: &mut v8::PinScope<'_, '_>) {
    let bun = install(scope);
    let key = v8::String::new(scope, "__bun").expect("key");
    scope
        .get_current_context()
        .global(scope)
        .set(scope, key.into(), bun.into())
        .expect("publish __bun");
}

/// Serialises the script's completion value through `JSON.stringify`.
pub fn json_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> serde_json::Value {
    let json_key = v8::String::new(scope, "JSON").expect("JSON");
    let json = scope
        .get_current_context()
        .global(scope)
        .get(scope, json_key.into())
        .expect("JSON");
    let stringify_key = v8::String::new(scope, "stringify").expect("stringify");
    let stringify = json
        .to_object(scope)
        .and_then(|object| object.get(scope, stringify_key.into()))
        .expect("stringify");
    let stringify = v8::Local::<v8::Function>::try_from(stringify).expect("function");
    let text = stringify
        .call(scope, json, &[value])
        .expect("stringify result")
        .to_rust_string_lossy(scope);
    serde_json::from_str(&text).expect("valid JSON")
}

/// Compiles and runs a script.
#[allow(dead_code)]
pub fn eval<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let source = v8::String::new(scope, source)?;
    let script = v8::Script::compile(scope, source, None)?;
    script.run(scope)
}
