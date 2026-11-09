//! Proves `internalBinding('string_decoder')` resolves through the real
//! registry, not just when the module is installed directly.
//!
//! The other tests call `StringDecoder::install` themselves, which skips the two
//! pieces a real runtime goes through:
//!
//! 1. `rn_bindings::install_all` discovering this crate at all — that generated
//!    list is the only thing connecting `crates/rn-bind-string-decoder` to the
//!    runtime;
//! 2. `BindingRegistry::install`, which is what `getInternalBinding` calls and
//!    which caches the object per isolate.
//!
//! A crate can compile, pass every behaviour test, and still be invisible to
//! JavaScript if the generated registry missed it. This test closes that gap: it
//! builds the registry the way `rn-cli` does and asks it for the namespace by
//! name, which is the same lookup `lib/string_decoder.js` performs.

use rn_core::BindingRegistry;
use rn_v8_sys::v8;

/// The namespace is registered, claims its ten members, and can be installed.
fn registry_resolves_the_namespace() {
    let mut registry = BindingRegistry::new();
    rn_bindings::install_all(&mut registry);

    // `internalBinding` fails the same way whether the namespace is absent or
    // merely unregistered-and-uninstallable, so check both facts first.
    assert!(
        registry.get("string_decoder").is_some(),
        "install_all must register string_decoder"
    );
    assert!(
        registry.can_install("string_decoder"),
        "string_decoder must have an installer, not just a contract entry"
    );

    let namespace = registry.get("string_decoder").expect("registered");
    assert_eq!(namespace.name, "string_decoder");
    assert_eq!(
        namespace.members.len(),
        10,
        "all ten contract members are claimed"
    );
    assert!(
        namespace.deferred.is_empty(),
        "nothing is deferred: {:?}",
        namespace.deferred
    );
    for member in [
        "decode",
        "encodings",
        "flush",
        "kBufferedBytes",
        "kEncodingField",
        "kIncompleteCharactersEnd",
        "kIncompleteCharactersStart",
        "kMissingBytes",
        "kNumFields",
        "kSize",
    ] {
        assert!(
            namespace.members.contains(member),
            "{member} is claimed by the registry"
        );
    }
}

/// The object `registry.install` builds is the one the JavaScript expects, and a
/// second lookup returns the same object — `internalBinding` is cached per
/// isolate, and `lib/string_decoder.js` and `lib/internal/util.js` both rely on
/// getting the identical namespace.
fn registry_installs_and_caches_the_object() {
    let mut registry = BindingRegistry::new();
    rn_bindings::install_all(&mut registry);

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let first = registry
        .install(scope, "string_decoder")
        .expect("internalBinding('string_decoder') resolves");
    let second = registry
        .install(scope, "string_decoder")
        .expect("the second lookup resolves too");

    // Same object, not a rebuild: `install` returns the cached global.
    assert_eq!(
        first, second,
        "internalBinding must return the identical object twice"
    );

    // The members are live on the object the runtime hands to JavaScript.
    for member in ["decode", "flush", "kSize", "kEncodingField", "encodings"] {
        let key = v8::String::new(scope, member).expect("key");
        let value = first.get(scope, key.into());
        let value = value.unwrap_or_else(|| panic!("{member} is present on the object"));
        assert!(
            !value.is_undefined(),
            "{member} is defined on the installed object"
        );
    }

    // Publish the namespace and drive it from JavaScript, which is the only way
    // to know the callbacks V8 sees behave as `lib/string_decoder.js` expects.
    let global = context.global(scope);
    let key = v8::String::new(scope, "__binding").expect("key");
    global.set(scope, key.into(), first.into());

    let result = run(scope, context);
    assert_eq!(
        result,
        r#"{"kSize":7,"utf8Field":1,"first":"","retained":2,"second":"😀","end":""}"#
    );
}

/// Decodes U+1F600 across two calls through the registry-built object.
fn run(scope: &mut v8::PinScope<'_, '_>, context: v8::Local<v8::Context>) -> String {
    let source = r#"
    (() => {
      const b = globalThis.__binding;
      const encodingsMap = { __proto__: null };
      for (let i = 0; i < b.encodings.length; ++i) encodingsMap[b.encodings[i]] = i;
      const state = new Uint8Array(b.kSize);
      state[b.kEncodingField] = encodingsMap['utf8'];
      const first = b.decode(state, new Uint8Array([0xf0, 0x9f]));
      const retained = state[b.kBufferedBytes];
      const second = b.decode(state, new Uint8Array([0x98, 0x80]));
      const end = b.flush(state);
      return JSON.stringify({
        kSize: b.kSize,
        utf8Field: encodingsMap['utf8'],
        first,
        retained,
        second,
        end,
      });
    })();
    "#;

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    let value = script.run(scope).expect("runs without throwing");
    let _ = context;
    value.to_rust_string_lossy(scope)
}

#[test]
fn internal_binding_string_decoder_resolves() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    registry_resolves_the_namespace();
    registry_installs_and_caches_the_object();
}
