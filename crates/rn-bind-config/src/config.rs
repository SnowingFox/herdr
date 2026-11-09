//! `internalBinding('config')`.
//!
//! `src/node_config.cc` in Node 28. The object is an internal view of compile
//! time options that only `lib/**` reads; command line switches live in
//! `internal/options` instead and are deliberately absent here.
//!
//! Every property below is installed read-only and non-configurable, matching
//! Node's `READONLY_PROPERTY`, which passes `v8::ReadOnly` and leaves the
//! remaining attributes at `v8::None`. `getDefaultLocale` is the single method.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::value::{Member, Value};

/// Members `lib/**` and the contract for `internalBinding('config')` expect.
pub const MEMBERS: &[&str] = &[
    "isDebugBuild",
    "openSSLIsBoringSSL",
    "hasOpenSSL",
    "hasIntl",
    "hasSmallICU",
    "hasTracing",
    "hasNodeOptions",
    "hasInspector",
    "noBrowserGlobals",
    "bits",
    "getDefaultLocale",
];

/// Values of the `config` namespace for a default Linux release build.
///
/// Each choice below follows the build option Node's own release binaries use.
/// Where a fact is conditional on a configure switch, the switch is named so
/// the assumption can be re-checked instead of silently drifting.
pub const VALUES: &[Member] = &[
    // `#if defined(DEBUG) && DEBUG`. Release builds define neither.
    ("isDebugBuild", Value::Bool(false)),
    // `#ifdef OPENSSL_IS_BORINGSSL`. Node's release binaries link OpenSSL, and
    // the vendored `deps/openssl` is upstream OpenSSL 4.1.0, not BoringSSL.
    ("openSSLIsBoringSSL", Value::Bool(false)),
    // `#if HAVE_OPENSSL`. A default build links the vendored OpenSSL.
    ("hasOpenSSL", Value::Bool(true)),
    // `#ifdef NODE_HAVE_I18N_SUPPORT`, on unless configured --without-intl.
    // Everything guarded by it (`icu`, `encoding_binding` transcoding,
    // `inspect` string width) only works when this is true.
    ("hasIntl", Value::Bool(true)),
    // `#ifdef NODE_HAVE_SMALL_ICU`, only set by the `small-icu` configure
    // option. A default Linux release build downloads full ICU data.
    ("hasSmallICU", Value::Bool(false)),
    // `#if NODE_USE_V8_PLATFORM`, inside the small-ICU guard. True because
    // `trace_events` needs platform tracing; rustnode links V8's default
    // platform, which is the same condition.
    ("hasTracing", Value::Bool(true)),
    // `#if !defined(NODE_WITHOUT_NODE_OPTIONS)`, inside the small-ICU guard.
    // `NODE_WITHOUT_NODE_OPTIONS` is only set by Android and embedder builds.
    ("hasNodeOptions", Value::Bool(true)),
    // `#if HAVE_INSPECTOR`. The inspector is built unless --without-inspector.
    // `lib/inspector.js` throws ERR_INSPECTOR_NOT_AVAILABLE when this is false,
    // so it must only become false together with the `inspector` binding.
    ("hasInspector", Value::Bool(true)),
    // `#ifdef NODE_NO_BROWSER_GLOBALS`, set by --no-browser-globals. Default
    // builds keep the browser globals, so this is false.
    ("noBrowserGlobals", Value::Bool(false)),
];

/// The `config` namespace.
#[derive(Debug, Default, Clone, Copy)]
pub struct Config;

impl Config {
    /// Number of bits in a pointer, as `config.bits` reports it.
    #[must_use]
    pub fn bits() -> i32 {
        // Deriving this from the target keeps a 32-bit build honest; Node
        // computes the same expression at runtime.
        (std::mem::size_of::<usize>() * 8) as i32
    }

    /// Value of one `config` property, for tests and documentation.
    #[must_use]
    pub fn get(name: &str) -> Option<Value> {
        if name == "bits" {
            return Some(Value::int(i64::from(Self::bits())));
        }
        VALUES
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }
}

impl BindingModule for Config {
    fn namespace(&self) -> &'static str {
        "config"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        for (name, value) in VALUES {
            crate::install_readonly(scope, object, name, *value)?;
        }

        // `bits` is `8 * sizeof(intptr_t)` in Node, so it is computed from the
        // target rather than tabled: 64 here, and still correct on a 32-bit
        // build.
        crate::install_readonly(scope, object, "bits", Value::int(i64::from(Self::bits())))?;

        // Node installs this with `SetMethodNoSideEffect`, so the function is a
        // plain data property rather than an accessor.
        let function = match v8::Function::builder(get_default_locale)
            .length(0)
            .build(scope)
        {
            Some(function) => function,
            None => {
                return Err("config.getDefaultLocale: could not create function".to_string());
            }
        };
        let key = crate::string(scope, "getDefaultLocale")?;
        object
            .set(scope, key.into(), function.into())
            .ok_or_else(|| "config.getDefaultLocale: could not define property".to_string())?;

        Ok(object)
    }
}

/// `Isolate::GetDefaultLocale()`, the host locale as a BCP 47 tag.
///
/// Node returns the isolate's locale, so a caller that sets
/// `v8::V8::set_default_locale` (or boots with `LANG`) sees the same value here
/// as `Intl` does.
fn get_default_locale<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let locale = v8::icu::get_language_tag();
    match v8::String::new(scope, &locale) {
        Some(value) => rv.set(value.into()),
        // `v8::String::new` only fails on allocation failure or an oversized
        // string; neither is recoverable from a binding, and Node's own
        // `ToV8Value` failure path also leaves the return value unset.
        None => rv.set_undefined(),
    }
}
