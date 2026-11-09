//! `internalBinding('builtins')`.
//!
//! This is the namespace Node's `lib/internal/bootstrap/realm.js` reads before
//! anything else. It hands the JavaScript layer the builtin table and the
//! compiler that turns a builtin id into a callable function, which is what
//! makes `require('node:fs')` resolve inside Node's own loader instead of a
//! Rust-side module map.
//!
//! Node splits the responsibilities across two C++ files: `node_builtins.cc`
//! owns the table and `BuiltinLoader::LookupAndCompile` owns compilation. Both
//! land here, because the JavaScript layer sees them as one object.

use rn_core::{BindingModule, InstallCtx};
use rn_js2c::{builtin_by_id, builtin_sources, core_ids, internal_ids, BuiltinKind};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/builtins.json`.
pub const MEMBERS: &[&str] = &[
    "builtinCategories",
    "builtinIds",
    "compileFunction",
    "config",
    "configs",
    "getCacheUsage",
    "hasCachedBuiltins",
    "importBuiltinSourceTextModule",
    "natives",
    "setInternalLoaders",
];

pub struct Builtins;

impl BindingModule for Builtins {
    fn namespace(&self) -> &'static str {
        "builtins"
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

        let config =
            v8::String::new(scope, BUILD_CONFIG).ok_or("cannot allocate the config string")?;
        set(scope, object, "config", config.into())?;
        set(scope, object, "configs", v8::undefined(scope).into())?;

        let values: [(&str, v8::Local<v8::Value>); 9] = [
            ("config", config.into()),
            ("configs", v8::undefined(scope).into()),
            ("builtinIds", id_array(scope)),
            ("builtinCategories", categories(scope)),
            ("natives", natives(scope)),
            (
                "hasCachedBuiltins",
                function(scope, "hasCachedBuiltins", has_cached_builtins)?,
            ),
            (
                "getCacheUsage",
                function(scope, "getCacheUsage", cache_usage)?,
            ),
            (
                "setInternalLoaders",
                function(scope, "setInternalLoaders", set_internal_loaders)?,
            ),
            (
                "importBuiltinSourceTextModule",
                function(
                    scope,
                    "importBuiltinSourceTextModule",
                    import_source_text_module,
                )?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        let compile = function(scope, "compileFunction", compile_function_callback)?;
        set(scope, object, "compileFunction", compile)?;

        Ok(object)
    }
}

/// Build configuration a real Node publishes as its `config.gypi` string.
///
/// rustnode does not generate a `config.gypi`, so this reproduces the keys the
/// JavaScript layer reads rather than shipping a whole gyp file. Note that the
/// separate native `config` namespace is what `buffer.js` consults for ICU and
/// inspector support; this string is read by the bootstrap switches.
const BUILD_CONFIG: &str = concat!(
    "{\"variables\":{\"v8_enable_i18n_support\":1,",
    "\"node_use_openssl\":1,\"node_shared_openssl\":0,",
    "\"node_use_bundled_ca\":1,\"node_use_dtrace\":0,",
    "\"node_use_etw\":0,\"node_use_perfetto\":0,",
    "\"node_shareable_openssl\":0,\"node_enable_v8_vtune_profiling\":0,",
    "\"node_target_type\":\"executable\"}}"
);

fn id_array<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let ids: Vec<&'static str> = builtin_sources()
        .iter()
        .map(|builtin| builtin.id())
        .collect();
    let array = v8::Array::new(scope, ids.len() as i32);
    for (index, id) in ids.iter().enumerate() {
        if let Some(value) = v8::String::new(scope, id) {
            array.set_index(scope, index as u32, value.into());
        }
    }
    array.into()
}

/// `{ canBeRequired, cannotBeRequired }`, which is how `realm.js` splits public
/// ids from internal ones without parsing the `internal/` prefix itself.
fn categories<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    let public: Vec<&'static str> = core_ids().collect();
    let internal: Vec<&'static str> = internal_ids().collect();
    for (name, ids) in [("canBeRequired", &public), ("cannotBeRequired", &internal)] {
        let array = v8::Array::new(scope, ids.len() as i32);
        for (index, id) in ids.iter().enumerate() {
            if let Some(value) = v8::String::new(scope, id) {
                array.set_index(scope, index as u32, value.into());
            }
        }
        if let Some(key) = v8::String::new(scope, name) {
            object.set(scope, key.into(), array.into());
        }
    }
    object.into()
}

/// `{ id: source }`, the legacy `process.binding('natives')` table.
fn natives<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let object = v8::Object::new(scope);
    for builtin in builtin_sources() {
        let (Some(key), Some(source)) = (
            v8::String::new(scope, builtin.id()),
            v8::String::new(scope, builtin.source()),
        ) else {
            continue;
        };
        object.set(scope, key.into(), source.into());
    }
    object.into()
}

fn compile_function_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let Some(id_value) = args.get(0).to_string(scope) else {
        return;
    };
    let id = id_value.to_rust_string_lossy(scope);
    let Some(builtin) = builtin_by_id(&id) else {
        throw(scope, &format!("Unknown builtin '{id}'"));
        return;
    };
    match compile(scope, builtin.id(), builtin.source(), builtin.kind()) {
        Some(function) => rv.set(function.into()),
        None => throw(scope, &format!("Failed to compile builtin '{id}'")),
    }
}

/// Compiles one builtin the way `BuiltinLoader::LookupAndCompile` does, with the
/// wrapper parameters its kind requires.
pub fn compile<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: &str,
    source: &str,
    kind: BuiltinKind,
) -> Option<v8::Local<'s, v8::Function>> {
    let origin_name = v8::String::new(scope, id)?;
    let origin = v8::ScriptOrigin::new(
        scope,
        origin_name.into(),
        0,
        0,
        false,
        0,
        None,
        false,
        false,
        false,
        None,
    );
    let text = v8::String::new(scope, source)?;
    let mut source_text = v8::script_compiler::Source::new(text, Some(&origin));
    let parameters: Vec<v8::Local<v8::String>> = kind
        .parameters()
        .iter()
        .filter_map(|parameter| v8::String::new(scope, parameter))
        .collect();
    v8::script_compiler::compile_function(
        scope,
        &mut source_text,
        &parameters,
        &[],
        v8::script_compiler::CompileOptions::NoCompileOptions,
        v8::script_compiler::NoCacheReason::NoReason,
    )
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a member name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn has_cached_builtins(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Boolean::new(scope, false).into());
}

fn cache_usage(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Number::new(scope, 0.0).into());
}

/// Stores the loaders `realm.js` hands over.
///
/// Everything the bootstrap runs afterwards closes over these, and the CLI needs
/// `require` to run a user script, so a silent no-op here leaves the whole
/// runtime without a module loader.
fn set_internal_loaders(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let internal_binding = v8::Local::<v8::Function>::try_from(args.get(0));
    let require = v8::Local::<v8::Function>::try_from(args.get(1));
    let (Ok(internal_binding), Ok(require)) = (internal_binding, require) else {
        throw(scope, "setInternalLoaders expects two functions");
        return;
    };
    rn_core::hook_slot::set_internal_loaders(
        v8::Global::new(scope, internal_binding),
        v8::Global::new(scope, require),
    );
}

fn import_source_text_module(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    throw(
        scope,
        "importBuiltinSourceTextModule is not implemented yet",
    );
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

/// Registers the `builtins` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Builtins);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_list_covers_the_recorded_contract() {
        assert_eq!(MEMBERS.len(), 10);
        for member in [
            "compileFunction",
            "builtinIds",
            "setInternalLoaders",
            "natives",
        ] {
            assert!(MEMBERS.contains(&member), "{member} missing");
        }
    }

    #[test]
    fn every_builtin_is_addressable_by_id() {
        for builtin in builtin_sources() {
            assert!(
                builtin_by_id(builtin.id()).is_some(),
                "{} missing from the id index",
                builtin.id()
            );
        }
    }

    #[test]
    fn the_realm_bootstrap_is_a_bootstrap_kind_with_process_parameters() {
        let realm = builtin_by_id("internal/bootstrap/realm").expect("realm builtin");
        assert_eq!(realm.kind(), BuiltinKind::BootstrapRealm);
        assert_eq!(
            realm.parameters(),
            &[
                "process",
                "getLinkedBinding",
                "getInternalBinding",
                "primordials"
            ]
        );
    }

    #[test]
    fn public_and_internal_builtins_partition_the_table() {
        let total = builtin_sources().len();
        let public = core_ids().count();
        let internal = internal_ids().count();
        assert_eq!(
            public + internal,
            total,
            "categories must partition the table"
        );
    }
}
