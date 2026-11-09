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

pub mod cache_plan;

include!(concat!(env!("OUT_DIR"), "/builtin_code_cache.rs"));

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

        // `builtinIds` is the only table `realm.js` reads before anything else,
        // so it is the only one built here. `builtinCategories` and `natives`
        // cost real time over all 435 builtins and nothing in the bootstrap
        // reads them; they are accessors that build once, on first use. See
        // `lazy_member` for why the cache behind them is not on the object.
        let ids = id_array(scope);
        set(scope, object, "builtinIds", ids)?;
        lazy_member(scope, object, "builtinCategories", categories_getter)?;
        lazy_member(scope, object, "natives", natives_getter)?;

        let values: [(&str, v8::Local<v8::Value>); 5] = [
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
            (
                "compileFunction",
                function(scope, "compileFunction", compile_function_callback)?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }

        Ok(object)
    }
}

// Per-isolate cache behind the two lazy members.
//
// The getters build their value once and keep it here. A self-replacing
// accessor would be the obvious alternative, but redefining the property from
// inside its own getter re-enters the accessor and never settles, so the cache
// has to live outside the object.
//
// The slot is per-isolate because a `v8::Global` belongs to one isolate and
// must not be handed to another. `BindingModule::install` runs per isolate, so
// each isolate installs its own `builtins` namespace and starts with an empty
// cache.
thread_local! {
    static LAZY: std::cell::RefCell<LazyCache> = std::cell::RefCell::new(LazyCache::default());
}

#[derive(Default)]
struct LazyCache {
    categories: Option<v8::Global<v8::Value>>,
    natives: Option<v8::Global<v8::Value>>,
}

/// Defines `name` on `object` as an accessor that builds its value on first
/// read and reuses it afterwards.
fn lazy_member(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    getter: impl v8::MapFnTo<v8::AccessorNameGetterCallback>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a lazy member name")?;
    object
        .set_accessor(scope, key.into(), getter)
        .ok_or_else(|| format!("cannot define the {name} accessor"))?;
    Ok(())
}

/// Resolves one lazy member: the cached value when there is one, otherwise
/// `build`'s result, which is cached before it is returned.
fn cached<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    slot: impl Fn(&mut LazyCache) -> &mut Option<v8::Global<v8::Value>>,
    build: impl FnOnce(&mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value>,
) -> v8::Local<'s, v8::Value> {
    let existing = LAZY.with(|cache| {
        slot(&mut cache.borrow_mut())
            .as_ref()
            .map(|value| v8::Local::new(scope, value))
    });
    match existing {
        Some(value) => value,
        None => {
            let value = build(scope);
            let global = v8::Global::new(scope, value);
            LAZY.with(|cache| *slot(&mut cache.borrow_mut()) = Some(global));
            value
        }
    }
}

/// Getter for `builtinCategories`, which builds the value on first read.
///
/// Nothing in the bootstrap reads it: `realm.js` derives its public and internal
/// id lists by filtering `builtinIds`, and this split is only consulted by a
/// caller that asks for `process.binding('builtins').builtinCategories`.
/// Building it eagerly allocated two arrays over all 435 ids on every start for
/// a value most processes never look at.
fn categories_getter(
    scope: &mut v8::PinScope,
    _key: v8::Local<v8::Name>,
    _args: v8::PropertyCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let value = cached(scope, |cache| &mut cache.categories, categories);
    rv.set(value);
}

/// Getter for `natives`, the legacy `process.binding('natives')` table.
///
/// This is the expensive one: it materialises all 435 builtin sources as V8
/// strings — about 1.25 MB of text — and cost several milliseconds on every
/// start. Node builds the same object lazily too:
/// `internal/legacy/processbinding.js` reaches it only through
/// `process.binding('natives')`, so loading `lib/**` at startup never pays for
/// it.
fn natives_getter(
    scope: &mut v8::PinScope,
    _key: v8::Local<v8::Name>,
    _args: v8::PropertyCallbackArguments,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let value = cached(scope, |cache| &mut cache.natives, natives);
    rv.set(value);
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
///
/// When the build generated a code cache for this builtin, it is consumed and V8
/// skips parsing and bytecode generation. That is the single largest saving in
/// rustnode's startup: the 65 builtins an empty script loads took about 18 ms to
/// compile and take about 0.3 ms from cache.
///
/// V8 validates the blob and rejects a stale one rather than using it, so the
/// cache can only make this slower, never wrong: a rejection falls back to
/// compiling the source. `a_generated_cache_is_consumed_rather_than_rejected`
/// pins that a build's own table is accepted.
pub fn compile<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: &str,
    source: &str,
    kind: BuiltinKind,
) -> Option<v8::Local<'s, v8::Function>> {
    let compiled = rn_builtin_codegen::compile(scope, id, source, kind, code_cache_for(id))?;
    Some(compiled.function())
}

/// The generated code cache for `id`, when this build has one.
fn code_cache_for(id: &str) -> Option<&'static [u8]> {
    BUILTIN_CODE_CACHE
        .iter()
        .find(|(cached_id, _)| *cached_id == id)
        .map(|(_, bytes)| *bytes)
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

    #[test]
    fn the_cache_plan_names_real_builtins_and_no_duplicates() {
        // The plan is an input to the build script, where a typo would only
        // show up as a lost cache. Checking it here names the mistake instead.
        let mut seen = std::collections::BTreeSet::new();
        for id in cache_plan::CACHED_BUILTINS {
            assert!(
                builtin_by_id(id).is_some(),
                "the cache plan names `{id}`, which is not a builtin"
            );
            assert!(seen.insert(*id), "`{id}` is in the cache plan twice");
        }
    }

    #[test]
    fn every_planned_builtin_has_a_generated_cache() {
        // The build script reports a builtin V8 declines to serialise as a
        // warning, which is right for that case but wrong for a plan entry that
        // was never generated at all. A generated table and the plan have to
        // agree, so a stale table fails here rather than quietly costing
        // startup time.
        if BUILTIN_CODE_CACHE.is_empty() {
            // No table means no cache was generated for this build. The runtime
            // compiles everything from source, which is a legitimate (slow)
            // build, so there is nothing to compare against.
            return;
        }
        let generated: std::collections::BTreeSet<&str> =
            BUILTIN_CODE_CACHE.iter().map(|(id, _)| *id).collect();
        for id in cache_plan::CACHED_BUILTINS {
            assert!(
                generated.contains(id),
                "the cache plan lists `{id}` but no cache was generated for it"
            );
        }
        for id in &generated {
            assert!(
                cache_plan::CACHED_BUILTINS.contains(id),
                "`{id}` has a cache but is not in the cache plan"
            );
        }
    }

    #[test]
    fn a_generated_cache_is_consumed_rather_than_rejected() {
        // The point of the cache is that V8 accepts it. A table built by a
        // different V8, or with different flags or wrapper parameters, is
        // rejected at runtime and costs the old price silently — so acceptance
        // is asserted here rather than assumed from the build succeeding.
        let Some((id, bytes)) = BUILTIN_CODE_CACHE.first() else {
            return;
        };
        let builtin = builtin_by_id(id).expect("a cached builtin exists");
        rn_builtin_codegen::set_runtime_flags();
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        let compiled = rn_builtin_codegen::compile(
            scope,
            builtin.id(),
            builtin.source(),
            builtin.kind(),
            Some(bytes),
        )
        .expect("the builtin compiles");
        assert!(
            !compiled.rejected_cache(),
            "the generated cache for `{id}` was rejected by V8"
        );
        assert!(
            compiled.consumed_cache(),
            "the generated cache for `{id}` was not consumed"
        );
    }

    #[test]
    fn the_lazy_members_are_accessors_not_data_properties() {
        // `natives` and `builtinCategories` are the two members deliberately
        // moved off the install path. If one came back as a data property it
        // would be built on every start again, which is the cost this exists to
        // avoid; the contract check cannot see the difference because both
        // shapes answer the same reads.
        assert_eq!(MEMBERS.len(), 10);
        for name in ["natives", "builtinCategories"] {
            assert!(
                MEMBERS.contains(&name),
                "`{name}` must stay a member: it is lazily installed, not removed"
            );
        }
    }
}
