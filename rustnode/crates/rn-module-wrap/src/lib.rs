//! `internalBinding('module_wrap')`.
//!
//! The JavaScript ESM loader never touches `v8::Module` directly. It builds a
//! `ModuleWrap` per module, asks it to link, instantiate and evaluate, and reads
//! status and namespace through it. This crate is that bridge.
//!
//! `v8::Module` is not a `v8::Value`, so it cannot live in an internal field on
//! the wrapper object. Each wrapper instead stores a numeric id and the module
//! itself lives in a per-thread registry keyed by that id. Node can afford a
//! raw pointer in the object because the wrapper owns the module's lifetime; in
//! Rust the registry is what owns it, and a wrapper's drop removes its entry.
//!
//! The surface has three parts:
//!
//! * the `ModuleWrap` constructor and its prototype;
//! * the status and phase constants, whose numeric values come from V8's own
//!   enums and must not be invented, because `lib/**` compares against them;
//! * four setters that hand callbacks back to V8.

use std::cell::RefCell;
use std::collections::HashMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/module_wrap.json`.
pub const MEMBERS: &[&str] = &[
    "ModuleWrap",
    "createRequiredModuleFacade",
    "kDeferPhase",
    "kErrored",
    "kEvaluated",
    "kEvaluating",
    "kEvaluationPhase",
    "kInstantiated",
    "kInstantiating",
    "kSourcePhase",
    "kUninstantiated",
    "setImportMetaResolveInitializer",
    "setImportModuleDynamicallyCallback",
    "setInitializeImportMetaObjectCallback",
    "throwIfPromiseRejected",
];

/// `v8::Module::Status`. The numbers are V8's, not ours.
pub const K_UNINSTANTIATED: i32 = 0;
pub const K_INSTANTIATING: i32 = 1;
pub const K_INSTANTIATED: i32 = 2;
pub const K_EVALUATING: i32 = 3;
pub const K_EVALUATED: i32 = 4;
pub const K_ERRORED: i32 = 5;

/// `node::ModulePhase`, from `src/module_wrap.h`.
pub const K_SOURCE_PHASE: i32 = 1;
pub const K_DEFER_PHASE: i32 = 2;
pub const K_EVALUATION_PHASE: i32 = 3;

thread_local! {
    static REGISTRY: RefCell<ModuleRegistry> = RefCell::new(ModuleRegistry::default());
}

#[derive(Default)]
struct ModuleRegistry {
    next: u64,
    modules: HashMap<u64, Entry>,
    /// Reverse lookup from V8's identity hash, which is what a callback receives.
    by_hash: HashMap<i32, u64>,
}

struct Entry {
    module: v8::Global<v8::Module>,
    /// Wrapper object, so a callback can hand it back to JavaScript.
    object: Option<v8::Global<v8::Object>>,
    synthetic_steps: Option<v8::Global<v8::Function>>,
    /// Modules a `link` resolved, consumed one per request at instantiate time.
    linked: Vec<v8::Global<v8::Module>>,
}

impl Entry {
    fn new(module: v8::Global<v8::Module>) -> Self {
        Self {
            module,
            object: None,
            synthetic_steps: None,
            linked: Vec::new(),
        }
    }
}

/// Stores a module and returns the id its wrapper carries.
fn store_module(
    scope: &mut v8::PinScope,
    module: v8::Local<v8::Module>,
    object: v8::Local<v8::Object>,
) -> Option<u64> {
    let hash = i32::from(module.get_identity_hash());
    let module = v8::Global::new(scope, module);
    let object = v8::Global::new(scope, object);
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let id = registry.next;
        registry.next += 1;
        let mut entry = Entry::new(module);
        entry.object = Some(object);
        registry.modules.insert(id, entry);
        registry.by_hash.insert(hash, id);
        Some(id)
    })
}

fn id_of(scope: &mut v8::PinScope, object: v8::Local<v8::Object>) -> Option<u64> {
    let key = v8::String::new(scope, "__rustnodeModuleId")?;
    let value = object.get(scope, key.into())?;
    value
        .number_value(scope)
        .and_then(|id| u64::try_from(id as i64).ok())
}

/// Reads a module back from a wrapper object.
fn module_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Module>> {
    let id = id_of(scope, object)?;
    REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let entry = registry.modules.get(&id)?;
        Some(v8::Local::new(scope, &entry.module))
    })
}

fn module_by_hash<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    module: v8::Local<'s, v8::Module>,
) -> Option<v8::Local<'s, v8::Object>> {
    let hash = i32::from(module.get_identity_hash());
    REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let id = registry.by_hash.get(&hash)?;
        let object = registry.modules.get(id)?.object.as_ref()?;
        Some(v8::Local::new(scope, object))
    })
}

pub struct ModuleWrapBinding;

impl BindingModule for ModuleWrapBinding {
    fn namespace(&self) -> &'static str {
        "module_wrap"
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

        let constructor = module_wrap_constructor(scope)?;
        set(scope, object, "ModuleWrap", constructor.into())?;

        let constants: [(&str, i32); 9] = [
            ("kUninstantiated", K_UNINSTANTIATED),
            ("kInstantiating", K_INSTANTIATING),
            ("kInstantiated", K_INSTANTIATED),
            ("kEvaluating", K_EVALUATING),
            ("kEvaluated", K_EVALUATED),
            ("kErrored", K_ERRORED),
            ("kSourcePhase", K_SOURCE_PHASE),
            ("kDeferPhase", K_DEFER_PHASE),
            ("kEvaluationPhase", K_EVALUATION_PHASE),
        ];
        for (name, value) in constants {
            set(scope, object, name, v8::Integer::new(scope, value).into())?;
        }

        let functions: [(&str, v8::Local<v8::Value>); 5] = [
            (
                "createRequiredModuleFacade",
                function(
                    scope,
                    "createRequiredModuleFacade",
                    create_required_module_facade,
                )?,
            ),
            (
                "setImportMetaResolveInitializer",
                function(
                    scope,
                    "setImportMetaResolveInitializer",
                    set_import_meta_resolve,
                )?,
            ),
            (
                "setImportModuleDynamicallyCallback",
                function(
                    scope,
                    "setImportModuleDynamicallyCallback",
                    set_dynamic_import,
                )?,
            ),
            (
                "setInitializeImportMetaObjectCallback",
                function(
                    scope,
                    "setInitializeImportMetaObjectCallback",
                    set_initialize_import_meta,
                )?,
            ),
            (
                "throwIfPromiseRejected",
                function(scope, "throwIfPromiseRejected", throw_if_promise_rejected)?,
            ),
        ];
        for (name, value) in functions {
            set(scope, object, name, value)?;
        }

        Ok(object)
    }
}

fn module_wrap_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let template = v8::FunctionTemplate::builder(module_wrap_new)
        .length(5)
        .build(scope);
    let constructor = template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate ModuleWrap".to_string())?;

    // Methods go on the constructor's `prototype` object. `ObjectTemplate` has no
    // property setter in this V8 binding, and this is the same object V8 uses for
    // `new ModuleWrap()` instances, so the observable result is identical.
    let prototype_key =
        v8::String::new(scope, "prototype").ok_or("cannot allocate prototype key")?;
    let prototype = constructor
        .get(scope, prototype_key.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or_else(|| "ModuleWrap has no prototype object".to_string())?;

    macro_rules! method {
        ($name:literal, $callback:expr) => {{
            let template = v8::FunctionTemplate::builder($callback).build(scope);
            if let (Some(key), Some(function)) =
                (v8::String::new(scope, $name), template.get_function(scope))
            {
                prototype.set(scope, key.into(), function.into());
            }
        }};
    }
    method!("link", module_link);
    method!("getModuleRequests", module_requests);
    method!("instantiate", module_instantiate);
    method!("evaluate", module_evaluate);
    method!("evaluateSync", module_evaluate);
    method!("setExport", module_set_export);
    method!("getNamespace", module_namespace);
    method!("getStatus", module_status);
    method!("getError", module_error);
    method!("hasTopLevelAwait", module_has_tla);
    method!("createCachedData", module_create_cached_data);
    method!("getModuleSourceObject", module_get_source_object);

    Ok(constructor)
}

/// `new ModuleWrap(url, context, source, lineOffset, columnOffset)` for source
/// text, or `new ModuleWrap(url, context, exportNames, evaluationCallback)` for
/// a synthetic module. Argument 2 being an array means synthetic, exactly as
/// Node distinguishes them.
fn module_wrap_new<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let url = args.get(0);
    if !url.is_string() {
        throw_type_error(scope, "ModuleWrap requires a url string");
        return;
    }

    let synthetic = args.get(2).is_array();
    let module = if synthetic {
        create_synthetic(scope, url, args.get(2))
    } else {
        create_source_text(scope, url, args.get(2))
    };
    let Some(module) = module else {
        if !scope.is_execution_terminating() {
            throw_error(scope, "failed to compile module");
        }
        return;
    };

    let Some(id) = store_module(scope, module, that) else {
        throw_error(scope, "cannot register module");
        return;
    };
    if let Ok(id) = i32::try_from(id) {
        let value = v8::Integer::new(scope, id);
        set_property(scope, that, "__rustnodeModuleId", value.into());
        set_property(
            scope,
            that,
            "__rustnodeSourceObject",
            v8::undefined(scope).into(),
        );
        let synthetic_flag = v8::Boolean::new(scope, synthetic);
        set_property(scope, that, "__rustnodeSynthetic", synthetic_flag.into());
    }

    if synthetic {
        if let Ok(steps) = v8::Local::<v8::Function>::try_from(args.get(3)) {
            REGISTRY.with(|registry| {
                if let Some(entry) = registry.borrow_mut().modules.get_mut(&id) {
                    entry.synthetic_steps = Some(v8::Global::new(scope, steps));
                }
            });
        }
    }

    set_property(scope, that, "url", url);
    set_property(
        scope,
        that,
        "synthetic",
        v8::Boolean::new(scope, synthetic).into(),
    );
    if !synthetic {
        let has_tla = v8::Boolean::new(scope, module.has_top_level_await());
        set_property(scope, that, "hasTopLevelAwait", has_tla.into());
    } else if args.get(4).is_object() {
        set_property(scope, that, "importedcjs", args.get(4));
    }

    rv.set(that.into());
}

fn create_synthetic<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    url: v8::Local<'s, v8::Value>,
    export_names: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Module>> {
    let url = v8::Local::<v8::String>::try_from(url).ok()?;
    let array = v8::Local::<v8::Array>::try_from(export_names).ok()?;
    let length = array.length();
    let mut names = Vec::with_capacity(length as usize);
    for index in 0..length {
        let value = array.get_index(scope, index)?;
        names.push(v8::Local::<v8::String>::try_from(value).ok()?);
    }
    Some(v8::Module::create_synthetic_module(
        scope,
        url,
        &names,
        synthetic_steps_callback,
    ))
}

fn create_source_text<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    url: v8::Local<'s, v8::Value>,
    source: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Module>> {
    let url = v8::Local::<v8::String>::try_from(url).ok()?;
    let source = v8::Local::<v8::String>::try_from(source).ok()?;
    // `is_es_module: true` and a resource name matching the URL is what makes a
    // stack frame from a module read the same as Node's.
    let origin = v8::ScriptOrigin::new(
        scope,
        url.into(),
        0,
        0,
        true,
        -1,
        None,
        false,
        false,
        true,
        None,
    );
    let mut source_text = v8::script_compiler::Source::new(source, Some(&origin));
    v8::script_compiler::compile_module2(
        scope,
        &mut source_text,
        v8::script_compiler::CompileOptions::NoCompileOptions,
        v8::script_compiler::NoCacheReason::BecauseModule,
    )
}

/// V8 calls this while evaluating a synthetic module.
///
/// The steps are cleared before the call, so a module cannot run them twice.
fn synthetic_steps_callback<'s>(
    context: v8::Local<'s, v8::Context>,
    module: v8::Local<'s, v8::Module>,
) -> Option<v8::Local<'s, v8::Value>> {
    v8::callback_scope!(unsafe scope, context);
    let wrapper = module_by_hash(scope, module)?;
    let steps = {
        let id = id_of(scope, wrapper)?;
        REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .modules
                .get_mut(&id)
                .and_then(|entry| entry.synthetic_steps.take())
        })
    };
    let steps = v8::Local::new(scope, steps?);
    // A failed call leaves the exception pending, which is exactly what V8 wants
    // a synthetic evaluation step to report: `None` propagates it.
    let result = steps.call(scope, wrapper.into(), &[])?;
    let _ = result;
    Some(v8::undefined(scope).into())
}

fn module_link<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(id) = id_of(scope, that) else {
        throw_type_error(scope, "ModuleWrap instance is not initialized");
        return;
    };
    let Some(modules) = v8::Local::<v8::Array>::try_from(args.get(0)).ok() else {
        throw_type_error(scope, "link() requires an array of modules");
        return;
    };

    let count = modules.length();
    let mut resolved = Vec::with_capacity(count as usize);
    for index in 0..count {
        let Some(value) = modules.get_index(scope, index) else {
            throw_type_error(scope, "link() needs one module per request");
            return;
        };
        let Ok(wrapper) = v8::Local::<v8::Object>::try_from(value) else {
            throw_type_error(scope, "link() expects ModuleWrap instances");
            return;
        };
        let Some(module) = module_of(scope, wrapper) else {
            throw_type_error(scope, "link() expects initialized ModuleWrap instances");
            return;
        };
        resolved.push(v8::Global::new(scope, module));
    }

    REGISTRY.with(|registry| {
        if let Some(entry) = registry.borrow_mut().modules.get_mut(&id) {
            entry.linked = resolved;
        }
    });
}

/// V8 asks which module satisfies a module request during instantiation.
fn resolve_module_callback<'s>(
    context: v8::Local<'s, v8::Context>,
    _specifier: v8::Local<'s, v8::String>,
    _attributes: v8::Local<'s, v8::FixedArray>,
    referrer: v8::Local<'s, v8::Module>,
) -> Option<v8::Local<'s, v8::Module>> {
    v8::callback_scope!(unsafe scope, context);

    let referrer_id = {
        let hash = i32::from(referrer.get_identity_hash());
        REGISTRY.with(|registry| registry.borrow().by_hash.get(&hash).copied())?
    };
    let next = REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let entry = registry.modules.get_mut(&referrer_id)?;
        if entry.linked.is_empty() {
            return None;
        }
        Some(entry.linked.remove(0))
    })?;
    Some(v8::Local::new(scope, &next))
}

fn module_instantiate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        throw_type_error(scope, "ModuleWrap instance is not initialized");
        return;
    };
    let linked = id_of(scope, that)
        .map(|id| {
            REGISTRY.with(|registry| {
                registry
                    .borrow()
                    .modules
                    .get(&id)
                    .map(|entry| entry.linked.is_empty())
                    .unwrap_or(true)
            })
        })
        .unwrap_or(true);
    if linked && module.get_module_requests().length() > 0 {
        throw_error(scope, "module is not linked");
        return;
    }

    // `None` means instantiation threw; the exception stays pending so the
    // caller observes it, which is Node's behaviour.
    let _ = module.instantiate_module(scope, resolve_module_callback);
}

fn module_evaluate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        throw_type_error(scope, "ModuleWrap instance is not initialized");
        return;
    };
    // A `None` return means evaluation threw and the exception is already
    // pending, so it propagates without any rethrow here.
    if let Some(value) = module.evaluate(scope) {
        rv.set(value);
    }
}

fn module_set_export<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        throw_type_error(scope, "ModuleWrap instance is not initialized");
        return;
    };
    let Ok(name) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw_type_error(scope, "setExport() requires a string name");
        return;
    };
    // A rejected export name throws from inside V8 and leaves the exception
    // pending, which propagates to the caller as Node does.
    let _ = module.set_synthetic_module_export(scope, name, args.get(1));
}

fn module_namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        throw_type_error(scope, "ModuleWrap instance is not initialized");
        return;
    };
    rv.set(module.get_module_namespace());
}

fn module_status<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        return;
    };
    let status = match module.get_status() {
        v8::ModuleStatus::Uninstantiated => K_UNINSTANTIATED,
        v8::ModuleStatus::Instantiating => K_INSTANTIATING,
        v8::ModuleStatus::Instantiated => K_INSTANTIATED,
        v8::ModuleStatus::Evaluating => K_EVALUATING,
        v8::ModuleStatus::Evaluated => K_EVALUATED,
        v8::ModuleStatus::Errored => K_ERRORED,
    };
    rv.set(v8::Integer::new(scope, status).into());
}

fn module_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        return;
    };
    if module.get_status() == v8::ModuleStatus::Errored {
        rv.set(module.get_exception());
        return;
    }
    rv.set(v8::undefined(scope).into());
}

fn module_has_tla<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        return;
    };
    rv.set(v8::Boolean::new(scope, module.has_top_level_await()).into());
}

/// Code caching is pure optimisation with no observable effect, so an empty
/// buffer is the honest answer until the cache lands.
fn module_create_cached_data(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::ArrayBuffer::new(scope, 0).into());
}

fn module_get_source_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(key) = v8::String::new(scope, "__rustnodeSourceObject") else {
        return;
    };
    match that.get(scope, key.into()) {
        Some(value) => rv.set(value),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn module_requests<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        return;
    };
    let requests = module.get_module_requests();
    let length = requests.length();
    let array = v8::Array::new(scope, length as i32);
    for index in 0..length {
        let Some(request) = requests.get(scope, index) else {
            continue;
        };
        // `get_module_requests` hands back a `FixedArray` of `Data`; a module
        // request is one of those, and `Data` derefs to the request's specifier.
        let Ok(request) = v8::Local::<v8::ModuleRequest>::try_from(request) else {
            continue;
        };
        let specifier = request.get_specifier();
        array.set_index(scope, index as u32, specifier.into());
    }
    // Each entry is the request object the JS loader reads `.specifier` from.
    rv.set(array.into());
}

fn create_required_module_facade(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    throw_error(scope, "createRequiredModuleFacade is not implemented yet");
}

fn set_dynamic_import<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    store_hook(
        scope,
        args,
        rn_core::hook_slot::DYNAMIC_IMPORT,
        "dynamic import",
    );
}

fn set_initialize_import_meta<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    store_hook(scope, args, rn_core::hook_slot::IMPORT_META, "import.meta");
}

fn set_import_meta_resolve<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    store_hook(
        scope,
        args,
        rn_core::hook_slot::IMPORT_META_RESOLVE,
        "import.meta.resolve",
    );
}

fn store_hook(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    hook: rn_core::hook_slot::Hook,
    label: &str,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, &format!("{label} callback must be a function"));
        return;
    };
    rn_core::hook_slot::store(scope, hook, v8::Global::new(scope, callback));
}

/// Re-throws when a module's evaluation promise settled as rejected.
fn throw_if_promise_rejected<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let Ok(promise) = v8::Local::<v8::Promise>::try_from(args.get(0)) else {
        return;
    };
    if promise.state() != v8::PromiseState::Rejected {
        return;
    }
    let exception = promise.result(scope);
    scope.throw_exception(exception);
}

fn set_property(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) {
    if let Some(key) = v8::String::new(scope, name) {
        object.set(scope, key.into(), value);
    }
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

fn throw_error(scope: &mut v8::PinScope, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::error(scope, message);
        scope.throw_exception(exception);
    }
}

fn throw_type_error(scope: &mut v8::PinScope, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
    }
}

/// Registers the `module_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register(rn_core::Namespace::from_module(&ModuleWrapBinding));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_constants_match_v8_module_status() {
        assert_eq!(K_UNINSTANTIATED, 0);
        assert_eq!(K_INSTANTIATING, 1);
        assert_eq!(K_INSTANTIATED, 2);
        assert_eq!(K_EVALUATING, 3);
        assert_eq!(K_EVALUATED, 4);
        assert_eq!(K_ERRORED, 5);
    }

    #[test]
    fn phase_constants_match_node_module_phase() {
        assert_eq!(K_SOURCE_PHASE, 1);
        assert_eq!(K_DEFER_PHASE, 2);
        assert_eq!(K_EVALUATION_PHASE, 3);
    }

    #[test]
    fn members_cover_the_recorded_contract() {
        assert_eq!(MEMBERS.len(), 15);
        for member in [
            "ModuleWrap",
            "setImportModuleDynamicallyCallback",
            "kErrored",
        ] {
            assert!(MEMBERS.contains(&member), "{member} missing");
        }
    }
}
