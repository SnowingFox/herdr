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
    /// Modules a `link` resolved, one per module request, indexed by that
    /// request's position. Kept rather than consumed: V8 instantiates a module
    /// more than once when a link failure is retried, and each pass resolves
    /// every request again.
    linked: Vec<v8::Global<v8::Module>>,
    /// How many requests the current instantiation has already resolved.
    ///
    /// V8 asks for a module's requests in source order, one call per request, so
    /// a cursor reproduces Node's index contract without needing the request
    /// index — which the `ResolveModuleCallback` signature here does not carry.
    served: usize,
    /// Whether `link()` has run. A synthetic module starts linked because it
    /// has no dependencies, which is what Node's constructor does too.
    is_linked: bool,
}

impl Entry {
    fn new(module: v8::Global<v8::Module>, synthetic: bool) -> Self {
        Self {
            module,
            object: None,
            synthetic_steps: None,
            linked: Vec::new(),
            served: 0,
            is_linked: synthetic,
        }
    }
}

/// Stores a module and returns the id its wrapper carries.
fn store_module(
    scope: &mut v8::PinScope,
    module: v8::Local<v8::Module>,
    object: v8::Local<v8::Object>,
    synthetic: bool,
) -> Option<u64> {
    let hash = i32::from(module.get_identity_hash());
    let module = v8::Global::new(scope, module);
    let object = v8::Global::new(scope, object);
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let id = registry.next;
        registry.next += 1;
        let mut entry = Entry::new(module, synthetic);
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
    method!("evaluateSync", module_evaluate_sync);
    method!("setExport", module_set_export);
    method!("getNamespace", module_namespace);
    method!("getStatus", module_status);
    method!("getError", module_error);
    method!("hasTopLevelAwait", module_has_tla);
    method!("createCachedData", module_create_cached_data);
    method!("getModuleSourceObject", module_get_source_object);
    method!("setModuleSourceObject", module_set_source_object);

    // `hasAsyncGraph` is a lazy accessor on the instance, not a prototype
    // method: `module_job.js` reads it as a property (`if (this.module
    // .hasAsyncGraph)`), and `lib/internal/vm/module.js` forwards it through a
    // getter of its own. Defining it on the prototype as a plain data property
    // would freeze the answer at link time, which is wrong because V8 only
    // knows the graph is async once the module is instantiated.
    if let Some(key) = v8::String::new(scope, "hasAsyncGraph") {
        prototype.set_accessor(scope, key.into(), has_async_graph);
    }

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

    let Some(id) = store_module(scope, module, that, synthetic) else {
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

    // The count is checked here rather than at instantiate time because a
    // mismatch means the JS loader and V8 disagree about the module's import
    // list, and every later resolve would pick a module by the wrong index.
    let request_count = module_of(scope, that)
        .map(|module| module.get_module_requests().length())
        .unwrap_or(0);
    if request_count != resolved.len() {
        throw_error(
            scope,
            "Module request count mismatch: V8 has a different number of module requests than the linked modules",
        );
        return;
    }
    REGISTRY.with(|registry| {
        if let Some(entry) = registry.borrow_mut().modules.get_mut(&id) {
            entry.linked = resolved;
            entry.is_linked = true;
        }
    });
}

/// V8 asks which module satisfies each module request during instantiation.
///
/// Node's `ResolveModule` indexes `linked_module_wraps_` by the request's
/// position, through `InstantiateModule`'s index-based callback. The v8 crate
/// exposes only the specifier/attributes variant, so this reproduces the index
/// by a cursor: V8 resolves a module's requests in source order, one call per
/// request, which is the same order `link()` stored them in.
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
        let module = entry.linked.get(entry.served)?;
        entry.served += 1;
        Some(module.clone())
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
    // Each instantiation pass resolves the whole request list again, so the
    // cursor starts from the beginning rather than continuing where a previous
    // failed attempt stopped.
    let ready = id_of(scope, that)
        .map(|id| {
            REGISTRY.with(|registry| {
                let mut registry = registry.borrow_mut();
                let Some(entry) = registry.modules.get_mut(&id) else {
                    return false;
                };
                entry.served = 0;
                // Node's `Instantiate` tests `linked_`, not the length of the
                // request list: a module with zero imports is linked as soon as
                // `link([])` runs, and one that was never linked is an error
                // even when it has nothing to resolve.
                entry.is_linked
            })
        })
        .unwrap_or(false);
    if !ready {
        throw_error(scope, "module is not linked");
        return;
    }

    // `None` means instantiation threw; the exception stays pending so the
    // caller observes it, which is Node's behaviour.
    let _ = module.instantiate_module(scope, resolve_module_callback);
}

/// `evaluate(timeout, breakOnSigint)`: the asynchronous evaluation entry point.
///
/// Returns V8's evaluation promise, which settles once the module graph — and
/// any top-level `await` in it — finishes. `module_job.js` awaits it for an
/// async graph and ignores it otherwise.
///
/// A `None` return means evaluation threw and the exception is already pending,
/// so it propagates without any rethrow here.
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
    if let Some(value) = module.evaluate(scope) {
        rv.set(value);
    }
}

/// `evaluateSync()`: evaluate a graph that is known to have no top-level await.
///
/// Node's `EvaluateSync` checks the promise V8 returns settled *synchronously*
/// and answers with the module namespace, which is what `runSync()` and the
/// synthetic facades expect. Returning the promise instead — as one shared
/// implementation used to — makes `job.runSync()` hand a pending promise to
/// `populateCJSExportsFromESM` and every `require(esm)` sees an empty object.
///
/// A graph with top-level await never gets here: `module_job.js` rejects it with
/// `ERR_REQUIRE_ASYNC_MODULE` before evaluating.
fn module_evaluate_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let that = args.this();
    let Some(module) = module_of(scope, that) else {
        throw_type_error(scope, "ModuleWrap instance is not initialized");
        return;
    };
    let Some(value) = module.evaluate(scope) else {
        // The exception is pending; leave it that way.
        return;
    };
    let Ok(promise) = v8::Local::<v8::Promise>::try_from(value) else {
        throw_error(scope, "module evaluation did not return a promise");
        return;
    };
    if promise.state() == v8::PromiseState::Rejected {
        let exception = promise.result(scope);
        scope.throw_exception(exception);
        return;
    }
    rv.set(module.get_module_namespace());
}

/// `module.hasAsyncGraph`: whether this module or anything it imports has a
/// top-level await.
///
/// V8 only knows the answer once the graph is instantiated, so reading it
/// earlier is a usage error rather than `false`. Node throws
/// `ERR_MODULE_NOT_INSTANTIATED` there; this throws the same message so the
/// failure names the real problem instead of reporting a wrong `false`.
fn has_async_graph<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _key: v8::Local<'s, v8::Name>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let holder = args.holder();
    let Some(module) = module_of(scope, holder) else {
        return;
    };
    if !matches!(
        module.get_status(),
        v8::ModuleStatus::Instantiated
            | v8::ModuleStatus::Evaluating
            | v8::ModuleStatus::Evaluated
            | v8::ModuleStatus::Errored
    ) {
        throw_error(
            scope,
            "module has not been instantiated yet, hasAsyncGraph can only be accessed after instantiation",
        );
        return;
    }
    rv.set(v8::Boolean::new(scope, module.is_graph_async()).into());
}

/// `module.setModuleSourceObject(object)`: attach the compiled source of a
/// module imported for its source phase.
///
/// Only WebAssembly and other embedder formats set this; `import ... source`
/// over a normal module throws `ERR_SOURCE_PHASE_NOT_DEFINED` in
/// `getModuleSourceObject`, which is the behaviour a module without one here
/// should have.
fn module_set_source_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let that = args.this();
    let value = args.get(0);
    if !value.is_object() {
        throw_type_error(scope, "setModuleSourceObject() requires an object");
        return;
    }
    set_property(scope, that, "__rustnodeSourceObject", value);
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

/// `getModuleRequests()`: one frozen request record per import of this module.
///
/// Node's loader reads `request.specifier`, `request.attributes` and
/// `request.phase` (`internal/modules/esm/module_job.js` passes the record
/// straight to `getOrCreateModuleJob`, which forwards `request.attributes` and
/// `request.phase` into resolution). Returning the bare specifier strings — as
/// this used to — makes every one of those `undefined`, and the first symptom is
/// `Cannot find package 'undefined'`, several frames away from the cause.
///
/// This mirrors `createModuleRequestsContainer` and
/// `createImportAttributesContainer` in `src/module_wrap.cc`: null-prototype
/// objects frozen at every level, with the phase translated to Node's
/// `ModulePhase` constant rather than V8's.
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
        if let Some(record) = request_record(scope, &request) {
            array.set_index(scope, index as u32, record.into());
        }
    }
    rv.set(array.into());
}

/// Builds one frozen `{ specifier, attributes, phase }` record.
fn request_record<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: &v8::ModuleRequest,
) -> Option<v8::Local<'s, v8::Object>> {
    let record = v8::Object::new(scope);
    // `Object::new` gives a normal prototype; Node builds these on a null
    // prototype so a polluted `Object.prototype` cannot shadow a field the
    // loader reads.
    if let Some(null) = null_prototype(scope) {
        record.set_prototype(scope, null);
    }

    let specifier = request.get_specifier();
    set_name(scope, record, "specifier", specifier.into())?;
    let attributes = import_attributes(scope, &request.get_import_attributes())?;
    set_name(scope, record, "attributes", attributes)?;
    let phase = v8::Integer::new(scope, phase_constant(request.get_phase()));
    set_name(scope, record, "phase", phase.into())?;

    record.set_integrity_level(scope, v8::IntegrityLevel::Frozen);
    Some(record)
}

/// Builds the frozen attributes object from V8's flat `[key, value, ...]` pair
/// list.
///
/// `ModuleRequest::GetImportAttributes` returns keys and values alternating with
/// a source offset after each pair, which is why the stride here is three and
/// not two. The offsets are diagnostics for a syntax error that never gets this
/// far, so they are skipped rather than published.
fn import_attributes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    raw: &v8::FixedArray,
) -> Option<v8::Local<'s, v8::Value>> {
    let attributes = v8::Object::new(scope);
    if let Some(null) = null_prototype(scope) {
        attributes.set_prototype(scope, null);
    }
    let mut index = 0;
    while index + 1 < raw.length() {
        let (Some(key), Some(value)) = (raw.get(scope, index), raw.get(scope, index + 1)) else {
            break;
        };
        let (Ok(key), Ok(value)) = (
            v8::Local::<v8::String>::try_from(key),
            v8::Local::<v8::String>::try_from(value),
        ) else {
            break;
        };
        attributes.set(scope, key.into(), value.into());
        index += 3;
    }
    attributes.set_integrity_level(scope, v8::IntegrityLevel::Frozen);
    Some(attributes.into())
}

/// V8's `ModuleImportPhase` as Node's `ModulePhase`.
///
/// The two enumerations have the same members but not the same numbers:
/// V8 starts `kSource` at 0 while `src/module_wrap.h` starts `kSourcePhase` at
/// 1, and the JS side compares against Node's values when it decides whether to
/// link and evaluate a request.
fn phase_constant(phase: v8::ModuleImportPhase) -> i32 {
    match phase {
        v8::ModuleImportPhase::kSource => K_SOURCE_PHASE,
        v8::ModuleImportPhase::kDefer => K_DEFER_PHASE,
        v8::ModuleImportPhase::kEvaluation => K_EVALUATION_PHASE,
    }
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
    // Only the callback is recorded here. V8's dynamically-import handler is
    // isolate-wide and can only be installed through `&mut Isolate`, which a
    // function callback does not have (the v8 crate's
    // `FunctionCallbackArguments::get_isolate` is documented as unsound while a
    // `CallbackScope` is open, and one always is inside a binding call).
    // [`install_isolate_callbacks`] does that once, from the CLI, and reads this
    // slot on every call so a replacement callback takes effect immediately.
    store_hook(
        scope,
        args,
        rn_core::hook_slot::DYNAMIC_IMPORT,
        "dynamic import",
    );
    // The referrer argument has to be the very symbol `internalBinding
    // ('symbols')` publishes: the JS callback compares it by identity and throws
    // when nothing matches.
    if let Ok(referrer) = rn_bind_symbols::ensure(
        scope,
        "vm_dynamic_import_default_internal",
        "vm_dynamic_import_default_internal",
    ) {
        rn_core::hook_slot::set_dynamic_import_referrer(scope, referrer.into());
    }
}

/// The isolate-level handler for `import()`.
///
/// Node's `ImportModuleDynamically` resolves the referrer's host-defined option
/// to a symbol and calls the JS loader with
/// `(id, specifier, phase, attributes, referrerName)`, wrapping the result in a
/// promise created in the referrer's context. This does the same, reading the
/// JS callback from the hook slot rather than from a per-realm field, because a
/// `fn` callback cannot capture one.
fn host_dynamic_import<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    _host_defined_options: v8::Local<'s, v8::Data>,
    resource_name: v8::Local<'s, v8::Value>,
    specifier: v8::Local<'s, v8::String>,
    import_attributes: v8::Local<'s, v8::FixedArray>,
) -> Option<v8::Local<'s, v8::Promise>> {
    let Some(callback) = rn_core::hook_slot::dynamic_import(scope) else {
        // `initializeESM()` has not run, so nothing can resolve this import.
        // A thrown error names the real problem; returning `None` would surface
        // as V8's generic "callback missing" instead.
        throw_error(
            scope,
            "a dynamic import callback was not specified (internal/modules/esm/utils was never initialized)",
        );
        return None;
    };
    let attributes = import_attributes_from_flat(scope, &import_attributes)?;
    // `vm_dynamic_import_default_internal` is the sentinel that makes the JS
    // callback route an ordinary `import()` from a plain script to the default
    // loader without emitting the `vm.USE_MAIN_CONTEXT_DEFAULT_LOADER`
    // warning. It is the same value `prepareExecution` puts on the global for
    // script contexts.
    let referrer = rn_core::hook_slot::dynamic_import_referrer(scope)
        .unwrap_or_else(|| v8::undefined(scope).into());
    let phase = v8::Integer::new(scope, K_EVALUATION_PHASE);
    let arguments = [
        referrer,
        specifier.into(),
        phase.into(),
        attributes.into(),
        resource_name,
    ];
    let result = callback.call(scope, v8::undefined(scope).into(), &arguments)?;

    // The JS callback returns whatever the loader produced, which may be a
    // promise or a plain namespace object (the embedder path returns the
    // latter). Resolving a fresh promise with it gives V8 the single promise
    // shape it expects in both cases.
    let resolver = v8::PromiseResolver::new(scope)?;
    resolver.resolve(scope, result)?;
    Some(resolver.get_promise(scope))
}

/// Builds `{ key: value }` from V8's flat `[key, value, ...]` attribute list.
///
/// Unlike a module request's attributes this array has stride two: the
/// dynamically-import callback is documented to leave the source offsets out.
fn import_attributes_from_flat<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    raw: &v8::FixedArray,
) -> Option<v8::Local<'s, v8::Object>> {
    let attributes = v8::Object::new(scope);
    if let Some(null) = null_prototype(scope) {
        attributes.set_prototype(scope, null);
    }
    let mut index = 0;
    while index + 1 < raw.length() {
        let (Some(key), Some(value)) = (raw.get(scope, index), raw.get(scope, index + 1)) else {
            break;
        };
        if let (Ok(key), Ok(value)) = (
            v8::Local::<v8::String>::try_from(key),
            v8::Local::<v8::String>::try_from(value),
        ) {
            attributes.set(scope, key.into(), value.into());
        }
        index += 2;
    }
    Some(attributes)
}

fn set_initialize_import_meta<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    // Recorded only; [`install_isolate_callbacks`] installs the isolate-wide
    // handler from the CLI, where a `&mut Isolate` is available.
    store_hook(scope, args, rn_core::hook_slot::IMPORT_META, "import.meta");
}

/// Installs the two isolate-wide ESM handlers V8 needs.
///
/// `import.meta` and `import()` are not dispatched through
/// `internalBinding()` at call time: V8 owns one handler per isolate, and the
/// only API that sets it takes `&mut Isolate`. A binding callback cannot reach
/// one (its `get_isolate` is documented unsound while the callback scope is
/// open), so the CLI calls this once after the realm bootstrap, before any user
/// code runs.
///
/// Both handlers read their JavaScript callback from
/// [`rn_core::hook_slot`] on each call rather than capturing it, because a bare
/// `fn` has no data slot; that also means `initializeESM()` replacing the
/// callback later is picked up without re-installing anything here.
pub fn install_isolate_callbacks(isolate: &mut v8::Isolate) {
    isolate.set_host_initialize_import_meta_object_callback(host_initialize_import_meta);
    isolate.set_host_import_module_dynamically_callback(host_dynamic_import);
}

/// The isolate-level handler for `import.meta`.
///
/// Node keeps `isMain` and the custom-callback registry on the `ModuleWrap`, and
/// its `HostInitializeImportMetaObjectCallback` either runs
/// `DefaultImportMetaObjectInitializer` for a loader-compiled module or calls
/// into JS with `(hostDefinedOptions, meta, wrap)`.
///
/// This crate has no realm object to hang the "which callback applies" decision
/// on, so the split is explicit: a module whose wrapper carries
/// `__rustnodeCustomImportMeta` was registered by `vm.SourceTextModule` and gets
/// the JS callback; everything else is a loader module and gets the default
/// initializer, which is the entire documented surface —
/// `dirname`, `filename`, `main`, `resolve`, `url`, in that order.
///
/// `extern "C"` because V8 takes a bare function pointer here, with no argument
/// adaptation.
unsafe extern "C" fn host_initialize_import_meta<'s>(
    context: v8::Local<'s, v8::Context>,
    module: v8::Local<'s, v8::Module>,
    meta: v8::Local<'s, v8::Object>,
) {
    v8::callback_scope!(unsafe scope, context);
    let Some(wrapper) = module_by_hash(scope, module) else {
        return;
    };
    if get_property(scope, wrapper, "__rustnodeCustomImportMeta")
        .map(|value| value.is_true())
        .unwrap_or(false)
    {
        // A `vm.SourceTextModule`: let the JS registry decide, exactly as Node
        // does, because the user-supplied `initializeImportMeta` lives there.
        if let Some(callback) = rn_core::hook_slot::import_meta(scope) {
            if let Some(id) = get_property(scope, wrapper, "__rustnodeHostDefinedOption") {
                let _ = callback.call(
                    scope,
                    v8::undefined(scope).into(),
                    &[id, meta.into(), wrapper.into()],
                );
            }
        }
        return;
    }
    initialize_import_meta_default(scope, wrapper, meta);
}

/// `DefaultImportMetaObjectInitializer` from `src/module_wrap.cc`.
///
/// The order matters: the test that watches this surface asserts
/// `Reflect.ownKeys(import.meta)` is exactly
/// `['dirname', 'filename', 'main', 'resolve', 'url']`, which is alphabetical,
/// and `dirname`/`filename` only exist for `file:` URLs — a `data:` module has
/// `['main', 'resolve', 'url']`.
///
/// `resolve` is a lazy accessor because its initializer is only installed on
/// the main thread once the cascaded loader exists; reading the property is
/// what creates the function, and it is created fresh per module so the module
/// URL it closes over is right.
fn initialize_import_meta_default<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    wrapper: v8::Local<'s, v8::Object>,
    meta: v8::Local<'s, v8::Object>,
) {
    let Some(url) = get_property(scope, wrapper, "url") else {
        return;
    };
    let Some(url_text) = url
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
    else {
        return;
    };

    if let Some(path) = file_url_to_path(&url_text) {
        if let Some(dirname) = path_dirname(&path) {
            if let Some(key) = v8::String::new(scope, "dirname") {
                if let Some(value) = v8::String::new(scope, &dirname) {
                    let _ = meta.create_data_property(scope, key.into(), value.into());
                }
            }
        }
        if let Some(key) = v8::String::new(scope, "filename") {
            if let Some(value) = v8::String::new(scope, &path) {
                let _ = meta.create_data_property(scope, key.into(), value.into());
            }
        }
    }

    let is_main = get_property(scope, wrapper, "isMain")
        .map(|value| value.is_true())
        .unwrap_or(false);
    if let Some(key) = v8::String::new(scope, "main") {
        let _ =
            meta.create_data_property(scope, key.into(), v8::Boolean::new(scope, is_main).into());
    }

    if rn_core::hook_slot::has_import_meta_resolve() {
        if let Some(key) = v8::String::new(scope, "resolve") {
            let attributes = v8::PropertyAttribute::NONE;
            let _ = meta.set_lazy_data_property_with_data(
                scope,
                key.into(),
                import_meta_resolve,
                url,
                attributes,
                v8::SideEffectType::HasSideEffect,
                v8::SideEffectType::HasSideEffect,
            );
        }
    }

    if let Some(key) = v8::String::new(scope, "url") {
        let _ = meta.create_data_property(scope, key.into(), url);
    }
}

/// The lazy getter behind `import.meta.resolve`.
///
/// Node binds the cascaded loader into `createImportMetaResolve` at
/// initialization and hands the module URL through the accessor's data slot, so
/// this does the same: one `resolve` function per module URL.
fn import_meta_resolve<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _key: v8::Local<'s, v8::Name>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Value>,
) {
    let Some(initializer) = rn_core::hook_slot::import_meta_resolve(scope) else {
        return;
    };
    let url = args.data();
    if let Some(value) = initializer.call(scope, v8::undefined(scope).into(), &[url]) {
        rv.set(value);
    }
}

/// `setImportMetaResolveInitializer` records the initializer that
/// `import.meta.resolve` is built from.
///
/// Node keeps it on the realm and only reads it from
/// `ImportMetaResolveLazyGetter`, so the lazy getter in
/// [`initialize_import_meta_default`] is the only consumer. No isolate-level
/// registration is involved, which is why this one can stay a plain store.
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

/// `set_property` as a `Result`, for call sites that must report an allocation
/// failure rather than silently leaving the property out.
fn set_property_checked(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Option<()> {
    let key = v8::String::new(scope, name)?;
    object.set(scope, key.into(), value)?;
    Some(())
}

fn set_name(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Option<()> {
    set_property_checked(scope, object, name, value)
}

fn get_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// The value `Object.setPrototypeOf` needs to build a null-prototype object.
///
/// Node creates its request records and import-attribute objects with
/// `Object::New(isolate, Null(isolate), ...)`, which is the same thing as
/// creating a plain object and setting its prototype to `null`: a polluted
/// `Object.prototype` then cannot shadow a field the loader reads.
fn null_prototype<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
    Some(v8::null(scope).into())
}

/// `fileURLToPath` for the subset an `import.meta` URL can contain.
///
/// Returns `None` for anything that is not a `file:` URL, which is what makes a
/// `data:` module's `import.meta` lack `dirname`/`filename`.
///
/// Node's version percent-decodes the path and rejects an encoded `/` or `\`
/// (`ERR_INVALID_FILE_URL_PATH`). The decode has to happen before the check for
/// that to be sound, and `%2F` is the case that matters: leaving it encoded
/// would produce a path that looks inside a directory it is not.
fn file_url_to_path(url: &str) -> Option<String> {
    let rest = url.strip_prefix("file://")?;
    // `file:///tmp/x` has an empty authority; `file://host/x` is a form Node
    // rejects on POSIX, and neither shape occurs for a module the loader found
    // by walking the filesystem.
    let path = rest.strip_prefix('/').map(|tail| format!("/{tail}"))?;
    let path = path.split(['?', '#']).next().unwrap_or(&path);
    let decoded = percent_decode(path)?;
    if decoded.contains('/') && path.contains("%2F") {
        return None;
    }
    Some(decoded)
}

/// Decodes `%XX` escapes as UTF-8, returning `None` on a malformed sequence.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The directory part of a decoded file path, without a trailing separator.
///
/// `import.meta.dirname` is `/tmp` for `/tmp/x.mjs` and `/` for `/x.mjs`; Node
/// slices at the last separator and keeps everything before it.
fn path_dirname(path: &str) -> Option<String> {
    let index = path.rfind('/')?;
    Some(if index == 0 {
        "/".to_string()
    } else {
        path[..index].to_string()
    })
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
    registry.register_module(ModuleWrapBinding);
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
    fn v8_phases_translate_to_node_numbers_not_v8_numbers() {
        // The two enumerations have the same members and different numbers: V8
        // starts `kSource` at 0, Node's `ModulePhase` starts `kSourcePhase` at 1.
        // Handing V8's numbers to the JS loader would make every request look
        // like a source-phase import, so the mapping is pinned rather than
        // assumed.
        assert_eq!(
            phase_constant(v8::ModuleImportPhase::kSource),
            K_SOURCE_PHASE
        );
        assert_eq!(
            phase_constant(v8::ModuleImportPhase::kDefer),
            K_DEFER_PHASE
        );
        assert_eq!(
            phase_constant(v8::ModuleImportPhase::kEvaluation),
            K_EVALUATION_PHASE
        );
        assert_ne!(K_SOURCE_PHASE, 0, "V8's kSource is 0; Node's is 1");
    }

    #[test]
    fn file_urls_convert_to_paths() {
        assert_eq!(
            file_url_to_path("file:///tmp/a/b.mjs").as_deref(),
            Some("/tmp/a/b.mjs")
        );
        // Percent escapes are decoded, which is what makes a spaced path the
        // file it names rather than a path containing `%20`.
        assert_eq!(
            file_url_to_path("file:///tmp/x%20y/z.mjs").as_deref(),
            Some("/tmp/x y/z.mjs")
        );
        assert_eq!(
            file_url_to_path("file:///tmp/a%25b.mjs").as_deref(),
            Some("/tmp/a%b.mjs")
        );
        // A `data:` module has no `dirname`/`filename`, which is what the
        // `import.meta` test asserts.
        assert_eq!(file_url_to_path("data:text/javascript,1"), None);
        assert_eq!(file_url_to_path("node:path"), None);
    }

    #[test]
    fn dirname_is_the_path_before_the_last_separator() {
        assert_eq!(path_dirname("/tmp/a/b.mjs").as_deref(), Some("/tmp/a"));
        assert_eq!(path_dirname("/b.mjs").as_deref(), Some("/"));
    }

    #[test]
    fn percent_decoding_rejects_a_truncated_escape() {
        assert_eq!(percent_decode("a%2"), None);
        assert_eq!(percent_decode("a%zz"), None);
        assert_eq!(percent_decode("a%2Fb").as_deref(), Some("a/b"));
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
