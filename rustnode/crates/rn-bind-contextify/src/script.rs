//! `ContextifyScript` and `makeContext`.
//!
//! These two are the `vm` module's native half:
//!
//! * `makeContext(sandbox, name, origin, allowStrings, allowWasm,
//!   ownMicrotaskQueue, hostDefinedOptionId)` contextifies a plain object.
//!   `lib/vm.js` hands the same object back to the user, so every property access
//!   inside the new realm has to reach through to it. That indirection is what
//!   makes `vm.createContext` observable at all.
//! * `ContextifyScript` is `vm.Script`: source compiled but not run, runnable
//!   later in this context or in a sandbox's.
//!
//! ## Two representations of "this object is a context"
//!
//! Node stores a `ContextifyContext` C++ object in a V8 *private* property on the
//! sandbox under `contextify_context_private_symbol`, then reads the `v8::Context`
//! back out of it. Rust has nowhere to hang a C++ object off a JS object, so this
//! crate keeps a thread-local registry and stores a numeric id in the same private
//! slot. The JavaScript layer only ever asks whether the value is `undefined`
//! (`isContext` in `lib/internal/vm.js`), so the observable shape is unchanged,
//! and the sandbox/context link stays in Rust where it can be tested.
//!
//! ## Why the sandbox needs interceptors
//!
//! Without them, `vm.runInContext('x', ctx)` would read the *new realm's* global
//! object, which starts empty, and the user's `sandbox.x` would be invisible. Node
//! installs named and indexed property handlers on the context's global object
//! template that forward every get, set, query, delete and enumerate to the
//! sandbox. [`install_sandbox_handlers`] does the same.

use std::cell::RefCell;
use std::collections::HashMap;

use rn_v8_sys::v8;

use crate::compile;

/// Members of the `ContextifyScript` prototype.
///
/// `createCachedData` and `runInContext` are the only two. `lib/internal/vm.js`
/// destructures `runInContext` off the prototype at module scope and calls it
/// through `FunctionPrototypeCall`, so it must be an own property there.
pub const SCRIPT_METHODS: &[&str] = &["createCachedData", "runInContext"];

/// The internal field holding a script wrapper's id in [`SCRIPTS`].
///
/// One field is enough: the only thing a script carries is the compiled form. The
/// source URL and source map URL are copied onto the object as ordinary
/// properties when it is constructed, as Node does.
///
/// The field holds a *number*, not the script itself, because `UnboundScript` is
/// not a `v8::Value` and so cannot live in an internal field. [`SCRIPTS`] owns the
/// scripts, keyed by that number, the same way `rn-module-wrap` owns modules.
const SCRIPT_FIELD: usize = 0;

thread_local! {
    /// Contexts created by `makeContext`, keyed by the id stored in the
    /// sandbox's private property.
    ///
    /// Thread-local because a `v8::Global<v8::Context>` belongs to one isolate,
    /// and rustnode keeps one isolate per thread.
    static CONTEXTS: RefCell<HashMap<u64, ContextifyContext>> = RefCell::new(HashMap::new());

    /// Compiled scripts, keyed by the id each wrapper carries in its internal
    /// field.
    static SCRIPTS: RefCell<HashMap<u64, v8::Global<v8::UnboundScript>>> =
        RefCell::new(HashMap::new());

    /// Next script id.
    static NEXT_SCRIPT_ID: RefCell<u64> = const { RefCell::new(1) };
}

/// Stores a compiled script and returns the id the wrapper carries.
fn store_script(scope: &mut v8::PinScope, script: v8::Local<v8::UnboundScript>) -> u64 {
    let id = NEXT_SCRIPT_ID.with(|next| {
        let mut next = next.borrow_mut();
        let id = *next;
        *next += 1;
        id
    });
    SCRIPTS.with(|scripts| {
        scripts
            .borrow_mut()
            .insert(id, v8::Global::new(scope, script));
    });
    id
}

/// One contextified sandbox.
pub struct ContextifyContext {
    /// The new realm.
    pub context: v8::Global<v8::Context>,
    /// The object passed to `vm.createContext`, where global reads and writes
    /// inside the realm are forwarded.
    pub sandbox: Option<v8::Global<v8::Object>>,
    /// Name reported in stack traces, from `options.name`.
    pub name: String,
    /// `options.origin`, or `""`.
    pub origin: String,
    /// Whether `eval` and `new Function` may compile strings in this realm.
    pub allow_code_gen_strings: bool,
    /// Whether WebAssembly may be compiled in this realm.
    pub allow_code_gen_wasm: bool,
    /// The explicit microtask queue when `microtaskMode: 'afterEvaluate'` asked
    /// for one, kept alive for the context's lifetime.
    pub microtask_queue: Option<v8::MicrotaskQueueHandle>,
}

impl std::fmt::Debug for ContextifyContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContextifyContext")
            .field("name", &self.name)
            .field("origin", &self.origin)
            .field("allow_code_gen_strings", &self.allow_code_gen_strings)
            .field("allow_code_gen_wasm", &self.allow_code_gen_wasm)
            .field("has_sandbox", &self.sandbox.is_some())
            .field("has_microtask_queue", &self.microtask_queue.is_some())
            .finish()
    }
}

/// Stores a context under `key`, which is its global object's identity hash.
///
/// The key has to be derivable from inside a property handler without a property
/// read, and the global object's identity hash is the only such handle V8 exposes
/// here. It is also exactly the object the interceptors are installed on, so the
/// mapping cannot drift.
fn store(key: u64, context: ContextifyContext) {
    CONTEXTS.with(|contexts| contexts.borrow_mut().insert(key, context));
}

/// The per-isolate mark that makes an object a `vm` context.
///
/// It resolves through `rn_core` rather than being created here, because
/// `lib/internal/vm.js`'s `isContext` reads the same symbol back out of
/// `internalBinding('util').privateSymbols`: two separately created symbols are
/// distinct identities and the lookup would never match.
fn context_symbol<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Symbol> {
    rn_core::symbol(scope, rn_core::CONTEXTIFY_CONTEXT)
}

/// The id stored on a contextified object, if it has one.
fn context_id_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<u64> {
    let symbol = context_symbol(scope);
    let value = object.get(scope, symbol.into())?;
    if value.is_undefined() {
        return None;
    }
    let id = value.number_value(scope)?;
    u64::try_from(id as i64).ok()
}

/// Resolves a sandbox to its realm, for `compileFunction`'s parsing context and
/// for `runInContext`.
pub fn context_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Context>> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let id = context_id_of(scope, object)?;
    CONTEXTS.with(|contexts| {
        contexts
            .borrow()
            .get(&id)
            .map(|entry| v8::Local::new(scope, &entry.context))
    })
}

/// `makeContext(sandbox, name, origin, allowStrings, allowWasm,
/// ownMicrotaskQueue, hostDefinedOptionId)`.
///
/// Returns the sandbox, except in the "vanilla" form where argument 1 is a symbol:
/// then there is no sandbox and the new realm's global object is returned, which is
/// what `vm.createContext(vm.constants.DONT_CONTEXTIFY)` produces.
pub fn make_context<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let first = args.get(0);
    let name = args.get(1).to_rust_string_lossy(scope);
    let origin = if args.get(2).is_string() {
        args.get(2).to_rust_string_lossy(scope)
    } else {
        String::new()
    };
    let allow_code_gen_strings = args.get(3).is_true();
    let allow_code_gen_wasm = args.get(4).is_true();
    let own_microtask_queue = args.get(5).is_true();

    let sandbox = if first.is_object() {
        match v8::Local::<v8::Object>::try_from(first) {
            Ok(object) => {
                // Contextifying the same sandbox twice would leave two realms
                // claiming one object, so Node asserts rather than choosing.
                if context_id_of(scope, object).is_some() {
                    return throw_error(scope, "Cannot contextify a sandbox object multiple times");
                }
                Some(object)
            }
            Err(_) => None,
        }
    } else if first.is_symbol() {
        // `vm.constants.DONT_CONTEXTIFY`: a plain realm with no sandbox.
        None
    } else {
        return throw_type_error(
            scope,
            "makeContext expects an object or vm.constants.DONT_CONTEXTIFY",
        );
    };

    // An explicit microtask queue is what `microtaskMode: 'afterEvaluate'` asks
    // for: microtasks run only when `vm` says so, not at the end of every turn.
    let microtask_queue = if own_microtask_queue {
        Some(v8::MicrotaskQueue::new(
            scope,
            v8::MicrotasksPolicy::Explicit,
        ))
    } else {
        None
    };

    let global_template = v8::ObjectTemplate::new(scope);
    install_sandbox_handlers(global_template);

    let mut options = v8::ContextOptions {
        global_template: Some(global_template),
        ..v8::ContextOptions::default()
    };
    if let Some(queue) = microtask_queue.as_ref() {
        let queue: &v8::MicrotaskQueue = queue;
        options.microtask_queue =
            Some(queue as *const v8::MicrotaskQueue as *mut v8::MicrotaskQueue);
    }
    let context = v8::Context::new(scope, options);

    // The security token ties the new realm to the main one, so objects can cross
    // between them without the cross-origin checks a foreign token imposes. Node
    // does this for every `vm` context.
    let main_token = scope.get_current_context().get_security_token(scope);
    context.set_security_token(main_token);

    // Generation is denied here and recorded on the context for the runtime to
    // check. The flag the JavaScript layer exposes is per-realm allow/deny, and
    // `allow_code_gen_strings`/`allow_code_gen_wasm` carry it.
    context.set_allow_generation_from_strings(false);

    // `hostDefinedOptionId` is stored on the realm's global so the dynamic-import
    // callback can find the right registration without the wrapper object. The
    // private name comes from `src/env_properties.h` for the same reason the
    // context mark does.
    {
        let symbol = host_defined_option_symbol(scope);
        let id = args.get(6);
        let global = context.global(scope);
        rn_core::define_mark(scope, global, symbol, id);
    }

    let key = i32::from(context.global(scope).get_identity_hash()) as u64;
    store(
        key,
        ContextifyContext {
            context: v8::Global::new(scope, context),
            sandbox: sandbox.map(|object| v8::Global::new(scope, object)),
            name,
            origin,
            allow_code_gen_strings,
            allow_code_gen_wasm,
            microtask_queue,
        },
    );
    let id = key;

    let marked = match sandbox {
        Some(sandbox) => sandbox,
        None => context.global(scope),
    };
    let id_value: v8::Local<v8::Value> = v8::Number::new(scope, id as f64).into();

    // Both the sandbox and the realm's global object carry the symbol mark. The
    // sandbox needs it so `vm.isContext(sandbox)` answers; the global needs it for
    // the vanilla form, where the global is what `makeContext` returns.
    let symbol = context_symbol(scope);
    rn_core::define_mark(scope, marked, symbol, id_value);
    let global = context.global(scope);
    if !global.strict_equals(marked.into()) {
        rn_core::define_mark(scope, global, symbol, id_value);
    }
    // `vm.isContext(sandbox)` asks the returned object; the mark is what answers.
    rv.set(marked.into());
}

/// The per-isolate `host_defined_option_symbol`, by Node's private name.
fn host_defined_option_symbol<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Symbol> {
    rn_core::symbol(scope, rn_core::HOST_DEFINED_OPTION)
}

/// Installs the handlers that make the sandbox the realm's property store.
///
/// `Intercepted::kYes` means V8 stops at the interceptor instead of consulting the
/// real global object, which is what makes the sandbox authoritative.
fn install_sandbox_handlers(template: v8::Local<v8::ObjectTemplate>) {
    let config = v8::NamedPropertyHandlerConfiguration::new()
        .getter(sandbox_get)
        .setter(sandbox_set)
        .query(sandbox_query)
        .deleter(sandbox_delete)
        .enumerator(sandbox_enumerate);
    template.set_named_property_handler(config);

    let indexed = v8::IndexedPropertyHandlerConfiguration::new()
        .getter(sandbox_get_index)
        .setter(sandbox_set_index)
        .query(sandbox_query_index)
        .deleter(sandbox_delete_index)
        .enumerator(sandbox_enumerate_index);
    template.set_indexed_property_handler(indexed);
}

/// The sandbox a handler should forward to.
///
/// The interceptor is installed on the global object *template*, so `holder()` is
/// the realm's global proxy; the sandbox is looked up from the context that proxy
/// belongs to. Returning `None` (a realm whose sandbox is gone) makes every handler
/// fall through to ordinary V8 behaviour rather than dropping the operation.
fn sandbox_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _holder: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    // The lookup is keyed by the *global object's* identity hash, not by a property
    // and not by embedder data. Reading any property here — including
    // `get_embedder_data`, which round-trips through V8's property machinery, and
    // the symbol mark itself — invokes this very handler and recurses until the
    // stack runs out. `Object::get_identity_hash` is a direct V8 call with no
    // property path, and it is stable for the life of the object.
    let context = scope.get_current_context();
    let id = i32::from(context.global(scope).get_identity_hash()) as u64;
    CONTEXTS.with(|contexts| {
        contexts
            .borrow()
            .get(&id)
            .and_then(|entry| entry.sandbox.as_ref())
            .map(|sandbox| v8::Local::new(scope, sandbox))
    })
}

fn sandbox_get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Value>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    // Only a property the sandbox actually has may be intercepted. `get` returns
    // `Some(undefined)` for a miss, so asking it alone would shadow every global
    // the new realm provides: `typeof Object` inside the realm would come back
    // `undefined`. The own-property check is what lets V8 fall through to the
    // realm's own global object and its prototype chain.
    if !sandbox.has_own_property(scope, key).unwrap_or(false) {
        return v8::Intercepted::kNo;
    }
    let Some(value) = sandbox.get(scope, key.into()) else {
        return v8::Intercepted::kNo;
    };
    rv.set(value);
    v8::Intercepted::kYes
}

fn sandbox_set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<v8::Name>,
    value: v8::Local<'s, v8::Value>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    sandbox.set(scope, key.into(), value);
    // A successful set reports success through the return value; without it a
    // strict-mode assignment throws even though it was stored.
    rv.set_bool(true);
    v8::Intercepted::kYes
}

fn sandbox_query<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Integer>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    if !sandbox.has_own_property(scope, key).unwrap_or(false) {
        return v8::Intercepted::kNo;
    }
    let attributes = sandbox
        .get_property_attributes(scope, key.into())
        .unwrap_or(v8::PropertyAttribute::NONE);
    rv.set(v8::Integer::new(scope, attributes.as_u32() as i32));
    v8::Intercepted::kYes
}

fn sandbox_delete<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    let deleted = sandbox.delete(scope, key.into()).unwrap_or(false);
    rv.set_bool(deleted);
    v8::Intercepted::kYes
}

fn sandbox_enumerate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Array>,
) {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return;
    };
    let Some(names) = sandbox.get_own_property_names(scope, v8::GetPropertyNamesArgs::default())
    else {
        return;
    };
    rv.set(names);
}

fn sandbox_get_index<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Value>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    let Some(value) = sandbox.get_index(scope, index) else {
        return v8::Intercepted::kNo;
    };
    rv.set(value);
    v8::Intercepted::kYes
}

fn sandbox_set_index<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    value: v8::Local<'s, v8::Value>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    sandbox.set_index(scope, index, value);
    rv.set_bool(true);
    v8::Intercepted::kYes
}

fn sandbox_query_index<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Integer>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    if !sandbox.has_index(scope, index).unwrap_or(false) {
        return v8::Intercepted::kNo;
    }
    rv.set(v8::Integer::new(
        scope,
        v8::PropertyAttribute::NONE.as_u32() as i32,
    ));
    v8::Intercepted::kYes
}

fn sandbox_delete_index<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return v8::Intercepted::kNo;
    };
    let deleted = sandbox.delete_index(scope, index).unwrap_or(false);
    rv.set_bool(deleted);
    v8::Intercepted::kYes
}

/// Enumerates the sandbox's indices.
///
/// The indices of an array-like sandbox are the integers `0..length`, and V8 uses
/// this answer to decide which numeric keys to surface. A sandbox that is not
/// array-like contributes none, which matches Node's `IndexedPropertyEnumerator`
/// returning an empty array for a non-array sandbox.
fn sandbox_enumerate_index<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Array>,
) {
    let Some(sandbox) = sandbox_for(scope, args.holder()) else {
        return;
    };
    let length_key = v8::String::new(scope, "length");
    let length = length_key
        .and_then(|key| sandbox.get(scope, key.into()))
        .and_then(|value| value.uint32_value(scope))
        .unwrap_or(0);
    let indices = v8::Array::new(scope, length as i32);
    for index in 0..length {
        let key = v8::Integer::new(scope, index as i32);
        indices.set_index(scope, index, key.into());
    }
    rv.set(indices);
}

/// Builds the `ContextifyScript` constructor with its two prototype methods.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(script_new)
        .length(2)
        .build(scope);
    let class_name =
        v8::String::new(scope, "ContextifyScript").ok_or("cannot allocate the class name")?;
    template.set_class_name(class_name);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let constructor = template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate ContextifyScript".to_string())?;

    // Methods live on the constructor's `prototype` object, which is the object
    // V8 uses for instances. `ObjectTemplate` has no property setter in this
    // binding, so this is how the prototype is populated and the observable
    // result is identical to `SetProtoMethod`.
    let prototype_key = v8::String::new(scope, "prototype").ok_or("prototype key")?;
    let prototype = constructor
        .get(scope, prototype_key.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or_else(|| "ContextifyScript has no prototype object".to_string())?;

    macro_rules! method {
        ($name:literal, $callback:expr) => {{
            let method = v8::FunctionTemplate::builder($callback).build(scope);
            if let (Some(function), Some(key)) =
                (method.get_function(scope), v8::String::new(scope, $name))
            {
                prototype.set(scope, key.into(), function.into());
            }
        }};
    }
    method!("createCachedData", create_cached_data);
    method!("runInContext", run_in_context);

    Ok(constructor.into())
}

/// `new ContextifyScript(code, filename, lineOffset, columnOffset, cachedData,
/// produceCachedData, parsingContext, hostDefinedOptionId)`.
fn script_new<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(code) = args.get(0).to_string(scope) else {
        return throw_type_error(scope, "ContextifyScript requires source text");
    };
    let Some(filename) = args.get(1).to_string(scope) else {
        return throw_type_error(scope, "ContextifyScript requires a filename");
    };
    let line_offset = args.get(2).int32_value(scope).unwrap_or(0);
    let column_offset = args.get(3).int32_value(scope).unwrap_or(0);
    let produce_cached_data = args.get(5).is_true();
    let symbol = v8::Local::<v8::Symbol>::try_from(args.get(7)).ok();

    // `parsingContext` selects the realm the source is parsed in. `vm.Script`
    // passes it so that a script compiled for a sandbox sees that sandbox's
    // globals rather than the main realm's.
    let parsing_context = match args.get(6) {
        value if value.is_undefined() => None,
        value => context_of(scope, value),
    };

    let mut cached = match compile::cached_data_argument(scope, args.get(4)) {
        Ok(bytes) => bytes,
        Err(message) => return throw_type_error(scope, &message),
    };
    let mut source = build_script_source(
        scope,
        code,
        filename,
        line_offset,
        column_offset,
        symbol,
        cached.as_mut(),
    );

    let compiled = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let script = match parsing_context {
            Some(context) => {
                let mut context_scope =
                    std::pin::pin!(v8::ContextScope::new(&mut **scope, context));
                let scope: &mut v8::PinScope<'s, '_> = &mut context_scope;
                compile_unbound(scope, &mut source)
            }
            None => {
                let scope: &mut v8::PinScope<'s, '_> = scope;
                compile_unbound(scope, &mut source)
            }
        };
        if script.is_none() && scope.has_caught() && !scope.has_terminated() {
            // V8's own error, with its source position and caret line intact.
            scope.rethrow();
        }
        script
    };

    let Some(script) = compiled else {
        return;
    };

    let new_cached_data = if produce_cached_data {
        script.create_code_cache()
    } else {
        None
    };

    let that = args.this();
    let id = store_script(scope, script);
    if !that.set_internal_field(SCRIPT_FIELD, v8::Number::new(scope, id as f64).into()) {
        return throw_error(scope, "ContextifyScript has no internal field");
    }

    if let Some(cached) = source.get_cached_data() {
        set(
            scope,
            that,
            "cachedDataRejected",
            v8::Boolean::new(scope, cached.rejected()).into(),
        );
    }
    if let Some(cached) = new_cached_data {
        if let Some(view) = compile::buffer_from(scope, &cached) {
            set(scope, that, "cachedData", view);
            set(
                scope,
                that,
                "cachedDataProduced",
                v8::Boolean::new(scope, true).into(),
            );
        }
    }
    set(scope, that, "sourceURL", script.get_source_url(scope));
    set(
        scope,
        that,
        "sourceMapURL",
        script.get_source_mapping_url(scope),
    );

    // `hostDefinedOptionId` is how `internal/modules/esm/utils.js` finds the
    // script's registry: `registerModule(referrer, ...)` reads
    // `referrer[host_defined_option_symbol]` and uses the symbol as a WeakMap
    // key, so the value must be *a symbol* or the map refuses it with "Invalid
    // value used as weak map key".
    //
    // Node stores it in the Script's real host-defined options and reads it back
    // with `ScriptOrigin`/`GetHostDefinedOptionId`. This binding has no path to
    // those, so the same symbol is written as a property on the wrapper, which is
    // the only thing the JS layer reads. `vm.Script` passes `undefined` here and
    // gets no property, which is why the failure only appeared on the
    // `compileScript` path `worker_thread.js` uses.
    if let Some(symbol) = symbol {
        if let Some(key) = v8::String::new(scope, "hostDefinedOptionId") {
            let _ = that.set(scope, key.into(), symbol.into());
        }
        let mark = host_defined_option_symbol(scope);
        rn_core::define_mark(scope, that, mark, symbol.into());
    }
}

fn compile_unbound<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &mut v8::script_compiler::Source,
) -> Option<v8::Local<'s, v8::UnboundScript>> {
    let options = if source.get_cached_data().is_some() {
        v8::script_compiler::CompileOptions::ConsumeCodeCache
    } else {
        v8::script_compiler::CompileOptions::NoCompileOptions
    };
    v8::script_compiler::compile_unbound_script(
        scope,
        source,
        options,
        v8::script_compiler::NoCacheReason::NoReason,
    )
}

fn build_script_source<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    code: v8::Local<'s, v8::String>,
    filename: v8::Local<'s, v8::String>,
    line_offset: i32,
    column_offset: i32,
    symbol: Option<v8::Local<'s, v8::Symbol>>,
    cached: Option<&mut compile::CachedBytes>,
) -> v8::script_compiler::Source {
    let host_defined = compile::host_defined_options(scope, symbol);
    let origin = compile::origin(
        scope,
        filename,
        line_offset,
        column_offset,
        Some(host_defined.into()),
    );
    match cached {
        Some(cached) if !cached.as_slice().is_empty() => {
            v8::script_compiler::Source::new_with_cached_data(
                code,
                Some(&origin),
                v8::script_compiler::CachedData::new(cached.as_slice()),
            )
        }
        _ => v8::script_compiler::Source::new(code, Some(&origin)),
    }
}

/// `script.createCachedData()`: V8's code cache for this script's source.
fn create_cached_data<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(script) = script_of(scope, args.this()) else {
        return throw_type_error(
            scope,
            "Script methods can only be called on script instances",
        );
    };
    // An empty `Buffer` rather than `undefined` when V8 declines to serialise:
    // `vm.Script.prototype.createCachedData` is documented to return a Buffer.
    let bytes: Vec<u8> = script
        .create_code_cache()
        .map(|cached| cached.to_vec())
        .unwrap_or_default();
    if let Some(view) = compile::buffer_from(scope, &bytes) {
        rv.set(view);
    }
}

/// The `UnboundScript` an instance carries.
fn script_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::UnboundScript>> {
    let field = object.get_internal_field(scope, SCRIPT_FIELD)?;
    let value = v8::Local::<v8::Value>::try_from(field).ok()?;
    let id = u64::try_from(value.number_value(scope)? as i64).ok()?;
    SCRIPTS.with(|scripts| {
        scripts
            .borrow()
            .get(&id)
            .map(|script| v8::Local::new(scope, script))
    })
}

/// `script.runInContext(sandbox, timeout, displayErrors, breakOnSigint,
/// breakOnFirstLine)`.
///
/// `sandbox` is `null` for the "run in this context" form. `breakOnSigint` and
/// `breakOnFirstLine` need the inspector and a SIGINT watchdog respectively, and
/// both are reported rather than silently ignored; see [`run_script`].
fn run_in_context<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(script) = script_of(scope, args.this()) else {
        return throw_type_error(
            scope,
            "Script methods can only be called on script instances",
        );
    };
    let timeout = args.get(1).int32_value(scope).unwrap_or(-1);
    let display_errors = args.get(2).is_true();
    let break_on_sigint = args.get(3).is_true();
    let break_on_first_line = args.get(4).is_true();

    let sandbox = args.get(0);
    let context = if sandbox.is_object() {
        match context_of(scope, sandbox) {
            Some(context) => Some(context),
            None => return throw_type_error(scope, "runInContext expects a contextified sandbox"),
        }
    } else if sandbox.is_null() {
        None
    } else {
        return throw_type_error(scope, "runInContext expects a sandbox object or null");
    };

    if break_on_first_line {
        return throw_error(
            scope,
            "runInContext: breakOnFirstLine needs the inspector, which rustnode does not host",
        );
    }
    if break_on_sigint {
        return throw_error(
            scope,
            "runInContext: breakOnSigint needs a V8 watchdog thread, which rustnode does not run",
        );
    }

    run_script(scope, script, context, timeout, display_errors, &mut rv);
}

/// Runs `script` in `context`, or the current realm when `context` is `None`.
///
/// A positive `timeout` needs V8's watchdog: `TerminateExecution` has to be
/// called from another thread while the script is running, and calling it from
/// this one would terminate the caller's own frame instead of the script's.
/// rustnode has no watchdog thread, so a timeout is reported rather than ignored:
/// a `vm` script that runs forever is a hung process the caller cannot diagnose.
fn run_script<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    script: v8::Local<'s, v8::UnboundScript>,
    context: Option<v8::Local<'s, v8::Context>>,
    timeout: i32,
    _display_errors: bool,
    rv: &mut v8::ReturnValue<'s, v8::Value>,
) {
    if timeout >= 0 {
        return throw_error(
            scope,
            "runInContext: script timeouts need a V8 watchdog thread, which rustnode does not run",
        );
    }

    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let result = match context {
        Some(context) => {
            let mut context_scope = std::pin::pin!(v8::ContextScope::new(&mut **scope, context));
            let scope: &mut v8::PinScope<'s, '_> = &mut context_scope;
            script.bind_to_current_context(scope).run(scope)
        }
        None => {
            let scope: &mut v8::PinScope<'s, '_> = scope;
            script.bind_to_current_context(scope).run(scope)
        }
    };
    match result {
        Some(value) => rv.set(value),
        None => {
            if scope.has_caught() && !scope.has_terminated() {
                scope.rethrow();
            }
        }
    }
}

fn set(
    scope: &v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) {
    if let Some(key) = v8::String::new(scope, name) {
        object.set(scope, key.into(), value);
    }
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prototype_carries_exactly_the_two_recorded_methods() {
        // `Object.getOwnPropertyNames(ContextifyScript.prototype)` on the real
        // binary reports `createCachedData`, `runInContext`, `constructor`.
        assert_eq!(SCRIPT_METHODS, ["createCachedData", "runInContext"]);
    }
}
