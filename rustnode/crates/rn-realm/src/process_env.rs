//! `process.env`, as Node builds it: an interceptor over the real environment.
//!
//! # Why an interceptor rather than an object
//!
//! Node's `process.env` is not a copy of the environment. `CreateEnvProxyTemplate`
//! in `src/node_env_var.cc` builds an `ObjectTemplate` whose named and indexed
//! property handlers read and write the process environment through libuv, and
//! `Realm::RunBootstrapping` instantiates it into `process.env`. Three
//! consequences are observable from JavaScript, and a plain object gets all
//! three wrong:
//!
//! * **Every value is a string.** `process.env.NUM = 42` stores `"42"`, because
//!   `EnvSetter` calls `value->ToString(env->context())` before storing. A plain
//!   object keeps the number, and `typeof process.env.NUM` is then `'number'`.
//! * **A write reaches a child process.** Storage is `uv_os_setenv`, which
//!   mutates the block `spawn()` copies, so `process.env.X = 'y'` followed by
//!   `spawnSync(process.execPath, …)` shows `X` in the child. A plain object is
//!   visible only to the JavaScript that assigned to it.
//! * **Numeric keys are ordinary variables.** `process.env[42] = 'x'` sets the
//!   variable named `"42"`, which is why Node installs an
//!   `IndexedPropertyHandlerConfiguration` alongside the named one. A named
//!   interceptor alone silently misses every numeric key, and
//!   `test/parallel/test-process-env.js` asserts exactly that case.
//!
//! # The shape of the object itself
//!
//! The template is created from a `FunctionTemplate`, so the instance has an
//! ordinary `Object.prototype` — not a null prototype, and not the object
//! `Object.create(null)` produces. That is deliberate and observable:
//!
//! ```console
//! $ node -e 'console.log(process.env.hasOwnProperty === Object.prototype.hasOwnProperty)'
//! true
//! ```
//!
//! `test-process-env.js` is explicit about it: `process.env.hasOwnProperty` is
//! `Object.prototype.hasOwnProperty` until user code assigns to that name, at
//! which point `Object.hasOwn(process.env, 'hasOwnProperty')` becomes `true`
//! because the interceptor now answers for it. So the instance must be a plain
//! object whose interceptor *shadows* anything reachable through the prototype.
//!
//! # What is not implemented
//!
//! `--trace-env` and the permission model's read-time reporting are stated as
//! gaps in [`GAPS`] rather than approximated.

use rn_v8_sys::v8;

/// The `process.env` behaviour deliberately left out of this build.
///
/// Each entry is a gap rather than a silent omission: a caller can report it,
/// and `DEVIATIONS` in `rn-compat` is the place a test would look. The list is
/// data so it can be asserted on instead of remembered.
pub const GAPS: &[(&str, &str)] = &[
    (
        "--trace-env",
        "src/node_env_var.cc's TraceEnvVar writes a line to stderr for every get, set, \
         query, delete and enumerate. The flag is parsed and stored, but nothing in this \
         module emits the lines.",
    ),
    (
        "DEP0104 under a worker's own realm",
        "The DEP0104 warning is emitted from the setter (--pending-deprecation and a value \
         that is not string, number or boolean), once per process. It reaches \
         process.emitWarning through the module loader, so an assignment that happens \
         before internal/process/warning is requireable is a silent skip; the store still \
         happens.",
    ),
    (
        "permission env scrub reporting",
        "Node's EnvGetter and EnvQuery publish a denial to node:permission-model:env and \
         warn once when a variable was removed by the startup scrub. This build scrubs the \
         block (rn-permission) but does not report a read of a removed variable, so \
         test-permission-env-warning.js fails. The scrub also does not wipe the initial \
         environment entries, so `/proc/<pid>/environ` still shows them.",
    ),
];

/// Builds the `process.env` object.
///
/// One instance per realm, which is what `Realm::RunBootstrapping` does with
/// `isolate_data()->env_proxy_template()->NewInstance(context())`. Worker threads
/// get their own, over the environment block they inherit.
pub fn create<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    // Node builds a `FunctionTemplate` and an `ObjectTemplate` from it rather
    // than a bare `ObjectTemplate::New(isolate)`. The constructor is never
    // exposed; what it does is give the instance the ordinary object prototype
    // instead of the null prototype a plain template produces, which is what
    // makes `process.env.hasOwnProperty` answer from `Object.prototype`.
    let constructor = v8::FunctionTemplate::new(scope, unused_constructor);
    let template = v8::ObjectTemplate::new_from_template(scope, constructor);

    template.set_named_property_handler(
        v8::NamedPropertyHandlerConfiguration::new()
            .getter(named_get)
            .setter(named_set)
            .query(named_query)
            .deleter(named_delete)
            .enumerator(enumerate)
            .definer(named_define)
            // `kHasNoSideEffect` is what Node passes, and it matters: without it
            // V8 refuses to run the getter from a context that has side effects
            // disabled, such as a `--frozen-intrinsics` snapshot or an
            // `util.inspect` custom formatter.
            .flags(v8::PropertyHandlerFlags::HAS_NO_SIDE_EFFECT),
    );

    // The indexed handler exists because `process.env[42]` is the variable named
    // `"42"`. Every callback forwards to the named one after converting the
    // index, exactly as `EnvGetterIndexed` and friends do.
    template.set_indexed_property_handler(
        v8::IndexedPropertyHandlerConfiguration::new()
            .getter(indexed_get)
            .setter(indexed_set)
            .query(indexed_query)
            .deleter(indexed_delete)
            .definer(indexed_define)
            .flags(v8::PropertyHandlerFlags::HAS_NO_SIDE_EFFECT),
    );

    template.new_instance(scope).inspect(|instance| {
        // Recorded so `structuredClone(process.env)` and
        // `postMessage(process.env)` can recognise it. Node uses
        // `env_proxy_ctor_template->HasInstance(object)` for the same purpose;
        // the instance is an ordinary object with no internal fields, so there
        // is nothing else to test.
        rn_core::env_proxy::set(scope, *instance);
    })
}

/// The constructor is never called; `FunctionTemplate::New(isolate)` in Node
/// passes no callback either. It exists so the instance has a prototype.
fn unused_constructor(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
}

/// The variable name behind a named property, if there is one.
///
/// A symbol is not a variable name: `EnvGetter` returns `undefined` for one and
/// intercepts the request, so `process.env[Symbol()]` is `undefined` rather than
/// falling through to the prototype. Every other handler that cannot name a
/// variable reports `None` and falls through to ordinary lookup.
fn name_of<'s>(scope: &mut v8::PinScope<'s, '_>, key: v8::Local<'s, v8::Name>) -> Option<String> {
    let value: v8::Local<'s, v8::Value> = key.into();
    if value.is_symbol() {
        return None;
    }
    Some(key.to_rust_string_lossy(scope))
}

/// `EnvGetter`.
fn named_get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    _args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Value>,
) -> v8::Intercepted {
    let value: v8::Local<'s, v8::Value> = key.into();
    if value.is_symbol() {
        // `EnvGetter` sets `undefined` and reports that it intercepted, so a
        // symbol read does not reach `Object.prototype`.
        rv.set_undefined();
        return v8::Intercepted::kYes;
    }
    let Some(name) = name_of(scope, key) else {
        return v8::Intercepted::kNo;
    };
    // `EnvGetter` reports a permission-model read before answering, and the
    // report can change the answer: a variable the startup scrub removed must
    // read as absent even though the scrub is what made it absent, and the
    // denial has to be published for a subscriber to see it.
    report_env_read(scope, &name);
    if rn_permission::runtime::env_read_is_denied(&name) {
        return v8::Intercepted::kNo;
    }
    match env_store::get(&name) {
        Some(value) => {
            if let Some(text) = v8::String::new(scope, &value) {
                rv.set(text.into());
            }
            v8::Intercepted::kYes
        }
        // A missing variable is *not* intercepted: the request falls through to
        // ordinary property lookup, so the prototype chain is still visible and
        // `process.env.missing` is a normal missing property.
        None => v8::Intercepted::kNo,
    }
}

/// Publishes what a read of `name` should report, per the permission model.
///
/// Node's `EnvGetter` calls `ReportRemovedEnvVar` when the variable is absent
/// and `AuditEnvVar` when the model is in warning-only mode; both land in
/// `Permission::PublishDenied`, which is a `node:permission-model:env`
/// publication. Doing it here rather than in the store keeps the store a data
/// structure with no JavaScript in it.
fn report_env_read(scope: &mut v8::PinScope<'_, '_>, name: &str) {
    match rn_permission::runtime::inspect_env_read(name) {
        rn_permission::runtime::EnvReadReport::Nothing => {}
        rn_permission::runtime::EnvReadReport::Audited { denied } => {
            rn_permission::runtime::publish_env_denial(scope, &denied);
        }
        rn_permission::runtime::EnvReadReport::Removed { denied, warn } => {
            rn_permission::runtime::publish_env_denial(scope, &denied);
            if warn {
                warn_removed_env_var(scope, name);
            }
        }
    }
}

/// The one-time warning for reading a variable the scrub removed.
///
/// `ReportRemovedEnvVar`'s `ProcessEmitWarning`:
///
/// ```text
/// The permission model removed the environment variable "%s" at startup.
/// Use --allow-env to manage permissions.
/// ```
///
/// It is a plain `Warning`, not a `DeprecationWarning`, and `ProcessEmitWarning`
/// respects `--no-warnings`, which `emitWarning` already does.
fn warn_removed_env_var(scope: &mut v8::PinScope<'_, '_>, name: &str) {
    let Some(require) = rn_core::hook_slot::require(scope) else {
        return;
    };
    let Some(id) = v8::String::new(scope, "internal/process/warning") else {
        return;
    };
    let Some(warning) = require.call(scope, v8::undefined(scope).into(), &[id.into()]) else {
        return;
    };
    let Ok(warning) = v8::Local::<v8::Object>::try_from(warning) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "emitWarning") else {
        return;
    };
    let Some(emit) = warning.get(scope, key.into()) else {
        return;
    };
    let Ok(emit) = v8::Local::<v8::Function>::try_from(emit) else {
        return;
    };
    let message = format!(
        "The permission model removed the environment variable \"{name}\" at startup. \
         Use --allow-env to manage permissions."
    );
    let Some(message) = v8::String::new(scope, &message) else {
        return;
    };
    let _ = emit.call(scope, warning.into(), &[message.into()]);
}

/// `EnvSetter`.
fn named_set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    value: v8::Local<'s, v8::Value>,
    _args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    if !store(scope, key, value) {
        return v8::Intercepted::kNo;
    }
    rv.set_bool(true);
    v8::Intercepted::kYes
}

/// The store half of `EnvSetter`, shared with `EnvDefiner`.
///
/// Everything assigned is coerced with `ToString` before it is stored, which is
/// the difference from a plain object: a number, a boolean, `undefined` and an
/// object with a `toString` all become the string `ToString` produces. A
/// `ToString` that throws — a symbol value, an object whose `toString` throws —
/// propagates, exactly as Node's `.ToLocal(&value_string)` does by returning
/// `kNo` with the exception already pending.
fn store<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    value: v8::Local<'s, v8::Value>,
) -> bool {
    // A symbol key names no variable. Node's `property->ToString` would produce
    // `"Symbol()"`, which is not a name anyone can read, so writing one is a
    // no-op that reports success rather than an error V8 cannot express here.
    let Some(name) = name_of(scope, key) else {
        return true;
    };
    warn_pending_deprecation(scope, value);
    let stored = store_named(scope, &name, value);
    // `DateTimeConfigurationChangeNotification`: writing a name that starts with
    // `TZ` means the process's time zone may have changed, and V8 caches the
    // detected zone. Node calls `tzset()` and then tells the isolate to
    // redetect; without that, a `Date` formatted after `process.env.TZ = 'UTC'`
    // keeps the previous zone and `date.getHours()` disagrees with Node.
    if stored && name.starts_with("TZ") {
        // `tzset` is not in the `libc` crate's surface here, so it is declared
        // directly: it is C library ABI, takes no arguments and cannot fail.
        extern "C" {
            fn tzset();
        }
        // SAFETY: no arguments, no return value, no failure mode.
        unsafe { tzset() };
        scope.date_time_configuration_change_notification(v8::TimeZoneDetection::Redetect);
    }
    stored
}

/// `EnvSetter`'s DEP0104 warning.
///
/// Node emits it when `--pending-deprecation` is on and the value is not a
/// string, number or boolean, because those are the only three types with an
/// obvious string form; anything else was almost certainly assigned by mistake.
/// The coercion still happens either way — the warning is an observation, not a
/// gate — which is why this runs before the store and not instead of it.
///
/// `env->EmitProcessEnvWarning()` fires at most once per process. Node records
/// that on the `Environment`, and this uses a process-wide `AtomicBool` because
/// every realm here shares one process and `test-process-env-deprecation.js`
/// sets two variables expecting one warning.
fn warn_pending_deprecation(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) {
    if value.is_string() || value.is_number() || value.is_boolean() {
        return;
    }
    if !pending_deprecation_enabled() {
        return;
    }
    if WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    // `ProcessEmitDeprecationWarning` reaches `process.emitWarning`, which is
    // JavaScript. There is no guarantee the module loader is ready when the
    // first assignment runs — `lib/internal/bootstrap/realm.js` reads
    // `process.env` before the loaders exist — so a missing `process`,
    // `emitWarning` or loader is a silent skip. The assignment itself is not
    // affected, which is the part that matters.
    let Some(require) = rn_core::hook_slot::require(scope) else {
        return;
    };
    let Some(id) = v8::String::new(scope, "internal/process/warning") else {
        return;
    };
    let Some(warning) = require.call(scope, v8::undefined(scope).into(), &[id.into()]) else {
        return;
    };
    let Ok(warning) = v8::Local::<v8::Object>::try_from(warning) else {
        return;
    };
    let Some(key) = v8::String::new(scope, "emitWarning") else {
        return;
    };
    let Some(emit) = warning.get(scope, key.into()) else {
        return;
    };
    let Ok(emit) = v8::Local::<v8::Function>::try_from(emit) else {
        return;
    };
    let (Some(message), Some(kind), Some(code)) = (
        v8::String::new(
            scope,
            "Assigning any value other than a string, number, or boolean to a \
             process.env property is deprecated. Please make sure to convert the \
             value to a string before setting process.env with it.",
        ),
        v8::String::new(scope, "DeprecationWarning"),
        v8::String::new(scope, "DEP0104"),
    ) else {
        return;
    };
    let _ = emit.call(
        scope,
        warning.into(),
        &[message.into(), kind.into(), code.into()],
    );
}

/// Whether `--pending-deprecation` was passed.
///
/// `env->options()->pending_deprecation` in `EnvSetter`. The option store is
/// where `lib/**` reads the same flag, so this and
/// `require('internal/options').getOptionValue('--pending-deprecation')` cannot
/// disagree.
fn pending_deprecation_enabled() -> bool {
    matches!(
        rn_bind_options::parsed::value_of("--pending-deprecation"),
        Some(rn_bind_options::parsed::ParsedValue::Bool(true))
    )
}

/// `env->EmitProcessEnvWarning()`'s "only once" latch.
static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Stores `value` under `name`, with `EnvSetter`'s `ToString` coercion.
///
/// Split from [`store`] so `EnvDefiner` can pass a descriptor's value, whose
/// lifetime is the descriptor's borrow rather than the callback's scope.
fn store_named(
    scope: &mut v8::PinScope<'_, '_>,
    name: &str,
    value: v8::Local<'_, v8::Value>,
) -> bool {
    let Some(text) = value.to_string(scope) else {
        return false;
    };
    let text = text.to_rust_string_lossy(scope);
    // An empty name is not a variable: `process.env[''] = ''` leaves it
    // undefined, which `test-process-env.js` asserts. libuv would accept it on
    // Unix, and libuv is not the authority on the language-level rule.
    if name.is_empty() {
        return true;
    }
    // A name with a NUL cannot be stored; libuv rejects it. Dropping the write
    // rather than throwing matches Node, whose `uv_os_setenv` result is
    // discarded.
    let _ = env_store::set(name, &text);
    true
}

/// `EnvQuery`.
fn named_query<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    _args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Integer>,
) -> v8::Intercepted {
    let Some(name) = name_of(scope, key) else {
        // `EnvQuery` only answers for strings; a symbol query falls through to
        // ordinary lookup, which is what makes `process.env[Symbol.iterator]`
        // find the real one.
        return v8::Intercepted::kNo;
    };
    if !env_store::contains(&name) {
        // A removed variable reports here too, because `'X' in process.env` is
        // a read of it: `test-permission-env-warning.js` counts the two value
        // reads and the `in` check as three events.
        report_env_read(scope, &name);
        return v8::Intercepted::kNo;
    }
    // `EnvQuery` reports for a variable that *is* present as well, but only the
    // audit half of the report — `AuditEnvVar` is called inside the
    // `has_env` branch. That is what makes `process.env.ALLOWED` and a variable
    // created at runtime report nothing while a scrubbed-but-still-present one
    // does. The warning half cannot apply here, because a variable that exists
    // was not removed.
    if let rn_permission::runtime::EnvReadReport::Audited { denied } =
        rn_permission::runtime::inspect_env_read(&name)
    {
        rn_permission::runtime::publish_env_denial(scope, &denied);
    }
    // `v8::None` — writable, enumerable, configurable — which is what every real
    // environment variable is. This is what makes
    // `Object.getOwnPropertyDescriptor(process.env, 'X')` report those three
    // flags instead of `undefined`, and it is why `delete` always succeeds.
    rv.set_int32(v8::PropertyAttribute::NONE.as_u32() as i32);
    v8::Intercepted::kYes
}

/// `EnvDeleter`.
///
/// Always reports `true`: "process.env never has non-configurable properties,
/// so always return true like the tc39 delete operator". A delete of a variable
/// that was never set also succeeds, which is what
/// `test-process-env.js`'s `delete process.env.NON_EXISTING_VARIABLE` asserts.
fn named_delete<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    _args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    if let Some(name) = name_of(scope, key) {
        if !name.is_empty() {
            let _ = env_store::unset(&name);
        }
    }
    rv.set_bool(true);
    v8::Intercepted::kYes
}

/// `EnvEnumerator`.
///
/// The keys `Object.keys(process.env)`, `for…in` and spread see. They come from
/// libuv's enumeration of the block, so a variable written a moment ago is
/// included and one that was deleted is not.
fn enumerate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Array>,
) {
    let entries = env_store::vars();
    let array = v8::Array::new(scope, entries.len() as i32);
    for (index, entry) in entries.iter().enumerate() {
        if let Some(name) = v8::String::new(scope, &entry.name) {
            array.set_index(scope, index as u32, name.into());
        }
    }
    rv.set(array);
}

/// `EnvDefiner`.
///
/// `defineProperty` on `process.env` only accepts a configurable, writable,
/// enumerable data descriptor. Node rejects the rest with
/// `ERR_INVALID_OBJECT_DEFINE_PROPERTY`, and the two messages differ: one for a
/// descriptor that is not a plain data descriptor, one for an accessor.
fn named_define<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    descriptor: &v8::PropertyDescriptor,
    _args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    if descriptor.has_get() || descriptor.has_set() {
        throw_define_property(
            scope,
            "'process.env' does not accept an accessor(getter/setter) descriptor",
        );
        return v8::Intercepted::kYes;
    }
    // A descriptor that has no value at all is Node's third case: it is not a
    // data descriptor, so it is rejected with the same message as one that omits
    // `writable`, `enumerable` or `configurable`.
    if !descriptor.has_value()
        || !descriptor.has_writable()
        || !descriptor.has_enumerable()
        || !descriptor.has_configurable()
        || !descriptor.writable()
        || !descriptor.enumerable()
        || !descriptor.configurable()
    {
        throw_define_property(
            scope,
            "'process.env' only accepts a configurable, writable, and enumerable data descriptor",
        );
        return v8::Intercepted::kYes;
    }
    // `name_of` needs the scope, so the name is resolved before the store call;
    // a symbol key names no variable, and `store_named` treats an empty name as
    // a successful no-op.
    let name = name_of(scope, key).unwrap_or_default();
    if !store_named(scope, &name, descriptor.value()) {
        // `store_named` only fails when `ToString` threw, and that exception is
        // already pending, so there is no result to report.
        return v8::Intercepted::kYes;
    }
    rv.set_bool(true);
    v8::Intercepted::kYes
}

/// `THROW_ERR_INVALID_OBJECT_DEFINE_PROPERTY`.
///
/// Node's macro raises a `TypeError` whose `code` is that name and whose message
/// is the text passed here. `lib/internal/errors.js` does not define it — it is
/// a C++-side code, from `src/node_errors.h` — so there is no message prefix to
/// reproduce.
fn throw_define_property(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    if let (Ok(object), Some(code)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "ERR_INVALID_OBJECT_DEFINE_PROPERTY"),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

/// The index as the variable name it names.
///
/// `Uint32ToString` in Node: a decimal, no separators, no sign.
fn index_name(index: u32) -> String {
    index.to_string()
}

fn indexed_get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    args: v8::PropertyCallbackArguments<'s>,
    rv: v8::ReturnValue<v8::Value>,
) -> v8::Intercepted {
    let Some(key) = v8::String::new(scope, &index_name(index)) else {
        return v8::Intercepted::kNo;
    };
    named_get(scope, key.into(), args, rv)
}

fn indexed_set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    value: v8::Local<'s, v8::Value>,
    args: v8::PropertyCallbackArguments<'s>,
    rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(key) = v8::String::new(scope, &index_name(index)) else {
        return v8::Intercepted::kNo;
    };
    named_set(scope, key.into(), value, args, rv)
}

fn indexed_query<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    args: v8::PropertyCallbackArguments<'s>,
    rv: v8::ReturnValue<v8::Integer>,
) -> v8::Intercepted {
    let Some(key) = v8::String::new(scope, &index_name(index)) else {
        return v8::Intercepted::kNo;
    };
    named_query(scope, key.into(), args, rv)
}

fn indexed_delete<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    args: v8::PropertyCallbackArguments<'s>,
    rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(key) = v8::String::new(scope, &index_name(index)) else {
        return v8::Intercepted::kNo;
    };
    named_delete(scope, key.into(), args, rv)
}

fn indexed_define<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    index: u32,
    descriptor: &v8::PropertyDescriptor,
    args: v8::PropertyCallbackArguments<'s>,
    rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    let Some(key) = v8::String::new(scope, &index_name(index)) else {
        return v8::Intercepted::kNo;
    };
    named_define(scope, key.into(), descriptor, args, rv)
}

/// The environment block this module reads and writes.
///
/// Re-exported so `os.tmpdir()`, `os.homedir()`, a child process and the
/// permission scrub all resolve the same store. Keeping the alias here documents
/// that this module owns no storage of its own: everything that looks like state
/// is libuv's.
pub use rn_env as env_store;
