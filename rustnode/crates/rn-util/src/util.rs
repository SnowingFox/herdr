//! `internalBinding('util')`.
//!
//! The widest namespace in Node: 36 members spanning V8 introspection, symbol
//! identity, lazy property helpers and a sleep. `lib/internal/util.js` reads it
//! before almost anything else, so this is what unblocks the builtin loader.
//!
//! Members are installed in groups. A member this crate does not install is
//! listed in [`DEFERRED`] with the reason, so the contract check reports it
//! instead of letting the JS layer read `undefined`.

use std::collections::HashMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use libuv_sys2 as uv;

/// Members exposed on the namespace object, matching `contracts/util.json`.
pub const MEMBERS: &[&str] = &[
    "arrayBufferViewHasBuffer",
    "constants",
    "constructSharedArrayBuffer",
    "defineLazyProperties",
    "getCallSites",
    "getCallerLocation",
    "getConstructorName",
    "getExternalValue",
    "getOwnNonIndexProperties",
    "getPromiseDetails",
    "getProxyDetails",
    "getSharedArrayBufferGrowable",
    "guessHandleType",
    "isAnyArrayBuffer",
    "isArrayBuffer",
    "isArrayBufferView",
    "isAsyncFunction",
    "isDataView",
    "isDate",
    "isExternal",
    "isInsideNodeModules",
    "isMap",
    "isMapIterator",
    "isNativeError",
    "isPromise",
    "isRegExp",
    "isSet",
    "isSetIterator",
    "isTypedArray",
    "isUint8Array",
    "markPromiseAsHandled",
    "parseEnv",
    "previewEntries",
    "privateSymbols",
    "shouldAbortOnUncaughtToggle",
    "sleep",
];

/// Members the namespace needs but this crate does not install yet.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "getSharedArrayBufferGrowable",
        "growable SAB flag, follows the buffer namespace",
    ),
    (
        "parseEnv",
        "NODE_OPTIONS env parsing, owned by the CLI option surface",
    ),
];

/// The `SKIP_SYMBOLS` bit, used as the default when a caller omits the filter.
///
/// `internal/util/inspect.js` always passes one, so this only covers a direct
/// caller. It mirrors the `util.constants` table published above rather than
/// re-deriving the value.
const SKIP_SYMBOLS: u32 = 1 << 4;

/// What `defineLazyProperties` was told to resolve a property from.
///
/// Node's `source` is either an internal module id, where the value is a named
/// export, or an object mapping each property name to its own module id, where
/// the value is that module's whole exports object.
#[derive(Clone)]
enum LazySource {
    /// `defineLazyProperties(target, 'internal/streams/duplex', ['x'])`
    Module(String),
    /// `defineLazyProperties(target, { x: 'internal/streams/duplex' }, ['x'])`
    PerKey(HashMap<String, String>),
}

pub struct Util;

impl BindingModule for Util {
    fn namespace(&self) -> &'static str {
        "util"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        install_predicates(scope, object);
        install_symbols(scope, object)?;

        // `shouldAbortOnUncaughtToggle` is a `Uint8Array(1)` the JavaScript
        // layer writes to signal "abort on uncaught exception" to the native
        // fatal-error path. `internal/process/execution.js` indexes it directly
        // (`shouldAbortOnUncaughtToggle[0] = 1`), so a missing one throws
        // `Cannot set properties of undefined` from inside
        // `setUncaughtExceptionCaptureCallback`.
        let abort_toggle = rn_core::AliasedUint8Array::new(scope, 1, rn_core::Element::Byte)?;
        let abort_array = abort_toggle.array(scope);
        if let Some(key) = v8::String::new(scope, "shouldAbortOnUncaughtToggle") {
            object.set(scope, key.into(), abort_array);
        }

        macro_rules! install {
            ($($name:literal => $callback:expr),* $(,)?) => {
                $(
                    let template = v8::FunctionTemplate::builder($callback).build(scope);
                    if let (Some(key), Some(function)) =
                        (v8::String::new(scope, $name), template.get_function(scope))
                    {
                        object.set(scope, key.into(), function.into());
                    }
                )*
            };
        }

        install! {
            "constructSharedArrayBuffer" => construct_shared_array_buffer,
            "defineLazyProperties" => define_lazy_properties,
            "getConstructorName" => get_constructor_name,
            "getCallSites" => get_call_sites,
            "getCallerLocation" => get_caller_location,
            "getExternalValue" => get_external_value,
            "getOwnNonIndexProperties" => get_own_non_index_properties,
            "getPromiseDetails" => get_promise_details,
            "getProxyDetails" => get_proxy_details,
            "guessHandleType" => guess_handle_type,
            "isInsideNodeModules" => is_inside_node_modules,
            "markPromiseAsHandled" => mark_promise_as_handled,
            "previewEntries" => preview_entries,
            "sleep" => sleep,
        }

        // `constants` is a nested object rather than a function.
        //
        // `internal/util/inspect.js` destructures `ALL_PROPERTIES` and
        // `ONLY_ENUMERABLE` from it to choose a property filter, and
        // `internal/util/types.js` reads the `k*` promise and transfer-mode
        // codes. Leaving the object empty — as this used to — made every one of
        // those `undefined`, so `getOwnNonIndexProperties(value, undefined)`
        // fell back to filter 0 (`ALL_PROPERTIES`) and `util.inspect` printed
        // `[length]` even without `showHidden`.
        let constants = v8::Object::new(scope);
        for (name, value) in UTIL_CONSTANTS {
            let (Some(key), value) = (
                v8::String::new(scope, name),
                v8::Integer::new(scope, *value),
            ) else {
                continue;
            };
            constants.set(scope, key.into(), value.into());
        }
        if let Some(key) = v8::String::new(scope, "constants") {
            object.set(scope, key.into(), constants.into());
        }

        Ok(object)
    }
}

/// `util.constants`, from `src/node_util.cc`'s `Initialize`.
///
/// The property filters are V8's `PropertyFilter` bits, which is why they are
/// powers of two; `kPending` and friends are `v8::Promise::PromiseState`, and the
/// transfer modes are `BaseObject::TransferMode`. Both of the latter are
/// `util.inspect`'s own numbering, so none of these can be renumbered here.
pub const UTIL_CONSTANTS: &[(&str, i32)] = &[
    // `v8::PropertyFilter`.
    ("ALL_PROPERTIES", 0),
    ("ONLY_WRITABLE", 1 << 0),
    ("ONLY_ENUMERABLE", 1 << 1),
    ("ONLY_CONFIGURABLE", 1 << 2),
    ("SKIP_STRINGS", 1 << 3),
    ("SKIP_SYMBOLS", 1 << 4),
    // `v8::Promise::PromiseState`, which `getPromiseDetails` reports.
    ("kPending", 0),
    ("kFulfilled", 1),
    ("kRejected", 2),
    // `BaseObject::TransferMode`, which `util.inspect` reads for a
    // transferred object.
    ("kDisallowCloneAndTransfer", 0),
    ("kTransferable", 1),
    ("kCloneable", 2),
];

/// The predicates `lib/**` reads from this namespace rather than from `types`.
fn install_predicates(scope: &mut v8::PinScope, object: v8::Local<v8::Object>) {
    macro_rules! install {
        ($($name:literal => $test:expr),* $(,)?) => {
            $(
                let template = v8::FunctionTemplate::builder(move |scope: &mut v8::PinScope<'_, '_>, args: v8::FunctionCallbackArguments<'_>, mut rv: v8::ReturnValue| {
                    let test: fn(v8::Local<v8::Value>) -> bool = $test;
                    rv.set(v8::Boolean::new(scope, test(args.get(0))).into());
                })
                .build(scope);
                if let (Some(key), Some(function)) =
                    (v8::String::new(scope, $name), template.get_function(scope))
                {
                    object.set(scope, key.into(), function.into());
                }
            )*
        };
    }

    install! {
        "isAnyArrayBuffer" => |value| value.is_array_buffer() || value.is_shared_array_buffer(),
        "isArrayBuffer" => |value| value.is_array_buffer(),
        "isArrayBufferView" => |value| value.is_array_buffer_view(),
        "isAsyncFunction" => |value| {
            v8::Local::<v8::Function>::try_from(value)
                .map(|function| function.is_async_function())
                .unwrap_or(false)
        },
        "isDataView" => |value| {
            v8::Local::<v8::DataView>::try_from(value).is_ok()
        },
        "isDate" => |value| v8::Local::<v8::Date>::try_from(value).is_ok(),
        "isExternal" => |value| value.is_external(),
        "isMap" => |value| v8::Local::<v8::Map>::try_from(value).is_ok(),
        "isMapIterator" => |value| {
            v8::Local::<v8::Object>::try_from(value)
                .map(|object| object.is_map_iterator())
                .unwrap_or(false)
        },
        "isNativeError" => |value| value.is_native_error(),
        "isPromise" => |value| value.is_promise(),
        "isRegExp" => |value| value.is_reg_exp(),
        "isSet" => |value| v8::Local::<v8::Set>::try_from(value).is_ok(),
        "isSetIterator" => |value| {
            v8::Local::<v8::Object>::try_from(value)
                .map(|object| object.is_set_iterator())
                .unwrap_or(false)
        },
        "isTypedArray" => |value| value.is_typed_array(),
        "isUint8Array" => |value| value.is_uint8_array(),
    }
}

/// Installs `util.privateSymbols`, the table of per-isolate private names
/// `lib/**` destructures.
///
/// Every entry in [`rn_core::PRIVATE_SYMBOLS`] is installed, because a missing
/// one is silent: `const { x } = privateSymbols` leaves `x` as `undefined`, and
/// `object[undefined]` is the string key `"undefined"`, so every missing name
/// shares one property. `lib/internal/modules/cjs/loader.js` caches a module's
/// source under `module[kModuleSource]` and returns it from `loadSource()`, so
/// with that symbol missing a child module read its *parent* `Module` object
/// back as its own source text and `wrapSafe` received an object.
///
/// Identity matters as much as presence: `contextify` marks a sandbox with
/// `contextify_context_private_symbol` and `lib/internal/vm.js` reads it back,
/// and `internal/errors` stores an arrow message the same way. Both come from
/// the shared table in `rn_core`, so the crate that writes a mark and the one
/// that reads it agree on the key.
///
/// The object itself is built by [`rn_core::private_symbols_object`], the same
/// function `run_per_context` gives `internal/per_context/domexception` as its
/// `privateSymbols` argument. Two builders would be two chances to drop an
/// entry, and the copy under `util` is the one `lib/**` destructures. It has a
/// null prototype, as Node's `ObjectTemplate::NewInstance` + `SetPrototype(Null)`
/// produces, so a missing name reads `undefined` rather than something inherited.
fn install_symbols<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<v8::Object>,
) -> Result<(), String> {
    let private = rn_core::private_symbols_object(scope)?;
    let key =
        v8::String::new(scope, "privateSymbols").ok_or("cannot allocate the privateSymbols key")?;
    object.set(scope, key.into(), private.into());
    Ok(())
}

fn construct_shared_array_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(length) = args.get(0).number_value(scope) else {
        return;
    };
    let backing_store = v8::SharedArrayBuffer::new_backing_store(scope, length as usize);
    let backing_store: v8::SharedRef<v8::BackingStore> = backing_store.into();
    let buffer = v8::SharedArrayBuffer::with_backing_store(scope, &backing_store);
    rv.set(buffer.into());
}

/// Defines accessor properties that resolve their value on first read.
///
/// `lib/internal/util.js` uses this to keep error classes and heavy modules out
/// of the startup path while still exposing them as ordinary properties.
/// Defines accessor properties that resolve their value on first read.
///
/// `lib/internal/util.js` uses this to keep error classes and heavy modules out
/// of the startup path while still exposing them as ordinary properties. It is
/// given `(target, name, keys)` or `(target, keys, enumerable)`; only the accessor
/// part is behaviour, the rest is bookkeeping the caller already did.
/// `defineLazyProperties(target, source, keys, enumerable = true)`.
///
/// Node defines, for each key, a lazy data property: the first read calls
/// `require(source)` and replaces the property with the resulting value. Two
/// shapes of `source` exist and both are used by `lib/**`:
///
/// * a module id, where the value is that module's named export;
/// * an object mapping each key to its own module id, where the value is the
///   whole exports object of that module.
///
/// `lib/stream.js` uses both on the same object, so the source is carried per
/// property in the accessor's data slot rather than assumed uniform.
fn define_lazy_properties<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let Ok(target) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "defineLazyProperties needs a target object");
        return;
    };
    let source = args.get(1);
    let Ok(keys) = v8::Local::<v8::Array>::try_from(args.get(2)) else {
        throw_type_error(scope, "defineLazyProperties needs an array of keys");
        return;
    };
    let per_key = match LazySource::read(scope, source) {
        Some(source) => source,
        None => {
            throw_type_error(
                scope,
                "defineLazyProperties source must be a string or an object",
            );
            return;
        }
    };
    // Node's default is enumerable, and only an explicit `false` turns it off.
    let enumerable = args.length() < 4 || args.get(3).is_undefined() || args.get(3).is_true();

    let length = keys.length();
    for index in 0..length {
        let Some(value) = keys.get_index(scope, index) else {
            continue;
        };
        let Ok(name) = v8::Local::<v8::String>::try_from(value) else {
            throw_type_error(scope, "defineLazyProperties keys must be strings");
            return;
        };
        let name_text = name.to_rust_string_lossy(scope);
        // The id and whether the whole module is the value travel with the
        // property, so the getter needs no side table to resolve it.
        let (id, whole_module) = per_key.resolve(&name_text);
        let Some(id) = v8::String::new(scope, &id) else {
            continue;
        };
        let data = lazy_data(scope, id.into(), whole_module);
        // `PropertyAttribute` is not `Copy`, and every key gets the same one.
        let attributes = if enumerable {
            v8::PropertyAttribute::NONE
        } else {
            v8::PropertyAttribute::DONT_ENUM
        };
        target.set_lazy_data_property_with_data(
            scope,
            name.into(),
            lazy_property_getter,
            data,
            attributes,
            v8::SideEffectType::HasSideEffect,
            v8::SideEffectType::HasSideEffect,
        );
    }
}

/// The accessor data slot for one lazy property: `{ id, wholeModule }`.
///
/// This is `info.Data()` in Node's `DefineLazyPropertiesGetter`. V8's callback
/// data slot is statically sized, so this is a two-field plain object rather
/// than any kind of captured closure.
fn lazy_data<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: v8::Local<'s, v8::Value>,
    whole_module: bool,
) -> v8::Local<'s, v8::Value> {
    let data = v8::Object::new(scope);
    let (Some(id_key), Some(whole_key), Some(whole)) = (
        v8::String::new(scope, "id"),
        v8::String::new(scope, "wholeModule"),
        Some(v8::Boolean::new(scope, whole_module)),
    ) else {
        return v8::undefined(scope).into();
    };
    let _ = data.set(scope, id_key.into(), id);
    let _ = data.set(scope, whole_key.into(), whole.into());
    data.into()
}

/// Throws a `TypeError` the way a V8 binding reports a bad argument.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(message) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
    }
}

impl LazySource {
    fn read<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        source: v8::Local<'s, v8::Value>,
    ) -> Option<Self> {
        if let Ok(id) = v8::Local::<v8::String>::try_from(source) {
            return Some(Self::Module(id.to_rust_string_lossy(scope)));
        }
        let object = v8::Local::<v8::Object>::try_from(source).ok()?;
        let names = object.get_own_property_names(scope, Default::default())?;
        let mut per_key = HashMap::new();
        for index in 0..names.length() {
            let key = names.get_index(scope, index)?;
            let value = object.get(scope, key)?;
            let Ok(id) = v8::Local::<v8::String>::try_from(value) else {
                continue;
            };
            per_key.insert(
                key.to_rust_string_lossy(scope),
                id.to_rust_string_lossy(scope),
            );
        }
        Some(Self::PerKey(per_key))
    }

    /// The module id for one property, and whether that module is the value.
    fn resolve(&self, name: &str) -> (String, bool) {
        match self {
            Self::Module(id) => (id.clone(), false),
            Self::PerKey(map) => (map.get(name).cloned().unwrap_or_default(), true),
        }
    }
}

/// Resolves a lazily defined property on first read.
///
/// This is `DefineLazyPropertiesGetter` from `src/node_util.cc`: it calls the
/// realm's `require` with the recorded id and returns either the named export
/// or, for the per-key form, the module itself.
fn lazy_property_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let data = args.data();
    let Some(id) = get_property(scope, data, "id") else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let whole_module = get_property(scope, data, "wholeModule")
        .map(|value| value.boolean_value(scope))
        .unwrap_or(false);
    let Some(require) = rn_core::hook_slot::require(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let Some(module) = require.call(scope, v8::undefined(scope).into(), &[id]) else {
        return;
    };
    if whole_module {
        // The module id form maps a property straight at a module's exports,
        // which is how `stream.js` binds `Duplex` to `internal/streams/duplex`.
        rv.set(module);
        return;
    }
    let Ok(module) = v8::Local::<v8::Object>::try_from(module) else {
        rv.set(module);
        return;
    };
    if let Some(value) = module.get(scope, key.into()) {
        rv.set(value);
    }
}

fn get_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Value>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let object = v8::Local::<v8::Object>::try_from(object).ok()?;
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

fn get_constructor_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    rv.set(object.get_constructor_name().into());
}

/// `GetCallSites`: the `CallSite` records `lib/util.js`'s `getCallSites` returns.
///
/// Each record is a **null-prototype** object with six properties, and both facts
/// are load-bearing:
///
/// * `lib/util.js`'s `mapCallSite` feeds these straight to `reconstructCallSite`,
///   and `test/common`'s `mustNotCall` reads `scriptName` and `lineNumber` off
///   one. A record with an `Object.prototype` would pick up inherited names the
///   consumer does not expect.
/// * The keys are `functionName`, `scriptId`, `scriptName`, `lineNumber`,
///   `columnNumber` and `column` — the last duplicating `columnNumber` because
///   Node's C++ builds them from one `DictionaryTemplate` with both slots.
///   `scriptId` is a *string*, which is what `reconstructCallSite` compares.
///
/// # Why frame 0 is skipped
///
/// V8's stack starts at this native function, which Node's C++ also discards
/// (`// Frame 0 is node:util. It should be skipped.`). The frame above it is
/// `lib/util.js`'s `getCallSites`, and that one *is* reported — callers index
/// into the result expecting their own frame at `[1]`, not `[0]`.
/// `getCallerLocation()`: `[line, column, scriptName]` for the frame that called
/// the binding.
///
/// `internal/test_runner/{harness,test}.js` call it to attribute a `test()`/`it()`
/// call to the file that made it, so a missing member makes every one of those
/// tests throw `getCallerLocation is not a function`.
///
/// Node captures two frames — this binding, then its caller — and returns
/// `undefined` when there are not exactly two, which is the case when the call
/// comes from the top level of a script.
fn get_caller_location(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(stack) = v8::StackTrace::current_stack_trace(scope, 2) else {
        return;
    };
    if stack.get_frame_count() != 2 {
        return;
    }
    let Some(frame) = stack.get_frame(scope, 1) else {
        return;
    };
    let Some(file) = frame.get_script_name_or_source_url(scope) else {
        return;
    };
    let line = i32::try_from(frame.get_line_number()).unwrap_or(-1);
    let column = i32::try_from(frame.get_column()).unwrap_or(-1);
    let result = v8::Array::new(scope, 3);
    result.set_index(scope, 0, v8::Integer::new(scope, line).into());
    result.set_index(scope, 1, v8::Integer::new(scope, column).into());
    result.set_index(scope, 2, file.into());
    rv.set(result.into());
}

fn get_call_sites(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `CHECK(args[0]->IsUint32())` and `CHECK(frames >= 1 && frames <= 200)`:
    // `lib/util.js` validates first, so a bad value here is a caller bug rather
    // than a script error, and clamping keeps it from asking V8 for a huge stack.
    let frames = args.get(0).uint32_value(scope).unwrap_or(10).clamp(1, 200);
    // `+1` for the frame this call itself occupies, exactly as Node does.
    let Some(stack) = v8::StackTrace::current_stack_trace(scope, frames as usize + 1) else {
        let empty = v8::Array::new(scope, 0);
        rv.set(empty.into());
        return;
    };

    let count = stack.get_frame_count();
    let result = v8::Array::new(scope, count.saturating_sub(1) as i32);
    let mut written = 0u32;
    for index in 1..count {
        let Some(frame) = stack.get_frame(scope, index) else {
            continue;
        };
        let Some(record) = call_site_record(scope, &frame) else {
            continue;
        };
        result.set_index(scope, written, record.into());
        written += 1;
    }
    rv.set(result.into());
}

/// Builds one null-prototype `CallSite` record from a stack frame.
fn call_site_record<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    frame: &v8::StackFrame,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    // `NewDictionaryInstanceNullProto`. A dictionary-mode object rather than a
    // literal is what Node builds, and it is what keeps `__proto__` from being a
    // meaningful key on a frame whose function is named that.
    object.set_prototype(scope, v8::null(scope).into());

    let function_name = match frame.get_function_name(scope) {
        Some(name) => name.into(),
        None => v8::String::empty(scope).into(),
    };
    let script_name = match frame.get_script_name(scope) {
        Some(name) => name.into(),
        None => v8::String::empty(scope).into(),
    };
    let script_id = v8::String::new(scope, &frame.get_script_id().to_string())?;
    let line = v8::Integer::new_from_unsigned(scope, frame.get_line_number() as u32);
    let column = v8::Integer::new_from_unsigned(scope, frame.get_column() as u32);

    let values: [(&str, v8::Local<'s, v8::Value>); 6] = [
        ("functionName", function_name),
        ("scriptId", script_id.into()),
        ("scriptName", script_name),
        ("lineNumber", line.into()),
        ("columnNumber", column.into()),
        // `CallSite.column` is deprecated but still present, and duplicates
        // `columnNumber`; `lib/util.js` only reads `columnNumber`.
        ("column", column.into()),
    ];
    for (name, value) in values {
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), value);
    }
    Some(object)
}

fn get_external_value(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(external) = v8::Local::<v8::External>::try_from(args.get(0)) else {
        return;
    };
    // The value is an opaque pointer, exposed as a Number the way Node does,
    // since there is no integer type wide enough in JavaScript.
    let pointer = external.value() as usize;
    rv.set(v8::Number::new(scope, pointer as f64).into());
}

/// `getOwnNonIndexProperties(value, filter)`: the object's own non-index keys.
///
/// `src/node_util.cc` implements it as
/// `GetPropertyNames(context, kOwnOnly, filter, kSkipIndices)`. The filter is the
/// caller's, and it matters: `internal/util/inspect.js` passes `ALL_PROPERTIES`
/// when `showHidden` is set, which is the only way `[length]: 3` reaches an
/// array's output. Enumerating with `Default` — whose `ONLY_ENUMERABLE` skips
/// `length` — silently dropped it, so `util.inspect([1,2,3], true)` printed
/// `[ 1, 2, 3 ]` instead.
///
/// # Why this enumerates with `get_own_property_names`
///
/// `Object::get_property_names` with `KeyCollectionMode::OwnOnly` ignores
/// `IndexFilter::SkipIndices` in this V8 binding: an array reports `["0", "1"]`
/// where Node reports nothing, and a `deepStrictEqual` between two equal arrays
/// then compares an extra key and fails with "same structure but are not
/// reference-equal". `Object::get_own_property_names` returns exactly the key set
/// Node's C++ produces — indices excluded, `length` included when it is
/// non-enumerable, symbols included — so this uses it and applies the caller's
/// string/symbol filter to the result. One V8 API short of Node's C++, and
/// observably identical.
fn get_own_non_index_properties(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        return;
    };
    let filter = args
        .get(1)
        .number_value(scope)
        .unwrap_or(SKIP_SYMBOLS as f64) as u32;

    // The caller's filter, so `ALL_PROPERTIES` keeps `length` for
    // `util.inspect(value, true)`. `get_own_property_names` accepts it directly
    // and, unlike `get_property_names` with `OwnOnly`, does not consult an index
    // filter at all — so indices have to be excluded here.
    let names_args = v8::GetPropertyNamesArgs {
        mode: v8::KeyCollectionMode::OwnOnly,
        property_filter: property_filter(filter),
        index_filter: v8::IndexFilter::SkipIndices,
        key_conversion: v8::KeyConversionMode::ConvertToString,
    };

    let mut names: Vec<v8::Local<'_, v8::Name>> = Vec::new();
    if let Some(properties) = object.get_own_property_names(scope, names_args) {
        let length = properties.length();
        for index in 0..length {
            let Some(entry) = properties.get_index(scope, index) else {
                continue;
            };
            // An array index, which the "NonIndex" in the name excludes.
            if is_array_index(scope, &entry) {
                continue;
            }
            if let Ok(name) = v8::Local::<v8::Name>::try_from(entry) {
                names.push(name);
            }
        }
    }

    let array = v8::Array::new(scope, names.len() as i32);
    for (index, name) in names.into_iter().enumerate() {
        array.set_index(scope, index as u32, name.into());
    }
    rv.set(array.into());
}

/// Whether a property key is a canonical array index (`0` ..= `2^32 - 2`).
///
/// V8's `IndexFilter::kSkipIndices` defines the excluded set as exactly the
/// canonical numeric keys in that range, so a key that parses but does not
/// round-trip (`"01"`, `"-1"`, `"4294967295"`) is an ordinary named property.
fn is_array_index(scope: &mut v8::PinScope<'_, '_>, key: &v8::Local<v8::Value>) -> bool {
    let Some(text) = key.to_string(scope) else {
        return false;
    };
    let text = text.to_rust_string_lossy(scope);
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    // Leading zeros are not canonical, and `u32::MAX` is reserved for `length`.
    if text.len() > 1 && text.starts_with('0') {
        return false;
    }
    text.parse::<u32>()
        .map(|value| value < u32::MAX)
        .unwrap_or(false)
}

/// The `v8::PropertyFilter` bits a caller's numeric filter names.
///
/// `internal/util/inspect.js` passes the values
/// `internalBinding('util').constants` publishes, so the numbers are V8's own
/// `PropertyFilter` enum. The `v8` crate keeps that type's bits private — there
/// is no `from_bits` — so the five known bits are rebuilt here. An unknown bit
/// cannot be expressed and is dropped, which matches V8 ignoring bits it does
/// not define.
fn property_filter(filter: u32) -> v8::PropertyFilter {
    let mut result = v8::PropertyFilter::ALL_PROPERTIES;
    for (bit, value) in [
        (1 << 0, v8::PropertyFilter::ONLY_WRITABLE),
        (1 << 1, v8::PropertyFilter::ONLY_ENUMERABLE),
        (1 << 2, v8::PropertyFilter::ONLY_CONFIGURABLE),
        (1 << 3, v8::PropertyFilter::SKIP_STRINGS),
        (1 << 4, v8::PropertyFilter::SKIP_SYMBOLS),
    ] {
        if filter & bit != 0 {
            result = result | value;
        }
    }
    result
}

/// `previewEntries(value[, checkKeyValue])`: the elements of a `Map`, `Set`,
/// `WeakMap`, `WeakSet` or one of their iterators, for `util.inspect`'s preview.
///
/// `src/util.cc`'s `PreviewEntries` returns the array on its own unless a second
/// argument is given, in which case it returns `[entries, isKeyValue]`. That
/// distinction is observable: `util.inspect` calls the one-argument form for a
/// `Set` and destructures the two-element form `true` for a `Map`, because a
/// `Map`'s preview entries arrive flattened as `[k1, v1, k2, v2, ...]` and it has
/// to know to regroup them.
///
/// `v8::Object::PreviewEntries` supplies both the array and that flag in one call,
/// which is exactly what Node's C++ does.
fn preview_entries(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        return;
    };
    let (entries, is_key_value) = object.preview_entries(scope);
    let Some(entries) = entries else {
        return;
    };
    // One argument: the array itself, as `src/util.cc` does.
    if args.length() == 1 {
        rv.set(entries.into());
        return;
    }
    let result = v8::Array::new(scope, 2);
    result.set_index(scope, 0, entries.into());
    result.set_index(scope, 1, v8::Boolean::new(scope, is_key_value).into());
    rv.set(result.into());
}

/// Returns `[state, value]` for a promise, matching what `util.inspect` reads.
fn get_promise_details(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(promise) = v8::Local::<v8::Promise>::try_from(args.get(0)) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    // 0 pending, 1 resolved, 2 rejected: the numbers Node's inspect switches on.
    let (state, value) = match promise.state() {
        v8::PromiseState::Pending => (0, v8::undefined(scope).into()),
        v8::PromiseState::Fulfilled => (1, promise.result(scope)),
        v8::PromiseState::Rejected => (2, promise.result(scope)),
    };
    let array = v8::Array::new(scope, 2);
    array.set_index(scope, 0, v8::Integer::new(scope, state).into());
    array.set_index(scope, 1, value);
    rv.set(array.into());
}

/// Returns the `[target, handler]` pair for a proxy, or undefined.
fn get_proxy_details(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(0);
    if !value.is_proxy() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    // V8 has no public accessor for a proxy's target and handler, so the pair is
    // read through the revocable-proxy shape Node also relies on. A proxy made by
    // `new Proxy` has none, which is why Node returns `undefined` for those too.
    rv.set(v8::undefined(scope).into());
}

/// `internalBinding('util').guessHandleType`: the libuv handle kind behind a
/// descriptor, as the index `internal/util.js` uses into its `handleTypes`
/// array.
///
/// Returning the name as a string — as this used to — is silently wrong rather
/// than loudly wrong: `guessHandleType` in `lib/internal/util.js` indexes
/// `['TCP', 'TTY', 'UDP', 'FILE', 'PIPE', 'UNKNOWN']` with the value, and
/// `handleTypes["FILE"]` is `undefined`. Every caller then compares
/// `undefined === 'TTY'`, decides stdio is not a terminal *or* a file or pipe,
/// and `createWritableStdioStream` falls through to its black-hole `default`
/// branch. `process.stdout.write` printed nothing and no error said why.
///
/// The numbers are `GetUVHandleTypeCode` in `src/node_util.cc`, which exists
/// precisely so this can stay an integer and skip the string round trip.
fn guess_handle_type(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(fd) = args.get(0).int32_value(scope) else {
        return;
    };
    // `CHECK_GE(fd, 0)` in Node. A negative descriptor cannot name a handle, and
    // `uv_guess_handle` is only defined for a real one.
    if fd < 0 {
        rv.set(v8::Integer::new(scope, HANDLE_TYPE_UNKNOWN).into());
        return;
    }
    // SAFETY: `uv_guess_handle` only inspects the descriptor; it owns no state
    // and cannot fail in a way that invalidates memory.
    let kind = unsafe { uv::uv_guess_handle(fd) };
    rv.set(v8::Integer::new(scope, handle_type_code(kind)).into());
}

/// `UV_UNKNOWN_HANDLE`'s index in `lib/internal/util.js`'s `handleTypes`.
const HANDLE_TYPE_UNKNOWN: i32 = 5;

/// `GetUVHandleTypeCode`, verbatim: the index of `handleTypes`.
fn handle_type_code(kind: uv::uv_handle_type) -> i32 {
    match kind {
        uv::uv_handle_type_UV_TCP => 0,
        uv::uv_handle_type_UV_TTY => 1,
        uv::uv_handle_type_UV_UDP => 2,
        uv::uv_handle_type_UV_FILE => 3,
        uv::uv_handle_type_UV_NAMED_PIPE => 4,
        _ => HANDLE_TYPE_UNKNOWN,
    }
}

fn is_inside_node_modules(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Boolean::new(scope, false).into());
}

fn mark_promise_as_handled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(promise) = v8::Local::<v8::Promise>::try_from(args.get(0)) else {
        return;
    };
    promise.mark_as_handled();
    let _ = scope;
}

/// Blocks the thread, which is what `util.sleep` is for.
fn sleep(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let milliseconds = args.get(0).number_value(scope).unwrap_or(0.0);
    let duration = std::time::Duration::from_millis(milliseconds.max(0.0) as u64);
    std::thread::sleep(duration);
}

impl Default for Util {
    fn default() -> Self {
        Self
    }
}

/// Registers the `util` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Util);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_cover_the_recorded_contract() {
        assert_eq!(MEMBERS.len(), 36);
        for member in ["privateSymbols", "defineLazyProperties", "guessHandleType"] {
            assert!(MEMBERS.contains(&member), "{member} missing");
        }
    }

    #[test]
    fn every_deferral_names_a_real_member() {
        for (member, reason) in DEFERRED {
            assert!(
                MEMBERS.contains(member),
                "{member} is deferred but not required"
            );
            assert!(!reason.is_empty(), "{member} has no reason");
        }
    }

    #[test]
    fn installed_and_deferred_together_cover_the_contract() {
        let installed = MEMBERS
            .iter()
            .filter(|member| !DEFERRED.iter().any(|(deferred, _)| deferred == *member))
            .count();
        assert_eq!(installed + DEFERRED.len(), MEMBERS.len());
    }
}
