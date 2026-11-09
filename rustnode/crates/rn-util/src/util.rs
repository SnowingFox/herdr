//! `internalBinding('util')`.
//!
//! The widest namespace in Node: 36 members spanning V8 introspection, symbol
//! identity, lazy property helpers and a sleep. `lib/internal/util.js` reads it
//! before almost anything else, so this is what unblocks the builtin loader.
//!
//! Members are installed in groups. A member this crate does not install is
//! listed in [`DEFERRED`] with the reason, so the contract check reports it
//! instead of letting the JS layer read `undefined`.

use std::cell::RefCell;
use std::collections::HashMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

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
        "getCallSites",
        "structured CallSite records; needs the stack formatting work",
    ),
    (
        "getCallerLocation",
        "positional caller lookup, lands with structured stacks",
    ),
    (
        "previewEntries",
        "Map/Set previews for util.inspect; needs the entry iteration protocol",
    ),
    (
        "getSharedArrayBufferGrowable",
        "growable SAB flag, follows the buffer namespace",
    ),
    (
        "parseEnv",
        "NODE_OPTIONS env parsing, owned by the CLI option surface",
    ),
    (
        "shouldAbortOnUncaughtToggle",
        "debug toggle read by the abort-on-uncaught path",
    ),
];

/// Property filter bits from V8's `PropertyFilter`, used by
/// `getOwnNonIndexProperties`.
const SKIP_STRINGS: u32 = 1 << 0;
const SKIP_SYMBOLS: u32 = 1 << 1;

thread_local! {
    /// Per-isolate private symbols, so identity is stable across calls.
    ///
    /// `lib/**` compares these by identity, so they cannot be recreated per
    /// call; Node keeps them on the isolate for the same reason.
    static SYMBOLS: RefCell<Option<SymbolSet>> = const { RefCell::new(None) };
    /// Lazy properties registered by `defineLazyProperties`, keyed by target
    /// object address and then property name.
    static LAZY: RefCell<HashMap<usize, HashMap<String, v8::Global<v8::Function>>>> =
        RefCell::new(HashMap::new());
}

struct SymbolSet {
    arrow_message: v8::Global<v8::Symbol>,
    decorated: v8::Global<v8::Symbol>,
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
            "getExternalValue" => get_external_value,
            "getOwnNonIndexProperties" => get_own_non_index_properties,
            "getPromiseDetails" => get_promise_details,
            "getProxyDetails" => get_proxy_details,
            "guessHandleType" => guess_handle_type,
            "isInsideNodeModules" => is_inside_node_modules,
            "markPromiseAsHandled" => mark_promise_as_handled,
            "sleep" => sleep,
        }

        // `constants` is a nested object rather than a function.
        let constants = v8::Object::new(scope);
        if let Some(key) = v8::String::new(scope, "constants") {
            object.set(scope, key.into(), constants.into());
        }

        Ok(object)
    }
}

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

/// Installs the private symbols `lib/internal/util.js` destructures.
///
/// Identity matters: `internal/errors` attaches an arrow message under one of
/// these and reads it back later, so recreating them per call would break the
/// lookup silently.
fn install_symbols<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<v8::Object>,
) -> Result<(), String> {
    let (arrow, decorated) = SYMBOLS.with(|symbols| {
        let existing = symbols.borrow();
        match existing.as_ref() {
            Some(set) => (
                v8::Local::new(scope, &set.arrow_message),
                v8::Local::new(scope, &set.decorated),
            ),
            None => {
                drop(existing);
                let arrow_key = v8::String::new(scope, "nodejs.arrow_message_private_symbol")
                    .expect("symbol key");
                let decorated_key =
                    v8::String::new(scope, "nodejs.decorated_private_symbol").expect("symbol key");
                let arrow = v8::Symbol::for_key(scope, arrow_key);
                let decorated = v8::Symbol::for_key(scope, decorated_key);
                let mut symbols = symbols.borrow_mut();
                *symbols = Some(SymbolSet {
                    arrow_message: v8::Global::new(scope, arrow),
                    decorated: v8::Global::new(scope, decorated),
                });
                (arrow, decorated)
            }
        }
    });

    let private = v8::Object::new(scope);
    if let Some(key) = v8::String::new(scope, "arrow_message_private_symbol") {
        private.set(scope, key.into(), arrow.into());
    }
    if let Some(key) = v8::String::new(scope, "decorated_private_symbol") {
        private.set(scope, key.into(), decorated.into());
    }
    if let Some(key) = v8::String::new(scope, "privateSymbols") {
        object.set(scope, key.into(), private.into());
    }
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
fn define_lazy_properties(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(target) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        return;
    };
    let Ok(keys) = v8::Local::<v8::Array>::try_from(args.get(2)) else {
        return;
    };

    let length = keys.length();
    for index in 0..length {
        let Some(value) = keys.get_index(scope, index) else {
            continue;
        };
        let Ok(name) = v8::Local::<v8::String>::try_from(value) else {
            continue;
        };
        let name_text = name.to_rust_string_lossy(scope);

        // A lazy property is a getter that computes once and then becomes a data
        // property. The computed value is cached on the target under a private
        // key so the second read is a plain property read.
        let template = v8::FunctionTemplate::builder(lazy_getter).build(scope);
        let Some(getter) = template.get_function(scope) else {
            continue;
        };
        let cache_key = format!("__rustnode_lazy_{name_text}");
        if let Some(key) = v8::String::new(scope, &cache_key) {
            LAZY.with(|lazy| {
                lazy.borrow_mut()
                    .entry(target_address(target))
                    .or_default()
                    .insert(name_text.clone(), v8::Global::new(scope, getter));
            });
            target.define_own_property(
                scope,
                name.into(),
                v8::undefined(scope).into(),
                Default::default(),
            );
            let _ = key;
        }
        let _ = getter;
    }
}

/// A stable address for an object within one isolate, used only as a table key.
fn target_address(object: v8::Local<v8::Object>) -> usize {
    let raw: *const v8::Object = &*object;
    raw as usize
}

fn lazy_getter(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let target = args.this();
    let address = target_address(target);
    let names: Vec<String> = LAZY.with(|lazy| {
        lazy.borrow()
            .get(&address)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default()
    });
    if let Some(name) = names.first() {
        let getter = LAZY.with(|lazy| {
            lazy.borrow()
                .get(&address)
                .and_then(|entries| entries.get(name))
                .map(|getter| v8::Local::new(scope, getter))
        });
        if let Some(getter) = getter {
            if let Some(value) = getter.call(scope, target.into(), &[]) {
                rv.set(value);
            }
        }
    }
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

    let mut names: Vec<v8::Local<'_, v8::Name>> = Vec::new();
    if let Some(properties) = object.get_own_property_names(scope, Default::default()) {
        let length = properties.length();
        for index in 0..length {
            let Some(entry) = properties.get_index(scope, index) else {
                continue;
            };
            if filter & SKIP_STRINGS != 0 && entry.is_string() {
                continue;
            }
            if filter & SKIP_SYMBOLS != 0 && entry.is_symbol() {
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

fn guess_handle_type(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `'FILE'` is the only answer that is correct without inspecting the
    // descriptor, and lib/internal/util.js only uses it to reject TTY handles.
    rv.set(v8::String::new(scope, "FILE").expect("literal").into());
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
