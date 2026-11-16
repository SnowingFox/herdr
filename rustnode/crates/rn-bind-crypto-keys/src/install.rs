//! Installing the key classes onto the `crypto` namespace object.
//!
//! This crate does not own a namespace: `src/crypto/crypto_keys.cc` is one
//! translation unit among the dozen `src/node_crypto.cc` aggregates onto one
//! `target`, and the crate split follows the translation unit, not the
//! namespace. So the export is [`install_classes`] and `rn-bind-crypto` calls it
//! from its own `install`.
//!
//! The name matters: `tools/regen-bindings.sh` discovers namespace providers by
//! grepping each crate's source for a `register` function declaration, so a
//! helper named `register_something` here would be treated as a namespace
//! provider and the build would fail on a symbol that crate does not export.
//! Slice 1 hit exactly this. The grep is a plain substring match, which is why
//! this comment does not spell the pattern out either.
//!
//! # The class protocol
//!
//! `createNativeKeyObjectClass(build)` builds the `NativeKeyObject` base class,
//! hands it to `build`, and remembers the four classes `build` returns —
//! `[KeyObject, SecretKeyObject, PublicKeyObject, PrivateKeyObject]`. That is why
//! this file keeps state: the binding constructs concrete keys later, from outside
//! the JavaScript closure, and needs those constructors then.
//!
//! # The brand
//!
//! `isKeyObject` must not be fooled by an object whose prototype was set to
//! `KeyObject.prototype`, and `test-crypto-keyobject-brand-check.js` also replaces
//! `KeyObject[Symbol.hasInstance]` and asserts the native answer is unchanged. The
//! distinguishing fact is therefore native state — the internal field holding the
//! key — which a script cannot create or write.
//!
//! `test-crypto-keyobject-no-own-symbols.js` asserts `Reflect.ownKeys(key)` is
//! empty, so the state cannot live in a private Symbol property either. One
//! internal field is the only place it can go.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::errors::{throw, KeyError};
use crate::state::KeyData;
use crate::templates::{self, set_key_data, with_key_data, INTERNAL_FIELD_COUNT};

/// The members this crate installs, for the parent crate's `MEMBERS` list.
///
/// Eleven names: the handle class, the three `KeyObject` class-protocol
/// functions, the three `NativeCryptoKey` ones, and the four key-generation jobs.
pub const MEMBERS: &[&str] = &[
    "KeyObjectHandle",
    "SecretKeyGenJob",
    "RsaKeyPairGenJob",
    "EcKeyPairGenJob",
    "NamedKeyPairGenJob",
    "createNativeKeyObjectClass",
    "getKeyObjectSlots",
    "isKeyObject",
    "createCryptoKeyClass",
    "getCryptoKeySlots",
    "isCryptoKey",
    "isKeyAlgorithmAvailable",
];

thread_local! {
    /// The `KeyObject` constructors `keys.js` built during load.
    ///
    /// A `thread_local` because a native keygen job runs inside a V8 callback with
    /// no path back to the binding, and one isolate per process makes the thread
    /// the isolate. `rn-bind-async-wrap` and `rn-uv` keep theirs the same way.
    static CLASSES: RefCell<Classes> = const { RefCell::new(Classes::new()) };
}

/// The constructors the callback protocol returns.
struct Classes {
    /// The `NativeKeyObject` template, kept so a second call reuses it. Two
    /// templates would make `instanceof` disagree between keys built at different
    /// times, which is why Node keeps it on the `Environment`.
    base: Option<v8::Global<v8::FunctionTemplate>>,
    key_object: Option<v8::Global<v8::Function>>,
    secret: Option<v8::Global<v8::Function>>,
    public: Option<v8::Global<v8::Function>>,
    private: Option<v8::Global<v8::Function>>,
    /// The `KeyObjectHandle` constructor, cached for the same reason.
    handle: Option<v8::Global<v8::Function>>,
}

impl Classes {
    const fn new() -> Self {
        Self {
            base: None,
            key_object: None,
            secret: None,
            public: None,
            private: None,
            handle: None,
        }
    }
}

fn with_classes<R>(body: impl FnOnce(&mut Classes) -> R) -> R {
    CLASSES.with(|slot| body(&mut slot.borrow_mut()))
}

/// Installs the key classes onto `target`, which is the `crypto` namespace.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // The handle class is built once and cached, because `keys.js` checks
    // `handle instanceof KeyObjectHandle` in `KeyObject`'s constructor, and a
    // fresh template per instance would fail that check.
    let handle = handle_constructor(scope)
        .ok_or_else(|| "cannot build the KeyObjectHandle class".to_string())?;
    // `crypto_keys.cc` sets this with a plain `target->Set(..., FIXED_ONE_BYTE_STRING(
    // "KeyObjectHandle"), KeyObjectHandle::Initialize(env))` rather than through
    // `SetConstructorFunction`, so the class has **no** name on Node —
    // `binding.KeyObjectHandle.name` is `""`. Setting one here would be a
    // divergence in the opposite direction, so the constructor keeps the empty
    // name its template arrives with.
    set(scope, target, "KeyObjectHandle", handle.into())?;

    for (name, built) in [
        (
            "createNativeKeyObjectClass",
            rn_core::method(create_native_key_object_class).build(scope),
        ),
        (
            "getKeyObjectSlots",
            rn_core::method(get_key_object_slots).build(scope),
        ),
        ("isKeyObject", rn_core::method(is_key_object).build(scope)),
        // `crypto_keys.cc` publishes all three through `SetMethod` /
        // `SetMethodNoSideEffect`, so none of them has a `[[Construct]]` and
        // `new binding.isCryptoKey({})` is a `TypeError` on Node. `method` is
        // that behaviour; `FunctionTemplate::builder` would silently accept
        // `new`, and `tools/constructible-audit.py` fails on the difference.
        (
            "createCryptoKeyClass",
            rn_core::method(crate::cryptokey::create_crypto_key_class).build(scope),
        ),
        (
            "getCryptoKeySlots",
            rn_core::method(crate::cryptokey::get_crypto_key_slots).build(scope),
        ),
        (
            "isCryptoKey",
            rn_core::method(crate::cryptokey::is_crypto_key).build(scope),
        ),
        (
            "isKeyAlgorithmAvailable",
            rn_core::method(is_key_algorithm_available).build(scope),
        ),
    ] {
        let function = built
            .get_function(scope)
            .ok_or_else(|| format!("cannot allocate crypto.{name}"))?;
        // `SetMethod` names the function after the property, which is observable
        // as `f.name`; the bare template builder leaves it `""`.
        if let Some(key) = v8::String::new(scope, name) {
            function.set_name(key);
        }
        set(scope, target, name, function.into())?;
    }

    crate::jobs::install_classes(scope, target)?;
    crate::dhbits::install_classes(scope, target)?;
    Ok(())
}

/// The `KeyObjectHandle` constructor, cached.
pub(crate) fn handle_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    if let Some(constructor) = with_classes(|classes| classes.handle.clone()) {
        return Some(v8::Local::new(scope, &constructor));
    }
    let template = rn_core::class(crate::handle::constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let prototype = template.prototype_template(scope);
    crate::handle::install_methods(scope, prototype)?;
    // No class name and no `set_name`: `crypto_keys.cc` exposes this through a
    // plain `target->Set`, not `SetConstructorFunction`, so Node's
    // `binding.KeyObjectHandle.name` is `""`. Its methods still get named,
    // because `SetProtoMethod` does name those — that happens in
    // `handle::install_methods`, which puts them in the prototype template.
    let function = template.get_function(scope)?;
    with_classes(|classes| classes.handle = Some(v8::Global::new(scope.as_ref(), function)));
    Some(function)
}

/// Creates a `KeyObjectHandle` over `data`, which is `KeyObjectHandle::Create`.
pub(crate) fn create_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    data: KeyData,
) -> Option<v8::Local<'s, v8::Object>> {
    let constructor = handle_constructor(scope)?;
    let object = constructor.new_instance(scope, &[])?;
    set_key_data(scope, object, data);
    Some(object)
}

/// `new NativeKeyObject(handle)`: copies the handle's key into the new object.
///
/// Node's `NativeKeyObject::New` *copies* the `KeyObjectData` out of the handle
/// rather than pointing at it. That is cheap because the data is reference
/// counted, and it means the `KeyObject` outlives the handle it was built from.
fn native_key_object_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Ok(handle) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw(scope, &KeyError::InvalidThis("KeyObjectHandle"));
        return;
    };
    let Some(data) = with_key_data(scope, handle, KeyData::clone) else {
        throw(scope, &KeyError::InvalidThis("KeyObjectHandle"));
        return;
    };
    set_key_data(scope, this, data);
    rv.set(this.into());
}

/// `createNativeKeyObjectClass(build)`.
fn create_native_key_object_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw(scope, &KeyError::InvalidThis("createNativeKeyObjectClass"));
        return;
    };
    let template = match with_classes(|classes| classes.base.clone()) {
        Some(template) => v8::Local::new(scope, &template),
        None => {
            let template = rn_core::class(native_key_object_constructor).build(scope);
            template
                .instance_template(scope)
                .set_internal_field_count(INTERNAL_FIELD_COUNT);
            if let Some(name) = v8::String::new(scope, "NativeKeyObject") {
                template.set_class_name(name);
            }
            with_classes(|classes| {
                classes.base = Some(v8::Global::new(scope.as_ref(), template));
            });
            template
        }
    };
    let Some(base) = template.get_function(scope) else {
        return;
    };

    // `keys.js`'s callback receives the base and returns the four classes. A
    // thrown exception is left pending rather than replaced: it carries the real
    // reason `keys.js` could not build its classes.
    let receiver = v8::undefined(scope).into();
    let Some(result) = callback.call(scope, receiver, &[base.into()]) else {
        return;
    };
    let Ok(array) = v8::Local::<v8::Array>::try_from(result) else {
        throw(scope, &KeyError::InvalidThis("createNativeKeyObjectClass"));
        return;
    };

    // Slot 0 is `KeyObject` and 1..=3 the concrete subclasses; every one is
    // needed because the binding constructs keys natively and the concrete class
    // is what decides `instanceof SecretKeyObject` in `keys.js`.
    for (index, slot) in [
        (0u32, Slot::KeyObject),
        (1, Slot::Secret),
        (2, Slot::Public),
        (3, Slot::Private),
    ] {
        // A slot the callback did not fill is skipped rather than rejected.
        // Node stores whatever the callback returned and fails later, at the point
        // a missing constructor is needed; throwing here would reject a callback
        // that returned a short array on purpose, which the binding's own test
        // does to exercise just the base class.
        let Some(value) = array.get_index(scope, index) else {
            return;
        };
        let Ok(constructor) = v8::Local::<v8::Function>::try_from(value) else {
            continue;
        };
        let global = v8::Global::new(scope.as_ref(), constructor);
        with_classes(|classes| match slot {
            Slot::KeyObject => classes.key_object = Some(global),
            Slot::Secret => classes.secret = Some(global),
            Slot::Public => classes.public = Some(global),
            Slot::Private => classes.private = Some(global),
        });
    }
    rv.set(result);
}

/// Which constructor a slot of the callback's array holds.
#[derive(Clone, Copy)]
enum Slot {
    KeyObject,
    Secret,
    Public,
    Private,
}

/// `isKeyObject(value)`.
fn is_key_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let is_key = templates::is_native_key_object(scope, args.get(0));
    rv.set(v8::Boolean::new(scope, is_key).into());
}

/// `isKeyAlgorithmAvailable(name)`, which `webcrypto` uses to reject an algorithm
/// this build's provider does not have.
fn is_key_algorithm_available<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let available = args
        .get(0)
        .to_string(scope)
        .map(|name| name.to_rust_string_lossy(scope))
        .and_then(|name| rn_crypto_openssl::KeyAlgorithm::from_name(&name))
        .is_some_and(rn_crypto_openssl::KeyAlgorithm::is_available);
    rv.set(v8::Boolean::new(scope, available).into());
}

/// `getKeyObjectSlots(key)` returns `[type, handle]`.
///
/// One call fills both slots `keys.js` caches, because the tuple is read on
/// almost every crypto operation and a second native round trip per read would be
/// per-operation overhead.
fn get_key_object_slots<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(key) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw(scope, &KeyError::InvalidThis("KeyObject"));
        return;
    };
    let Some(data) = with_key_data(scope, key, KeyData::clone) else {
        throw(scope, &KeyError::InvalidThis("KeyObject"));
        return;
    };
    let Some(handle) = create_handle(scope, data.clone()) else {
        throw(
            scope,
            &KeyError::OperationFailed("cannot create the KeyObjectHandle"),
        );
        return;
    };
    let key_type = v8::Integer::new(scope, data.key_type().as_raw());
    rv.set(v8::Array::new_with_elements(scope, &[key_type.into(), handle.into()]).into());
}

/// Builds a real `Buffer` over a copy of `bytes`.
///
/// `Buffer.from(arrayBuffer, 0, length)`, resolved off the global `Buffer` the
/// runtime installed, rather than `new Buffer(...)`: the constructor form is
/// deprecated and its warning reaches stderr, which several tests capture.
pub fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let buffer = buffer_constructor(scope)?;
    let from_key = v8::String::new(scope, "from")?;
    let from = buffer.get(scope, from_key.into())?;
    let from = v8::Local::<v8::Function>::try_from(from).ok()?;
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, bytes.len() as i32);
    let called = from.call(
        scope,
        buffer.into(),
        &[array_buffer.into(), start.into(), length.into()],
    )?;
    called.is_object().then_some(called)
}

/// The global `Buffer` constructor object.
///
/// An `Object` rather than a `Function`: the real `Buffer` is callable, but
/// nothing here calls it — only `Buffer.from` — and requiring a callable would
/// reject a usable `Buffer` shape.
fn buffer_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    object.set(scope, key.into(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_is_the_class_protocol_plus_the_jobs() {
        // These twelve are what `keys.js`, `keygen.js` and `webcrypto` destructure,
        // and `rn-bind-crypto` moves exactly these from `DEFERRED` to `MEMBERS`.
        //
        // The three `NativeCryptoKey` members were added with the `isCryptoKey`
        // brand: `keys.js` destructures `createCryptoKeyClass` at module scope
        // and calls `getCryptoKeySlots`/`isCryptoKey` from the `CryptoKey`
        // getters, so all three have to exist or `util.types.isCryptoKey` throws
        // "isNativeCryptoKey is not a function".
        assert_eq!(MEMBERS.len(), 12);
        for name in [
            "KeyObjectHandle",
            "createNativeKeyObjectClass",
            "getKeyObjectSlots",
            "isKeyObject",
            "isKeyAlgorithmAvailable",
            "createCryptoKeyClass",
            "getCryptoKeySlots",
            "isCryptoKey",
        ] {
            assert!(MEMBERS.contains(&name), "{name}");
        }
        for name in [
            "SecretKeyGenJob",
            "RsaKeyPairGenJob",
            "EcKeyPairGenJob",
            "NamedKeyPairGenJob",
        ] {
            assert!(MEMBERS.contains(&name), "{name}");
        }
    }

    #[test]
    fn no_member_is_named_twice() {
        let mut sorted = MEMBERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), MEMBERS.len());
    }
}
