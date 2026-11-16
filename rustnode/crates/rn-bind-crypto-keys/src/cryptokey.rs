//! The `NativeCryptoKey` base class and the `isCryptoKey` brand check.
//!
//! `src/crypto/crypto_keys.cc` installs three members here — `createCryptoKeyClass`,
//! `getCryptoKeySlots` and `isCryptoKey` — and `lib/internal/crypto/keys.js` runs
//! the first at module scope to build the `CryptoKey` hierarchy:
//!
//! ```js
//! const { 0: CryptoKey, 1: InternalCryptoKey } = createCryptoKeyClass((NativeCryptoKey) => {
//!   class CryptoKey { … }
//!   class InternalCryptoKey extends NativeCryptoKey { … }
//!   return [CryptoKey, InternalCryptoKey];
//! });
//! ```
//!
//! # What `NativeCryptoKey` has to be
//!
//! Node creates a `FunctionTemplate` once, stores it on the `Environment`, and
//! hands the *constructor function* to the callback. `InternalCryptoKey` extends
//! it, so `super(handle, algorithm, usagesMask, extractable, secondaryHandle,
//! seedData)` reaches `NativeCryptoKey::New`, which copies the `KeyObjectData`
//! out of the handle and keeps the algorithm/usages/extractable slots natively.
//!
//! # The brand
//!
//! `isCryptoKey` is `NativeCryptoKey::HasInstance`, which is
//! `env->crypto_cryptokey_constructor_template()->HasInstance(value)`. It is a
//! *template* brand, not a prototype check, so an object can neither reach it by
//! `Object.create(CryptoKey.prototype)` nor fake it by writing properties. Two
//! consequences follow, and both are load-bearing:
//!
//! * A `KeyObject` reports **false**. `createSecretKey()` and `generateKeyPairSync`
//!   return `KeyObject`s, which are a different class with a different template.
//!   `util.types.isKeyObject` is the accessor for those. The oracle confirms this
//!   (`{ kKeyType: isCryptoKey(createSecretKey(...)) }` is `false`), and
//!   `keys.js` relies on it: `getCryptoKeyType` and friends start with
//!   `if (!isCryptoKey(key)) throw new ERR_INVALID_THIS('CryptoKey')`.
//! * A genuine `CryptoKey` from `subtle.importKey`, `subtle.generateKey` or
//!   `subtle.wrapKey` reports **true**, because those paths construct
//!   `InternalCryptoKey`, which inherits the template.
//!
//! # Why a private symbol rather than a prototype walk
//!
//! V8 exposes `HasInstance` only on `v8::FunctionTemplate`, and the `v8` crate
//! this build links does not bind it. Walking the prototype chain instead would
//! make `Object.create(CryptoKey.prototype)` report `true`, which is exactly the
//! impostor the brand has to reject. So the base constructor writes a V8
//! `Private` symbol — invisible to `Reflect.ownKeys` and to `for…in`, and
//! impossible to forge from script because the key never leaves this module —
//! and `isCryptoKey` tests for it. That is a stronger check than the prototype
//! walk and strictly narrower than the template: only an instance the base
//! constructor actually ran on carries it.

use std::cell::RefCell;

use rn_v8_sys::v8;

/// The `Private` symbol the base constructor brands each instance with.
///
/// `Private::for_api` interns by name within the isolate, so every call returns
/// the same symbol and a second `createCryptoKeyClass` agrees with the first.
/// The name is qualified the way V8's own documentation recommends, so it cannot
/// collide with another embedder's private symbol.
const BRAND_NAME: &str = "herdr:NativeCryptoKey";

thread_local! {
    /// The `NativeCryptoKey` template, kept so a second call reuses it.
    ///
    /// Node stores this on the `Environment` for the same reason: two templates
    /// would make `instanceof` disagree between keys built at different times,
    /// and `keys.js` checks `key instanceof NativeCryptoKey` in `InternalCryptoKey`'s
    /// constructor path.
    static TEMPLATE: RefCell<Option<v8::Global<v8::FunctionTemplate>>> =
        const { RefCell::new(None) };
}

/// `createCryptoKeyClass(callback)`.
///
/// Builds (or reuses) the `NativeCryptoKey` template, hands its constructor to
/// `callback`, and returns whatever the callback returned — the array
/// `keys.js` destructures into `[CryptoKey, InternalCryptoKey]`.
pub fn create_crypto_key_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw_type_error(scope, "createCryptoKeyClass needs a callback");
        return;
    };

    let template = match TEMPLATE.with(|slot| slot.borrow().clone()) {
        Some(template) => v8::Local::new(scope, &template),
        None => {
            // `NativeCryptoKey` is a real class: `keys.js`'s `InternalCryptoKey
            // extends NativeCryptoKey` and calls `super(...)`, so its template
            // must stay constructible. Node builds it with
            // `NewFunctionTemplate(isolate, NativeCryptoKey::New)`, which
            // defaults to `kAllow`. `class` says so at the call site; every
            // publication of the three *members* in `install.rs` is `method`.
            let template = rn_core::class(native_crypto_key_constructor).build(scope);
            // The instance holds the key data (`KEY_DATA_FIELD`,
            // `KEY_PRESENT_FIELD`) plus the WebCrypto slot array, so the count is
            // one past the slot field. Reserving too few makes V8 silently drop
            // the write, and the brand then never lands.
            template
                .instance_template(scope)
                .set_internal_field_count(CRYPTO_KEY_INTERNAL_FIELD_COUNT);
            if let Some(name) = v8::String::new(scope, "NativeCryptoKey") {
                template.set_class_name(name);
            }
            TEMPLATE.with(|slot| {
                *slot.borrow_mut() = Some(v8::Global::new(scope.as_ref(), template));
            });
            template
        }
    };

    let Some(constructor) = template.get_function(scope) else {
        throw_type_error(scope, "cannot allocate NativeCryptoKey");
        return;
    };
    // A thrown exception inside the callback is left pending rather than
    // replaced: it carries the real reason `keys.js` could not build its classes.
    let receiver = v8::undefined(scope).into();
    let Some(result) = callback.call(scope, receiver, &[constructor.into()]) else {
        return;
    };
    rv.set(result);
}

/// `new NativeCryptoKey(handle, algorithm, usagesMask, extractable[,
/// secondaryHandle[, seedData]])`.
///
/// Node's `NativeCryptoKey::New` keeps the handle's `KeyObjectData` plus the
/// WebCrypto slots. This build keeps only the slot array: `keys.js` reads key
/// material back through `getCryptoKeyHandle`, so the data itself is reached
/// through the handle in slot 4, and storing a second copy here would make this
/// object answer `isKeyObject` (see the comment in the body). What this
/// function must do is brand the instance, because `isCryptoKey` is the only
/// thing that separates a real `CryptoKey` from a `KeyObject`.
fn native_crypto_key_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();

    // Node `CHECK`s that args[0] is a `KeyObjectHandle`. Throwing instead keeps
    // the misuse catchable rather than aborting the process; the class is not
    // reachable from user script, so only a broken `keys.js` gets here.
    let Some(handle) = v8::Local::<v8::Object>::try_from(args.get(0)).ok() else {
        throw_type_error(scope, "NativeCryptoKey needs a KeyObjectHandle");
        return;
    };
    if crate::templates::with_key_data(scope, handle, |_| ()).is_none() {
        throw_type_error(scope, "NativeCryptoKey needs a KeyObjectHandle");
        return;
    }

    // The key data is deliberately **not** copied onto this object.
    //
    // `isKeyObject` in Node is `NativeKeyObject`'s template brand, and this
    // crate approximates it with "carries key data" (see
    // `templates::is_native_key_object`). Copying the handle's `KeyObjectData`
    // here would therefore make `isKeyObject(cryptoKey)` true, while Node keeps
    // the two classes on separate templates and answers false. `keys.js` reads
    // key material back through `getCryptoKeyHandle(key)`, which takes the
    // handle out of the slot array below, so nothing needs the data here.
    //
    // The slots are what `getCryptoKeySlots` returns, in `keys.js`'s order
    // (`kSlotType` 0 … `kSlotSeedData` 6): the handle's key type, `extractable`,
    // the algorithm, the usages mask, the handle, then the optional
    // secondary handle and seed data.
    let key_type = crate::templates::with_key_data(scope, handle, |data| data.key_type().as_raw())
        .unwrap_or_default();
    let key_type = v8::Integer::new(scope, key_type);
    let slots = v8::Array::new(scope, 7);
    let slot_values = [
        key_type.into(),
        args.get(3), // extractable
        args.get(1), // algorithm
        args.get(2), // usages mask
        handle.into(),
        args.get(4), // secondary handle
        args.get(5), // seed data
    ];
    for (index, value) in slot_values.into_iter().enumerate() {
        slots.set_index(scope, index as u32, value);
    }
    this.set_internal_field(CRYPTO_KEY_SLOTS_FIELD, slots.into());

    brand(scope, this);
    rv.set(this.into());
}

/// The internal field the WebCrypto slots array occupies.
///
/// A `NativeCryptoKey` is **not** a `KeyObject`: it stores the slot array and
/// nothing else, so this starts at 0 rather than past the key-data fields. That
/// separation is load-bearing, not tidiness — `isKeyObject` here answers "does
/// this object carry key data", so a CryptoKey that stored key data would be
/// reported as a KeyObject while Node reports false.
const CRYPTO_KEY_SLOTS_FIELD: usize = 0;

/// The internal field count `NativeCryptoKey` reserves.
pub const CRYPTO_KEY_INTERNAL_FIELD_COUNT: usize = CRYPTO_KEY_SLOTS_FIELD + 1;

/// Marks `object` as a `NativeCryptoKey` instance.
fn brand(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
    let Some(name) = v8::String::new(scope, BRAND_NAME) else {
        return;
    };
    let key = v8::Private::for_api(scope, Some(name));
    let marker = v8::Boolean::new(scope, true);
    object.set_private(scope, key, marker.into());
}

/// Whether `value` was constructed by the `NativeCryptoKey` constructor.
///
/// Never throws and never panics on a non-object: a primitive, `null`,
/// `undefined` and a plain object all answer `false`, which is what
/// `util.types.isCryptoKey` promises.
pub fn is_native_crypto_key(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> bool {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return false;
    };
    let Some(name) = v8::String::new(scope, BRAND_NAME) else {
        return false;
    };
    let key = v8::Private::for_api(scope, Some(name));
    matches!(object.has_private(scope, key), Some(true))
}

/// `isCryptoKey(value)`.
pub fn is_crypto_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let branded = is_native_crypto_key(scope, args.get(0));
    rv.set(v8::Boolean::new(scope, branded).into());
}

/// `getCryptoKeySlots(key)`: the slot array `keys.js` caches per instance.
///
/// Returns the array the constructor stored, or throws for an object that was
/// not built by this class. Node validates the receiver with
/// `NativeCryptoKey::HasInstance` and throws `ERR_INVALID_THIS` on failure.
///
/// The brand is checked **first**, not the internal field count: a `KeyObject`
/// also has a field at index 0 (its key pointer), so a count check alone would
/// read an aligned-pointer field and hand `keys.js` something that is not a
/// slot array.
pub fn get_crypto_key_slots<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    if !is_native_crypto_key(scope, args.get(0)) {
        throw_type_error(scope, "getCryptoKeySlots needs a CryptoKey");
        return;
    }
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "getCryptoKeySlots needs a CryptoKey");
        return;
    };
    // The brand has already proved this object came from this constructor, and
    // an internal field past its count reads as `None` rather than out of
    // bounds, so the `get_internal_field` below is the whole check. A redundant
    // `internal_field_count() <= CRYPTO_KEY_SLOTS_FIELD` guard would also be
    // vacuous now that the slot field is index 0 — clippy rejects it as an
    // absurd comparison, and correctly so.
    let Some(slots) = object.get_internal_field(scope, CRYPTO_KEY_SLOTS_FIELD) else {
        throw_type_error(scope, "getCryptoKeySlots needs a CryptoKey");
        return;
    };
    let Some(slots) = v8::Local::<v8::Value>::try_from(slots).ok() else {
        throw_type_error(scope, "getCryptoKeySlots needs a CryptoKey");
        return;
    };
    rv.set(slots);
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_brand_name_is_qualified() {
        // V8's own guidance for `Private::for_api` is a qualified name; an
        // unqualified one can collide with another embedder's private symbol in
        // the same isolate, which would make `isCryptoKey` answer for their
        // objects.
        assert_eq!(BRAND_NAME, "herdr:NativeCryptoKey");
        assert!(BRAND_NAME.contains(':'));
    }

    #[test]
    fn a_crypto_key_stores_no_key_data() {
        // `isKeyObject` in this crate is "carries key data"
        // (`templates::is_native_key_object`), which is how it stands in for
        // Node's separate `NativeKeyObject` template brand. A `CryptoKey` must
        // therefore never satisfy it: an earlier revision copied the handle's
        // `KeyObjectData` onto the instance, and `util.types.isKeyObject`
        // reported `true` for every `subtle.importKey` result where the oracle
        // reports `false`.
        //
        // Index 0 is *shared* with `KEY_DATA_FIELD` — the two classes reuse the
        // same slot for different things — so "the indices differ" is not the
        // invariant. What actually keeps `isKeyObject` false is that
        // `with_key_data` requires the `KEY_PRESENT_FIELD` marker to be truthy,
        // and a `NativeCryptoKey` reserves only one field, so that marker is
        // past its count and `key_pointer` returns `None` before it ever reads
        // index 0 as a pointer.
        assert_eq!(CRYPTO_KEY_SLOTS_FIELD, 0);
        assert_eq!(CRYPTO_KEY_INTERNAL_FIELD_COUNT, 1);
        assert!(
            CRYPTO_KEY_INTERNAL_FIELD_COUNT <= crate::templates::KEY_PRESENT_FIELD as usize,
            "a CryptoKey must not reserve the key-present marker field, or \
             `with_key_data` would read index 0 as a key pointer and \
             `isKeyObject` would report true"
        );
    }

    #[test]
    fn the_slots_are_in_keys_js_order() {
        // `keys.js` indexes the array positionally: `kSlotType` is 0,
        // `kSlotExtractable` 1, `kSlotAlgorithm` 2, `kSlotUsagesMask` 3,
        // `kSlotHandle` 4, `kSlotSecondaryHandle` 5, `kSlotSeedData` 6. A
        // different order type-checks and then makes every `CryptoKey` getter
        // read the wrong slot, so the count is pinned here.
        const KEYS_JS_SLOT_COUNT: usize = 7;
        let slots = [
            0u32, // type
            1,    // extractable
            2,    // algorithm
            3,    // usages mask
            4,    // handle
            5,    // secondary handle
            6,    // seed data
        ];
        assert_eq!(slots.len(), KEYS_JS_SLOT_COUNT);
        assert_eq!(
            slots[4], 4,
            "`kSlotHandle` is where `getCryptoKeyHandle` reads"
        );
    }
}
