//! `DiffieHellman` and `DiffieHellmanGroup` for `internalBinding('crypto')`.
//!
//! `src/crypto/crypto_dh.cc` is the binding this mirrors. Both names are
//! constructors on the *same* namespace object as the hashing surface, because
//! `src/node_crypto.cc` aggregates a dozen classes onto one `target`; the crate
//! split here is per translation unit, not per namespace. This crate therefore
//! exposes [`install_classes`] rather than a `BindingModule`, and
//! `rn-bind-crypto` installs the classes onto the object it already builds.
//!
//! # What the JavaScript does with these two
//!
//! `lib/internal/crypto/diffiehellman.js` builds a JavaScript `DiffieHellman`
//! whose only job is argument validation and encoding; every operation is
//! `this[kHandle].<method>(...)` on one of these objects:
//!
//! | JavaScript | native |
//! | --- | --- |
//! | `new DiffieHellman(sizeOrKey, generator)` | `DiffieHellman` constructor |
//! | `new DiffieHellmanGroup(name)` | `DiffieHellmanGroup` constructor |
//! | `generateKeys()` | `generateKeys` → `generate_keys` |
//! | `computeSecret(key)` | `computeSecret` → `compute_secret` |
//! | `getPrime()`/`getGenerator()`/`getPublicKey()`/`getPrivateKey()` | the four getters |
//! | `setPublicKey(k)`/`setPrivateKey(k)` | the two setters |
//! | `verifyError` (a *property*, not a call) | `Check` behind an accessor |
//!
//! `DiffieHellmanGroup` has `generateKeys`, `computeSecret` and the four getters
//! and **no setters**: `test-crypto-dh-group-setters.js` asserts
//! `dhg.setPrivateKey === undefined`, so the two constructors cannot share a
//! prototype. They are built from separate templates here for that reason.
//!
//! # State ownership
//!
//! The `Dh` lives in a heap allocation behind an internal field, with a
//! `Weak::with_guaranteed_finalizer` to free it, exactly as the `Hash` and
//! `Hmac` handles in `rn-bind-crypto` do. V8's GC is the only thing that decides
//! when a key object dies, so a finalizer is the only correct place to release
//! it.

use std::cell::RefCell;

use rn_v8_sys::v8;

pub mod state;

use state::{check_result, Dh, DhError};

/// The internal field holding the `*mut RefCell<Dh>`.
const DH_STATE_FIELD: i32 = 0;

/// `DiffieHellman::kInternalFieldCount` is 1 in Node, and the field is the
/// `BaseObject` pointer. One is all this needs too.
const INTERNAL_FIELD_COUNT: usize = 1;

/// Installs both constructors onto `target`, which is the `crypto` namespace.
///
/// Called from `rn-bind-crypto`'s `install`, so this crate never builds a
/// namespace object of its own.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let group = build_group_class(scope)?;
    let full = build_class(scope)?;
    set(scope, target, "DiffieHellman", full)?;
    set(scope, target, "DiffieHellmanGroup", group)
}

/// The members this crate installs, for the parent crate's `MEMBERS` list.
pub const MEMBERS: &[&str] = &["DiffieHellman", "DiffieHellmanGroup"];

/// `new DiffieHellman(sizeOrKey, generator)`.
///
/// `crypto_dh.cc`'s `New` accepts either a bit count (`Int32`) or a prime as an
/// array buffer / view, with the generator as a number or a second buffer. The
/// JavaScript has already validated and coerced the argument *shapes*, so this
/// only has to distinguish the two forms and convert bytes.
fn constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let first = args.get(0);
    let second = args.get(1);

    let dh = if let Ok(bits) = v8::Local::<v8::Int32>::try_from(first) {
        // `New`: a bit count requires an int32 generator, and a bit count below
        // 2 is `DH_R_MODULUS_TOO_SMALL`.
        let Some(generator) = v8::Local::<v8::Int32>::try_from(second)
            .ok()
            .map(|value| value.value())
        else {
            throw_type_error(scope, "Second argument must be an int32");
            return;
        };
        // Both rejections are `DhError` variants, so the constructor does not
        // duplicate the error shapes: `generate_parameters` reports
        // `ModulusTooSmall`/`BadGenerator` and `throw_dh_error` maps them.
        Dh::generate_parameters(bits.value(), generator)
    } else {
        let Some(prime) = bytes_of(first) else {
            throw_type_error(scope, "Invalid prime");
            return;
        };
        let Ok(prime) = openssl::bn::BigNum::from_slice(&prime) else {
            throw_type_error(scope, "Invalid prime");
            return;
        };
        let generator = if let Ok(value) = v8::Local::<v8::Int32>::try_from(second) {
            let value = value.value();
            // A negative generator cannot be a `BigNum::from_u32`; `crypto_dh.cc`
            // passes the signed value to `BN_set_word`, which rejects it and
            // raises `DH_R_BAD_GENERATOR`. Checking the sign here is that same
            // rejection, and the alternative — casting to `u32` — would turn
            // `-1` into 4294967295 and then trip the "generator above p" rule
            // only for small primes.
            if value < 0 {
                throw_dh_error(scope, &DhError::BadGenerator);
                return;
            }
            match openssl::bn::BigNum::from_u32(value as u32) {
                Ok(generator) => generator,
                Err(_) => {
                    throw_dh_error(scope, &DhError::BadGenerator);
                    return;
                }
            }
        } else if let Some(generator) = bytes_of(second) {
            match openssl::bn::BigNum::from_slice(&generator) {
                Ok(generator) => generator,
                Err(_) => {
                    throw_dh_error(scope, &DhError::BadGenerator);
                    return;
                }
            }
        } else {
            throw_type_error(scope, "Second argument must be an int32 or a buffer");
            return;
        };
        Dh::from_parameters(prime, generator)
    };

    match dh {
        Ok(dh) => install(scope, &args, &mut rv, dh),
        Err(error) => throw_dh_error(scope, &error),
    }
}

/// `new DiffieHellmanGroup(name)`.
fn group_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(name) = string_of(scope, args.get(0)) else {
        throw_type_error(scope, "Group name must be a string");
        return;
    };
    match Dh::from_group(&name) {
        Ok(dh) => install(scope, &args, &mut rv, dh),
        Err(DhError::UnknownGroup(_)) => {
            throw_coded(scope, "Unknown DH group", "ERR_CRYPTO_UNKNOWN_DH_GROUP");
        }
        Err(error) => throw_dh_error(scope, &error),
    }
}

/// Stores the state on the new object and returns it.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    dh: Dh,
) {
    let this = args.this();
    let pointer = Box::into_raw(Box::new(RefCell::new(dh)));
    this.set_aligned_pointer_in_internal_field(
        DH_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    // `crypto_dh.cc` installs `verifyError` as a read-only accessor over
    // `DHPointer::check()`. The parameters cannot change after construction, so
    // computing it here and storing it read-only is the same observation.
    let codes = match with_state(this, |dh| dh.verify_error()) {
        Some(codes) => codes,
        None => check_result::CHECK_FAILED,
    };
    if let Err(error) = install_verify_error(scope, this, codes) {
        // The state and its finalizer are already in place; leaving the property
        // off would only make `verifyError` read `undefined`, which is a worse
        // failure to debug than a thrown error here.
        throw(scope, &error);
        return;
    }
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        this,
        Box::new(move || {
            let pointer = address as *mut RefCell<Dh>;
            // SAFETY: allocated by `install` for this object alone, and this
            // finalizer is the only thing that frees it.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    rv.set(this.into());
}

/// Runs `body` with the object's `Dh`, or reports that the receiver is not one.
///
/// A receiver that is not a `DiffieHellman` gets the error Node's
/// `ASSIGN_OR_RETURN_UNWRAP` produces, rather than a panic. The borrow is a
/// `RefCell` because the methods are `&mut self` in Node and the callbacks are
/// `Fn`; a re-entrant borrow cannot happen because nothing in this crate calls
/// back into V8 while holding it.
fn with_state<R>(this: v8::Local<v8::Object>, body: impl FnOnce(&mut Dh) -> R) -> Option<R> {
    // SAFETY: the pointer was written by `install` into this object's field 0,
    // and nothing but its finalizer clears or replaces it.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(DH_STATE_FIELD, 0) }
        as *mut RefCell<Dh>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above, and the finalizer runs only once the object is
    // unreachable, which cannot happen while `this` is a live local.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

fn generate_keys(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let result = with_state(args.this(), |dh| dh.generate_keys());
    match result {
        Some(Ok(bytes)) => emit_bytes(scope, &mut rv, &bytes),
        Some(Err(error)) => throw_dh_error(scope, &error),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn compute_secret(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(peer) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    let result = with_state(args.this(), |dh| dh.compute_secret(&peer));
    match result {
        Some(Ok(bytes)) => emit_bytes(scope, &mut rv, &bytes),
        Some(Err(error)) => throw_dh_error(scope, &error),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn get_prime(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |dh| dh.prime_bytes()) {
        Some(bytes) => emit_bytes(scope, &mut rv, &bytes),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn get_generator(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |dh| dh.generator_bytes()) {
        Some(bytes) => emit_bytes(scope, &mut rv, &bytes),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn get_public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |dh| dh.public_key_bytes()) {
        Some(Ok(bytes)) => emit_bytes(scope, &mut rv, &bytes),
        Some(Err(error)) => throw_dh_error(scope, &error),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn get_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match with_state(args.this(), |dh| dh.private_key_bytes()) {
        Some(Ok(bytes)) => emit_bytes(scope, &mut rv, &bytes),
        Some(Err(error)) => throw_dh_error(scope, &error),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn set_public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(key) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    match with_state(args.this(), |dh| dh.set_public_key(&key)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_dh_error(scope, &error),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

fn set_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(key) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    match with_state(args.this(), |dh| dh.set_private_key(&key)) {
        Some(Ok(())) => {}
        Some(Err(error)) => throw_dh_error(scope, &error),
        None => throw(scope, "Invalid DiffieHellman receiver"),
    }
}

/// Installs a prototype method from an `fn` item.
///
/// A macro rather than a table of function pointers: `FunctionTemplate::builder`
/// needs the *item* type, because V8's trampoline is generic over a zero-sized
/// unit type (`v8::support::UnitValue`). A `fn` pointer is not zero-sized and
/// fails to compile there, so the method list cannot be a plain slice.
macro_rules! install_methods {
    ($scope:ident, $prototype:ident, $($name:literal => $callback:path),* $(,)?) => {
        $(
            {
                let template = v8::FunctionTemplate::builder($callback).build($scope);
                let Some(key) = v8::String::new($scope, $name) else {
                    return Err(format!("cannot allocate the {} property name", $name));
                };
                $prototype.set(key.into(), template.into());
            }
        )*
    };
}

/// The six operations and getters both classes share.
macro_rules! shared_methods {
    ($scope:ident, $prototype:ident) => {
        install_methods!(
            $scope,
            $prototype,
            "generateKeys" => generate_keys,
            "computeSecret" => compute_secret,
            "getPrime" => get_prime,
            "getGenerator" => get_generator,
            "getPublicKey" => get_public_key,
            "getPrivateKey" => get_private_key,
        )
    };
}

/// Builds `DiffieHellman`: every method plus the two setters.
fn build_class<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let prototype = template.prototype_template(scope);
    shared_methods!(scope, prototype);
    // `test-crypto-dh-group-setters.js` asserts the *group* class has no
    // setters, so these are installed here and not in `shared_methods!`.
    install_methods!(
        scope,
        prototype,
        "setPublicKey" => set_public_key,
        "setPrivateKey" => set_private_key,
    );
    finish(scope, template, "DiffieHellman")
}

/// Builds `DiffieHellmanGroup`: the shared surface only, no setters.
fn build_group_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(group_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let prototype = template.prototype_template(scope);
    shared_methods!(scope, prototype);
    finish(scope, template, "DiffieHellmanGroup")
}

/// Installs `verifyError` on the new instance as a read-only data property.
///
/// `crypto_dh.cc` installs an `AccessorProperty` with `ReadOnly | DontDelete`
/// whose getter runs `DHPointer::check()`. A data property with the same
/// attributes is observably equivalent here because nothing can change the
/// parameters after construction — `setPublicKey`/`setPrivateKey` replace keys,
/// not `p` or `g` — so the value the accessor would compute is the value this
/// stores, and it is stored once instead of recomputed on every read.
///
/// It is defined on the *instance* rather than the prototype because
/// `lib/internal/crypto/diffiehellman.js` reads `this[kHandle].verifyError`
/// exactly once, in the JavaScript wrapper's own constructor, and a prototype
/// accessor cannot see which instance is being read (`PropertyCallbackInfo`'s
/// `holder` is the prototype, not the receiver).
fn install_verify_error(
    scope: &mut v8::PinScope<'_, '_>,
    instance: v8::Local<v8::Object>,
    codes: i32,
) -> Result<(), String> {
    let Some(key) = v8::String::new(scope, "verifyError") else {
        return Err("cannot allocate the verifyError property name".to_string());
    };
    let value = v8::Integer::new(scope, codes);
    instance
        .define_own_property(
            scope,
            key.into(),
            value.into(),
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| "cannot define verifyError".to_string())?;
    Ok(())
}

/// Names the class and returns its constructor.
fn finish<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    template: v8::Local<'s, v8::FunctionTemplate>,
    name: &str,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    let Some(function_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} function name"));
    };
    function.set_name(function_name);
    Ok(function.into())
}

// ---------------------------------------------------------------------------
// Argument marshalling
// ---------------------------------------------------------------------------

/// Copies the bytes behind a `Buffer`, typed array, `DataView` or
/// `ArrayBuffer`, or `None` for anything else.
///
/// Type-strict on purpose: `AGENTS.md` records that a binding which coerces its
/// arguments hides the caller's bug, and `crypto_dh.cc`'s
/// `ArrayBufferOrViewContents` is equally strict.
fn bytes_of(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let length = view.byte_length();
        let mut bytes = vec![0u8; length];
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Some(bytes);
    }
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
    let store = buffer.get_backing_store();
    let length = buffer.byte_length();
    let mut bytes = vec![0u8; length];
    if length > 0 {
        // `data()` on a non-shared backing store is contiguous; the length was
        // taken from the buffer itself, so the slice cannot overrun.
        let data = store.data()?;
        // SAFETY: `data` points at `length` bytes owned by `store`, which is
        // alive for this call.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

/// Reads a JavaScript string as UTF-8, or `None` for a non-string.
fn string_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<String> {
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(text.to_rust_string_lossy(scope))
}

/// Emits bytes as a `Buffer`, which is what `diffiehellman.js` expects.
///
/// The JavaScript calls `buffer.toString(encoding)` and `Buffer.isBuffer` on the
/// result in several places, and a plain `Uint8Array` would satisfy neither. Node
/// builds a real `Buffer` through `Buffer::New(env, ab, 0, len)`; the equivalent
/// here is `Buffer.from(arrayBuffer, 0, len)`, resolved off the global `Buffer`
/// the runtime installed.
fn emit_bytes(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    match buffer_from(scope, bytes) {
        Ok(value) => rv.set(value),
        Err(reason) => throw(
            scope,
            &format!("cannot allocate the Diffie-Hellman result: {reason}"),
        ),
    }
}

/// `Buffer.from(arrayBuffer, 0, length)` over a fresh backing store.
///
/// `Buffer.from` rather than `new Buffer(...)`: the latter is deprecated and the
/// deprecation warning is visible to every test that captures stderr, which
/// several do.
///
/// The global `Buffer` is looked up on every call rather than cached, because a
/// `v8::Global` held across calls would pin the constructor for the isolate's
/// lifetime and outlive a context teardown. `Buffer.from` is a property read on
/// a global, which is cheap next to the modular exponentiation that produced
/// `bytes`.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Result<v8::Local<'s, v8::Value>, &'static str> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let buffer = buffer_constructor(scope).ok_or("global Buffer is not a function")?;
    let from_key = v8::String::new(scope, "from").ok_or("cannot allocate 'from'")?;
    let from = buffer
        .get(scope, from_key.into())
        .ok_or("Buffer.from lookup failed")?;
    let from =
        v8::Local::<v8::Function>::try_from(from).map_err(|_| "Buffer.from is not a function")?;
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, bytes.len() as i32);
    let receiver = buffer.into();
    let called = from
        .call(
            scope,
            receiver,
            &[array_buffer.into(), start.into(), length.into()],
        )
        .ok_or("Buffer.from threw")?;
    if !called.is_object() {
        return Err("Buffer.from returned a non-object");
    }
    Ok(called)
}

/// The global `Buffer` constructor object.
///
/// Returned as an `Object` rather than a `Function`: the real `Buffer` is a
/// function, but nothing here calls it — only `Buffer.from` — and requiring a
/// callable would reject a perfectly usable `Buffer` shape.
fn buffer_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn throw_dh_error(scope: &mut v8::PinScope<'_, '_>, error: &DhError) {
    match error {
        DhError::UnknownGroup(_) => {
            throw_coded(scope, "Unknown DH group", "ERR_CRYPTO_UNKNOWN_DH_GROUP")
        }
        // Node's `THROW_ERR_CRYPTO_INVALID_STATE(env, "No public key ...")`
        // reports the argument as the whole message, not through
        // `ERR_CRYPTO_INVALID_STATE`'s `Invalid state for operation %s` template:
        // `crypto_dh.cc` throws the argument text directly and only tags the
        // code. Verified against a real `node`: `getPublicKey()` before
        // `generateKeys()` yields exactly
        // `No public key - did you forget to generate one?`.
        DhError::InvalidState(message) => throw_coded(scope, message, "ERR_CRYPTO_INVALID_STATE"),
        DhError::InvalidKeyLength(message) => {
            throw_coded(scope, message, "ERR_CRYPTO_INVALID_KEYLEN")
        }
        DhError::InvalidKeyType(message) => {
            throw_coded(scope, message, "ERR_CRYPTO_INVALID_KEYTYPE")
        }
        DhError::OperationFailed(message) => {
            throw_coded(scope, message, "ERR_CRYPTO_OPERATION_FAILED")
        }
        DhError::InvalidArgument(message) => throw_coded(scope, message, "ERR_INVALID_ARG_VALUE"),
        DhError::ModulusTooSmall => throw_openssl(
            scope,
            "modulus too small",
            "Diffie-Hellman",
            "DH",
            MODULUS_TOO_SMALL_REASON,
        ),
        DhError::BadGenerator => throw_openssl(
            scope,
            "bad generator",
            "Diffie-Hellman",
            "DH",
            BAD_GENERATOR_REASON,
        ),
        DhError::OpenSsl(stack) => throw(scope, &stack.to_string()),
    }
}

/// Throws an `Error` carrying a `.code`, which is the shape Node's tests read.
fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    if let Some(code_key) = v8::String::new(scope, "code") {
        if let Some(code_value) = v8::String::new(scope, code) {
            object.set(scope, code_key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws the OpenSSL-shaped error `ThrowCryptoError` builds.
///
/// The shape is four fields, and `test-crypto-dh-errors.js` reads two of them:
///
/// ```text
/// code     ERR_OSSL_DH_MODULUS_TOO_SMALL
/// library  Diffie-Hellman routines
/// reason   modulus too small
/// message  error:0280007E:Diffie-Hellman routines::modulus too small
/// ```
///
/// The code is **not** the display name upper-cased: OpenSSL's library *name* is
/// `Diffie-Hellman` while the name `error::Decorate` builds the code from is the
/// library's short id, `DH`. Deriving the code from the display name produces
/// `ERR_OSSL_DIFFIE_HELLMAN_MODULUS_TOO_SMALL`, which is a plausible-looking
/// string no Node test accepts. Both are passed in explicitly for that reason.
fn throw_openssl(
    scope: &mut v8::PinScope<'_, '_>,
    reason: &str,
    display_library: &str,
    short_library: &str,
    packed_error: u64,
) {
    let message = format!("error:{packed_error:08X}:{display_library} routines::{reason}");
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    let code = format!(
        "ERR_OSSL_{}_{}",
        short_library.to_ascii_uppercase(),
        reason.to_ascii_uppercase().replace(' ', "_")
    );
    for (name, value) in [
        ("code", code),
        ("library", format!("{display_library} routines")),
        ("reason", reason.to_string()),
    ] {
        let (Some(key), Some(text)) =
            (v8::String::new(scope, name), v8::String::new(scope, &value))
        else {
            continue;
        };
        object.set(scope, key.into(), text.into());
    }
    scope.throw_exception(exception);
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// `DH_R_MODULUS_TOO_SMALL` as OpenSSL 3 packs it: library 28 (`DH`), reason 126.
const MODULUS_TOO_SMALL_REASON: u64 = 0x0280_007E;
/// `DH_R_BAD_GENERATOR`: library 28, reason 101.
const BAD_GENERATOR_REASON: u64 = 0x0280_0065;

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
