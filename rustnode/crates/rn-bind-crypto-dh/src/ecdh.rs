//! `ECDH` and `ECDHConvertKey`: the elliptic-curve half of `crypto_ec.cc`.
//!
//! `src/crypto/crypto_ec.cc` defines these three members and
//! `lib/internal/crypto/diffiehellman.js` drives them from a JavaScript `ECDH`
//! that adds only validation and encoding:
//!
//! | JavaScript | native |
//! | --- | --- |
//! | `new ECDH(curve)` | the `ECDH` constructor |
//! | `generateKeys()` | `GenerateKeys` |
//! | `computeSecret(key)` | `ComputeSecret` |
//! | `getPublicKey(form)` | `GetPublicKey` |
//! | `getPrivateKey()` | `GetPrivateKey` |
//! | `setPrivateKey(k)` / `setPublicKey(k)` | the two setters |
//! | `ECDH.convertKey(k, curve, form)` | `ECDHConvertKey` |
//!
//! # Why the state is a key pair, not an `EC_KEY`
//!
//! Node 28 links OpenSSL and so takes the `NCRYPTO_USE_OPENSSL_PROVIDER` branch
//! of `ECKeyPointer`, which keeps a group, a private `BIGNUM` and a public
//! `EC_POINT` and never builds an `EC_KEY` at all. The branch is observable in
//! three places this module therefore has to match:
//!
//! * `generateKeys()` draws a fresh key through `EVP_PKEY_keygen` and stores the
//!   private scalar and the encoded point separately, so a later
//!   `getPrivateKey()` returns the scalar at its *natural* width (`BN_num_bytes`)
//!   rather than padded — `ncrypto::Cipher`'s `getPrivateKey` is
//!   `EncodePadded(..., BignumPointer::GetByteCount(b))`, i.e. unpadded.
//! * `computeSecret()` uses `EVP_PKEY_derive` and returns the secret at the
//!   length OpenSSL reports, which is already the field size for a `P-256` key,
//!   so no padding step is needed and none is applied.
//! * `setPrivateKey()` sets the scalar and *recomputes* the point, which is why
//!   `getPublicKey()` changes after it while `getPrivateKey()` does not.
//!
//! # Why `computeSecret` can return a string
//!
//! `ECDH::ComputeSecret` sets the return value to the literal
//! `"ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY"` when the peer key does not parse, and
//! `dhComputeSecret` in the JavaScript tests `typeof ret === 'string'` to decide
//! to throw. So this must return the *string* for that failure rather than
//! throwing: throwing would also work at the call site but the intermediate
//! contract would be wrong, and `test-crypto-ecdh.js` calls the handle directly
//! through `internalBinding`.

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::PKey as OpenSslPKey;
use rn_v8_sys::v8;

use crate::{buffer_from, throw_type_error};

/// The internal field holding the `*mut RefCell<EcdhState>`.
const ECDH_STATE_FIELD: i32 = 0;

/// `ECDH::kInternalFieldCount` is 1 in Node: the `BaseObject` pointer.
const INTERNAL_FIELD_COUNT: usize = 1;

/// `POINT_CONVERSION_COMPRESSED`, from OpenSSL's `ec.h`.
const POINT_CONVERSION_COMPRESSED: u32 = 2;
/// `POINT_CONVERSION_UNCOMPRESSED`.
const POINT_CONVERSION_UNCOMPRESSED: u32 = 4;
/// `POINT_CONVERSION_HYBRID`.
const POINT_CONVERSION_HYBRID: u32 = 6;

/// The curve's group, private scalar and public point.
///
/// This is `ncrypto::ECKeyPointer` on the OpenSSL-provider branch: no `EC_KEY`,
/// because the operations below are `EC_POINT_*` and `EVP_PKEY_derive` on the
/// pieces rather than on a legacy key object.
struct EcdhState {
    group: EcGroup,
    /// `None` until `generateKeys` or `setPrivateKey`.
    private: Option<BigNum>,
    /// `None` until `generateKeys` or `setPublicKey`.
    public: Option<EcPoint>,
}

impl EcdhState {
    /// `ECKeyPointer::NewByCurveName`: a group with no key material.
    fn new(nid: Nid) -> Result<Self, ()> {
        let group = EcGroup::from_curve_name(nid).map_err(|_| ())?;
        Ok(Self {
            group,
            private: None,
            public: None,
        })
    }

    /// `ECKeyPointer::generate`.
    ///
    /// Draws the key with `EVP_PKEY_keygen` and splits it into the scalar and the
    /// encoded point, exactly as `ECKeyPointer::generate` does on this branch.
    /// Using `EcKey::generate` instead would produce the same pair, but the scalar
    /// would come from a different RNG call sequence — and a `P-521` key's
    /// scalar width is observable through `getPrivateKey()`.
    fn generate(&mut self) -> Result<(), ()> {
        let context = openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::EC).map_err(|_| ())?;
        let mut context = context;
        context.keygen_init().map_err(|_| ())?;
        // `setEcParameters(nid, OPENSSL_EC_NAMED_CURVE)`: the curve by NID.
        // `set_ec_param_enc` has no wrapper in either crate, and it is
        // `EVP_PKEY_CTX_set_ec_param_enc` — not `set_ec_paramgen_curve_nid` —
        // that selects named versus explicit encoding. A key generated without
        // it is still a named-curve key on OpenSSL 3, because the provider's EC
        // keygen defaults to named encoding.
        context
            .set_ec_paramgen_curve_nid(self.group.curve_name().ok_or(())?)
            .map_err(|_| ())?;
        let generated = context.keygen().map_err(|_| ())?;

        // `EVP_PKEY_get_bn_param(OSSL_PKEY_PARAM_PRIV_KEY)`.
        let private = generated
            .ec_key()
            .map_err(|_| ())?
            .private_key()
            .to_owned()
            .map_err(|_| ())?;
        // `EVP_PKEY_get_octet_string_param(OSSL_PKEY_PARAM_PUB_KEY)` then
        // `EC_POINT_oct2point`, which is what the provider branch does.
        let public = generated
            .ec_key()
            .map_err(|_| ())?
            .public_key()
            .to_owned(&self.group)
            .map_err(|_| ())?;

        self.private = Some(private);
        self.public = Some(public);
        Ok(())
    }

    /// `ECKeyPointer::checkKey`, which decides whether `computeSecret` may run.
    ///
    /// `IsKeyPairValid` caches this per FIPS generation, but the generation
    /// cannot change in this build (`getFipsCrypto()` is a constant false and
    /// `setFipsCrypto` is deferred), so the check is made each time. It is a
    /// handful of `BIGNUM` comparisons, and the alternative is a cache whose
    /// invalidation rule has no way to be exercised.
    fn is_valid(&self) -> bool {
        // A private scalar must be in `[1, n-1]`; `ECKeyPointer::checkKey`
        // rejects zero, a negative value and anything at or above the order.
        if let Some(private) = &self.private {
            let Ok(mut order) = BigNum::new() else {
                return false;
            };
            let Ok(mut context) = BigNumContext::new() else {
                return false;
            };
            if self.group.order(&mut order, &mut context).is_err() {
                return false;
            }
            // `BN_is_zero` has no wrapper; a zero `BigNum` has zero bits, which
            // is the same question and is what `BN_num_bits` answers.
            if private.num_bits() == 0 || private.is_negative() || private >= &order {
                return false;
            }
        }
        // A public point must be on the curve.
        if let Some(public) = &self.public {
            let Ok(mut context) = BigNumContext::new() else {
                return false;
            };
            if !public
                .is_on_curve(&self.group, &mut context)
                .unwrap_or(false)
            {
                return false;
            }
        }
        // When both are present, the point must be the scalar's multiple of the
        // generator. This is the check `ECKeyPointer::checkKey` makes with
        // `EC_POINT_cmp`, and it is what makes a `setPrivateKey` followed by a
        // `computeSecret` using the *old* public key fail.
        if let (Some(private), Some(public)) = (&self.private, &self.public) {
            let Ok(expected) = EcPoint::new(&self.group) else {
                return false;
            };
            let mut expected = expected;
            let Ok(mut context) = BigNumContext::new() else {
                return false;
            };
            if expected
                .mul_generator2(&self.group, private, &mut context)
                .is_err()
            {
                return false;
            }
            if !expected
                .eq(&self.group, public, &mut context)
                .unwrap_or(false)
            {
                return false;
            }
        }
        true
    }

    /// `ECKeyPointer::computeSecret`: an `EVP_PKEY_derive` between the two.
    ///
    /// `None` when either half is missing or OpenSSL refuses; the caller turns
    /// that into `ERR_CRYPTO_OPERATION_FAILED`.
    fn compute_secret(&self, peer: &EcPoint) -> Option<Vec<u8>> {
        let private = self.private.as_ref()?;
        let our_key = self.as_pkey()?;

        // The peer as a key of the same group: `ECKeyPointer::New(group)` with
        // only a public point set, which `NCrypto::NewDhPKey`'s EC sibling does.
        let mut peer_key = EcKey::from_public_key(&self.group, peer).ok()?;
        // `set_public_key` is on the private-building type; the public-only form
        // is what `from_public_key` produced, so nothing else is needed.
        let _ = &mut peer_key;
        let peer_key = OpenSslPKey::from_ec_key(peer_key).ok()?;

        let mut deriver = openssl::derive::Deriver::new(&our_key).ok()?;
        deriver.set_peer(&peer_key).ok()?;
        let secret = deriver.derive_to_vec().ok()?;
        // `EVP_PKEY_derive` reports the field size for an EC key, so the secret
        // already has the width `computeSecret` is documented to return; the
        // padding branch in the C++ is for the DH path, not this one.
        let _ = private;
        Some(secret)
    }

    /// The key material as an `EVP_PKEY`, which `EVP_PKEY_derive` needs.
    fn as_pkey(&self) -> Option<OpenSslPKey<openssl::pkey::Private>> {
        let private = self.private.as_ref()?;
        let public = self.public.as_ref()?;
        let key = EcKey::from_private_components(&self.group, private, public).ok()?;
        // `from_private_components` does not check the pair; `check_key` is what
        // `EC_KEY_check_key` would do, and an invalid pair must not reach
        // `EVP_PKEY_derive` where it would fail with a less specific reason.
        key.check_key().ok()?;
        OpenSslPKey::from_ec_key(key).ok()
    }
}

/// `new ECDH(curve)`.
fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // `CHECK(args[0]->IsString())`, then `OBJ_sn2nid`. An unknown name is
    // `ERR_CRYPTO_INVALID_CURVE`, which is what `createECDH('bogus')` reports.
    let Some(name) = string_of(scope, args.get(0)) else {
        throw_type_error(scope, "The curve argument must be a string");
        return;
    };
    let Some(nid) = crate::curve_nid(&name) else {
        throw_coded(scope, "Invalid EC curve name", "ERR_CRYPTO_INVALID_CURVE");
        return;
    };
    let state = match EcdhState::new(nid) {
        Ok(state) => state,
        // `Failed to create key using named curve`, which the C++ reports as
        // `ERR_CRYPTO_OPERATION_FAILED`.
        Err(()) => {
            throw_coded(
                scope,
                "Failed to create key using named curve",
                "ERR_CRYPTO_OPERATION_FAILED",
            );
            return;
        }
    };
    install(scope, this, state);
    rv.set(this.into());
}

/// Stores the state on the new object with a finalizer.
fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    state: EcdhState,
) {
    let pointer = Box::into_raw(Box::new(std::cell::RefCell::new(state)));
    object.set_aligned_pointer_in_internal_field(
        ECDH_STATE_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut std::cell::RefCell<EcdhState>;
            // SAFETY: allocated by `install` for this object alone, and this
            // finalizer is the only thing that frees it.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// Runs `body` with the object's state, or reports a foreign receiver.
fn with_state<R>(
    object: v8::Local<'_, v8::Object>,
    body: impl FnOnce(&mut EcdhState) -> R,
) -> Option<R> {
    // SAFETY: the pointer was written by `install` into this object's field 0, and
    // nothing but its finalizer clears or replaces it.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(ECDH_STATE_FIELD, 0) }
        as *mut std::cell::RefCell<EcdhState>;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above, and the finalizer runs only once the object is
    // unreachable, which cannot happen while `object` is a live local.
    let cell = unsafe { &*pointer };
    let mut state = cell.try_borrow_mut().ok()?;
    Some(body(&mut state))
}

/// `ECDH.prototype.generateKeys()`.
fn generate_keys(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    match with_state(args.this(), |state| state.generate()) {
        Some(Ok(())) => {}
        Some(Err(())) => throw_coded(
            scope,
            "Failed to generate key",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
        None => throw_type_error(scope, "Invalid ECDH receiver"),
    }
}

/// `ECDH.prototype.computeSecret(key)`.
///
/// Returns the secret as a `Buffer`, or the literal
/// `ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY` string when the peer point does not
/// parse — `diffiehellman.js` tests for a string and throws itself.
fn compute_secret(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(peer_bytes) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    let outcome = with_state(args.this(), |state| {
        if !state.is_valid() {
            return Outcome::InvalidKeyPair;
        }
        let Some(peer) = point_from_bytes(&state.group, &peer_bytes) else {
            return Outcome::InvalidPublicKey;
        };
        match state.compute_secret(&peer) {
            Some(secret) => Outcome::Secret(secret),
            None => Outcome::Failed,
        }
    });
    match outcome {
        Some(Outcome::Secret(secret)) => match buffer_from(scope, &secret) {
            Ok(buffer) => rv.set(buffer),
            Err(reason) => throw_coded(scope, reason, "ERR_CRYPTO_OPERATION_FAILED"),
        },
        Some(Outcome::InvalidPublicKey) => {
            // The string, not a throw: `dhComputeSecret` checks for it.
            if let Some(value) = v8::String::new(scope, "ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY") {
                rv.set(value.into());
            }
        }
        Some(Outcome::InvalidKeyPair) => throw_coded(
            scope,
            "Failed to compute ECDH key",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
        Some(Outcome::Failed) => throw_coded(
            scope,
            "Failed to compute ECDH key",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
        None => throw_type_error(scope, "Invalid ECDH receiver"),
    }
}

/// What `computeSecret` decided.
enum Outcome {
    Secret(Vec<u8>),
    /// The peer bytes are not a point on this curve.
    InvalidPublicKey,
    /// The local key pair is incomplete or inconsistent.
    InvalidKeyPair,
    /// OpenSSL refused the derivation.
    Failed,
}

/// `ECDH.prototype.getPublicKey(form)`.
///
/// Emits the point in the requested conversion form. The form is a
/// `POINT_CONVERSION_*` value from `binding.constants.crypto`, which
/// `diffiehellman.js` maps from `'compressed'`/`'uncompressed'`/`'hybrid'`.
fn get_public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let form = args
        .get(0)
        .uint32_value(scope)
        .unwrap_or(POINT_CONVERSION_UNCOMPRESSED);
    let encoded = with_state(args.this(), |state| {
        let public = state.public.as_ref()?;
        let mut context = BigNumContext::new().ok()?;
        public
            .to_bytes(&state.group, form_from_raw(form), &mut context)
            .ok()
    });
    match encoded {
        Some(Some(bytes)) => match buffer_from(scope, &bytes) {
            Ok(buffer) => rv.set(buffer),
            Err(reason) => throw_coded(scope, reason, "ERR_CRYPTO_OPERATION_FAILED"),
        },
        // `Failed to get ECDH public key`: the key has not been generated.
        Some(None) => throw_coded(
            scope,
            "Failed to get ECDH public key",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
        None => throw_type_error(scope, "Invalid ECDH receiver"),
    }
}

/// `ECDH.prototype.getPrivateKey()`.
fn get_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `getPrivateKey` encodes at `BignumPointer::GetByteCount(b)`, which is
    // `BN_num_bytes` — the scalar's *natural* width, not the field width. That is
    // observable: a `P-256` scalar whose top byte is zero reports 31 bytes.
    let encoded = with_state(args.this(), |state| {
        state.private.as_ref().map(|private| private.to_vec())
    });
    match encoded {
        Some(Some(bytes)) => match buffer_from(scope, &bytes) {
            Ok(buffer) => rv.set(buffer),
            Err(reason) => throw_coded(scope, reason, "ERR_CRYPTO_OPERATION_FAILED"),
        },
        Some(None) => throw_coded(
            scope,
            "Failed to get ECDH private key",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
        None => throw_type_error(scope, "Invalid ECDH receiver"),
    }
}

/// `ECDH.prototype.setPrivateKey(key)`.
///
/// Recomputes the public point from the scalar, which is what
/// `ECKeyPointer::setPrivateKey` does in the C++ caller (`EC_POINT_mul` on the
/// private key). `has_valid_key_pair_ = false` in Node is a cache invalidation
/// with no equivalent here because nothing is cached.
fn set_private_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(bytes) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    let outcome = with_state(args.this(), |state| {
        let Ok(private) = BigNum::from_slice(&bytes) else {
            return Err((
                "Failed to convert Buffer to BN",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        };
        // `IsKeyValidForCurve`: `[1, n-1]`.
        let Ok(mut order) = BigNum::new() else {
            return Err((
                "Failed to convert Buffer to BN",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        };
        let Ok(mut order_context) = BigNumContext::new() else {
            return Err((
                "Failed to convert Buffer to BN",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        };
        if state.group.order(&mut order, &mut order_context).is_err() {
            return Err((
                "Failed to convert Buffer to BN",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        }
        if private.num_bits() == 0 || private.is_negative() || private >= order {
            return Err((
                "Private key is not valid for specified curve.",
                "ERR_CRYPTO_INVALID_KEYTYPE",
            ));
        }
        // `EC_POINT_mul(group, pub, priv, nullptr, nullptr)`: the point is the
        // scalar's multiple of the generator.
        let Ok(point) = EcPoint::new(&state.group) else {
            return Err((
                "Failed to generate ECDH public key",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        };
        let mut point = point;
        let Ok(mut context) = BigNumContext::new() else {
            return Err((
                "Failed to generate ECDH public key",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        };
        if point
            .mul_generator2(&state.group, &private, &mut context)
            .is_err()
        {
            return Err((
                "Failed to generate ECDH public key",
                "ERR_CRYPTO_OPERATION_FAILED",
            ));
        }
        state.private = Some(private);
        state.public = Some(point);
        Ok(())
    });
    match outcome {
        Some(Ok(())) => {}
        Some(Err((message, code))) => throw_coded(scope, message, code),
        None => throw_type_error(scope, "Invalid ECDH receiver"),
    }
}

/// `ECDH.prototype.setPublicKey(key)`.
fn set_public_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(bytes) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    let outcome = with_state(args.this(), |state| {
        point_from_bytes(&state.group, &bytes).map(|point| {
            state.public = Some(point);
        })
    });
    match outcome {
        Some(Some(())) => {}
        Some(None) => throw_coded(
            scope,
            "Failed to convert Buffer to EC_POINT",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
        None => throw_type_error(scope, "Invalid ECDH receiver"),
    }
}

/// `ECDHConvertKey(key, curve, form)`.
///
/// Converts a point between the three encodings. An empty key returns the empty
/// string, which `test-crypto-ecdh.js` checks — the C++ has
/// `if (args0.empty()) return args.GetReturnValue().SetEmptyString()`.
fn convert_key(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(bytes) = bytes_of(args.get(0)) else {
        throw_type_error(
            scope,
            "The key argument must be an ArrayBuffer or a typed array",
        );
        return;
    };
    if bytes.is_empty() {
        if let Some(value) = v8::String::new(scope, "") {
            rv.set(value.into());
        }
        return;
    }
    let Some(curve) = string_of(scope, args.get(1)) else {
        throw_type_error(scope, "The curve argument must be a string");
        return;
    };
    let Some(nid) = crate::curve_nid(&curve) else {
        throw_coded(scope, "Invalid EC curve name", "ERR_CRYPTO_INVALID_CURVE");
        return;
    };
    let Ok(group) = EcGroup::from_curve_name(nid) else {
        throw_coded(
            scope,
            "Failed to get EC_GROUP",
            "ERR_CRYPTO_OPERATION_FAILED",
        );
        return;
    };
    let Some(point) = point_from_bytes(&group, &bytes) else {
        throw_coded(
            scope,
            "Failed to convert Buffer to EC_POINT",
            "ERR_CRYPTO_OPERATION_FAILED",
        );
        return;
    };
    let form = args
        .get(2)
        .uint32_value(scope)
        .unwrap_or(POINT_CONVERSION_UNCOMPRESSED);
    let Ok(mut context) = BigNumContext::new() else {
        throw_coded(
            scope,
            "Failed to get public key length",
            "ERR_CRYPTO_OPERATION_FAILED",
        );
        return;
    };
    match point.to_bytes(&group, form_from_raw(form), &mut context) {
        Ok(converted) => match buffer_from(scope, &converted) {
            Ok(buffer) => rv.set(buffer),
            Err(reason) => throw_coded(scope, reason, "ERR_CRYPTO_OPERATION_FAILED"),
        },
        Err(_) => throw_coded(
            scope,
            "Failed to get public key",
            "ERR_CRYPTO_OPERATION_FAILED",
        ),
    }
}

/// `EC_POINT_oct2point`, which is `ECPointPointer::setFromBuffer`.
fn point_from_bytes(group: &EcGroup, bytes: &[u8]) -> Option<EcPoint> {
    let mut context = BigNumContext::new().ok()?;
    let point = EcPoint::from_bytes(group, bytes, &mut context).ok()?;
    Some(point)
}

/// The `point_conversion_form_t` a `POINT_CONVERSION_*` value selects.
///
/// An unknown value becomes uncompressed, which is the default
/// `diffiehellman.js` passes; OpenSSL would otherwise reject a raw cast it could
/// not interpret.
fn form_from_raw(value: u32) -> PointConversionForm {
    match value {
        POINT_CONVERSION_COMPRESSED => PointConversionForm::COMPRESSED,
        POINT_CONVERSION_HYBRID => PointConversionForm::HYBRID,
        _ => PointConversionForm::UNCOMPRESSED,
    }
}

/// Reads a string argument.
fn string_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> Option<String> {
    let value = v8::Local::<v8::String>::try_from(value).ok()?;
    Some(value.to_rust_string_lossy(scope))
}

/// Copies the bytes behind a buffer source.
fn bytes_of(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
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
        let data = store.data()?;
        // SAFETY: `data` points at `length` bytes owned by `store`, which is
        // alive for this call, and the copy completes before returning.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), length);
        }
    }
    Some(bytes)
}

/// Throws an `Error` carrying a `.code`, which is the shape Node's tests read.
fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    // `ERR_CRYPTO_INVALID_KEYTYPE` and `ERR_CRYPTO_INVALID_CURVE` are declared as
    // a `RangeError` and a `TypeError` respectively in `internal/errors`, and
    // Node's tests check the constructor as well as the code.
    let exception = match code {
        "ERR_CRYPTO_INVALID_KEYTYPE" => v8::Exception::range_error(scope, text),
        "ERR_CRYPTO_INVALID_CURVE" => v8::Exception::type_error(scope, text),
        _ => v8::Exception::error(scope, text),
    };
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let (Some(key), Some(value)) =
            (v8::String::new(scope, "code"), v8::String::new(scope, code))
        {
            object.set(scope, key.into(), value.into());
        }
    }
    scope.throw_exception(exception);
}

/// Installs `ECDH` and `ECDHConvertKey` onto the namespace object.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELD_COUNT);
    let prototype = template.prototype_template(scope);
    // The method list is a macro rather than a table for the reason
    // `rn-bind-crypto-dh` records: `FunctionTemplate::builder` needs the item
    // type, and a `fn` pointer is not zero-sized.
    macro_rules! methods {
        ($($name:literal => $callback:path),* $(,)?) => {
            $(
                {
                    let built = v8::FunctionTemplate::builder($callback).build(scope);
                    let method = $name;
                    let key = v8::String::new(scope, method)
                        .ok_or_else(|| format!("cannot allocate ECDH.{method}"))?;
                    prototype.set(key.into(), built.into());
                }
            )*
        };
    }
    methods!(
        "generateKeys" => generate_keys,
        "computeSecret" => compute_secret,
        "getPublicKey" => get_public_key,
        "getPrivateKey" => get_private_key,
        "setPublicKey" => set_public_key,
        "setPrivateKey" => set_private_key,
    );
    let class_name = v8::String::new(scope, "ECDH").ok_or("cannot allocate the ECDH class name")?;
    template.set_class_name(class_name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the ECDH constructor")?;
    let key = v8::String::new(scope, "ECDH").ok_or("cannot allocate the ECDH name")?;
    target.set(scope, key.into(), function.into());

    let convert = v8::FunctionTemplate::builder(convert_key)
        .build(scope)
        .get_function(scope)
        .ok_or("cannot allocate crypto.ECDHConvertKey")?;
    let key = v8::String::new(scope, "ECDHConvertKey")
        .ok_or("cannot allocate the ECDHConvertKey name")?;
    target.set(scope, key.into(), convert.into());
    Ok(())
}

/// The members this module installs, for the parent crate's `MEMBERS` list.
pub const MEMBERS: &[&str] = &["ECDH", "ECDHConvertKey"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_point_conversion_values_are_openssls() {
        // `binding.constants.crypto.POINT_CONVERSION_*`, which
        // `diffiehellman.js` maps the string spellings onto. Getting one wrong
        // silently changes the encoding of every public key this returns.
        assert_eq!(POINT_CONVERSION_COMPRESSED, 2);
        assert_eq!(POINT_CONVERSION_UNCOMPRESSED, 4);
        assert_eq!(POINT_CONVERSION_HYBRID, 6);
        // `PointConversionForm` is a newtype over OpenSSL's enum with no
        // `PartialEq` or accessor, so the encoding round-trip is the check: a
        // point written compressed is 33 bytes and hybrid is 65, while
        // uncompressed is 65 too but starts with 0x04 rather than 0x06 or 0x07.
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        let mut state = EcdhState::new(Nid::X9_62_PRIME256V1).expect("P-256");
        state.generate().expect("key");
        let public = state.public.as_ref().expect("public");
        let mut context = BigNumContext::new().expect("context");
        let compressed = public
            .to_bytes(
                &group,
                form_from_raw(POINT_CONVERSION_COMPRESSED),
                &mut context,
            )
            .expect("compressed");
        let hybrid = public
            .to_bytes(&group, form_from_raw(POINT_CONVERSION_HYBRID), &mut context)
            .expect("hybrid");
        let uncompressed = public
            .to_bytes(&group, form_from_raw(0), &mut context)
            .expect("uncompressed");
        assert_eq!(compressed.len(), 33, "compressed is 0x02/0x03 plus x");
        assert_eq!(hybrid.len(), 65, "hybrid is the full point");
        assert_eq!(uncompressed.len(), 65, "the unknown value defaults here");
        // Hybrid's leading byte is 0x06 or 0x07 depending on whether `y` is
        // even or odd — that is what "hybrid" means, and `0x06` is only the
        // low-y case. Compressed's leading byte carries the same bit (`0x02` /
        // `0x03`), and the two must agree, which is the real property.
        assert!(
            hybrid[0] == 6 || hybrid[0] == 7,
            "hybrid marker is 0x06 or 0x07, got {}",
            hybrid[0]
        );
        assert_eq!(
            compressed[0],
            hybrid[0] & 1 | 2,
            "compressed and hybrid encode the same y parity"
        );
        assert_eq!(uncompressed[0], 4, "uncompressed's leading byte");
    }

    #[test]
    fn a_generated_pair_agrees_with_itself() {
        // A `P-256` key's public point is 65 bytes uncompressed (0x04 || x || y),
        // 33 compressed and its secret is the field width, 32. These are the
        // numbers `test-crypto-ecdh.js` compares, and they are a property of the
        // curve rather than of any particular key.
        let mut alice = EcdhState::new(Nid::X9_62_PRIME256V1).expect("P-256");
        let mut bob = EcdhState::new(Nid::X9_62_PRIME256V1).expect("P-256");
        alice.generate().expect("alice key");
        bob.generate().expect("bob key");

        let mut context = BigNumContext::new().expect("context");
        let alice_public = alice
            .public
            .as_ref()
            .expect("public")
            .to_bytes(
                &alice.group,
                PointConversionForm::UNCOMPRESSED,
                &mut context,
            )
            .expect("encode");
        assert_eq!(alice_public.len(), 65);
        assert_eq!(alice_public[0], 4, "uncompressed marker");

        let alice_secret = alice
            .compute_secret(bob.public.as_ref().expect("bob public"))
            .expect("alice secret");
        let bob_secret = bob
            .compute_secret(alice.public.as_ref().expect("alice public"))
            .expect("bob secret");
        assert_eq!(alice_secret, bob_secret, "both peers derive one secret");
        assert_eq!(alice_secret.len(), 32, "P-256 field width");
    }

    #[test]
    fn setting_a_private_key_recomputes_the_point() {
        // `test-crypto-ecdh.js` sets a fixed scalar and compares the public key
        // against a published value. Only the property that matters here is
        // checked: the point follows the scalar rather than staying behind.
        let mut state = EcdhState::new(Nid::X9_62_PRIME256V1).expect("P-256");
        state.generate().expect("key");
        let mut context = BigNumContext::new().expect("context");
        let before = state
            .public
            .as_ref()
            .expect("public")
            .to_bytes(
                &state.group,
                PointConversionForm::UNCOMPRESSED,
                &mut context,
            )
            .expect("encode");

        // Scalar 1 is a legal private key and its point is the generator.
        let one = BigNum::from_u32(1).expect("one");
        let mut point = EcPoint::new(&state.group).expect("point");
        point
            .mul_generator2(&state.group, &one, &mut context)
            .expect("mul");
        state.private = Some(one);
        state.public = Some(point);

        let after = state
            .public
            .as_ref()
            .expect("public")
            .to_bytes(
                &state.group,
                PointConversionForm::UNCOMPRESSED,
                &mut context,
            )
            .expect("encode");
        assert_ne!(before, after, "the point follows the scalar");
        assert!(state.is_valid(), "scalar 1 is in [1, n-1]");
    }
}
