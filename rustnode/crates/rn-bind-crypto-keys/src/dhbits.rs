//! `DHBitsJob`, the shared-secret derivation job `subtle.deriveBits` drives.
//!
//! `src/crypto/crypto_dh.cc` defines `DHBitsJob` as a `DeriveBitsJob<DHBitsTraits>`:
//! a `CryptoJob` whose constructor reads a public key and a private key from the
//! same five-slot encoding layout every other key argument uses, derives the
//! shared secret with `EVP_PKEY_derive`, and returns it as an `ArrayBuffer`.
//!
//! # The two callers, and why the mode matters
//!
//! | caller | mode | key slots |
//! | --- | --- | --- |
//! | `crypto.diffieHellman(options, cb)` | `kCryptoJobAsync`/`Sync` | encoded bytes |
//! | `ecdhDeriveBits` in `diffiehellman.js` | `kCryptoJobWebCrypto` | two `KeyObjectHandle`s |
//!
//! The WebCrypto form is what `subtle.deriveBits`/`deriveKey` reach, and it is a
//! promise the completion settles — not the `[err, secret]` tuple the callback
//! form destructures. Both shapes come from the shared `rn-crypto-job`
//! dispatch, so this module only supplies the work and the JavaScript result.
//!
//! `DeriveBitsJob`'s `Run` has the same three branches as every other
//! `CryptoJob`: sync returns the tuple, async queues for `ondone`, WebCrypto
//! returns a promise. The last is the one that was missing, so every
//! `subtle.deriveBits({name: 'ECDH', …})` threw "Unsupported operation" before
//! this class existed.

use rn_crypto_job::{dispatch, Completion, CryptoJobError, JobMode, Runnable};
use rn_crypto_openssl::PKey;
use rn_v8_sys::v8;

use crate::errors::{throw, KeyError};
use crate::handle::read_key_from_js;
use crate::state::{KeyData, KeyType};

/// The internal field a `DHBitsJob` stores its state in.
const JOB_FIELD: i32 = 0;

/// Installs `DHBitsJob` onto `target`, the `crypto` namespace object.
pub fn install_classes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = rn_core::class(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(JOB_FIELD as usize + 1);
    let prototype = template.prototype_template(scope);
    let key = v8::String::new(scope, "run").ok_or("cannot allocate DHBitsJob.run")?;
    prototype.set(key.into(), rn_core::method(run).build(scope).into());
    let name = v8::String::new(scope, "DHBitsJob").ok_or("cannot allocate the DHBitsJob name")?;
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or_else(|| "cannot allocate the DHBitsJob constructor".to_string())?;
    let property = v8::String::new(scope, "DHBitsJob").ok_or("cannot allocate the property name")?;
    target.set(scope, property.into(), function.into());
    Ok(())
}

/// The two keys the derivation runs between.
///
/// `DHBitsConfig` is exactly this pair, and `DHBitsTraits::DeriveBits` calls
/// `DHPointer::stateless(private, public)` on them.
struct DhBits {
    public: PKey,
    private: PKey,
}

impl Runnable for DhBits {
    type Output = Vec<u8>;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        derive(&self.private, &self.public)
            .map_err(|error| crate::errors::job_error(&error))
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        // `DHBitsTraits::EncodeOutput` is `out->ToArrayBuffer(env)`, so the
        // result is an `ArrayBuffer` and not the `Buffer` the traditional form
        // wraps in `Buffer.from`.
        let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(
            output.into_boxed_slice(),
        )
        .make_shared();
        Some(v8::ArrayBuffer::with_backing_store(scope, &store).into())
    }
}

/// `EVP_PKEY_derive` between a private key and a peer's public half.
///
/// `DHPointer::stateless` for the EC/X25519 families: `EVP_PKEY_derive_init` on
/// the private key, `EVP_PKEY_derive_set_peer` with the public one, then two
/// `EVP_PKEY_derive` calls to learn the length before writing it. The DH-specific
/// size padding `DHPointer` applies is not part of this path — `stateless` skips
/// it, which is why the EC secret is the field width rather than the padded
/// prime width.
fn derive(private: &PKey, public: &PKey) -> Result<Vec<u8>, KeyError> {
    // `EVP_PKEY_derive_set_peer` accepts a `PKey<Private>` that holds only public
    // material, which is exactly what `KeyData::asymmetric(kKeyTypePublic, …)`
    // wraps: the public half of a generated pair. Rebuilding it as a
    // `PKey<Public>` would need a re-parse and could reject a key the caller
    // already proved it holds.
    let mut deriver = openssl::derive::Deriver::new(private.openssl_ref())
        .map_err(|_| KeyError::OperationFailed("Failed to derive the shared secret"))?;
    deriver
        .set_peer(public.openssl_ref())
        .map_err(|_| KeyError::OperationFailed("Failed to derive the shared secret"))?;
    deriver
        .derive_to_vec()
        .map_err(|_| KeyError::OperationFailed("Failed to derive the shared secret"))
}

/// `new DHBitsJob(mode, pubData, pubFormat, pubType, pubPassphrase,
/// pubNamedCurve, privData, …)`.
///
/// Both keys use the five-slot layout `read_key_from_js` consumes, which is the
/// same shape `crypto.diffieHellman` and the WebCrypto path both build — the
/// difference is only what sits in slot 0 of each (encoded bytes versus a
/// `KeyObjectHandle`).
fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, &KeyError::ConstructCallRequired);
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    // The public half occupies slots 1..6 and the private half 6..11.
    let mut offset = 1usize;
    let public = read_key_from_js(scope, &args, &mut offset, KeyType::Public);
    let Some(public) = public else {
        return;
    };
    let private = read_key_from_js(scope, &args, &mut offset, KeyType::Private);
    let Some(private) = private else {
        return;
    };
    let (Some(public), Some(private)) = (public.asymmetric_key(), private.asymmetric_key()) else {
        throw(scope, &KeyError::InvalidKeyType);
        return;
    };
    install_job(
        scope,
        this,
        mode,
        DhBits {
            public: public.clone(),
            private: private.clone(),
        },
    );
    rv.set(this.into());
}

/// Stores the job and its mode on the instance, and installs `run`.
fn install_job(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    mode: JobMode,
    job: DhBits,
) {
    let boxed = Box::new((mode, std::cell::RefCell::new(Some(job))));
    let pointer = Box::into_raw(boxed);
    object.set_aligned_pointer_in_internal_field(
        JOB_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut (JobMode, std::cell::RefCell<Option<DhBits>>);
            // SAFETY: allocated just above for this object alone, freed once.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    let template = rn_core::class(run).build(scope);
    let Some(function) = template.get_function(scope) else {
        return;
    };
    if let Some(key) = v8::String::new(scope, "run") {
        object.set(scope, key.into(), function.into());
    }
}

/// `job.run()`.
fn run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // SAFETY: field 0 is the box `install_job` created for this object.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(JOB_FIELD, 0) }
        as *mut (JobMode, std::cell::RefCell<Option<DhBits>>);
    if pointer.is_null() {
        throw(scope, &KeyError::InvalidThis("CryptoJob"));
        return;
    }
    // SAFETY: as above; the finalizer runs only when the object is unreachable.
    let (mode, cell) = unsafe { &*pointer };
    let job = match cell.try_borrow_mut() {
        Ok(mut slot) => slot.take(),
        Err(_) => None,
    };
    let Some(job) = job else {
        throw(scope, &KeyError::OperationFailed("Job already ran"));
        return;
    };
    let mode = *mode;
    let completion = match mode {
        JobMode::WebCrypto => Completion::Promise,
        JobMode::Async | JobMode::Sync => Completion::Callback,
    };
    match dispatch(scope, mode, job, this, completion) {
        Some(value) => rv.set(value),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// Reads a `KeyData` as a `PKey`, or reports the wrong type.
#[allow(dead_code)]
fn asymmetric(data: &KeyData) -> Option<PKey> {
    data.asymmetric_key().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_secret_is_the_field_width() {
        // Two P-256 keys agree on a 32-byte secret, which is what the oracle's
        // `subtle.deriveBits({name: 'ECDH'}, …, 128)` returns after the JS slices
        // it. `DHPointer::stateless` does not pad for EC, so this is the raw
        // `EVP_PKEY_derive` output.
        let ours = PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256"));
        let theirs = PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256"));
        let secret = derive(&ours, &theirs);
        assert_eq!(secret.expect("derives").len(), 32);
    }

    #[test]
    fn the_public_key_drives_the_derivation_only_through_its_public_half() {
        // `DHBitsTraits::DeriveBits` calls `DHPointer::stateless(private,
        // public)`, so two pairs deriving in opposite directions agree. If the
        // public slot were read as private material the two directions would
        // disagree, which is what this pins without needing V8.
        let alice = PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256"));
        let bob = PKey::from_private(openssl::pkey::PKey::ec_gen("prime256v1").expect("P-256"));
        assert_eq!(
            derive(&alice, &bob).expect("alice derives"),
            derive(&bob, &alice).expect("bob derives")
        );
    }
}
