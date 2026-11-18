//! `[error, value]` tuple a sync `run()` returns.
//!
//! Every sync job in `lib/**` is written the same way:
//!
//! ```text
//! const { 0: err, 1: value } = job.run();
//! if (err !== undefined) throw err;
//! ```
//!
//! So the error is a *value* in slot 0, never a thrown exception. Throwing would
//! surface from `job.run()` itself, which is a different place than the caller's
//! `throw err` — and `generateKeyPairSync`'s `handleError` reads `ret[0]` and
//! throws it itself, so a throw here would skip that path entirely.
//!
//! `undefined` rather than `null` in the empty slot: the callers test
//! `err !== undefined` and `value === undefined`, and `null` would read as a
//! present-but-empty value.
//!
//! # A failure *inside* `finish`
//!
//! `KeyGenJob::ToResult` and `DeriveBitsJob::ToResult` wrap the encode step in a
//! `TryCatch`: when it throws, the exception becomes `*err` and the value stays
//! undefined. That is not the same as slot 0 staying empty — the error has to
//! reach JavaScript, and `generateKeyPairSync`'s `handleError` only throws what
//! it finds in slot 0. Leaving both slots undefined turned
//! `generateKeyPairSync('dsa', { publicKeyEncoding: { format: 'jwk' } })` into
//! `TypeError: Cannot destructure property '0' of 'keys' as it is undefined`
//! instead of the `ERR_CRYPTO_JWK_UNSUPPORTED_KEY_TYPE` the oracle reports.

use rn_v8_sys::v8;

use crate::{CryptoJobError, Runnable};

/// Builds the two-element array.
pub fn tuple<'s, J: Runnable>(
    scope: &mut v8::PinScope<'s, '_>,
    job: &J,
    result: Result<J::Output, CryptoJobError>,
) -> v8::Local<'s, v8::Value> {
    let undefined = v8::undefined(scope);
    let (error, value): (v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>) = match result {
        Ok(output) => {
            // The encode step runs under its own `TryCatch`, exactly as Node's
            // `ToResult` does, so a throw from it becomes the error value the
            // caller's `handleError` reads rather than an unhandled exception.
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let inner = &mut try_catch.init();
            let value = job.finish(inner, output);
            match inner.exception() {
                Some(exception) => (exception, undefined.into()),
                None => match value {
                    Some(value) => (undefined.into(), value),
                    None => (undefined.into(), undefined.into()),
                },
            }
        }
        Err(error) => (error.exception(scope), undefined.into()),
    };
    v8::Array::new_with_elements(scope, &[error, value]).into()
}
