//! The `[error, value]` tuple a sync `run()` returns.
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
        Ok(output) => match job.finish(scope, output) {
            Some(value) => (undefined.into(), value),
            // `finish` threw; the pending exception is what the caller sees, and
            // leaving slot 1 empty keeps the shape a two-element array.
            None => (undefined.into(), undefined.into()),
        },
        Err(error) => (error.exception(scope), undefined.into()),
    };
    v8::Array::new_with_elements(scope, &[error, value]).into()
}
