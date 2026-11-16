//! `RandomBytesJob`, `RandomPrimeJob` and `CheckPrimeJob` — the three async
//! jobs `lib/internal/crypto/random.js` builds.
//!
//! `src/crypto/crypto_random.cc` is the source. Each is a `DeriveBitsJob` over a
//! `Random*Traits`, which means the shape is the same for all three:
//!
//! ```text
//! new RandomBytesJob(kCryptoJobAsync, buf, offset, size)
//! new RandomPrimeJob(mode, size, safe, add, rem)
//! new CheckPrimeJob(mode, candidate, checks)
//! ```
//!
//! and then `job.ondone = ...; job.run()`, or `const { 0: err, 1: v } =
//! job.run()` in the sync form.
//!
//! # Why these were the visible failure
//!
//! `randomBytes(n, cb)` does not have a sync fallback: `randomFill` in
//! `lib/internal/crypto/random.js:229` constructs a `RandomBytesJob`
//! unconditionally whenever a callback was supplied. The same is true of
//! `randomFill(buf, cb)`, `randomInt`'s cache refill (which calls `randomFill`),
//! `generatePrime` and `checkPrime`. So every async random API threw
//! `TypeError: RandomBytesJob is not a constructor` even though the sync half
//! worked, which is what made the gap look like a scheduling problem when it was
//! a missing class.
//!
//! # `RandomBytesJob` writes into the caller's buffer
//!
//! This is the one job here whose output is not a value: `RandomBytesTraits`
//! fills the buffer it was handed and `EncodeOutput` returns `undefined`, so
//! `ondone(err)` — not `ondone(err, buf)` — is the whole delivery, and
//! `random.js` closes over `buf` in its bound callback. That is why the job
//! needs the backing store rather than a copy: filling a copy would leave the
//! caller's buffer untouched and the test still "passing" because the callback
//! ran.
//!
//! The buffer is therefore held as a `SharedRef<BackingStore>` rooted for the
//! duration of the job, and the fill happens through it on the pool thread. A
//! shared backing store is `Send`, and nothing else may alias it while the job is
//! queued — `random.js` only ever passes a freshly-allocated `FastBuffer` or one
//! the caller promised not to touch.

use rn_crypto_job::{CryptoJobError, JobMode, OpenSslDetail, Runnable};
use rn_crypto_openssl::openssl_error;
use rn_v8_sys::v8;

use crate::encoding;
use crate::engine;

/// The internal field a job instance stores its state in.
pub const JOB_FIELD: i32 = 0;

/// `new RandomBytesJob(mode, buffer, offset, size)`.
///
/// The buffer is a `Buffer`, `TypedArray`, `DataView` or `ArrayBuffer`; `offset`
/// and `size` are byte offsets into it and have already been validated against
/// its length by `assertOffset`/`assertSize`, so an out-of-range pair here is a
/// programming error and is rejected rather than clamped.
pub struct RandomBytesJob {
    /// The range to fill, held through the backing store so it stays valid on
    /// the pool thread even if JavaScript drops every reference to the buffer.
    target: BackingStoreRange,
}

impl RandomBytesJob {
    /// Reads the three arguments and takes a share of the backing store.
    ///
    /// Returns `None` after throwing for a buffer that is not a buffer source or
    /// a range outside it.
    pub fn from_arguments<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        value: v8::Local<'s, v8::Value>,
        offset: usize,
        size: usize,
    ) -> Option<Self> {
        let target = BackingStoreRange::new(scope, value, offset, size)?;
        Some(Self { target })
    }
}

impl Runnable for RandomBytesJob {
    /// `undefined`: the fill happened in place.
    type Output = ();

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        self.target.fill()
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        Some(v8::undefined(scope).into())
    }
}

/// A byte range inside a JavaScript backing store, held for the job's lifetime.
pub struct BackingStoreRange {
    /// A share of the store, which keeps the memory alive independently of the
    /// JavaScript object.
    store: v8::SharedRef<v8::BackingStore>,
    /// The first byte to write, which is the view's `byte_offset` plus the
    /// caller's offset.
    start: usize,
    /// How many bytes to write.
    length: usize,
}

impl BackingStoreRange {
    /// Resolves `value[offset .. offset + size]` against its backing store.
    ///
    /// `value` may be an `ArrayBuffer` or any `ArrayBufferView`. For a view the
    /// byte offset is the view's own, exactly as `ArrayBufferOrViewContents` in
    /// `node_buffer.h` computes it, so `randomFill(buf.subarray(4), 0, 2)` fills
    /// the right two bytes.
    fn new<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        value: v8::Local<'s, v8::Value>,
        offset: usize,
        size: usize,
    ) -> Option<Self> {
        let (store, base, length) = view_store(value)?;
        let start = base.checked_add(offset)?;
        let end_in_view = offset.checked_add(size)?;
        // The bound is the *view's* length, not the backing store's: `random.js`
        // validated `offset + size` against `TypedArrayPrototypeGetByteLength`,
        // and `randomFill(buf.subarray(2, 5), 0, 3)` is legal even though byte 5
        // of the store is outside that view. Using the store's length here would
        // reject that call and — worse — accept a range that reaches into a
        // neighbouring view.
        if end_in_view > length {
            let message = format!(
                "The value of \"offset + size\" is out of range. It must be <= {length}. Received {end_in_view}"
            );
            throw_range(scope, &message);
            return None;
        }
        Some(Self {
            store,
            start,
            length: size,
        })
    }

    /// Fills the range with cryptographically strong bytes.
    fn fill(&mut self) -> Result<(), CryptoJobError> {
        if self.length == 0 {
            return Ok(());
        }
        // SAFETY: `start..start + length` was bounds-checked against the store
        // when this range was built, the store is held by `self` so the memory
        // is alive, and a job holds the only reference to the range until the
        // completion — `random.js` never hands the same buffer to two jobs.
        let bytes = unsafe {
            let Some(base) = self.store.data() else {
                return Err(CryptoJobError::operation_failed(
                    "The buffer has no backing store",
                ));
            };
            std::slice::from_raw_parts_mut(base.as_ptr().cast::<u8>().add(self.start), self.length)
        };
        engine::random_fill(bytes).map_err(engine_error)
    }
}

/// Turns a `CryptoError` into the job error Node would report.
///
/// A random failure has nothing on the OpenSSL queue in practice, but the shape
/// is the same either way: `CryptoErrorStore` captures whatever is there and
/// falls back to `ERR_CRYPTO_OPERATION_FAILED`.
pub fn engine_error(error: engine::CryptoError) -> CryptoJobError {
    openssl_error().map_or_else(
        || CryptoJobError::operation_failed(&error.to_string()),
        |detail| {
            CryptoJobError::OpenSsl(OpenSslDetail {
                packed: detail.packed,
                code: detail.code(),
                library: detail.library_display,
                reason: detail.reason,
                message: detail.message,
            })
        },
    )
}

/// [`engine_error`] for a failure the `openssl` crate already drained.
///
/// `openssl`'s helpers move the queue into the returned `ErrorStack`, so by the
/// time a caller has one, `ERR_peek_error` sees nothing. The stack's entries are
/// therefore the detail, and its first is the root cause — the one
/// `ThrowCryptoError` reports. A stack with no entries at all falls back to
/// `ERR_CRYPTO_OPERATION_FAILED` with the caller's message, which is what
/// `CryptoErrorStore` does when it captured nothing.
pub fn stack_error(stack: &openssl::error::ErrorStack) -> CryptoJobError {
    stack_error_named(stack, "could not generate prime")
}

/// [`stack_error`] with the caller's own fallback message.
///
/// The fallback only appears when OpenSSL queued nothing, so the message is the
/// operation's name rather than a fixed one: "could not generate prime" would be
/// a lie from `Argon2Job`.
pub fn stack_error_named(stack: &openssl::error::ErrorStack, fallback: &str) -> CryptoJobError {
    // `Error::code()` is already the packed `ERR_get_error` value; the `openssl`
    // crate keeps it verbatim and only splits it for `library()`/`reason()`.
    let Some(error) = stack.errors().first() else {
        return CryptoJobError::operation_failed(fallback);
    };
    let packed = error.code();
    match rn_crypto_openssl::openssl_error_for(packed) {
        Some(detail) => CryptoJobError::OpenSsl(OpenSslDetail {
            packed,
            code: detail.code(),
            library: detail.library_display,
            reason: detail.reason,
            message: detail.message,
        }),
        None => CryptoJobError::operation_failed(&stack.to_string()),
    }
}

/// `new RandomPrimeJob(mode, size, safe, add, rem)`.
///
/// The output is an `ArrayBuffer` of exactly `ceil(size / 8)` bytes holding the
/// prime big-endian, which is `RandomPrimeTraits::EncodeOutput`'s
/// `BignumPointer::EncodePaddedInto` at the prime's byte length.
pub struct RandomPrimeJob {
    /// The requested bit length, which `assertSize` has already validated as a
    /// positive int32.
    bits: u32,
    safe: bool,
    add: Option<openssl::bn::BigNum>,
    rem: Option<openssl::bn::BigNum>,
}

impl RandomPrimeJob {
    /// Reads the four arguments after the mode.
    ///
    /// `add` and `rem` are buffers of an unsigned big-endian integer, or absent.
    /// Node's checks live here rather than in the constructor's caller because
    /// `random.js` passes the raw buffers through: an `add` wider than `size`
    /// bits, or a `rem >= add`, would make OpenSSL loop forever, so both are
    /// rejected before the work is queued.
    pub fn from_arguments<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        args: &v8::FunctionCallbackArguments<'s>,
    ) -> Option<Self> {
        let bits = args.get(1).uint32_value(scope).unwrap_or(0);
        let safe = args.get(2).is_true();
        let add = big_num_argument(scope, args.get(3))?;
        let rem = big_num_argument(scope, args.get(4))?;

        if let Some(add) = &add {
            if add.num_bits() as u32 > bits {
                // Both rejections are `ERR_OUT_OF_RANGE` thrown synchronously
                // from the constructor, not delivered to `ondone`: `random.js`
                // builds the job inside `createRandomPrimeJob`, whose caller has
                // no try/catch, so this is the throw path.
                throw_range(scope, "invalid options.add");
                return None;
            }
            if let Some(rem) = &rem {
                if add <= rem {
                    throw_range(scope, "invalid options.rem");
                    return None;
                }
            }
        }
        Some(Self {
            bits,
            safe,
            add,
            rem,
        })
    }
}

impl Runnable for RandomPrimeJob {
    type Output = Vec<u8>;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        let mut prime = openssl::bn::BigNum::new()
            .map_err(|_| CryptoJobError::operation_failed("could not generate prime"))?;
        // `BN_generate_prime_ex`, the call `BignumPointer::generate` makes.
        prime
            .generate_prime(
                self.bits as i32,
                self.safe,
                self.add.as_ref().map(|value| value.as_ref()),
                self.rem.as_ref().map(|value| value.as_ref()),
            )
            .map_err(|stack| stack_error(&stack))?;
        // `EncodeOutput` allocates `ceil(bits / 8)` bytes and pads the prime into
        // them, so a prime whose top byte happened to be zero is *not* shortened.
        // `generatePrime` compares the byte length in several Node tests, and
        // `sync`/`async` must agree with each other.
        let width = self.bits.div_ceil(8) as usize;
        prime
            .to_vec_padded(width as i32)
            .map_err(|_| CryptoJobError::operation_failed("could not generate prime"))
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        // An `ArrayBuffer`, not a `Buffer`: `random.js` wraps the result itself
        // (`job.result = arrayBufferToUnsignedBigInt` for the bigint form) and
        // `generatePrimeSync` is documented to return an `ArrayBuffer`.
        encoding::array_buffer(scope, &output).map(v8::Local::into)
    }
}

/// `new CheckPrimeJob(mode, candidate, checks)`.
///
/// The output is a boolean; `CheckPrimeTraits::EncodeOutput` builds it from the
/// single byte `isPrime` wrote.
pub struct CheckPrimeJob {
    candidate: openssl::bn::BigNum,
    checks: i32,
}

impl CheckPrimeJob {
    /// Reads the candidate and the check count.
    pub fn from_arguments<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        args: &v8::FunctionCallbackArguments<'s>,
    ) -> Option<Self> {
        let bytes = match buffer_bytes(args.get(1)) {
            Some(bytes) => bytes,
            None => {
                throw_type(
                    scope,
                    "The \"candidate\" argument must be an ArrayBufferView",
                );
                return None;
            }
        };
        let candidate = openssl::bn::BigNum::from_slice(&bytes)
            .map_err(|_| ())
            .ok()?;
        let checks = args.get(2).int32_value(scope).unwrap_or(0);
        Some(Self { candidate, checks })
    }
}

impl Runnable for CheckPrimeJob {
    type Output = bool;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        let mut context = openssl::bn::BigNumContext::new().map_err(|stack| stack_error(&stack))?;
        self.candidate
            .is_prime(self.checks, &mut context)
            .map_err(|stack| stack_error(&stack))
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        Some(v8::Boolean::new(scope, output).into())
    }
}

/// Reads a buffer argument as a `BigNum`, treating an absent one as absent.
///
/// Returns `Some(None)` for `undefined`/`null`, which is how `random.js` passes
/// "no options.add". A present but unreadable value is a programming error: the
/// JavaScript has already checked it is a buffer source.
fn big_num_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Option<openssl::bn::BigNum>> {
    if value.is_undefined() || value.is_null() {
        return Some(None);
    }
    let Some(bytes) = buffer_bytes(value) else {
        throw_range(scope, "invalid options.add");
        return None;
    };
    match openssl::bn::BigNum::from_slice(&bytes) {
        Ok(number) => Some(Some(number)),
        Err(_) => {
            // `BignumPointer(add.data, add.size)` failing is
            // `ERR_CRYPTO_OPERATION_FAILED` in Node's `AdditionalConfig`, but
            // the only way to reach it is an allocation failure, so the
            // constructor reports the same code it would.
            throw_range(scope, "invalid options.add");
            None
        }
    }
}

/// Copies the bytes behind a buffer source.
fn buffer_bytes(value: v8::Local<'_, v8::Value>) -> Option<Vec<u8>> {
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

/// The backing store, byte offset and length of a buffer source.
fn view_store(
    value: v8::Local<'_, v8::Value>,
) -> Option<(v8::SharedRef<v8::BackingStore>, usize, usize)> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let store = view.get_backing_store()?;
        return Some((store, view.byte_offset(), view.byte_length()));
    }
    let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
    let store = buffer.get_backing_store();
    let length = buffer.byte_length();
    Some((store, 0, length))
}

/// Throws the `ERR_OUT_OF_RANGE` a `RangeError` carries.
fn throw_range(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::range_error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let (Some(key), Some(code)) = (
            v8::String::new(scope, "code"),
            v8::String::new(scope, "ERR_OUT_OF_RANGE"),
        ) {
            object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws a `TypeError` from a job callback.
///
/// `crate::install` owns the one implementation every member of the namespace
/// uses, so this is a re-export rather than a second copy — a copy is how two
/// members end up with two different messages for the same rejection.
pub fn throw_type(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    crate::install::throw_type_error(scope, message);
}

/// The mode a job was constructed with, read from slot 0.
///
/// `lib/**` passes `kCryptoJob*`, and a value outside the three is a CHECK in
/// Node. Reported as a throw here so a bad mode cannot silently pick a path.
pub fn mode_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<JobMode> {
    match JobMode::from_raw(args.get(0).int32_value(scope).unwrap_or(-1)) {
        Some(mode) => Some(mode),
        None => {
            throw_type(scope, "Unsupported CryptoJobMode");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_prime_width_is_ceil_of_the_bit_length() {
        // `EncodeOutput` sizes the buffer at `ceil(bits / 8)`, and both
        // `generatePrime` and `generatePrimeSync` compare it. A prime returned at
        // its natural width would be one byte short whenever the top byte is
        // zero, which is a 1-in-256 failure rather than a 1-in-a-million one.
        for (bits, width) in [(8, 1), (16, 2), (9, 2), (64, 8), (1, 1), (127, 16)] {
            assert_eq!((bits as u32).div_ceil(8) as usize, width, "{bits} bits");
        }
    }
}
