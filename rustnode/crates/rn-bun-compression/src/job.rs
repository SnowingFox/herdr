//! The threadpool half of `Bun.zstdCompress` and `Bun.zstdDecompress`.
//!
//! The work is queued with `uv_queue_work` and the promise is settled from the
//! completion, so the ordering is Bun's and not merely the bytes: measured on
//! 1.4.4, the promise is unresolved when the call returns, a `.then` on it runs in
//! the microtask checkpoint of the completion, and a 40 MiB compression does not
//! block a 1 ms interval timer.
//!
//! # Why not reuse `rn-crypto-job`
//!
//! That crate implements Node's `CryptoJob` three-mode protocol — a `job.run()`
//! returning `[err, value]`, an `ondone` callback, and a WebCrypto rejection shape
//! — and its error type is `CryptoJobError`, whose constructors all produce
//! `ERR_CRYPTO_*` codes. Neither the modes nor the error family is this group's:
//! there are two modes here (both promise), and the errors are `ERR_ZSTD` or a
//! plain `Error` with no code. Adapting it would mean a `Runnable` whose `run`
//! returns a `CryptoJobError` that has to be re-tagged as `ERR_ZSTD` at the
//! boundary, which is a worse seam than this small direct implementation.
//!
//! What *is* reused is everything that makes a queued completion correct: the
//! request is registered with [`rn_uv::threadpool`] so `process.exit()` cancels
//! it, and delivery goes through [`rn_uv::callback::with_context`], which is the
//! one primitive in this workspace that re-enters V8 from inside `uv_run`.
//! `rn-bind-fs`'s `jobs.rs` and `rn-crypto-job` are the reference shapes.

use std::sync::Mutex;

use rn_v8_sys::v8;

use crate::args;
use crate::error::CompressionError;
use crate::zstd_codec;

/// What a queued member computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Compress { level: i32 },
    Decompress,
}

/// One queued request: the bytes, what to do with them, and where the answer goes.
pub struct Work {
    input: Vec<u8>,
    kind: Kind,
}

impl Work {
    pub fn compress(input: Vec<u8>, level: i32) -> Self {
        Self {
            input,
            kind: Kind::Compress { level },
        }
    }

    pub fn decompress(input: Vec<u8>) -> Self {
        Self {
            input,
            kind: Kind::Decompress,
        }
    }

    fn run(&self) -> Result<Vec<u8>, CompressionError> {
        match self.kind {
            Kind::Compress { level } => zstd_codec::compress(&self.input, level),
            Kind::Decompress => zstd_codec::decompress(&self.input),
        }
    }
}

/// The state an in-flight request owns.
///
/// Boxed and handed to libuv. Every field is a `Mutex` because the work callback
/// runs on a pool thread and the completion runs on the loop's thread: the input
/// crosses one way and the result the other, and the promise handle is only ever
/// touched on the loop thread.
struct Queued {
    /// Taken by the work callback, put back afterwards so the completion can read
    /// the kind without a second copy of it.
    work: Mutex<Option<Work>>,
    /// The computed result, written on the pool thread and taken on the loop.
    result: Mutex<Option<Result<Vec<u8>, CompressionError>>>,
    /// The promise `schedule` returned, rooted so it survives a collection while
    /// the work is in flight.
    resolver: Mutex<Option<v8::Global<v8::PromiseResolver>>>,
}

impl Queued {
    /// Takes a field out of its `Mutex`, recovering from a poisoned lock.
    ///
    /// A poison means a previous holder panicked. The values already stored are
    /// still owned and still valid, so recovering is better than losing them and
    /// leaving a promise unsettled forever.
    fn take<T>(slot: &Mutex<Option<T>>) -> Option<T> {
        match slot.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

/// Creates the promise and queues `work`.
///
/// Returns the promise, or a JavaScript value if the promise could not be created
/// (`Bun` is being installed in an isolate V8 refused to give a resolver for,
/// which leaves an exception pending).
pub fn schedule<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    work: Work,
) -> Result<v8::Local<'s, v8::Value>, CompressionError> {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        return Err(CompressionError::Zstd {
            reason: "cannot create the promise".to_string(),
            decompress: true,
        });
    };
    let promise = resolver.get_promise(scope);

    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        // No loop means no threadpool and no completion to settle the promise
        // with, so the failure is delivered now rather than leaving it pending
        // forever. Node's own jobs reject in the same position.
        let error = CompressionError::Zstd {
            reason: "no event loop is available".to_string(),
            decompress: matches!(work.kind, Kind::Decompress),
        };
        let exception = error.exception(scope);
        resolver.reject(scope, exception);
        return Ok(promise.into());
    };

    let state = Box::into_raw(Box::new(Queued {
        work: Mutex::new(Some(work)),
        result: Mutex::new(None),
        resolver: Mutex::new(Some(v8::Global::new(scope.as_ref(), resolver))),
    }));

    let mut request: Box<libuv_sys2::uv_work_t> = Box::new(unsafe { std::mem::zeroed() });
    request.data = state.cast();
    let request = Box::into_raw(request);
    // Visible to the exit path, which cancels it if `process.exit()` runs while
    // this job is still queued.
    rn_uv::threadpool::register(request);

    // SAFETY: `loop_pointer` is the process loop, which outlives the request;
    // `request` is heap-allocated and stays valid until the after-work callback
    // frees it.
    let queued = unsafe {
        libuv_sys2::uv_queue_work(
            loop_pointer,
            request,
            Some(work_trampoline),
            Some(after_work_trampoline),
        )
    };
    if queued != 0 {
        // The loop refused the work, so no callback will arrive. Both boxes are
        // freed here and the promise is rejected inline, which keeps the
        // contract either way: the caller always gets a settled promise.
        rn_uv::threadpool::unregister(request);
        // SAFETY: neither box was handed on; libuv took no ownership on failure.
        let state = unsafe { Box::from_raw(state) };
        unsafe { drop(Box::from_raw(request)) };
        let resolver = Queued::take(&state.resolver);
        if let Some(resolver) = resolver {
            let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &resolver);
            let error = CompressionError::Zstd {
                reason: "cannot queue the job".to_string(),
                decompress: false,
            };
            let exception = error.exception(scope);
            resolver.reject(scope, exception);
        }
    }

    Ok(promise.into())
}

/// The threadpool half: runs the codec off the main thread.
///
/// # Safety
///
/// `request` must be the `uv_work_t` [`schedule`] allocated, whose `data` is the
/// `Queued` box for this job.
unsafe extern "C" fn work_trampoline(request: *mut libuv_sys2::uv_work_t) {
    // SAFETY: per the contract above, `data` is the box `schedule` created, and
    // libuv calls the work callback exactly once per queued request.
    let state = unsafe { &*((*request).data as *mut Queued) };
    let outcome = match state.work.lock() {
        Ok(slot) => match slot.as_ref() {
            Some(work) => work.run(),
            // Taken twice would be a libuv contract violation; there is nothing
            // to run, so the failure is reported rather than panicking on a pool
            // thread.
            None => Err(CompressionError::Zstd {
                reason: "the job ran twice".to_string(),
                decompress: false,
            }),
        },
        Err(poisoned) => match poisoned.into_inner().as_ref() {
            Some(work) => work.run(),
            None => Err(CompressionError::Zstd {
                reason: "the job ran twice".to_string(),
                decompress: false,
            }),
        },
    };
    let mut slot = match state.result.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    *slot = Some(outcome);
}

/// The loop half: turns the result into a settled promise.
///
/// # Safety
///
/// As [`work_trampoline`].
unsafe extern "C" fn after_work_trampoline(
    request: *mut libuv_sys2::uv_work_t,
    status: std::ffi::c_int,
) {
    // SAFETY: `state` and `request` were created by `schedule` and are freed
    // here, exactly once, now that no other callback will use them.
    let state = unsafe { Box::from_raw((*request).data as *mut Queued) };
    rn_uv::threadpool::unregister(request);
    unsafe { drop(Box::from_raw(request)) };

    let Some(resolver) = Queued::take(&state.resolver) else {
        return;
    };
    // A cancelled request (`UV_ECANCELED`) ran no work. `process.exit()` is the
    // only route to that, and the process is going away, so there is nothing
    // left to settle — but settling it is still cheaper than reasoning about a
    // promise nobody can observe.
    let outcome = if status == libuv_sys2::uv_errno_t_UV_ECANCELED {
        Err(CompressionError::Zstd {
            reason: "the job was cancelled".to_string(),
            decompress: false,
        })
    } else {
        Queued::take(&state.result).unwrap_or_else(|| {
            Err(CompressionError::Zstd {
                reason: "the job produced no result".to_string(),
                decompress: false,
            })
        })
    };

    // The completion runs inside `uv_run`, which has no V8 scope and no entered
    // context, so settling goes through the same primitive the socket and fs
    // bindings use.
    rn_uv::callback::with_context(|scope| {
        let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &resolver);
        match outcome {
            Ok(bytes) => match args::buffer(scope, bytes) {
                Some(value) => {
                    resolver.resolve(scope, value);
                }
                None => {
                    let error = CompressionError::Zstd {
                        reason: "the result could not be built".to_string(),
                        decompress: false,
                    };
                    let exception = error.exception(scope);
                    resolver.reject(scope, exception);
                }
            },
            Err(error) => {
                let exception = error.exception(scope);
                resolver.reject(scope, exception);
            }
        }
    });
}
