//! The `AsyncWrap` identity of a `CryptoJob` instance.
//!
//! Every job class in the `crypto` namespace derives from `CryptoJob`, which
//! derives from `AsyncWrap`:
//!
//! ```text
//! CryptoJob(env, object, type, mode, params)
//!   : AsyncWrap(env, object, type)     // -> AsyncReset -> EmitAsyncInit
//! ```
//!
//! (`src/crypto/crypto_util.h:339-345`), and its completion is
//! `ptr->MakeCallback(env->ondone_string(), ...)` (`:449-473`). So a job is an
//! async resource from construction to completion, and a hook that is enabled
//! before `crypto.randomBytes(n, cb)` sees `init` with `RANDOMBYTESREQUEST`, a
//! `before`/`after` pair around `ondone`, and a `destroy`.
//!
//! # Why the ids are stored on the instance
//!
//! Node keeps them in the C++ object behind the class's one internal field. Here
//! field 0 is the job parameters, and the completion runs after the
//! constructor's scope has gone, so the ids live in one more internal field as a
//! boxed [`rn_core::AsyncWrapState`] freed by the object's own finalizer.
//!
//! # Why two functions and not one
//!
//! `jobs.rs` (random, prime, Argon2) delivers through `rn-crypto-job`'s
//! threadpool `dispatch`, while `kdf.rs` computes inline and calls `ondone`
//! itself. Both need the same identity and both need the same
//! `InternalCallbackScope`, so the pair is here rather than duplicated.

use rn_v8_sys::v8;

/// The internal field a job's `AsyncWrapState` lives in.
///
/// Field 0 is the job's own parameters in every class, so this is the next slot.
pub const ASYNC_FIELD: i32 = 1;

/// How many internal fields a job class reserves.
pub const JOB_FIELDS: i32 = ASYNC_FIELD + 1;

/// `CryptoJob(env, object, type, ...) : AsyncWrap(env, object, type)`.
///
/// Emits `init` once and records the ids on `object`. A `None` return means the
/// `async_wrap` binding has not installed yet, which is the bootstrap state; the
/// job still runs, it just reports nothing.
pub fn begin(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    provider: u32,
) -> Option<rn_crypto_job::JobAsyncWrap> {
    let (async_id, trigger_async_id) =
        rn_bind_async_wrap::emit_init_for_new_resource(scope, object, provider)?;
    let state = Box::new(rn_core::AsyncWrapState {
        async_id,
        trigger_async_id,
        provider,
    });
    object.set_aligned_pointer_in_internal_field(
        ASYNC_FIELD,
        Box::into_raw(state).cast_const().cast(),
        0,
    );
    // SAFETY: the pointer was just written to this object's own field.
    let address =
        unsafe { object.get_aligned_pointer_from_internal_field(ASYNC_FIELD, 0) } as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut rn_core::AsyncWrapState;
            // SAFETY: allocated just above for this object alone, freed once by
            // the finalizer V8 guarantees to run.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    Some(rn_crypto_job::JobAsyncWrap {
        async_id,
        trigger_async_id,
    })
}

/// Reads back the identity [`begin`] stored, if the object carries one.
pub fn state_of(object: v8::Local<v8::Object>) -> Option<rn_crypto_job::JobAsyncWrap> {
    if object.internal_field_count() <= ASYNC_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer produced by `begin`, and the
    // object is live for the duration of this call.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(ASYNC_FIELD, 0) }
        as *const rn_core::AsyncWrapState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the allocation is owned by this object.
    let state = unsafe { *pointer };
    Some(rn_crypto_job::JobAsyncWrap {
        async_id: state.async_id,
        trigger_async_id: state.trigger_async_id,
    })
}

/// Runs `body` inside the job's async context, then queues its `destroy`.
///
/// This is `CryptoJob::AfterThreadPoolWork`'s `InternalCallbackScope` plus the
/// `unique_ptr` release that follows it. A job with no recorded identity runs
/// `body` unscoped, which is what the bootstrap path did before.
pub fn in_job_scope<R>(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> R,
) -> Option<R> {
    let async_wrap = state_of(object)?;
    if async_wrap.async_id <= 0.0 {
        return None;
    }
    let resource = v8::Global::new(scope.as_ref(), object);
    // `with_scope` returns `None` when the body threw, after reporting the
    // exception through `process._fatalException`. The scope itself did open,
    // so the destroy is still owed — that is why it is emitted outside the
    // `Option`.
    let result = rn_core::callback_scope::with_scope(
        scope,
        rn_core::callback_scope::ScopeArgs {
            context: async_wrap.context(),
            resource: Some(resource),
            frame: None,
        },
        body,
    );
    rn_bind_async_wrap::emit_destroy(async_wrap.async_id);
    result
}
