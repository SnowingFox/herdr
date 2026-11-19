//! Delivering a finished operation back to JavaScript.
//!
//! This is the part of the binding that has to reproduce Node's *asynchrony*
//! guarantee. Node's `uv_fs_*` calls complete on the event loop, so the
//! JavaScript that started them always runs to completion first. Callers rely on
//! that: `lib/fs.js` assigns `req.context` and `req.oncomplete` immediately after
//! calling into the binding, and `bindSignalToReq` assigns `oncomplete` after
//! `new FSReqCallback()`.
//!
//! rustnode performs the syscall inline (see `lib.rs` for why) but must not call
//! `oncomplete` inline. Completion is therefore queued as a microtask, which V8
//! runs after the current script returns to the top-level call depth. The
//! observable order — start call, assign handlers, then completion — is
//! preserved exactly.
//!
//! Promise mode resolves the same value a callback would have received, skipping
//! the error-first convention because a rejection carries the error.

use rn_v8_sys::v8;
use rn_v8_sys::v8::Local;

use crate::error::FsError;
use crate::request::error_object;

/// What a completed operation produced, in handles that belong to the scope
/// doing the delivering.
pub enum Payload<'s> {
    /// Resolves to `undefined`; callbacks get one argument.
    Unit,
    /// Resolves to one value; callbacks get `(null, value)`.
    Value(Local<'s, v8::Value>),
    /// Callbacks get a single `[first, second]` array; promises resolve to that
    /// array. Matching `FSReqCallback::Resolve(Pair)` is what `mkstemp` needs.
    Pair(Local<'s, v8::Value>, Local<'s, v8::Value>),
}

/// Why an operation produced no value.
///
/// Two kinds because the permission model's denial is not a syscall error: it
/// carries its own code and its own two fields, and `ERR_ACCESS_DENIED` is a
/// plain `Error` rather than a `UVException`. Delivering it through the
/// `FsError` path would give it an `errno` and a `syscall` Node never sets.
pub enum Failure {
    /// A syscall failed; delivered as the `UVException` shape.
    Syscall(FsError),
    /// The permission model refused the operation before any syscall ran.
    Denied(rn_permission::AccessDeniedError),
}

impl From<FsError> for Failure {
    fn from(error: FsError) -> Self {
        Self::Syscall(error)
    }
}

/// A completion ready to be delivered.
pub struct Completion<'s> {
    pub payload: Result<Payload<'s>, Failure>,
}

impl<'s> Completion<'s> {
    pub fn unit() -> Self {
        Self {
            payload: Ok(Payload::Unit),
        }
    }

    pub fn value(value: Local<'s, v8::Value>) -> Self {
        Self {
            payload: Ok(Payload::Value(value)),
        }
    }

    pub fn pair(first: Local<'s, v8::Value>, second: Local<'s, v8::Value>) -> Self {
        Self {
            payload: Ok(Payload::Pair(first, second)),
        }
    }

    pub fn failed(error: FsError) -> Self {
        Self {
            payload: Err(Failure::Syscall(error)),
        }
    }

    /// A completion that delivers `error` to whichever calling convention the
    /// request selected.
    pub fn denied(error: rn_permission::AccessDeniedError) -> Self {
        Self {
            payload: Err(Failure::Denied(error)),
        }
    }

    pub fn from_result(result: Result<(), FsError>) -> Self {
        match result {
            Ok(()) => Self::unit(),
            Err(error) => Self::failed(error),
        }
    }
}

/// A payload whose handles outlive the scope that produced it.
///
/// A deferred completion runs after the native call has returned and the
/// caller's handle scope has been popped, so every JS value it carries must be
/// rooted. Holding a `Local` here would leave V8 with a dangling handle, which
/// crashes on the next allocation that reuses the slot.
enum Rooted {
    Unit,
    Value(v8::Global<v8::Value>),
    Pair(v8::Global<v8::Value>, v8::Global<v8::Value>),
}

/// Owns everything the microtask needs across the native/JS boundary.
struct CallbackDelivery {
    request: v8::Global<v8::Object>,
    /// A [`Failure`] holds no V8 handles, so it survives the scope that
    /// produced it as-is; only the success payload has to be rooted.
    payload: Result<Rooted, Failure>,
    /// The request's `AsyncWrap` identity.
    ///
    /// `FSReqCallback` is an `AsyncWrap` (`src/node_file.cc:583`), so its
    /// `oncomplete` runs through `AsyncWrap::MakeCallback`: the completion
    /// pushes the request's async context, emits `before`, and emits `after` on
    /// the way out. Without the ids the `init` this request emitted has no
    /// matching `before`, which is what `test/async-hooks/init-hooks.js`'s
    /// `sanityCheck` reports as "expects 1 before".
    context: rn_core::callback_scope::AsyncContext,
}

/// Converts a completion into rooted handles.
///
/// Must be called while the producing scope is still alive.
fn root<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    completion: Completion<'s>,
) -> Result<Rooted, Failure> {
    match completion.payload {
        Ok(Payload::Unit) => Ok(Rooted::Unit),
        Ok(Payload::Value(value)) => {
            let global = v8::Global::new(scope.as_ref(), value);
            Ok(Rooted::Value(global))
        }
        Ok(Payload::Pair(first, second)) => {
            let first = v8::Global::new(scope.as_ref(), first);
            let second = v8::Global::new(scope.as_ref(), second);
            Ok(Rooted::Pair(first, second))
        }
        Err(failure) => Err(failure),
    }
}

/// Queues `completion` for a callback-style request object.
///
/// `request` is the `FSReqCallback` the JavaScript layer constructed, and this
/// is where that request becomes async-hook visible. Node creates the resource in
/// the C++ constructor:
///
/// ```text
/// FSReqBase(binding_data, req, AsyncWrap::PROVIDER_FSREQCALLBACK, use_bigint)
///   : ReqWrap(binding_data->env(), req, type)   // AsyncWrap ctor -> AsyncReset
/// ```
///
/// (`src/node_file-inl.h:53-60`, `:91-94`), and the reset emits `init` with
/// `FSREQCALLBACK` before `lib/fs.js` has even assigned `oncomplete`. Emitting it
/// here rather than in the constructor is the same resource with the same
/// trigger, because `lib/fs.js` calls the binding synchronously right after
/// `new FSReqCallback()` — the execution id has not changed in between.
pub fn deliver_to_callback<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: Local<'s, v8::Object>,
    completion: Completion<'s>,
) {
    // Root the payload and the request before the scope goes away.
    let request = v8::Global::new(scope.as_ref(), request);
    let payload = root(scope, completion);
    let context = begin_request(scope, &request);

    let boxed = Box::new(CallbackDelivery {
        request,
        payload,
        context,
    });
    let pointer = Box::into_raw(boxed);
    let external = v8::External::new(scope, pointer.cast());
    let template = rn_core::class(callback_trampoline)
        .data(external.into())
        .build(scope);
    let Some(function) = template.get_function(scope) else {
        // The microtask could not be created, so reclaim the box; the completion
        // is dropped and the request never fires, which is the same outcome as
        // Node dropping a cancelled request.
        // SAFETY: `pointer` came from `Box::into_raw` immediately above and was
        // never handed to the trampoline, so this is the only owning reference.
        unsafe { drop(Box::from_raw(pointer)) };
        return;
    };

    scope.as_mut().enqueue_microtask(function);
}

/// Creates and emits the `FSREQCALLBACK` resource for a request object.
///
/// The ids are written onto the object under `async_id_symbol` and
/// `trigger_async_id_symbol` as well as returned, because both readers exist:
/// `lib/fs.js`'s `bindSignalToReq` and the `destroy` bookkeeping read them, and
/// `node --expose-internals`'s `getAsyncId()` path does too.
///
/// A request whose ids are already present is *not* reset: `lib/fs.js` reuses
/// the `FSReqCallback` it constructed for the whole `open`/`fstat`/`read`
/// sequence of a chunked `readFile`, and each of those is a separate Node
/// request. `classify` hands the same object back for each, so the reset has to
/// happen per call — which is what Node's `ReqWrap::Dispatch` does not do either:
/// it constructs a *new* `FSReqCallback` per step. Here the object is reused, so
/// the reset is what makes each step its own `init`.
fn begin_request(
    scope: &mut v8::PinScope<'_, '_>,
    request: &v8::Global<v8::Object>,
) -> rn_core::callback_scope::AsyncContext {
    let object = v8::Local::new(scope, request);
    let (async_id, trigger_async_id) = rn_bind_async_wrap::emit_init_for_new_resource(
        scope,
        object,
        rn_core::async_wrap::PROVIDER_FSREQCALLBACK,
    )
    .unwrap_or((rn_core::INVALID_ASYNC_ID, rn_core::INVALID_ASYNC_ID));

    // `AsyncWrap::object()->Set(async_id_symbol, ...)` is what
    // `getAsyncId()`-style readers on the JS side expect; the symbols come from
    // the shared table so an id read back is the one the hook saw.
    if let (Ok(id_key), Ok(trigger_key)) = (
        rn_bind_symbols::ensure(scope, "async_id_symbol", "async_id_symbol"),
        rn_bind_symbols::ensure(scope, "trigger_async_id_symbol", "trigger_async_id_symbol"),
    ) {
        object.set(
            scope,
            id_key.into(),
            v8::Number::new(scope, async_id).into(),
        );
        object.set(
            scope,
            trigger_key.into(),
            v8::Number::new(scope, trigger_async_id).into(),
        );
    }

    rn_core::callback_scope::AsyncContext {
        async_id,
        trigger_async_id,
    }
}

fn callback_trampoline(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let Some(external) = Local::<v8::External>::try_from(args.data()).ok() else {
        return;
    };
    // SAFETY: the pointer was produced by `Box::into_raw` in
    // `deliver_to_callback`, handed to exactly one function template, and the
    // microtask that owns that template runs at most once. Ownership is taken
    // here so the box (and the `Global`s inside it) is released on drop.
    let delivery = unsafe { Box::from_raw(external.value().cast::<CallbackDelivery>()) };

    let request: Local<v8::Object> = Local::new(scope, &delivery.request);
    // `bindSignalToReq` marks the request cancelled and reports the abort
    // itself, so the queued completion must not run the handler again — that
    // would deliver a second, contradictory result for a call the caller already
    // settled.
    if let Some(cancelled) = v8::String::new(scope, "cancelled") {
        if request
            .get(scope, cancelled.into())
            .is_some_and(|value| value.is_true())
        {
            return;
        }
    }
    let Some(key) = v8::String::new(scope, "oncomplete") else {
        return;
    };
    let Some(handler_value) = request.get(scope, key.into()) else {
        return;
    };
    let Ok(handler) = Local::<v8::Function>::try_from(handler_value) else {
        // The JS layer assigns `oncomplete` before the completion is delivered,
        // so a non-function means the caller abandoned the request. Node treats
        // that as a no-op too.
        return;
    };

    let arguments: Vec<Local<v8::Value>> = match delivery.payload {
        Err(Failure::Syscall(error)) => match error_object(scope, &error) {
            Some(object) => vec![object],
            None => return,
        },
        Err(Failure::Denied(error)) => vec![error.to_value(scope)],
        Ok(Rooted::Unit) => vec![v8::null(scope).into()],
        Ok(Rooted::Value(value)) => {
            let value = Local::new(scope, &value);
            vec![v8::null(scope).into(), value]
        }
        Ok(Rooted::Pair(first, second)) => {
            let first = Local::new(scope, &first);
            let second = Local::new(scope, &second);
            let array = v8::Array::new_with_elements(scope, &[first, second]);
            vec![v8::null(scope).into(), array.into()]
        }
    };

    // `req_wrap->MakeCallback(oncomplete_string, argc, argv)` is what Node calls
    // (`src/node_file.cc:738`), and `MakeCallback` is what pushes the request's
    // async context and emits `before`/`after`. A bare `Function::Call` runs the
    // handler at whatever id happened to be current, so the `init` this request
    // emitted would never be followed by a `before` and `init-hooks.js`'s
    // `sanityCheck` reports the activity as unbalanced.
    let callback = v8::Global::new(scope.as_ref(), handler);
    let resource = v8::Global::new(scope.as_ref(), request);
    let receiver: Local<v8::Value> = request.into();
    let receiver = v8::Global::new(scope.as_ref(), receiver);
    let rooted: Vec<v8::Global<v8::Value>> = arguments
        .iter()
        .map(|argument| v8::Global::new(scope.as_ref(), *argument))
        .collect();

    let result = rn_core::callback_scope::with_scope(
        scope,
        rn_core::callback_scope::ScopeArgs {
            context: delivery.context,
            resource: Some(resource),
            frame: None,
        },
        |scoped| {
            let callback: Local<v8::Function> = Local::new(scoped, &callback);
            let receiver = Local::new(scoped, &receiver);
            let arguments: Vec<Local<v8::Value>> = rooted
                .iter()
                .map(|argument| Local::new(scoped, argument))
                .collect();
            let _ = callback.call(scoped, receiver, &arguments);
        },
    );

    // `FSReqBase::~FSReqBase` calls `EmitDestroy`, and it runs as the request
    // wrap is released after the callback. `with_scope` reports a throw itself
    // and still returns, so the destroy is emitted either way.
    let _ = result;
    rn_bind_async_wrap::emit_destroy(delivery.context.async_id);
}

/// Delivers `completion` by settling a promise created now.
///
/// Promise mode settles immediately: the promise is returned to JavaScript
/// before the script continues, and V8 queues the `then` callbacks itself, so the
/// ordering guarantee holds without a microtask of our own.
///
/// The promise is not the async resource Node reports for this call. A
/// `kUsePromises` binding call constructs an `FSReqPromise`, which is
/// `AsyncWrap(env, obj, PROVIDER_FSREQPROMISE)` (`src/node_file-inl.h:219-223`),
/// and only *that* object is resolved — so `fs.promises.stat` reports
/// `FSREQPROMISE` and not merely the `PROMISE` V8 emits for the promise itself.
/// `Resolve`/`Reject` settle it inside an `InternalCallbackScope`, so the wrap
/// gets a matching `before`/`after` pair, and the wrap is destroyed as the
/// completion returns.
///
/// The resource object is a plain object, which is also what Node hands over:
/// `FSReqPromise::New` allocates one and attaches the resolver to it as the
/// `promise` property.
pub fn deliver_to_promise<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    completion: Completion<'s>,
) -> Option<Local<'s, v8::Promise>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    let promise = resolver.get_promise(scope);

    // The resolver is rooted because the settle runs inside a scope of a
    // different lifetime and needs to reach the promise it belongs to.
    let resolver = v8::Global::new(scope.as_ref(), resolver);
    let resource = v8::Object::new(scope);
    let async_id = rn_bind_async_wrap::emit_init_for_new_resource(
        scope,
        resource,
        rn_core::async_wrap::PROVIDER_FSREQPROMISE,
    );
    let resource = v8::Global::new(scope.as_ref(), resource);
    let context = async_id.map(|(async_id, trigger_async_id)| {
        rn_core::callback_scope::AsyncContext {
            async_id,
            trigger_async_id,
        }
    });

    // `InternalCallbackScope callback_scope(this)` around the settle, which is
    // what makes the `FSREQPROMISE` id the one executing while `then` handlers
    // are queued.
    let payload = root(scope, completion);
    let settle = |scoped: &mut v8::PinScope<'_, '_>, payload: Result<Rooted, Failure>| {
        let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scoped, &resolver);
        settle_promise(scoped, resolver, payload);
    };
    match context {
        Some(context) => {
            let _ = rn_core::callback_scope::with_scope(
                scope,
                rn_core::callback_scope::ScopeArgs {
                    context,
                    resource: Some(resource),
                    frame: None,
                },
                |scoped| settle(scoped, payload),
            );
            rn_bind_async_wrap::emit_destroy(context.async_id);
        }
        None => settle(scope, payload),
    }

    Some(promise)
}

/// `FSReqPromise::Resolve` / `Reject`: settle the promise with the payload.
fn settle_promise<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    resolver: Local<'s, v8::PromiseResolver>,
    payload: Result<Rooted, Failure>,
) {
    match payload {
        Err(Failure::Syscall(error)) => {
            if let Some(object) = error_object(scope, &error) {
                resolver.reject(scope, object);
            }
        }
        Err(Failure::Denied(error)) => {
            let value = error.to_value(scope);
            resolver.reject(scope, value);
        }
        Ok(Rooted::Unit) => {
            resolver.resolve(scope, v8::undefined(scope).into());
        }
        Ok(Rooted::Value(value)) => {
            let value = Local::<v8::Value>::new(&*scope, &value);
            resolver.resolve(scope, value);
        }
        Ok(Rooted::Pair(first, second)) => {
            // `fs.mkstemp` destructures the pair, and promise mode must give it
            // the same shape the callback form delivers.
            let first = Local::<v8::Value>::new(&*scope, &first);
            let second = Local::<v8::Value>::new(&*scope, &second);
            let array = v8::Array::new_with_elements(scope, &[first, second]);
            resolver.resolve(scope, array.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::with_context as with_scope;

    #[test]
    fn callback_completion_runs_after_the_current_script() {
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.order = [];
                globalThis.req = {
                  oncomplete(err, value) { order.push(['callback', err, value]); },
                };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let req_key = v8::String::new(scope, "req").expect("key");
            let req_value = global.get(scope, req_key.into()).expect("req");
            let req: Local<v8::Object> = req_value.try_into().expect("object");

            let value = v8::Number::new(scope, 42.0);
            deliver_to_callback(scope, req, Completion::value(value.into()));

            let order_key = v8::String::new(scope, "order").expect("key");
            let order_value = global.get(scope, order_key.into()).expect("order");
            let order: Local<v8::Array> = order_value.try_into().expect("array");
            assert_eq!(order.length(), 0, "completion must be deferred");

            scope.as_mut().perform_microtask_checkpoint();

            let order_key = v8::String::new(scope, "order").expect("key");
            let order_value = global.get(scope, order_key.into()).expect("order");
            let order: Local<v8::Array> = order_value.try_into().expect("array");
            assert_eq!(order.length(), 1, "completion must run once");

            let entry = order.get_index(scope, 0).expect("entry");
            let entry: Local<v8::Array> = entry.try_into().expect("entry array");
            let name = entry.get_index(scope, 0).expect("name");
            assert_eq!(name.to_rust_string_lossy(scope), "callback");
            let error = entry.get_index(scope, 1).expect("err");
            assert!(error.is_null());
            // The value must survive the popped handle scope, which only works
            // because it was rooted in a `Global`.
            let value = entry.get_index(scope, 2).expect("value");
            assert_eq!(value.number_value(scope), Some(42.0));
        });
    }

    #[test]
    fn callback_payload_survives_allocation_pressure() {
        // A value that would be collected or relocated if the deferred payload
        // still pointed at a popped handle slot.
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = null;
                globalThis.req = { oncomplete(err, value) { globalThis.seen = value; } };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let req_key = v8::String::new(scope, "req").expect("key");
            let req_value = global.get(scope, req_key.into()).expect("req");
            let req: Local<v8::Object> = req_value.try_into().expect("object");

            let text = v8::String::new(scope, "a payload that must survive").expect("text");
            deliver_to_callback(scope, req, Completion::value(text.into()));

            // Churn the heap so any dangling handle would be overwritten.
            for index in 0..2_000 {
                let _ = v8::String::new(scope, &format!("garbage-{index}")).expect("alloc");
            }

            scope.as_mut().perform_microtask_checkpoint();

            let seen_key = v8::String::new(scope, "seen").expect("key");
            let seen = global.get(scope, seen_key.into()).expect("seen");
            assert_eq!(
                seen.to_rust_string_lossy(scope),
                "a payload that must survive"
            );
        });
    }

    #[test]
    fn callback_completion_reports_errors_first() {
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = null;
                globalThis.req = { oncomplete(err) { globalThis.seen = err; } };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let req_key = v8::String::new(scope, "req").expect("key");
            let req_value = global.get(scope, req_key.into()).expect("req");
            let req: Local<v8::Object> = req_value.try_into().expect("object");

            let error = FsError::from_errno("open", libc::ENOENT).path("/nope");
            deliver_to_callback(scope, req, Completion::failed(error));
            scope.as_mut().perform_microtask_checkpoint();

            let seen_key = v8::String::new(scope, "seen").expect("key");
            let seen = global.get(scope, seen_key.into()).expect("seen");
            let seen: Local<v8::Object> = seen.try_into().expect("object");
            let code_key = v8::String::new(scope, "code").expect("key");
            let code = seen.get(scope, code_key.into()).expect("code");
            assert_eq!(code.to_rust_string_lossy(scope), "ENOENT");
        });
    }

    #[test]
    fn promise_resolves_with_value() {
        with_scope(|scope| {
            let value = v8::Number::new(scope, 7.0);
            let promise =
                deliver_to_promise(scope, Completion::value(value.into())).expect("promise");
            assert_eq!(promise.state(), v8::PromiseState::Fulfilled);
            let result = promise.result(scope);
            assert_eq!(result.number_value(scope), Some(7.0));
        });
    }

    #[test]
    fn promise_rejects_with_error_object() {
        with_scope(|scope| {
            let error = FsError::from_errno("stat", libc::ENOENT).path("/nope");
            let promise = deliver_to_promise(scope, Completion::failed(error)).expect("promise");
            assert_eq!(promise.state(), v8::PromiseState::Rejected);
            let result = promise.result(scope);
            let object: Local<v8::Object> = result.try_into().expect("object");
            let code_key = v8::String::new(scope, "code").expect("key");
            let code = object.get(scope, code_key.into()).expect("code");
            assert_eq!(code.to_rust_string_lossy(scope), "ENOENT");
        });
    }

    #[test]
    fn promise_pair_mode_resolves_to_array() {
        with_scope(|scope| {
            let first = v8::Number::new(scope, 1.0);
            let second = v8::Number::new(scope, 2.0);
            let promise = deliver_to_promise(scope, Completion::pair(first.into(), second.into()))
                .expect("promise");
            assert_eq!(promise.state(), v8::PromiseState::Fulfilled);
            let result = promise.result(scope);
            let array: Local<v8::Array> = result.try_into().expect("array");
            assert_eq!(array.length(), 2);
            let zero = array.get_index(scope, 0).expect("first");
            assert_eq!(zero.number_value(scope), Some(1.0));
        });
    }

    #[test]
    fn abandoned_request_does_not_run_a_callback() {
        with_scope(|scope| {
            // A request object with no `oncomplete` must be a no-op, not a crash.
            let request = v8::Object::new(scope);
            deliver_to_callback(scope, request, Completion::unit());
            scope.as_mut().perform_microtask_checkpoint();
        });
    }
}
