//! Delivering a finished lookup back to JavaScript.
//!
//! Node dispatches `uv_getaddrinfo`/`uv_getnameinfo` onto the libuv threadpool
//! and reports completion from the loop, so the JavaScript that started a lookup
//! always runs to completion first. `lib/dns.js` depends on that: it assigns
//! `req.oncomplete` *after* calling into the binding (`dns.lookup`) or *before*
//! (`lookupService`), and only the deferred delivery makes both legal.
//!
//! rustnode has no event loop yet, so the resolution itself happens inline (see
//! `sys.rs`) and the *completion* is queued as a microtask. The observable
//! ordering is preserved exactly: the native call returns, the caller assigns its
//! handlers and returns, and only then does `oncomplete` run.
//!
//! What this does *not* provide is concurrency. A slow resolver blocks the
//! process instead of the threadpool, which is the same trade `rn-bind-fs` makes
//! and is recorded in the crate README.

use rn_permission::AccessDeniedError;
use rn_v8_sys::v8;

use crate::sys::LookupError;

/// What a finished lookup produced, in handles belonging to the delivering
/// scope.
pub(crate) enum Payload<'s> {
    /// `getaddrinfo`'s `(status, addresses)`. `None` in the error slot means
    /// success, which is `Integer::New(0)` in Node.
    Addresses(Result<v8::Local<'s, v8::Array>, LookupError>),
    /// `getnameinfo`'s `(status, hostname, service)`.
    NameInfo(Result<(v8::Local<'s, v8::String>, v8::Local<'s, v8::String>), LookupError>),
    /// A `ChannelWrap.query*` result: `(status, result, ttls)`.
    ///
    /// `result` is absent for the record types c-ares answers without a TTL
    /// array (`queryCname`, `querySoa`, and the plain-string queries), which is
    /// why the third argument is optional rather than always present.
    Query(QueryPayload<'s>),
    /// A denied `net` check: the `oncomplete` call receives the
    /// `ERR_ACCESS_DENIED` error object as its only argument.
    ///
    /// That is `SET_INSUFFICIENT_PERMISSION_ERROR_CALLBACK`, which does
    /// `MakeCallback(oncomplete, 1, &arg)` with the error rather than a status —
    /// so `lib/dns.js`'s `if (errCode)` branch reads `err.code` off the object
    /// itself, which is why a status code here would produce
    /// `Cannot read properties of null (reading 'code')`.
    PermissionDenied(AccessDeniedError),
}

/// The three arguments a `QueryReqWrap.oncomplete` call receives.
pub(crate) enum QueryPayload<'s> {
    Ok {
        result: v8::Local<'s, v8::Value>,
        ttls: Option<v8::Local<'s, v8::Array>>,
    },
    Err(i32),
}

/// A payload whose handles outlive the scope that produced it.
///
/// A deferred completion runs after the native call has returned and the
/// caller's handle scope has been popped, so every JS value has to be rooted.
/// Holding a `Local` across the boundary would leave V8 with a dangling handle.
enum Rooted {
    Addresses(Result<v8::Global<v8::Array>, i32>),
    NameInfo(Result<(v8::Global<v8::String>, v8::Global<v8::String>), i32>),
    Query(RootedQuery),
    PermissionDenied(AccessDeniedError),
}

enum RootedQuery {
    Ok {
        result: v8::Global<v8::Value>,
        ttls: Option<v8::Global<v8::Array>>,
    },
    Err(i32),
}

/// Owns everything the microtask needs across the native/JS boundary.
struct Delivery {
    request: v8::Global<v8::Object>,
    payload: Rooted,
}

/// Roots a payload while the producing scope is still alive.
fn root<'s>(scope: &mut v8::PinScope<'s, '_>, payload: Payload<'s>) -> Rooted {
    match payload {
        Payload::Addresses(Ok(addresses)) => {
            Rooted::Addresses(Ok(v8::Global::new(scope.as_ref(), addresses)))
        }
        Payload::Addresses(Err(error)) => Rooted::Addresses(Err(error.0)),
        Payload::PermissionDenied(denied) => Rooted::PermissionDenied(denied),
        Payload::NameInfo(Ok((hostname, service))) => Rooted::NameInfo(Ok((
            v8::Global::new(scope.as_ref(), hostname),
            v8::Global::new(scope.as_ref(), service),
        ))),
        Payload::NameInfo(Err(error)) => Rooted::NameInfo(Err(error.0)),
        Payload::Query(QueryPayload::Ok { result, ttls }) => Rooted::Query(RootedQuery::Ok {
            result: v8::Global::new(scope.as_ref(), result),
            ttls: ttls.map(|ttls| v8::Global::new(scope.as_ref(), ttls)),
        }),
        Payload::Query(QueryPayload::Err(status)) => Rooted::Query(RootedQuery::Err(status)),
    }
}

/// Queues `payload` as `request.oncomplete(...)` on the microtask queue.
///
/// `lib/dns.js` reads `oncomplete` off the request object at call time
/// (`MakeCallback(env->oncomplete_string(), ...)`), so the lookup happens then
/// rather than now; a request whose handler was never assigned is a no-op, which
/// is what Node does for an abandoned request too.
pub(crate) fn deliver<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    request: v8::Local<'s, v8::Object>,
    payload: Payload<'s>,
) {
    let request = v8::Global::new(scope.as_ref(), request);
    let payload = root(scope, payload);

    let boxed = Box::new(Delivery { request, payload });
    let pointer = Box::into_raw(boxed);
    let external = v8::External::new(scope, pointer.cast());
    let template = v8::FunctionTemplate::builder(trampoline)
        .data(external.into())
        .build(scope);
    let Some(function) = template.get_function(scope) else {
        // The microtask could not be created, so reclaim the box. The request
        // then never fires, which is the same outcome as Node dropping a
        // request it could not dispatch.
        // SAFETY: `pointer` came from `Box::into_raw` immediately above and was
        // never handed to the trampoline, so this is the only owning reference.
        unsafe { drop(Box::from_raw(pointer)) };
        return;
    };
    scope.as_mut().enqueue_microtask(function);
}

fn trampoline(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue<v8::Value>,
) {
    let Some(external) = v8::Local::<v8::External>::try_from(args.data()).ok() else {
        return;
    };
    // SAFETY: the pointer was produced by `Box::into_raw` in `deliver`, handed
    // to exactly one function template, and the microtask owning that template
    // runs at most once. Ownership is taken here so the box — and the `Global`s
    // inside it — is released on drop.
    let delivery = unsafe { Box::from_raw(external.value().cast::<Delivery>()) };

    let request: v8::Local<v8::Object> = v8::Local::new(scope, &delivery.request);
    let Some(key) = v8::String::new(scope, "oncomplete") else {
        return;
    };
    let Some(handler_value) = request.get(scope, key.into()) else {
        return;
    };
    let Ok(handler) = v8::Local::<v8::Function>::try_from(handler_value) else {
        return;
    };

    let arguments: Vec<v8::Local<v8::Value>> = match delivery.payload {
        Rooted::Addresses(Ok(addresses)) => {
            let addresses = v8::Local::new(scope, &addresses);
            vec![v8::Integer::new(scope, 0).into(), addresses.into()]
        }
        Rooted::Addresses(Err(status)) => {
            vec![
                v8::Integer::new(scope, status).into(),
                v8::null(scope).into(),
            ]
        }
        Rooted::NameInfo(Ok((hostname, service))) => {
            let hostname = v8::Local::new(scope, &hostname);
            let service = v8::Local::new(scope, &service);
            vec![
                v8::Integer::new(scope, 0).into(),
                hostname.into(),
                service.into(),
            ]
        }
        Rooted::NameInfo(Err(status)) => vec![
            v8::Integer::new(scope, status).into(),
            v8::null(scope).into(),
            v8::null(scope).into(),
        ],
        Rooted::Query(RootedQuery::Ok { result, ttls }) => {
            let result = v8::Local::new(scope, &result);
            match ttls {
                Some(ttls) => {
                    let ttls = v8::Local::new(scope, ttls);
                    vec![v8::Integer::new(scope, 0).into(), result, ttls.into()]
                }
                // `onresolve` reads `ttls[index]` only when the caller asked for
                // TTLs and the array is truthy, so `undefined` is the right
                // absent value: `dns.resolve4()` without `{ ttl: true }` must
                // not see an array of zeroes.
                None => vec![v8::Integer::new(scope, 0).into(), result],
            }
        }
        Rooted::Query(RootedQuery::Err(status)) => vec![
            v8::Integer::new(scope, status).into(),
            v8::null(scope).into(),
        ],
        // `MakeCallback(oncomplete, 1, &arg)`: the error object is the only
        // argument. `lib/dns.js` reads `err.code` off it directly.
        Rooted::PermissionDenied(denied) => vec![denied.to_value(scope)],
    };

    // `this` is the request object, matching `req_wrap->MakeCallback(...)`.
    let receiver: v8::Local<v8::Value> = request.into();
    // An exception thrown by the callback belongs to the caller's stack; V8
    // reports it through the microtask machinery, so the result is ignored.
    let _ = handler.call(scope, receiver, &arguments);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testsupport::with_context as with_scope;

    /// The whole point of the deferral: the handler must not run inside the
    /// native call, because `dns.lookup` assigns it afterwards.
    #[test]
    fn addresses_arrive_after_the_current_script() {
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = [];
                globalThis.req = {
                  oncomplete(status, addresses) {
                    seen.push([status, addresses && Array.from(addresses)]);
                  },
                };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, key.into())
                .expect("req")
                .try_into()
                .expect("object");

            let first = v8::String::new(scope, "127.0.0.1").expect("address");
            let addresses = v8::Array::new(scope, 1);
            addresses.set_index(scope, 0, first.into());
            deliver(scope, request, Payload::Addresses(Ok(addresses)));

            assert_eq!(seen_len(scope), 0, "completion must be deferred");
            scope.as_mut().perform_microtask_checkpoint();
            assert_eq!(seen_len(scope), 1, "completion must run once");

            let entry = seen_entry(scope);
            let status = entry.get_index(scope, 0).expect("status");
            assert_eq!(status.number_value(scope), Some(0.0));
            let addresses: v8::Local<v8::Array> = entry
                .get_index(scope, 1)
                .expect("addresses")
                .try_into()
                .expect("array");
            assert_eq!(addresses.length(), 1);
            let address = addresses.get_index(scope, 0).expect("address");
            assert_eq!(address.to_rust_string_lossy(scope), "127.0.0.1");
        });
    }

    /// The error shape is `(status, null)`, not `(null, status)`; `lib/dns.js`
    /// tests the first argument for truthiness.
    #[test]
    fn a_failed_lookup_reports_the_status_first_and_null_after() {
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = [];
                globalThis.req = {
                  oncomplete(status, addresses) {
                    seen.push([status, addresses === null ? 'null' : typeof addresses]);
                  },
                };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, key.into())
                .expect("req")
                .try_into()
                .expect("object");

            deliver(scope, request, Payload::Addresses(Err(LookupError(-3008))));
            scope.as_mut().perform_microtask_checkpoint();

            let entry = seen_entry(scope);
            let status = entry.get_index(scope, 0).expect("status");
            assert_eq!(status.number_value(scope), Some(-3008.0));
            let second = entry.get_index(scope, 1).expect("second");
            assert_eq!(second.to_rust_string_lossy(scope), "null");
        });
    }

    /// `lookupService`'s handler is assigned before the call, so it must receive
    /// `(0, hostname, service)` in that order.
    #[test]
    fn name_info_delivers_three_arguments() {
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = null;
                globalThis.req = {
                  oncomplete(status, hostname, service) {
                    globalThis.seen = [status, hostname, service];
                  },
                };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, key.into())
                .expect("req")
                .try_into()
                .expect("object");

            let hostname = v8::String::new(scope, "localhost").expect("hostname");
            let service = v8::String::new(scope, "http").expect("service");
            deliver(scope, request, Payload::NameInfo(Ok((hostname, service))));
            scope.as_mut().perform_microtask_checkpoint();

            let seen_key = v8::String::new(scope, "seen").expect("key");
            let seen: v8::Local<v8::Array> = global
                .get(scope, seen_key.into())
                .expect("seen")
                .try_into()
                .expect("array");
            assert_eq!(seen.length(), 3);
            let status = seen.get_index(scope, 0).expect("status");
            assert_eq!(status.number_value(scope), Some(0.0));
            let host = seen.get_index(scope, 1).expect("hostname");
            assert_eq!(host.to_rust_string_lossy(scope), "localhost");
            let svc = seen.get_index(scope, 2).expect("service");
            assert_eq!(svc.to_rust_string_lossy(scope), "http");
        });
    }

    /// A payload must survive the popped handle scope that created it, which
    /// only works because it was rooted in a `Global`.
    #[test]
    fn the_payload_survives_allocation_pressure() {
        with_scope(|scope| {
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = null;
                globalThis.req = {
                  oncomplete(status, hostname) { globalThis.seen = hostname; },
                };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let global = scope.get_current_context().global(scope);
            let key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, key.into())
                .expect("req")
                .try_into()
                .expect("object");

            let hostname = v8::String::new(scope, "a name that must survive").expect("hostname");
            let service = v8::String::new(scope, "80").expect("service");
            deliver(scope, request, Payload::NameInfo(Ok((hostname, service))));

            for index in 0..2_000 {
                let _ = v8::String::new(scope, &format!("garbage-{index}")).expect("alloc");
            }

            scope.as_mut().perform_microtask_checkpoint();
            let seen_key = v8::String::new(scope, "seen").expect("key");
            let seen = global.get(scope, seen_key.into()).expect("seen");
            assert_eq!(seen.to_rust_string_lossy(scope), "a name that must survive");
        });
    }

    /// A request with no handler is a no-op, not a crash.
    #[test]
    fn an_abandoned_request_does_not_run_a_callback() {
        with_scope(|scope| {
            let request = v8::Object::new(scope);
            deliver(scope, request, Payload::Addresses(Err(LookupError(-3008))));
            scope.as_mut().perform_microtask_checkpoint();
        });
    }

    fn seen_len(scope: &mut v8::PinScope<'_, '_>) -> u32 {
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "seen").expect("key");
        let seen: v8::Local<v8::Array> = global
            .get(scope, key.into())
            .expect("seen")
            .try_into()
            .expect("array");
        seen.length()
    }

    fn seen_entry<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Array> {
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "seen").expect("key");
        let seen: v8::Local<v8::Array> = global
            .get(scope, key.into())
            .expect("seen")
            .try_into()
            .expect("array");
        seen.get_index(scope, 0)
            .expect("entry")
            .try_into()
            .expect("array")
    }
}
