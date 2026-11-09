//! `TCPConnectWrap` and the `WriteWrap` factory.
//!
//! `TCPConnectWrap` is `AsyncWrap::MakeLazilyInitializedJSTemplate(env)`: a plain
//! constructor with one internal field and no prototype methods. `lib/net.js`
//! constructs one per connection attempt and assigns `oncomplete`,
//! `address`, `port`, `localAddress`, `localPort` and `addressType` before
//! calling `handle.connect(req, address, port)`.
//!
//! `WriteWrap` belongs to `internalBinding('stream_wrap')`, but a write path here
//! needs a fresh one when `lib/internal/stream_base_commons.js` passes `null` as
//! the request. Rather than reach across crates for the template, the write paths
//! construct one through the `stream_wrap` namespace's own constructor: it is the
//! same object shape either way.

use libuv_sys2 as uv;
use rn_v8_sys::v8;

/// Builds the `TCPConnectWrap` constructor.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(connect_wrap_new)
        .length(0)
        .build(scope);
    // `AsyncWrap::MakeLazilyInitializedJSTemplate` produces a class with one
    // internal field and no methods.
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let Some(name) = v8::String::new(scope, "TCPConnectWrap") else {
        return Err("cannot allocate the TCPConnectWrap class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate TCPConnectWrap")?;
    function.set_name(name);
    Ok(function.into())
}

/// The `TCPConnectWrap` constructor callback.
///
/// Node's template has no constructor body beyond `AsyncWrap`'s bookkeeping, and
/// `lib/net.js` only ever writes properties onto the result, so there is nothing
/// to do here.
fn connect_wrap_new(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    rv.set(object.into());
}

/// Builds a fresh `WriteWrap` for a write whose caller passed no request object.
///
/// This is `StreamBase::Write`'s
/// `env->write_wrap_template()->InstanceTemplate()->NewInstance()` path. The
/// object it returns is what `lib/internal/stream_base_commons.js` attaches
/// `oncomplete` to, so the field set has to match
/// `crates/rn-bind-stream-wrap/src/wrap.rs`.
pub fn new_write_wrap<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    // The fields `afterWriteDispatched` reads, pre-created so the object shape is
    // the same one the constructor produces.
    let null = v8::null(scope);
    for name in ["oncomplete", "callback", "handle", "buffer", "writeStatus"] {
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), null.into());
    }
    let async_key = v8::String::new(scope, "async")?;
    object.set(
        scope,
        async_key.into(),
        v8::Boolean::new(scope, false).into(),
    );
    let bytes_key = v8::String::new(scope, "bytes")?;
    object.set(scope, bytes_key.into(), v8::Integer::new(scope, 0).into());
    Some(object)
}

/// `uv_buf_t` is `#[repr(C)]` in libuv; this only exists so the type is named in
/// one place.
pub type Buffer = uv::uv_buf_t;
