//! `PipeConnectWrap`.
//!
//! `AsyncWrap::MakeLazilyInitializedJSTemplate(env)`: a plain constructor with
//! one internal field and no prototype methods. `lib/net.js` constructs one per
//! pipe connection attempt, assigns `address` and `oncomplete`, and passes it to
//! `handle.connect(req, path)`.

use rn_v8_sys::v8;

/// Builds the `PipeConnectWrap` constructor.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).length(0).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let Some(name) = v8::String::new(scope, "PipeConnectWrap") else {
        return Err("cannot allocate the PipeConnectWrap class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate PipeConnectWrap")?;
    function.set_name(name);
    Ok(function.into())
}

/// The `PipeConnectWrap` constructor callback.
///
/// Node's template has no constructor body beyond `AsyncWrap`'s bookkeeping, and
/// `lib/net.js` only writes properties onto the result.
fn new(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    rv.set(object.into());
}
