//! V8 plumbing shared by the namespaces's members.
//!
//! Three Node idioms appear throughout `src/node_options.cc` and each maps to
//! a specific property attribute, so they get separate entry points rather
//! than one generic setter:
//!
//! * `NODE_DEFINE_CONSTANT` — `ReadOnly | DontDelete`, used for `envSettings`
//!   and `types`.
//! * `Object::New(isolate, null, names, values, n)` — a null-prototype object
//!   built with all its properties at once, used for every returned object and
//!   for each option's info. Building it in one call matters: the property
//!   order is observable through `Object.keys`.
//! * `SetMethodNoSideEffect` — a plain data property holding a function.

use rn_v8_sys::v8;

/// Creates a JavaScript string, mapping a failed allocation to a plain error.
pub(crate) fn string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, value).ok_or_else(|| format!("could not allocate string {value:?}"))
}

/// Creates a null-prototype object with every property set at construction.
///
/// Node passes the whole name/value array to `Object::New`, so the properties
/// exist in that order from the start. Setting them one by one would produce
/// the same contents but a different observable order once an inherited
/// setter or a numeric-looking key enters the picture, so the array form is
/// kept.
pub(crate) fn object_with<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    properties: &[(&str, v8::Local<'s, v8::Value>)],
) -> Result<v8::Local<'s, v8::Object>, String> {
    let mut names = Vec::with_capacity(properties.len());
    let mut values = Vec::with_capacity(properties.len());
    for (name, value) in properties {
        names.push(string(scope, name)?.into());
        values.push(*value);
    }
    let null = v8::null(scope);
    Ok(v8::Object::with_prototype_and_properties(
        scope,
        null.into(),
        &names,
        &values,
    ))
}

/// Defines one `DontDelete | ReadOnly` constant on an ordinary object.
///
/// `NODE_DEFINE_CONSTANT` passes exactly `ReadOnly | DontDelete`, and V8
/// derives the rest: the property is non-writable, enumerable, and
/// non-configurable, so assigning to it from strict-mode code throws and
/// `delete` fails. `types` in particular is read with `ObjectKeys` by
/// `lib/internal/main/print_help.js`, so dropping `enumerable` would silently
/// break `--help` even though the value would still be readable.
pub(crate) fn define_constant(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = string(scope, name)?;
    object
        .define_own_property(
            scope,
            key.into(),
            value,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| format!("could not define constant {name:?}"))?;
    Ok(())
}

/// Defines one method as an ordinary data property.
///
/// Node uses `SetMethodNoSideEffect`, which ends in `Set` with no attribute
/// argument: writable, enumerable and configurable. `lib/**` only calls these,
/// and `lib/internal/process/per_thread.js` destructures them once at load.
pub(crate) fn define_method(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = v8::FunctionTemplate::builder(callback)
        .build(scope)
        .get_function(scope)
        .ok_or_else(|| format!("could not create options.{name}"))?;
    let key = string(scope, name)?;
    object
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("could not define method {name:?}"))?;
    Ok(())
}

/// `{ host, port }`, the object a `kHostPort` option reports.
///
/// The host is borrowed rather than taken as a `&'static str` because a parsed
/// host name is owned by the store, while a table default is static; one
/// signature serves both without forcing the parser to leak its strings.
pub(crate) fn host_port_to_v8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    host: &str,
    port: u16,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let host = string(scope, host)?;
    let port = v8::Integer::new(scope, i32::from(port));
    Ok(object_with(scope, &[("host", host.into()), ("port", port.into())])?.into())
}

/// Throws a JavaScript `Error` and leaves the return value unset.
///
/// `Environment::ThrowError` is a plain `v8::Exception::Error`, so no `code`
/// property is ever attached; `parseNodeOptionsEnvVar` adds one deliberately
/// and builds its own error instead of using this helper.
pub(crate) fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}
