//! Shared V8 plumbing for the two namespaces.

use rn_v8_sys::v8;

use crate::value::{Member, Value};

/// Creates a JavaScript string, mapping a failed allocation to a plain error.
pub(crate) fn string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, value).ok_or_else(|| format!("could not allocate string {value:?}"))
}

/// Defines one read-only property on `object`.
///
/// Node's `READONLY_PROPERTY` passes exactly `v8::ReadOnly`: the property stays
/// enumerable and configurable, while assignment throws from strict-mode code.
/// `install_constant` below is the `NODE_DEFINE_CONSTANT` variant, which
/// additionally passes `DontDelete`; the two namespaces differ and keep
/// separate entry points.
pub(crate) fn install_readonly(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: Value,
) -> Result<(), String> {
    let key = string(scope, name)?;
    let value = to_v8(scope, value)?;
    object
        .define_own_property(scope, key.into(), value, v8::PropertyAttribute::READ_ONLY)
        .ok_or_else(|| format!("could not define property {name:?}"))?;
    Ok(())
}

/// Defines one `DontDelete | ReadOnly` constant, as `NODE_DEFINE_CONSTANT` does.
pub(crate) fn install_constant(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: Value,
) -> Result<(), String> {
    let key = string(scope, name)?;
    let value = to_v8(scope, value)?;
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

/// Converts a namespace value into a V8 value.
fn to_v8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: Value,
) -> Result<v8::Local<'s, v8::Value>, String> {
    Ok(match value {
        Value::Num(number) => v8::Number::new(scope, number).into(),
        Value::Bool(flag) => v8::Boolean::new(scope, flag).into(),
        Value::Str(text) => string(scope, text)?.into(),
    })
}

/// Creates a null-prototype object populated with a constant table.
pub(crate) fn table_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    table: &[Member],
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = null_proto_object(scope);
    for (name, value) in table {
        install_constant(scope, object, name, *value)?;
    }
    Ok(object)
}

/// Creates a plain object with no prototype, as Node does for `constants`
/// sub-objects (`v8::Object::New` with a `null` prototype).
pub(crate) fn null_proto_object<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Object> {
    let null = v8::null(scope);
    v8::Object::with_prototype_and_properties(scope, null.into(), &[], &[])
}
