//! The `constants` member: the `measureMemory` mode and execution enums.
//!
//! `lib/vm.js` copies these out at module scope to build its own `mode` and
//! `execution` lookup tables, so both the numbers and the shape matter. The values
//! are V8's: `MeasureMemoryMode` has `SUMMARY = 0`, `DETAILED = 1`, and
//! `MeasureMemoryExecution` has `DEFAULT = 0`, `EAGER = 1`.
//!
//! Node defines the integers with `NODE_DEFINE_CONSTANT` (enumerable, non-writable,
//! non-configurable) and nests them under `constants.measureMemory.{mode,execution}`
//! with `READONLY_PROPERTY` (enumerable, non-writable, configurable). The nesting is
//! reproduced rather than flattened because `vm.js` reaches through it.

use rn_v8_sys::v8;

/// `MeasureMemoryMode`, from `v8::MeasureMemoryMode`.
pub const MODE_SUMMARY: i32 = 0;
pub const MODE_DETAILED: i32 = 1;

/// `MeasureMemoryExecution`, from `v8::MeasureMemoryExecution`.
pub const EXECUTION_DEFAULT: i32 = 0;
pub const EXECUTION_EAGER: i32 = 1;

/// Builds the `constants` object.
pub fn value<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let mode = enum_object(
        scope,
        &[("SUMMARY", MODE_SUMMARY), ("DETAILED", MODE_DETAILED)],
    );
    let execution = enum_object(
        scope,
        &[("DEFAULT", EXECUTION_DEFAULT), ("EAGER", EXECUTION_EAGER)],
    );

    let measure_memory = v8::Object::new(scope);
    readonly(scope, measure_memory, "mode", mode.into());
    readonly(scope, measure_memory, "execution", execution.into());

    let constants = v8::Object::new(scope);
    readonly(scope, constants, "measureMemory", measure_memory.into());
    constants.into()
}

/// An object of integer constants with `NODE_DEFINE_CONSTANT` attributes.
///
/// Returns an `Object` rather than a `Value` so the caller keeps the concrete type
/// and can pass it straight to [`readonly`].
fn enum_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[(&str, i32)],
) -> v8::Local<'s, v8::Object> {
    let object = v8::Object::new(scope);
    for (name, number) in entries {
        let Some(key) = v8::String::new(scope, name) else {
            continue;
        };
        let value: v8::Local<v8::Value> = v8::Integer::new(scope, *number).into();
        // `NODE_DEFINE_CONSTANT` is `Set(..., static_cast<PropertyAttribute>(
        // ReadOnly | DontDelete | DontEnum))`, inverted: the constant is
        // enumerable, non-writable and non-configurable.
        object.define_own_property(
            scope,
            key.into(),
            value,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }
    object
}

/// Defines `name` with `READONLY_PROPERTY` attributes: non-writable, enumerable,
/// configurable.
///
/// Written as a free function rather than a closure because a closure taking its
/// own `scope: &mut PinScope` parameter shadows the caller's, and the objects it
/// builds are then created in that inner scope and can be collected.
fn readonly(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) {
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    // `define_property` with a value-only descriptor leaves a later attribute
    // default in place, which is exactly `READONLY_PROPERTY`.
    let descriptor = v8::PropertyDescriptor::new_from_value_writable(value, false);
    object.define_property(scope, key.into(), &descriptor);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enums_are_v8s_numbers() {
        // `MeasureMemoryMode` and `MeasureMemoryExecution` are V8 enums; these
        // numbers are compared against what `lib/vm.js` derived from the same
        // constants, so changing one without the other silently picks the wrong
        // measurement mode.
        assert_eq!(MODE_SUMMARY, 0);
        assert_eq!(MODE_DETAILED, 1);
        assert_eq!(EXECUTION_DEFAULT, 0);
        assert_eq!(EXECUTION_EAGER, 1);
    }
}
