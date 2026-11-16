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
    // `READONLY_PROPERTY` is `ReadOnly | DontDelete` inverted: enumerable and
    // configurable. `new_from_value_writable` leaves `enumerable` and
    // `configurable` at V8's `PropertyDescriptor` default of false, so both have
    // to be set, or `Object.keys(constants)` is empty and
    // `JSON.stringify(constants.measureMemory)` is `{}` where Node reports two
    // enum objects.
    let mut descriptor = v8::PropertyDescriptor::new_from_value_writable(value, false);
    descriptor.set_enumerable(true);
    descriptor.set_configurable(true);
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

    #[test]
    fn the_constants_are_enumerable_and_configurable_like_readonly_property() {
        // `READONLY_PROPERTY` in Node is `ReadOnly | DontDelete` inverted, so the
        // property is enumerable and configurable. `Object.keys` and
        // `JSON.stringify` both observe it: `vm.js` reads these through a
        // destructure that works either way, which is exactly why a wrong
        // attribute here is invisible until something enumerates the object.
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();

        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);

        let constants = value(scope);
        let constants =
            v8::Local::<v8::Object>::try_from(constants).expect("constants is an object");
        let measure_memory_key = v8::String::new(scope, "measureMemory").expect("key");
        let attributes = constants
            .get_property_attributes(scope, measure_memory_key.into())
            .expect("measureMemory is an own property");
        assert!(
            attributes.is_read_only(),
            "measureMemory is non-writable like READONLY_PROPERTY"
        );
        assert!(
            !attributes.is_dont_enum(),
            "measureMemory must be enumerable: Object.keys(constants) has it in Node"
        );
        assert!(
            !attributes.is_dont_delete(),
            "measureMemory must be configurable"
        );

        let measure_memory = constants
            .get(scope, measure_memory_key.into())
            .expect("measureMemory reads back");
        let measure_memory =
            v8::Local::<v8::Object>::try_from(measure_memory).expect("it is an object");
        for name in ["mode", "execution"] {
            let name_key = v8::String::new(scope, name).expect("key");
            let attributes = measure_memory
                .get_property_attributes(scope, name_key.into())
                .expect("nested property");
            assert!(
                !attributes.is_dont_enum(),
                "{name} must be enumerable or JSON.stringify drops it"
            );
        }
    }
}
