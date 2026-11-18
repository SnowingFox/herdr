//! `measureMemory`, the member behind `vm.measureMemory()`.
//!
//! `lib/vm.js` reads this binding at module scope as `measureMemory:
//! _measureMemory` and calls it from inside `vm.measureMemory()` with the two
//! enum values it looked up in `constants.measureMemory`. So the signature is
//! two integers in, one promise out, and the argument check is Node's:
//! `src/node_contextify.cc:2006` opens with `CHECK(args[0]->IsInt32())` and the
//! same for `args[1]`, which rejects anything V8 would have to coerce.
//!
//! The promise is what makes this observable. V8 resolves it with the
//! measurement, so the shape the caller sees (`{ total, current, other }`) comes
//! from V8's `MeasureMemoryDelegate::Default` and not from this file. Node
//! ignores `Isolate::MeasureMemory`'s return value, and so does this.

use rn_v8_sys::v8;

use crate::constants;

/// `measureMemory(mode, execution)`.
pub fn measure_memory<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    // Node uses `CHECK(args[i]->IsInt32())`. A `CHECK` aborts the process, which
    // a JavaScript binding may not do, so the same condition is enforced as a
    // thrown `TypeError`. Coercing with `int32_value` instead would be the bug
    // this repo has already paid for: it answers `Some(0)` for a string.
    let Some(mode) = int32_arg(scope, args.get(0), "mode") else {
        return;
    };
    let Some(execution) = int32_arg(scope, args.get(1), "execution") else {
        return;
    };

    // V8's enums, which `constants.rs` also publishes to `lib/vm.js`. The
    // numbers are accepted only in the range that maps onto a real enumerator:
    // Node passes the integer through `static_cast`, so an out-of-range value
    // would select an enumerator that does not exist.
    let mode = match mode {
        constants::MODE_SUMMARY => rn_v8_sys::MeasureMemoryMode::Summary,
        constants::MODE_DETAILED => rn_v8_sys::MeasureMemoryMode::Detailed,
        other => {
            throw_type_error(scope, &format!("mode must be 0 or 1, received {other}"));
            return;
        }
    };
    let execution = match execution {
        constants::EXECUTION_DEFAULT => rn_v8_sys::MeasureMemoryExecution::Default,
        constants::EXECUTION_EAGER => rn_v8_sys::MeasureMemoryExecution::Eager,
        // `lib/vm.js` does not offer this value, so it is reachable only by
        // calling the binding directly. V8 supports it, so it is passed through
        // rather than rejected.
        2 => rn_v8_sys::MeasureMemoryExecution::Lazy,
        other => {
            throw_type_error(
                scope,
                &format!("execution must be 0, 1 or 2, received {other}"),
            );
            return;
        }
    };

    let context = scope.get_current_context();
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        // No current context, or V8 declined to allocate a resolver. `vm.js`
        // reads `undefined` here as `ERR_CONTEXT_NOT_INITIALIZED`.
        return;
    };

    // SAFETY: `context` is this scope's current context and `resolver` was just
    // created in it, so both outlive the call. V8 keeps the promise the
    // delegate resolves, not a borrow of either handle.
    unsafe { rn_v8_sys::measure_memory(scope, context, resolver, mode, execution) };

    rv.set(resolver.get_promise(scope).into());
}

/// Reads `value` as an `i32` only when V8 says it *is* an `Int32`.
///
/// Throws and returns `None` otherwise. Node's `CHECK(args[i]->IsInt32())` is a
/// type test, not a conversion, so `int32_value`'s coercing behaviour is wrong
/// here; `try_from` is the strict form.
fn int32_arg(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
    name: &str,
) -> Option<i32> {
    match v8::Local::<v8::Int32>::try_from(value) {
        Ok(int) => Some(int.value()),
        Err(_) => {
            throw_type_error(scope, &format!("{name} must be an integer"));
            None
        }
    }
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_constants_are_the_shims_enum_values() {
        // `constants.rs` publishes these numbers to `lib/vm.js`, and this module
        // translates them back into the enums the shim takes. A drift between the
        // two tables would select the wrong mode without anything throwing.
        assert_eq!(
            constants::MODE_SUMMARY,
            rn_v8_sys::MeasureMemoryMode::Summary as i32
        );
        assert_eq!(
            constants::MODE_DETAILED,
            rn_v8_sys::MeasureMemoryMode::Detailed as i32
        );
        assert_eq!(
            constants::EXECUTION_DEFAULT,
            rn_v8_sys::MeasureMemoryExecution::Default as i32
        );
        assert_eq!(
            constants::EXECUTION_EAGER,
            rn_v8_sys::MeasureMemoryExecution::Eager as i32
        );
    }
}
