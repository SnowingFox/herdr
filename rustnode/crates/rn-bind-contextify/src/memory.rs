//! `measureMemory(mode, execution)`.
//!
//! `lib/vm.js` validates and maps option strings before calling this, so this
//! binding receives integer enum values (`constants.measureMemory.*`) and must
//! return the `Promise` V8 resolves with memory statistics.

use rn_v8_sys::v8;
use rn_v8_sys::{MeasureMemoryExecution, MeasureMemoryMode};

use crate::constants;

/// `measureMemory(mode, execution)`.
pub fn measure_memory<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(mode_number) = int32_arg(args.get(0)) else {
        return throw_type_error(scope, "measureMemory requires an int32 mode");
    };
    let Some(mode) = mode_from_i32(mode_number) else {
        return throw_type_error(scope, "measureMemory mode is out of range");
    };
    let Some(execution_number) = int32_arg(args.get(1)) else {
        return throw_type_error(scope, "measureMemory requires an int32 execution");
    };
    let Some(execution) = execution_from_i32(execution_number) else {
        return throw_type_error(scope, "measureMemory execution is out of range");
    };

    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        return;
    };
    // SAFETY: `resolver` and `scope` come from the current entered isolate and
    // context; enum values are validated against Node/V8 constants above.
    let promise = unsafe { rn_v8_sys::measure_memory(scope, resolver, mode, execution) };
    if let Some(promise) = promise {
        // V8 resolves this promise from a task posted to the platform's
        // foreground runner, which owns no libuv handle. Without the hint the
        // loop can decide it has nothing left to do and exit first.
        rn_core::platform_tasks::note_possible_pending();
        rv.set(promise.into());
    }
}

fn int32_arg(value: v8::Local<'_, v8::Value>) -> Option<i32> {
    v8::Local::<v8::Int32>::try_from(value)
        .ok()
        .map(|value| value.value())
}

fn mode_from_i32(value: i32) -> Option<MeasureMemoryMode> {
    match value {
        constants::MODE_SUMMARY => Some(MeasureMemoryMode::Summary),
        constants::MODE_DETAILED => Some(MeasureMemoryMode::Detailed),
        _ => None,
    }
}

fn execution_from_i32(value: i32) -> Option<MeasureMemoryExecution> {
    match value {
        constants::EXECUTION_DEFAULT => Some(MeasureMemoryExecution::Default),
        constants::EXECUTION_EAGER => Some(MeasureMemoryExecution::Eager),
        _ => None,
    }
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}
