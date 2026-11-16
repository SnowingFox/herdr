//! Publishing the members onto the `Bun` object.
//!
//! Each member is a thin V8 callback over an algorithm in another module;
//! nothing here reimplements anything. What this file does own is argument
//! coercion and error shape, both of which are observable and both of which were
//! measured against Bun rather than inferred:
//!
//! * `stripANSI()` with no argument stringifies to `"undefined"`, while
//!   `stringWidth()` with no argument returns `0`. The two disagree about a
//!   missing argument, so they are handled differently rather than through one
//!   shared helper.
//! * `allocUnsafe`, `indexOfLine` and the `readableStreamTo*` family reuse
//!   Node's `ERR_INVALID_ARG_TYPE` and `ERR_OUT_OF_RANGE` message forms
//!   *verbatim*, so the validators below transcribe Node's `validateNumber`,
//!   `validateInteger` and `validateBuffer` text instead of inventing wording.
//!
//! # The value members are JavaScript
//!
//! `deepEquals`, `deepMatch` and `inspect` walk arbitrary object graphs and meet
//! Maps, Sets, getters and cycles. Written against V8's Rust API each would have
//! to re-implement `Map.prototype.entries`, prototype identity and the iteration
//! protocol; written in JavaScript they are ordinary property reads. `values.js`
//! holds that half and is evaluated once with the native `stringWidth` passed
//! in, so column measurement stays in Rust where the generated table lives.

use rn_v8_sys::v8;

use crate::ansi;
use crate::buffers;
use crate::html;
use crate::semver;
use crate::slice;
use crate::timers;
use crate::uuid;
use crate::width;
use crate::wrap;

/// The JavaScript half of the value members.
const VALUES_JS: &str = include_str!("values.js");
/// The `readableStreamTo*` family.
const STREAMS_JS: &str = include_str!("streams.js");
const TIMERS_JS: &str = include_str!("timers.js");

/// `Bun.ArrayBufferSink`, whose instances have methods but whose constructor has
/// no `prototype` property.
use crate::inspect::SINK_JS;

/// Publishes every member onto `target`.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    publish_text_members(scope, target)?;
    publish_value_members(scope, target)?;
    publish_timing_members(scope, target)?;
    publish_buffer_members(scope, target)?;
    publish_crypto_members(scope, target)?;
    publish_semver_member(scope, target)?;
    publish_stream_members(scope, target)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// Builds a `TypeError` with an optional `code` property, and throws it.
fn throw_type_error(
    scope: &mut v8::PinScope<'_, '_>,
    code: Option<&str>,
    message: &str,
) -> Option<()> {
    let message = v8::String::new(scope, message)?;
    let exception = v8::Exception::type_error(scope, message);
    if let Some(code) = code {
        if let Some(object) = exception.to_object(scope) {
            if let Some(key) = v8::String::new(scope, "code") {
                if let Some(value) = v8::String::new(scope, code) {
                    object.set(scope, key.into(), value.into());
                }
            }
        }
    }
    scope.throw_exception(exception);
    None
}

fn throw_range_error(
    scope: &mut v8::PinScope<'_, '_>,
    code: Option<&str>,
    message: &str,
) -> Option<()> {
    let message = v8::String::new(scope, message)?;
    let exception = v8::Exception::range_error(scope, message);
    if let Some(code) = code {
        if let Some(object) = exception.to_object(scope) {
            if let Some(key) = v8::String::new(scope, "code") {
                if let Some(value) = v8::String::new(scope, code) {
                    object.set(scope, key.into(), value.into());
                }
            }
        }
    }
    scope.throw_exception(exception);
    None
}

fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) -> Option<()> {
    let message = v8::String::new(scope, message)?;
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
    None
}

/// The UTF-16 units a JS value coerces to with `String()`, which is what every
/// text member does to its first argument.
fn to_units(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<Vec<u16>> {
    let string = value.to_string(scope)?;
    let length = string.length();
    let mut units = vec![0u16; length];
    if length > 0 {
        // `write` fills at most `length` units for an already-shaped string, so
        // the result is exact for every non-external string.
        string.write_v2(scope, 0, &mut units, v8::WriteFlags::empty());
    }
    Some(units)
}

fn from_units<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    units: &[u16],
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_two_byte(scope, units, v8::NewStringType::Normal)
}

/// Publishes a named function with an explicit `length`.
///
/// The length is not decorative: `Bun.stripANSI.length` is 1 and
/// `Bun.wrapAnsi.length` is 3, and a gate that compares the public shape reads
/// them.
fn publish<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = rn_core::named_method_with_length(scope, name, length, callback)?;
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    // Bun publishes every member as a writable, enumerable, **non-configurable**
    // property (`NODE_DEFINE_CONSTANT`-style: `DontDelete`, and its descriptor
    // reports `configurable: false`). A plain `Set` would make it configurable,
    // which is an observable difference to anything auditing the object shape.
    target
        .define_own_property(
            scope,
            key.into(),
            function.into(),
            v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| format!("cannot publish {name}"))?;
    Ok(())
}

/// Reads `options[name]` as a truthy boolean, with Bun's "absent keeps the
/// default" rule: `undefined`, `null` and an empty string leave `default` alone.
fn truthy_option(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<v8::Object>,
    name: &str,
    default: bool,
) -> bool {
    let Some(key) = v8::String::new(scope, name) else {
        return default;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return default;
    };
    if value.is_undefined() || value.is_null() {
        return default;
    }
    if value.is_string() && value.to_rust_string_lossy(scope).is_empty() {
        return default;
    }
    value.boolean_value(scope)
}

/// Redefines a function's own `length`.
///
/// A JavaScript function reports its declared parameter count, so a helper
/// written as `deepEquals(a, b, strict)` reports 3 while Bun's reports 2. The
/// published number is what a caller reads and what the compat gate compares, so
/// it is set explicitly rather than left to the declaration.
fn set_length(
    scope: &mut v8::PinScope<'_, '_>,
    function: v8::Local<v8::Function>,
    length: i32,
) -> Option<()> {
    let key = v8::String::new(scope, "length")?;
    let value = v8::Number::new(scope, f64::from(length));
    let object: v8::Local<v8::Object> = function.into();
    object.define_own_property(
        scope,
        key.into(),
        value.into(),
        v8::PropertyAttribute::DONT_ENUM | v8::PropertyAttribute::DONT_DELETE,
    )?;
    Some(())
}

fn read_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    target.get(scope, key.into())
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn publish_text_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    publish(scope, target, "stripANSI", 1, strip_ansi)?;
    publish(scope, target, "wrapAnsi", 3, wrap_ansi)?;
    publish(scope, target, "sliceAnsi", 5, slice_ansi)?;
    publish(scope, target, "stringWidth", 2, string_width)?;
    publish(scope, target, "escapeHTML", 2, escape_html)?;
    Ok(())
}

/// `Bun.stripANSI(text)`.
///
/// Coerces with `String()`, so `stripANSI()` is `"undefined"` and
/// `stripANSI(42)` is `"42"`. A truncated escape sequence swallows the rest of
/// the string, which is why `stripANSI("a\x1bb")` is `"a"`.
fn strip_ansi(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = to_units(scope, args.get(0)) else {
        return;
    };
    let stripped = ansi::strip(&text);
    if let Some(value) = from_units(scope, &stripped) {
        rv.set(value.into());
    }
}

/// `Bun.escapeHTML(text, ...)`. The second argument is ignored.
fn escape_html(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = to_units(scope, args.get(0)) else {
        return;
    };
    let escaped = html::escape_html_units(&text);
    if let Some(value) = from_units(scope, &escaped) {
        rv.set(value.into());
    }
}

/// `Bun.stringWidth(text, options?)`.
///
/// Returns `0` for a missing argument — unlike `stripANSI`, which stringifies
/// it — and honours `countAnsiEscapeCodes`, `ambiguousIsNarrow` and
/// `perCodePoint`, the last of which switches to a different width algorithm
/// entirely (see [`crate::width`]).
fn string_width(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let input = args.get(0);
    if input.is_undefined() {
        rv.set(v8::Number::new(scope, 0.0).into());
        return;
    }
    let Some(text) = to_units(scope, input) else {
        return;
    };
    if text.is_empty() {
        rv.set(v8::Number::new(scope, 0.0).into());
        return;
    }

    let mut count_ansi = false;
    let mut ambiguous_is_narrow = true;
    let mut per_code_point = false;
    let options = args.get(1);
    if options.is_object() {
        if let Some(object) = options.to_object(scope) {
            count_ansi = truthy_option(scope, object, "countAnsiEscapeCodes", false);
            ambiguous_is_narrow = truthy_option(scope, object, "ambiguousIsNarrow", true);
            per_code_point = truthy_option(scope, object, "perCodePoint", false);
        }
    }

    let ambiguous_as_wide = !ambiguous_is_narrow;
    let width = if per_code_point {
        width::per_code_point_width_of(&text, !count_ansi, ambiguous_as_wide)
    } else {
        width::visible_width(&text, count_ansi, ambiguous_as_wide)
    };
    rv.set(v8::Number::new(scope, width as f64).into());
}

/// `Bun.wrapAnsi(text, columns, options?)`.
fn wrap_ansi(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = to_units(scope, args.get(0)) else {
        return;
    };
    if text.is_empty() {
        rv.set(v8::String::empty(scope).into());
        return;
    }

    // Only a positive, finite width enables wrapping: `0`, a negative number,
    // `NaN` and `Infinity` all mean "leave the text alone", which is why
    // `wrapAnsi("abc", 0)` is `"abc"`.
    let mut columns = 0usize;
    let columns_value = args.get(1);
    if !columns_value.is_undefined() {
        if let Some(number) = columns_value.number_value(scope) {
            if number.is_finite() && number > 0.0 {
                columns = number.trunc() as usize;
            }
        }
    }

    let mut options = wrap::WrapOptions::default();
    let options_value = args.get(2);
    if options_value.is_object() {
        if let Some(object) = options_value.to_object(scope) {
            options.hard = truthy_option(scope, object, "hard", false);
            // `wordWrap` and `trim` default on, so only an explicit `false`
            // turns them off: Bun tests `!== false`, not truthiness.
            options.word_wrap = !is_false(scope, object, "wordWrap");
            options.trim = !is_false(scope, object, "trim");
            options.ambiguous_is_narrow = truthy_option(scope, object, "ambiguousIsNarrow", true);
        }
    }

    let wrapped = wrap::wrap(&text, columns, options);
    if let Some(value) = from_units(scope, &wrapped) {
        rv.set(value.into());
    }
}

/// `Bun.sliceAnsi(text, start, end, options?)`.
///
/// Columns, not code units, and the ANSI state active at the cut is re-asserted
/// on the slice.
fn slice_ansi(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = to_units(scope, args.get(0)) else {
        return;
    };
    if text.is_empty() {
        rv.set(v8::String::empty(scope).into());
        return;
    }

    // The index handling matches `String.prototype.slice`: absent start is `0`,
    // absent end is `+Infinity`, and each is truncated toward zero.
    let start_value = args.get(1);
    let start = if start_value.is_undefined() {
        0.0
    } else {
        integer_or_infinity(scope, start_value)
    };
    let end_value = args.get(2);
    let end = if end_value.is_undefined() {
        f64::INFINITY
    } else {
        integer_or_infinity(scope, end_value)
    };

    let mut options = slice::SliceOptions::default();
    let arg4 = args.get(3);
    if arg4.is_boolean() {
        options.ambiguous_is_narrow = arg4.boolean_value(scope);
    } else if arg4.is_object() {
        if let Some(object) = arg4.to_object(scope) {
            options.ambiguous_is_narrow = truthy_option(scope, object, "ambiguousIsNarrow", true);
        }
    }

    let total = slice::total_width(&text, options);
    let (start_column, end_column) = resolve_bounds(start, end, total);
    if end_column <= start_column {
        rv.set(v8::String::empty(scope).into());
        return;
    }
    let sliced = slice::slice(&text, start_column, end_column, options);
    if let Some(value) = from_units(scope, &sliced) {
        rv.set(value.into());
    }
}

/// Resolves `[start, end)` the way `String.prototype.slice` does, in columns.
///
/// An unbounded end is `usize::MAX`, which keeps trailing zero-width clusters
/// and escape sequences instead of cutting them off.
fn resolve_bounds(start: f64, end: f64, total: usize) -> (usize, usize) {
    let from = if start < 0.0 {
        total as f64 + start
    } else {
        start
    };
    let to = if end < 0.0 { total as f64 + end } else { end };
    let from = from.max(0.0);
    if to.is_infinite() {
        return (from as usize, usize::MAX);
    }
    let to = to.min(total as f64);
    // `NaN` compares false against everything, and an empty or reversed range is
    // an empty slice; both land on the same early return. Written as a positive
    // test because `!(to > from)` is the comparison clippy objects to on floats.
    if to.is_nan() || to <= from {
        return (from as usize, from as usize);
    }
    (from as usize, to as usize)
}

fn integer_or_infinity(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> f64 {
    let Some(number) = value.number_value(scope) else {
        return 0.0;
    };
    if number.is_nan() || number == 0.0 {
        return 0.0;
    }
    number.trunc()
}

/// Reads `options[name]` and reports whether it is exactly `false`.
fn is_false(scope: &mut v8::PinScope<'_, '_>, options: v8::Local<v8::Object>, name: &str) -> bool {
    let Some(key) = v8::String::new(scope, name) else {
        return false;
    };
    options
        .get(scope, key.into())
        .map(|value| value.is_false())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Value shapes, from values.js
// ---------------------------------------------------------------------------

fn publish_value_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let installed = evaluate(scope, VALUES_JS, "values.js")?;
    let installed = v8::Local::<v8::Function>::try_from(installed)
        .map_err(|_| "values.js did not evaluate to a function".to_string())?;

    // The factory takes the native `stringWidth`, so `inspect.table` measures
    // columns with the same table everything else uses.
    let string_width =
        read_member(scope, target, "stringWidth").ok_or("values.js needs stringWidth")?;
    let members = installed
        .call(scope, v8::undefined(scope).into(), &[string_width])
        .ok_or("values.js factory threw")?;
    let members = members
        .to_object(scope)
        .ok_or("values.js factory did not return an object")?;

    // `deepEquals` is declared `(a, b, strict)` in JavaScript but Bun publishes
    // length 2; the same holds for `deepMatch` and `inspect`.
    for (name, length) in [("deepEquals", 2), ("deepMatch", 2), ("inspect", 2)] {
        let key = v8::String::new(scope, name).ok_or("cannot allocate member name")?;
        let function = members
            .get(scope, key.into())
            .ok_or_else(|| format!("values.js has no {name}"))?;
        if let Ok(function) = v8::Local::<v8::Function>::try_from(function) {
            set_length(scope, function, length);
        }
        target
            .define_own_property(
                scope,
                key.into(),
                function,
                v8::PropertyAttribute::DONT_DELETE,
            )
            .ok_or_else(|| format!("cannot publish {name}"))?;
    }

    // `inspect.custom` is Node's symbol and `inspect.table` the table renderer.
    // Both are measured: `Bun.inspect.custom === Symbol.for("nodejs.util.inspect.custom")`
    // is `true` and `typeof Bun.inspect.table` is `"function"`.
    let inspect = read_member(scope, target, "inspect")
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or("inspect is not an object")?;

    if let Some(custom) = symbol_for(scope, "nodejs.util.inspect.custom") {
        if let Some(key) = v8::String::new(scope, "custom") {
            inspect.set(scope, key.into(), custom);
        }
    }

    let table_key = v8::String::new(scope, "inspectTable").ok_or("cannot allocate table")?;
    let table = members
        .get(scope, table_key.into())
        .ok_or("values.js has no table")?;
    // The function inside values.js is `inspectTable`; the name a caller reads
    // back from `Bun.inspect.table.name` is `table`.
    if let Ok(function) = v8::Local::<v8::Function>::try_from(table) {
        if let Some(name) = v8::String::new(scope, "table") {
            function.set_name(name);
        }
    }
    if let Some(key) = v8::String::new(scope, "table") {
        inspect.set(scope, key.into(), table);
    }

    Ok(())
}

/// Compiles and runs a factory script, returning its completion value.
///
/// The two JS modules are function expressions, so the value is the factory
/// itself and calling it yields the members. A compile error or a throw is
/// reported with the JS message, because a silent failure here would leave
/// `Bun.deepEquals` missing with no explanation at startup.
fn evaluate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
    label: &str,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let source =
        v8::String::new(scope, source).ok_or_else(|| format!("cannot allocate {label}"))?;
    let script = v8::Script::compile(scope, source, None)
        .ok_or_else(|| format!("cannot compile {label}"))?;
    match script.run(scope) {
        Some(value) => Ok(value),
        None => Err(format!("{label} threw while being evaluated")),
    }
}

fn symbol_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let global = scope.get_current_context().global(scope);
    let symbol_key = v8::String::new(scope, "Symbol")?;
    let symbol = global.get(scope, symbol_key.into())?;
    let symbol = v8::Local::<v8::Object>::try_from(symbol).ok()?;
    let for_key = v8::String::new(scope, "for")?;
    let function = symbol.get(scope, for_key.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    let argument = v8::String::new(scope, name)?;
    function.call(scope, symbol.into(), &[argument.into()])
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

fn publish_timing_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // `sleep` builds a promise around a real timer, which is `new Promise` plus
    // `setTimeout` in JavaScript and a promise resolver driven across native
    // frames in Rust. The JS form is `timers.js`.
    let installed = evaluate(scope, TIMERS_JS, "timers.js")?;
    let installed = v8::Local::<v8::Function>::try_from(installed)
        .map_err(|_| "timers.js did not evaluate to a function".to_string())?;
    let members = installed
        .call(scope, v8::undefined(scope).into(), &[])
        .and_then(|value| value.to_object(scope))
        .ok_or("timers.js factory did not return an object")?;
    let sleep_key = v8::String::new(scope, "sleep").ok_or("cannot allocate sleep")?;
    let sleep = members
        .get(scope, sleep_key.into())
        .ok_or("timers.js has no sleep")?;
    if let Ok(function) = v8::Local::<v8::Function>::try_from(sleep) {
        function.set_name(sleep_key);
    }
    target
        .define_own_property(
            scope,
            sleep_key.into(),
            sleep,
            v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or("cannot publish sleep")?;
    publish(scope, target, "sleepSync", 1, sleep_sync)?;
    publish(scope, target, "shrink", 0, shrink)?;
    Ok(())
}

/// `Bun.sleepSync(ms)`: blocks the thread.
///
/// Carries `ERR_INVALID_ARG_TYPE` and rejects a negative duration by name and
/// value, unlike `sleep`.
fn sleep_sync(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let argument = args.get(0);
    let number = if argument.is_number() {
        argument.number_value(scope)
    } else {
        None
    };
    match timers::validate_sleep_sync(number) {
        Ok(milliseconds) => {
            timers::sleep_sync(milliseconds);
            rv.set(v8::undefined(scope).into());
        }
        Err(error) => {
            throw_type_error(scope, Some("ERR_INVALID_ARG_TYPE"), &error.message());
        }
    }
}

/// `Bun.shrink()`: returns `undefined`.
///
/// The memory effect is not observable in a test; the invariant Bun documents is
/// only that it exists, takes no arguments and does not throw.
fn shrink(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::undefined(scope).into());
}

// ---------------------------------------------------------------------------
// Buffer-adjacent members
// ---------------------------------------------------------------------------

fn publish_buffer_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    publish(scope, target, "concatArrayBuffers", 3, concat_array_buffers)?;
    publish(scope, target, "allocUnsafe", 1, alloc_unsafe)?;
    publish(scope, target, "indexOfLine", 1, index_of_line)?;
    publish_array_buffer_sink(scope, target)?;
    Ok(())
}

/// `Bun.concatArrayBuffers(buffers, totalLength?)`: a new **`ArrayBuffer`**.
///
/// Every element may be a typed array or an `ArrayBuffer`, mixed freely, and the
/// result's prototype is `ArrayBuffer` — not `Uint8Array`, not `Buffer`.
fn concat_array_buffers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let argument = args.get(0);
    if argument.is_undefined() || args.length() == 0 {
        throw_type_error(scope, None, "Expected at least one argument");
        return;
    }
    let Some(array) = v8::Local::<v8::Array>::try_from(argument).ok() else {
        throw_type_error(scope, None, "Argument must be an array");
        return;
    };

    let length = array.length();
    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(length as usize);
    let mut total = 0usize;
    for index in 0..length {
        let Some(element) = array.get_index(scope, index) else {
            throw_type_error(scope, None, "Expected TypedArray");
            return;
        };
        // An `ArrayBuffer` and any `ArrayBufferView` are both accepted, and
        // anything else is the `Expected TypedArray` failure.
        let bytes = if element.is_array_buffer() {
            match v8::Local::<v8::ArrayBuffer>::try_from(element) {
                Ok(buffer) => {
                    let length = buffer.byte_length();
                    let mut out = vec![0u8; length];
                    if length > 0 {
                        let store = buffer.get_backing_store();
                        if let Some(data) = store.data() {
                            // SAFETY: the store covers `byte_length()`, which is
                            // the length V8 reported for this buffer.
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    data.as_ptr().cast::<u8>(),
                                    out.as_mut_ptr(),
                                    length,
                                );
                            }
                        }
                    }
                    out
                }
                Err(_) => {
                    throw_type_error(scope, None, "Expected TypedArray");
                    return;
                }
            }
        } else if element.is_array_buffer_view() {
            match v8::Local::<v8::ArrayBufferView>::try_from(element) {
                Ok(view) => {
                    let mut out = vec![0u8; view.byte_length()];
                    view.copy_contents(&mut out);
                    out
                }
                Err(_) => {
                    throw_type_error(scope, None, "Expected TypedArray");
                    return;
                }
            }
        } else {
            throw_type_error(scope, None, "Expected TypedArray");
            return;
        };
        total += bytes.len();
        pieces.push(bytes);
    }

    // An explicit total length is honoured when it is larger, and the result is
    // still whatever was actually written. Bun accepts the argument and does not
    // truncate to it, which `concat([a,b], 4)` on four bytes cannot distinguish;
    // a smaller total is the case that matters and is measured as "the caller's
    // number does not cut the data".
    let mut destination = vec![0u8; total];
    let mut offset = 0usize;
    for piece in &pieces {
        destination[offset..offset + piece.len()].copy_from_slice(piece);
        offset += piece.len();
    }

    let Some(buffer) = buffers::array_buffer_from(scope, &destination) else {
        throw_error(scope, "concatArrayBuffers could not allocate the result");
        return;
    };
    rv.set(buffer.into());
}

/// `Bun.allocUnsafe(size)`: an **unpooled** `Uint8Array`, not a `Buffer`.
///
/// The validator messages are Node's, transcribed: a numeric string is a
/// `TypeError`, a negative number is one `RangeError` and a non-integer another.
fn alloc_unsafe(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let argument = args.get(0);
    if !argument.is_number() {
        let received = if argument.is_undefined() {
            "Received undefined".to_string()
        } else if argument.is_string() {
            format!(
                "Received type string ('{}')",
                argument.to_rust_string_lossy(scope)
            )
        } else if argument.is_object() && !argument.is_number_object() {
            let object = argument.to_object(scope);
            let name = object
                .map(|object| object.get_constructor_name().to_rust_string_lossy(scope))
                .unwrap_or_else(|| "Object".to_string());
            format!("Received an instance of {name}")
        } else {
            format!(
                "Received type {}",
                match argument.is_boolean() {
                    true => "boolean",
                    false => "object",
                }
            )
        };
        throw_type_error(
            scope,
            Some("ERR_INVALID_ARG_TYPE"),
            &format!("The \"size\" argument must be of type number. {received}"),
        );
        return;
    }

    let Some(number) = argument.number_value(scope) else {
        return;
    };
    if number.fract() != 0.0 {
        throw_range_error(
            scope,
            Some("ERR_OUT_OF_RANGE"),
            &format!(
                "The value of \"size\" is out of range. It must be an integer. Received {}",
                format_received(number)
            ),
        );
        return;
    }
    if !(0.0..=4_294_967_295.0).contains(&number) {
        throw_range_error(
            scope,
            Some("ERR_OUT_OF_RANGE"),
            &format!(
                "The value of \"size\" is out of range. It must be >= 0 && <= 4294967295. Received {}",
                format_received(number)
            ),
        );
        return;
    }

    // A plain `Uint8Array` over its own fresh `ArrayBuffer`: no pool, so two
    // consecutive small allocations never share a backing store. That is the
    // measured difference from `Buffer.allocUnsafe`.
    let length = number as usize;
    let Some(buffer) = buffers::array_buffer_from(scope, &vec![0u8; length]) else {
        throw_error(scope, "allocUnsafe could not allocate the buffer");
        return;
    };
    let Some(view) = buffers::uint8_array_from(scope, buffer) else {
        throw_error(scope, "allocUnsafe could not create the view");
        return;
    };
    rv.set(view.into());
}

fn format_received(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e21 {
        format!("{}", number as i64)
    } else {
        format!("{number}")
    }
}

/// `Bun.indexOfLine(buffer, offset?)`: the index of the next `\n`.
///
/// For CRLF the reported index is the `\n`, so the `\r` stays part of the line
/// content. A string argument is rejected outright — this reads bytes, not text.
fn index_of_line(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let argument = args.get(0);
    let bytes = if argument.is_array_buffer() {
        buffers::array_buffer_bytes(scope, argument)
    } else if argument.is_array_buffer_view() {
        buffers::view_bytes(scope, argument)
    } else {
        None
    };
    let Some(bytes) = bytes else {
        throw_type_error(
            scope,
            Some("ERR_INVALID_ARG_TYPE"),
            "buffer must be an ArrayBuffer or ArrayBufferView",
        );
        return;
    };

    let offset_value = args.get(1);
    let offset = if offset_value.is_undefined() {
        0usize
    } else {
        offset_value
            .number_value(scope)
            .map(|number| number.max(0.0).trunc() as usize)
            .unwrap_or(0)
    };

    let index = if offset >= bytes.len() {
        -1.0
    } else {
        match bytes[offset..].iter().position(|byte| *byte == b'\n') {
            Some(found) => (offset + found) as f64,
            None => -1.0,
        }
    };
    rv.set(v8::Number::new(scope, index).into());
}

// ---------------------------------------------------------------------------
// Crypto members
// ---------------------------------------------------------------------------

fn publish_crypto_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    publish(scope, target, "randomUUIDv5", 3, random_uuid_v5)?;
    publish(scope, target, "randomUUIDv7", 2, random_uuid_v7)?;
    Ok(())
}

/// `Bun.randomUUIDv5(name, namespace)`.
///
/// The argument order is **name first**, and the namespace is validated before
/// the name, which is why swapping them reports the namespace format rather than
/// the name type.
fn random_uuid_v5(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let namespace_value = args.get(1);
    if args.length() == 0 {
        throw_type_error(
            scope,
            Some("ERR_INVALID_ARG_TYPE"),
            "name must be a string, ArrayBuffer or ArrayBufferView",
        );
        return;
    }
    let Some(name) = bytes_argument(scope, args.get(0)) else {
        throw_type_error(
            scope,
            Some("ERR_INVALID_ARG_TYPE"),
            "name must be a string, ArrayBuffer or ArrayBufferView",
        );
        return;
    };
    if namespace_value.is_undefined() {
        throw_type_error(
            scope,
            Some("ERR_INVALID_ARG_TYPE"),
            "namespace must be a string, ArrayBuffer or ArrayBufferView",
        );
        return;
    }
    let Some(namespace_bytes) = bytes_argument(scope, namespace_value) else {
        throw_type_error(
            scope,
            Some("ERR_INVALID_ARG_TYPE"),
            "namespace must be a string, ArrayBuffer or ArrayBufferView",
        );
        return;
    };
    // A 16-byte namespace is used as-is; anything else must be a UUID string,
    // and failing that the format error is what Bun reports.
    let namespace = if namespace_bytes.len() == 16 {
        let mut namespace = [0u8; 16];
        namespace.copy_from_slice(&namespace_bytes);
        namespace
    } else {
        let text = namespace_value.to_rust_string_lossy(scope);
        match uuid::parse_uuid(&text) {
            Some(namespace) => namespace,
            None => {
                throw_type_error(
                    scope,
                    Some("ERR_INVALID_ARG_VALUE"),
                    "Invalid UUID format for namespace",
                );
                return;
            }
        }
    };

    let generated = uuid::uuid_v5(&name, &namespace);
    if let Some(value) = v8::String::new(scope, &uuid::format_uuid(&generated)) {
        rv.set(value.into());
    }
}

/// `Bun.randomUUIDv7()`.
///
/// Only its invariants are stable — version nibble `7`, variant in `[89ab]`,
/// uniqueness, and lexicographic non-decrease over consecutive calls — so no
/// value is ever compared against a literal.
fn random_uuid_v7(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let mut random = [0u8; 10];
    if let Err(message) = uuid::fill_random(&mut random) {
        throw_error(scope, &message);
        return;
    }
    let (millis, counter) = uuid::next_v7_clock();
    let generated = uuid::uuid_v7(millis, counter, &random);
    if let Some(value) = v8::String::new(scope, &uuid::format_uuid(&generated)) {
        rv.set(value.into());
    }
}

/// The bytes of a string, `ArrayBuffer` or `ArrayBufferView`.
fn bytes_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<Vec<u8>> {
    if value.is_string() {
        return Some(value.to_rust_string_lossy(scope).into_bytes());
    }
    if value.is_array_buffer() {
        return buffers::array_buffer_bytes(scope, value);
    }
    if value.is_array_buffer_view() {
        return buffers::view_bytes(scope, value);
    }
    None
}

// ---------------------------------------------------------------------------
// semver
// ---------------------------------------------------------------------------

fn publish_semver_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let object = v8::Object::new(scope);
    let satisfies = rn_core::named_method_with_length(scope, "satisfies", 2, semver_satisfies)?;
    let order = rn_core::named_method_with_length(scope, "order", 2, semver_order)?;

    let satisfies_key = v8::String::new(scope, "satisfies").ok_or("cannot allocate satisfies")?;
    object
        .set(scope, satisfies_key.into(), satisfies.into())
        .ok_or("cannot publish satisfies")?;
    let order_key = v8::String::new(scope, "order").ok_or("cannot allocate order")?;
    object
        .set(scope, order_key.into(), order.into())
        .ok_or("cannot publish order")?;

    // `Bun.semver` is a read-only, non-configurable plain object with exactly
    // two own keys, which is measured.
    let key = v8::String::new(scope, "semver").ok_or("cannot allocate semver")?;
    target
        .define_own_property(
            scope,
            key.into(),
            object.into(),
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or("cannot publish semver")?;
    Ok(())
}

/// `Bun.semver.satisfies(version, range)`. Never throws.
fn semver_satisfies(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if args.length() == 0 {
        // Measured: no arguments is `false`, not a throw, which is the opposite
        // of `order`.
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    }
    let version = args.get(0).to_rust_string_lossy(scope);
    let range = args.get(1).to_rust_string_lossy(scope);
    let satisfied = semver::satisfies(&version, &range);
    rv.set(v8::Boolean::new(scope, satisfied).into());
}

/// `Bun.semver.order(a, b)`: throws on an empty or missing version, with a
/// message that ends in a literal newline.
fn semver_order(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let left = if args.length() > 0 && !args.get(0).is_undefined() {
        Some(args.get(0).to_rust_string_lossy(scope))
    } else {
        None
    };
    let right = if args.length() > 1 && !args.get(1).is_undefined() {
        Some(args.get(1).to_rust_string_lossy(scope))
    } else {
        None
    };
    match semver::order(left.as_deref(), right.as_deref()) {
        Ok(result) => rv.set(v8::Number::new(scope, f64::from(result)).into()),
        Err(error) => {
            throw_error(scope, &error.message());
        }
    }
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

fn publish_stream_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // Consuming a `ReadableStream` means driving its async iterator and keeping
    // the promise chain alive across native frames. In JavaScript it is one
    // `for await` loop per helper, and the measured ordering — validation throws
    // synchronously, `stream.locked` is still false when the call returns, and
    // an errored stream rejects with its own error — falls out of the language
    // rather than being reconstructed.
    let installed = evaluate(scope, STREAMS_JS, "streams.js")?;
    let installed = v8::Local::<v8::Function>::try_from(installed)
        .map_err(|_| "streams.js did not evaluate to a function".to_string())?;
    let members = installed
        .call(scope, v8::undefined(scope).into(), &[])
        .and_then(|value| value.to_object(scope))
        .ok_or("streams.js factory did not return an object")?;
    for (name, length) in [
        ("readableStreamToArray", 1),
        ("readableStreamToArrayBuffer", 1),
        ("readableStreamToBlob", 1),
        ("readableStreamToBytes", 1),
        ("readableStreamToFormData", 1),
        ("readableStreamToJSON", 1),
        ("readableStreamToText", 1),
    ] {
        let key = v8::String::new(scope, name).ok_or("cannot allocate stream helper name")?;
        let function = members
            .get(scope, key.into())
            .ok_or_else(|| format!("streams.js has no {name}"))?;
        if let Ok(function) = v8::Local::<v8::Function>::try_from(function) {
            // Bun reports 1 for all seven even though
            // `readableStreamToFormData` accepts a boundary second argument.
            function.set_name(key);
            set_length(scope, function, length);
        }
        target
            .define_own_property(
                scope,
                key.into(),
                function,
                v8::PropertyAttribute::DONT_DELETE,
            )
            .ok_or_else(|| format!("cannot publish {name}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ArrayBufferSink
// ---------------------------------------------------------------------------

/// `Bun.ArrayBufferSink`, whose shape is unusual enough to deserve its own note.
///
/// `Bun.ArrayBufferSink.prototype` is **`undefined`**, yet instances have
/// methods: the prototype object exists but is not reachable from the
/// constructor, and it is found through `Object.getPrototypeOf(instance)`. A
/// gate that read `Ctor.prototype` would report no methods at all, so the
/// constructor is installed without a `prototype` property and the methods are
/// placed on a plain object that becomes the instance's prototype.
fn publish_array_buffer_sink<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // The methods live in JavaScript; the constructor is built here so the
    // instance shape can be controlled.
    //
    // Bun's own constructor reports `Bun.ArrayBufferSink.prototype === undefined`
    // while still being constructible. That combination is not reachable from
    // V8's Rust API: `FunctionTemplate::remove_prototype` drops the property and
    // `[[Construct]]` together, and there is no `prototype_provider` binding. So
    // the shape here is the closest constructible one — a normal function, with
    // the methods on a prototype object whose `constructor` points back at it —
    // and the one divergence (`typeof Bun.ArrayBufferSink.prototype` is
    // `"object"` rather than `"undefined"`) is recorded in
    // `tests/data/streams-oracle.json`'s `sinkShape.prototypeType` and asserted
    // explicitly by `tests/streams_parity.rs` so it cannot drift silently.
    let factory = evaluate(scope, SINK_JS, "ArrayBufferSink")?;
    let factory = v8::Local::<v8::Function>::try_from(factory)
        .map_err(|_| "the sink factory must evaluate to a function".to_string())?;
    let parts = factory
        .call(scope, v8::undefined(scope).into(), &[])
        .and_then(|value| value.to_object(scope))
        .ok_or("the sink factory did not return an object")?;
    let create_key = v8::String::new(scope, "create").ok_or("cannot allocate create")?;
    let create = parts
        .get(scope, create_key.into())
        .ok_or("the sink factory has no create")?;
    let create =
        v8::Local::<v8::Function>::try_from(create).map_err(|_| "create is not a function")?;
    let create = v8::Global::new(scope, create);
    STATE.with(|slot| *slot.borrow_mut() = Some(SinkFactory { create }));

    // `class` rather than `method` here: the template has to allow `new`, and
    // `rn_core::method` passes `ConstructorBehavior::Throw` (correct for every
    // binding member, wrong for a class). A function built from a class template
    // is constructible, which is what `new Bun.ArrayBufferSink()` needs.
    let template = rn_core::class(ArrayBufferSink::construct).build(scope);
    let constructor = rn_core::named_template(scope, "ArrayBufferSink", template)?;

    // The prototype object is created by the JavaScript factory and carries the
    // methods, `sinkId` and `Symbol.toStringTag`. Publishing it as the
    // constructor's `prototype` is what makes `new` produce an instance whose
    // `Object.getPrototypeOf` finds all nine members.
    let proto_key = v8::String::new(scope, "proto").ok_or("cannot allocate proto")?;
    let proto = parts
        .get(scope, proto_key.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or("the sink factory has no proto")?;
    if let Some(prototype_key) = v8::String::new(scope, "prototype") {
        constructor.set(scope, prototype_key.into(), proto.into());
    }
    if let Some(constructor_key) = v8::String::new(scope, "constructor") {
        proto.set(scope, constructor_key.into(), constructor.into());
    }

    let key = v8::String::new(scope, "ArrayBufferSink").ok_or("cannot allocate ArrayBufferSink")?;
    target
        .set(scope, key.into(), constructor.into())
        .ok_or("cannot publish ArrayBufferSink")?;
    Ok(())
}

/// The per-thread sink factory, so the constructor body can reach the JavaScript
/// `create` without a global or a template data slot.
struct SinkFactory {
    create: v8::Global<v8::Function>,
}

thread_local! {
    static STATE: std::cell::RefCell<Option<SinkFactory>> = const { std::cell::RefCell::new(None) };
}

/// The `ArrayBufferSink` constructor body: delegates instance creation to the
/// JavaScript side, which owns the prototype and the per-instance `WeakMap`.
struct ArrayBufferSink;

impl ArrayBufferSink {
    fn construct(
        scope: &mut v8::PinScope<'_, '_>,
        args: v8::FunctionCallbackArguments<'_>,
        mut rv: v8::ReturnValue<'_>,
    ) {
        let Some(create) =
            STATE.with(|slot| slot.borrow().as_ref().map(|factory| factory.create.clone()))
        else {
            throw_error(scope, "ArrayBufferSink is not installed on this thread");
            return;
        };
        let create = v8::Local::new(scope, create);
        let options = args.get(0);
        match create.call(scope, v8::undefined(scope).into(), &[options]) {
            Some(instance) => rv.set(instance),
            None => {
                throw_error(scope, "ArrayBufferSink could not create an instance");
            }
        }
    }
}
