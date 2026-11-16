//! `Bun.JSONL.parse` and `Bun.JSONL.parseChunk`.
//!
//! JSONL is one JSON value per line. Node has no equivalent, so this is pure
//! gain, but the failure behaviour is not what a first reading suggests and it is
//! the whole reason this member needs its own tests:
//!
//! ```text
//! parse('{"a":1}\nXXX\n{"b":2}\n')   [{a: 1}]   a bad line after a good one TRUNCATES
//! parse('notjson\n{"a":1}\n')        THROW       ... but a bad FIRST line throws
//! parse('nope')                      []          ... and a bad only line is empty
//! ```
//!
//! So an error surfaces as a throw **only while no value has been produced**.
//! Once one has, the rest of the buffer is abandoned and the partial array is
//! returned. A caller cannot distinguish "clean end" from "gave up" by the return
//! value alone, which is exactly why `parseChunk` exists.
//!
//! # `parseChunk`
//!
//! `{values, read, done, error}` — an ordinary object with `Object.prototype`.
//!
//! * `read` is bytes consumed, always landing just past a `\n`;
//! * `read > 0` → slice the buffer by `read` and call again;
//! * `read === 0 && done === false` → an incomplete tail, wait for more bytes;
//! * `read === 0 && done === true` → the buffer is exhausted.
//!
//! **Never loop while `read === 0`.** A drain written as `while (pos < len)`
//! with `pos += read` spins forever at the end of the buffer, and the measured
//! terminating state is explicit:
//!
//! ```text
//! drain '{"a":1}\n{"b":"xx"}\n{"c":3}\n'
//!   [{at:0, read:26, done:true}, {at:26, read:0, done:true}]   <- the second is the signal
//! ```
//!
//! The `error` field is subtler than "set on bad input": an unparseable *token*
//! sets it and stops, while an unterminated *object* is reported as "need more
//! data" with `error: null`:
//!
//! ```text
//! parseChunk('{"a":1}\nnotjson\n{"b":2}\n')   error: SyntaxError, done: false, read: 7
//! parseChunk('{"a":1}\n{"b":\n{"c":3}\n')     error: null,      done: false, read: 7
//! ```
//!
//! The `error` object is a real `SyntaxError` with the message
//! `"Failed to parse JSONL"` and no `code`, so it is constructed from the
//! exception the parser would have thrown.
//!
//! # Validation is strict JSON
//!
//! Each line is parsed as JSON, not JSON5 or JSONC: `{'a':1}`, `{"a":1,}`,
//! `NaN` and `// x` are all `Failed to parse JSONL`. The exception is a
//! duplicate key, which is last-wins like any object literal.

use rn_v8_sys::v8;

use crate::convert::{bytes_of, throw_type_error};
use crate::value::Value;

/// Builds the `Bun.JSONL` namespace object.
///
/// Two measured quirks distinguish this namespace from its six siblings and are
/// reproduced here:
///
/// * its two members are **non-configurable** (`{writable: true, enumerable:
///   true, configurable: false}`), while every other member in the group is
///   configurable;
/// * the namespace itself carries a non-writable `Symbol.toStringTag` of
///   `"JSONL"`, which none of the others do.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    member(scope, object, "parse", 1, parse)?;
    member(scope, object, "parseChunk", 1, parse_chunk)?;
    let tag =
        v8::String::new(scope, "JSONL").ok_or_else(|| "cannot allocate the tag".to_string())?;
    // `Symbol.for("Symbol.toStringTag")` — wait, the well-known symbol is
    // `Symbol.toStringTag`, an intrinsic rather than a registry entry, so it is
    // read off `Symbol` exactly as `getOwnPropertyDescriptor(Bun.JSONL,
    // Symbol.toStringTag)` would.
    let key = well_known_to_string_tag(scope)
        .ok_or_else(|| "cannot read Symbol.toStringTag".to_string())?;
    let mut descriptor = v8::PropertyDescriptor::new_from_value(tag.into());
    descriptor.set_enumerable(false);
    descriptor.set_configurable(true);
    object
        .define_property(scope, key.into(), &descriptor)
        .ok_or_else(|| "cannot define Symbol.toStringTag".to_string())?;
    Ok(object)
}

/// `Symbol.toStringTag` from the current context.
fn well_known_to_string_tag<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Symbol>> {
    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "Symbol")?;
    let constructor = global
        .get(scope, name.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())?;
    let tag = v8::String::new(scope, "toStringTag")?;
    let value = constructor.get(scope, tag.into())?;
    v8::Local::<v8::Symbol>::try_from(value).ok()
}

fn member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = v8::Function::builder(callback)
        .length(length)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope)
        .ok_or_else(|| format!("cannot build {name}"))?;
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    function.set_name(key);
    let mut descriptor = v8::PropertyDescriptor::new_from_value_writable(function.into(), true);
    descriptor.set_enumerable(true);
    descriptor.set_configurable(false);
    target
        .define_property(scope, key.into(), &descriptor)
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

/// `Bun.JSONL.parse(input)`.
fn parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(input) = text_argument(scope, args.get(0), "JSONL.parse requires a string argument")
    else {
        return;
    };
    match parse_all(&input) {
        Ok(values) => {
            let mut cache = crate::convert::IdentityCache::new();
            let value = Value::array(values);
            match crate::convert::to_js(scope, &value, &mut cache) {
                Ok(js) => rv.set(js),
                Err(message) => crate::convert::throw_error(scope, &message),
            }
        }
        Err(()) => crate::convert::throw_syntax_error(scope, "Failed to parse JSONL"),
    }
}

/// Reads an argument as text, or throws `message` with no `code` and returns
/// `None`.
///
/// `JSONL`'s `TypeError` has **no** `code`, unlike the other parsers'
/// `ERR_INVALID_ARG_TYPE`, so it does not go through
/// [`crate::convert::coerce_to_string`].
fn text_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    message: &str,
) -> Option<String> {
    if value.is_string() {
        return Some(value.to_rust_string_lossy(scope));
    }
    if let Some(bytes) = bytes_of(scope, value) {
        return Some(bytes);
    }
    // Everything else is `String()`-coerced, so `JSONL.parse(5)` is `[5]` and
    // `JSONL.parse(true)` is `[true]`. An `ArrayBuffer` is a byte view in
    // `bytes_of` only when it is a `Uint8Array`-like view, which is what Bun
    // accepts; a raw `ArrayBuffer` is stringified to `"[object ArrayBuffer]"`
    // and fails to parse, which is also what Bun does.
    if value.is_symbol() {
        throw_type_error(scope, "Cannot convert a symbol to a string");
        return None;
    }
    // An `ArrayBuffer` is not a stringified object here: Bun's message for
    // `JSONL.parse(undefined)` and for a raw `ArrayBuffer` is the same argument
    // error, because the check runs before any coercion.
    if value.is_undefined() || value.is_null() {
        throw_type_error(scope, message);
        return None;
    }
    if value.is_array_buffer() || value.is_shared_array_buffer() || value.is_array_buffer_view() {
        throw_type_error(scope, message);
        return None;
    }
    value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
}

/// Every value in a buffer, applying Bun's truncate-on-error rule.
///
/// The rule is about **what follows the failing token**, not about which line it
/// is on. Measured, one buffer per row:
///
/// ```text
/// parse('nope')                []       the bad token ends the buffer
/// parse('nope ')               THROW    one trailing space is enough
/// parse('nope\n')              THROW    ... and so is a newline
/// parse('{"a":')               []       an incomplete value is not an error
/// parse('{"a":nope')           []       ... nor an incomplete token
/// parse('{"a":nope ')          THROW
/// parse('[nope')               []       ... at any nesting depth
/// parse('1\nxx')               [1]      a good value first, then truncation
/// ```
///
/// So a line yields one of three outcomes:
///
/// * a value;
/// * "incomplete" — the parser ran out of input mid-value, so more bytes could
///   still make it valid: silent truncation;
/// * "invalid" — a token that is definitely wrong: an error **iff** a byte follows
///   it in the buffer, and a silent truncation otherwise.
///
/// Once a value has been produced, an invalid token truncates rather than throws,
/// which is what `parse('{"a":1}\nXXX\n{"b":2}\n')` returning `[{a: 1}]` shows.
fn parse_all(input: &str) -> Result<Vec<Value>, ()> {
    let bytes = input.as_bytes();
    let mut values = Vec::new();
    let mut at = 0usize;
    loop {
        // Skip whitespace and line breaks between values; a value may be followed
        // by anything on its own line, so the next one starts at the next line.
        while at < bytes.len() && matches!(bytes[at], b' ' | b'\t' | b'\n' | b'\r') {
            at += 1;
        }
        if at >= bytes.len() {
            return Ok(values);
        }
        // The rest of this line is one candidate value. The **raw** line is
        // parsed, not the trimmed one, so the parser's failure offset is an offset
        // into the buffer and "is there a byte after this token" is answerable.
        let end = bytes[at..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| at + offset);
        let line = &input[at..end];
        if line.trim().is_empty() {
            at = (end + 1).min(bytes.len());
            continue;
        }
        match crate::json::parse_at(line) {
            Ok((value, _)) => {
                values.push(value);
                at = (end + 1).min(bytes.len());
            }
            // Ran out of input mid-value: silent, whatever follows.
            Err(error) if error.kind == crate::json::JsonErrorKind::Incomplete => {
                return Ok(values)
            }
            Err(error) => {
                // A definite failure is an error only when a byte follows the
                // token that failed — a trailing space is enough, and so is the
                // newline at the end of the line.
                let failed_at = at + error.at;
                let follows = failed_at < bytes.len();
                if !follows || !values.is_empty() {
                    return Ok(values);
                }
                return Err(());
            }
        }
    }
}

/// `Bun.JSONL.parseChunk(input)`.
fn parse_chunk<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(input) = text_argument(
        scope,
        args.get(0),
        "JSONL.parseChunk requires a string argument",
    ) else {
        return;
    };
    let chunk = chunk(&input);
    let object = v8::Object::new(scope);
    let mut cache = crate::convert::IdentityCache::new();
    let mut set = |scope: &mut v8::PinScope<'_, '_>,
                   object: v8::Local<v8::Object>,
                   key: &str,
                   value: &Value|
     -> Result<(), String> {
        let js = crate::convert::to_js(scope, value, &mut cache)?;
        let name =
            v8::String::new(scope, key).ok_or_else(|| "cannot allocate a key".to_string())?;
        object
            .set(scope, name.into(), js)
            .ok_or_else(|| format!("cannot set {key}"))?;
        Ok(())
    };
    let read = v8::Number::new(scope, chunk.read as f64);
    let done = v8::Boolean::new(scope, chunk.done);
    if let Err(message) = (|| -> Result<(), String> {
        set(scope, object, "values", &Value::array(chunk.values))?;
        let name = v8::String::new(scope, "read").ok_or_else(|| "read".to_string())?;
        object
            .set(scope, name.into(), read.into())
            .ok_or_else(|| "cannot set read".to_string())?;
        let name = v8::String::new(scope, "done").ok_or_else(|| "done".to_string())?;
        object
            .set(scope, name.into(), done.into())
            .ok_or_else(|| "cannot set done".to_string())?;
        let name = v8::String::new(scope, "error").ok_or_else(|| "error".to_string())?;
        let error = match chunk.error {
            true => {
                let text = v8::String::new(scope, "Failed to parse JSONL").unwrap_or_else(|| {
                    v8::String::new(scope, "").expect("an empty string allocates")
                });
                v8::Exception::syntax_error(scope, text)
            }
            false => v8::null(scope).into(),
        };
        object
            .set(scope, name.into(), error)
            .ok_or_else(|| "cannot set error".to_string())?;
        Ok(())
    })() {
        crate::convert::throw_error(scope, &message);
        return;
    }
    rv.set(object.into());
}

/// The result of one `parseChunk` call.
struct Chunk {
    values: Vec<Value>,
    read: usize,
    done: bool,
    error: bool,
}

/// Splits a buffer at its last complete line and parses what is complete.
///
/// `read` always lands just past a `\n`, which is what makes resuming a plain
/// slice. A line that is complete but unparseable sets `error` and stops the read
/// before it; a trailing line with no newline is not consumed at all when it
/// fails to parse, because it may be incomplete.
fn chunk(input: &str) -> Chunk {
    let bytes = input.as_bytes();
    // The offset just past the last newline, which is the most this call can
    // consume.
    let mut consumed = 0usize;
    #[allow(unused_assignments)]
    let mut previous_end = 0usize;
    let mut start = 0usize;
    let mut values = Vec::new();
    let mut error = false;
    while let Some(offset) = bytes[start..].iter().position(|byte| *byte == b'\n') {
        let end = start + offset;
        let line = input[start..end].trim();
        // `read` excludes the line's own terminator, and a `\r\n` pair counts as
        // one terminator: `'{"a":1}\n'` reads 7 of 8 bytes and
        // `'{"a":1}\r\n'` also reads 7 of 9.
        let line_end = if bytes.get(end.wrapping_sub(1)) == Some(&b'\r') && end > start {
            end - 1
        } else {
            end
        };
        start = end + 1;
        if line.is_empty() {
            // A blank line advances the cursor only if something has already
            // been read; a buffer of nothing but blanks reads 0.
            continue;
        }
        previous_end = consumed;
        consumed = line_end;
        match crate::json::parse(line) {
            Ok(value) => values.push(value),
            Err(crate::json::JsonError {
                kind: crate::json::JsonErrorKind::Incomplete,
                ..
            }) => {
                // Not consumed, and not an error: the line may be a prefix of a
                // value whose rest is in the next chunk. `read` therefore stays at
                // the previous complete line rather than jumping past this one.
                return Chunk {
                    values,
                    read: previous_end,
                    done: false,
                    error: false,
                };
            }
            Err(_) => {
                error = true;
                // The malformed line is not consumed, so `read` stays at the end
                // of the **previous** complete line — which is the offset this
                // loop had before the malformed line was considered.
                consumed = previous_end;
                break;
            }
        }
    }
    if error {
        return Chunk {
            values,
            read: consumed,
            done: false,
            error: true,
        };
    }
    // A trailing line with no newline: it is consumed only when it parses, and
    // its `read` is its own length because there is no terminator to exclude.
    let tail = input[start..].trim();
    if !tail.is_empty() {
        if let Ok(value) = crate::json::parse(tail) {
            values.push(value);
            consumed = bytes.len();
        } else {
            // Not consumed, and not done: the tail may be incomplete, and Bun
            // reports that as "need more data" rather than an error.
            return Chunk {
                values,
                read: consumed,
                done: false,
                error: false,
            };
        }
    }
    Chunk {
        values,
        read: consumed,
        done: true,
        error,
    }
}
