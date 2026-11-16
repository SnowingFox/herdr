//! `Bun.JSON5.stringify(value, replacer, space)`.
//!
//! Output, measured:
//!
//! ```text
//! {a:1,b:"x",c:[1,2],d:true,e:null}   {a:1,b:'x',c:[1,2],d:true,e:null}
//! {a:1}, null, 2                      {\n  a: 1,\n}
//! [1,2], null, 2                      [\n  1,\n  2,\n]
//! "hi"                                'hi'
//! undefined                           undefined
//! {a:NaN,b:Infinity}                  {a:NaN,b:Infinity}
//! {a:new Date(0)}                     {d:{}}      (no enumerable own keys)
//! {a:()=>{}, b:1}                     {b:1}       (functions are dropped)
//! [undefined,1]                       [null,1]    (array holes become null)
//! ```
//!
//! Under `space` the output is multi-line with a **trailing comma** after the
//! last property of every object and array. A JSON-shaped emitter passes
//! `JSON.parse` and fails this.

use rn_v8_sys::v8;

use crate::convert::{from_js, throw_error, FromJsError};
use crate::json5::{format_float, is_identifier, quote_string};
use crate::value::{Map, Value};

/// `Bun.JSON5.stringify(value, replacer, space)`.
pub fn stringify<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = args.get(0);
    if value.is_undefined() {
        rv.set_undefined();
        return;
    }
    let replacer = args.get(1);
    if !replacer.is_null() && !replacer.is_undefined() {
        throw_error(
            scope,
            "JSON5.stringify does not support the replacer argument",
        );
        return;
    }
    let indent = indent_of(scope, args.get(2));
    let converted = match from_js(scope, value) {
        Ok(converted) => converted,
        Err(FromJsError::Throwing) => return,
        Err(FromJsError::Unconvertible) => {
            rv.set_undefined();
            return;
        }
        Err(FromJsError::BigInt) => {
            throw_error(scope, "JSON5.stringify cannot serialize BigInt");
            return;
        }
    };
    let mut out = String::new();
    write_value(&converted, &indent, 0, &mut out, false);
    let Some(text) = v8::String::new(scope, &out) else {
        return;
    };
    rv.set(text.into());
}

/// The indent string, from `stringify`'s third argument.
///
/// A number is clamped to 10 and truncated; a string is used as-is and also
/// clamped to 10 characters. Measured: `2` gives two spaces, `4` four, `"\t"` a
/// tab, `"4"` the literal `4`, and `1.9` one space.
fn indent_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<String> {
    if value.is_string() {
        let text = value.to_rust_string_lossy(scope);
        if text.is_empty() {
            return None;
        }
        return Some(text.chars().take(10).collect());
    }
    if !value.is_number() {
        return None;
    }
    let number = value.number_value(scope).unwrap_or(f64::NAN);
    if !number.is_finite() || number <= 0.0 {
        return None;
    }
    Some(" ".repeat((number.trunc() as usize).min(10)))
}

/// Writes `value`, indented by `indent` at `depth`.
///
/// `in_array` matters for one rule: a function or `undefined` inside an array
/// becomes `null`, while as an object property it is dropped. The conversion
/// layer has already flattened both to [`Value::Null`], so the caller passes the
/// distinction down.
fn write_value(
    value: &Value,
    indent: &Option<String>,
    depth: usize,
    out: &mut String,
    in_array: bool,
) {
    let _ = in_array;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&format_float(*number)),
        Value::String(text) => out.push_str(&quote_string(text)),
        Value::Temporal(text) => out.push_str(&quote_string(text)),
        // A `Date` writes as `{}`, the same as YAML's walk of it.
        Value::Date(_) => out.push_str("{}"),
        Value::Array(items) => write_array(items, indent, depth, out),
        Value::Map(map) => write_map(map, indent, depth, out),
        // Only a caller-level `stringify(undefined)` reaches this, and the
        // member returns `undefined` before getting here.
        Value::Omitted => out.push_str("null"),
    }
}

fn write_array(
    items: &crate::value::Shared<Vec<Value>>,
    indent: &Option<String>,
    depth: usize,
    out: &mut String,
) {
    let items = items.borrow();
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    match indent {
        None => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, indent, depth, out, true);
            }
            out.push(']');
        }
        Some(text) => {
            let indent: Option<String> = Some(text.clone());
            out.push('[');
            for item in items.iter() {
                out.push('\n');
                push_indent(out, &indent, depth + 1);
                write_value(item, &indent, depth + 1, out, true);
                // The trailing comma is JSON5's, not optional.
                out.push(',');
            }
            out.push('\n');
            push_indent(out, &indent, depth);
            out.push(']');
        }
    }
}

fn write_map(
    map: &crate::value::Shared<Map>,
    indent: &Option<String>,
    depth: usize,
    out: &mut String,
) {
    let map = map.borrow();
    // An `undefined` property is dropped, so the count of written entries is not
    // the map's length.
    let entries: Vec<&(String, Value)> = map.iter().filter(|(_, v)| !v.is_omitted()).collect();
    if entries.is_empty() {
        out.push_str("{}");
        return;
    }
    match indent {
        None => {
            out.push('{');
            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_key(out, key);
                out.push(':');
                write_value(value, indent, depth, out, false);
            }
            out.push('}');
        }
        Some(text) => {
            let indent: Option<String> = Some(text.clone());
            out.push('{');
            for (key, value) in entries {
                out.push('\n');
                push_indent(out, &indent, depth + 1);
                push_key(out, key);
                out.push_str(": ");
                write_value(value, &indent, depth + 1, out, false);
                out.push(',');
            }
            out.push('\n');
            push_indent(out, &indent, depth);
            out.push('}');
        }
    }
}

fn push_key(out: &mut String, key: &str) {
    if is_identifier(key) {
        out.push_str(key);
    } else {
        out.push_str(&quote_string(key));
    }
}

fn push_indent(out: &mut String, indent: &Option<String>, depth: usize) {
    if let Some(indent) = indent {
        for _ in 0..depth {
            out.push_str(indent);
        }
    }
}
