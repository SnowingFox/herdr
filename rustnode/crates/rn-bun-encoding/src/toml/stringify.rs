//! `Bun.TOML.stringify(value, replacer, space)`.
//!
//! `space` is accepted and **ignored** — TOML has no indentation to choose — and
//! `replacer` is refused rather than ignored, unlike `JSON.stringify`. The layout
//! Bun emits, measured:
//!
//! ```text
//! {a:1, b:"x"}                 a = 1\nb = "x"\n
//! {a:{b:{c:1}}}                [a.b]\nc = 1\n
//! {a:[{x:1},{y:2}]}            [[a]]\nx = 1\n\n[[a]]\ny = 2\n
//! {t:{a:1}, u:{y:2}}           [t]\na = 1\n\n[u]\ny = 2\n
//! {z:1, t:{y:2, s:{x:3}}, a:4} z = 1\na = 4\n\n[t]\ny = 2\n\n[t.s]\nx = 3\n
//! {}                           (empty string)
//! ```
//!
//! Three rules produce all of it:
//!
//! 1. **Scalars first, in their original order.** `z`, then `a`, keeps `z:1` and
//!    `a:4` ahead of the table, even though `a` is later in the object.
//! 2. **Then tables and arrays of tables, in their original order**, each
//!    preceded by one blank line. That is why `{t:{…}, u:{…}}` has a blank line
//!    before `[u]` but `{a:{b:{c:1}}}` — a single nested table — has none.
//! 3. **An empty table is a header with no body** (`[a]`), and an empty array —
//!    of anything — is a bare value (`a = []`), not a table.
//!
//! `null` is a hard error while `undefined` is silently dropped; a function or a
//! symbol value is dropped with it, and a bigint is an error.

use rn_v8_sys::v8;

use crate::convert::{from_js, throw_error, FromJsError};
use crate::value::{Map, Value};

/// `Bun.TOML.stringify(value, replacer, space)`.
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
            "TOML.stringify does not support the replacer argument",
        );
        return;
    }
    // `space` is read and discarded: TOML's layout is fixed.
    let converted = match from_js(scope, value) {
        Ok(converted) => converted,
        Err(FromJsError::Throwing) => return,
        Err(FromJsError::Unconvertible) => {
            // A top-level function or symbol has no TOML form, and Bun answers
            // `undefined` for it rather than writing an empty document.
            rv.set_undefined();
            return;
        }
        Err(FromJsError::BigInt) => {
            throw_error(scope, "TOML.stringify cannot serialize BigInt");
            return;
        }
    };
    let Value::Map(map) = &converted else {
        let _ = converted;
        throw_error(
            scope,
            "TOML.stringify expects an object at the top level (a TOML document is a table)",
        );
        return;
    };
    let mut out = String::new();
    match emit_table(map, &mut Vec::new(), &mut out, false) {
        Ok(()) => {
            let Some(text) = v8::String::new(scope, &out) else {
                return;
            };
            rv.set(text.into());
        }
        Err(message) => throw_error(scope, &message),
    }
}

/// Emits one table's contents at `path`.
///
/// The header for this table has already been written by the caller (or is
/// omitted for the document root), so this writes the values then recurses into
/// the sub-tables.
///
/// Two layout rules, both measured:
///
/// * **values first, then sub-tables**, each group in the object's own order.
///   `{z: 1, t: {y: 2, s: {x: 3}}, a: 4}` is `z = 1\na = 4\n\n[t]…`, so `a` jumps
///   ahead of `t` but stays after `z`.
/// * **one blank line before a header, never at the start of the document.**
///   `{a: {b: {c: 1}}}` is `[a.b]\nc = 1\n` with no leading newline, while
///   `{a: 1, t: {b: 2}}` has one between the value and `[t]`.
///
/// An array of **tables** is not a value: it becomes `[[key]]` sections. An array
/// that mixes a mapping and a scalar is a value (`a = [{ x = 1 }, 2]`), and an
/// empty array is a value (`a = []`).
fn emit_table(
    map: &crate::value::Shared<Map>,
    path: &mut Vec<String>,
    out: &mut String,
    emit_keys: bool,
) -> Result<(), String> {
    for (key, value) in map.borrow().iter() {
        if !is_value(value) {
            continue;
        }
        out.push_str(&key_repr(key));
        out.push_str(" = ");
        out.push_str(&inline_value(key, value)?);
        out.push('\n');
    }
    for (key, value) in map.borrow().iter() {
        match value {
            Value::Map(nested) => {
                path.push(key.clone());
                // A table with values of its own gets a header; one that only
                // exists to hold sub-tables does not. `{a: {b: {c: 1}}}` is
                // `[a.b]` with no `[a]`, while `{a: {b: 1, c: {d: 2}}}` has both.
                let has_values = nested.borrow().iter().any(|(_, item)| is_value(item));
                let has_children = !nested.borrow().is_empty();
                if has_values {
                    open_header(out, path, false);
                }
                emit_table(nested, path, out, true)?;
                // A child that rendered nothing and had no values needs its own
                // header so the table is not silently lost.
                if !has_values && !has_children {
                    open_header(out, path, false);
                }
                path.pop();
            }
            Value::Array(items) if is_array_of_tables(items) => {
                path.push(key.clone());
                let snapshot: Vec<Value> = items.borrow().clone();
                for item in &snapshot {
                    open_header(out, path, true);
                    if let Value::Map(element) = item {
                        emit_table(element, path, out, true)?;
                    }
                }
                path.pop();
            }
            _ => {}
        }
    }
    let _ = emit_keys;
    Ok(())
}

/// Writes `\n[key]\n` or `\n[[key]]\n`, except at the very start of the output.
///
/// The blank line separates a header from whatever came before it, and there is
/// nothing before the first line of a document.
fn open_header(out: &mut String, path: &[String], array: bool) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(if array { "[[" } else { "[" });
    out.push_str(&path_repr(path));
    out.push_str(if array { "]]\n" } else { "]\n" });
}

/// Whether a value is written as `key = …` inside a table rather than as a
/// header of its own.
///
/// An `Omitted` value — `undefined`, a function, a symbol — is not a value at
/// all: it disappears, which is why `{a: undefined}` is the empty document.
fn is_value(value: &Value) -> bool {
    match value {
        Value::Omitted => false,
        Value::Map(_) => false,
        Value::Array(items) => !is_array_of_tables(items),
        _ => true,
    }
}

/// Whether an array is an array of tables, which is `[[a]]`, rather than a
/// value, which is `a = [{...}]`.
///
/// The rule is that every member is a mapping. An array that mixes a mapping and
/// a scalar is a value: `{a: [{x:1}, 2]}` is `a = [{ x = 1 }, 2]`.
fn is_array_of_tables(items: &crate::value::Shared<Vec<Value>>) -> bool {
    let items = items.borrow();
    !items.is_empty() && items.iter().all(|item| matches!(item, Value::Map(_)))
}

/// A key, quoted unless it is a legal bare key.
///
/// Bun quotes anything outside `A-Za-z0-9_-`, including a `.` and a non-ASCII
/// letter: `{"a b": 1}` is `"a b" = 1` and `{"é": 5}` is `"é" = 5`.
fn key_repr(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if bare {
        key.to_string()
    } else {
        quote_string(key)
    }
}

fn path_repr(path: &[String]) -> String {
    path.iter()
        .map(|segment| key_repr(segment))
        .collect::<Vec<_>>()
        .join(".")
}

/// A value written after `key = `, or inside an array.
fn inline_value(key: &str, value: &Value) -> Result<String, String> {
    Ok(match value {
        Value::Null => {
            return Err(format!(
                "TOML cannot represent null (key '{key}'); remove the key or use a sentinel value"
            ));
        }
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => crate::toml::format_float(*number),
        Value::String(text) => quote_string(text),
        Value::Temporal(text) => text.clone(),
        // A `Date` is an instant, written in TOML's offset-date-time form.
        Value::Date(millis) => crate::toml::date_to_rfc3339(*millis),
        Value::Array(items) => {
            let items = items.borrow();
            let mut parts = Vec::with_capacity(items.len());
            for item in items.iter() {
                parts.push(inline_value(key, item).map_err(|error| {
                    if error.starts_with("TOML cannot represent null (key ") {
                        "TOML cannot represent null in an array".to_string()
                    } else {
                        error
                    }
                })?);
            }
            format!("[{}]", parts.join(", "))
        }
        Value::Omitted => String::new(),
        Value::Map(map) => {
            // Only reached for an array member, since a top-level mapping is a
            // header. An inline table writes its keys in order.
            let map = map.borrow();
            let mut parts = Vec::with_capacity(map.len());
            for (name, item) in map.iter() {
                if item.is_omitted() {
                    continue;
                }
                parts.push(format!(
                    "{} = {}",
                    key_repr(name),
                    inline_value(name, item)?
                ));
            }
            format!("{{ {} }}", parts.join(", "))
        }
    })
}

/// A string in TOML basic-string form.
fn quote_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if control.is_control() || control == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
