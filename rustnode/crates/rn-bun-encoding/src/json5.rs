//! `Bun.JSON5.parse` and `Bun.JSON5.stringify`.
//!
//! JSON5 is JSON with comments, single quotes, trailing commas, unquoted keys,
//! hex numbers, a leading `+`, `Infinity`/`NaN`, and string line continuations.
//! Bun implements it as a hand-written scanner and the diagnostics below are its
//! own, not `serde_json`'s, so the scanner is here.
//!
//! Two measured behaviours are worth pinning before reading the code:
//!
//! * **`Infinity` and `NaN` are accepted but do not survive.** Bun parses
//!   `{inf: Infinity}` and hands back `{inf: Infinity}`, which is right, but a
//!   `JSON.stringify` comparison reports `null` because JSON has no spelling for
//!   them. So the test compares with `Object.is`.
//! * **`undefined` is a parse error but `NaN` is not.** `{a: undefined}` is
//!   `Unexpected token`; the leniency is limited to the numeric keywords.
//!
//! `stringify` is JSON5-flavoured, not JSON: unquoted keys, single-quoted
//! strings, and — under a `space` — a trailing comma after the last property.
//! A JSON-compatible emitter passes a `JSON.parse` check and fails this one.

use rn_v8_sys::v8;

use crate::convert::{throw_error, throw_syntax_error};
use crate::value::format_number;

mod parse;
mod stringify;

/// Builds the `Bun.JSON5` namespace object.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    set(scope, object, "parse", 1, parse_member)?;
    set(scope, object, "stringify", 3, stringify::stringify)?;
    Ok(object)
}

fn set<'s>(
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
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

fn parse_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `JSON5.parse` refuses `null` and a missing argument with
    // `ERR_INVALID_ARG_TYPE`, and stringifies everything else — so `parse(42)`
    // is the document `42` and `parse([])` is `""`, which is an empty-input
    // error. The nullish check comes first because `String(null)` is a legal
    // document Bun never parses.
    let argument = args.get(0);
    let input = match crate::convert::string_or_bytes(scope, argument) {
        Some(input) => input,
        None if argument.is_null() || argument.is_undefined() => {
            crate::convert::throw_type_error_with_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
            );
            return;
        }
        None => match argument.to_string(scope) {
            Some(text) => text.to_rust_string_lossy(scope),
            None => return,
        },
    };
    let value = match parse::value(&input) {
        Ok(value) => value,
        Err(message) => {
            throw_syntax_error(scope, &format!("JSON5 Parse error: {message}"));
            return;
        }
    };
    let mut cache = crate::convert::IdentityCache::new();
    match crate::convert::to_js(scope, &value, &mut cache) {
        Ok(js) => rv.set(js),
        Err(message) => throw_error(scope, &message),
    }
}

/// A float the way `JSON5.stringify` writes it: `NaN` and `±Infinity` spelled
/// out, and everything else JavaScript's `String(n)`.
pub(crate) fn format_float(value: f64) -> String {
    format_number(value)
}

/// Whether a key can be written without quotes.
pub(crate) fn is_identifier(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|character| character.is_alphanumeric() || character == '_' || character == '$')
}

/// A string in JSON5 single-quoted form.
pub(crate) fn quote_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for character in text.chars() {
        match character {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{0}' => out.push_str("\\0"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quoted_strings_escape_the_delimiter_only() {
        assert_eq!(quote_string("x"), "'x'");
        assert_eq!(quote_string("it's"), "'it\\'s'");
        assert_eq!(quote_string("a\"b"), "'a\"b'");
        assert_eq!(quote_string("a\\b"), "'a\\\\b'");
        assert_eq!(quote_string("x\ny"), "'x\\ny'");
        assert_eq!(quote_string("é"), "'é'");
    }

    #[test]
    fn identifiers_are_the_unquoted_key_set() {
        for key in ["a", "a1", "_", "$", "$x", "_y", "é"] {
            assert!(is_identifier(key), "{key} should be unquoted");
        }
        for key in ["", "1", "a b", "a-b", "a.b"] {
            assert!(!is_identifier(key), "{key} should be quoted");
        }
    }
}
