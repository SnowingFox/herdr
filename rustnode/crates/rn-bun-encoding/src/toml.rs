//! `Bun.TOML.parse` and `Bun.TOML.stringify`.
//!
//! # Why this is a parser rather than a wrapper round `toml`
//!
//! `toml` 0.8 is a correct TOML 1.0 implementation, but its diagnostics are
//! nothing like Bun's and cannot be made so:
//!
//! ```text
//! input:  "a = [1 2]"
//! Bun:    TOML Parse error: Expected ',' or ']' in an array but found '2'
//! toml:   invalid array
//!         expected `]`
//! ```
//!
//! Bun names the offending token in most of its messages, and it distinguishes
//! shapes that `toml` collapses into one. A mapping table could match the common
//! cases and would quietly get the rest wrong, which is a divergence that only
//! appears once something is already failing. So the grammar is here, written
//! against Bun's measured message set, and `toml` is not a dependency — which
//! also keeps this crate off `toml_edit`, `serde_spanned` and `winnow`.
//!
//! # Tables, and the ways a name can already exist
//!
//! Bun reports each collision separately and the messages are not
//! interchangeable. Measured, one document per case:
//!
//! ```text
//! a = 1      then [a]        Cannot redefine key 'a' as a table
//! a = {x=1}  then [a]        Cannot redefine inline table 'a'
//! a = 1      then [[a]]      Cannot redefine key 'a' as an array of tables
//! [a]        then [a]        Cannot redefine table 'a'
//! [a]        then [[a]]      Cannot redefine table 'a' as an array of tables
//! [[a]]      then [a]        Cannot redefine array of tables 'a' as a table
//! [a] b=1    then [a.b.c]    Cannot redefine key 'b' as a table
//! a = {x=1}  then [a.c]      Cannot extend inline table 'a'
//! [a.b] c=1  then [a] b.d=1  Cannot extend table 'b' with a dotted key
//! ```
//!
//! A table therefore has to remember **how it was created**, and every
//! construction checks that kind rather than mere presence.
//!
//! The other half is that `[a.b]` followed by `[a]` is legal — a header may open
//! an implicit parent that only existed because a child named it — while `[a.b]`
//! followed by `[a.b]` is not. That is the difference between
//! [`TableKind::Implicit`] and [`TableKind::Header`].
//!
//! # Datetimes become `Temporal`
//!
//! Bun returns `Temporal.Instant`/`PlainDate`/`PlainTime`/`PlainDateTime`, never
//! `Date`, and the spec pins `constructor.name` for all four.
//! [`crate::convert`] builds the real object; this module only decides which one
//! a datetime text denotes and normalises an offset to UTC, which is what Bun's
//! `String(value)` reports and what `TOML.stringify` writes back.

use rn_v8_sys::v8;

use crate::convert::throw_error;

/// How a table came into existence, which decides what may extend it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TableKind {
    /// Opened by a `[header]`.
    Header,
    /// Named only as the parent of a header (`[a.b]` makes `a` implicit).
    Implicit,
    /// Created by a dotted key (`a.b = 1` makes `a` dotted).
    Dotted,
    /// The contents of an inline table (`a = {x = 1}`), closed to extension.
    Inline,
}

/// The kind of every table in one document, by cell identity.
///
/// A table reached through a `Value::Map` does not carry its kind, and the kind
/// is not something a consumer can see, so it lives beside the document rather
/// than inside it.
pub(crate) type Kinds = std::collections::HashMap<usize, TableKind>;

/// A float the way TOML writes it.
///
/// TOML differs from JavaScript in one place: an integral value beyond 2^53 has
/// no integer form, so it is written with a `.0` to say `float`
/// (`9007199254740992.0`), and negative zero keeps its sign (`-0.0`).
pub(crate) fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-inf" } else { "inf" }.to_string();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0"
        }
        .to_string();
    }
    let formatted = crate::value::format_number_with(value, true);
    if value.fract() == 0.0 && value.abs() >= 9_007_199_254_740_992.0 {
        return format!("{formatted}.0");
    }
    formatted
}

pub(crate) mod datetime;
mod stringify;
mod table;
mod value;

/// Builds the `Bun.TOML` namespace object.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    set(scope, object, "parse", 1, parse)?;
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

/// `Bun.TOML.parse(input)`.
fn parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Unlike the other parsers, `TOML.parse` refuses anything that is not a
    // string or bytes instead of stringifying it. A `Blob` reaches here only as
    // its bytes, when the caller has already read it; see the crate report for
    // that one divergence.
    // The argument rules, measured one value at a time:
    //
    //   no argument, `null`, `undefined`   ERR_INVALID_ARG_TYPE
    //   `42`, `true`                       String()-coerced, then parsed
    //   `{}`                               String() is "[object Object]"
    //   `[]`, `["a=1"]`                    String()-coerced, so a one-element
    //                                      array of TOML text parses as that text
    //
    // Only the first row refuses, so the check is "is it nullish", not "is it a
    // string or bytes" — which is why this does not reuse
    // `require_string_or_bytes`.
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
    let value = match table::document(&input) {
        Ok(value) => value,
        Err(message) => {
            crate::convert::throw_syntax_error(scope, &format!("TOML Parse error: {message}"));
            return;
        }
    };
    let mut cache = crate::convert::IdentityCache::new();
    match crate::convert::to_js(scope, &value, &mut cache) {
        Ok(js) => rv.set(js),
        Err(message) => throw_error(scope, &message),
    }
}

/// The RFC 3339 instant for a JavaScript `Date`, shared with `XML.stringify`.
pub(crate) fn date_to_rfc3339(millis: f64) -> String {
    datetime::from_millis(millis)
}
