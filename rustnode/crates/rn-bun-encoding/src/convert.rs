//! Turning [`Value`] into V8 values and back.
//!
//! Both directions are shared by every namespace, so the rules that only hold
//! for one format live in that format's module and the rules that hold for all
//! of them live here.
//!
//! # Identity
//!
//! A YAML alias is the *same object* as its anchor, and YAML alone can produce a
//! cycle. Both fall out of one rule: a [`Shared`] cell is converted at most once
//! per document, and every later occurrence reuses the object already built for
//! it. The cache is keyed by [`Shared::identity`], so a mapping nested in two
//! places becomes one JavaScript object instead of two that look alike, and a
//! cycle becomes a self-referencing object instead of infinite recursion.
//!
//! The cache is per-conversion, not global: two separate `YAML.parse` calls must
//! not share objects, and an identity address is only meaningful for as long as
//! the document holding it is alive.

use std::collections::HashMap;

use rn_v8_sys::v8;

use crate::value::{Map, Value};

/// The objects a single conversion has already built, by cell identity.
///
/// `Global` rather than `Local` because an object built early can be evicted
/// from the handle scope by the time a later alias needs it, and a dangling
/// `Local` would be a use-after-free. The handle is reset when the conversion
/// finishes, so nothing outlives the call.
#[derive(Default)]
pub struct IdentityCache {
    built: HashMap<usize, v8::Global<v8::Object>>,
}

impl IdentityCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Builds the JavaScript value for a parsed [`Value`].
///
/// A [`Value::Temporal`] is materialised as the real `Temporal` object Bun
/// returns, not as a string: Bun 1.4.4 answers `TOML.parse("d = 1979-05-27")`
/// with a `Temporal.PlainDate`, and the spec records `ctor`, tag and
/// `String(value)` for all four datetime kinds. The JSON serialisation of a
/// `PlainDate` and of the string `"1979-05-27"` are identical, so a test that
/// only compares JSON cannot tell them apart — that is exactly why this converts
/// rather than storing the text.
pub fn to_js<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: &Value,
    cache: &mut IdentityCache,
) -> Result<v8::Local<'s, v8::Value>, String> {
    Ok(match value {
        // `Omitted` never reaches an array element or a mapping value that a
        // parser produced, so converting it as `null` is only a safety net.
        Value::Null | Value::Omitted => v8::null(scope).into(),
        Value::Bool(flag) => v8::Boolean::new(scope, *flag).into(),
        Value::Number(number) => v8::Number::new(scope, *number).into(),
        Value::String(text) => v8::String::new(scope, text)
            .ok_or_else(|| "cannot allocate a string".to_string())?
            .into(),
        Value::Array(items) => {
            if let Some(existing) = cache.built.get(&items.identity()) {
                return Ok(v8::Local::new(scope, existing).into());
            }
            // Arrays and objects are both real objects in JavaScript; the cache
            // stores them as `Object` so one entry can serve either kind.
            let array = v8::Array::new(scope, 0);
            let as_object = v8::Local::<v8::Object>::from(array);
            cache
                .built
                .insert(items.identity(), v8::Global::new(scope, as_object));
            for item in items.borrow().iter() {
                let element = to_js(scope, item, cache)?;
                let length = array.length();
                array
                    .set_index(scope, length, element)
                    .ok_or_else(|| "cannot set an array element".to_string())?;
            }
            array.into()
        }
        Value::Map(map) => {
            if let Some(existing) = cache.built.get(&map.identity()) {
                return Ok(v8::Local::new(scope, existing).into());
            }
            let object = v8::Object::new(scope);
            cache
                .built
                .insert(map.identity(), v8::Global::new(scope, object));
            for (key, item) in map.borrow().iter() {
                let name = v8::String::new(scope, key)
                    .ok_or_else(|| "cannot allocate a key".to_string())?;
                let element = to_js(scope, item, cache)?;
                object
                    .set(scope, name.into(), element)
                    .ok_or_else(|| format!("cannot set the key {key}"))?;
            }
            object.into()
        }
        Value::Temporal(text) => temporal(scope, text)?,
        // A `Date` only reaches `to_js` from a parsed document, which never
        // produces one; the variant exists for the stringify direction.
        Value::Date(_) => v8::null(scope).into(),
    })
}

/// Builds the `Temporal` instance a TOML datetime denotes.
///
/// The kind is chosen by the shape of the text, which is the same rule Bun
/// applies: an offset or `Z` is an `Instant` normalised to UTC, a date alone is
/// a `PlainDate`, a time alone is a `PlainTime`, and a date-time with no offset
/// is a `PlainDateTime`. `Temporal.<Kind>.from(text)` performs the construction,
/// so the parsing of leap seconds, fractional precision and offset normalisation
/// is the engine's rather than a second implementation here.
fn temporal<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    text: &str,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let kind = temporal_kind(text);
    let global = scope.get_current_context().global(scope);
    let temporal_key =
        v8::String::new(scope, "Temporal").ok_or_else(|| "cannot allocate Temporal".to_string())?;
    let temporal = global
        .get(scope, temporal_key.into())
        .filter(|value| value.is_object())
        .ok_or_else(|| "Temporal is not available in this context".to_string())?;
    let temporal = v8::Local::<v8::Object>::try_from(temporal)
        .map_err(|_| "Temporal is not available in this context".to_string())?;
    let kind_key = v8::String::new(scope, kind)
        .ok_or_else(|| "cannot allocate a Temporal kind".to_string())?;
    let constructor = temporal
        .get(scope, kind_key.into())
        .filter(|value| value.is_object())
        .ok_or_else(|| format!("Temporal.{kind} is not available in this context"))?;
    let constructor = v8::Local::<v8::Object>::try_from(constructor)
        .map_err(|_| format!("Temporal.{kind} is not an object"))?;
    let from_key =
        v8::String::new(scope, "from").ok_or_else(|| "cannot allocate from".to_string())?;
    let from = constructor
        .get(scope, from_key.into())
        .filter(|value| value.is_function())
        .ok_or_else(|| format!("Temporal.{kind}.from is not a function"))?;
    let from = v8::Local::<v8::Function>::try_from(from)
        .map_err(|_| format!("Temporal.{kind}.from is not a function"))?;
    let text = v8::String::new(scope, text)
        .ok_or_else(|| "cannot allocate a Temporal string".to_string())?;
    from.call(scope, constructor.into(), &[text.into()])
        .ok_or_else(|| format!("Temporal.{kind}.from threw for {text:?}"))
}

/// Which `Temporal` constructor a TOML datetime text denotes.
fn temporal_kind(text: &str) -> &'static str {
    let bytes = text.as_bytes();
    let has_date = bytes.len() >= 10 && bytes[4] == b'-' && bytes[7] == b'-';
    let has_time = text.contains(':');
    let has_offset = text.ends_with('Z')
        || text.ends_with('z')
        || text
            .rfind(['+', '-'])
            .is_some_and(|at| at > 10 && text[at..].contains(':'));
    match (has_date, has_time) {
        (false, _) => "PlainTime",
        (true, true) if has_offset => "Instant",
        (true, true) => "PlainDateTime",
        (true, false) => "PlainDate",
    }
}

/// Reads `value` as whatever a stringifier should serialise.
///
/// Objects are walked as `Map`s, arrays as `Value::Array`s. A plain string has
/// to stay a [`Value::String`] rather than an array of characters, so strings and
/// arrays are checked before the generic object path.
pub fn from_js<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Value, FromJsError> {
    // `undefined` is not `null`: an object property holding it is dropped by
    // every stringifier here, while a `null` one is written. The two coincide
    // only inside an array, where the array emitter maps `Omitted` to `null`.
    if value.is_undefined() {
        return Ok(Value::Omitted);
    }
    if value.is_null() {
        return Ok(Value::Null);
    }
    if value.is_boolean() {
        return Ok(Value::Bool(value.boolean_value(scope)));
    }
    if value.is_number() {
        return Ok(Value::Number(value.number_value(scope).unwrap_or(f64::NAN)));
    }
    if value.is_string() {
        return Ok(Value::String(value.to_rust_string_lossy(scope)));
    }
    if value.is_big_int() {
        return Err(FromJsError::BigInt);
    }
    // A function is an object in V8, so this has to come before the object
    // branch or it would be walked as `{}` — which is exactly what
    // `{a: () => {}}` produced before this check existed.
    if value.is_function() {
        return Err(FromJsError::Unconvertible);
    }
    if value.is_symbol() {
        return Err(FromJsError::Unconvertible);
    }
    // A boxed primitive (`new Number(1)`) is an object whose enumerable own keys
    // are its index properties, which is the same trap: `String.prototype`
    // methods make `Bun.YAML.stringify(new String("x"))` an object, not a string.
    // Walking it is what every stringifier here does, so no special case.

    if value.is_array() {
        let array =
            v8::Local::<v8::Array>::try_from(value).map_err(|_| FromJsError::Unconvertible)?;
        let length = array.length();
        let mut items = Vec::with_capacity(length as usize);
        for index in 0..length {
            let element = array.get_index(scope, index).ok_or(FromJsError::Throwing)?;
            // An array hole, an explicit `undefined` and a function member are
            // all `null` in `JSON.stringify`, so the distinction is erased here
            // rather than in each array emitter.
            let converted = match from_js(scope, element) {
                Ok(converted) => converted,
                Err(FromJsError::Unconvertible) => Value::Omitted,
                Err(other) => return Err(other),
            };
            items.push(if converted.is_omitted() {
                Value::Null
            } else {
                converted
            });
        }
        return Ok(Value::array(items));
    }
    if value.is_date() {
        // A `Date` has no enumerable own property, so walking it would give `{}`.
        // `TOML.stringify({d: new Date(0)})` is `d = 1970-01-01T00:00:00Z`, and
        // `YAML.stringify` gives `{d: {}}` — so the two members disagree about
        // what a Date is, and neither is served by a generic walk. This converts
        // it to the ISO text, which TOML writes verbatim; YAML's emitter chooses
        // `{}` for a `Temporal`-shaped value because that is what its own
        // object walk produces, and the corpus pins both.
        let date =
            v8::Local::<v8::Date>::try_from(value).map_err(|_| FromJsError::Unconvertible)?;
        return Ok(Value::Date(date.value_of()));
    }
    if value.is_object() {
        let object =
            v8::Local::<v8::Object>::try_from(value).map_err(|_| FromJsError::Unconvertible)?;
        return Ok(Value::map(object_from_js(scope, object)?));
    }
    Err(FromJsError::Unconvertible)
}

/// Why a value could not be converted.
#[derive(Debug)]
pub enum FromJsError {
    /// A JavaScript exception is already pending on the scope.
    ///
    /// A property getter can throw, and a `Proxy` can throw from `ownKeys`; both
    /// surface here as "the exception is the error", not as a Rust-side failure,
    /// so the caller returns without throwing a second one.
    Throwing,
    /// A value with no representation in any of these formats — a symbol or a
    /// function.
    ///
    /// These are **dropped** from a mapping and become `null` in an array, which
    /// is what `JSON.stringify` does and what every Bun stringifier here does.
    Unconvertible,
    /// A bigint, which is a hard error rather than a drop.
    ///
    /// Every stringifier here refuses one: `YAML.stringify({a: 10n})`,
    /// `TOML.stringify({a: 10n})` and `JSON5.stringify` all say so, and the
    /// message differs per member. It is a separate variant because the caller
    /// has to produce that message, and because silently dropping a bigint would
    /// turn a precision bug into a missing field.
    BigInt,
}

/// Walks `object`'s own enumerable string-keyed properties into a [`Map`].
///
/// `Object.keys` semantics: own properties, enumerable, strings only, in the
/// order V8 reports them. That is what `JSON.stringify` and Bun's stringifiers
/// iterate, so it is the right projection.
fn object_from_js<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Result<Map, FromJsError> {
    let names = object
        .get_property_names(
            scope,
            v8::GetPropertyNamesArgs {
                mode: v8::KeyCollectionMode::OwnOnly,
                property_filter: v8::PropertyFilter::ONLY_ENUMERABLE,
                index_filter: v8::IndexFilter::IncludeIndices,
                key_conversion: v8::KeyConversionMode::ConvertToString,
            },
        )
        .ok_or(FromJsError::Throwing)?;
    let mut map = Map::new();
    for index in 0..names.length() {
        let name = names.get_index(scope, index).ok_or(FromJsError::Throwing)?;
        let name = name
            .to_string(scope)
            .ok_or(FromJsError::Throwing)?
            .to_rust_string_lossy(scope);
        let key = v8::String::new(scope, &name).ok_or(FromJsError::Throwing)?;
        let element = object.get(scope, key.into()).ok_or(FromJsError::Throwing)?;
        // A function or symbol property is omitted rather than an error: every
        // stringifier here drops it, which is `JSON.stringify`'s rule and Bun's.
        let converted = match from_js(scope, element) {
            Ok(converted) => converted,
            Err(FromJsError::Unconvertible) => Value::Omitted,
            Err(other) => return Err(other),
        };
        map.push(name, converted);
    }
    Ok(map)
}

/// Reads argument as a string-or-bytes value, applying `String()` to every other
/// non-symbol value.
///
/// This is the rule `Bun.YAML.parse`, `Bun.JSON5.parse`, `Bun.JSONC.parse` and
/// `Bun.XML.parse` follow: `parse(42)` parses `"42"`, `parse()` parses
/// `"undefined"`, and `parse(Symbol())` throws the engine's own
/// `TypeError: Cannot convert a symbol to a string` rather than being stringified.
///
/// Byte views are decoded as UTF-8 with replacement, which is what Bun does with
/// invalid bytes: `YAML.parse(new Uint8Array([0xff, 0x41]))` is the string
/// `"\u{fffd}A"`.
pub fn coerce_to_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<String, CoerceError> {
    if value.is_string() {
        return Ok(value.to_rust_string_lossy(scope));
    }
    if let Some(bytes) = bytes_of(scope, value) {
        return Ok(bytes);
    }
    if value.is_symbol() {
        // `String()` on a symbol is legal, but Bun's native parsers run the
        // value through a conversion that rejects it. Match the rejection and
        // the message rather than inventing one.
        throw_type_error(scope, "Cannot convert a symbol to a string");
        return Err(CoerceError::Thrown);
    }
    let Some(text) = value.to_string(scope) else {
        return Err(CoerceError::Thrown);
    };
    Ok(text.to_rust_string_lossy(scope))
}

/// Reads a value as UTF-8 text if it is a byte view, and `None` otherwise.
///
/// `ArrayBuffer`, `SharedArrayBuffer` and every `ArrayBufferView` (which includes
/// `DataView` and the typed arrays) are byte views. Note that Bun treats a
/// `Uint16Array` as **bytes**, not as code units:
/// `markdown.html(new Uint16Array([35, 32, 120]))` renders the six bytes
/// `23 00 20 00 78 00`, so the view is read as UTF-8 rather than reinterpreted.
pub fn bytes_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<String> {
    let _ = scope;
    if value.is_array_buffer() || value.is_shared_array_buffer() {
        let buffer = v8::Local::<v8::ArrayBuffer>::try_from(value).ok()?;
        let length = buffer.byte_length();
        let store = buffer.get_backing_store();
        let cells = store.get(..length)?;
        let bytes: Vec<u8> = cells.iter().map(|cell| cell.get()).collect();
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    if value.is_array_buffer_view() {
        let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
        let mut bytes = vec![0u8; view.byte_length()];
        view.copy_contents(&mut bytes);
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    None
}

/// Why a coerced argument could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum CoerceError {
    /// An exception is pending on the scope.
    Thrown,
}

/// Throws `TypeError` with `message` and no `code`.
pub fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws `TypeError` with `message` and `code`, which is what Bun's argument
/// validators do for `ERR_INVALID_ARG_TYPE`.
pub fn throw_type_error_with_code(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    set_error_code(scope, exception, code);
    scope.throw_exception(exception);
}

/// Throws `SyntaxError` with `message`. Bun's parser errors carry no `code`.
pub fn throw_syntax_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::syntax_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a plain `Error` with `message`, which is what the three stringify
/// argument checks and the XML/TOML representability checks use.
pub fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

/// Sets `error.code`, which Bun does for `ERR_INVALID_ARG_TYPE` and not for its
/// parser errors.
fn set_error_code(scope: &mut v8::PinScope<'_, '_>, exception: v8::Local<v8::Value>, code: &str) {
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        return;
    };
    let Some(code) = v8::String::new(scope, code) else {
        return;
    };
    if let Some(key) = v8::String::new(scope, "code") {
        let _ = object.set(scope, key.into(), code.into());
    }
}

/// Reads a value as a string or bytes, and throws `message` with
/// `ERR_INVALID_ARG_TYPE` when it is anything else.
///
/// This is `Bun.TOML.parse`'s rule: it takes a string or bytes and refuses the
/// rest, unlike the four parsers that stringify. The spec pins the message
/// `"input must be a string, ArrayBuffer, ArrayBufferView or Blob"`.
///
/// A `Blob` is not read: Bun accepts one because its own `Blob` can be read
/// synchronously, and `rn-bind-blob`'s can too, but the read would need a V8
/// call into the blob handle and this crate cannot reach that crate's private
/// keys. The divergence is recorded in the crate report rather than pretended
/// away; the message still names `Blob`, because it is Bun's message.
pub fn require_string_or_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    message: &str,
) -> Result<String, CoerceError> {
    if value.is_string() {
        return Ok(value.to_rust_string_lossy(scope));
    }
    if let Some(bytes) = bytes_of(scope, value) {
        return Ok(bytes);
    }
    throw_type_error_with_code(scope, "ERR_INVALID_ARG_TYPE", message);
    Err(CoerceError::Thrown)
}

/// Reads a value as a string or bytes, and otherwise returns `None` without
/// throwing.
///
/// `Bun.markdown`'s four entry points all validate the same way but throw the
/// same `"Expected a string or buffer to render"`, so they share one check.
pub fn string_or_bytes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<String> {
    if value.is_string() {
        return Some(value.to_rust_string_lossy(scope));
    }
    bytes_of(scope, value)
}

#[cfg(test)]
mod tests {
    use super::temporal_kind;

    #[test]
    fn temporal_kinds_follow_the_offset_rule() {
        assert_eq!(temporal_kind("1979-05-27T07:32:00Z"), "Instant");
        assert_eq!(temporal_kind("1979-05-27T07:32:00.999999Z"), "Instant");
        assert_eq!(temporal_kind("1979-05-27T00:32:00-07:00"), "Instant");
        assert_eq!(temporal_kind("1979-05-27T07:32:00+00:00"), "Instant");
        assert_eq!(temporal_kind("1979-05-27"), "PlainDate");
        assert_eq!(temporal_kind("07:32:00"), "PlainTime");
        assert_eq!(temporal_kind("07:32:00.999"), "PlainTime");
        assert_eq!(temporal_kind("1979-05-27T07:32:00"), "PlainDateTime");
        assert_eq!(temporal_kind("1979-05-27T07:32:00.5"), "PlainDateTime");
    }
}
