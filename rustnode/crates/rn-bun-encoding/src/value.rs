//! The `value` model every parser produces and each stringifier consumes.
//!
//! The parsers work on bytes and produce this tree; [`crate::convert`] turns it
//! into JavaScript. Nothing here touches V8, so the whole conversion layer is
//! testable without an isolate.
//!
//! # Why sequences and mappings are shared cells
//!
//! YAML has anchors and aliases, and Bun **resolves them to the same object
//! rather than a copy**. Two measurements from Bun 1.4.4 fix the design:
//!
//! ```text
//! const p = Bun.YAML.parse("a: &x [1]\nb: *x");   p.a === p.b  =>  true
//! Bun.YAML.parse("a: &x\n  b: *x")                =>  a cyclic object
//! ```
//!
//! The second one is genuinely cyclic — `JSON.stringify` on it throws
//! `TypeError: JSON.stringify cannot serialize cyclic structures` — so an alias
//! is not something a deep tree can express at all. [`Shared`] is one `Rc` of a
//! `RefCell`, which gives identity comparison (`Rc::ptr_eq`), in-place filling
//! after a node has been given an anchor (the cycle case), and a cheap clone for
//! the alias itself. The other five formats build the same structure without
//! ever sharing two references, so they pay only for the pointer.
//!
//! # Key order is insertion order, as in JavaScript
//!
//! `Bun.YAML.parse` hands back an object whose `Object.keys()` follows the
//! document, except that canonical array indexes sort ahead of string keys,
//! which V8's object model does on its own. [`Map`] therefore appends, and a
//! duplicate key replaces the value **in place**, which is what `obj[k] = v`
//! does. That is observable: `YAML.parse("a: 1\nb: 2\na: 3")` has
//! `Object.keys()` of `["a", "b"]`, not `["b", "a"]`.
//!
//! # Numbers are `f64`
//!
//! Every format here parses to a JavaScript number, so an integer beyond 2^53
//! cannot be represented and TOML is the only format that refuses it instead of
//! rounding. Holding `f64` rather than `i64` keeps those two behaviours one
//! code path apart instead of two.

use std::cell::{Ref, RefCell, RefMut};
use std::fmt::Write as _;
use std::rc::Rc;

/// A value shared by identity, which is what a YAML anchor produces.
#[derive(Debug)]
pub struct Shared<T>(Rc<RefCell<T>>);

impl<T> Shared<T> {
    /// Wraps `value`.
    pub fn new(value: T) -> Self {
        Shared(Rc::new(RefCell::new(value)))
    }

    /// Whether two handles are the same cell.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// The address of the cell, which is the key [`crate::convert`] uses to
    /// notice that two aliases are one object.
    pub fn identity(&self) -> usize {
        Rc::as_ptr(&self.0) as usize
    }

    /// Borrows the contents.
    pub fn borrow(&self) -> Ref<'_, T> {
        self.0.borrow()
    }

    /// Borrows the contents mutably.
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        self.0.borrow_mut()
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Shared(Rc::clone(&self.0))
    }
}

impl<T: PartialEq> PartialEq for Shared<T> {
    /// Structural equality, with identity short-circuiting recursion.
    ///
    /// The short-circuit is what makes comparing two cyclic documents
    /// terminate: an alias pair compares equal on the pointer before either side
    /// is entered again.
    fn eq(&self, other: &Self) -> bool {
        if self.ptr_eq(other) {
            return true;
        }
        *self.borrow() == *other.borrow()
    }
}

/// One parsed value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// JavaScript `null`, and YAML's `~`.
    Null,
    /// A boolean scalar.
    Bool(bool),
    /// A number. `NaN` and the infinities are legal members.
    Number(f64),
    /// A string, including one that came from a quoted or block scalar.
    String(String),
    /// A sequence.
    Array(Shared<Vec<Value>>),
    /// A mapping.
    Map(Shared<Map>),
    /// A value a stringifier must omit: `undefined`, a function, a symbol.
    ///
    /// Distinct from [`Value::Null`] because every stringifier here writes
    /// `null` differently from "this key is not there": an object property that
    /// is `undefined` disappears from `YAML.stringify`'s `{a: true, b: undefined}`
    /// -> `{a: true}` and from `JSON5.stringify` likewise, while a `null`
    /// property is written. In an array the two coincide — `[undefined]` is
    /// `[null]` — which is why the array emitter maps this to `Null` and the
    /// mapping emitter drops it.
    Omitted,
    /// A JavaScript `Date`, kept as its epoch milliseconds.
    ///
    /// A `Date` has no enumerable own properties, so a generic object walk gives
    /// `{}`. TOML writes it as an RFC 3339 instant; YAML writes `{}` because that
    /// is what its own walk produces. The two members therefore read this
    /// differently, which is why the millis are kept rather than pre-formatted.
    Date(f64),
    /// A TOML datetime, which Bun materialises as a `Temporal` object.
    ///
    /// The payload is the text Bun's own `String(value)` reports for the
    /// corresponding `Temporal` instance — normalised to UTC for a value that
    /// carried an offset, and otherwise the local form it was written in.
    /// Keeping the text rather than a broken-down date is deliberate: it is what
    /// the JavaScript constructor is handed, so it is also what a round-trip
    /// through `TOML.stringify` emits, and it is the only representation that
    /// cannot lose a fractional second beyond nanosecond precision.
    Temporal(String),
}

impl Value {
    /// A sequence value.
    pub fn array(items: Vec<Value>) -> Self {
        Value::Array(Shared::new(items))
    }

    /// A mapping value.
    pub fn map(map: Map) -> Self {
        Value::Map(Shared::new(map))
    }

    /// An empty mapping, which is also how a document root starts.
    pub fn empty_map() -> Self {
        Value::map(Map::new())
    }

    /// What `typeof` reports for this value.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null | Value::Omitted => "object",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) | Value::Map(_) | Value::Temporal(_) | Value::Date(_) => "object",
        }
    }

    /// The sequence contents, or `None` for any other kind.
    pub fn as_array(&self) -> Option<Ref<'_, Vec<Value>>> {
        match self {
            Value::Array(items) => Some(items.borrow()),
            _ => None,
        }
    }

    /// The mapping contents, or `None` for any other kind.
    pub fn as_map(&self) -> Option<Ref<'_, Map>> {
        match self {
            Value::Map(map) => Some(map.borrow()),
            _ => None,
        }
    }

    /// The mapping contents mutably, or `None` for any other kind.
    pub fn as_map_mut(&self) -> Option<RefMut<'_, Map>> {
        match self {
            Value::Map(map) => Some(map.borrow_mut()),
            _ => None,
        }
    }

    /// The string contents, or `None` for any other kind.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// Whether the key this value belongs to should be omitted entirely.
    pub fn is_omitted(&self) -> bool {
        matches!(self, Value::Omitted)
    }
}

/// An insertion-ordered string-keyed map.
///
/// A `Vec` of pairs rather than an `IndexMap` because the maps here are small,
/// the tree is built once and serialised once, and a linear scan keeps the
/// in-place-replacement rule the module docs describe obvious.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Map {
    entries: Vec<(String, Value)>,
}

impl Map {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks a key up.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Looks a key up mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Whether the map has `key`.
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Appends or replaces. A replacement keeps the original position, which is
    /// what `object[key] = value` does in JavaScript.
    pub fn insert(&mut self, key: String, value: Value) {
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some((_, existing)) => *existing = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Appends without replacing, keeping a duplicate key as a separate entry.
    ///
    /// TOML uses this while it builds a table: a document that defines a key
    /// twice is an error and the duplicate has to be *seen* to be reported, so
    /// the builder needs a push that cannot silently overwrite.
    pub fn push(&mut self, key: String, value: Value) {
        self.entries.push((key, value));
    }

    /// Iterates over the entries in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, (String, Value)> {
        self.entries.iter()
    }

    /// The entries as a slice, in insertion order.
    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }
}

impl FromIterator<(String, Value)> for Map {
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Self {
        let mut map = Map::new();
        for (key, value) in iter {
            map.push(key, value);
        }
        map
    }
}

/// Formats a number the way JavaScript's `Number.prototype.toString` does.
///
/// This is not cosmetic: every emitter writes numbers, and both `YAML.stringify`
/// and `TOML.stringify` write `1e+21` for `1e21` and `100000000000000000000` for
/// `1e20`. Rust's `Display` writes the full expansion in both cases, so using it
/// would produce TOML that reads back as a different number and YAML that is
/// merely ugly. Rust's `Debug` instead switches to exponent form at `1e21` and
/// at `1e-5`, drops the `.0` a JS integer has, and writes `1e21` where JS writes
/// `1e+21` — three separate differences, so neither formatter is used directly.
///
/// The algorithm is the shortest round-trip digits (`Debug`, which is Ryu) plus
/// JavaScript's exponent thresholds: an exponent form is used when the decimal
/// exponent `k` satisfies `k <= -6 || k >= 22`, and `+` is written before a
/// non-negative exponent. Those bounds are Bun's own: `String(1e20)` is
/// `"100000000000000000000"` and `String(1e21)` is `"1e+21"`, while
/// `String(1e-6)` is `"0.000001"` and `String(1e-7)` is `"1e-7"`.
pub fn format_number(value: f64) -> String {
    format_number_with(value, false)
}

/// [`format_number`], with JavaScript's `-0` kept.
///
/// `Number#toString` reports `-0` as `"0"`; `YAML.stringify` writes `-0`, and
/// TOML writes `-0.0`. The flag exists so those two can ask for the sign rather
/// than special-casing it at the call site.
pub fn format_number_with(value: f64, keep_negative_zero: bool) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-Infinity" } else { "Infinity" }.to_string();
    }
    if value == 0.0 {
        return if keep_negative_zero && value.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }
    // `Debug` on f64 is Ryu's shortest round-trip form, e.g. `1e21`, `1e-7`,
    // `0.30000000000000004`, `1.7976931348623157e308`, `123456789.12345679`.
    let shortest = format!("{value:?}");
    let (negative, body) = match shortest.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, shortest.as_str()),
    };
    let (mantissa, exponent) = match body.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (
            mantissa,
            exponent
                .parse::<i32>()
                .unwrap_or_else(|_| unreachable!("Rust always writes a decimal exponent")),
        ),
        None => (body, 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };
    let digits: String = format!("{integer}{fraction}");
    // `k` is the position of the decimal point relative to the digits: the value
    // is `0.digits × 10^k`. `1e21` has digits `1` and `k` of 22.
    let mut k = integer.len() as i32 + exponent;
    let trimmed = digits.trim_start_matches('0');
    let leading_zeros = digits.len() - trimmed.len();
    let trimmed = trimmed.trim_end_matches('0');
    let digits = if trimmed.is_empty() { "0" } else { trimmed };
    k -= leading_zeros as i32;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if k <= -6 || k >= 22 {
        // Exponent form: one digit, an optional fraction, `e`, and a signed
        // exponent with no zero padding.
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let e = k - 1;
        if e >= 0 {
            out.push('+');
        }
        let _ = write!(out, "{e}");
    } else if k <= 0 {
        // `0.000…digits`, with `-k` zeros between the point and the first digit.
        out.push_str("0.");
        for _ in 0..(-k) {
            out.push('0');
        }
        out.push_str(digits);
    } else {
        let k = k as usize;
        if digits.len() <= k {
            out.push_str(digits);
            for _ in 0..(k - digits.len()) {
                out.push('0');
            }
        } else {
            out.push_str(&digits[..k]);
            out.push('.');
            out.push_str(&digits[k..]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_number_matches_javascript() {
        // Every pair below was read off `String(n)` in Bun 1.4.4, including the
        // three exponent thresholds and the `e+` spelling.
        for (value, expected) in [
            (0.0, "0"),
            (1.0, "1"),
            (-1.0, "-1"),
            (1.5, "1.5"),
            (-1.5, "-1.5"),
            (100.0, "100"),
            (1e6, "1000000"),
            (1e7, "10000000"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e300, "1e+300"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (0.1 + 0.2, "0.30000000000000004"),
            (1.0 / 3.0, "0.3333333333333333"),
            (123_456_789.123_456_79, "123456789.12345679"),
            (9007199254740991.0, "9007199254740991"),
            (9007199254740992.0, "9007199254740992"),
            (123456789012345678.0, "123456789012345680"),
            (1.2345e-5, "0.000012345"),
            (-1e-7, "-1e-7"),
            (1e-21, "1e-21"),
            (1.5e300, "1.5e+300"),
        ] {
            assert_eq!(format_number(value), expected, "for {value:?}");
        }
        assert_eq!(format_number(f64::NAN), "NaN");
        assert_eq!(format_number(f64::INFINITY), "Infinity");
        assert_eq!(format_number(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(format_number_with(-0.0, true), "-0");
        assert_eq!(format_number_with(-0.0, false), "0");
    }

    #[test]
    fn map_replaces_in_place_and_push_does_not() {
        let mut map = Map::new();
        map.insert("a".into(), Value::Number(1.0));
        map.insert("b".into(), Value::Number(2.0));
        map.insert("a".into(), Value::Number(3.0));
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "b"], "replacement keeps the original position");
        assert_eq!(map.get("a"), Some(&Value::Number(3.0)));

        map.push("b".into(), Value::Number(4.0));
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "b", "b"], "push keeps the duplicate visible");
    }

    #[test]
    fn a_cycle_compares_equal_to_itself() {
        // The identity short-circuit is what keeps this from recursing forever.
        let items = Shared::new(Vec::new());
        let value = Value::Array(items.clone());
        items.borrow_mut().push(value.clone());
        assert_eq!(value, value.clone());
    }
}
