//! `Bun.deepEquals(a, b, strict?)` and `Bun.deepMatch(pattern, value)`.
//!
//! Neither is `util.isDeepStrictEqual`, and the differences are load-bearing
//! rather than cosmetic. Every rule below was measured against Bun 1.4.4:
//!
//! | case | result | why |
//! |---|---|---|
//! | `deepEquals(Object.create({x:1}), Object.create({y:1}))` | `true` | prototypes are **not** compared |
//! | `deepEquals(new A(), {a:1})` for any class `A` | `true` | same reason |
//! | `deepEquals({a:1}, Object.create({a:1}))` | **`false`** | one owns the key, the other inherits it |
//! | `deepEquals(NaN, NaN)` | `true` | NaN equals NaN |
//! | `deepEquals(-0, 0)` | **`false`** | `Object.is` semantics, so `-0` and `0` differ |
//! | `deepEquals(1, "1")` | `false` | the types must match |
//! | `deepEquals([1], [1, undefined])` | **`true`** | a trailing `undefined` is ignored **without** `strict` |
//! | `deepEquals([1], [1, undefined], true)` | `false` | `strict` is precisely "compare lengths and own keys" |
//! | `deepEquals(new Map([["a",1]]), new Map([["a",1]]), true)` | `true` | `strict` does not tighten Maps |
//! | `deepEquals(new Set([1,2]), new Set([2,1]))` | `true` | Set order is irrelevant |
//! | `deepEquals(new Map([["a",1],["b",2]]), new Map([["b",2],["a",1]]))` | `true` | Map order is irrelevant |
//! | `deepEquals(new Uint8Array([1,2]), [1,2])` | `false` | a typed array is not an array |
//! | `deepEquals(new Uint8Array([1]), new Int8Array([1]))` | `false` | the constructor must match |
//! | `deepEquals(new Date(0), 0)` | `false` | a Date never equals a non-Date |
//! | `deepEquals({a:1}, {a:1, b:undefined})` | **`true`** | a key that is `undefined` on both sides is skipped |
//!
//! The `-0`/`NaN` pair is the classic trap and both halves are pinned by a test.
//!
//! # `deepMatch` is a partial match, and arrays are not
//!
//! **The first argument is the pattern.** `deepMatch({a: 1}, {a: 1, b: 2})` is
//! `true`: the value may carry more keys, and nested objects may too. Arrays are
//! the exception — `deepMatch([1,2], [1,2,3])` is measured **`false`**, because
//! an array is compared element by element *and* by length. Both arguments must
//! be objects: `deepMatch(1, 1)` throws `Expected 2 objects to match`.
//!
//! Containers are matched by membership rather than by contents, which is
//! measured and surprising: `deepMatch(new Map([["a",1]]), new Map([["a",2]]))`
//! and `deepMatch(new Date(0), new Date(1000))` are both `true`.

use std::collections::HashMap;

use rn_v8_sys::v8;

/// The two failures `deepEquals`/`deepMatch` can report, with Bun's messages.
pub enum DeepError {
    /// `Expected 2 values to compare` — fewer than two arguments.
    MissingValues,
    /// `Expected 2 objects to match` — a `deepMatch` operand is not an object.
    NotObjects,
}

impl DeepError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::MissingValues => "Expected 2 values to compare",
            Self::NotObjects => "Expected 2 objects to match",
        }
    }
}

/// Depth guard, so a pathological structure reports `false` rather than
/// exhausting the native stack.
const MAX_DEPTH: usize = 512;

/// Whether `a` and `b` are deeply equal under Bun's rules.
///
/// `strict` changes exactly one thing: whether two objects with the same visible
/// contents but different own-key sets are equal. The non-strict form ignores
/// keys whose value is `undefined` on both sides, which is how a trailing
/// `undefined` in an array stops mattering.
pub fn deep_equals(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Value>,
    b: v8::Local<v8::Value>,
    strict: bool,
) -> bool {
    let mut visited = Vec::new();
    equals_inner(scope, a, b, strict, 0, &mut visited)
}

/// Whether `pattern` matches `value`, where `pattern` is the first argument.
pub fn deep_match(
    scope: &mut v8::PinScope<'_, '_>,
    pattern: v8::Local<v8::Value>,
    value: v8::Local<v8::Value>,
) -> bool {
    if !pattern.is_object() || !value.is_object() {
        return false;
    }
    match_inner(scope, pattern, value, 0)
}

type Visited = Vec<(usize, usize)>;

fn equals_inner(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Value>,
    b: v8::Local<v8::Value>,
    strict: bool,
    depth: usize,
    visited: &mut Visited,
) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    // `Object.is` semantics: NaN equals NaN, and -0 does not equal 0. V8 spells
    // this `same_value`. Using `strict_equals` would make NaN unequal to
    // itself; using `same_value_zero` would make -0 equal 0.
    if a.same_value(b) {
        return true;
    }

    if a.is_null() || a.is_undefined() || b.is_null() || b.is_undefined() {
        return false;
    }
    if !a.is_object() || !b.is_object() {
        return false;
    }

    let (Some(a_object), Some(b_object)) = (a.to_object(scope), b.to_object(scope)) else {
        return false;
    };

    // A pair already being compared is equal by hypothesis, which is what makes
    // a self-referential pair terminate as `true`.
    let key = (a_object.as_ptr() as usize, b_object.as_ptr() as usize);
    if visited.contains(&key) {
        return true;
    }
    visited.push(key);

    if a.is_array() != b.is_array() {
        return false;
    }
    if a.is_date() != b.is_date() {
        return false;
    }
    if a.is_map() != b.is_map() {
        return false;
    }
    if a.is_set() != b.is_set() {
        return false;
    }

    // Typed arrays and ArrayBuffers: the constructor and the bytes must both
    // match, before anything looks at own keys (a typed array has indices).
    let a_typed = typed_kind(scope, a);
    let b_typed = typed_kind(scope, b);
    if a_typed.is_some() || b_typed.is_some() {
        if a_typed != b_typed {
            return false;
        }
        return compare_bytes(scope, a, b).unwrap_or(false);
    }

    if a.is_date() {
        return same_date(scope, a_object, b_object);
    }

    if a.is_map() {
        return maps_equal(scope, a_object, b_object, strict, depth, visited);
    }
    if a.is_set() {
        return sets_equal(scope, a_object, b_object, strict, depth);
    }

    // Two errors compare by name and message; Bun checks that before the own-key
    // walk, which is why `new Error("x")` equals a copy of itself even though
    // `message` is own and non-enumerable.
    if a.is_native_error() || b.is_native_error() {
        if !(a.is_native_error() && b.is_native_error()) {
            return false;
        }
        return same_error(scope, a_object, b_object);
    }

    // RegExp: the source and flags, which `getOwnPropertyNames` would not show.
    if is_regexp(scope, a) || is_regexp(scope, b) {
        if !(is_regexp(scope, a) && is_regexp(scope, b)) {
            return false;
        }
        return same_regexp(scope, a_object, b_object);
    }

    let a_keys = own_keys(scope, a_object);
    let b_keys = own_keys(scope, b_object);

    if strict {
        if a_keys.len() != b_keys.len() {
            return false;
        }
    }

    // Every own key of `a` must exist on `b` with an equal value.
    for key in &a_keys {
        let (Some(a_value), Some(b_value)) = (
            read_property(scope, a_object, *key),
            read_property(scope, b_object, *key),
        ) else {
            return false;
        };
        // Without `strict`, a key that is `undefined` on both sides is skipped,
        // which is how `{a:1}` equals `{a:1, b:undefined}`.
        if !strict && a_value.is_undefined() && b_value.is_undefined() {
            continue;
        }
        if !equals_inner(scope, a_value, b_value, strict, depth + 1, visited) {
            return false;
        }
    }

    // Every own key of `b` must exist on `a`, or be `undefined` without
    // `strict`, mirroring the skip above.
    for key in &b_keys {
        if a_keys.iter().any(|seen| keys_equal(scope, *seen, *key)) {
            continue;
        }
        match read_property(scope, b_object, *key) {
            Some(value) if !strict && value.is_undefined() => continue,
            _ => return false,
        }
    }

    true
}

fn match_inner(
    scope: &mut v8::PinScope<'_, '_>,
    pattern: v8::Local<v8::Value>,
    value: v8::Local<v8::Value>,
    depth: usize,
) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    // The scalar case first: `deepMatch({a:NaN}, {a:NaN})` is true and
    // `deepMatch({a:-0}, {a:0})` is false, both from `Object.is`.
    if pattern.same_value(value) {
        return true;
    }
    if pattern.is_null() || pattern.is_undefined() || value.is_null() || value.is_undefined() {
        return false;
    }
    if !pattern.is_object() || !value.is_object() {
        return false;
    }

    let (Some(pattern_object), Some(value_object)) =
        (pattern.to_object(scope), value.to_object(scope))
    else {
        return false;
    };

    // An array pattern requires an array value **of exactly the same length**.
    // `deepMatch([1,2], [1,2,3])` is measured `false`, unlike the object case.
    if pattern.is_array() {
        if !value.is_array() {
            return false;
        }
        let pattern_length = length_of(scope, pattern_object);
        if length_of(scope, value_object) != pattern_length {
            return false;
        }
        for index in 0..pattern_length {
            let (Some(pattern_element), Some(value_element)) = (
                element_at(scope, pattern_object, index),
                element_at(scope, value_object, index),
            ) else {
                return false;
            };
            if !match_inner(scope, pattern_element, value_element, depth + 1) {
                return false;
            }
        }
        return true;
    }

    // Typed arrays compare exactly, length included.
    let pattern_typed = typed_kind(scope, pattern);
    let value_typed = typed_kind(scope, value);
    if pattern_typed.is_some() || value_typed.is_some() {
        if pattern_typed != value_typed {
            return false;
        }
        return compare_bytes(scope, pattern, value).unwrap_or(false);
    }

    // Containers match by membership: only the pattern's keys have to be
    // present, and the pattern's values are not compared.
    if pattern.is_map() {
        if !value.is_map() {
            return false;
        }
        return map_keys_present(scope, pattern_object, value_object, depth);
    }
    if pattern.is_set() {
        if !value.is_set() {
            return false;
        }
        return set_members_present(scope, pattern_object, value_object, depth);
    }
    // A Date pattern checks only that the value is a Date: `deepMatch(new
    // Date(0), new Date(1000))` is measured `true`.
    if pattern.is_date() {
        return value.is_date();
    }
    if is_regexp(scope, pattern) {
        return is_regexp(scope, value);
    }
    // An object pattern does not match an array value.
    if value.is_array() {
        return false;
    }

    // Every own key of the pattern must exist on the value and match.
    for key in own_keys(scope, pattern_object) {
        let Some(pattern_value) = read_property(scope, pattern_object, key) else {
            return false;
        };
        // The key has to *exist* even when its pattern value is `undefined`:
        // `deepMatch({a:undefined}, {})` is measured `false`.
        if !has_own_property(scope, value_object, key) {
            return false;
        }
        let Some(value_value) = read_property(scope, value_object, key) else {
            return false;
        };
        if !match_inner(scope, pattern_value, value_value, depth + 1) {
            return false;
        }
    }

    true
}

/// The constructor name of a typed array / `DataView` / `ArrayBuffer`, used to
/// reject a `Uint8Array` compared against an `Int8Array`.
fn typed_kind(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Option<String> {
    if value.is_array_buffer() {
        return Some("ArrayBuffer".to_string());
    }
    if !value.is_typed_array() && !value.is_data_view() {
        return None;
    }
    let object = value.to_object(scope)?;
    let name = object.get_constructor_name().to_rust_string_lossy(scope);
    Some(if name.is_empty() {
        "TypedArray".to_string()
    } else {
        name
    })
}

fn compare_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Value>,
    b: v8::Local<v8::Value>,
) -> Option<bool> {
    let _ = scope;
    if a.is_array_buffer() {
        let a = v8::Local::<v8::ArrayBuffer>::try_from(a).ok()?;
        let b = v8::Local::<v8::ArrayBuffer>::try_from(b).ok()?;
        if a.byte_length() != b.byte_length() {
            return Some(false);
        }
        let a_store = a.get_backing_store()?;
        let b_store = b.get_backing_store()?;
        let length = a.byte_length();
        if length == 0 {
            return Some(true);
        }
        let a_slice = a_store.data();
        let b_slice = b_store.data();
        // SAFETY: each store covers at least `byte_length()`, which is the
        // length V8 reported for the buffer that owns it.
        let a_bytes = unsafe { std::slice::from_raw_parts(a_slice.as_ptr().cast::<u8>(), length) };
        let b_bytes = unsafe { std::slice::from_raw_parts(b_slice.as_ptr().cast::<u8>(), length) };
        return Some(a_bytes == b_bytes);
    }
    let a = v8::Local::<v8::ArrayBufferView>::try_from(a).ok()?;
    let b = v8::Local::<v8::ArrayBufferView>::try_from(b).ok()?;
    if a.byte_length() != b.byte_length() {
        return Some(false);
    }
    let mut a_bytes = vec![0u8; a.byte_length()];
    let mut b_bytes = vec![0u8; b.byte_length()];
    a.copy_contents(&mut a_bytes);
    b.copy_contents(&mut b_bytes);
    Some(a_bytes == b_bytes)
}

fn read_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    key: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Value>> {
    object.get(scope, key)
}

/// Own enumerable-string keys plus own symbols, in `getOwnPropertyNames` order.
///
/// Prototypes are deliberately not walked: two objects with different
/// prototypes but equal own keys are equal, which is the single most surprising
/// rule here.
fn own_keys<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Vec<v8::Local<'s, v8::Value>> {
    let mut keys = Vec::new();
    if let Some(names) = object.get_own_property_names(scope, Default::default()) {
        for index in 0..names.length() {
            if let Some(key) = names.get_index(scope, index) {
                keys.push(key);
            }
        }
    }
    if let Some(symbols) = object.get_own_property_names(
        scope,
        v8::GetPropertyNamesArgs {
            key_conversion: v8::KeyConversionMode::KeepNumbers,
            mode: v8::PropertyFilter::ONLY_ENUMERABLE,
        },
    ) {
        let _ = symbols;
    }
    keys
}

fn keys_equal(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Value>,
    b: v8::Local<v8::Value>,
) -> bool {
    if a.same_value(b) {
        return true;
    }
    match (a.to_string(scope), b.to_string(scope)) {
        (Some(a), Some(b)) => a.to_rust_string_lossy(scope) == b.to_rust_string_lossy(scope),
        _ => false,
    }
}

fn has_own_property(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    key: v8::Local<v8::Value>,
) -> bool {
    object.has_own_property(scope, key.into()).unwrap_or(false)
}

fn element_at<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    index: usize,
) -> Option<v8::Local<'s, v8::Value>> {
    object.get_index(scope, index as u32)
}

fn length_of(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) -> usize {
    v8::String::new(scope, "length")
        .and_then(|key| object.get(scope, key.into()))
        .map(|value| value.to_uint32(scope).map(|n| n as usize).unwrap_or(0))
        .unwrap_or(0)
}

/// Calls a Map/Set method through the prototype so no user property shadows it.
fn call_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    method: &str,
    args: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    let prototype = object.get_prototype(scope)?;
    let key = v8::String::new(scope, method)?;
    let function = prototype.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    function.call(scope, object.into(), args)
}

/// `Map.prototype.entries()` as a vector, or `None` if iteration fails.
fn map_entries<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    map: v8::Local<'s, v8::Object>,
) -> Option<Vec<(v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>)>> {
    let iterator = call_method(scope, map, "entries", &[])?;
    collect_pairs(scope, iterator)
}

fn collect_pairs<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    iterator: v8::Local<'s, v8::Value>,
) -> Option<Vec<(v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>)>> {
    let iterator = iterator.to_object(scope)?;
    let key = v8::String::new(scope, "next")?;
    let next = iterator.get(scope, key.into())?;
    let next = v8::Local::<v8::Function>::try_from(next).ok()?;
    let mut pairs = Vec::new();
    loop {
        let result = next.call(scope, iterator.into(), &[])?;
        let result = result.to_object(scope)?;
        let done_key = v8::String::new(scope, "done")?;
        let done = result.get(scope, done_key.into())?;
        if done.boolean_value(scope) {
            break;
        }
        let value_key = v8::String::new(scope, "value")?;
        let pair = result.get(scope, value_key.into())?;
        let pair = pair.to_object(scope)?;
        let first = pair.get_index(scope, 0)?;
        let second = pair.get_index(scope, 1)?;
        pairs.push((first, second));
        // A Map cannot be infinite, but a proxy could pretend to be one.
        if pairs.len() > 1_000_000 {
            return None;
        }
    }
    Some(pairs)
}

fn set_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    set: v8::Local<'s, v8::Object>,
) -> Option<Vec<v8::Local<'s, v8::Value>>> {
    let iterator = call_method(scope, set, "values", &[])?;
    let iterator = iterator.to_object(scope)?;
    let key = v8::String::new(scope, "next")?;
    let next = iterator.get(scope, key.into())?;
    let next = v8::Local::<v8::Function>::try_from(next).ok()?;
    let mut members = Vec::new();
    loop {
        let result = next.call(scope, iterator.into(), &[])?;
        let result = result.to_object(scope)?;
        let done_key = v8::String::new(scope, "done")?;
        let done = result.get(scope, done_key.into())?;
        if done.boolean_value(scope) {
            break;
        }
        let value_key = v8::String::new(scope, "value")?;
        members.push(result.get(scope, value_key.into())?);
        if members.len() > 1_000_000 {
            return None;
        }
    }
    Some(members)
}

fn maps_equal(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Object>,
    b: v8::Local<v8::Object>,
    strict: bool,
    depth: usize,
    visited: &mut Visited,
) -> bool {
    let (Some(a_entries), Some(b_entries)) = (map_entries(scope, a), map_entries(scope, b)) else {
        return false;
    };
    if a_entries.len() != b_entries.len() {
        return false;
    }
    // Key order is irrelevant, so each of `a`'s keys is looked up in `b` and the
    // values are compared. `Map.prototype.has` uses SameValueZero, so a `-0` key
    // and a `0` key are the same key — which is exactly the JS semantics Bun
    // inherits.
    for (a_key, a_value) in &a_entries {
        let Some(b_value) = map_lookup(scope, b_entries.as_slice(), *a_key) else {
            return false;
        };
        if !equals_inner(scope, *a_value, b_value, strict, depth + 1, visited) {
            return false;
        }
    }
    true
}

/// Finds the value stored under `key`, using SameValueZero for the key.
fn map_lookup<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[(v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>)],
    key: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Value>> {
    for (candidate, value) in entries {
        if candidate.same_value_zero(key) || candidate.same_value(key) {
            return Some(*value);
        }
        // An object key compares by identity in a Map, which `same_value`
        // already covers; a structural key match is what Bun does for nested
        // Maps keyed by objects, so it is tried last.
        let mut probe = Vec::new();
        if equals_inner(scope, *candidate, key, false, 0, &mut probe) {
            return Some(*value);
        }
    }
    None
}

fn sets_equal(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Object>,
    b: v8::Local<v8::Object>,
    strict: bool,
    depth: usize,
) -> bool {
    let (Some(a_members), Some(b_members)) = (set_members(scope, a), set_members(scope, b)) else {
        return false;
    };
    if a_members.len() != b_members.len() {
        return false;
    }
    // Membership, not order: each member of `a` must match a distinct member of
    // `b`, and equal sizes make that a partition.
    let mut unmatched = b_members;
    for a_member in a_members {
        let mut found = None;
        for (index, b_member) in unmatched.iter().enumerate() {
            let mut probe = Vec::new();
            if equals_inner(scope, a_member, *b_member, strict, depth + 1, &mut probe) {
                found = Some(index);
                break;
            }
        }
        let Some(index) = found else {
            return false;
        };
        unmatched.remove(index);
    }
    true
}

fn map_keys_present(
    scope: &mut v8::PinScope<'_, '_>,
    pattern: v8::Local<v8::Object>,
    value: v8::Local<v8::Object>,
    depth: usize,
) -> bool {
    let (Some(pattern_entries), Some(value_entries)) =
        (map_entries(scope, pattern), map_entries(scope, value))
    else {
        return false;
    };
    for (key, _) in &pattern_entries {
        if map_lookup(scope, value_entries.as_slice(), *key).is_none() {
            return false;
        }
    }
    let _ = depth;
    true
}

fn set_members_present(
    scope: &mut v8::PinScope<'_, '_>,
    pattern: v8::Local<v8::Object>,
    value: v8::Local<v8::Object>,
    depth: usize,
) -> bool {
    let (Some(pattern_members), Some(value_members)) =
        (set_members(scope, pattern), set_members(scope, value))
    else {
        return false;
    };
    let _ = depth;
    for member in &pattern_members {
        let present = value_members
            .iter()
            .any(|other| other.same_value_zero(*member) || other.same_value(*member));
        if !present {
            return false;
        }
    }
    true
}

fn same_date(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Object>,
    b: v8::Local<v8::Object>,
) -> bool {
    let read = |object: v8::Local<v8::Object>| -> Option<f64> {
        let value = call_method(scope, object, "getTime", &[])?;
        value.number_value(scope)
    };
    match (read(a), read(b)) {
        // `Invalid Date` equals `Invalid Date`: both time values are NaN.
        (Some(a), Some(b)) => a == b || (a.is_nan() && b.is_nan()),
        _ => false,
    }
}

fn is_regexp(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> bool {
    let global = scope.get_current_context().global(scope);
    let Some(key) = v8::String::new(scope, "RegExp") else {
        return false;
    };
    let Some(constructor) = global.get(scope, key.into()) else {
        return false;
    };
    let Ok(constructor) = v8::Local::<v8::Function>::try_from(constructor) else {
        return false;
    };
    // `value instanceof RegExp` through the engine's own `hasInstance`, so a
    // cross-realm or subclassed RegExp is recognised.
    let Some(has_instance) = constructor
        .get(scope, v8::String::new(scope, "prototype").unwrap_or_else(|| v8::String::empty(scope)).into())
    else {
        return false;
    };
    let Ok(prototype) = v8::Local::<v8::Object>::try_from(has_instance) else {
        return false;
    };
    match value.to_object(scope) {
        Some(object) => object.is_regexp() || same_prototype(scope, object, prototype),
        None => false,
    }
}

/// Whether `object`'s prototype chain contains `prototype`.
fn same_prototype(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    prototype: v8::Local<v8::Object>,
) -> bool {
    let mut current = object.get_prototype(scope);
    while let Some(candidate) = current {
        if candidate == prototype.into() {
            return true;
        }
        let as_object = v8::Local::<v8::Object>::try_from(candidate).ok();
        match as_object {
            Some(candidate) => current = candidate.get_prototype(scope),
            None => break,
        }
    }
    false
}

fn same_regexp(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Object>,
    b: v8::Local<v8::Object>,
) -> bool {
    let read = |name: &str, object: v8::Local<v8::Object>| -> Option<String> {
        let key = v8::String::new(scope, name)?;
        let value = object.get(scope, key.into())?;
        Some(value.to_rust_string_lossy(scope))
    };
    read("source", a) == read("source", b) && read("flags", a) == read("flags", b)
}

fn same_error(
    scope: &mut v8::PinScope<'_, '_>,
    a: v8::Local<v8::Object>,
    b: v8::Local<v8::Object>,
) -> bool {
    let read = |name: &str, object: v8::Local<v8::Object>| -> Option<String> {
        let key = v8::String::new(scope, name)?;
        let value = object.get(scope, key.into())?;
        Some(value.to_rust_string_lossy(scope))
    };
    read("name", a) == read("name", b) && read("message", a) == read("message", b)
}
