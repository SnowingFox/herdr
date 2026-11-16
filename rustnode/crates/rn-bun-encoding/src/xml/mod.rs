//! `Bun.XML.parse` and `Bun.XML.stringify`.
//!
//! Bun's XML parser is a small non-DOM one: it produces nested plain objects and
//! nothing else. The mapping rules are the entire specification, and each was
//! measured:
//!
//! | XML | JavaScript |
//! | --- | --- |
//! | element with only text | a **string** under the element's key |
//! | empty or self-closing element | `""` |
//! | attribute | a `@`-prefixed key, `@id` |
//! | mixed content | a `#text` key |
//! | repeated siblings | an **array** |
//! | root | the single top-level key |
//! | declaration, comment, doctype | dropped |
//! | CDATA | its text |
//! | entities | decoded, including numeric and hexadecimal |
//!
//! # `#text` is concatenated verbatim, and that is not a detail
//!
//! `XML.parse("<p>hello <b>bold</b> world</p>")` has `#text` of
//! `"hello  world"` — **two** spaces. The runs either side of the element are
//! joined as they are, so the space that ended the first and the space that began
//! the second both survive. A parser that trims or collapses gives
//! `"hello world"` and fails:
//!
//! ```text
//! "<p>a <b>x</b> b</p>"   #text: "a  b"      two runs, two spaces
//! "<p>a\t<b>x</b>b</p>"   #text: "a\tb"      a tab is not a space
//! "<p>a<b>x</b> <i>y</i>c</p>"  #text: "ac"  the middle run is only a space
//! ```
//!
//! The last one is the other half of the rule: a run that is **entirely
//! whitespace** is dropped, and the remaining runs still join with nothing
//! between them. So "a" + (dropped) + "c" is `"ac"`, while the two-space case
//! keeps both spaces because neither run is whitespace-only.
//!
//! # No namespaces
//!
//! `ns:a` keeps its prefix as the key and `xmlns:ns` appears as an ordinary
//! `@`-prefixed attribute. There is no resolution and no prefix stripping, which
//! is worth stating because a DOM parser would do both.
//!
//! # `stringify` has two input shapes
//!
//! It accepts either the shape `parse` produced — `{root: {...}}` — or an
//! explicit `{name, attributes, children}` node. `parse`→`stringify` is a
//! round trip for the documents measured, with one exception recorded in the
//! crate report: the parsed shape cannot distinguish an attribute from an element
//! whose name begins with `@`.

use rn_v8_sys::v8;

use crate::convert::{
    coerce_to_string, require_string_or_bytes, throw_error, throw_syntax_error, CoerceError,
};
use crate::value::{Map, Shared, Value};

mod parse;
mod stringify;

/// Builds the `Bun.XML` namespace object.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    set(scope, object, "parse", 2, parse_member)?;
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

/// `Bun.XML.parse(input, options?)`.
///
/// `length` is **2** — the second argument exists and is ignored. Measured:
/// `XML.parse("<a>1</a>", {any: "option"})` is `{a: "1"}`.
fn parse_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `XML.parse` stringifies a non-symbol argument, so `parse(42)` fails as XML
    // for the document `"42"` rather than as an argument-type error. The one
    // exception is a missing argument, which is `ERR_INVALID_ARG_TYPE`; Bun
    // gives the same message for a wrong type on the *other* parsers, and here
    // it is only reachable with no argument at all.
    if args.length() == 0 {
        crate::convert::throw_type_error_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "input must be a string, ArrayBuffer, ArrayBufferView or Blob",
        );
        return;
    }
    let _ = require_string_or_bytes;
    let input = if args.get(0).is_symbol() {
        crate::convert::throw_type_error(scope, "Cannot convert a symbol to a string");
        return;
    } else {
        match coerce_to_string(scope, args.get(0)) {
            Ok(input) => input,
            Err(CoerceError::Thrown) => return,
        }
    };
    let value = match parse::document(&input) {
        Ok(value) => value,
        Err(message) => {
            throw_syntax_error(scope, &format!("XML Parse error: {message}"));
            return;
        }
    };
    let mut cache = crate::convert::IdentityCache::new();
    match crate::convert::to_js(scope, &value, &mut cache) {
        Ok(js) => rv.set(js),
        Err(message) => throw_error(scope, &message),
    }
}

/// Accumulates a `#text` value at the position the text first appeared.
///
/// A second run appends to the same key rather than replacing it, which is what
/// makes `<p>a<b>x</b>c</p>` one `"ac"` and not one `"a"` overwritten by `"c"`.
fn insert_text(map: &Shared<Map>, text: &str) {
    let mut borrow = map.borrow_mut();
    match borrow.get_mut("#text") {
        Some(Value::String(existing)) => existing.push_str(text),
        _ => borrow.insert("#text".to_string(), Value::String(text.to_string())),
    }
}

/// A parsed element, before it becomes a [`Value`].
pub(crate) struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// Text runs, verbatim and in order.
    pub texts: Vec<String>,
    /// The text runs grouped by where they sit relative to the children: entry
    /// `i` is the text before child `i`, and the last entry is the text after the
    /// final child.
    pub runs: Vec<Vec<String>>,
}

impl Element {
    /// Whether the element's content is text only.
    ///
    /// An element with an **attribute** is never a bare string: it has to be an
    /// object to carry the `@`-prefixed key, which is why
    /// `<a x="1">t</a>` is `{a: {"@x": "1", "#text": "t"}}` and not `{a: "t"}`.
    fn text_only(&self) -> Option<String> {
        if !self.children.is_empty() || !self.attributes.is_empty() {
            return None;
        }
        Some(self.texts.to_vec().concat())
    }

    /// The text run that sits immediately before child `index`, or at the end.
    ///
    /// `parse` pushes one entry per child and one per text run into a single
    /// ordered list, so this is a lookup rather than a scan.
    fn text_at(&self, index: usize) -> Option<String> {
        let runs = self.runs.get(index)?;
        let joined: String = runs
            .iter()
            .filter(|run| !run.trim().is_empty())
            .cloned()
            .collect();
        (!joined.is_empty()).then_some(joined)
    }

    /// The element as the object Bun produces.
    ///
    /// **Key order follows the document**, with one measured rule: `#text` takes
    /// the position of the element's text content. `<p>a<b>x</b>c</p>` is
    /// `["#text", "b"]` and `<p><b>x</b>c</p>` is `["b", "#text"]`, so the key is
    /// inserted when the first non-whitespace text run is seen and filled in as
    /// the runs accumulate — not appended at the end, which would give one fixed
    /// order for both.
    pub(crate) fn to_value(&self) -> Value {
        // A string when the element is text only, which covers the empty element
        // (`""`) and the self-closing one (also `""`).
        if let Some(text) = self.text_only() {
            return Value::String(text);
        }
        let map = Shared::new(Map::new());
        for (name, value) in &self.attributes {
            map.borrow_mut()
                .insert(format!("@{name}"), Value::String(value.clone()));
        }
        // Siblings and text runs share one stream order, which `parse` records by
        // interleaving them into `children` and `texts` with a tag each.
        for (position, child) in self.children.iter().enumerate() {
            let text_before = self.text_before(position);
            if !text_before.is_empty() {
                insert_text(&map, &text_before);
            }
            let value = child.to_value();
            let mut borrow = map.borrow_mut();
            match borrow.get_mut(&child.name) {
                // A repeated sibling becomes an array, in document order.
                Some(Value::Array(existing)) => existing.borrow_mut().push(value),
                Some(existing) => {
                    let first = existing.clone();
                    let array = Shared::new(vec![first, value]);
                    *existing = Value::Array(array);
                }
                None => borrow.insert(child.name.clone(), value),
            }
        }
        let tail = self.text_after_last();
        if !tail.is_empty() {
            insert_text(&map, &tail);
        }
        Value::Map(map)
    }

    /// The text runs that preceded the `position`-th child.
    fn text_before(&self, position: usize) -> String {
        self.text_at(position).unwrap_or_default()
    }

    fn text_after_last(&self) -> String {
        self.text_at(self.children.len()).unwrap_or_default()
    }
}
