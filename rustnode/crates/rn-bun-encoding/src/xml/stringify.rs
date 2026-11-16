//! `Bun.XML.stringify(value, replacer, space)`.
//!
//! Two input shapes, measured:
//!
//! ```text
//! {root:{a:"1"}}                                        <root><a>1</a></root>
//! parse("<r><a>1</a></r>")                              <r><a>1</a></r>
//! {name:"root", attributes:{id:"1"}, children:[{name:"a", attributes:{}, children:["txt"]}]}
//!                                                       <root id="1"><a>txt</a></root>
//! {name:"a", attributes:{}, children:[]}                <a/>
//! ```
//!
//! The `name`/`attributes`/`children` form wins when a `name` string is present;
//! otherwise the object must have exactly one key, which names the root. Bun's
//! own messages for the four ways that can go wrong are below, and they are
//! distinct enough to be worth reproducing:
//!
//! ```text
//! {}                             the top-level object must have one key naming the root element
//! {a:"1", b:"2"}                 an XML document has exactly one root element, but the top-level object has more than one key
//! {r:["1","2"]}                  the root element 'r' cannot be an array (an XML document has exactly one root element)
//! {r:{a:[["1"]]}}                nested arrays cannot be represented (element 'a')
//! string input                   expects an object: a { name, attributes, children } node or an object with a single root element key
//! ```
//!
//! # Escaping is asymmetric, and that is measured
//!
//! Text escapes `<`, `&` and `>` but **not** `"` or `'`; an attribute value
//! escapes `<`, `&`, `>` and `"` but **not** `'`, because Bun emits attributes
//! with double quotes and does not need to escape the single one.
//!
//! ```text
//! {r:{a:"<&>\"'"}}    <r><a>&lt;&amp;&gt;"'</a></r>
//! {r:{"@a":"<&>\"'"}} <r a="&lt;&amp;&gt;&quot;'"/>
//! ```

use rn_v8_sys::v8;

use crate::convert::{from_js, throw_error, FromJsError};
use crate::value::{Map, Value};

/// `Bun.XML.stringify(value, replacer, space)`.
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
    let converted = match from_js(scope, value) {
        Ok(converted) => converted,
        Err(FromJsError::Throwing) => return,
        Err(FromJsError::Unconvertible) | Err(FromJsError::BigInt) => {
            throw_error(
                scope,
                "XML.stringify expects an object: a { name, attributes, children } node or an object with a single root element key",
            );
            return;
        }
    };
    let mut out = String::new();
    match emit_root(&converted, &mut out) {
        Ok(()) => {
            let Some(text) = v8::String::new(scope, &out) else {
                return;
            };
            rv.set(text.into());
        }
        Err(message) => throw_error(scope, &message),
    }
}

const EXPECTS_OBJECT: &str = "XML.stringify expects an object: a { name, attributes, children } node or an object with a single root element key";

fn emit_root(value: &Value, out: &mut String) -> Result<(), String> {
    let Value::Map(map) = value else {
        return Err(EXPECTS_OBJECT.to_string());
    };
    let map = map.borrow();
    // The explicit node shape wins when it is present.
    if map.get("name").and_then(Value::as_str).is_some() {
        return emit_node(&map, out);
    }
    match map.len() {
        0 => Err("XML.stringify: the top-level object must have one key naming the root element"
            .to_string()),
        1 => {
            let (name, inner) = &map.entries()[0];
            emit_element(name, inner, out)
        }
        _ => Err("XML.stringify: an XML document has exactly one root element, but the top-level object has more than one key".to_string()),
    }
}

/// An explicit `{name, attributes, children}` node.
fn emit_node(map: &Map, out: &mut String) -> Result<(), String> {
    let name = map
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| EXPECTS_OBJECT.to_string())?;
    let attributes = match map.get("attributes") {
        Some(Value::Map(attributes)) => Some(attributes.borrow().clone()),
        _ => None,
    };
    let children = match map.get("children") {
        Some(Value::Array(children)) => Some(children.borrow().clone()),
        _ => None,
    };
    let pairs: Vec<(String, String)> = attributes
        .as_ref()
        .map(|attributes| {
            attributes
                .iter()
                .map(|(key, value)| (key.clone(), text_of(value)))
                .collect()
        })
        .unwrap_or_default();
    write_open(name, &pairs, out);
    let has_children = children
        .as_ref()
        .is_some_and(|children| !children.is_empty());
    if !has_children {
        out.push_str("/>");
        return Ok(());
    }
    out.push('>');
    write_children(children.unwrap_or_default(), name, out)?;
    out.push_str("</");
    out.push_str(name);
    out.push('>');
    Ok(())
}

/// A key of the parsed shape: an element name bound to its content.
fn emit_element(name: &str, value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Array(items) => {
            if !items.borrow().is_empty() {
                return Err(format!(
                    "XML.stringify: the root element '{name}' cannot be an array (an XML document has exactly one root element)"
                ));
            }
            write_open(name, &[], out);
            out.push_str("/>");
            Ok(())
        }
        Value::Map(map) => {
            let map = map.borrow();
            // `@`-prefixed keys are attributes and `#text` is text; both are
            // pulled out before the children are written.
            let mut attributes: Vec<(String, String)> = Vec::new();
            for (key, item) in map.iter() {
                if item.is_omitted() {
                    continue;
                }
                if let Some(attribute) = key.strip_prefix('@') {
                    attributes.push((attribute.to_string(), text_of(item)));
                }
            }
            write_open(name, &attributes, out);
            let children: Vec<&(String, Value)> = map
                .iter()
                .filter(|(key, value)| !key.starts_with('@') && !value.is_omitted())
                .collect();
            if children.is_empty() {
                out.push_str("/>");
                return Ok(());
            }
            out.push('>');
            for (key, item) in children {
                if key == "#text" {
                    out.push_str(&escape_text(&text_of(item)));
                } else {
                    write_element(key, item, out)?;
                }
            }
            out.push_str("</");
            out.push_str(name);
            out.push('>');
            Ok(())
        }
        // A bare value is an element with text or a self-closing element.
        Value::Null => {
            write_open(name, &[], out);
            out.push_str("/>");
            Ok(())
        }
        other => {
            write_open(name, &[], out);
            out.push('>');
            out.push_str(&escape_text(&text_of(other)));
            out.push_str("</");
            out.push_str(name);
            out.push('>');
            Ok(())
        }
    }
}

fn write_element(name: &str, value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Array(items) => {
            let items = items.borrow().clone();
            for item in &items {
                if matches!(item, Value::Array(_)) {
                    return Err(format!(
                        "XML.stringify: nested arrays cannot be represented (element '{name}')"
                    ));
                }
            }
            for item in &items {
                emit_element(name, item, out)?;
            }
            Ok(())
        }
        other => emit_element(name, other, out),
    }
}

/// The children of an explicit node: strings are text, objects are elements.
fn write_children(children: Vec<Value>, parent: &str, out: &mut String) -> Result<(), String> {
    for child in &children {
        match child {
            Value::Map(map) => emit_node(&map.borrow(), out)?,
            Value::Array(_) => {
                return Err(format!(
                    "XML.stringify: nested arrays cannot be represented (element '{parent}')"
                ))
            }
            other => out.push_str(&escape_text(&text_of(other))),
        }
    }
    Ok(())
}

/// Writes an open tag, given attribute pairs in the order they should appear.
fn write_open(name: &str, attributes: &[(String, String)], out: &mut String) {
    out.push('<');
    out.push_str(name);
    for (attribute, value) in attributes {
        out.push(' ');
        out.push_str(attribute);
        out.push_str("=\"");
        out.push_str(&escape_attribute(value));
        out.push('"');
    }
}

/// A value rendered as text: numbers and booleans use JavaScript's `String()`,
/// and `null` is the empty string.
fn text_of(value: &Value) -> String {
    match value {
        Value::Null | Value::Omitted => String::new(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => crate::value::format_number(*number),
        Value::String(text) => text.clone(),
        Value::Temporal(text) => text.clone(),
        Value::Date(millis) => crate::toml::date_to_rfc3339(*millis),
        Value::Array(_) | Value::Map(_) => String::new(),
    }
}

/// Text escaping: `<`, `&` and `>`.
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// Attribute escaping: `<`, `&`, `>` and `"`.
fn escape_attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}
