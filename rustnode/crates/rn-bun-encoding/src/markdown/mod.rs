//! `Bun.markdown.html`, `.ansi`, `.render` and `.react`.
//!
//! Four members, all rendering the same CommonMark + GFM document four ways:
//!
//! | member | `length` | returns |
//! | --- | --- | --- |
//! | `html` | 1 | an HTML string |
//! | `ansi` | 2 | a terminal string |
//! | `render` | 3 | plain text, or a string built by caller callbacks |
//! | `react` | 3 | a React element object |
//!
//! # `html` is CommonMark plus a small GFM set, and nothing else
//!
//! Enabled: tables, task lists, strikethrough, autolinks, and raw HTML passed
//! through. Disabled: front matter, footnotes, description lists, math, heading
//! anchors, and smart punctuation (`"a"` stays `&quot;a&quot;` rather than
//! becoming a typographic quote). The renderer is written here rather than taken
//! from `comrak`'s default because two node kinds differ:
//!
//! ```text
//! Bun:   <tr><th>a</th><th>b</th></tr>          one line per row
//! comrak <tr>\n<th>a</th>\n<th>b</th>\n</tr>
//!
//! Bun:   <li class="task-list-item"><input type="checkbox" class="task-list-item-checkbox" disabled checked>done</li>
//! comrak <li><input type="checkbox" checked="" disabled="" /> done</li>
//! ```
//!
//! Everything else — 99 of the 106 hand-measured documents including nested
//! lists, loose lists, block quotes, code blocks, setext headings, link
//! references, hard breaks and raw HTML blocks — matches comrak byte for byte,
//! which is what made comrak worth depending on.
//!
//! # `render` with no callbacks returns plain text, not HTML
//!
//! ```text
//! Bun.markdown.render("**b**")   "b"
//! ```
//!
//! This surprises anyone who assumes `render` is the general entry point. With
//! callbacks each one receives `(childrenString, meta?)`:
//!
//! * argument 1 is the **already-rendered** string of the children, not an AST
//!   node, so a callback composes by concatenation;
//! * argument 2 is present only on block-ish nodes: `heading` gets `{level}`,
//!   `list` gets `{ordered, depth}`, `listItem` gets `{index, depth, ordered}`,
//!   `link` gets `{href}`, `image` gets `{src}`;
//! * a callback that returns a non-string has its value coerced through `String()`,
//!   so `null` and `undefined` become the empty string and `42` becomes `"42"`;
//! * a callback may throw, and the exception propagates;
//! * an unknown key is ignored.
//!
//! Callback names, measured: `heading`, `paragraph`, `strong`, `em`, `list`,
//! `listItem`, `code` (a block), `codespan` (inline), `link`, `image`,
//! `blockquote`, `hr`, `del`, `table`, `html`, `text`, `softbreak`, `linebreak`.
//!
//! # `ansi` is a terminal rendering with fixed escapes
//!
//! `colors: false` in the second argument drops the escapes and keeps the layout.
//! Every other option is ignored — `width`, `columns` and `strip` change nothing.
//!
//! # `react` builds objects by hand
//!
//! The element is `{$$typeof, type, key, ref, props}` with `$$typeof` and `type`
//! taken from `Symbol.for`, so the objects compare equal to ones built by a
//! React-compatible library in the same process.

use rn_v8_sys::v8;

use crate::convert::{from_js, string_or_bytes, throw_error, throw_type_error_with_code};
use crate::value::{Map, Shared, Value};

mod ansi;
mod html;
mod react;
mod render;

/// Builds the `Bun.markdown` namespace object.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    set(scope, object, "html", 1, html_member)?;
    set(scope, object, "ansi", 2, ansi_member)?;
    set(scope, object, "render", 3, render_member)?;
    set(scope, object, "react", 3, react_member)?;
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

/// The one message all four entry points share for a bad argument.
///
/// It is `ERR_INVALID_ARG_TYPE`, and unlike the parsers it does not stringify —
/// `markdown.html(42)` throws rather than rendering the document `"42"`.
const EXPECTED: &str = "Expected a string or buffer to render";

/// Reads the source argument or throws, returning `None` when it threw.
fn source<'s>(scope: &mut v8::PinScope<'s, '_>, value: v8::Local<'s, v8::Value>) -> Option<String> {
    match string_or_bytes(scope, value) {
        Some(text) => Some(text),
        None => {
            throw_type_error_with_code(scope, "ERR_INVALID_ARG_TYPE", EXPECTED);
            None
        }
    }
}

/// The option object of an `ansi` call, if it is an object.
fn option_map<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Shared<Map>> {
    if !value.is_object() || value.is_null() {
        return None;
    }
    match from_js(scope, value) {
        Ok(Value::Map(map)) => Some(map),
        _ => None,
    }
}

fn html_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(text) = source(scope, args.get(0)) else {
        return;
    };
    let out = html::render(&text);
    match v8::String::new(scope, &out) {
        Some(text) => rv.set(text.into()),
        None => throw_error(scope, "cannot allocate the output"),
    }
}

fn ansi_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let options_value = args.get(1);
    let Some(text) = source(scope, args.get(0)) else {
        return;
    };
    // Only `colors: false` is honoured; every other option is measured to change
    // nothing.
    let colors = option_map(scope, options_value)
        .and_then(|map| match map.borrow().get("colors") {
            Some(Value::Bool(flag)) => Some(*flag),
            _ => None,
        })
        .unwrap_or(true);
    let out = ansi::render(&text, colors);
    match v8::String::new(scope, &out) {
        Some(text) => rv.set(text.into()),
        None => throw_error(scope, "cannot allocate the output"),
    }
}

fn render_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let options_value = args.get(1);
    let Some(text) = source(scope, args.get(0)) else {
        return;
    };
    let callbacks = if options_value.is_function() || !options_value.is_object() {
        None
    } else {
        Some(render::Callbacks {
            object: options_value,
        })
    };
    let out = match render::render(scope, &text, callbacks) {
        Ok(Some(out)) => out,
        // A callback threw, and the exception is already pending.
        Ok(None) => return,
        Err(message) => {
            throw_error(scope, &message);
            return;
        }
    };
    match v8::String::new(scope, &out) {
        Some(text) => rv.set(text.into()),
        None => throw_error(scope, "cannot allocate the output"),
    }
}

fn react_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let options_value = args.get(1);
    let Some(text) = source(scope, args.get(0)) else {
        return;
    };
    let callbacks = if options_value.is_object() && !options_value.is_null() {
        Some(react::Callbacks {
            object: options_value,
        })
    } else {
        None
    };
    match react::build(scope, &text, callbacks) {
        Ok(Some(element)) => rv.set(element),
        Ok(None) => (),
        Err(message) => throw_error(scope, &message),
    }
}

/// The comrak extension and render options Bun's `html` output corresponds to.
///
/// The set is measured rather than assumed: turning on any of the extensions not
/// listed here changes at least one of the 106 documents in a way Bun does not.
pub(crate) fn comrak_options() -> comrak::Options<'static> {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.tasklist = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    // Raw HTML is passed through, not escaped.
    options.render.r#unsafe = true;
    // `markdown.html("a < b")` escapes, but a raw inline `<b>` passes; that is
    // comrak's default with `unsafe`, so nothing else is needed.
    options.render.width = 0;
    options
}

/// Parses `text` and walks the document.
pub(crate) fn parse<'a>(arena: &'a comrak::Arena<'a>, text: &str) -> comrak::Node<'a> {
    comrak::parse_document(arena, text, &comrak_options())
}
