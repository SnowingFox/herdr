//! `Bun.markdown.react` — a React element object, built by hand.
//!
//! Measured shape:
//!
//! ```text
//! react("# Hi")
//!   { keys: ["$$typeof","type","key","ref","props"],
//!     $$typeof: Symbol(react.transitional.element),
//!     type:     Symbol(react.fragment),
//!     key:      null,
//!     ref:      null,
//!     props:    { children: [ … ] } }
//! ```
//!
//! The two symbols are `Symbol.for("react.transitional.element")` and
//! `Symbol.for("react.fragment")`, so they compare equal to the ones a
//! React-compatible library creates in the same process — the test asserts
//! `el.$$typeof === Symbol.for("react.transitional.element")` rather than
//! string-matching it.
//!
//! The root is always a **fragment** whose `props.children` is an array of block
//! elements. Each block becomes `{type: "<tag>", props: {children: [...]}}`, and
//! an inline element nests in its parent's `children`. Text is a plain string
//! child, and adjacent text is kept as separate entries rather than merged:
//! `"**b** and *i*"` is `[<strong>b</strong>, " and ", <em>i</em>]`.
//!
//! `react("")` is a fragment with `children: []`.
//!
//! When callbacks are supplied they work as they do for
//! [`crate::markdown::render`] — the callback's return value becomes the
//! element's `type` and the children stay its `props.children` — which is what
//! makes a custom component possible without an AST crossing into JavaScript.

use comrak::nodes::NodeValue;
use comrak::Node;
use rn_v8_sys::v8;

use crate::value::Map;

/// The caller's callbacks, as V8 sees them.
pub struct Callbacks<'s> {
    pub object: v8::Local<'s, v8::Value>,
}

/// Builds the fragment element for a document.
pub fn build<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    text: &str,
    callbacks: Option<Callbacks<'s>>,
) -> Result<Option<v8::Local<'s, v8::Value>>, String> {
    let arena = comrak::Arena::new();
    let root = super::parse(&arena, text);
    // `Symbol.for`, not `Symbol::for_api`: the registry symbol is what makes
    // `el.$$typeof === Symbol.for("react.transitional.element")` true, which is
    // how a React-compatible library and this object recognise each other.
    let element_type = registry_symbol(scope, "react.transitional.element")?;
    let fragment = registry_symbol(scope, "react.fragment")?;
    let mut builder = Builder {
        scope,
        callbacks,
        element_type,
        threw: false,
    };
    let mut children: Vec<v8::Local<'s, v8::Value>> = Vec::new();
    for child in root.children() {
        if let Some(value) = builder.node(child)? {
            children.push(value);
        }
    }
    if builder.threw {
        return Ok(None);
    }
    let scope = &mut *builder.scope;
    let props = v8::Object::new(scope);
    let key = v8::String::new(scope, "children").ok_or("cannot allocate".to_string())?;
    let array = v8::Array::new(scope, 0);
    for (index, child) in children.iter().enumerate() {
        array
            .set_index(scope, index as u32, *child)
            .ok_or("cannot set a child".to_string())?;
    }
    props
        .set(scope, key.into(), array.into())
        .ok_or("cannot set children".to_string())?;
    element(scope, builder.element_type, fragment.into(), props.into()).map(Some)
}

struct Builder<'s, 'scope, 'p> {
    scope: &'scope mut v8::PinScope<'s, 'p>,
    callbacks: Option<Callbacks<'s>>,
    element_type: v8::Local<'s, v8::Symbol>,
    threw: bool,
}

impl<'s, 'scope, 'p> Builder<'s, 'scope, 'p> {
    /// One node as a value: an element, or a string for text.
    fn node(&mut self, node: Node<'_>) -> Result<Option<v8::Local<'s, v8::Value>>, String> {
        match &node.data.borrow().value {
            NodeValue::Text(text) => Ok(Some(
                v8::String::new(self.scope, text)
                    .ok_or("cannot allocate text".to_string())?
                    .into(),
            )),
            NodeValue::Code(code) => {
                let inner = v8::String::new(self.scope, &code.literal)
                    .ok_or("cannot allocate text".to_string())?;
                Ok(Some(self.element("code", vec![inner.into()])?))
            }
            // A soft break is a newline inside the surrounding text, which Bun
            // keeps as its own child.
            NodeValue::SoftBreak => Ok(Some(
                v8::String::new(self.scope, "\n")
                    .ok_or("cannot allocate text".to_string())?
                    .into(),
            )),
            NodeValue::LineBreak => Ok(Some(
                v8::String::new(self.scope, "\n")
                    .ok_or("cannot allocate text".to_string())?
                    .into(),
            )),
            // Raw HTML is text here, not an element.
            NodeValue::HtmlInline(html) => Ok(Some(
                v8::String::new(self.scope, html)
                    .ok_or("cannot allocate text".to_string())?
                    .into(),
            )),
            NodeValue::HtmlBlock(html) => Ok(Some(
                v8::String::new(self.scope, &html.literal)
                    .ok_or("cannot allocate text".to_string())?
                    .into(),
            )),
            other => {
                let name = element_name(other);
                let mut children: Vec<v8::Local<'s, v8::Value>> = Vec::new();
                for child in node.children() {
                    if let Some(value) = self.node(child)? {
                        children.push(value);
                    }
                }
                let custom = self.custom(name, &children);
                if let Some(custom) = custom {
                    return Ok(Some(custom));
                }
                Ok(Some(self.element(name, children)?))
            }
        }
    }

    /// Calls the caller's callback for `name`, if any, and wraps its result the
    /// way Bun does.
    fn custom(
        &mut self,
        name: &str,
        children: &[v8::Local<'s, v8::Value>],
    ) -> Option<v8::Local<'s, v8::Value>> {
        let callbacks = self.callbacks.as_ref()?;
        let object = v8::Local::<v8::Object>::try_from(callbacks.object).ok()?;
        let key = v8::String::new(self.scope, name)?;
        let value = object.get(self.scope, key.into())?;
        let callback = v8::Local::<v8::Function>::try_from(value).ok()?;
        // A callback receives the concatenated text of its children, which is
        // what `render` gives it, so the two members compose the same way.
        let joined = children
            .iter()
            .filter_map(|child| {
                v8::Local::<v8::String>::try_from(*child)
                    .ok()
                    .map(|text| text.to_rust_string_lossy(self.scope))
            })
            .collect::<Vec<_>>()
            .join("");
        let text = v8::String::new(self.scope, &joined)?;
        let undefined = v8::undefined(self.scope);
        let Some(result) = callback.call(self.scope, undefined.into(), &[text.into()]) else {
            self.threw = true;
            return None;
        };
        if self.scope.is_execution_terminating() {
            self.threw = true;
            return None;
        }
        let props = v8::Object::new(self.scope);
        let key = v8::String::new(self.scope, "children")?;
        let array = v8::Array::new(self.scope, 0);
        for (index, child) in children.iter().enumerate() {
            array.set_index(self.scope, index as u32, *child)?;
        }
        props.set(self.scope, key.into(), array.into())?;
        element(self.scope, self.element_type, result, props.into()).ok()
    }

    /// An element with a tag name and children.
    fn element(
        &mut self,
        tag: &str,
        children: Vec<v8::Local<'s, v8::Value>>,
    ) -> Result<v8::Local<'s, v8::Value>, String> {
        let props = v8::Object::new(self.scope);
        let key = v8::String::new(self.scope, "children").ok_or("cannot allocate".to_string())?;
        let array = v8::Array::new(self.scope, 0);
        for (index, child) in children.iter().enumerate() {
            array
                .set_index(self.scope, index as u32, *child)
                .ok_or("cannot set a child".to_string())?;
        }
        props
            .set(self.scope, key.into(), array.into())
            .ok_or("cannot set children".to_string())?;
        let tag = v8::String::new(self.scope, tag).ok_or("cannot allocate a tag".to_string())?;
        element(self.scope, self.element_type, tag.into(), props.into())
    }
}

/// A symbol from the global registry, the way `Symbol.for(key)` does it.
///
/// V8's `Symbol::for_api` is the per-isolate API and answers a different symbol
/// from `Symbol.for`, so calling JavaScript's own `Symbol.for` is the only way to
/// get the one a library will compare against.
fn registry_symbol<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: &str,
) -> Result<v8::Local<'s, v8::Symbol>, String> {
    let symbol = v8::Symbol::for_api(
        scope,
        v8::String::new(scope, key).ok_or_else(|| "cannot allocate".to_string())?,
    );
    let _ = symbol;
    let global = scope.get_current_context().global(scope);
    let name = v8::String::new(scope, "Symbol").ok_or_else(|| "cannot allocate".to_string())?;
    let constructor = global
        .get(scope, name.into())
        .and_then(|value| v8::Local::<v8::Object>::try_from(value).ok())
        .ok_or_else(|| "Symbol is not available".to_string())?;
    let for_name = v8::String::new(scope, "for").ok_or_else(|| "cannot allocate".to_string())?;
    let function = constructor
        .get(scope, for_name.into())
        .and_then(|value| v8::Local::<v8::Function>::try_from(value).ok())
        .ok_or_else(|| "Symbol.for is not available".to_string())?;
    let key = v8::String::new(scope, key).ok_or_else(|| "cannot allocate".to_string())?;
    let undefined = v8::undefined(scope);
    let symbol = function
        .call(scope, constructor.into(), &[key.into()])
        .and_then(|value| v8::Local::<v8::Symbol>::try_from(value).ok())
        .ok_or_else(|| "Symbol.for did not answer a symbol".to_string())?;
    let _ = undefined;
    Ok(symbol)
}

/// The element Bun's renderer uses for a node.
fn element_name(value: &NodeValue) -> &'static str {
    match value {
        NodeValue::Paragraph => "p",
        NodeValue::Heading(heading) => match heading.level {
            1 => "h1",
            2 => "h2",
            3 => "h3",
            4 => "h4",
            5 => "h5",
            _ => "h6",
        },
        NodeValue::Strong => "strong",
        NodeValue::Emph => "em",
        NodeValue::Strikethrough => "del",
        NodeValue::BlockQuote => "blockquote",
        NodeValue::List(list) => {
            if matches!(list.list_type, comrak::nodes::ListType::Ordered) {
                "ol"
            } else {
                "ul"
            }
        }
        NodeValue::Item(_) | NodeValue::TaskItem(_) => "li",
        NodeValue::CodeBlock(_) => "pre",
        NodeValue::ThematicBreak => "hr",
        NodeValue::Link(_) => "a",
        NodeValue::Image(_) => "img",
        NodeValue::Table(_) => "table",
        NodeValue::TableRow(true) => "tr",
        NodeValue::TableRow(false) => "tr",
        NodeValue::TableCell => "td",
        _ => "span",
    }
}

/// Builds one React element object.
///
/// The shape is `{$$typeof, type, key, ref, props}` in that order, because
/// `Object.keys` on it is observable and the test compares the key list.
fn element<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    element_type: v8::Local<'s, v8::Symbol>,
    kind: v8::Local<'s, v8::Value>,
    props: v8::Local<'s, v8::Value>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let object = v8::Object::new(scope);
    for (name, value) in [
        ("$$typeof", element_type.into()),
        ("type", kind),
        ("key", v8::null(scope).into()),
        ("ref", v8::null(scope).into()),
        ("props", props),
    ] {
        let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
        object
            .set(scope, key.into(), value)
            .ok_or_else(|| format!("cannot set {name}"))?;
    }
    let _ = Map::new();
    Ok(object.into())
}
