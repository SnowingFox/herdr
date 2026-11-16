//! `Bun.markdown.render` — plain text, or a caller-driven string.
//!
//! # With no callbacks it is a plain-text renderer
//!
//! ```text
//! render("# h\n\ntext")   "htext"
//! render("- a\n- b")      "ab"
//! render("```\ncode\n```") "code\n"
//! ```
//!
//! Block boundaries contribute nothing, list markers nothing, an `<hr>` nothing,
//! and a code block keeps its trailing newline. That is the default: every node
//! is replaced by the concatenation of its children, except the leaf kinds that
//! have text or a newline of their own.
//!
//! # With callbacks, argument 1 is the rendered children
//!
//! A callback is looked up by node name. It receives the **already-rendered**
//! string of the node's children — not an AST node — so composition is
//! concatenation, and the callbacks run innermost first. `softbreak` and
//! `linebreak` are the two places a newline is introduced by default; with no
//! callback they are `"\n"`.
//!
//! The meta object on block-ish nodes, measured:
//!
//! | callback | meta |
//! | --- | --- |
//! | `heading` | `{level}` |
//! | `list` | `{ordered, depth}` |
//! | `listItem` | `{index, depth, ordered}` |
//! | `link` | `{href}` |
//! | `image` | `{src}` |
//!
//! `paragraph`, `strong`, `em`, `codespan`, `code`, `blockquote`, `hr`, `del`,
//! `table`, `html` and `text` get **one** argument. A callback that returns a
//! non-string has the value coerced by `String()`; a callback may throw and the
//! exception propagates out of `render`.

use comrak::nodes::{ListType, NodeValue};
use comrak::Node;
use rn_v8_sys::v8;

use crate::value::{Map, Shared};

/// The caller's callback object, as V8 sees it.
///
/// Kept as the raw object rather than a converted [`Map`] because a callback is
/// a function, which the conversion layer deliberately refuses.
pub struct Callbacks<'s> {
    pub object: v8::Local<'s, v8::Value>,
}

/// How deep in a list the walker is, for the `list` and `listItem` meta.
#[derive(Clone, Copy, Default)]
struct ListState {
    depth: usize,
    ordered: bool,
    index: usize,
}

/// Renders `text`.
///
/// `Ok(None)` means a callback threw and the exception is pending.
pub fn render<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    text: &str,
    callbacks: Option<Callbacks<'s>>,
) -> Result<Option<String>, String> {
    let arena = comrak::Arena::new();
    let root = super::parse(&arena, text);
    let mut walker = Walker {
        scope,
        callbacks,
        threw: false,
    };
    let mut out = String::new();
    for child in root.children() {
        let rendered = walker.block(child, ListState::default())?;
        out.push_str(&rendered);
    }
    if walker.threw {
        return Ok(None);
    }
    Ok(Some(out))
}

struct Walker<'s, 'scope, 'p> {
    scope: &'scope mut v8::PinScope<'s, 'p>,
    callbacks: Option<Callbacks<'s>>,
    threw: bool,
}

impl<'s, 'scope, 'p> Walker<'s, 'scope, 'p> {
    /// Renders one block and its children.
    fn block(&mut self, node: Node<'_>, state: ListState) -> Result<String, String> {
        // A code block contributes its literal text, with the trailing newline
        // Bun keeps; an HTML block contributes its raw source. Both are leaves as
        // far as this renderer is concerned.
        let children = match &node.data.borrow().value {
            NodeValue::CodeBlock(code) => code.literal.clone(),
            NodeValue::HtmlBlock(html) => {
                let mut text = html.literal.clone();
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                text
            }
            _ => self.children(node, state)?,
        };
        let (name, meta) = block_name(node, state);
        Ok(self.apply(name, &children, meta))
    }

    fn children(&mut self, node: Node<'_>, state: ListState) -> Result<String, String> {
        let mut out = String::new();
        let is_list = matches!(node.data.borrow().value, NodeValue::List(_));
        let ordered = match &node.data.borrow().value {
            NodeValue::List(list) => matches!(list.list_type, ListType::Ordered),
            _ => state.ordered,
        };
        // A list's *children* see one more level of depth than the list itself, so
        // `list` reports the depth of the list and `listItem` the depth of the
        // item: `"- a\n  - b"` has `list` at 0 and 1 and the items at 0 and 1.
        let inner = if is_list {
            ListState {
                depth: state.depth,
                ordered,
                index: 0,
            }
        } else {
            state
        };
        let mut item_index = 0usize;
        for child in node.children() {
            let child_is_item = matches!(child.data.borrow().value, NodeValue::Item(_));
            let child_state = if child_is_item {
                ListState {
                    depth: inner.depth,
                    ordered,
                    index: item_index,
                }
            } else if is_list {
                // A nested list inside a list is one level deeper.
                ListState {
                    depth: inner.depth + 1,
                    ordered: inner.ordered,
                    index: 0,
                }
            } else if matches!(node.data.borrow().value, NodeValue::Item(_)) {
                // The blocks inside a list item belong to a list one level down.
                ListState {
                    depth: state.depth + 1,
                    ordered: state.ordered,
                    index: state.index,
                }
            } else {
                inner
            };
            // A paragraph inside a tight list item is not a block the renderer
            // reports: `render("- li1")` is `"li1"`, not `"<P>li1</P>"` with a
            // `paragraph` callback, because commonmark.js's tight-list rule makes
            // that paragraph transparent. The rule is "the item's parent list is
            // tight and the item holds exactly this one paragraph".
            let transparent =
                matches!(child.data.borrow().value, NodeValue::Paragraph) && tight_paragraph(child);
            let rendered = if transparent {
                self.children(child, child_state)?
            } else if is_block(&child.data.borrow().value) {
                self.block(child, child_state)?
            } else {
                self.inline(child, child_state)?
            };
            out.push_str(&rendered);
            if child_is_item {
                item_index += 1;
            }
        }
        Ok(out)
    }

    fn inline(&mut self, node: Node<'_>, state: ListState) -> Result<String, String> {
        // A text node's content is its own, not its children's — it has none —
        // and a code span's is its literal. Everything else composes from the
        // children, which is what makes `render` a plain-text renderer when no
        // callback replaces a node.
        let children = match &node.data.borrow().value {
            NodeValue::Text(text) => text.to_string(),
            NodeValue::Code(code) => code.literal.clone(),
            NodeValue::SoftBreak | NodeValue::LineBreak => "\n".to_string(),
            NodeValue::HtmlInline(html) => html.clone(),
            _ => self.children(node, state)?,
        };
        let (name, meta) = inline_name(node, state);
        Ok(self.apply(name, &children, meta))
    }

    /// The callback for `name`, if the caller supplied one.
    ///
    /// The returned handle is tied to the scope rather than to `self`, so the
    /// caller can keep using the scope afterwards; `Local<'s, _>` is what the
    /// scope yields.
    fn lookup(&mut self, name: &str) -> Option<v8::Local<'s, v8::Function>> {
        let object = self.callbacks.as_ref()?.object;
        let object = v8::Local::<v8::Object>::try_from(object).ok()?;
        let key = v8::String::new(self.scope, name)?;
        let value = object.get(self.scope, key.into())?;
        v8::Local::<v8::Function>::try_from(value).ok()
    }

    /// Calls the callback for `name` if there is one, and otherwise returns the
    /// default for that node.
    fn apply(&mut self, name: &str, children: &str, meta: Option<Meta>) -> String {
        if self.callbacks.is_none() {
            return children.to_string();
        }
        let Some(callback) = self.lookup(name) else {
            return children.to_string();
        };
        let Some(text) = v8::String::new(self.scope, children) else {
            return children.to_string();
        };
        let mut arguments: Vec<v8::Local<'s, v8::Value>> = vec![text.into()];
        if let Some(meta) = meta {
            if let Some(object) = self.meta_object(&meta) {
                arguments.push(object);
            }
        }
        let undefined = v8::undefined(self.scope);
        let Some(result) = callback.call(self.scope, undefined.into(), &arguments) else {
            self.threw = true;
            return String::new();
        };
        if self.scope.is_execution_terminating() {
            self.threw = true;
            return String::new();
        }
        // `null` and `undefined` become the empty string, and a number or boolean
        // becomes its `String()` form — which is `String(value)` minus the two
        // cases where `String()` would say `"null"` or `"undefined"` and Bun says
        // nothing at all.
        if result.is_null() || result.is_undefined() {
            return String::new();
        }
        result.to_rust_string_lossy(self.scope)
    }

    fn meta_object(&mut self, meta: &Meta) -> Option<v8::Local<'s, v8::Value>> {
        let object = v8::Object::new(self.scope);
        for (key, value) in meta.pairs() {
            let name = v8::String::new(self.scope, key)?;
            let value: v8::Local<'s, v8::Value> = match value {
                MetaValueRef::Number(number) => v8::Number::new(self.scope, number).into(),
                MetaValueRef::Bool(flag) => v8::Boolean::new(self.scope, flag).into(),
                MetaValueRef::String(text) => v8::String::new(self.scope, text.as_str())?.into(),
            };
            object.set(self.scope, name.into(), value)?;
        }
        Some(object.into())
    }
}

/// The meta object a callback's second argument carries.
struct Meta {
    pairs: Vec<(&'static str, MetaValue)>,
}

enum MetaValue {
    Number(f64),
    Bool(bool),
    String(String),
}

impl Meta {
    fn pairs(&self) -> Vec<(&'static str, MetaValueRef<'_>)> {
        self.pairs
            .iter()
            .map(|(key, value)| {
                (
                    *key,
                    match value {
                        MetaValue::Number(number) => MetaValueRef::Number(*number),
                        MetaValue::Bool(flag) => MetaValueRef::Bool(*flag),
                        MetaValue::String(text) => MetaValueRef::String(text),
                    },
                )
            })
            .collect()
    }
}

enum MetaValueRef<'a> {
    Number(f64),
    Bool(bool),
    String(&'a String),
}

/// The callback name and meta for a block node.
fn block_name(node: Node<'_>, state: ListState) -> (&'static str, Option<Meta>) {
    match &node.data.borrow().value {
        NodeValue::Paragraph => ("paragraph", None),
        NodeValue::Heading(heading) => (
            "heading",
            Some(Meta {
                pairs: vec![("level", MetaValue::Number(heading.level as f64))],
            }),
        ),
        NodeValue::BlockQuote => ("blockquote", None),
        NodeValue::List(list) => (
            "list",
            Some(Meta {
                pairs: vec![
                    (
                        "ordered",
                        MetaValue::Bool(matches!(list.list_type, ListType::Ordered)),
                    ),
                    ("depth", MetaValue::Number(state.depth as f64)),
                ],
            }),
        ),
        NodeValue::Item(_) => (
            "listItem",
            Some(Meta {
                pairs: vec![
                    ("index", MetaValue::Number(state.index as f64)),
                    ("depth", MetaValue::Number(state.depth as f64)),
                    ("ordered", MetaValue::Bool(state.ordered)),
                ],
            }),
        ),
        NodeValue::TaskItem(_) => (
            "listItem",
            Some(Meta {
                pairs: vec![
                    ("index", MetaValue::Number(state.index as f64)),
                    ("depth", MetaValue::Number(state.depth as f64)),
                    ("ordered", MetaValue::Bool(state.ordered)),
                ],
            }),
        ),
        NodeValue::CodeBlock(_) => ("code", None),
        NodeValue::ThematicBreak => ("hr", None),
        NodeValue::Table(_) => ("table", None),
        NodeValue::HtmlBlock(_) => ("html", None),
        NodeValue::SoftBreak => ("softbreak", None),
        NodeValue::LineBreak => ("linebreak", None),
        _ => ("", None),
    }
}

/// The callback name and meta for an inline node.
fn inline_name(node: Node<'_>, _state: ListState) -> (&'static str, Option<Meta>) {
    match &node.data.borrow().value {
        NodeValue::Text(_) => ("text", None),
        NodeValue::Strong => ("strong", None),
        NodeValue::Emph => ("em", None),
        NodeValue::Strikethrough => ("del", None),
        NodeValue::Code(_) => ("codespan", None),
        NodeValue::Link(link) => (
            "link",
            Some(Meta {
                pairs: vec![("href", MetaValue::String(link.url.clone()))],
            }),
        ),
        NodeValue::Image(link) => (
            "image",
            Some(Meta {
                pairs: vec![("src", MetaValue::String(link.url.clone()))],
            }),
        ),
        NodeValue::HtmlInline(_) => ("html", None),
        NodeValue::SoftBreak => ("softbreak", None),
        NodeValue::LineBreak => ("linebreak", None),
        _ => ("", None),
    }
}

/// Whether a paragraph is inside a tight list item, in which case it renders
/// transparently — its inline children and no `paragraph` node.
fn tight_paragraph(node: Node<'_>) -> bool {
    let Some(item) = node.parent() else {
        return false;
    };
    if !matches!(
        item.data.borrow().value,
        NodeValue::Item(_) | NodeValue::TaskItem(_)
    ) {
        return false;
    }
    let Some(list) = item.parent() else {
        return false;
    };
    match &list.data.borrow().value {
        NodeValue::List(list) => list.tight,
        _ => false,
    }
}

fn is_block(value: &NodeValue) -> bool {
    matches!(
        value,
        NodeValue::Document
            | NodeValue::Paragraph
            | NodeValue::Heading(_)
            | NodeValue::BlockQuote
            | NodeValue::List(_)
            | NodeValue::Item(_)
            | NodeValue::TaskItem(_)
            | NodeValue::CodeBlock(_)
            | NodeValue::ThematicBreak
            | NodeValue::Table(_)
            | NodeValue::TableRow(_)
            | NodeValue::TableCell
            | NodeValue::HtmlBlock(_)
    )
}

/// Unused, but keeps the `Shared` import meaningful if the walker later needs a
/// converted options map.
#[allow(dead_code)]
type UnusedMap = Shared<Map>;
