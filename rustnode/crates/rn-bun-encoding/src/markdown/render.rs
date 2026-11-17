//! `Bun.markdown.render` — plain text, or a caller-driven string.
//!
//! Everything here is measured against Bun 1.4.4 rather than inferred from the
//! documentation, and three of the measured facts contradict what the obvious
//! reading of "render with callbacks" would produce.
//!
//! # With no callbacks it is a plain-text renderer
//!
//! ```text
//! render("p1\n\np2")          "p1p2"
//! render("a\nb")              "a\nb"
//! render("```js\nx\n```")     "x\n"
//! render("<div>x</div>")      "<div>x</div>\n"
//! render("| a | b |\n|-|-|\n| 1 | 2 |")  "ab12"
//! render("a\n\n---\n\nb")     "ab"
//! ```
//!
//! Block boundaries contribute nothing, a soft or hard break is `"\n"`, and a
//! code block or HTML block keeps its trailing newline.
//!
//! # With callbacks the tree is fully walked, including the leaves
//!
//! The default path is *not* what the callbacks see. With any callback present,
//! every node is visited — including `text`, `paragraph`, `tr`, `thead`,
//! `tbody` — and a leaf still calls the caller's `text` even when no callback
//! replaced it. So a `code` callback receives the concatenation of the `text`
//! children (`"x"` and `"\n"`), not the raw literal.
//!
//! # The callback keys are not the HTML tag names
//!
//! Measured with a `Proxy` over the callbacks object, the full key set Bun
//! consults is:
//!
//! ```text
//! blockquote code codespan emphasis heading hr html image link list listItem
//! paragraph strikethrough strong table tbody td text th thead tr
//! ```
//!
//! `emphasis` and `strikethrough`, not `em` and `del`; `code` for a fenced block
//! and `codespan` for an inline one. `softbreak` and `linebreak` are **never**
//! consulted — a break is a `"\n"` inside the neighbouring `text` nodes.
//!
//! # The meta objects
//!
//! | callback | meta |
//! | --- | --- |
//! | `heading` | `{level}` |
//! | `list` | `{ordered, depth}` plus `{start}` when ordered |
//! | `listItem` | `{index, depth, ordered}` plus `{start}` when ordered, `{checked}` when a task item |
//! | `link` | `{href}`, plus `{title}` when one is present |
//! | `image` | `{src}`, plus `{title}` when one is present |
//! | `th`, `td` | `{}`, plus `{align}` when the column is aligned |
//! | `code` | `{language}`, only when the fence names one |
//! | everything else | no second argument at all |
//!
//! A callback that returns a non-string has the value coerced by `String()`; a
//! callback may throw and the exception propagates out of `render`.

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
    /// The list's first ordinal, which Bun reports only for ordered lists.
    start: Option<usize>,
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
        let rendered = walker.block(child, ListState::default(), None)?;
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
    ///
    /// `align` is the enclosing table column's alignment, which only a `th`/`td`
    /// consumes; every other block ignores it.
    fn block(
        &mut self,
        node: Node<'_>,
        state: ListState,
        align: Option<&'static str>,
    ) -> Result<String, String> {
        let children = self.children(node, state)?;
        let (name, meta) = block_name(node, state, align);
        Ok(self.apply(name, &children, meta))
    }

    fn children(&mut self, node: Node<'_>, state: ListState) -> Result<String, String> {
        let mut out = String::new();
        // A code block or HTML block is a leaf that still reports its content as
        // `text` children, **one per line and one for each newline**: measured,
        // ```` ```js\nlet a=1\nlet b=2\n``` ```` calls `text("let a=1")`,
        // `text("\n")`, `text("let b=2")`, `text("\n")`. Comrak holds the literal
        // on the node rather than as child nodes, so it is split here.
        match &node.data.borrow().value {
            NodeValue::CodeBlock(code) => {
                for line in lines_of(&code.literal) {
                    let rendered = self.apply("text", line, None);
                    out.push_str(&rendered);
                }
                return Ok(out);
            }
            NodeValue::HtmlBlock(html) => {
                for line in lines_of(&html.literal) {
                    let rendered = self.apply("text", line, None);
                    out.push_str(&rendered);
                }
                return Ok(out);
            }
            _ => {}
        }
        let is_list = matches!(node.data.borrow().value, NodeValue::List(_));
        let (ordered, start) = match &node.data.borrow().value {
            NodeValue::List(list) => (
                matches!(list.list_type, ListType::Ordered),
                Some(list.start),
            ),
            _ => (state.ordered, state.start),
        };
        // A list's *children* see one more level of depth than the list itself, so
        // `list` reports the depth of the list and `listItem` the depth of the
        // item: `"- a\n  - b"` has `list` at 0 and 1 and the items at 0 and 1.
        let inner = ListState {
            depth: state.depth,
            ordered,
            index: 0,
            start,
        };
        // A table's rows are grouped: Bun reports `table(thead(tr(..))*
        // tbody(tr(..))*)`, with each section closed as soon as its rows are
        // done — so `tbody` is **absent** from a header-only table, which the
        // measurement above shows. Comrak attaches the rows directly to the
        // table, so the two wrappers are synthesised here.
        if let NodeValue::Table(_) = node.data.borrow().value {
            let alignments = table_alignments(node);
            let mut head = String::new();
            let mut body = String::new();
            let mut body_rows = 0usize;
            let mut head_closed = false;
            for row in node.children() {
                let header = matches!(row.data.borrow().value, NodeValue::TableRow(true));
                if !header && !head_closed {
                    out.push_str(&self.apply("thead", &head, None));
                    head_closed = true;
                }
                let rendered = self.children_with(row, state, &alignments)?;
                let rendered = self.apply("tr", &rendered, None);
                if header {
                    head.push_str(&rendered);
                } else {
                    body_rows += 1;
                    body.push_str(&rendered);
                }
            }
            if !head_closed {
                out.push_str(&self.apply("thead", &head, None));
            }
            // A body row that renders to nothing still reports `tbody`: measured,
            // `| a |\n|---|\n|  |` calls `tbody("")`. The section exists because
            // the *table* has a body row, not because its rendering is non-empty,
            // so the presence of a row is what decides.
            if body_rows > 0 {
                out.push_str(&self.apply("tbody", &body, None));
            }
            return Ok(out);
        }
        let mut item_index = 0usize;
        for child in node.children() {
            let child_is_item = matches!(
                child.data.borrow().value,
                NodeValue::Item(_) | NodeValue::TaskItem(_)
            );
            let child_state = if child_is_item {
                ListState {
                    depth: inner.depth,
                    ordered,
                    index: item_index,
                    start,
                }
            } else if is_list {
                // A nested list inside a list is one level deeper.
                ListState {
                    depth: inner.depth + 1,
                    ordered: inner.ordered,
                    index: 0,
                    start: inner.start,
                }
            } else if matches!(node.data.borrow().value, NodeValue::Item(_)) {
                // The blocks inside a list item belong to a list one level down.
                ListState {
                    depth: state.depth + 1,
                    ordered: state.ordered,
                    index: state.index,
                    start: state.start,
                }
            } else {
                inner
            };
            // A paragraph inside a tight list item is not a block the renderer
            // reports: `render("- li1")` is `"li1"`, not a `paragraph` node,
            // because commonmark's tight-list rule makes that paragraph
            // transparent.
            let transparent =
                matches!(child.data.borrow().value, NodeValue::Paragraph) && tight_paragraph(child);
            let rendered = if transparent {
                self.children(child, child_state)?
            } else if is_block(&child.data.borrow().value) {
                self.block(child, child_state, None)?
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

    /// Renders a table row's cells, with their column alignments.
    fn children_with(
        &mut self,
        node: Node<'_>,
        state: ListState,
        alignments: &[Option<&'static str>],
    ) -> Result<String, String> {
        let mut out = String::new();
        for cell in node.children() {
            let align = column_align(&cell, alignments);
            let rendered = self.block(cell, state, align)?;
            out.push_str(&rendered);
        }
        Ok(out)
    }

    fn inline(&mut self, node: Node<'_>, state: ListState) -> Result<String, String> {
        // Every inline leaf reports its content through `text`, except a break:
        // measured, `` `b` `` calls `text("b")` and then `codespan` with that
        // result, while a soft or hard break emits `"\n"` and consults **no**
        // callback at all — not `text`, not `softbreak`, not `linebreak`. The
        // newline therefore goes straight into the output.
        let (name, meta) = inline_name(node);
        let children = match &node.data.borrow().value {
            NodeValue::Text(text) => return Ok(self.apply("text", text, None)),
            NodeValue::Code(code) => {
                let inner = self.apply("text", &code.literal, None);
                return Ok(self.apply("codespan", &inner, meta));
            }
            NodeValue::SoftBreak | NodeValue::LineBreak => return Ok("\n".to_string()),
            NodeValue::HtmlInline(html) => {
                let inner = self.apply("text", html, None);
                return Ok(self.apply("html", &inner, meta));
            }
            _ => self.children(node, state)?,
        };
        Ok(self.apply(name, &children, meta))
    }

    /// The callback for `name`, if the caller supplied one.
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
        // becomes its `String()` form.
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
///
/// `align` is only read for a table cell; passing `None` everywhere else keeps
/// the signature honest about that.
fn block_name(
    node: Node<'_>,
    state: ListState,
    align: Option<&'static str>,
) -> (&'static str, Option<Meta>) {
    match &node.data.borrow().value {
        NodeValue::Paragraph => ("paragraph", None),
        NodeValue::Heading(heading) => (
            "heading",
            Some(Meta {
                pairs: vec![("level", MetaValue::Number(heading.level as f64))],
            }),
        ),
        NodeValue::BlockQuote => ("blockquote", None),
        NodeValue::List(list) => {
            let ordered = matches!(list.list_type, ListType::Ordered);
            // Key order is measured: `ordered`, then `start` (ordered only), then
            // `depth`. `JSON.stringify` of the meta shows it, and an object's own
            // key order is observable.
            let mut pairs = vec![("ordered", MetaValue::Bool(ordered))];
            // `start` is the list's own first ordinal rather than always 1.
            if ordered {
                pairs.push(("start", MetaValue::Number(list.start as f64)));
            }
            pairs.push(("depth", MetaValue::Number(state.depth as f64)));
            ("list", Some(Meta { pairs }))
        }
        NodeValue::Item(_) => (
            "listItem",
            Some(Meta {
                pairs: item_pairs(state, None),
            }),
        ),
        NodeValue::TaskItem(item) => (
            "listItem",
            Some(Meta {
                // A task item always reports `checked`, and an unchecked one is
                // `checked: false` rather than an absent key.
                pairs: item_pairs(state, Some(item.symbol)),
            }),
        ),
        NodeValue::CodeBlock(code) => {
            let language = code.info.trim();
            if language.is_empty() {
                ("code", None)
            } else {
                // The fence's first word: ```` ```js title="a" ```` reports `js`.
                let name = language.split_whitespace().next().unwrap_or(language);
                (
                    "code",
                    Some(Meta {
                        pairs: vec![("language", MetaValue::String(name.to_string()))],
                    }),
                )
            }
        }
        NodeValue::ThematicBreak => ("hr", None),
        NodeValue::Table(_) => ("table", None),
        NodeValue::TableRow(_) => ("tr", None),
        NodeValue::TableCell => {
            let name = if in_head_row(node) { "th" } else { "td" };
            (
                name,
                Some(Meta {
                    pairs: cell_pairs(align),
                }),
            )
        }
        NodeValue::HtmlBlock(_) => ("html", None),
        _ => ("", None),
    }
}

/// The `listItem` meta pairs, shared by items and task items.
///
/// `checked` is added for a **task item only**, and `None` means unchecked: the
/// key is present with `false`, not absent. Measured, `- [ ] a` reports
/// `{index, depth, ordered, checked:false}`.
fn item_pairs(state: ListState, checked: Option<Option<char>>) -> Vec<(&'static str, MetaValue)> {
    let mut pairs = vec![
        ("index", MetaValue::Number(state.index as f64)),
        ("depth", MetaValue::Number(state.depth as f64)),
        ("ordered", MetaValue::Bool(state.ordered)),
    ];
    if state.ordered {
        let start = state.start.unwrap_or(1);
        pairs.push(("start", MetaValue::Number(start as f64)));
    }
    if let Some(symbol) = checked {
        // `[x]` and `[X]` are both checked; `[ ]` is not.
        pairs.push((
            "checked",
            MetaValue::Bool(matches!(symbol, Some('x' | 'X'))),
        ));
    }
    pairs
}

/// A table cell's meta: `{}` with no alignment, `{align}` with one.
fn cell_pairs(align: Option<&'static str>) -> Vec<(&'static str, MetaValue)> {
    match align {
        Some(align) => vec![("align", MetaValue::String(align.to_string()))],
        None => Vec::new(),
    }
}

/// Whether a table row is part of the header.
fn in_head_row(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| matches!(parent.data.borrow().value, NodeValue::TableRow(true)))
}

/// The alignments of a table's columns, in order.
fn table_alignments(node: Node<'_>) -> Vec<Option<&'static str>> {
    let NodeValue::Table(table) = &node.data.borrow().value else {
        return Vec::new();
    };
    table
        .alignments
        .iter()
        .map(|alignment| match alignment {
            comrak::nodes::TableAlignment::Left => Some("left"),
            comrak::nodes::TableAlignment::Center => Some("center"),
            comrak::nodes::TableAlignment::Right => Some("right"),
            comrak::nodes::TableAlignment::None => None,
        })
        .collect()
}

/// The alignment for a table cell, by its column index within the row.
///
/// The alignments live on the `Table` node, two levels above the cell, so this
/// walks up once per cell rather than threading a vector through the walk.
fn column_align(node: &Node<'_>, alignments: &[Option<&'static str>]) -> Option<&'static str> {
    if !matches!(node.data.borrow().value, NodeValue::TableCell) {
        return None;
    }
    let column = node
        .previous_sibling()
        .map(|mut sibling| {
            let mut index = 1;
            while let Some(previous) = sibling.previous_sibling() {
                index += 1;
                sibling = previous;
            }
            index
        })
        .unwrap_or(0);
    alignments.get(column).copied().flatten()
}

/// The callback name and meta for an inline node.
fn inline_name(node: Node<'_>) -> (&'static str, Option<Meta>) {
    match &node.data.borrow().value {
        NodeValue::Text(_) => ("text", None),
        NodeValue::Strong => ("strong", None),
        NodeValue::Emph => ("emphasis", None),
        NodeValue::Strikethrough => ("strikethrough", None),
        NodeValue::Code(_) => ("codespan", None),
        NodeValue::Link(link) => (
            "link",
            Some(Meta {
                pairs: link_pairs("href", &link.url, &link.title),
            }),
        ),
        NodeValue::Image(link) => (
            "image",
            Some(Meta {
                pairs: link_pairs("src", &link.url, &link.title),
            }),
        ),
        NodeValue::HtmlInline(_) => ("html", None),
        // A break is reported as a `text("\n")` and consults no callback of its
        // own: measured, `softbreak` and `linebreak` are never looked up.
        NodeValue::SoftBreak | NodeValue::LineBreak => ("", None),
        _ => ("", None),
    }
}

/// A link's or image's meta: the URL under `href`/`src`, and `title` only when
/// there is one. Measured: an empty `title=""` is omitted rather than reported.
fn link_pairs(url_key: &'static str, url: &str, title: &str) -> Vec<(&'static str, MetaValue)> {
    let mut pairs = vec![(url_key, MetaValue::String(url.to_string()))];
    if !title.is_empty() {
        pairs.push(("title", MetaValue::String(title.to_string())));
    }
    pairs
}

/// A block literal split into the `text` nodes Bun reports for it.
///
/// One item per line's content and one `"\n"` between them, with a trailing
/// `"\n"` appended when the literal lacks one. Measured, `render("<div>x</div>")`
/// is `"<div>x</div>\n"` although the source has no trailing newline.
fn lines_of(literal: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    for segment in literal.split_inclusive('\n') {
        match segment.strip_suffix('\n') {
            Some(content) => {
                if !content.is_empty() {
                    lines.push(content);
                }
                lines.push("\n");
            }
            None => lines.push(segment),
        }
    }
    if !literal.ends_with('\n') {
        lines.push("\n");
    }
    lines
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
