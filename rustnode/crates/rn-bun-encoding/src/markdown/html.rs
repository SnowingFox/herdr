//! `Bun.markdown.html` — CommonMark + GFM to HTML, byte for byte.
//!
//! The walker is here rather than `comrak::markdown_to_html` for two node kinds
//! whose markup Bun writes differently, and each is pinned by a test:
//!
//! ```text
//! table row      Bun   <tr><th>a</th><th>b</th></tr>\n     comrak splits it over lines
//! task item      Bun   <li class="task-list-item"><input type="checkbox"
//!                       class="task-list-item-checkbox" disabled checked>done</li>
//!                comrak <li><input type="checkbox" checked="" disabled="" /> done</li>
//! ```
//!
//! Everything else is the commonmark.js layout comrak also produces, including
//! the details that are easy to get wrong: a blank line between two blocks in the
//! same list item, `<br />` with a space for a hard break but `<hr />` likewise,
//! `\n` after every block and inside `<pre><code>`, and `&quot;` for a double
//! quote in text.

use comrak::nodes::{ListType, NodeValue, TableAlignment};
use comrak::Node;

/// Renders a document.
pub fn render(text: &str) -> String {
    let arena = comrak::Arena::new();
    let root = super::parse(&arena, text);
    let mut out = String::new();
    // An empty document renders as the empty string, not as a newline.
    for child in root.children() {
        block(child, &mut out, false);
    }
    out
}

/// The text of a node's children, rendered inline.
fn inline_children(node: Node<'_>) -> String {
    let mut out = String::new();
    for child in node.children() {
        inline(child, &mut out);
    }
    out
}

/// One inline node.
fn inline(node: Node<'_>, out: &mut String) {
    match &node.data.borrow().value {
        NodeValue::Text(text) => escape_text(text, out),
        NodeValue::SoftBreak => out.push('\n'),
        NodeValue::LineBreak => out.push_str("<br />\n"),
        NodeValue::Code(code) => {
            out.push_str("<code>");
            escape_text(&code.literal, out);
            out.push_str("</code>");
        }
        NodeValue::Emph => {
            out.push_str("<em>");
            out.push_str(&inline_children(node));
            out.push_str("</em>");
        }
        NodeValue::Strong => {
            out.push_str("<strong>");
            out.push_str(&inline_children(node));
            out.push_str("</strong>");
        }
        NodeValue::Strikethrough => {
            out.push_str("<del>");
            out.push_str(&inline_children(node));
            out.push_str("</del>");
        }
        NodeValue::Link(link) => {
            out.push_str("<a href=\"");
            escape_href(&link.url, out);
            out.push('"');
            if !link.title.is_empty() {
                out.push_str(" title=\"");
                escape_text(&link.title, out);
                out.push('"');
            }
            out.push('>');
            out.push_str(&inline_children(node));
            out.push_str("</a>");
        }
        NodeValue::Image(link) => {
            out.push_str("<img src=\"");
            escape_href(&link.url, out);
            out.push_str("\" alt=\"");
            // The alt text is the plain text of the children, not their markup.
            let mut alt = String::new();
            plain_children(node, &mut alt);
            escape_text(&alt, out);
            out.push('"');
            if !link.title.is_empty() {
                out.push_str(" title=\"");
                escape_text(&link.title, out);
                out.push('"');
            }
            out.push_str(" />");
        }
        // Inline raw HTML passes through verbatim.
        NodeValue::HtmlInline(html) => out.push_str(html),
        // Anything the extension set does not enable still has its text
        // rendered, so no content is silently dropped.
        NodeValue::Escaped | NodeValue::Math(_) => out.push_str(&inline_children(node)),
        _ => out.push_str(&inline_children(node)),
    }
}

/// The plain text of a node's children, for an `alt` attribute.
fn plain_children(node: Node<'_>, out: &mut String) {
    for child in node.children() {
        match &child.data.borrow().value {
            NodeValue::Text(text) => out.push_str(text),
            NodeValue::Code(code) => out.push_str(&code.literal),
            _ => plain_children(child, out),
        }
    }
}

/// One block node.
///
/// `tight` is whether the enclosing list is tight, which decides whether a
/// paragraph inside a list item is wrapped in `<p>`. Bun follows commonmark.js
/// here: a tight list omits the `<p>`, a loose one keeps it.
fn block(node: Node<'_>, out: &mut String, tight: bool) {
    match &node.data.borrow().value {
        NodeValue::Document => {
            for child in node.children() {
                block(child, out, false);
            }
        }
        NodeValue::Paragraph => {
            if tight {
                inline_children_into(node, out);
                out.push('\n');
            } else {
                out.push_str("<p>");
                inline_children_into(node, out);
                out.push_str("</p>\n");
            }
        }
        NodeValue::Heading(heading) => {
            let level = heading.level;
            out.push_str(&format!("<h{level}>"));
            inline_children_into(node, out);
            out.push_str(&format!("</h{level}>\n"));
        }
        NodeValue::ThematicBreak => out.push_str("<hr />\n"),
        NodeValue::BlockQuote => {
            out.push_str("<blockquote>\n");
            for child in node.children() {
                block(child, out, false);
            }
            out.push_str("</blockquote>\n");
        }
        NodeValue::List(list) => {
            let ordered = matches!(list.list_type, ListType::Ordered);
            let tag = if ordered { "ol" } else { "ul" };
            out.push('<');
            out.push_str(tag);
            // An ordered list that does not start at 1 says so.
            if ordered && list.start != 1 {
                out.push_str(&format!(" start=\"{}\"", list.start));
            }
            out.push_str(">\n");
            // A list is tight when none of its items is separated from another by
            // a blank line, which comrak records on the list.
            // comrak records tightness on the list itself, which is exactly the
            // blank-line rule the CommonMark spec defines and what its own HTML
            // renderer reads. Reconstructing it from paragraph counts was wrong:
            // `"1. a\n\n2. b"` is loose and has one paragraph per item.
            let tight = list.tight;
            for item in node.children() {
                item_block(item, out, tight);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push_str(">\n");
        }
        NodeValue::CodeBlock(code) => {
            out.push_str("<pre><code");
            let language = language_of(&code.info);
            if !language.is_empty() {
                out.push_str(" class=\"language-");
                escape_text(&language, out);
                out.push('"');
            }
            out.push('>');
            escape_text(&code.literal, out);
            if !code.literal.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("</code></pre>\n");
        }
        NodeValue::HtmlBlock(html) => {
            out.push_str(&html.literal);
            out.push('\n');
        }
        NodeValue::Table(_) => table(node, out),
        // Anything else contributes its blocks, so content is never dropped.
        _ => {
            for child in node.children() {
                block(child, out, tight);
            }
        }
    }
}

fn inline_children_into(node: Node<'_>, out: &mut String) {
    for child in node.children() {
        inline(child, out);
    }
}

/// One list item.
fn item_block(node: Node<'_>, out: &mut String, tight: bool) {
    // A task item is an `Item` whose first child is a `TaskItem`, so the class
    // goes on the `<li>` and the checkbox leads the content.
    let task = match &node.data.borrow().value {
        NodeValue::TaskItem(task) => Some(task.symbol.is_some()),
        _ => None,
    };
    if let Some(checked) = task {
        out.push_str("<li class=\"task-list-item\">");
        out.push_str("<input type=\"checkbox\" class=\"task-list-item-checkbox\" disabled");
        if checked {
            out.push_str(" checked");
        }
        out.push('>');
        // The content follows the checkbox with no separator.
        let mut content = String::new();
        for child in node.children() {
            block(child, &mut content, true);
        }
        out.push_str(content.trim_end_matches('\n'));
        out.push_str("</li>\n");
        return;
    }
    if let NodeValue::TaskItem(_) = &node.data.borrow().value {}
    out.push_str("<li>");
    let blocks: Vec<Node<'_>> = node.children().collect();
    let single_paragraph =
        tight && blocks.len() == 1 && matches!(blocks[0].data.borrow().value, NodeValue::Paragraph);
    if single_paragraph {
        inline_children_into(blocks[0], out);
        out.push_str("</li>\n");
        return;
    }
    if tight {
        // A tight item keeps its blocks inline: a leading text line, then a
        // nested list whose own trailing newline is kept. The measured shape of
        // `"- a\n  - b"` is `<li>a\n<ul>…</ul>\n</li>`, so the newline after a
        // nested list's `</ul>` survives and only the final one is replaced by
        // `</li>`.
        let mut content = String::new();
        for child in &blocks {
            block(child, &mut content, true);
        }
        out.push_str(&content);
        out.push_str("</li>\n");
        return;
    }
    out.push('\n');
    for child in &blocks {
        block(child, out, false);
    }
    out.push_str("</li>\n");
}

/// A GFM table.
fn table(node: Node<'_>, out: &mut String) {
    let alignments = match &node.data.borrow().value {
        NodeValue::Table(table) => table.alignments.clone(),
        _ => Vec::new(),
    };
    let mut rows = node.children();
    let Some(header) = rows.next() else {
        return;
    };
    out.push_str("<table>\n<thead>\n");
    table_row(header, &alignments, "th", out);
    out.push_str("</thead>\n");
    let body: Vec<Node<'_>> = rows.collect();
    if !body.is_empty() {
        out.push_str("<tbody>\n");
        for row in &body {
            table_row(row, &alignments, "td", out);
        }
        out.push_str("</tbody>\n");
    }
    out.push_str("</table>\n");
}

/// One table row: `<tr>` and its cells on one line, which is Bun's layout.
fn table_row(row: Node<'_>, alignments: &[TableAlignment], cell: &str, out: &mut String) {
    out.push_str("<tr>");
    for (index, column) in row.children().enumerate() {
        let alignment = alignments
            .get(index)
            .copied()
            .unwrap_or(TableAlignment::None);
        out.push('<');
        out.push_str(cell);
        match alignment {
            TableAlignment::Left => out.push_str(" align=\"left\""),
            TableAlignment::Center => out.push_str(" align=\"center\""),
            TableAlignment::Right => out.push_str(" align=\"right\""),
            TableAlignment::None => {}
        }
        out.push('>');
        inline_children_into(column, out);
        out.push_str("</");
        out.push_str(cell);
        out.push('>');
    }
    out.push_str("</tr>\n");
}

/// The language of a fenced code block: the first word of the info string.
fn language_of(info: &str) -> String {
    info.split_whitespace().next().unwrap_or("").to_string()
}

/// Text escaping: `<`, `>`, `&` and `"`.
///
/// The double quote is escaped in text as well as in attributes, which is
/// measurable: `markdown.html("\"quotes\"")` is `&quot;quotes&quot;` and not
/// `"quotes"`.
fn escape_text(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
}

/// An `href` or `src`: `&` becomes `&amp;` and other characters are left alone.
fn escape_href(url: &str, out: &mut String) {
    for character in url.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            other => out.push(other),
        }
    }
}
