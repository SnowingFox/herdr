//! `Bun.markdown.ansi` — the terminal rendering.
//!
//! Exact escapes for the measured documents, so they are pinned in tests rather
//! than described:
//!
//! ```text
//! ansi("# Hi")        \x1b[1m\x1b[35mHi\x1b[0m\n\x1b[2m═══\x1b[0m\n
//! ansi("## H2")       \x1b[1m\x1b[36mH2\x1b[0m\n\x1b[2m───\x1b[0m\n
//! ansi("**b**")       \x1b[1mb\x1b[22m\x1b[0m\n
//! ansi("*i*")         \x1b[3mi\x1b[23m\x1b[0m\n
//! ansi("~~s~~")       \x1b[9ms\x1b[29m\x1b[0m\n
//! ansi("`x`")         \x1b[48;5;236m\x1b[38;5;215mx\x1b[39m\x1b[49m\x1b[0m\n
//! ansi("- a\n- b")    "  \x1b[36m• \x1b[0ma\n  \x1b[36m• \x1b[0mb\n"
//! ansi("1. a")        "   \x1b[36m1. \x1b[0ma\n"
//! ansi("> q")         \x1b[38;5;242m│ \x1b[39mq\x1b[0m\n
//! ansi("---")         \x1b[2m────…────\x1b[0m\n      (60 rule characters)
//! ansi("")            ""
//! ```
//!
//! `colors: false` in the second argument drops every escape and keeps the
//! layout, so `ansi("# Hi\n**b**", {colors: false})` is `"Hi\n===\n\nb\n"`. Every
//! other option is measured to change nothing: `width`, `columns` and `strip`
//! all leave the output identical.
//!
//! The rule character for a heading is the box-drawing heavy horizontal `═` for
//! level 1 and light `─` for level 2, and the `---` rule is 60 light horizontals —
//! measured, not a terminal-width guess, because the output must be byte-stable
//! under a pipe where no terminal width exists.

use comrak::nodes::{ListType, NodeValue};
use comrak::Node;

/// Renders a document.
pub fn render(text: &str, colors: bool) -> String {
    let arena = comrak::Arena::new();
    let root = super::parse(&arena, text);
    let mut cursor = Cursor {
        colors,
        out: String::new(),
        after_block: false,
    };
    for child in root.children() {
        cursor.block(child, 0);
    }
    cursor.out
}

/// A writer carrying the small amount of state the layout needs.
struct Cursor {
    colors: bool,
    out: String,
    /// Whether the previous block ended a line that already has its newline.
    after_block: bool,
}

impl Cursor {
    /// The rule character for a heading level, which is ASCII when colours are
    /// off.
    ///
    /// `colors: false` is not "the same layout without escapes": Bun also swaps
    /// the box-drawing characters for ASCII (`"==="` for `"═══"`, `"*"` for
    /// `"•"`, `"|"` for `"│"`). Every glyph below was measured in both modes.
    fn heading_rule(&self, level: u32) -> char {
        match (self.colors, level) {
            (true, 1) => '═',
            (true, _) => '─',
            (false, 1) => '=',
            (false, _) => '-',
        }
    }

    fn bullet(&self) -> &'static str {
        if self.colors {
            "• "
        } else {
            "* "
        }
    }

    fn quote_bar(&self) -> &'static str {
        if self.colors {
            "│ "
        } else {
            "| "
        }
    }

    fn hr_char(&self) -> char {
        if self.colors {
            '─'
        } else {
            '-'
        }
    }

    fn checked_box(&self, checked: bool) -> &'static str {
        match (self.colors, checked) {
            (true, true) => "☒ ",
            (true, false) => "☐ ",
            (false, true) => "[x] ",
            (false, false) => "[ ] ",
        }
    }

    fn image_prefix(&self) -> &'static str {
        if self.colors {
            "📷 "
        } else {
            "[img] "
        }
    }
}

impl Cursor {
    fn paint(&mut self, escape: &str) {
        if self.colors {
            self.out.push_str(escape);
        }
    }

    /// Starts a block: a blank line separates two blocks.
    fn start_block(&mut self) {
        if self.after_block {
            self.out.push('\n');
        }
        self.after_block = true;
    }

    fn block(&mut self, node: Node<'_>, depth: usize) {
        match &node.data.borrow().value {
            NodeValue::Paragraph => {
                self.start_block();
                self.inline_children(node);
                self.paint("\x1b[0m");
                self.out.push('\n');
            }
            NodeValue::Heading(heading) => {
                self.start_block();
                let level = heading.level;
                // The colours and rules, measured: level 1 is bold magenta with a
                // heavy `═` rule, level 2 is bold cyan with a light `─` rule, and
                // level 3 and below are bold yellow with **no rule at all**.
                self.paint("\x1b[1m");
                match level {
                    1 => {
                        self.paint("\x1b[35m");
                        self.inline_children(node);
                        self.paint("\x1b[0m");
                        self.out.push('\n');
                        // The rule is the heading's visible width, with a minimum
                        // of three: `"# a"` still gets `"═══"`.
                        let width = visible_last_line(&self.out);
                        self.paint("\x1b[2m");
                        for _ in 0..width.max(3) {
                            self.out.push(self.heading_rule(1));
                        }
                        self.paint("\x1b[0m");
                        self.out.push('\n');
                    }
                    2 => {
                        self.paint("\x1b[36m");
                        self.inline_children(node);
                        self.paint("\x1b[0m");
                        self.out.push('\n');
                        let width = visible_last_line(&self.out);
                        self.paint("\x1b[2m");
                        for _ in 0..width.max(3) {
                            self.out.push(self.heading_rule(2));
                        }
                        self.paint("\x1b[0m");
                        self.out.push('\n');
                    }
                    _ => {
                        self.paint("\x1b[33m");
                        self.inline_children(node);
                        self.paint("\x1b[0m");
                        self.out.push('\n');
                    }
                }
            }
            NodeValue::List(list) => {
                self.start_block();
                let ordered = matches!(list.list_type, ListType::Ordered);
                for (index, item) in (list.start..).zip(node.children()) {
                    self.list_item(item, depth, ordered, index);
                }
            }
            NodeValue::CodeBlock(code) => {
                self.start_block();
                let language = code
                    .info
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                self.paint("\x1b[2m");
                self.out.push_str(if self.colors { "┌─ " } else { "+- " });
                self.paint("\x1b[0m");
                if !language.is_empty() {
                    self.paint("\x1b[2m");
                    self.paint("\x1b[3m");
                    self.out.push_str(&language);
                    self.paint("\x1b[0m");
                } else {
                    // Without a language the header is still drawn, and the
                    // measured output keeps the trailing space.
                }
                self.out.push('\n');
                for line in code.literal.lines() {
                    self.paint("\x1b[2m");
                    self.out.push_str(self.quote_bar());
                    self.paint("\x1b[0m");
                    self.out.push_str(line);
                    self.out.push('\n');
                }
                self.paint("\x1b[2m");
                self.out.push_str(if self.colors { "└─" } else { "+-" });
                self.paint("\x1b[0m");
                self.out.push('\n');
            }
            NodeValue::BlockQuote => {
                self.start_block();
                let mut inner = String::new();
                for child in node.children() {
                    let mut nested = Cursor {
                        colors: false,
                        out: String::new(),
                        after_block: false,
                    };
                    nested.block(child, depth + 1);
                    inner.push_str(&nested.out);
                }
                self.paint("\x1b[38;5;242m");
                let mut first = true;
                for line in inner.trim_end_matches('\n').split('\n') {
                    if !first {
                        self.out.push('\n');
                        self.paint("\x1b[38;5;242m");
                    }
                    first = false;
                    self.out.push_str(self.quote_bar());
                    self.paint("\x1b[39m");
                    self.out.push_str(line);
                }
                self.paint("\x1b[0m");
                self.out.push('\n');
            }
            NodeValue::ThematicBreak => {
                self.start_block();
                self.paint("\x1b[2m");
                let rule = self.hr_char();
                for _ in 0..60 {
                    self.out.push(rule);
                }
                self.paint("\x1b[0m");
                self.out.push('\n');
            }
            NodeValue::Table(_) => {
                self.start_block();
                self.table(node);
            }
            NodeValue::HtmlBlock(html) => {
                self.start_block();
                self.paint("\x1b[2m");
                self.out.push_str(&html.literal);
                self.paint("\x1b[22m");
                self.paint("\x1b[2m");
                self.out.push('\n');
                self.paint("\x1b[22m");
                self.after_block = false;
            }
            _ => {
                for child in node.children() {
                    self.block(child, depth);
                }
            }
        }
    }

    fn list_item(&mut self, item: Node<'_>, depth: usize, ordered: bool, index: usize) {
        let marker = if ordered {
            format!("{index}. ")
        } else {
            self.bullet().to_string()
        };
        // The measured indent is two spaces per depth for a bullet plus the
        // marker's own padding, and three for an ordered marker.
        // The indentation is the enclosing item's own marker column plus the
        // marker's width, measured: `- a` starts its bullet at column 2, a bullet
        // one level in starts at 6, and an ordered marker always starts at 3
        // whatever its digits are (`1.`, `10.` and `100.` all do).
        let indent = if ordered {
            " ".repeat(depth * 6 + 3)
        } else {
            " ".repeat(depth * 4 + 2)
        };
        let is_task = matches!(item.data.borrow().value, NodeValue::TaskItem(_));
        // A task item takes the checkbox **instead of** the bullet when colours
        // are off (`"  [x] d"`), and beside it when they are on
        // (`"  \x1b[36m• \x1b[0m\x1b[32m☒ \x1b[0md"`).
        if !is_task || self.colors {
            self.out.push_str(&indent);
            self.paint("\x1b[36m");
            self.out.push_str(&marker);
            self.paint("\x1b[0m");
        } else {
            self.out.push_str(&indent);
        }
        if is_task {
            let checked = match &item.data.borrow().value {
                NodeValue::TaskItem(task) => task.symbol.is_some(),
                _ => false,
            };
            self.paint("\x1b[32m");
            self.out.push_str(self.checked_box(checked));
            self.paint("\x1b[0m");
        }
        let mut first = true;
        for child in item.children() {
            match &child.data.borrow().value {
                NodeValue::Paragraph => {
                    if !first {
                        self.out.push('\n');
                    }
                    first = false;
                    self.inline_children(child);
                }
                NodeValue::List(_) => {
                    self.out.push('\n');
                    if let NodeValue::List(list) = &child.data.borrow().value {
                        let ordered = matches!(list.list_type, ListType::Ordered);
                        for (index, nested) in (list.start..).zip(child.children()) {
                            self.list_item(nested, depth + 1, ordered, index);
                        }
                        // The nested list's last item already ended its line, so
                        // the enclosing item's own newline is suppressed.
                        self.out.pop();
                    }
                }
                _ => {
                    if !first {
                        self.out.push('\n');
                    }
                    first = false;
                    self.block(child, depth + 1);
                }
            }
        }
        self.out.push('\n');
    }

    fn table(&mut self, node: Node<'_>) {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut widths: Vec<usize> = Vec::new();
        for row in node.children() {
            let mut cells = Vec::new();
            for (index, cell) in row.children().enumerate() {
                let mut nested = Cursor {
                    colors: false,
                    out: String::new(),
                    after_block: false,
                };
                nested.inline_children(cell);
                let text = nested.out;
                let width = text.chars().count();
                if widths.len() <= index {
                    widths.push(width);
                } else if widths[index] < width {
                    widths[index] = width;
                }
                cells.push(text);
            }
            rows.push(cells);
        }
        // Every cell is padded to the widest in its column plus two, and the
        // header row is bold.
        let colors = self.colors;
        let glyph = |colored: &'static str, plain: &'static str| {
            if colors {
                colored
            } else {
                plain
            }
        };
        let border = |out: &mut String, left: &str, mid: &str, right: &str| {
            out.push_str(left);
            for (index, width) in widths.iter().enumerate() {
                if index > 0 {
                    out.push_str(mid);
                }
                let rule = if colors { '─' } else { '-' };
                // Measured: `| a | b |` in ASCII is `+-----+-----+`, five dashes
                // for a one-character cell — the cell plus two either side plus
                // the two spaces the coloured form already had.
                let pad = if colors { width + 2 } else { width + 4 };
                for _ in 0..pad {
                    out.push(rule);
                }
            }
            out.push_str(right);
        };
        self.paint("\x1b[2m");
        border(
            &mut self.out,
            glyph("┌", "+"),
            glyph("┬", "+"),
            glyph("┐", "+"),
        );
        self.paint("\x1b[0m");
        self.out.push('\n');
        for (row_index, cells) in rows.iter().enumerate() {
            if row_index == 1 {
                self.paint("\x1b[2m");
                border(
                    &mut self.out,
                    glyph("├", "+"),
                    glyph("┼", "+"),
                    glyph("┤", "+"),
                );
                self.paint("\x1b[0m");
                self.out.push('\n');
            }
            self.paint("\x1b[2m");
            self.out.push(if colors { '│' } else { '|' });
            self.paint("\x1b[0m");
            for (index, cell) in cells.iter().enumerate() {
                self.out.push(' ');
                if row_index == 0 {
                    self.paint("\x1b[1m");
                }
                self.out.push_str(cell);
                if row_index == 0 {
                    self.paint("\x1b[0m");
                }
                let width = widths.get(index).copied().unwrap_or(0);
                let pad = if colors {
                    width - cell.chars().count() + 1
                } else {
                    width - cell.chars().count() + 3
                };
                for _ in 0..pad {
                    self.out.push(' ');
                }
                self.paint("\x1b[2m");
                self.out.push(if colors { '│' } else { '|' });
                self.paint("\x1b[0m");
            }
            self.out.push('\n');
        }
        self.paint("\x1b[2m");
        border(
            &mut self.out,
            glyph("└", "+"),
            glyph("┴", "+"),
            glyph("┘", "+"),
        );
        self.paint("\x1b[0m");
        self.out.push('\n');
    }

    fn inline_children(&mut self, node: Node<'_>) {
        for child in node.children() {
            self.inline(child);
        }
    }

    fn inline(&mut self, node: Node<'_>) {
        match &node.data.borrow().value {
            NodeValue::Text(text) => self.out.push_str(text),
            NodeValue::SoftBreak => self.out.push('\n'),
            NodeValue::LineBreak => self.out.push('\n'),
            NodeValue::Emph => {
                self.paint("\x1b[3m");
                self.inline_children(node);
                self.paint("\x1b[23m");
            }
            NodeValue::Strong => {
                self.paint("\x1b[1m");
                self.inline_children(node);
                self.paint("\x1b[22m");
            }
            NodeValue::Strikethrough => {
                self.paint("\x1b[9m");
                self.inline_children(node);
                self.paint("\x1b[29m");
            }
            NodeValue::Code(code) => {
                self.paint("\x1b[48;5;236m");
                self.paint("\x1b[38;5;215m");
                self.out.push_str(&code.literal);
                self.paint("\x1b[39m");
                self.paint("\x1b[49m");
            }
            NodeValue::Link(link) => {
                self.paint("\x1b[34m");
                self.paint("\x1b[4m");
                self.inline_children(node);
                self.paint("\x1b[24m");
                self.paint("\x1b[39m");
                self.paint("\x1b[2m");
                self.out.push_str(" (");
                self.out.push_str(&link.url);
                self.paint("\x1b[2m");
                self.out.push(')');
                self.paint("\x1b[39m");
                self.paint("\x1b[22m");
            }
            NodeValue::Image(link) => {
                self.paint("\x1b[35m");
                self.out.push_str(self.image_prefix());
                let mut alt = String::new();
                for child in node.children() {
                    plain(child, &mut alt);
                }
                self.out.push_str(&alt);
                self.paint("\x1b[0m");
                let _ = link;
            }
            NodeValue::HtmlInline(html) => self.out.push_str(html),
            _ => self.inline_children(node),
        }
    }
}

fn plain(node: Node<'_>, out: &mut String) {
    match &node.data.borrow().value {
        NodeValue::Text(text) => out.push_str(text),
        NodeValue::Code(code) => out.push_str(&code.literal),
        _ => {
            for child in node.children() {
                plain(child, out);
            }
        }
    }
}

/// The visible width of the last line of `text`, ignoring escapes.
fn visible_last_line(text: &str) -> usize {
    let from = text.rfind('\n').map_or(0, |at| at + 1);
    visible_width(text, from)
}

/// The visible width of the line that starts at `from`, ignoring escapes.
fn visible_width(text: &str, from: usize) -> usize {
    let mut width = 0;
    let mut chars = text[from..].chars();
    while let Some(character) = chars.next() {
        if character == '\x1b' {
            // Skip to the end of the escape.
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        width += 1;
    }
    width
}
