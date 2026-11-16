//! A JSON writer that reproduces Node's `JSONWriter` byte for byte.
//!
//! `src/json_utils.h` is not a general-purpose serializer: it is a streaming
//! writer with two modes and a rule that the *caller* emits fields in the order
//! they must appear. That shape is the contract, because a report is read by
//! tooling that has always seen this layout:
//!
//! * compact mode writes no whitespace at all;
//! * pretty mode indents two spaces per level, puts `": "` after a key, and
//!   writes `[\n]` — with the newline — for an empty array and `{}` for an empty
//!   object.
//!
//! The last two are not cosmetic either. `"workers": [\n  ]` is what a real Node
//! report contains for an empty worker list, and a differ that compares byte for
//! byte sees the difference between that and `[]`.
//!
//! `EscapeJsonChars` is reproduced as it is written: `\\`, `\"`, and the control
//! characters below `0x20` as their short form where one exists and `\u00XX`
//! otherwise. Everything above that, including multi-byte UTF-8, is passed
//! through untouched — Node's writer is byte-oriented on purpose, so a `String`
//! that is not valid UTF-8 would still round-trip.

/// Escapes a string for a JSON string literal, as `EscapeJsonChars` does.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            control if (control as u32) < 0x20 => out.push_str(control_escape(control as u8)),
            other => out.push(other),
        }
    }
    out
}

/// The replacement for one control character, from `control_symbols`.
fn control_escape(value: u8) -> &'static str {
    const REPLACEMENTS: [&str; 0x20] = [
        "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
        "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r", "\\u000e", "\\u000f", "\\u0010", "\\u0011",
        "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017", "\\u0018", "\\u0019",
        "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
    ];
    REPLACEMENTS[value as usize]
}

/// Streaming JSON writer with Node's layout.
pub struct JsonWriter {
    out: String,
    compact: bool,
    indent: i32,
    /// Whether a value has been written at the current level, which is what
    /// decides whether a comma is due.
    after_value: bool,
}

impl JsonWriter {
    #[must_use]
    pub fn new(compact: bool) -> Self {
        Self {
            out: String::new(),
            compact,
            indent: 0,
            after_value: false,
        }
    }

    /// The document written so far.
    #[must_use]
    pub fn finish(self) -> String {
        self.out
    }

    fn advance(&mut self) {
        if self.compact {
            return;
        }
        for _ in 0..self.indent {
            self.out.push(' ');
        }
    }

    fn one_space(&mut self) {
        if !self.compact {
            self.out.push(' ');
        }
    }

    fn new_line(&mut self) {
        if !self.compact {
            self.out.push('\n');
        }
    }

    fn comma(&mut self) {
        if self.after_value {
            self.out.push(',');
        }
    }

    fn string(&mut self, text: &str) {
        self.out.push('"');
        self.out.push_str(&escape(text));
        self.out.push('"');
    }

    /// `json_start`: the top-level `{`.
    pub fn start(&mut self) {
        self.comma();
        self.new_line();
        self.advance();
        self.out.push('{');
        self.indent += 2;
        self.after_value = false;
    }

    /// `json_end`: the top-level `}`, which also ends the line.
    pub fn end(&mut self) {
        self.new_line();
        self.indent -= 2;
        self.advance();
        self.out.push('}');
        if self.indent == 0 {
            self.out.push('\n');
        }
        self.after_value = true;
    }

    /// `json_objectstart`.
    pub fn object_start(&mut self, key: &str) {
        self.comma();
        self.new_line();
        self.advance();
        self.string(key);
        self.out.push(':');
        self.one_space();
        self.out.push('{');
        self.indent += 2;
        self.after_value = false;
    }

    /// `json_arraystart`.
    pub fn array_start(&mut self, key: &str) {
        self.comma();
        self.new_line();
        self.advance();
        self.string(key);
        self.out.push(':');
        self.one_space();
        self.out.push('[');
        self.indent += 2;
        self.after_value = false;
    }

    /// `json_objectend`.
    pub fn object_end(&mut self) {
        self.new_line();
        self.indent -= 2;
        self.advance();
        self.out.push('}');
        self.after_value = true;
    }

    /// `json_arrayend`.
    pub fn array_end(&mut self) {
        self.new_line();
        self.indent -= 2;
        self.advance();
        self.out.push(']');
        self.after_value = true;
    }

    /// `json_keyvalue` with a string value.
    pub fn key_string(&mut self, key: &str, value: &str) {
        self.comma();
        self.new_line();
        self.advance();
        self.string(key);
        self.out.push(':');
        self.one_space();
        self.string(value);
        self.after_value = true;
    }

    /// `json_keyvalue` with an already-rendered JSON value.
    ///
    /// `Node`'s writer accepts numbers and `std::string_view`/`Null` overloads;
    /// an unquoted value is what a number, a boolean and `null` all need, so one
    /// entry point that takes the rendered text covers them.
    pub fn key_raw(&mut self, key: &str, value: &str) {
        self.comma();
        self.new_line();
        self.advance();
        self.string(key);
        self.out.push(':');
        self.one_space();
        self.out.push_str(value);
        self.after_value = true;
    }

    /// `json_keyvalue` with an integer value.
    pub fn key_int(&mut self, key: &str, value: impl std::fmt::Display) {
        self.key_raw(key, &value.to_string());
    }

    /// `json_keyvalue` with a float value, rendered as `std::ostream` would.
    pub fn key_float(&mut self, key: &str, value: f64) {
        self.key_raw(key, &number(value));
    }

    /// `json_keyvalue(key, JSONWriter::Null{})`.
    pub fn key_null(&mut self, key: &str) {
        self.key_raw(key, "null");
    }

    /// `json_element` with a string value.
    pub fn element_string(&mut self, value: &str) {
        self.comma();
        self.new_line();
        self.advance();
        self.string(value);
        self.after_value = true;
    }

    /// `json_element` with an already-rendered JSON value.
    pub fn element_raw(&mut self, value: &str) {
        self.comma();
        self.new_line();
        self.advance();
        self.out.push_str(value);
        self.after_value = true;
    }

    /// `json_element` with an integer value.
    pub fn element_int(&mut self, value: impl std::fmt::Display) {
        self.element_raw(&value.to_string());
    }

    /// `json_element` with a foreign (already-formatted) JSON document.
    ///
    /// `JSONWriter::ForeignJSON` is re-indented to the current depth, which is
    /// what a worker subreport needs: it is a whole report rendered at depth 0.
    pub fn element_foreign(&mut self, json: &str) {
        let reindented = reindent(json, self.indent);
        self.element_raw(&reindented);
    }
}

/// Renders a float for a JSON number position.
///
/// Node streams a `double` through `std::ostream`'s default formatting, which
/// keeps six significant digits. Reproducing that here would truncate the values
/// in a way that loses information without gaining comparability — every float
/// in a report is a measurement, so two runs never agree on it. Rust's shortest
/// round-tripping form is used instead, and no value changes type or sign.
#[must_use]
pub fn number(value: f64) -> String {
    format!("{value}")
}

/// `Reindent`: adds `indent_depth` spaces to the start of every line.
///
/// The first line is indented too, because the caller has already advanced to
/// the current depth before writing a foreign element.
#[must_use]
pub fn reindent(text: &str, indent_depth: i32) -> String {
    if indent_depth <= 0 {
        return text.to_string();
    }
    let indent = " ".repeat(indent_depth as usize);
    let mut out = String::with_capacity(text.len() + indent.len());
    let mut rest = text;
    loop {
        out.push_str(&indent);
        match rest.find('\n') {
            Some(position) => {
                out.push_str(&rest[..=position]);
                rest = &rest[position + 1..];
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_mode_indents_two_spaces_and_keeps_empty_containers_apart() {
        let mut writer = JsonWriter::new(false);
        writer.start();
        writer.key_string("a", "1");
        writer.array_start("empty");
        writer.array_end();
        writer.object_start("none");
        writer.object_end();
        writer.end();
        // The leading newline is Node's: `json_start` calls `write_new_line`
        // unconditionally, so a real report begins with an empty line before the
        // opening brace.
        assert_eq!(
            writer.finish(),
            "\n{\n  \"a\": \"1\",\n  \"empty\": [\n  ],\n  \"none\": {\n  }\n}\n"
        );
    }

    #[test]
    fn compact_mode_writes_no_whitespace() {
        let mut writer = JsonWriter::new(true);
        writer.start();
        writer.key_string("a", "1");
        writer.array_start("empty");
        writer.array_end();
        writer.end();
        assert_eq!(writer.finish(), "{\"a\":\"1\",\"empty\":[]}\n");
    }

    #[test]
    fn control_characters_use_node_short_forms() {
        // `EscapeJsonChars` emits `\b`, `\t`, `\n`, `\f` and `\r` where JSON has
        // a short escape and `\u00XX` for the rest.
        assert_eq!(escape("\u{8}\u{9}\u{a}\u{c}\u{d}"), "\\b\\t\\n\\f\\r");
        assert_eq!(escape("\u{0}\u{1f}"), "\\u0000\\u001f");
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(escape("héllo"), "héllo");
    }

    #[test]
    fn a_foreign_document_is_indented_to_the_current_depth() {
        assert_eq!(
            reindent("{\n  \"a\": 1\n}", 4),
            "    {\n      \"a\": 1\n    }"
        );
        assert_eq!(reindent("x", 0), "x");
    }
}
