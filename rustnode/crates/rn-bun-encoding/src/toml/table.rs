//! The TOML 1.0 grammar, producing a [`Value`] mapping.
//!
//! The scanner half: bytes in, tokens out. Table semantics are in the parent
//! module's documentation; this file is the grammar plus the diagnostics Bun
//! produces, one message per measured failure.

use crate::toml::TableKind;
use crate::value::{Map, Shared, Value};

use super::Kinds;

/// What a name in a table refers to.
#[derive(Clone)]
pub(super) enum Slot {
    /// A plain value: a scalar, an array of scalars, a datetime.
    Value,
    /// A nested table.
    Table(Shared<Map>),
    /// The last element of an array of tables.
    ArrayOfTables(Shared<Map>),
}

/// Parses a document into a mapping.
pub fn document(input: &str) -> Result<Value, String> {
    let root = Shared::new(Map::new());
    let mut parser = Parser {
        bytes: input.as_bytes(),
        at: 0,
        root: root.clone(),
        kinds: Kinds::new(),
        current: Vec::new(),
        context: "a key/value pair",
    };
    // A byte-order mark is allowed only at the very start.
    if parser.bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        parser.at = 3;
    }
    parser.run()?;
    let map = root.borrow().clone();
    Ok(Value::map(map))
}

pub(super) struct Parser<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) at: usize,
    root: Shared<Map>,
    pub(super) kinds: Kinds,
    /// The path of the table new key/value pairs land in.
    pub(super) current: Vec<String>,
    /// What the previous construction was, for the tail of Bun's message text.
    pub(super) context: &'static str,
}

impl<'a> Parser<'a> {
    fn run(&mut self) -> Result<(), String> {
        loop {
            self.skip_trivia();
            if self.at >= self.bytes.len() {
                return Ok(());
            }
            if self.peek() == Some(b'[') {
                self.header()?;
            } else {
                self.key_value()?;
            }
        }
    }

    // -- byte helpers -------------------------------------------------------

    pub(super) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    pub(super) fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.at + offset).copied()
    }

    pub(super) fn found(&self) -> String {
        match self.peek() {
            None => "end of file".to_string(),
            Some(byte) => format!("'{}'", display(byte)),
        }
    }

    pub(super) fn skip_trivia(&mut self) {
        loop {
            self.skip_spaces();
            match self.peek() {
                Some(b'\n') => self.at += 1,
                Some(b'\r') if self.peek_at(1) == Some(b'\n') => self.at += 2,
                _ => return,
            }
        }
    }

    pub(super) fn skip_spaces(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') => self.at += 1,
                Some(b'#') => {
                    while self.peek().is_some_and(|byte| byte != b'\n') {
                        self.at += 1;
                    }
                }
                _ => return,
            }
        }
    }

    /// Consumes the rest of a line, which must be empty apart from a comment.
    pub(super) fn end_of_line(&mut self) -> Result<(), String> {
        self.skip_spaces();
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.at += 1;
                Ok(())
            }
            Some(b'\r') if self.peek_at(1) == Some(b'\n') => {
                self.at += 2;
                Ok(())
            }
            // A bare carriage return is refused rather than treated as a line
            // ending, which is what Bun does.
            Some(b'\r') => {
                Err("Bare carriage return is not allowed; use \\r\\n or \\n".to_string())
            }
            Some(_) => Err(format!(
                "Expected a newline or end of file after {}",
                self.context
            )),
        }
    }

    // -- kinds --------------------------------------------------------------

    pub(super) fn kind_of(&self, map: &Shared<Map>) -> TableKind {
        *self
            .kinds
            .get(&map.identity())
            .unwrap_or(&TableKind::Implicit)
    }

    pub(super) fn set_kind(&mut self, map: &Shared<Map>, kind: TableKind) {
        self.kinds.insert(map.identity(), kind);
    }

    pub(super) fn slot(&self, map: &Shared<Map>, key: &str) -> Option<Slot> {
        match map.borrow().get(key)? {
            Value::Map(nested) => Some(Slot::Table(nested.clone())),
            Value::Array(items) => match items.borrow().last() {
                // An array of tables is appended to and addressed at its last
                // element. An array of *scalars* is a plain value, and a header
                // may not name one.
                Some(Value::Map(last)) => {
                    if self.kind_of(last) == TableKind::Header
                        || self.kind_of(last) == TableKind::Implicit
                    {
                        Some(Slot::ArrayOfTables(last.clone()))
                    } else {
                        Some(Slot::Value)
                    }
                }
                _ => Some(Slot::Value),
            },
            _ => Some(Slot::Value),
        }
    }

    // -- headers ------------------------------------------------------------

    pub(super) fn header(&mut self) -> Result<(), String> {
        let is_array = self.peek_at(1) == Some(b'[');
        self.at += if is_array { 2 } else { 1 };
        let path = self.header_path(is_array)?;
        if is_array {
            self.open_array_of_tables(&path)?;
        } else {
            self.open_table(&path)?;
        }
        self.context = "a table header";
        self.end_of_line()
    }

    /// The dotted name of a table header, up to and including its closer.
    pub(super) fn header_path(&mut self, is_array: bool) -> Result<Vec<String>, String> {
        let mut path = Vec::new();
        loop {
            self.skip_spaces();
            path.push(self.key_segment()?);
            self.skip_spaces();
            match self.peek() {
                Some(b'.') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    if is_array {
                        if self.peek() == Some(b']') {
                            self.at += 1;
                        } else {
                            return Err(format!(
                                "Expected ']]' to close an array-of-tables header but found {}",
                                self.found()
                            ));
                        }
                    }
                    return Ok(path);
                }
                _ => {
                    return Err(if is_array {
                        format!(
                            "Expected ']]' to close an array-of-tables header but found {}",
                            self.found()
                        )
                    } else {
                        format!(
                            "Expected ']' to close a table header but found {}",
                            self.found()
                        )
                    });
                }
            }
        }
    }

    /// Walks the parent segments of a header, creating implicit tables.
    pub(super) fn walk_headers(&mut self, parents: &[String]) -> Result<Shared<Map>, String> {
        let mut table = self.root.clone();
        for segment in parents {
            match self.slot(&table, segment) {
                None => {
                    let child = Shared::new(Map::new());
                    table
                        .borrow_mut()
                        .push(segment.clone(), Value::Map(child.clone()));
                    self.set_kind(&child, TableKind::Implicit);
                    table = child;
                }
                Some(Slot::Table(nested)) => {
                    if self.kind_of(&nested) == TableKind::Inline {
                        return Err(format!("Cannot extend inline table '{segment}'"));
                    }
                    table = nested;
                }
                Some(Slot::ArrayOfTables(last)) => table = last,
                Some(Slot::Value) => {
                    return Err(format!("Cannot redefine key '{segment}' as a table"));
                }
            }
        }
        Ok(table)
    }

    pub(super) fn open_table(&mut self, path: &[String]) -> Result<(), String> {
        let (last, parents) = path.split_last().expect("a header path is never empty");
        let parent = self.walk_headers(parents)?;
        match self.slot(&parent, last) {
            None => {
                let child = Shared::new(Map::new());
                parent
                    .borrow_mut()
                    .push(last.clone(), Value::Map(child.clone()));
                self.set_kind(&child, TableKind::Header);
            }
            Some(Slot::Table(nested)) => match self.kind_of(&nested) {
                TableKind::Inline => return Err(format!("Cannot redefine inline table '{last}'")),
                TableKind::Header => return Err(format!("Cannot redefine table '{last}'")),
                // A header may name a table that only existed as a parent, or
                // that a dotted key created: `[x.y]` then `[x]` is legal.
                TableKind::Implicit | TableKind::Dotted => {
                    self.set_kind(&nested, TableKind::Header);
                }
            },
            Some(Slot::ArrayOfTables(_)) => {
                return Err(format!(
                    "Cannot redefine array of tables '{last}' as a table"
                ));
            }
            Some(Slot::Value) => {
                return Err(format!("Cannot redefine key '{last}' as a table"));
            }
        }
        self.current = path.to_vec();
        Ok(())
    }

    pub(super) fn open_array_of_tables(&mut self, path: &[String]) -> Result<(), String> {
        let (last, parents) = path.split_last().expect("a header path is never empty");
        let parent = self.walk_headers(parents)?;
        match self.slot(&parent, last) {
            None => {
                let element = Shared::new(Map::new());
                parent.borrow_mut().push(
                    last.clone(),
                    Value::array(vec![Value::Map(element.clone())]),
                );
                self.set_kind(&element, TableKind::Header);
            }
            Some(Slot::ArrayOfTables(last_element)) => {
                // Append to the array the element lives in. The array is the
                // parent's value under `last`, so it is reachable from there.
                let element = Shared::new(Map::new());
                let appended = {
                    let mut map = parent.borrow_mut();
                    match map.get_mut(last) {
                        Some(Value::Array(items)) => {
                            items.borrow_mut().push(Value::Map(element.clone()));
                            true
                        }
                        _ => false,
                    }
                };
                if !appended {
                    return Err(format!(
                        "Cannot redefine table '{last}' as an array of tables"
                    ));
                }
                let _ = last_element;
                self.set_kind(&element, TableKind::Header);
            }
            Some(Slot::Table(nested)) => {
                let kind = self.kind_of(&nested);
                return Err(if kind == TableKind::Inline {
                    format!("Cannot redefine key '{last}' as an array of tables")
                } else {
                    format!("Cannot redefine table '{last}' as an array of tables")
                });
            }
            Some(Slot::Value) => {
                return Err(format!(
                    "Cannot redefine key '{last}' as an array of tables"
                ));
            }
        }
        self.current = path.to_vec();
        Ok(())
    }

    // -- key/value pairs ----------------------------------------------------

    pub(super) fn key_value(&mut self) -> Result<(), String> {
        let mut segments = Vec::new();
        loop {
            self.skip_spaces();
            segments.push(self.key_segment()?);
            self.skip_spaces();
            if self.peek() == Some(b'.') {
                self.at += 1;
                continue;
            }
            break;
        }
        if self.peek() != Some(b'=') {
            return Err(format!(
                "Expected '=' after a key but found {}",
                self.found()
            ));
        }
        self.at += 1;
        self.skip_spaces();
        match self.peek() {
            None => return Err("Missing value after '='".to_string()),
            Some(b'\n') | Some(b'\r') => {
                return Err("Missing value after '='; values must be on the same line".to_string());
            }
            _ => {}
        }
        let value = self.value()?;
        self.context = "a key/value pair";
        self.end_of_line()?;
        self.insert_dotted(&segments, value)
    }

    /// Inserts `value` at `segments` under the current table.
    pub(super) fn insert_dotted(
        &mut self,
        segments: &[String],
        value: Value,
    ) -> Result<(), String> {
        let mut table = self.current_table();
        let (last, prefix) = segments
            .split_last()
            .expect("a key always has at least one segment");
        for segment in prefix {
            match self.slot(&table, segment) {
                None => {
                    let child = Shared::new(Map::new());
                    table
                        .borrow_mut()
                        .push(segment.clone(), Value::Map(child.clone()));
                    self.set_kind(&child, TableKind::Dotted);
                    table = child;
                }
                Some(Slot::Table(nested)) => match self.kind_of(&nested) {
                    // `a = {b=1}` then `a.c = 2` is "cannot extend", because an
                    // inline table is closed. The same goes for a table a header
                    // opened or that a dotted key already created.
                    TableKind::Inline => {
                        return Err(format!("Cannot extend inline table '{segment}'"));
                    }
                    TableKind::Header | TableKind::Implicit | TableKind::Dotted => {
                        return Err(format!("Cannot extend table '{segment}' with a dotted key"));
                    }
                },
                Some(Slot::ArrayOfTables(_)) => {
                    return Err(format!("Cannot extend array '{segment}'"));
                }
                Some(Slot::Value) => {
                    return Err(format!("Cannot redefine key '{segment}'"));
                }
            }
        }
        match self.slot(&table, last) {
            None => {
                table.borrow_mut().push(last.clone(), value);
                Ok(())
            }
            Some(Slot::Table(nested)) => {
                let kind = self.kind_of(&nested);
                Err(if kind == TableKind::Inline {
                    format!("Cannot redefine inline table '{last}'")
                } else {
                    format!("Cannot redefine key '{last}'")
                })
            }
            Some(_) => Err(format!("Cannot redefine key '{last}'")),
        }
    }

    /// The table the current header opened.
    pub(super) fn current_table(&mut self) -> Shared<Map> {
        let mut table = self.root.clone();
        let path = self.current.clone();
        for segment in &path {
            match self.slot(&table, segment) {
                Some(Slot::Table(nested)) => table = nested,
                Some(Slot::ArrayOfTables(last)) => table = last,
                // The path was created by a header, so it resolves; if it does
                // not, the document is already in an unreachable state.
                _ => return table,
            }
        }
        table
    }

    // -- keys ---------------------------------------------------------------

    pub(super) fn key_segment(&mut self) -> Result<String, String> {
        match self.peek() {
            Some(b'"') => {
                self.at += 1;
                self.basic_string_body()
            }
            Some(b'\'') => {
                self.at += 1;
                self.literal_string_body()
            }
            Some(byte) if is_bare_key(byte) => {
                let start = self.at;
                while self.peek().is_some_and(is_bare_key) {
                    self.at += 1;
                }
                Ok(String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned())
            }
            _ => Err(format!("Expected a key but found {}", self.found())),
        }
    }

    /// Marks a table as an inline one, closing it to extension.
    pub(super) fn mark_inline(&mut self, map: &Shared<Map>) {
        self.set_kind(map, TableKind::Inline);
    }

    /// Skips spaces, comments and line endings, which is what an array's and an
    /// inline table's interior allows.
    pub(super) fn skip_whitespace_and_newlines(&mut self) {
        self.skip_trivia();
    }
}

fn is_bare_key(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

pub(super) fn display(byte: u8) -> String {
    if byte.is_ascii_graphic() || byte == b' ' {
        (byte as char).to_string()
    } else {
        format!("(0x{byte:02X})")
    }
}
