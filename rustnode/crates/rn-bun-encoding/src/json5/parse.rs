//! The JSON5 scanner.
//!
//! A single-pass recursive-descent parser over bytes. The diagnostics are Bun's
//! measured set:
//!
//! ```text
//! ""                 Unexpected end of input
//! " "                Unexpected end of input
//! "{"                Unexpected end of input
//! "[1,"              Unexpected end of input
//! "{a:}"             Unexpected token
//! "tru"              Unexpected token
//! "{a-b:1}"          Unexpected character
//! "{a:1,,}"          Invalid identifier start character
//! "{a:1} extra"      Unexpected token after JSON5 value
//! "{a.b:1}"          Invalid number
//! "01"               Leading zeros are not allowed in JSON5
//! "{a:1 /* }"        Unterminated multi-line comment
//! ```
//!
//! Note the distinction between "end of input" and "end of file": JSON5 says
//! `Unexpected end of input` while JSONC says `Unexpected end of file` for the
//! same condition. The two members do not share a scanner because of that.

use crate::value::{Map, Value};

/// What [`Parser::escape`] returns for a line continuation: nothing is emitted,
/// so a caller must drop it rather than push it into the string.
const SKIP_ESCAPE: char = '\u{10ffff}';

/// Parses one JSON5 value.
pub fn value(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        at: 0,
    };
    // A byte-order mark at the start is tolerated.
    if parser.bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        parser.at = 3;
    }
    parser.skip_trivia()?;
    let value = parser.value()?;
    parser.skip_trivia()?;
    if parser.at < parser.bytes.len() {
        return Err("Unexpected token after JSON5 value".to_string());
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.at + offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek();
        if byte.is_some() {
            self.at += 1;
        }
        byte
    }

    /// Skips whitespace, `//` comments and `/* */` comments.
    fn skip_trivia(&mut self) -> Result<(), String> {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => self.at += 1,
                // U+2028 and U+2029 are line terminators in JSON5, and JSON5
                // treats them as whitespace between tokens.
                Some(0xe2)
                    if self.peek_at(1) == Some(0x80)
                        && matches!(self.peek_at(2), Some(0xa8) | Some(0xa9)) =>
                {
                    self.at += 3;
                }
                Some(b'/') => match self.peek_at(1) {
                    Some(b'/') => {
                        self.at += 2;
                        while self.peek().is_some_and(|byte| byte != b'\n') {
                            self.at += 1;
                        }
                    }
                    Some(b'*') => {
                        self.at += 2;
                        loop {
                            match self.peek() {
                                None => return Err("Unterminated multi-line comment".to_string()),
                                Some(b'*') if self.peek_at(1) == Some(b'/') => {
                                    self.at += 2;
                                    break;
                                }
                                Some(_) => self.at += 1,
                            }
                        }
                    }
                    _ => return Ok(()),
                },
                _ => return Ok(()),
            }
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            None => Err("Unexpected end of input".to_string()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                self.at += 1;
                Ok(Value::String(self.double_quoted()?))
            }
            Some(b'\'') => {
                self.at += 1;
                Ok(Value::String(self.single_quoted()?))
            }
            Some(b't') => self.keyword("true", Value::Bool(true)),
            Some(b'f') => self.keyword("false", Value::Bool(false)),
            Some(b'n') => self.keyword("null", Value::Null),
            Some(b'I') => self.keyword("Infinity", Value::Number(f64::INFINITY)),
            Some(b'N') => self.keyword("NaN", Value::Number(f64::NAN)),
            Some(b'+') | Some(b'-') | Some(b'0'..=b'9') | Some(b'.') => self.number(),
            _ => Err("Unexpected token".to_string()),
        }
    }

    fn keyword(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            // A keyword must end at a non-identifier byte, so `truex` is not
            // `true` followed by junk.
            if self
                .peek()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err("Unexpected token".to_string());
            }
            return Ok(value);
        }
        Err("Unexpected token".to_string())
    }

    fn object(&mut self) -> Result<Value, String> {
        self.at += 1;
        let map = Map::new();
        self.skip_trivia()?;
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::map(map));
        }
        let mut map = map;
        loop {
            self.skip_trivia()?;
            let key = self.key()?;
            self.skip_trivia()?;
            if self.peek() != Some(b':') {
                return Err("Unexpected token".to_string());
            }
            self.at += 1;
            self.skip_trivia()?;
            let value = self.value()?;
            map.insert(key, value);
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_trivia()?;
                    // A trailing comma is legal, so a `}` here ends the object.
                    if self.peek() == Some(b'}') {
                        self.at += 1;
                        return Ok(Value::map(map));
                    }
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::map(map));
                }
                // A missing comma is its own message: `{a:1 b:2}`.
                None => return Err("Unexpected end of input".to_string()),
                Some(_) => return Err("Expected ','".to_string()),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.at += 1;
        let mut items = Vec::new();
        self.skip_trivia()?;
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::array(items));
        }
        loop {
            self.skip_trivia()?;
            if self.peek().is_none() {
                return Err("Unexpected end of input".to_string());
            }
            items.push(self.value()?);
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_trivia()?;
                    if self.peek() == Some(b']') {
                        self.at += 1;
                        return Ok(Value::array(items));
                    }
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::array(items));
                }
                None => return Err("Unexpected end of input".to_string()),
                Some(_) => return Err("Expected ','".to_string()),
            }
        }
    }

    /// A key: quoted, or an ECMAScript identifier.
    fn key(&mut self) -> Result<String, String> {
        match self.peek() {
            Some(b'"') => {
                self.at += 1;
                self.double_quoted()
            }
            Some(b'\'') => {
                self.at += 1;
                self.single_quoted()
            }
            Some(byte) if is_identifier_start(byte) => {
                let start = self.at;
                self.at += 1;
                while self.peek().is_some_and(is_identifier_part) {
                    self.at += 1;
                }
                // A dash is not an identifier part, so `a-b` stops at the `-`
                // and the caller reports the character it found.
                if self.peek() == Some(b'-') {
                    return Err("Unexpected character".to_string());
                }
                // A `.` after a bare key is a dot-key attempt: `{a.b:1}` is
                // `Invalid number` on Bun, because its scanner enters the number
                // path for the `.`.
                if self.peek() == Some(b'.') {
                    return Err("Invalid number".to_string());
                }
                Ok(String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned())
            }
            None => Err("Unexpected end of input".to_string()),
            // A `.` starts a number, so the scanner reports a number problem;
            // every other non-identifier byte is a character problem.
            Some(b'.') => Err("Invalid number".to_string()),
            Some(_) => Err("Invalid identifier start character".to_string()),
        }
    }

    fn double_quoted(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated string".to_string()),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escaped = self.escape()?;
                    if escaped != SKIP_ESCAPE {
                        out.push(escaped);
                    }
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

    fn single_quoted(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated string".to_string()),
                Some(b'\'') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escaped = self.escape()?;
                    if escaped != SKIP_ESCAPE {
                        out.push(escaped);
                    }
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

    /// One character of UTF-8, advancing past it.
    fn take_char(&mut self) -> char {
        let start = self.at;
        let width = match self.peek() {
            Some(byte) if byte < 0x80 => 1,
            Some(byte) if byte >= 0xf0 => 4,
            Some(byte) if byte >= 0xe0 => 3,
            Some(byte) if byte >= 0xc0 => 2,
            _ => 1,
        };
        self.at = (start + width).min(self.bytes.len());
        std::str::from_utf8(&self.bytes[start..self.at])
            .ok()
            .and_then(|text| text.chars().next())
            .unwrap_or('\u{fffd}')
    }

    /// An escape, with the backslash consumed.
    ///
    /// JSON5 adds `\v`, `\0` and `\xNN` to JSON's set, and a backslash before a
    /// line terminator continues the string.
    fn escape(&mut self) -> Result<char, String> {
        let Some(byte) = self.bump() else {
            return Err("Unexpected end of input".to_string());
        };
        Ok(match byte {
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'v' => '\u{b}',
            b'0' => '\u{0}',
            b'x' => self.hex_char(2)?,
            b'u' => self.hex_char(4)?,
            // A backslash before a line terminator is a line continuation: both
            // the backslash and the terminator disappear, which is why
            // `'{a: 'x\\\ny'}'` is `"xy"` and not `"x\ny"`.
            b'\n' => return Ok(SKIP_ESCAPE),
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.at += 1;
                }
                return Ok(SKIP_ESCAPE);
            }
            // U+2028/U+2029 as a line terminator continue the line too.
            0xe2 if self.peek_at(0) == Some(0x80)
                && matches!(self.peek_at(1), Some(0xa8) | Some(0xa9)) =>
            {
                self.at += 2;
                return Ok(SKIP_ESCAPE);
            }
            // Every other escaped character is itself, which is JSON5's
            // non-escape-character rule: `\q` is `q`.
            other => other as char,
        })
    }

    fn hex_char(&mut self, digits: usize) -> Result<char, String> {
        let mut text = String::new();
        for _ in 0..digits {
            match self.bump() {
                Some(byte) if byte.is_ascii_hexdigit() => text.push(byte as char),
                _ => return Err("Invalid unicode escape: expected 4 hex digits".to_string()),
            }
        }
        u32::from_str_radix(&text, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| "Invalid unicode escape: expected 4 hex digits".to_string())
    }

    /// A number, including `+`, `0x`, `Infinity`, `NaN` and a leading `.`.
    fn number(&mut self) -> Result<Value, String> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if matches!(self.peek(), Some(b'+') | Some(b'-')) {
            self.at += 1;
        }
        // `Infinity` and `NaN` may carry a sign.
        if self.bytes[self.at..].starts_with(b"Infinity") {
            self.at += "Infinity".len();
            return Ok(Value::Number(if negative {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }));
        }
        if self.bytes[self.at..].starts_with(b"NaN") {
            self.at += "NaN".len();
            return Ok(Value::Number(f64::NAN));
        }
        // Hexadecimal.
        if self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'x') | Some(b'X')) {
            self.at += 2;
            let digits_at = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_hexdigit()) {
                self.at += 1;
            }
            if self.at == digits_at {
                return Err("Invalid hex number".to_string());
            }
            let text = std::str::from_utf8(&self.bytes[digits_at..self.at]).unwrap_or("0");
            let value =
                u64::from_str_radix(text, 16).map_err(|_| "Invalid hex number".to_string())?;
            let value = value as f64;
            return Ok(Value::Number(if negative { -value } else { value }));
        }
        // Leading zero: `01` and `-01` are refused; `0` and `0.5` are not.
        if self.peek() == Some(b'0') && self.peek_at(1).is_some_and(|byte| byte.is_ascii_digit()) {
            return Err("Leading zeros are not allowed in JSON5".to_string());
        }
        let mut is_float = false;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if self.peek() == Some(b'.') {
            is_float = true;
            self.at += 1;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.at += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.at += 1;
            }
            let digits_at = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == digits_at {
                return Err("Invalid number".to_string());
            }
        }
        // A sign with nothing numeric after it is a character problem, not a
        // number problem: `{a:+}` is `Unexpected character`.
        if self.at == start + 1 && matches!(self.bytes[start], b'+' | b'-') {
            return Err("Unexpected character".to_string());
        }
        if self.at == start {
            return Err("Invalid number".to_string());
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).unwrap_or("0");
        let text = text.strip_prefix('+').unwrap_or(text);
        let _ = is_float;
        text.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| "Invalid number".to_string())
    }
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$' || byte >= 0x80
}

fn is_identifier_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}
