//! A strict JSON parser, used by [`crate::jsonl`].
//!
//! JSONL parses each line as JSON proper: no comments, no single quotes, no
//! trailing commas, no `NaN`. The error text never reaches a caller — JSONL
//! reports every failure as `"Failed to parse JSONL"` — so this parser only has
//! to be correct, not to explain itself. It lives here rather than using
//! `serde_json` because the output has to be a [`Value`], and going through
//! `serde_json::Value` would mean a second tree and a conversion pass for every
//! line of every stream.

use crate::value::{Map, Value};

/// Why a line could not be parsed.
#[derive(Debug, PartialEq, Eq)]
pub struct JsonError {
    /// Whether the failure is "ran out of input" rather than "definitely wrong".
    pub kind: JsonErrorKind,
    /// The offset within the input at which the parser stopped.
    ///
    /// The position is the whole point: `JSONL.parse('nope ')` throws because the
    /// space follows the bad token, and `JSONL.parse('nope')` is silent because
    /// nothing does. Both are equally invalid, so only the offset separates them.
    pub at: usize,
}

/// The two failure kinds.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum JsonErrorKind {
    /// The input ran out part-way through a value, so it may be incomplete rather
    /// than wrong.
    ///
    /// This is the distinction JSONL's whole failure behaviour rests on:
    /// `JSONL.parse('{"a":')` is `[]` because the object could still arrive, while
    /// `JSONL.parse('nope ')` throws because the space ended a token that cannot
    /// be anything.
    Incomplete,
    /// The input is definitely not JSON.
    Invalid,
}

/// Parses one JSON value from the start of `input`, ignoring anything after it.
///
/// Trailing content is deliberately ignored: `JSONL.parse('1 2')` is `[1]`, so a
/// line is a value followed by whatever, and the caller does not see the rest.
pub fn parse(input: &str) -> Result<Value, JsonError> {
    parse_at(input).map(|(value, _)| value)
}

/// [`parse`], also answering where the value ended.
///
/// JSONL needs the offset: its error rule is decided by whether **any byte
/// follows the failing token**, so a parser that only says "invalid" cannot
/// reproduce it. `'nope'` is silent and `'nope '` throws even though both are
/// equally invalid, and the difference is one byte.
pub fn parse_at(input: &str) -> Result<(Value, usize), JsonError> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        at: 0,
    };
    let value = parser.value()?;
    Ok((value, parser.at))
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek();
        if byte.is_some() {
            self.at += 1;
        }
        byte
    }

    /// The error for an unrecognised byte at the cursor.
    ///
    /// At the end of input this is still **invalid**, not incomplete: `nope` is a
    /// complete token that is not a value, and JSONL's rule turns on exactly that
    /// distinction — `JSONL.parse('nope')` is `[]` while `JSONL.parse('{"a":')` is
    /// also `[]` but for the other reason, and only the latter would become valid
    /// with more bytes.
    fn invalid(&self) -> JsonError {
        JsonError {
            kind: JsonErrorKind::Invalid,
            at: self.at,
        }
    }

    /// An invalid token at the cursor's current position, whether or not the
    /// buffer ends there.
    fn wrong(&self) -> JsonError {
        JsonError {
            kind: JsonErrorKind::Invalid,
            at: self.at,
        }
    }

    /// The error for an unrecognised **word** at the cursor, with the cursor moved
    /// past it.
    ///
    /// A bare identifier is one token, so `nope ` fails after the `nope` rather
    /// than at its first letter: the trailing space is what makes JSONL report it
    /// as an error rather than a truncation, and the offset has to say so.
    fn bad_word(&mut self) -> JsonError {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.at += 1;
        }
        JsonError {
            kind: JsonErrorKind::Invalid,
            at: self.at.max(start),
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.at += 1;
        }
    }

    fn value(&mut self) -> Result<Value, JsonError> {
        self.skip_whitespace();
        match self.peek() {
            None => Err(JsonError {
                kind: JsonErrorKind::Incomplete,
                at: self.at,
            }),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                self.at += 1;
                Ok(Value::String(self.string()?))
            }
            Some(b't') => self.keyword("true", Value::Bool(true)),
            Some(b'f') => self.keyword("false", Value::Bool(false)),
            Some(b'n') => self.keyword("null", Value::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            // A word that starts like a keyword but is not one, and any other
            // bare identifier, is one invalid token.
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => Err(self.bad_word()),
            _ => Err(self.invalid()),
        }
    }

    fn keyword(&mut self, word: &str, value: Value) -> Result<Value, JsonError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            return Ok(value);
        }
        Err(self.bad_word())
    }

    fn object(&mut self) -> Result<Value, JsonError> {
        self.at += 1;
        let mut map = Map::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::map(map));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.wrong());
            }
            self.at += 1;
            let key = self.string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.wrong());
            }
            self.at += 1;
            let value = self.value()?;
            map.insert(key, value);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(Value::map(map)),
                _ => return Err(self.wrong()),
            }
        }
    }

    fn array(&mut self) -> Result<Value, JsonError> {
        self.at += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => return Ok(Value::array(items)),
                _ => return Err(self.wrong()),
            }
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.wrong()),
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.escape()?),
                // A control character is not legal in a JSON string.
                Some(byte) if byte < 0x20 => return Err(self.wrong()),
                Some(byte) => {
                    // Reconstruct the character, since the string is UTF-8.
                    self.at -= 1;
                    let start = self.at;
                    let width = match byte {
                        byte if byte < 0x80 => 1,
                        byte if byte >= 0xf0 => 4,
                        byte if byte >= 0xe0 => 3,
                        byte if byte >= 0xc0 => 2,
                        _ => return Err(self.wrong()),
                    };
                    self.at = (start + width).min(self.bytes.len());
                    let text = std::str::from_utf8(&self.bytes[start..self.at])
                        .map_err(|_| self.wrong())?;
                    out.push_str(text);
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        Ok(match self.bump() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let mut text = String::new();
                for _ in 0..4 {
                    match self.bump() {
                        Some(byte) if byte.is_ascii_hexdigit() => text.push(byte as char),
                        _ => return Err(self.wrong()),
                    }
                }
                let code = u32::from_str_radix(&text, 16).map_err(|_| self.wrong())?;
                char::from_u32(code).unwrap_or('\u{fffd}')
            }
            _ => return Err(self.wrong()),
        })
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        // A leading zero is only legal alone.
        if self.peek() == Some(b'0') {
            self.at += 1;
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(self.wrong());
            }
        } else {
            let digits = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == digits {
                return Err(self.wrong());
            }
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            let digits = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == digits {
                return Err(self.wrong());
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.at += 1;
            }
            let digits = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == digits {
                return Err(self.wrong());
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| self.wrong())?;
        text.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| self.wrong())
    }
}
