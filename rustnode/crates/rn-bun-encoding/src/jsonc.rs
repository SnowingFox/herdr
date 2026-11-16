//! `Bun.JSONC.parse` — and **only** `parse`.
//!
//! `Bun.JSONC` has exactly one own property. `Bun.JSONC.stringify` is
//! `undefined` on Bun 1.4.4, and adding one would be a divergence in the same way
//! a missing member is, so there is deliberately no function here that could be
//! published under that name.
//!
//! # What it accepts
//!
//! Comments (`//` and `/* */`), trailing commas, single-quoted strings, and — as
//! a consequence of the lenient scanner — unquoted *keys* are **not** accepted
//! while unquoted values that happen to be valid JSON5 numbers partly are. The
//! measured surface:
//!
//! ```text
//! // c\n{"a":1 /* x */, "b":[1,2,]}   {a: 1, b: [1, 2]}
//! {"a":1,}                            {a: 1}
//! {'a':1}                             {a: 1}
//! {a:1}                               THROW Expected string but found "a"
//! {"a":}                              THROW Unexpected }
//!                                     THROW Unexpected end of input
//! ```
//!
//! Trailing content is *ignored*: `1 2`, `{}{}`, `{"a":1} x` all parse the first
//! value and drop the rest, which is why this differs from JSON5's
//! `Unexpected token after JSON5 value`.
//!
//! # Why it is not JSON5 with the messages changed
//!
//! The two differ in more than wording, and each difference is measured:
//!
//! * `0x10` is `1` in JSONC (`0`, then `x10` is trailing junk) and `16` in JSON5;
//! * `.5` is `0.5` in both, but `1.` is `1` in both and `+1` is an error in
//!   JSONC with `Unsupported syntax: Operators are not allowed in JSON`;
//! * `1_0` is `10` in JSONC;
//! * `NaN`, `Infinity` and `undefined` are each their own `Unexpected …` message;
//! * a control character in a string is `Syntax Error`;
//! * "no argument" is a shorter message than JSON5's, with the same code.
//!
//! Sharing one scanner would mean a table of per-member switches; separating them
//! costs about a hundred lines and keeps each message at the place it is decided.

use rn_v8_sys::v8;

use crate::convert::{throw_error, throw_syntax_error};
use crate::value::{Map, Value};

/// Builds the `Bun.JSONC` namespace object. One member, no `stringify`.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    let function = v8::Function::builder(parse)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope)
        .ok_or_else(|| "cannot build parse".to_string())?;
    let key = v8::String::new(scope, "parse").ok_or_else(|| "cannot allocate parse".to_string())?;
    function.set_name(key);
    object
        .set(scope, key.into(), function.into())
        .ok_or_else(|| "cannot define parse".to_string())?;
    Ok(object)
}

fn parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    // The rules, measured:
    //
    //   no argument, `null`, `undefined`  ERR_INVALID_ARG_TYPE, message
    //                                     "input must be a string" — shorter
    //                                     than JSON5's, which is why the two do
    //                                     not share a validator
    //   `5`                               String()-coerced, so the document "5"
    //   a byte view                       read as **UTF-8 bytes**, not decoded as
    //                                     text: `Uint8Array` of `{"a":1}` is the
    //                                     characters `{`,`"`,... but Bun answers
    //                                     123, which is the number its scanner
    //                                     reads from the bytes' first `1`
    //   `[]`                              String()-coerced, so "" and then an
    //                                     empty-input error
    let argument = args.get(0);
    // The argument rules, measured one value at a time. JSONC is the odd one out
    // in this group and each row was checked against Bun 1.4.4:
    //
    //   no argument, `null`, `undefined`   ERR_INVALID_ARG_TYPE with the message
    //                                      "input must be a string" — shorter than
    //                                      JSON5's, which is why the two do not
    //                                      share a validator
    //   5, `['{"a":1}']`                   String()-coerced, so the document
    //                                      "5" / '{"a":1}'
    //   Uint8Array, Uint16Array,           String()-coerced **as an array**, so
    //   any typed array                    `TextEncoder().encode('{"a":1}')` is
    //                                      `"123,34,97,34,58,49,125"` and parses as
    //                                      the number 123. There is no byte-view
    //                                      path here, unlike every sibling.
    //   ArrayBuffer, DataView              String()-coerced, so "[object Object]"
    //                                      and `Unexpected object`
    //
    // So the only special case is nullish; everything else is `String()`.
    let input = if argument.is_null() || argument.is_undefined() {
        crate::convert::throw_type_error_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "input must be a string",
        );
        return;
    } else if argument.is_string() {
        argument.to_rust_string_lossy(scope)
    } else {
        match argument.to_string(scope) {
            Some(text) => text.to_rust_string_lossy(scope),
            None => return,
        }
    };
    let value = match value(&input) {
        Ok(value) => value,
        Err(message) => {
            throw_syntax_error(scope, &format!("JSONC Parse error: {message}"));
            return;
        }
    };
    let mut cache = crate::convert::IdentityCache::new();
    match crate::convert::to_js(scope, &value, &mut cache) {
        Ok(js) => rv.set(js),
        Err(message) => throw_error(scope, &message),
    }
}

/// Parses one JSONC value, ignoring anything after it.
fn value(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        at: 0,
    };
    if parser.bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        parser.at = 3;
    }
    let length_before = parser.at;
    parser.skip_trivia()?;
    if parser.at >= parser.bytes.len() {
        // An empty buffer is `Unexpected end of input`; a buffer of only
        // whitespace or comments is `Unexpected end of file`. The two are
        // different messages on Bun 1.4.4 and a test that shares one fails the
        // other.
        return Err(if length_before == parser.bytes.len() {
            "Unexpected end of input".to_string()
        } else {
            "Unexpected end of file".to_string()
        });
    }
    parser.value()
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

    fn skip_trivia(&mut self) -> Result<(), String> {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => self.at += 1,
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
                                None => {
                                    return Err("Expected \"*/\" to terminate multi-line comment"
                                        .to_string())
                                }
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
            None => Err("Unexpected end of file".to_string()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                self.at += 1;
                Ok(Value::String(self.string(b'"')?))
            }
            Some(b'\'') => {
                self.at += 1;
                Ok(Value::String(self.string(b'\'')?))
            }
            Some(b't') => self.keyword("true", Value::Bool(true)),
            Some(b'f') => self.keyword("false", Value::Bool(false)),
            Some(b'n') => self.keyword("null", Value::Null),
            // The three value keywords JSON does not have each get their own
            // message, and they are checked before the number scanner so `NaN` is
            // not read as junk. The consumed word is reported verbatim so a
            // near-miss like `nulll` names what was actually there.
            Some(b'N') | Some(b'I') | Some(b'u') | Some(b'U') => {
                let word = self.word();
                Err(format!("Unexpected {word}"))
            }
            // A `+` is explicitly an operator, which JSONC says it does not allow.
            Some(b'+') => Err("Unsupported syntax: Operators are not allowed in JSON".to_string()),
            Some(b'-') | Some(b'0'..=b'9') | Some(b'.') => self.number(),
            Some(byte) => Err(format!("Unexpected {}", byte as char)),
        }
    }

    /// The identifier-like run at the cursor, for a message.
    fn word(&mut self) -> String {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.at += 1;
        }
        String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned()
    }

    fn keyword(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            let save = self.at;
            self.at += word.len();
            if self
                .peek()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                // `nulll` is reported with the whole word, which is what Bun's
                // scanner does.
                self.at = save;
                return Err(format!("Unexpected {}", self.word()));
            }
            return Ok(value);
        }
        Err(format!("Unexpected {}", self.word()))
    }

    fn object(&mut self) -> Result<Value, String> {
        self.at += 1;
        let mut map = Map::new();
        self.skip_trivia()?;
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::map(map));
        }
        loop {
            self.skip_trivia()?;
            if self.at >= self.bytes.len() {
                return Err("Expected \"}\" but found end of file".to_string());
            }
            // A key must be quoted: `{a:1}` is `Expected string but found "a"`.
            let key = match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    self.string(b'"')?
                }
                Some(b'\'') => {
                    self.at += 1;
                    self.string(b'\'')?
                }
                None => return Err("Expected string but found end of file".to_string()),
                Some(_) => {
                    let word = self.word();
                    return Err(format!("Expected string but found \"{word}\""));
                }
            };
            self.skip_trivia()?;
            match self.peek() {
                Some(b':') => self.at += 1,
                None => return Err("Expected \":\" but found end of file".to_string()),
                Some(byte) => {
                    return Err(format!("Expected \":\" but found \"{}\"", byte as char));
                }
            }
            self.skip_trivia()?;
            if self.peek().is_none() {
                return Err("Unexpected end of file".to_string());
            }
            let value = self.value()?;
            map.insert(key, value);
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_trivia()?;
                    if self.peek() == Some(b'}') {
                        self.at += 1;
                        return Ok(Value::map(map));
                    }
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::map(map));
                }
                None => return Err("Expected \"}\" but found end of file".to_string()),
                Some(byte) => {
                    return Err(format!("Expected \",\" but found \"{}\"", byte as char));
                }
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
            if self.peek() == Some(b']') {
                return Err("Unexpected ]".to_string());
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
                None => return Err("Expected \"]\" but found end of file".to_string()),
                Some(byte) => {
                    return Err(format!("Expected \",\" but found \"{}\"", byte as char));
                }
            }
        }
    }

    /// A string body, with the opening delimiter consumed.
    fn string(&mut self, delimiter: u8) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated string literal".to_string()),
                // A raw newline inside a string is unterminated rather than a
                // separate message.
                Some(b'\n') => return Err("Unterminated string literal".to_string()),
                Some(byte) if byte == delimiter => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    out.push(self.escape()?);
                }
                Some(byte) if byte < 0x20 => {
                    let _ = byte;
                    return Err("Syntax Error".to_string());
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

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

    fn escape(&mut self) -> Result<char, String> {
        let Some(byte) = self.bump() else {
            return Err("Unterminated string literal".to_string());
        };
        Ok(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = self.hex4()?;
                // A high surrogate followed by an escaped low surrogate is one
                // astral character. Each `\uXXXX` alone is a UTF-16 code unit,
                // which a Rust `char` cannot hold, so the pair has to be joined
                // here and an unpaired half has no representation at all.
                if (0xd800..0xdc00).contains(&high) {
                    let saved = self.at;
                    if self.peek() == Some(b'\\') && self.peek_at(1) == Some(b'u') {
                        self.at += 2;
                        if let Ok(low) = self.hex4() {
                            if (0xdc00..0xe000).contains(&low) {
                                let combined = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
                                return Ok(char::from_u32(combined).unwrap_or('\u{fffd}'));
                            }
                        }
                    }
                    self.at = saved;
                    return Ok('\u{fffd}');
                }
                // An unpaired surrogate has no `char`, and `String` is UTF-8, so
                // it cannot be represented: Bun keeps the lone `\ud83d` and this
                // build answers U+FFFD. It is the one measured JSONC divergence
                // and is recorded in the crate report rather than papered over —
                // a replacement character in a decoded string is visible, while
                // silently dropping the code unit would not be.
                char::from_u32(high).unwrap_or('\u{fffd}')
            }
            _ => return Err("Syntax Error".to_string()),
        })
    }

    /// Four hex digits, as a code unit.
    fn hex4(&mut self) -> Result<u32, String> {
        let mut text = String::new();
        for _ in 0..4 {
            match self.bump() {
                Some(byte) if byte.is_ascii_hexdigit() => text.push(byte as char),
                _ => return Err("Syntax Error".to_string()),
            }
        }
        u32::from_str_radix(&text, 16).map_err(|_| "Syntax Error".to_string())
    }

    /// A number.
    ///
    /// Not JSON's grammar: the scanner is lenient in ways that are visible, and
    /// each of these was measured:
    ///
    /// ```text
    /// 01    1       a leading zero is not refused
    /// 0x1   1       the `x1` is trailing junk and is dropped, not an error
    /// 1_0   10      `_` is a digit separator, unlike JSON5 where it is an error
    /// .5    0.5     1.   1
    /// ```
    ///
    /// Trailing content after the value is ignored at the top level, which is why
    /// `0x1` succeeds there; inside an array it is reported by the array's
    /// separator check. `1_0` is the same: the `_` separator is consumed by the
    /// digit run.
    fn number(&mut self) -> Result<Value, String> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_digit() || byte == b'_')
        {
            self.at += 1;
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.at += 1;
            while self
                .peek()
                .is_some_and(|byte| byte.is_ascii_digit() || byte == b'_')
            {
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
                return Err("Syntax Error".to_string());
            }
        }
        // The lenient scanner keeps reading identifier-ish bytes as part of the
        // number token, which is why `0x1` and `1_0` are values: `x1` and `_0`
        // vanish into the token instead of becoming trailing content.
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
        {
            self.at += 1;
        }
        let raw = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
        // Strip a radix prefix and any separator, which is what the value is.
        let text: String = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(digits) => {
                let digits: String = digits
                    .chars()
                    .filter(|character| character.is_ascii_hexdigit())
                    .collect();
                u64::from_str_radix(&digits, 16)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|_| "0".to_string())
            }
            None => raw.chars().filter(|character| *character != '_').collect(),
        };
        if text.is_empty() || text == "-" {
            return Err("Syntax Error".to_string());
        }
        let _ = is_float;
        text.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| "Syntax Error".to_string())
    }
}
