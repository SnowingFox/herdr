//! TOML value parsing: scalars, arrays, inline tables and datetimes.
//!
//! Every error message here is a measured one from Bun 1.4.4, and the
//! distinctions Bun draws that a generic TOML parser would not are kept: an
//! unquoted `tru` is `Strings must be quoted: "tru"` rather than a parse error,
//! `1979-05-27T07:32` is accepted and completed with `:00`, and `\x41` is a
//! legal escape even though TOML 1.0 does not define it.

use crate::value::{Map, Value};

use super::table::Parser;

impl<'a> Parser<'a> {
    /// One value, starting at the current byte.
    pub(super) fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            None => Err("Expected a value but found end of file".to_string()),
            Some(b'"') => self.basic_string(),
            Some(b'\'') => self.literal_string(),
            Some(b'[') => self.array(),
            Some(b'{') => self.inline_table(),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'+') | Some(b'-') | Some(b'0'..=b'9') => self.number_or_datetime(),
            Some(b'i') | Some(b'n') => self.special_float(),
            // A bare word that is not a keyword is a string in TOML 0.5 and an
            // error in 1.0, and Bun reports it with the word quoted — which is
            // also what `tru` and `truex` get, so the branch is shared.
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = self.at;
                while self.peek().is_some_and(is_bare_key) {
                    self.at += 1;
                }
                let word = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
                Err(format!("Strings must be quoted: \"{word}\""))
            }
            Some(byte) => Err(format!(
                "Expected a value but found '{}'",
                super::table::display(byte)
            )),
        }
    }

    // -- strings ------------------------------------------------------------

    pub(super) fn basic_string(&mut self) -> Result<Value, String> {
        let multiline = self.peek_at(1) == Some(b'"') && self.peek_at(2) == Some(b'"');
        if multiline {
            self.at += 3;
            // A newline immediately after the opening delimiter is trimmed.
            self.trim_leading_newline();
            let text = self.basic_multiline_body()?;
            return Ok(Value::String(text));
        }
        self.at += 1;
        let text = self.basic_string_body()?;
        Ok(Value::String(text))
    }

    pub(super) fn literal_string(&mut self) -> Result<Value, String> {
        let multiline = self.peek_at(1) == Some(b'\'') && self.peek_at(2) == Some(b'\'');
        if multiline {
            self.at += 3;
            self.trim_leading_newline();
            let text = self.literal_multiline_body()?;
            return Ok(Value::String(text));
        }
        self.at += 1;
        let text = self.literal_string_body()?;
        Ok(Value::String(text))
    }

    fn trim_leading_newline(&mut self) {
        match self.peek() {
            Some(b'\n') => self.at += 1,
            Some(b'\r') if self.peek_at(1) == Some(b'\n') => self.at += 2,
            _ => {}
        }
    }

    /// The body of a `"…"` string, with the opening quote already consumed.
    pub(super) fn basic_string_body(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated string".to_string()),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                // A basic string is single-line: a newline is an error, and Bun
                // says why.
                Some(b'\n') => {
                    return Err(
                        "Unterminated string; newlines must be escaped in basic strings"
                            .to_string(),
                    )
                }
                Some(b'\r') if self.peek_at(1) == Some(b'\n') => {
                    return Err(
                        "Unterminated string; newlines must be escaped in basic strings"
                            .to_string(),
                    )
                }
                Some(b'\\') => {
                    self.at += 1;
                    out.push(self.escape()?);
                }
                Some(byte) if byte < 0x20 || byte == 0x7f => {
                    return Err(format!(
                        "Control character must be escaped in a string: (0x{byte:02X})"
                    ));
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

    /// The body of a `"""…"""` string, with the opening delimiter consumed.
    fn basic_multiline_body(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated string".to_string()),
                Some(b'"') if self.peek_at(1) == Some(b'"') && self.peek_at(2) == Some(b'"') => {
                    self.at += 3;
                    // Up to two additional quotes belong to the content.
                    while self.peek() == Some(b'"') {
                        self.at += 1;
                        out.push('"');
                    }
                    return Ok(out);
                }
                Some(b'\\') => {
                    // A line-ending backslash trims the newline and all following
                    // whitespace, which is TOML's continuation rule.
                    let mut look = self.at + 1;
                    while self
                        .bytes
                        .get(look)
                        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
                    {
                        look += 1;
                    }
                    if self.bytes.get(look) == Some(&b'\n')
                        || (self.bytes.get(look) == Some(&b'\r')
                            && self.bytes.get(look + 1) == Some(&b'\n'))
                    {
                        self.at = look;
                        while self.peek().is_some_and(|byte| {
                            byte == b' ' || byte == b'\t' || byte == b'\n' || byte == b'\r'
                        }) {
                            self.at += 1;
                        }
                        continue;
                    }
                    self.at += 1;
                    out.push(self.escape()?);
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

    /// The body of a `'…'` string, with the opening quote consumed.
    pub(super) fn literal_string_body(&mut self) -> Result<String, String> {
        let start = self.at;
        loop {
            match self.peek() {
                None => return Err("Unterminated string".to_string()),
                Some(b'\'') => {
                    let text = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
                    self.at += 1;
                    return Ok(text);
                }
                Some(b'\n') => return Err("Unterminated string".to_string()),
                Some(_) => self.at += 1,
            }
        }
    }

    fn literal_multiline_body(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated string".to_string()),
                Some(b'\'') if self.peek_at(1) == Some(b'\'') && self.peek_at(2) == Some(b'\'') => {
                    self.at += 3;
                    while self.peek() == Some(b'\'') {
                        self.at += 1;
                        out.push('\'');
                    }
                    return Ok(out);
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

    /// One character of UTF-8, advancing past it.
    fn take_char(&mut self) -> char {
        let start = self.at;
        // The input is a `&str`, so `self.bytes` is valid UTF-8 and the first
        // byte says how long the character is.
        let width = match self.bytes.get(start) {
            Some(byte) if *byte < 0x80 => 1,
            Some(byte) if *byte >= 0xf0 => 4,
            Some(byte) if *byte >= 0xe0 => 3,
            Some(byte) if *byte >= 0xc0 => 2,
            _ => 1,
        };
        self.at = (start + width).min(self.bytes.len());
        std::str::from_utf8(&self.bytes[start..self.at])
            .ok()
            .and_then(|text| text.chars().next())
            .unwrap_or('\u{fffd}')
    }

    /// The character an escape denotes, with the backslash consumed.
    fn escape(&mut self) -> Result<char, String> {
        let Some(byte) = self.bump() else {
            return Err("Unterminated string".to_string());
        };
        Ok(match byte {
            b'b' => '\u{8}',
            b't' => '\t',
            b'n' => '\n',
            b'f' => '\u{c}',
            b'r' => '\r',
            b'e' => '\u{1b}',
            b'"' => '"',
            b'\\' => '\\',
            // TOML 1.0 does not define `\x`, but Bun accepts it.
            b'x' => self.hex_char(2)?,
            b'u' => self.hex_char(4)?,
            b'U' => self.hex_char(8)?,
            other => {
                return Err(format!(
                    "Invalid escape sequence: '{}'",
                    display_char(other)
                ))
            }
        })
    }

    fn hex_char(&mut self, digits: usize) -> Result<char, String> {
        let mut text = String::new();
        for _ in 0..digits {
            match self.bump() {
                Some(byte) if byte.is_ascii_hexdigit() => text.push(byte as char),
                _ => {
                    return Err(
                        "A Unicode escape must be followed by exactly 4 hex digits".to_string()
                    )
                }
            }
        }
        let code = u32::from_str_radix(&text, 16)
            .map_err(|_| "A Unicode escape must be followed by exactly 4 hex digits".to_string())?;
        char::from_u32(code)
            .ok_or_else(|| "A Unicode escape must be followed by exactly 4 hex digits".to_string())
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.at).copied();
        if byte.is_some() {
            self.at += 1;
        }
        byte
    }

    // -- arrays and inline tables -------------------------------------------

    fn array(&mut self) -> Result<Value, String> {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            self.skip_whitespace_and_newlines();
            match self.peek() {
                None => {
                    return Err("Expected ',' or ']' in an array but found end of file".to_string())
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::array(items));
                }
                _ => {}
            }
            items.push(self.value()?);
            self.skip_whitespace_and_newlines();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::array(items));
                }
                // End of input is reported with the same message as a wrong
                // token, naming the end rather than an invented one.
                None => {
                    return Err("Expected ',' or ']' in an array but found end of file".to_string())
                }
                Some(byte) => {
                    return Err(format!(
                        "Expected ',' or ']' in an array but found '{}'",
                        display_char(byte)
                    ))
                }
            }
        }
    }

    fn inline_table(&mut self) -> Result<Value, String> {
        self.at += 1;
        let map = crate::value::Shared::new(Map::new());
        loop {
            self.skip_whitespace_and_newlines();
            match self.peek() {
                None => {
                    return Err("Unterminated inline table; expected '}'".to_string());
                }
                Some(b'}') => {
                    self.at += 1;
                    let contents = map.borrow().clone();
                    let value = Value::map(contents);
                    // The table is now closed to extension.
                    if let Value::Map(cell) = &value {
                        self.mark_inline(cell);
                    }
                    return Ok(value);
                }
                _ => {}
            }
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
                    return Err(
                        "Missing value after '='; values must be on the same line".to_string()
                    )
                }
                _ => {}
            }
            let value = self.value()?;
            insert_inline(&map, &segments, value)?;
            self.skip_whitespace_and_newlines();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                }
                Some(b'}') => {
                    self.at += 1;
                    let contents = map.borrow().clone();
                    let value = Value::map(contents);
                    if let Value::Map(cell) = &value {
                        self.mark_inline(cell);
                    }
                    return Ok(value);
                }
                None => {
                    return Err(
                        "Expected ',' or '}' in an inline table but found end of file".to_string(),
                    )
                }
                Some(byte) => {
                    return Err(format!(
                        "Expected ',' or '}}' in an inline table but found '{}'",
                        display_char(byte)
                    ))
                }
            }
        }
    }

    // -- booleans and numbers -----------------------------------------------

    fn boolean(&mut self) -> Result<Value, String> {
        let start = self.at;
        while self.peek().is_some_and(is_bare_key) {
            self.at += 1;
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
        match text.as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(format!("Strings must be quoted: \"{text}\"")),
        }
    }

    fn special_float(&mut self) -> Result<Value, String> {
        let start = self.at;
        while self.peek().is_some_and(is_bare_key) {
            self.at += 1;
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
        match text.as_str() {
            "inf" => Ok(Value::Number(f64::INFINITY)),
            "nan" => Ok(Value::Number(f64::NAN)),
            _ => Err(format!("Strings must be quoted: \"{text}\"")),
        }
    }

    /// A number or a datetime. TOML's scanner shares a prefix between the two, so
    /// this reads the whole run and then decides.
    fn number_or_datetime(&mut self) -> Result<Value, String> {
        let start = self.at;
        // Signs belong to numbers, not to dates.
        let negative = self.peek() == Some(b'-');
        if self.peek() == Some(b'+') || self.peek() == Some(b'-') {
            self.at += 1;
        }
        // A leading zero is refused only for a plain integer, not for `0x`/`0o`/
        // `0b`, a float, or a date.
        let digits_start = self.at;
        // Underscores are digit separators in TOML, so `1_000` is one integer.
        // `check_underscores` validates their placement later; the count here is
        // of real digits, which is what the radix and leading-zero checks read.
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_digit() || byte == b'_')
        {
            self.at += 1;
        }
        let digits = self.bytes[digits_start..self.at]
            .iter()
            .filter(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return Err("Expected a number but found end of file".to_string());
        }
        let first = *self.bytes[digits_start..self.at]
            .iter()
            .find(|byte| byte.is_ascii_digit())
            .unwrap_or(&b'0');
        // Radix prefixes.
        if digits == 1 && first == b'0' {
            match self.peek() {
                Some(b'x') | Some(b'o') | Some(b'b') => {
                    if negative || self.bytes.get(digits_start - 1) == Some(&b'+') {
                        return Err(
                            "A sign is not allowed on hexadecimal, octal, or binary integers"
                                .to_string(),
                        );
                    }
                    let radix = match self.peek() {
                        Some(b'x') => 16,
                        Some(b'o') => 8,
                        _ => 2,
                    };
                    self.at += 1;
                    let digits_at = self.at;
                    while self
                        .peek()
                        .is_some_and(|byte| (byte as char).is_digit(radix) || byte == b'_')
                    {
                        self.at += 1;
                    }
                    let text: String = String::from_utf8_lossy(&self.bytes[digits_at..self.at])
                        .chars()
                        .filter(|character| *character != '_')
                        .collect();
                    if text.is_empty() {
                        return Err(
                            "Expected at least one digit after the radix prefix".to_string()
                        );
                    }
                    return u64::from_str_radix(&text, radix)
                        .map(|value| Value::Number(value as f64))
                        .map_err(|_| {
                            "Expected at least one digit after the radix prefix".to_string()
                        });
                }
                // A date must have four digits in the year; two more make it one.
                _ if digits == 2 && self.peek().is_some_and(|byte| byte.is_ascii_digit()) => {
                    return self.datetime(start);
                }
                _ => {}
            }
        }
        // A leading zero is refused for a plain integer, but `07:32:00` is a
        // local time and `0` before `x`/`o`/`b` is a radix prefix. Both were
        // handled above, so what reaches here with more digits really is `01`.
        if first == b'0'
            && digits > 1
            && !matches!(
                self.peek(),
                Some(b':') | Some(b'.') | Some(b'e') | Some(b'E')
            )
        {
            return Err("Leading zeros are not allowed in numbers".to_string());
        }
        // A date: `dddd-` after four digits.
        if digits == 4 && self.peek() == Some(b'-') {
            return self.datetime(start);
        }
        // A local time starts with two digits and a colon, and `2 <= digits <= 2`
        // is the only shape TOML allows (`07:32:00`).
        if digits == 2 && self.peek() == Some(b':') {
            return self.datetime(start);
        }
        // Fraction. Underscores are legal between digits here, which is why the
        // run accepts them and `check_underscores` validates afterwards.
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.at += 1;
            let fraction_start = self.at;
            while self
                .peek()
                .is_some_and(|byte| byte.is_ascii_digit() || byte == b'_')
            {
                self.at += 1;
            }
            if self.at == fraction_start {
                return Err("A decimal point must be followed by at least one digit".to_string());
            }
        }
        // Exponent, with the same underscore allowance.
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.at += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.at += 1;
            }
            let exponent_start = self.at;
            while self
                .peek()
                .is_some_and(|byte| byte.is_ascii_digit() || byte == b'_')
            {
                self.at += 1;
            }
            if self.at == exponent_start {
                return Err("An exponent must contain at least one digit".to_string());
            }
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
        let cleaned: String = text.chars().filter(|character| *character != '_').collect();
        // A trailing `.` followed by anything else is a value-then-character
        // problem, which Bun reports by naming the character.
        // Validate the separators before the trailing-character check, so
        // `1__0` is an underscore error rather than "unexpected character '_'".
        self.check_underscores(&text)?;
        if let Some(byte) = self.peek() {
            if !matches!(
                byte,
                b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}' | b'#'
            ) {
                return Err(format!(
                    "Unexpected character after a value: '{}'",
                    display_char(byte)
                ));
            }
        }
        if is_float {
            cleaned
                .parse::<f64>()
                .map(Value::Number)
                .map_err(|_| "Expected a number".to_string())
        } else {
            // An integer beyond 2^53 cannot round-trip through a JavaScript
            // number, and Bun refuses rather than losing precision.
            let magnitude = cleaned.trim_start_matches(['+', '-']).parse::<u64>();
            match magnitude {
                Ok(value) if value > 9007199254740991 => Err(
                    "Integer cannot be losslessly represented as a JavaScript number; it must be within +/-(2^53 - 1)"
                        .to_string(),
                ),
                Ok(value) => {
                    let signed = if cleaned.starts_with('-') {
                        -(value as f64)
                    } else {
                        value as f64
                    };
                    Ok(Value::Number(signed))
                }
                Err(_) => Err(
                    "Integer cannot be losslessly represented as a JavaScript number; it must be within +/-(2^53 - 1)"
                        .to_string(),
                ),
            }
        }
    }

    fn check_underscores(&self, text: &str) -> Result<(), String> {
        let bytes = text.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if *byte != b'_' {
                continue;
            }
            let before = index.checked_sub(1).and_then(|at| bytes.get(at));
            let after = bytes.get(index + 1);
            if !before.is_some_and(u8::is_ascii_digit) || !after.is_some_and(u8::is_ascii_digit) {
                return Err("Underscores in numbers must be surrounded by digits".to_string());
            }
        }
        Ok(())
    }

    /// A date, time or datetime, starting at `start`.
    fn datetime(&mut self, start: usize) -> Result<Value, String> {
        // Consume the whole run of date/time characters.
        while self.peek().is_some_and(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'-' | b':' | b'.' | b'+' | b'T' | b't' | b'Z' | b'z' | b' '
                )
        }) {
            // A space is part of a datetime only between a date and a time, so it
            // is included here and validated below.
            self.at += 1;
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.at])
            .trim()
            .to_string();
        crate::toml::datetime::normalize(&text)
    }
}

/// Inserts into an inline table, which may not redefine or extend anything.
fn insert_inline(
    map: &crate::value::Shared<Map>,
    segments: &[String],
    value: Value,
) -> Result<(), String> {
    let (last, prefix) = segments.split_last().expect("a key has a segment");
    let mut table = map.clone();
    for segment in prefix {
        let exists = table.borrow().contains(segment);
        if !exists {
            let child = crate::value::Shared::new(Map::new());
            table
                .borrow_mut()
                .push(segment.clone(), Value::Map(child.clone()));
            table = child;
            continue;
        }
        let next = match table.borrow().get(segment) {
            Some(Value::Map(nested)) => nested.clone(),
            _ => return Err(format!("Cannot redefine key '{segment}'")),
        };
        table = next;
    }
    if table.borrow().contains(last) {
        return Err(format!("Cannot redefine key '{last}'"));
    }
    table.borrow_mut().push(last.clone(), value);
    Ok(())
}

fn is_bare_key(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn display_char(byte: u8) -> String {
    if byte.is_ascii_graphic() || byte == b' ' {
        (byte as char).to_string()
    } else {
        format!("(0x{byte:02X})")
    }
}
