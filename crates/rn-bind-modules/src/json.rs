//! Reading the fields `package.json` contributes to module resolution.
//!
//! Node parses `package.json` with simdjson's *on-demand* API and copies out
//! only the seven fields `src/node_modules.cc` consults. That has three
//! consequences this module reproduces deliberately:
//!
//! * Validation is lazy. simdjson walks the top-level object and only fully
//!   tokenises a value it is asked about, so a malformed literal in an
//!   unrelated field can survive a read that a whole-document parser would
//!   reject. Verified against Node: `{"name":"n","x":tru}` and
//!   `{"name":"n","x":{1:2}}` both load, while `{"name":"n","x":[1,}` throws.
//!   [`Parser::skip_value`] mirrors that: it balances delimiters and nothing
//!   more.
//! * `exports` and `imports` that are objects or arrays come back as *raw JSON
//!   text*, not as parsed values, so the JavaScript layer can parse them
//!   lazily and only when a specifier actually needs them. The raw span is the
//!   text from the value's first byte up to the following delimiter, which is
//!   what simdjson's `raw_json()` returns, trailing whitespace included.
//! * Field types are enforced per field, and the enforcement is not uniform:
//!   a non-string `name` or `type` is a hard `ERR_INVALID_PACKAGE_CONFIG`,
//!   while a non-string `main` is silently dropped.
//!
//! The whole buffer's UTF-8 is still validated up front, because Node's read
//! path hands simdjson a byte buffer and simdjson rejects invalid UTF-8 even in
//! fields it skips.

/// One `package.json`, reduced to what the loader reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageFields {
    /// `name`, only ever present when it was a string.
    pub name: Option<String>,
    /// `main`, dropped when it was not a string.
    pub main: Option<String>,
    /// `"none"` unless the file said `"commonjs"` or `"module"`.
    pub type_field: String,
    /// `imports` as plain text: the string itself, or raw JSON for a
    /// container. `None` when absent or of an unusable type.
    pub imports: Option<String>,
    /// `exports`, in the same encoding as [`Self::imports`].
    pub exports: Option<String>,
    /// `private`, only when it was a boolean.
    pub is_private: Option<bool>,
}

/// A `package.json` that cannot be used, with no further detail.
///
/// Every failure path in `src/node_modules.cc` raises the same
/// `ERR_INVALID_PACKAGE_CONFIG` with the same message, so the message needs no
/// classification of the underlying cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPackageJson;

/// Parses a `package.json` body.
pub fn parse(bytes: &[u8]) -> Result<PackageFields, InvalidPackageJson> {
    let text = std::str::from_utf8(bytes).map_err(|_| InvalidPackageJson)?;
    // simdjson skips a UTF-8 BOM, and Node relies on that rather than stripping
    // it, so it must be dropped here too or the first `{` looks like junk.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    Parser::new(text).document()
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            text,
            pos: 0,
        }
    }

    fn document(mut self) -> Result<PackageFields, InvalidPackageJson> {
        let mut fields = PackageFields {
            type_field: "none".to_string(),
            ..PackageFields::default()
        };
        self.skip_whitespace();
        self.expect(b'{')?;
        let mut first = true;
        loop {
            self.skip_whitespace();
            if self.eat(b'}') {
                break;
            }
            if !first {
                self.expect(b',')?;
                self.skip_whitespace();
                if self.eat(b'}') {
                    // A trailing comma before the close is not JSON, and
                    // simdjson's member iterator rejects it.
                    return Err(InvalidPackageJson);
                }
            }
            first = false;

            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value_start = self.pos;

            match key.as_str() {
                "name" => {
                    // A `name` that is present but not a string is fatal here,
                    // unlike every other optional field.
                    if self.peek() != Some(b'"') {
                        return Err(InvalidPackageJson);
                    }
                    fields.name = Some(self.string()?);
                }
                "main" => {
                    if self.peek() == Some(b'"') {
                        fields.main = Some(self.string()?);
                    } else {
                        self.skip_value()?;
                    }
                }
                "type" => {
                    if self.peek() != Some(b'"') {
                        return Err(InvalidPackageJson);
                    }
                    let value = self.string()?;
                    if value == "commonjs" || value == "module" {
                        fields.type_field = value;
                    }
                }
                "exports" => {
                    fields.exports = self.string_or_raw(value_start)?;
                }
                "imports" => {
                    fields.imports = self.string_or_raw(value_start)?;
                }
                "private" => match self.peek() {
                    Some(b't') | Some(b'f') => {
                        let end = self.scalar_token();
                        match &self.text[self.pos..end] {
                            "true" => {
                                fields.is_private = Some(true);
                                self.pos = end;
                            }
                            "false" => {
                                fields.is_private = Some(false);
                                self.pos = end;
                            }
                            // Not a boolean literal: Node tests
                            // `value.get_bool()` and ignores the failure.
                            _ => self.skip_value()?,
                        }
                    }
                    _ => self.skip_value()?,
                },
                // `scripts` is parsed by Node and then never serialised, so
                // skipping it is behaviourally identical.
                _ => self.skip_value()?,
            }
        }
        self.skip_whitespace();
        if self.pos != self.bytes.len() {
            // Trailing content after the object means the file is not a single
            // JSON value.
            return Err(InvalidPackageJson);
        }
        Ok(fields)
    }

    /// Reads an `exports`/`imports` value.
    ///
    /// A string is decoded, because the JavaScript side compares it against
    /// subpaths and re-encodes it. A container is returned as the raw source
    /// text so the caller can parse it lazily.
    fn string_or_raw(&mut self, value_start: usize) -> Result<Option<String>, InvalidPackageJson> {
        match self.peek() {
            Some(b'"') => Ok(Some(self.string()?)),
            Some(b'{') | Some(b'[') => {
                self.skip_value()?;
                // The span runs to the *delimiter*, so any whitespace between
                // the closing brace and the comma or the object's own `}` is
                // part of it. Node hands that text to `JSON.parse`, where it is
                // insignificant, but the string itself is observable.
                self.skip_whitespace();
                let end = self.pos;
                Ok(Some(self.text[value_start..end].to_string()))
            }
            // Numbers, booleans and null are not valid exports/imports shapes;
            // Node leaves the field unset rather than complaining.
            _ => {
                self.skip_value()?;
                Ok(None)
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), InvalidPackageJson> {
        if self.eat(byte) {
            Ok(())
        } else {
            Err(InvalidPackageJson)
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// End of a bare token, which runs until a delimiter or whitespace.
    fn scalar_token(&self) -> usize {
        let mut end = self.pos;
        while let Some(byte) = self.bytes.get(end) {
            if matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                break;
            }
            end += 1;
        }
        end
    }

    /// Steps over one value without interpreting it.
    ///
    /// Containers are balanced rather than fully validated, which is what
    /// simdjson does when it skips a field: `[1,}` is rejected because `}`
    /// cannot appear inside an array, while a bare `tru` is accepted because
    /// nothing forces the literal to be looked at.
    fn skip_value(&mut self) -> Result<(), InvalidPackageJson> {
        match self.peek() {
            Some(b'"') => {
                self.skip_string()?;
                Ok(())
            }
            Some(b'{') => self.skip_container(b'{', b'}'),
            Some(b'[') => self.skip_container(b'[', b']'),
            Some(_) => {
                let end = self.scalar_token();
                if end == self.pos {
                    return Err(InvalidPackageJson);
                }
                self.pos = end;
                Ok(())
            }
            None => Err(InvalidPackageJson),
        }
    }

    fn skip_container(&mut self, open: u8, close: u8) -> Result<(), InvalidPackageJson> {
        let mut stack = vec![close];
        self.pos += 1;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => self.skip_string()?,
                b'{' => {
                    stack.push(b'}');
                    self.pos += 1;
                }
                b'[' => {
                    stack.push(b']');
                    self.pos += 1;
                }
                b'}' | b']' => {
                    if stack.pop() != Some(byte) {
                        return Err(InvalidPackageJson);
                    }
                    self.pos += 1;
                    if stack.is_empty() {
                        return Ok(());
                    }
                }
                _ => self.pos += 1,
            }
        }
        let _ = open;
        // Ran out of input before the container closed.
        Err(InvalidPackageJson)
    }

    fn skip_string(&mut self) -> Result<(), InvalidPackageJson> {
        // Escape sequences are checked for shape but not for surrogate pairing:
        // an unpaired escape in a field Node never reads is invisible to it.
        self.expect(b'"')?;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(escaped) = self.peek() else {
                        return Err(InvalidPackageJson);
                    };
                    if escaped == b'u' {
                        for _ in 0..4 {
                            self.pos += 1;
                            match self.peek() {
                                Some(hex) if hex.is_ascii_hexdigit() => {}
                                _ => return Err(InvalidPackageJson),
                            }
                        }
                        self.pos += 1;
                    } else if matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        self.pos += 1;
                    } else {
                        return Err(InvalidPackageJson);
                    }
                }
                byte if byte < 0x20 => return Err(InvalidPackageJson),
                _ => {
                    self.pos += 1;
                }
            }
        }
        Err(InvalidPackageJson)
    }

    /// Reads a JSON string and decodes it.
    fn string(&mut self) -> Result<String, InvalidPackageJson> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(InvalidPackageJson);
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(escaped) = self.peek() else {
                        return Err(InvalidPackageJson);
                    };
                    match escaped {
                        b'"' => {
                            out.push('"');
                            self.pos += 1;
                        }
                        b'\\' => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        b'/' => {
                            out.push('/');
                            self.pos += 1;
                        }
                        b'b' => {
                            out.push('\u{8}');
                            self.pos += 1;
                        }
                        b'f' => {
                            out.push('\u{c}');
                            self.pos += 1;
                        }
                        b'n' => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        b'r' => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        b't' => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        b'u' => {
                            self.pos += 1;
                            let first = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&first) {
                                // A high surrogate must be followed by a low one
                                // that forms a single scalar value.
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let second = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&second) {
                                    return Err(InvalidPackageJson);
                                }
                                0x10000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00)
                            } else if (0xdc00..0xe000).contains(&first) {
                                // A lone low surrogate cannot be encoded in UTF-8.
                                return Err(InvalidPackageJson);
                            } else {
                                u32::from(first)
                            };
                            let Some(character) = char::from_u32(code) else {
                                return Err(InvalidPackageJson);
                            };
                            out.push(character);
                        }
                        _ => return Err(InvalidPackageJson),
                    }
                }
                byte if byte < 0x20 => return Err(InvalidPackageJson),
                _ => {
                    // Copy the whole UTF-8 sequence, not just one byte.
                    let start = self.pos;
                    let width = utf8_width(byte);
                    let end = start + width;
                    let Some(slice) = self.text.get(start..end) else {
                        return Err(InvalidPackageJson);
                    };
                    out.push_str(slice);
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, InvalidPackageJson> {
        let mut value = 0u16;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return Err(InvalidPackageJson);
            };
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(InvalidPackageJson),
            };
            value = (value << 4) | u16::from(digit);
            self.pos += 1;
        }
        Ok(value)
    }
}

/// Length in bytes of the UTF-8 sequence starting with `lead`.
///
/// The input has already been validated as UTF-8, so a continuation byte here
/// means the caller's position is mid-sequence; reporting 1 keeps the copy
/// aligned with what `str::get` will accept.
fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(text: &str) -> PackageFields {
        parse(text.as_bytes()).expect("valid package.json")
    }

    #[test]
    fn reads_the_fields_the_loader_uses() {
        let parsed = fields(r#"{"name":"pkg","main":"./m.js","type":"module"}"#);
        assert_eq!(parsed.name.as_deref(), Some("pkg"));
        assert_eq!(parsed.main.as_deref(), Some("./m.js"));
        assert_eq!(parsed.type_field, "module");
    }

    #[test]
    fn type_defaults_to_none_and_ignores_unknown_values() {
        assert_eq!(fields("{}").type_field, "none");
        // Node only accepts the two real values; a typo becomes "none" rather
        // than an error, matching `ParsePackageJSON`.
        assert_eq!(fields(r#"{"type":"esm"}"#).type_field, "none");
        assert_eq!(fields(r#"{"type":"commonjs"}"#).type_field, "commonjs");
    }

    #[test]
    fn non_string_name_and_type_are_fatal() {
        assert!(parse(br#"{"name":42}"#).is_err());
        assert!(parse(br#"{"name":null}"#).is_err());
        assert!(parse(br#"{"type":42}"#).is_err());
        assert!(parse(br#"{"type":null}"#).is_err());
    }

    #[test]
    fn non_string_main_is_dropped() {
        assert_eq!(fields(r#"{"main":42}"#).main, None);
        assert_eq!(fields(r#"{"main":null}"#).main, None);
    }

    #[test]
    fn exports_and_imports_keep_raw_json_for_containers() {
        let parsed = fields(r##"{"exports":{".":"./i.js"},"imports":{"#a":"./a.js"}}"##);
        assert_eq!(parsed.exports.as_deref(), Some(r#"{".":"./i.js"}"#));
        assert_eq!(parsed.imports.as_deref(), Some(r##"{"#a":"./a.js"}"##));
    }

    #[test]
    fn exports_strings_are_decoded_and_scalars_dropped() {
        let parsed = fields(r#"{"exports":"./a.js"}"#);
        assert_eq!(parsed.exports.as_deref(), Some("./a.js"));
        assert_eq!(fields(r#"{"exports":1}"#).exports, None);
    }

    #[test]
    fn raw_container_span_includes_trailing_whitespace() {
        // simdjson's `raw_json()` stops at the delimiter, so the whitespace
        // before it is part of the span. Node hands that text to `JSON.parse`,
        // where it is insignificant, but the value is observable.
        let parsed = fields("{\"exports\":{\"x\":1}   ,\"b\":2}");
        assert_eq!(parsed.exports.as_deref(), Some(r#"{"x":1}   "#));
    }

    #[test]
    fn last_duplicate_key_wins() {
        assert_eq!(
            fields(r#"{"name":"first","name":"second"}"#)
                .name
                .as_deref(),
            Some("second")
        );
    }

    #[test]
    fn bom_is_skipped() {
        assert_eq!(
            fields("\u{feff}{\"name\":\"bom\"}").name.as_deref(),
            Some("bom")
        );
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for source in [
            "",
            "   ",
            "[]",
            "null",
            "\"hi\"",
            r#"{"name":"x""#,
            "{name:\"x\"}",
            r#"{"name":"x",}"#,
            r#"{"name":"x" /*c*/}"#,
            r#"{"name":"x"} garbage"#,
            r#"{"name":"n","x":[1,}"#,
        ] {
            assert!(
                parse(source.as_bytes()).is_err(),
                "should reject {source:?}"
            );
        }
    }

    #[test]
    fn skipped_values_are_not_fully_validated() {
        // Both of these load in Node because simdjson never looks inside the
        // value of a field it does not care about.
        assert!(parse(br#"{"name":"n","x":tru}"#).is_ok());
        assert!(parse(br#"{"name":"n","x":{1:2}}"#).is_ok());
    }

    #[test]
    fn invalid_utf8_is_rejected_even_when_skipped() {
        let mut bytes = br#"{"name":"n","x":""#.to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(br#""}"#);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn escapes_are_decoded_and_lone_surrogates_rejected() {
        assert_eq!(
            fields(r#"{"name":"a\u0041\n\"b"}"#).name.as_deref(),
            Some("aA\n\"b")
        );
        assert_eq!(
            fields(r#"{"name":"\ud83d\ude00"}"#).name.as_deref(),
            Some("😀")
        );
        assert!(parse(br#"{"name":"\ud800"}"#).is_err());
        assert!(parse(br#"{"name":"\udc00"}"#).is_err());
    }

    #[test]
    fn private_is_only_kept_when_boolean() {
        assert_eq!(fields(r#"{"private":true}"#).is_private, Some(true));
        assert_eq!(fields(r#"{"private":false}"#).is_private, Some(false));
        assert_eq!(fields(r#"{"private":"yes"}"#).is_private, None);
    }

    #[test]
    fn multibyte_keys_and_values_survive() {
        assert_eq!(
            fields(r#"{"name":"päckchen"}"#).name.as_deref(),
            Some("päckchen")
        );
    }
}
