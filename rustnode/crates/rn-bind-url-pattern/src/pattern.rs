//! The WHATWG URL pattern algorithm, ported from `ada`.
//!
//! Node implements `URLPattern` over `ada::url_pattern`, which is the spec's
//! algorithm written out by the ada authors. This module is a port of the same
//! functions, keeping ada's names and step comments where the step is not
//! obvious, so a later reader can diff the two instead of re-deriving the spec.
//!
//! The pieces, in the order the constructor uses them:
//!
//! 1. [`tokenize`] — the pattern tokenizer. Two policies: `strict` for a
//!    pattern string and `lenient` for a constructor string, exactly as the
//!    spec's two call sites use it.
//! 2. [`parse_pattern_string`] — tokens to a part list (fixed text, segment
//!    wildcards, full wildcards, regexps, with prefix/suffix/modifier).
//! 3. [`Component::compile`] — part list to a component that can match a
//!    component of a URL, either by literal comparison, wildcard acceptance,
//!    or a real regexp.
//! 4. [`process_init`] — a `URLPatternInit` dictionary to the eight component
//!    pattern strings, resolving `baseURL` the way the spec's "process a
//!    URLPatternInit" step does.
//!
//! The only deliberate departure from ada is the regexp engine: ada's
//! `std::regex` path is dead weight here because Node passes a
//! `v8::RegExp`-backed provider, so [`Regex`] is a thin wrapper over V8's own
//! `RegExp` with the same `v` flag Node requests. That is not a shortcut — it
//! is the same engine Node matches with, which is what keeps `\\d`, `{x,y}`
//! alternation and Unicode sets behaving identically.

use std::fmt;

/// A tokenizer or parser failure. `ada` distinguishes only "type error" here,
/// and every caller turns it into `ERR_INVALID_URL_PATTERN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternError;

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid URL pattern")
    }
}

impl std::error::Error for PatternError {}

/// The eight components, in the order the spec and `URL_PATTERN_COMPONENTS`
/// list them.
pub const COMPONENTS: &[&str] = &[
    "protocol", "username", "password", "hostname", "port", "pathname", "search", "hash",
];

/// Which of the two tokenizer policies to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPolicy {
    Strict,
    Lenient,
}

/// `token_type` in `ada`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    InvalidChar,
    Open,
    Close,
    Regexp,
    Name,
    Char,
    EscapedChar,
    OtherModifier,
    Asterisk,
    End,
}

/// A token, with the byte span of the input it covers.
///
/// The spec carries a string value; ada instead carries `index` into the input
/// plus a borrowed value. Keeping the borrowed `value` as a `&str` slice of the
/// input is what makes this allocation-free apart from the token vector.
#[derive(Debug, Clone, Copy)]
pub struct Token<'a> {
    pub kind: TokenType,
    pub index: usize,
    pub value: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartType {
    FixedText,
    Regexp,
    SegmentWildcard,
    FullWildcard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    None,
    Optional,
    ZeroOrMore,
    OneOrMore,
}

impl Modifier {
    fn as_str(self) -> &'static str {
        match self {
            Modifier::None => "",
            Modifier::Optional => "?",
            Modifier::ZeroOrMore => "*",
            Modifier::OneOrMore => "+",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub kind: PartType,
    pub value: String,
    pub modifier: Modifier,
    pub name: String,
    pub prefix: String,
    pub suffix: String,
}

impl Part {
    fn fixed(value: String, modifier: Modifier) -> Self {
        Self {
            kind: PartType::FixedText,
            value,
            modifier,
            name: String::new(),
            prefix: String::new(),
            suffix: String::new(),
        }
    }

    fn is_regexp(&self) -> bool {
        self.kind == PartType::Regexp
    }
}

/// `url_pattern_compile_component_options`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompileOptions {
    pub ignore_case: bool,
    /// The component's delimiter code point, if it has one.
    pub delimiter: Option<char>,
    /// The component's prefix code point, if it has one.
    pub prefix: Option<char>,
}

impl CompileOptions {
    /// The options Node compiles each component with.
    ///
    /// `src/node_url_pattern.cc` does not pass options; ada's `parse_url_pattern`
    /// picks the delimiter and prefix per component from the spec's table, so
    /// this is that table.
    pub fn for_component(name: &str, ignore_case: bool) -> Self {
        match name {
            "protocol" => Self {
                ignore_case,
                delimiter: Some(':'),
                prefix: None,
            },
            "username" => Self {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
            "password" => Self {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
            "hostname" => Self {
                ignore_case,
                delimiter: Some('.'),
                prefix: None,
            },
            "port" => Self {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
            "pathname" => Self {
                ignore_case,
                delimiter: Some('/'),
                prefix: Some('/'),
            },
            "search" => Self {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
            "hash" => Self {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
            _ => Self {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
        }
    }

    fn delimiter_str(&self) -> &'static str {
        match self.delimiter {
            Some('/') => "/",
            Some('.') => ".",
            Some(':') => ":",
            _ => "",
        }
    }

    fn prefix_str(&self) -> &'static str {
        match self.prefix {
            Some('/') => "/",
            Some('.') => ".",
            Some(':') => ":",
            _ => "",
        }
    }
}

/// `generate_segment_wildcard_regexp`.
fn segment_wildcard_regexp(options: CompileOptions) -> String {
    let delimiter = escape_regexp_string(options.delimiter_str());
    format!("[^{delimiter}]+?")
}

/// `escape_regexp_string`: backslash the characters that mean something to a
/// regexp.
fn escape_regexp_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        if matches!(
            c,
            '.' | '+'
                | '*'
                | '?'
                | '^'
                | '$'
                | '{'
                | '}'
                | '('
                | ')'
                | '['
                | ']'
                | '|'
                | '/'
                | '\\'
        ) {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

/// `escape_pattern_string`: backslash the characters that mean something to the
/// pattern tokenizer.
pub fn escape_pattern_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        if matches!(c, '+' | '*' | '?' | ':' | '{' | '}' | '(' | ')' | '\\') {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

/// Decodes one UTF-8 code point at `index`, returning it and the index of the
/// next one.
///
/// ada does this by hand so a malformed sequence can be reported as an invalid
/// code point rather than aborting. Rust's `chars()` cannot express that, so
/// the byte-oriented form is kept: an invalid lead or continuation byte yields
/// the offending byte as the code point and advances by one, which is what
/// ada's `get_next_code_point` does and what keeps the tokenizer total.
fn next_code_point(input: &[u8], index: usize) -> (char, usize, bool) {
    let first = input[index];
    if first < 0x80 {
        return (first as char, index + 1, false);
    }
    let (mut code, len) = if first & 0xE0 == 0xC0 {
        ((first & 0x1F) as u32, 2)
    } else if first & 0xF0 == 0xE0 {
        ((first & 0x0F) as u32, 3)
    } else if first & 0xF8 == 0xF0 {
        ((first & 0x07) as u32, 4)
    } else {
        return (first as char, index + 1, true);
    };
    if (len == 2 && first < 0xC2) || (len == 4 && first > 0xF4) {
        return (first as char, index + 1, true);
    }
    if index + len > input.len() {
        return (first as char, index + 1, true);
    }
    for offset in 1..len {
        let byte = input[index + offset];
        if byte & 0xC0 != 0x80 {
            return (first as char, index + 1, true);
        }
        code = (code << 6) | (byte & 0x3F) as u32;
    }
    match char::from_u32(code) {
        Some(c) => (c, index + len, false),
        None => (first as char, index + 1, true),
    }
}

/// A code point valid at the start of a pattern name, per the spec's "is a
/// valid name code point".
///
/// The fast paths are ada's: `$`, `_` and ASCII letters start a name, and `$`,
/// ASCII letters and digits continue one. Everything else falls through to the
/// Unicode `ID_Start` / `ID_Continue` tables, which is what makes `:名前` a
/// valid name. `unicode-ident` is those exact two tables — `char::is_alphabetic`
/// is not, because `ID_Start` excludes some characters that are alphabetic and
/// includes `Nl`/`Other_ID_Start` cases.
fn is_valid_name_code_point(code: char, first: bool) -> bool {
    if first {
        if code == '$' || code == '_' || code.is_ascii_alphabetic() {
            return true;
        }
        return unicode_ident::is_xid_start(code)
            // `ID_Start` is not `XID_Start`: ada's table is `ID_Start`, which
            // additionally admits `Other_ID_Start` (`U+1885`, `U+1886`,
            // `U+2118`, `U+212E`, `U+309B`, `U+309C`).
            || matches!(code, '\u{1885}' | '\u{1886}' | '\u{2118}' | '\u{212E}' | '\u{309B}' | '\u{309C}');
    }
    if code == '$' || code.is_ascii_alphanumeric() {
        return true;
    }
    unicode_ident::is_xid_continue(code)
        // Likewise `Other_ID_Continue`, which `ID_Continue` includes on top of
        // `XID_Continue`.
        || matches!(code, '\u{00B7}' | '\u{0387}' | '\u{1369}'..='\u{1371}' | '\u{19DA}')
}

fn is_ascii(code: char) -> bool {
    code.is_ascii()
}

/// `tokenize`.
pub fn tokenize(input: &str, policy: TokenPolicy) -> Result<Vec<Token<'_>>, PatternError> {
    let bytes = input.as_bytes();
    let mut tokens: Vec<Token<'_>> = Vec::new();
    let mut index = 0usize;

    // `add_token`, with the value taken as a slice of the input.
    fn add<'a>(
        tokens: &mut Vec<Token<'a>>,
        input: &'a str,
        kind: TokenType,
        index: &mut usize,
        next_position: usize,
        value_position: usize,
        value_length: usize,
    ) {
        tokens.push(Token {
            kind,
            index: *index,
            value: &input[value_position..value_position + value_length],
        });
        *index = next_position;
    }

    fn add_default<'a>(
        tokens: &mut Vec<Token<'a>>,
        input: &'a str,
        kind: TokenType,
        index: &mut usize,
        next_position: usize,
        value_position: usize,
    ) {
        let len = next_position.saturating_sub(value_position);
        add(
            tokens,
            input,
            kind,
            index,
            next_position,
            value_position,
            len,
        );
    }

    /// `process a tokenizing error`.
    fn error<'a>(
        tokens: &mut Vec<Token<'a>>,
        input: &'a str,
        policy: TokenPolicy,
        index: &mut usize,
        next_position: usize,
        value_position: usize,
    ) -> Result<(), PatternError> {
        match policy {
            TokenPolicy::Strict => Err(PatternError),
            TokenPolicy::Lenient => {
                add_default(
                    tokens,
                    input,
                    TokenType::InvalidChar,
                    index,
                    next_position,
                    value_position,
                );
                Ok(())
            }
        }
    }

    while index < bytes.len() {
        let start = index;
        let (code_point, mut next_index, invalid) = next_code_point(bytes, index);

        if invalid {
            error(&mut tokens, input, policy, &mut index, next_index, start)?;
            continue;
        }

        match code_point {
            '*' => add(
                &mut tokens,
                input,
                TokenType::Asterisk,
                &mut index,
                next_index,
                start,
                next_index - start,
            ),
            '+' | '?' => add(
                &mut tokens,
                input,
                TokenType::OtherModifier,
                &mut index,
                next_index,
                start,
                next_index - start,
            ),
            '\\' => {
                if index == bytes.len() - 1 {
                    error(&mut tokens, input, policy, &mut index, next_index, start)?;
                    continue;
                }
                let escaped_index = next_index;
                let (_, after_escape, escape_invalid) = next_code_point(bytes, escaped_index);
                next_index = after_escape;
                if escape_invalid {
                    error(
                        &mut tokens,
                        input,
                        policy,
                        &mut index,
                        next_index,
                        escaped_index,
                    )?;
                    continue;
                }
                add_default(
                    &mut tokens,
                    input,
                    TokenType::EscapedChar,
                    &mut index,
                    next_index,
                    escaped_index,
                );
            }
            '{' => add(
                &mut tokens,
                input,
                TokenType::Open,
                &mut index,
                next_index,
                start,
                next_index - start,
            ),
            '}' => add(
                &mut tokens,
                input,
                TokenType::Close,
                &mut index,
                next_index,
                start,
                next_index - start,
            ),
            ':' => {
                let name_start = next_index;
                let mut name_position = name_start;
                let mut invalid_name = false;
                while name_position < bytes.len() {
                    let (code, after, bad) = next_code_point(bytes, name_position);
                    next_index = after;
                    if bad {
                        error(
                            &mut tokens,
                            input,
                            policy,
                            &mut index,
                            next_index,
                            name_position,
                        )?;
                        invalid_name = true;
                        break;
                    }
                    let first = name_position == name_start;
                    if !is_valid_name_code_point(code, first) {
                        break;
                    }
                    name_position = next_index;
                }
                if invalid_name {
                    continue;
                }
                if name_position <= name_start {
                    error(&mut tokens, input, policy, &mut index, name_start, start)?;
                    continue;
                }
                add(
                    &mut tokens,
                    input,
                    TokenType::Name,
                    &mut index,
                    name_position,
                    name_start,
                    name_position - name_start,
                );
            }
            '(' => {
                let mut depth = 1usize;
                let regexp_start = next_index;
                let mut regexp_position = regexp_start;
                let mut failed = false;
                while regexp_position < bytes.len() {
                    let (code, after, bad) = next_code_point(bytes, regexp_position);
                    next_index = after;
                    if bad {
                        error(
                            &mut tokens,
                            input,
                            policy,
                            &mut index,
                            next_index,
                            regexp_position,
                        )?;
                        failed = true;
                        break;
                    }
                    if !is_ascii(code) {
                        error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                        failed = true;
                        break;
                    }
                    if regexp_position == regexp_start && code == '?' {
                        error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                        failed = true;
                        break;
                    }
                    if code == '\\' {
                        if regexp_position == bytes.len() - 1 {
                            error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                            failed = true;
                            break;
                        }
                        let escaped_index = next_index;
                        let (escaped, after_escape, escape_bad) =
                            next_code_point(bytes, escaped_index);
                        next_index = after_escape;
                        if escape_bad || !is_ascii(escaped) {
                            error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                            failed = true;
                            break;
                        }
                        regexp_position = next_index;
                        continue;
                    }
                    if code == ')' {
                        depth -= 1;
                        if depth == 0 {
                            regexp_position = next_index;
                            break;
                        }
                    } else if code == '(' {
                        depth += 1;
                        if regexp_position == bytes.len() - 1 {
                            error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                            failed = true;
                            break;
                        }
                        let temporary_position = next_index;
                        let (next_code, after_next, next_bad) =
                            next_code_point(bytes, temporary_position);
                        next_index = after_next;
                        if next_bad {
                            error(
                                &mut tokens,
                                input,
                                policy,
                                &mut index,
                                next_index,
                                temporary_position,
                            )?;
                            failed = true;
                            break;
                        }
                        if next_code != '?' {
                            error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                            failed = true;
                            break;
                        }
                        next_index = temporary_position;
                    }
                    regexp_position = next_index;
                }
                if failed {
                    continue;
                }
                if depth != 0 {
                    error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                    continue;
                }
                // `regexp_length` is the span between the parentheses. ada
                // computes `regexp_position - regexp_start - 1`, which assumes
                // the closing paren is one byte; a multi-byte character before
                // it would make that wrong, so the span is taken directly.
                let regexp_length = regexp_position.saturating_sub(regexp_start + 1);
                if regexp_length == 0 {
                    error(&mut tokens, input, policy, &mut index, regexp_start, start)?;
                    continue;
                }
                add(
                    &mut tokens,
                    input,
                    TokenType::Regexp,
                    &mut index,
                    regexp_position,
                    regexp_start,
                    regexp_length,
                );
            }
            _ => add(
                &mut tokens,
                input,
                TokenType::Char,
                &mut index,
                next_index,
                start,
                next_index - start,
            ),
        }
    }

    let end = index;
    add(&mut tokens, input, TokenType::End, &mut index, end, end, 0);
    Ok(tokens)
}

/// The pattern-string parser: tokens in, part list out.
struct Parser<'a, 'b> {
    tokens: Vec<Token<'a>>,
    segment_wildcard_regexp: String,
    parts: Vec<Part>,
    pending_fixed_value: String,
    index: usize,
    next_numeric_name: usize,
    options: CompileOptions,
    canonicalize: fn(&str) -> Result<String, PatternError>,
    _input: &'b str,
}

impl<'a, 'b> Parser<'a, 'b> {
    fn can_continue(&self) -> bool {
        self.index < self.tokens.len()
    }

    fn try_consume(&mut self, kind: TokenType) -> Option<Token<'a>> {
        let token = *self.tokens.get(self.index)?;
        if token.kind != kind {
            return None;
        }
        self.index += 1;
        Some(token)
    }

    fn try_consume_modifier(&mut self) -> Option<Token<'a>> {
        if let Some(token) = self.try_consume(TokenType::OtherModifier) {
            return Some(token);
        }
        self.try_consume(TokenType::Asterisk)
    }

    fn try_consume_regexp_or_wildcard(&mut self, name: Option<Token<'a>>) -> Option<Token<'a>> {
        let token = self.try_consume(TokenType::Regexp);
        if name.is_none() && token.is_none() {
            return self.try_consume(TokenType::Asterisk);
        }
        token
    }

    fn consume_text(&mut self) -> String {
        let mut result = String::new();
        loop {
            let token = self
                .try_consume(TokenType::Char)
                .or_else(|| self.try_consume(TokenType::EscapedChar));
            match token {
                Some(token) => result.push_str(token.value),
                None => break,
            }
        }
        result
    }

    fn consume_required(&mut self, kind: TokenType) -> bool {
        self.try_consume(kind).is_some()
    }

    fn maybe_add_pending_fixed(&mut self) -> Result<(), PatternError> {
        if self.pending_fixed_value.is_empty() {
            return Ok(());
        }
        let encoded = (self.canonicalize)(&self.pending_fixed_value)?;
        self.pending_fixed_value.clear();
        self.parts.push(Part::fixed(encoded, Modifier::None));
        Ok(())
    }

    fn add_part(
        &mut self,
        prefix: &str,
        name: Option<Token<'a>>,
        regexp_or_wildcard: Option<Token<'a>>,
        suffix: &str,
        modifier_token: Option<Token<'a>>,
    ) -> Result<(), PatternError> {
        let mut modifier = Modifier::None;
        if let Some(token) = modifier_token {
            match token.value {
                "?" => modifier = Modifier::Optional,
                "*" => modifier = Modifier::ZeroOrMore,
                "+" => modifier = Modifier::OneOrMore,
                _ => {}
            }
        }

        if name.is_none() && regexp_or_wildcard.is_none() && modifier == Modifier::None {
            self.pending_fixed_value.push_str(prefix);
            return Ok(());
        }

        self.maybe_add_pending_fixed()?;

        if name.is_none() && regexp_or_wildcard.is_none() {
            if prefix.is_empty() {
                return Ok(());
            }
            let encoded = (self.canonicalize)(prefix)?;
            self.parts.push(Part::fixed(encoded, modifier));
            return Ok(());
        }

        let regexp_value = match regexp_or_wildcard {
            None => self.segment_wildcard_regexp.clone(),
            Some(token) if token.kind == TokenType::Asterisk => ".*".to_string(),
            Some(token) => token.value.to_string(),
        };

        let mut kind = PartType::Regexp;
        let mut regexp_value = regexp_value;
        if regexp_value == self.segment_wildcard_regexp {
            kind = PartType::SegmentWildcard;
            regexp_value.clear();
        } else if regexp_value == ".*" {
            kind = PartType::FullWildcard;
            regexp_value.clear();
        }

        let name = match name {
            Some(token) => token.value.to_string(),
            None => {
                let generated = self.next_numeric_name.to_string();
                self.next_numeric_name += 1;
                generated
            }
        };

        if !name.is_empty() && self.parts.iter().any(|part| part.name == name) {
            return Err(PatternError);
        }

        let encoded_prefix = (self.canonicalize)(prefix)?;
        let encoded_suffix = (self.canonicalize)(suffix)?;
        self.parts.push(Part {
            kind,
            value: regexp_value,
            modifier,
            name,
            prefix: encoded_prefix,
            suffix: encoded_suffix,
        });
        Ok(())
    }
}

/// `parse_pattern_string`.
pub fn parse_pattern_string(
    input: &str,
    options: CompileOptions,
    canonicalize: fn(&str) -> Result<String, PatternError>,
) -> Result<Vec<Part>, PatternError> {
    let tokens = tokenize(input, TokenPolicy::Strict)?;
    let mut parser = Parser {
        tokens,
        segment_wildcard_regexp: segment_wildcard_regexp(options),
        parts: Vec::new(),
        pending_fixed_value: String::new(),
        index: 0,
        next_numeric_name: 0,
        options,
        canonicalize,
        _input: input,
    };

    while parser.can_continue() {
        let char_token = parser.try_consume(TokenType::Char);
        let name_token = parser.try_consume(TokenType::Name);
        let regexp_or_wildcard = parser.try_consume_regexp_or_wildcard(name_token);

        if name_token.is_some() || regexp_or_wildcard.is_some() {
            let mut prefix = char_token.map(|t| t.value).unwrap_or("");
            if !prefix.is_empty() && prefix != parser.options.prefix_str() {
                parser.pending_fixed_value.push_str(prefix);
                prefix = "";
            }
            parser.maybe_add_pending_fixed()?;
            let modifier_token = parser.try_consume_modifier();
            parser.add_part(prefix, name_token, regexp_or_wildcard, "", modifier_token)?;
            continue;
        }

        let mut fixed_token = char_token;
        if fixed_token.is_none() {
            fixed_token = parser.try_consume(TokenType::EscapedChar);
        }
        if let Some(token) = fixed_token {
            parser.pending_fixed_value.push_str(token.value);
            continue;
        }

        if parser.try_consume(TokenType::Open).is_some() {
            let prefix = parser.consume_text();
            let name_token = parser.try_consume(TokenType::Name);
            let regexp_or_wildcard = parser.try_consume_regexp_or_wildcard(name_token);
            let suffix = parser.consume_text();
            if !parser.consume_required(TokenType::Close) {
                return Err(PatternError);
            }
            let modifier_token = parser.try_consume_modifier();
            parser.add_part(
                &prefix,
                name_token,
                regexp_or_wildcard,
                &suffix,
                modifier_token,
            )?;
            continue;
        }

        parser.maybe_add_pending_fixed()?;
        if !parser.consume_required(TokenType::End) {
            return Err(PatternError);
        }
    }

    Ok(parser.parts)
}

/// `generate_pattern_string`: a part list back to a pattern string.
pub fn generate_pattern_string(parts: &[Part], options: CompileOptions) -> String {
    let mut result = String::new();
    for (index, part) in parts.iter().enumerate() {
        let previous = index.checked_sub(1).and_then(|i| parts.get(i));
        let next = parts.get(index + 1);

        if part.kind == PartType::FixedText {
            if part.modifier == Modifier::None {
                result.push_str(&escape_pattern_string(&part.value));
                continue;
            }
            result.push('{');
            result.push_str(&escape_pattern_string(&part.value));
            result.push('}');
            result.push_str(part.modifier.as_str());
            continue;
        }

        let custom_name = !part
            .name
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(true);
        let mut needs_grouping = !part.suffix.is_empty()
            || (!part.prefix.is_empty() && part.prefix != options.prefix_str());

        if !needs_grouping
            && custom_name
            && part.kind == PartType::SegmentWildcard
            && part.modifier == Modifier::None
        {
            if let Some(next) = next {
                if next.prefix.is_empty() && next.suffix.is_empty() {
                    if next.kind == PartType::FixedText {
                        if let Some(c) = next.value.chars().next() {
                            if is_valid_name_code_point(c, false) {
                                needs_grouping = true;
                            }
                        }
                    } else {
                        needs_grouping = next
                            .name
                            .chars()
                            .next()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false);
                    }
                }
            }
        }

        if !needs_grouping && part.prefix.is_empty() {
            if let Some(previous) = previous {
                if previous.kind == PartType::FixedText
                    && !previous.value.is_empty()
                    && !options.prefix_str().is_empty()
                    && previous.value.ends_with(options.prefix_str())
                {
                    needs_grouping = true;
                }
            }
        }

        if needs_grouping {
            result.push('{');
        }
        result.push_str(&escape_pattern_string(&part.prefix));
        if custom_name {
            result.push(':');
            result.push_str(&part.name);
        }
        match part.kind {
            PartType::Regexp => {
                result.push('(');
                result.push_str(&part.value);
                result.push(')');
            }
            PartType::SegmentWildcard if !custom_name => {
                result.push('(');
                result.push_str(&segment_wildcard_regexp(options));
                result.push(')');
            }
            PartType::FullWildcard => {
                let bare = !custom_name
                    && (previous.is_none()
                        || previous
                            .map(|p| p.kind == PartType::FixedText)
                            .unwrap_or(false)
                        || previous
                            .map(|p| p.modifier != Modifier::None)
                            .unwrap_or(false)
                        || needs_grouping
                        || !part.prefix.is_empty());
                if bare {
                    result.push('*');
                } else {
                    result.push_str("(.*)");
                }
            }
            _ => {}
        }
        if part.kind == PartType::SegmentWildcard && custom_name && !part.suffix.is_empty() {
            if let Some(c) = part.suffix.chars().next() {
                if is_valid_name_code_point(c, false) {
                    result.push('\\');
                }
            }
        }
        result.push_str(&escape_pattern_string(&part.suffix));
        if needs_grouping {
            result.push('}');
        }
        result.push_str(part.modifier.as_str());
    }
    result
}

/// `generate_regular_expression_and_name_list`.
pub fn generate_regular_expression_and_name_list(
    parts: &[Part],
    options: CompileOptions,
) -> (String, Vec<String>) {
    let mut result = String::from("^");
    let mut names: Vec<String> = Vec::new();
    let segment = segment_wildcard_regexp(options);

    for part in parts {
        if part.kind == PartType::FixedText {
            if part.modifier == Modifier::None {
                result.push_str(&escape_regexp_string(&part.value));
            } else {
                result.push_str("(?:");
                result.push_str(&escape_regexp_string(&part.value));
                result.push(')');
                result.push_str(part.modifier.as_str());
            }
            continue;
        }

        names.push(part.name.clone());
        let regexp_value = match part.kind {
            PartType::SegmentWildcard => segment.clone(),
            PartType::FullWildcard => ".*".to_string(),
            _ => part.value.clone(),
        };

        if part.prefix.is_empty() && part.suffix.is_empty() {
            if part.modifier == Modifier::None || part.modifier == Modifier::Optional {
                result.push('(');
                result.push_str(&regexp_value);
                result.push(')');
                result.push_str(part.modifier.as_str());
            } else {
                result.push_str("((?:");
                result.push_str(&regexp_value);
                result.push(')');
                result.push_str(part.modifier.as_str());
                result.push(')');
            }
            continue;
        }

        if part.modifier == Modifier::None || part.modifier == Modifier::Optional {
            result.push_str("(?:");
            result.push_str(&escape_regexp_string(&part.prefix));
            result.push('(');
            result.push_str(&regexp_value);
            result.push(')');
            result.push_str(&escape_regexp_string(&part.suffix));
            result.push(')');
            result.push_str(part.modifier.as_str());
            continue;
        }

        result.push_str("(?:");
        result.push_str(&escape_regexp_string(&part.prefix));
        result.push_str("((?:");
        result.push_str(&regexp_value);
        result.push_str(")(?:");
        result.push_str(&escape_regexp_string(&part.suffix));
        result.push_str(&escape_regexp_string(&part.prefix));
        result.push_str("(?:");
        result.push_str(&regexp_value);
        result.push_str("))*)");
        result.push_str(&escape_regexp_string(&part.suffix));
        result.push(')');
        if part.modifier == Modifier::ZeroOrMore {
            result.push('?');
        }
    }

    result.push('$');
    (result, names)
}

/// One compiled pattern component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentType {
    Empty,
    ExactMatch,
    FullWildcard,
    Regexp,
}

/// A component's pattern string plus how to match against it.
#[derive(Debug, Clone)]
pub struct Component {
    pub pattern: String,
    pub kind: ComponentType,
    pub exact_match_value: String,
    pub regexp_source: Option<String>,
    pub group_name_list: Vec<String>,
    pub has_regexp_groups: bool,
    pub ignore_case: bool,
}

impl Component {
    /// `url_pattern_component::compile` with the identity canonicalizer.
    pub fn compile(input: &str, options: CompileOptions) -> Result<Self, PatternError> {
        Self::compile_with(input, options, |value| Ok(value.to_string()))
    }

    /// `url_pattern_component::compile`: parse the pattern, run every fixed-text
    /// part through `canonicalize`, and record how to match the result.
    ///
    /// The canonicalizer is applied to the parts rather than to the whole input
    /// because the input is pattern syntax: only the literal text in it is a URL
    /// component. That is why `{pathname: "/b/{x,y}"}` compiles from the parts
    /// `/b/` and `x,y` and reports `"/b/x,y"`.
    pub fn compile_with(
        input: &str,
        options: CompileOptions,
        canonicalize: fn(&str) -> Result<String, PatternError>,
    ) -> Result<Self, PatternError> {
        let parts = parse_pattern_string(input, options, canonicalize)?;
        let has_regexp_groups = parts.iter().any(Part::is_regexp);

        let mut kind = ComponentType::Regexp;
        let mut exact_match_value = String::new();
        if parts.is_empty() {
            kind = ComponentType::Empty;
        } else if parts.len() == 1 {
            let part = &parts[0];
            if part.kind == PartType::FixedText
                && part.modifier == Modifier::None
                && !options.ignore_case
            {
                kind = ComponentType::ExactMatch;
                exact_match_value = part.value.clone();
            } else if part.kind == PartType::FullWildcard
                && part.modifier == Modifier::None
                && part.prefix.is_empty()
                && part.suffix.is_empty()
            {
                kind = ComponentType::FullWildcard;
            }
        }

        let pattern = generate_pattern_string(&parts, options);

        if kind != ComponentType::Regexp {
            let group_name_list = if kind == ComponentType::FullWildcard {
                parts
                    .first()
                    .map(|p| vec![p.name.clone()])
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            return Ok(Self {
                pattern,
                kind,
                exact_match_value,
                regexp_source: None,
                group_name_list,
                has_regexp_groups,
                ignore_case: options.ignore_case,
            });
        }

        let (regexp_source, group_name_list) =
            generate_regular_expression_and_name_list(&parts, options);
        Ok(Self {
            pattern,
            kind,
            exact_match_value,
            regexp_source: Some(regexp_source),
            group_name_list,
            has_regexp_groups,
            ignore_case: options.ignore_case,
        })
    }

    /// The regexp source to hand to V8, if this component needs one.
    pub fn regexp_source(&self) -> Option<&str> {
        self.regexp_source.as_deref()
    }

    /// Whether a component matches, without producing groups.
    ///
    /// The literal and wildcard cases are answered without a regexp, which is
    /// what ada's `fast_test` does. The regexp case is answered by the caller,
    /// which owns the V8 `RegExp`.
    pub fn fast_test(&self, input: &str) -> Option<bool> {
        match self.kind {
            ComponentType::FullWildcard => Some(true),
            ComponentType::ExactMatch => Some(input == self.exact_match_value),
            ComponentType::Empty => Some(input.is_empty()),
            ComponentType::Regexp => None,
        }
    }
}

/// The eight compiled components of a pattern.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub components: [Component; 8],
}

impl CompiledPattern {
    pub fn has_regexp_groups(&self) -> bool {
        self.components.iter().any(|c| c.has_regexp_groups)
    }
}

/// The pattern strings, in `COMPONENTS` order.
pub type ComponentStrings = [String; 8];

/// The canonicalizer applied to a component's fixed text when it is compiled.
///
/// `url_pattern_component::compile` takes an encoding callback and applies it to
/// every fixed-text part, so the *pattern string* a getter reports is the
/// canonicalised one: `{hostname: "E.COM"}` reports `"e.com"` and
/// `{pathname: "/b/{x,y}"}` reports `"/b/x,y"` because the braces are pattern
/// syntax rather than text. Node picks the callback per component in
/// `parse_url_pattern_impl`, and this is that table.
fn canonicalizer(name: &str) -> fn(&str) -> Result<String, PatternError> {
    match name {
        "protocol" => canonicalize_protocol,
        "username" => |value: &str| canonicalize_with(value, &USERINFO_PERCENT_ENCODE),
        "password" => |value: &str| canonicalize_with(value, &USERINFO_PERCENT_ENCODE),
        "hostname" => canonicalize_hostname,
        "port" => |value: &str| {
            if value.is_empty() {
                return Ok(String::new());
            }
            canonicalize_port(value)
        },
        "pathname" => canonicalize_pathname,
        "search" => |value: &str| canonicalize_with(value, &QUERY_PERCENT_ENCODE),
        _ => |value: &str| canonicalize_with(value, &FRAGMENT_PERCENT_ENCODE),
    }
}

/// `canonicalize_pathname`.
///
/// The spec runs the basic URL parser over the value in *path state override*,
/// which is what `Url::set_path` does: dot segments are resolved, `^` and space
/// are percent-encoded, and `?`/`#` are ordinary path code points rather than
/// delimiters.
///
/// A value without a leading slash needs the same treatment but must not gain
/// one, so ada prefixes the sentinel `/-` and strips it afterwards — `"a"` stays
/// `"a"` while `"../a"` still resolves to `"a"`. The sentinel is reproduced
/// here for the same reason.
fn canonicalize_pathname(value: &str) -> Result<String, PatternError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let leading_slash = value.starts_with('/');
    let modified = if leading_slash {
        value.to_string()
    } else {
        format!("/-{value}")
    };
    // `set_pathname` is ada's own path-state-override path, which is what Node's
    // `canonicalize_pathname` calls. Using ada rather than a second WHATWG parser
    // matters here: the path percent-encode set and the dot-segment rules are
    // the same code Node runs, so `^` encodes and `?`/`#` stay literal without
    // this crate restating either rule.
    let mut url = ada_url::Url::parse("fake://fake-url", None).map_err(|_| PatternError)?;
    // A rejected path leaves the URL unchanged, so the result has to be checked
    // or the dummy's own path would be returned as if it were the input's.
    let accepted: Result<(), ()> = url.set_pathname(Some(&modified));
    if accepted.is_err() {
        return Err(PatternError);
    }
    let path = url.pathname();
    if leading_slash {
        return Ok(path.to_string());
    }
    // The sentinel can be consumed by traversal, in which case the value was not
    // a usable path.
    if path.len() < 2 {
        return Err(PatternError);
    }
    Ok(path[2..].to_string())
}

/// `canonicalize_port` without a protocol.
///
/// ada's version returns the value unchanged when it is empty, rejects anything
/// that does not start with a digit, and otherwise keeps the leading digits with
/// leading zeros removed ("0080" is 80). Trailing text is *not* quietly kept:
/// `{port: "x"}` and `{port: "8x"}` behave differently in Node — the first
/// throws, the second is port 8 — so the two cases are distinguished here rather
/// than collapsed.
fn canonicalize_port(value: &str) -> Result<String, PatternError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let trimmed = remove_ascii_tab_or_newline(value);
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(PatternError);
    }
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    let parsed: u64 = digits.parse().map_err(|_| PatternError)?;
    if parsed > u16::MAX as u64 {
        return Err(PatternError);
    }
    Ok(parsed.to_string())
}

/// Compiles the eight components of a pattern.
///
/// The order and the per-component options mirror `parse_url_pattern_impl`: the
/// hostname uses `.` as its delimiter and the pathname `/` as both delimiter and
/// prefix, everything else takes the empty defaults. `ignore_case` is applied to
/// every component, which is what the spec's `compileOptions` does.
pub fn compile_all(
    strings: &ComponentStrings,
    ignore_case: bool,
) -> Result<CompiledPattern, PatternError> {
    let mut components: [Option<Component>; 8] = Default::default();
    for (index, name) in COMPONENTS.iter().enumerate() {
        let mut options = match *name {
            "hostname" => CompileOptions {
                ignore_case,
                delimiter: Some('.'),
                prefix: None,
            },
            "pathname" => CompileOptions {
                ignore_case,
                delimiter: Some('/'),
                prefix: Some('/'),
            },
            _ => CompileOptions {
                ignore_case,
                delimiter: None,
                prefix: None,
            },
        };
        options.ignore_case = ignore_case;
        components[index] = Some(Component::compile_with(
            &strings[index],
            options,
            canonicalizer(name),
        )?);
    }
    Ok(CompiledPattern {
        components: [
            components[0]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[1]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[2]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[3]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[4]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[5]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[6]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
            components[7]
                .take()
                .unwrap_or_else(|| empty_component(ignore_case)),
        ],
    })
}

fn empty_component(ignore_case: bool) -> Component {
    Component {
        pattern: String::new(),
        kind: ComponentType::Empty,
        exact_match_value: String::new(),
        regexp_source: None,
        group_name_list: Vec::new(),
        has_regexp_groups: false,
        ignore_case,
    }
}

/// The components of a URL being matched, in `COMPONENTS` order.
#[derive(Debug, Clone, Default)]
pub struct UrlComponents {
    pub values: ComponentStrings,
}

impl UrlComponents {
    /// The component strings of a URL, from a string input and optional base.
    ///
    /// This is ada's string-input branch: parse the input (resolving a relative
    /// one against `base_url`), then read the scheme without its `:`, the
    /// query and fragment without their delimiters, and the path as the URL
    /// serializer leaves it.
    ///
    /// A relative input with no base is *not* a failure. Node still resolves it,
    /// against an empty URL, so `test("a")` sees path `"/a"` with every other
    /// component empty; only an input that cannot be a URL at all (a bare
    /// `":"`, say) matches nothing. The empty base is reproduced by resolving
    /// against a synthetic one and then clearing the components that base
    /// supplied, which is what makes the path normalisation identical.
    pub fn from_url(input: &str, base_url: Option<&str>) -> Option<Self> {
        // A base that does not parse is not a relative-input situation: the
        // input cannot be resolved at all, so nothing matches. This is what
        // makes `test("/a", null)` false rather than resolving `/a` against an
        // empty base — `"null"` is a string that ada rejects.
        if let Some(base) = base_url {
            if ada_url::Url::parse(base, None).is_err() {
                return None;
            }
        }

        let parsed = match ada_url::Url::parse(input, base_url) {
            Ok(parsed) => parsed,
            Err(_) => {
                // Relative: resolve against an empty base, then drop what the
                // synthetic base contributed. The empty string is a special
                // case — resolving it yields the base's path `"/"`, but Node
                // reports the input's own (absent) path, which is `""`.
                if input.is_empty() {
                    return Some(Self::default());
                }
                let resolved = ada_url::Url::parse(input, Some("fake://fake-url/")).ok()?;
                return Some(Self {
                    values: [
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        resolved.pathname().to_string(),
                        delimited(resolved.search()),
                        delimited(resolved.hash()),
                    ],
                });
            }
        };
        Some(Self {
            values: [
                parsed.protocol().trim_end_matches(':').to_string(),
                parsed.username().to_string(),
                parsed.password().to_string(),
                parsed.hostname().to_string(),
                parsed.port().to_string(),
                parsed.pathname().to_string(),
                delimited(parsed.search()),
                delimited(parsed.hash()),
            ],
        })
    }
}

/// Strips the leading `?` or `#` that ada's accessors carry.
///
/// ada reports the query and fragment *with* their delimiter, and the pattern's
/// components are stored without one (`process_search`/`process_hash` remove a
/// single leading delimiter), so the comparison needs them removed here.
fn delimited(value: &str) -> String {
    value
        .strip_prefix('?')
        .or_else(|| value.strip_prefix('#'))
        .unwrap_or(value)
        .to_string()
}

/// A `URLPatternInit` as the dictionary it is.
///
/// A field that is absent is `None`; a field that is present but empty is
/// `Some("")`. The distinction is load-bearing — `{port: ""}` is a pattern for
/// "no port" while `{}` is a wildcard — so it cannot be flattened to strings.
#[derive(Debug, Clone, Default)]
pub struct Init {
    pub protocol: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<String>,
    pub pathname: Option<String>,
    pub search: Option<String>,
    pub hash: Option<String>,
    pub base_url: Option<String>,
}

/// Which of the spec's two `URLPatternInit` processing types to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessType {
    Url,
    Pattern,
}

fn process_base_url_string(input: &str, kind: ProcessType) -> String {
    if kind != ProcessType::Pattern {
        return input.to_string();
    }
    escape_pattern_string(input)
}

fn is_absolute_pathname(input: &str, kind: ProcessType) -> bool {
    if input.is_empty() {
        return false;
    }
    if input.starts_with('/') {
        return true;
    }
    if kind == ProcessType::Url {
        return false;
    }
    if input.len() < 2 {
        return false;
    }
    input.as_bytes()[1] == b'/' && (input.starts_with('\\') || input.starts_with('{'))
}

/// `process_init`: the spec's "process a URLPatternInit".
///
/// `base` is the constructor's second argument when it was a string; the spec
/// treats `init.baseURL` and that argument as the same thing, so the caller
/// merges them first.
pub fn process_init(init: &Init, kind: ProcessType) -> Result<[Option<String>; 8], PatternError> {
    let mut result: [Option<String>; 8] = Default::default();

    let base = match init.base_url.as_deref() {
        Some(text) => Some(parse_base_url(text)?),
        None => None,
    };

    if let Some(base) = &base {
        if init.protocol.is_none() {
            result[0] = Some(process_base_url_string(&base.protocol, kind));
        }
        if kind != ProcessType::Pattern
            && init.protocol.is_none()
            && init.hostname.is_none()
            && init.port.is_none()
            && init.username.is_none()
        {
            result[1] = Some(process_base_url_string(&base.username, kind));
        }
        if kind != ProcessType::Pattern
            && init.protocol.is_none()
            && init.hostname.is_none()
            && init.port.is_none()
            && init.username.is_none()
            && init.password.is_none()
        {
            result[2] = Some(process_base_url_string(&base.password, kind));
        }
        if init.protocol.is_none() && init.hostname.is_none() {
            result[3] = Some(process_base_url_string(&base.hostname, kind));
        }
        if init.protocol.is_none() && init.hostname.is_none() && init.port.is_none() {
            result[4] = Some(base.port.clone());
        }
        if init.protocol.is_none()
            && init.hostname.is_none()
            && init.port.is_none()
            && init.pathname.is_none()
        {
            result[5] = Some(process_base_url_string(&base.pathname, kind));
        }
        if init.protocol.is_none()
            && init.hostname.is_none()
            && init.port.is_none()
            && init.pathname.is_none()
            && init.search.is_none()
        {
            result[6] = Some(process_base_url_string(&base.search, kind));
        }
        if init.protocol.is_none()
            && init.hostname.is_none()
            && init.port.is_none()
            && init.pathname.is_none()
            && init.search.is_none()
            && init.hash.is_none()
        {
            result[7] = Some(process_base_url_string(&base.hash, kind));
        }
    }

    if let Some(value) = &init.protocol {
        result[0] = Some(process_protocol(value, kind)?);
    }
    if let Some(value) = &init.username {
        result[1] = Some(process_username(value, kind)?);
    }
    if let Some(value) = &init.password {
        result[2] = Some(process_password(value, kind)?);
    }
    if let Some(value) = &init.hostname {
        result[3] = Some(process_hostname(value, kind)?);
    }
    if let Some(value) = &init.port {
        let protocol = result[0].clone().unwrap_or_else(|| "fake".to_string());
        result[4] = Some(process_port(value, &protocol, kind)?);
    }
    if let Some(value) = &init.pathname {
        result[5] = Some(value.clone());
        if let Some(base) = &base {
            if !base.opaque_path && !is_absolute_pathname(value, kind) {
                let base_path = process_base_url_string(&base.pathname, kind);
                if let Some(slash) = base_path.rfind('/') {
                    let mut merged = base_path[..=slash].to_string();
                    merged.push_str(result[5].as_deref().unwrap_or_default());
                    result[5] = Some(merged);
                }
            }
        }
        let protocol = result[0].clone().unwrap_or_default();
        let pathname = result[5].clone().unwrap_or_default();
        result[5] = Some(process_pathname(&pathname, &protocol, kind)?);
    }
    if let Some(value) = &init.search {
        result[6] = Some(process_search(value, kind)?);
    }
    if let Some(value) = &init.hash {
        result[7] = Some(process_hash(value, kind)?);
    }

    Ok(result)
}

/// The constructor's tail: `process_init`, then the two steps that follow it.
///
/// This is `parse_url_pattern_impl` in `parser-inl.h`, which is what Node calls.
/// The two extra steps are constructor-only:
///
/// * a component the init never produced becomes `"*"`, a wildcard. That is what
///   makes `new URLPattern({pathname: "/a"}).protocol` read `"*"`; `""` would
///   be a component matching only the empty string, which is a different and
///   much narrower pattern.
/// * a port equal to the scheme's default is cleared, so
///   `new URLPattern("https://a.com:443/x").port` is `""`.
pub fn finish_init(init: &Init, kind: ProcessType) -> Result<ComponentStrings, PatternError> {
    let mut values = process_init(init, kind)?;
    for slot in values.iter_mut() {
        if slot.is_none() {
            *slot = Some("*".to_string());
        }
    }

    let mut strings: ComponentStrings = Default::default();
    for (index, slot) in values.into_iter().enumerate() {
        strings[index] = slot.unwrap_or_else(|| "*".to_string());
    }

    let protocol = strings[0].clone();
    if is_special_scheme(&protocol) {
        let default = special_port(&protocol);
        if default != 0 && strings[4] == default.to_string() {
            strings[4].clear();
        }
    }
    Ok(strings)
}

/// The states the constructor-string parser moves through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstructorState {
    Init,
    Protocol,
    Authority,
    Username,
    Password,
    Hostname,
    Port,
    Pathname,
    Search,
    Hash,
    Done,
}

/// `constructor_string_parser`: a pattern string like
/// `https://user:pw@example.com:8080/a?q#h` into a `URLPatternInit`.
///
/// This is the state machine from the spec's "parse a constructor string". It
/// runs on the *lenient* token list, so a raw `{` or `:` in a path does not
/// abort the way it would when the same text is parsed as a pattern component.
struct ConstructorParser<'a> {
    input: &'a str,
    tokens: Vec<Token<'a>>,
    result: Init,
    component_start: usize,
    token_index: usize,
    token_increment: usize,
    group_depth: usize,
    hostname_ipv6_bracket_depth: usize,
    protocol_matches_special_scheme: bool,
    state: ConstructorState,
}

impl<'a> ConstructorParser<'a> {
    fn safe_token(&self, index: usize) -> Token<'a> {
        match self.tokens.get(index) {
            Some(token) => *token,
            None => *self.tokens.last().expect("the token list ends with END"),
        }
    }

    fn rewind(&mut self) {
        self.token_index = self.component_start;
        self.token_increment = 0;
    }

    fn is_non_special_pattern_char(&self, index: usize, value: char) -> bool {
        let token = self.safe_token(index);
        if let Some(first) = token.value.chars().next() {
            if first != value {
                return false;
            }
        }
        matches!(
            token.kind,
            TokenType::Char | TokenType::EscapedChar | TokenType::InvalidChar
        )
    }

    fn is_hash_prefix(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, '#')
    }

    fn is_search_prefix(&self) -> bool {
        if self.is_non_special_pattern_char(self.token_index, '?') {
            return true;
        }
        let token = self.safe_token(self.token_index);
        if token.value != "?" {
            return false;
        }
        if self.token_index == 0 {
            return true;
        }
        let previous = self.safe_token(self.token_index - 1);
        !matches!(
            previous.kind,
            TokenType::Name | TokenType::Regexp | TokenType::Close | TokenType::Asterisk
        )
    }

    fn is_group_open(&self) -> bool {
        self.safe_token(self.token_index).kind == TokenType::Open
    }

    fn is_group_close(&self) -> bool {
        self.safe_token(self.token_index).kind == TokenType::Close
    }

    fn is_protocol_suffix(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, ':')
    }

    fn next_is_authority_slashes(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index + 1, '/')
            && self.is_non_special_pattern_char(self.token_index + 2, '/')
    }

    fn is_identity_terminator(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, '@')
    }

    fn is_pathname_start(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, '/')
    }

    fn is_password_prefix(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, ':')
    }

    fn is_ipv6_open(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, '[')
    }

    fn is_ipv6_close(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, ']')
    }

    fn is_port_prefix(&self) -> bool {
        self.is_non_special_pattern_char(self.token_index, ':')
    }

    fn make_component_string(&self) -> String {
        let end_index = self.safe_token(self.token_index).index;
        let start_index = self.safe_token(self.component_start).index;
        self.input[start_index..end_index.max(start_index)].to_string()
    }

    fn compute_protocol_matches_special_scheme(
        &mut self,
        matcher: &mut dyn FnMut(&Component, &str) -> bool,
    ) -> Result<(), PatternError> {
        let protocol_string = self.make_component_string();
        let options = CompileOptions::for_component("protocol", false);
        let component = Component::compile(&protocol_string, options)?;
        self.protocol_matches_special_scheme =
            component_matches_special_scheme(&component, matcher);
        Ok(())
    }

    fn change_state(&mut self, new_state: ConstructorState, skip: usize) {
        if self.state != ConstructorState::Init
            && self.state != ConstructorState::Authority
            && self.state != ConstructorState::Done
        {
            let value = self.make_component_string();
            match self.state {
                ConstructorState::Protocol => self.result.protocol = Some(value),
                ConstructorState::Username => self.result.username = Some(value),
                ConstructorState::Password => self.result.password = Some(value),
                ConstructorState::Hostname => self.result.hostname = Some(value),
                ConstructorState::Port => self.result.port = Some(value),
                ConstructorState::Pathname => self.result.pathname = Some(value),
                ConstructorState::Search => self.result.search = Some(value),
                ConstructorState::Hash => self.result.hash = Some(value),
                _ => {}
            }
        }

        if self.state != ConstructorState::Init && new_state != ConstructorState::Done {
            let leaves_authority = matches!(
                self.state,
                ConstructorState::Protocol
                    | ConstructorState::Authority
                    | ConstructorState::Username
                    | ConstructorState::Password
            );
            let enters_component = matches!(
                new_state,
                ConstructorState::Port
                    | ConstructorState::Pathname
                    | ConstructorState::Search
                    | ConstructorState::Hash
            );
            if leaves_authority && enters_component && self.result.hostname.is_none() {
                self.result.hostname = Some(String::new());
            }

            let in_authority = matches!(
                self.state,
                ConstructorState::Protocol
                    | ConstructorState::Authority
                    | ConstructorState::Username
                    | ConstructorState::Password
                    | ConstructorState::Hostname
                    | ConstructorState::Port
            );
            if in_authority
                && matches!(new_state, ConstructorState::Search | ConstructorState::Hash)
                && self.result.pathname.is_none()
            {
                self.result.pathname = Some(if self.protocol_matches_special_scheme {
                    "/".to_string()
                } else {
                    String::new()
                });
            }

            let before_hash = matches!(
                self.state,
                ConstructorState::Protocol
                    | ConstructorState::Authority
                    | ConstructorState::Username
                    | ConstructorState::Password
                    | ConstructorState::Hostname
                    | ConstructorState::Port
                    | ConstructorState::Pathname
            );
            if before_hash && new_state == ConstructorState::Hash && self.result.search.is_none() {
                self.result.search = Some(String::new());
            }
        }

        self.state = new_state;
        self.token_index += skip;
        self.component_start = self.token_index;
        self.token_increment = 0;
    }

    fn parse(
        input: &'a str,
        matches: &mut dyn FnMut(&Component, &str) -> bool,
    ) -> Result<Init, PatternError> {
        let tokens = tokenize(input, TokenPolicy::Lenient)?;
        let mut parser = Self {
            input,
            tokens,
            result: Init::default(),
            component_start: 0,
            token_index: 0,
            token_increment: 1,
            group_depth: 0,
            hostname_ipv6_bracket_depth: 0,
            protocol_matches_special_scheme: false,
            state: ConstructorState::Init,
        };

        while parser.token_index < parser.tokens.len() {
            parser.token_increment = 1;

            if parser.safe_token(parser.token_index).kind == TokenType::End {
                match parser.state {
                    ConstructorState::Init => {
                        parser.rewind();
                        if parser.is_hash_prefix() {
                            parser.change_state(ConstructorState::Hash, 1);
                        } else if parser.is_search_prefix() {
                            parser.change_state(ConstructorState::Search, 1);
                        } else {
                            parser.change_state(ConstructorState::Pathname, 0);
                        }
                        parser.token_index += parser.token_increment;
                        continue;
                    }
                    ConstructorState::Authority => {
                        parser.rewind();
                        parser.change_state(ConstructorState::Hostname, 0);
                        parser.token_index += parser.token_increment;
                        continue;
                    }
                    _ => {
                        parser.change_state(ConstructorState::Done, 0);
                        break;
                    }
                }
            }

            if parser.is_group_open() {
                parser.group_depth += 1;
                parser.token_index += parser.token_increment;
                continue;
            }

            if parser.group_depth > 0 {
                if parser.is_group_close() {
                    parser.group_depth -= 1;
                } else {
                    parser.token_index += parser.token_increment;
                    continue;
                }
            }

            match parser.state {
                ConstructorState::Init => {
                    if parser.is_protocol_suffix() {
                        parser.rewind();
                        parser.change_state(ConstructorState::Protocol, 0);
                    }
                }
                ConstructorState::Protocol => {
                    if parser.is_protocol_suffix() {
                        parser.compute_protocol_matches_special_scheme(matches)?;
                        let mut next_state = ConstructorState::Pathname;
                        let mut skip = 1;
                        if parser.next_is_authority_slashes() {
                            next_state = ConstructorState::Authority;
                            skip = 3;
                        } else if parser.protocol_matches_special_scheme {
                            next_state = ConstructorState::Authority;
                        }
                        parser.change_state(next_state, skip);
                    }
                }
                ConstructorState::Authority => {
                    if parser.is_identity_terminator() {
                        parser.rewind();
                        parser.change_state(ConstructorState::Username, 0);
                    } else if parser.is_pathname_start()
                        || parser.is_search_prefix()
                        || parser.is_hash_prefix()
                    {
                        parser.rewind();
                        parser.change_state(ConstructorState::Hostname, 0);
                    }
                }
                ConstructorState::Username => {
                    if parser.is_password_prefix() {
                        parser.change_state(ConstructorState::Password, 1);
                    } else if parser.is_identity_terminator() {
                        parser.change_state(ConstructorState::Hostname, 1);
                    }
                }
                ConstructorState::Password => {
                    if parser.is_identity_terminator() {
                        parser.change_state(ConstructorState::Hostname, 1);
                    }
                }
                ConstructorState::Hostname => {
                    if parser.is_ipv6_open() {
                        parser.hostname_ipv6_bracket_depth += 1;
                    } else if parser.is_ipv6_close() {
                        parser.hostname_ipv6_bracket_depth =
                            parser.hostname_ipv6_bracket_depth.saturating_sub(1);
                    } else if parser.is_port_prefix() && parser.hostname_ipv6_bracket_depth == 0 {
                        parser.change_state(ConstructorState::Port, 1);
                    } else if parser.is_pathname_start() {
                        parser.change_state(ConstructorState::Pathname, 0);
                    } else if parser.is_search_prefix() {
                        parser.change_state(ConstructorState::Search, 1);
                    } else if parser.is_hash_prefix() {
                        parser.change_state(ConstructorState::Hash, 1);
                    }
                }
                ConstructorState::Port => {
                    if parser.is_pathname_start() {
                        parser.change_state(ConstructorState::Pathname, 0);
                    } else if parser.is_search_prefix() {
                        parser.change_state(ConstructorState::Search, 1);
                    } else if parser.is_hash_prefix() {
                        parser.change_state(ConstructorState::Hash, 1);
                    }
                }
                ConstructorState::Pathname => {
                    if parser.is_search_prefix() {
                        parser.change_state(ConstructorState::Search, 1);
                    } else if parser.is_hash_prefix() {
                        parser.change_state(ConstructorState::Hash, 1);
                    }
                }
                ConstructorState::Search => {
                    if parser.is_hash_prefix() {
                        parser.change_state(ConstructorState::Hash, 1);
                    }
                }
                ConstructorState::Hash | ConstructorState::Done => {}
            }

            parser.token_index += parser.token_increment;
        }

        // A hostname with no port means the pattern is for "no port", not for
        // any port. This is the spec's last step and it is what makes
        // `new URLPattern("https://a.com/x").port` read `""` against the
        // wildcard a bare `{}` dictionary would give.
        if parser.result.hostname.is_some() && parser.result.port.is_none() {
            parser.result.port = Some(String::new());
        }

        Ok(parser.result)
    }
}

/// `protocol_component_matches_special_scheme`.
///
/// A regexp component has to be evaluated to answer this, and this module has
/// no engine of its own — V8's `RegExp` lives in the binding layer — so the
/// caller supplies `matches`, which is asked whether the component accepts one
/// of the special schemes.
fn component_matches_special_scheme(
    component: &Component,
    matches: &mut dyn FnMut(&Component, &str) -> bool,
) -> bool {
    match component.kind {
        ComponentType::Empty => false,
        ComponentType::ExactMatch => is_special_scheme(&component.exact_match_value),
        ComponentType::FullWildcard => true,
        ComponentType::Regexp => ["http", "https", "ws", "wss", "ftp", "file"]
            .iter()
            .any(|scheme| matches(component, scheme)),
    }
}

/// `parse a constructor string`: a pattern string into a `URLPatternInit`.
pub fn parse_constructor_string(
    input: &str,
    matches: &mut dyn FnMut(&Component, &str) -> bool,
) -> Result<Init, PatternError> {
    ConstructorParser::parse(input, matches)
}

/// The components of a parsed URL, as `process_init` needs them.
#[derive(Debug, Clone)]
pub struct BaseUrl {
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub port: String,
    pub pathname: String,
    pub search: String,
    pub hash: String,
    pub opaque_path: bool,
}

/// Parses a base URL with `ada-url`, the library `src/node_url.cc` is built on.
///
/// Using ada here rather than a second WHATWG parser is the point: a base URL is
/// parsed by the same code Node runs, so `baseURL` inheritance cannot disagree
/// with the `URL` namespace about a host, a path or a special scheme.
fn parse_base_url(text: &str) -> Result<BaseUrl, PatternError> {
    let url = ada_url::Url::parse(text, None).map_err(|_| PatternError)?;
    // `HostType::Domain` with an empty hostname is how ada spells "no host"; a
    // `mailto:` or `data:` URL is the case that reaches the opaque-path branch
    // of `process_init`.
    let opaque_path = url.host_type() == ada_url::HostType::Domain && url.hostname().is_empty();
    Ok(BaseUrl {
        protocol: url.protocol().trim_end_matches(':').to_string(),
        username: url.username().to_string(),
        password: url.password().to_string(),
        hostname: url.hostname().to_string(),
        port: url.port().to_string(),
        pathname: url.pathname().to_string(),
        search: delimited(url.search()),
        hash: delimited(url.hash()),
        opaque_path,
    })
}

fn process_protocol(value: &str, kind: ProcessType) -> Result<String, PatternError> {
    let value = value.strip_suffix(':').unwrap_or(value);
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    canonicalize_protocol(value)
}

fn process_username(value: &str, kind: ProcessType) -> Result<String, PatternError> {
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    canonicalize_with(value, &USERINFO_PERCENT_ENCODE)
}

fn process_password(value: &str, kind: ProcessType) -> Result<String, PatternError> {
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    canonicalize_with(value, &USERINFO_PERCENT_ENCODE)
}

fn process_hostname(value: &str, kind: ProcessType) -> Result<String, PatternError> {
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    canonicalize_hostname(value)
}

fn process_port(value: &str, protocol: &str, kind: ProcessType) -> Result<String, PatternError> {
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    canonicalize_port_with_protocol(value, protocol)
}

fn process_pathname(
    value: &str,
    protocol: &str,
    kind: ProcessType,
) -> Result<String, PatternError> {
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    if protocol.is_empty() || is_special_scheme(protocol) {
        return canonicalize_with(value, &PATH_PERCENT_ENCODE);
    }
    canonicalize_with(value, &C0_CONTROL_PERCENT_ENCODE)
}

fn process_search(value: &str, kind: ProcessType) -> Result<String, PatternError> {
    let value = value.strip_prefix('?').unwrap_or(value);
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    let stripped = remove_ascii_tab_or_newline(value);
    canonicalize_with(&stripped, &QUERY_PERCENT_ENCODE)
}

fn process_hash(value: &str, kind: ProcessType) -> Result<String, PatternError> {
    let value = value.strip_prefix('#').unwrap_or(value);
    if kind == ProcessType::Pattern {
        return Ok(value.to_string());
    }
    let stripped = remove_ascii_tab_or_newline(value);
    canonicalize_with(&stripped, &FRAGMENT_PERCENT_ENCODE)
}

fn remove_ascii_tab_or_newline(input: &str) -> String {
    input
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

pub fn is_special_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp" | "file")
}

fn is_ascii_digit(c: char) -> bool {
    c.is_ascii_digit()
}

/// `canonicalize_protocol`.
fn canonicalize_protocol(input: &str) -> Result<String, PatternError> {
    if input.is_empty() {
        return Ok(String::new());
    }
    let scheme = input.strip_suffix(':').unwrap_or(input);
    if is_special_scheme(scheme) {
        return Ok(scheme.to_string());
    }
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return Err(PatternError),
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return Err(PatternError);
    }
    Ok(scheme.to_ascii_lowercase())
}

/// `canonicalize_port_with_protocol`.
fn canonicalize_port_with_protocol(value: &str, protocol: &str) -> Result<String, PatternError> {
    let trimmed = remove_ascii_tab_or_newline(value);
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed.starts_with(is_ascii_digit) {
        return Err(PatternError);
    }
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    let parsed: u32 = digits.parse().map_err(|_| PatternError)?;
    if parsed > u16::MAX as u32 {
        return Err(PatternError);
    }
    let protocol = protocol.strip_suffix(':').unwrap_or(protocol);
    let protocol = if protocol.is_empty() {
        "fake"
    } else {
        protocol
    };
    let default = if is_special_scheme(protocol) {
        special_port(protocol)
    } else {
        0
    };
    if default != 0 && default == parsed {
        return Ok(String::new());
    }
    Ok(parsed.to_string())
}

fn special_port(scheme: &str) -> u32 {
    match scheme {
        "ftp" => 21,
        "file" => 0,
        "http" | "ws" => 80,
        "https" | "wss" => 443,
        _ => 0,
    }
}

/// `canonicalize_hostname`: lowercase, then IDNA the labels the way the URL
/// parser does.
///
/// ada runs the value through `set_hostname` on a dummy `https://` URL, which
/// is exactly `url::Url`'s host parsing, so this builds the same dummy URL and
/// reads the host back out. That keeps IDNA, IPv4 rewriting and the
/// `xn--`-passthrough rule in one place instead of a second implementation.
fn canonicalize_hostname(input: &str) -> Result<String, PatternError> {
    if input.is_empty() {
        return Ok(String::new());
    }
    if input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !looks_like_ipv4(input)
    {
        return Ok(input.to_ascii_lowercase());
    }
    // `set_hostname` on a dummy `https://` URL is ada's own host parser, which is
    // what `canonicalize_hostname` does in the C++: the protocol has to be
    // special or IDNA is skipped.
    //
    // The result has to be checked. ada leaves the URL untouched on a rejected
    // host, so ignoring it would return the dummy's own `dummy.test` for an
    // invalid input like `a^b` where Node throws.
    let mut dummy = ada_url::Url::parse("https://dummy.test", None).map_err(|_| PatternError)?;
    let accepted: Result<(), ()> = dummy.set_hostname(Some(input));
    if accepted.is_err() {
        return Err(PatternError);
    }
    Ok(dummy.hostname().to_string())
}

/// Whether a host is IPv4-shaped, which the host parser rewrites
/// (`0` becomes `0.0.0.0`) and so must not take the fast path above.
fn looks_like_ipv4(input: &str) -> bool {
    ada_url::Url::parse(&format!("https://{input}/"), None)
        .map(|url| url.host_type() == ada_url::HostType::IPV4)
        .unwrap_or(false)
}

/// `canonicalize_*` for the percent-encode-set components.
fn canonicalize_with(input: &str, set: &[bool; 128]) -> Result<String, PatternError> {
    if input.is_empty() {
        return Ok(String::new());
    }
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        // A non-ASCII code point is always encoded; the table only carries the
        // ASCII half. Both cases are one UTF-8 encode and the same escapes.
        let encode = !c.is_ascii() || set[c as usize];
        if !encode {
            result.push(c);
            continue;
        }
        let mut buffer = [0u8; 4];
        for byte in c.encode_utf8(&mut buffer).as_bytes() {
            result.push('%');
            result.push(hex_upper(byte >> 4));
            result.push(hex_upper(byte & 0xF));
        }
    }
    Ok(result)
}

fn hex_upper(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
}

/// Builds a 128-entry ASCII membership table from the code points ada's
/// 256-entry bitset marks. Every byte at or above 0x80 is encoded, so only the
/// ASCII half needs a table.
const fn encode_set(ascii: &[u8]) -> [bool; 128] {
    let mut table = [false; 128];
    let mut index = 0;
    while index < ascii.len() {
        table[ascii[index] as usize] = true;
        index += 1;
    }
    table
}

const C0_CONTROL_PERCENT_ENCODE: [bool; 128] = encode_set(&[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x7F,
]);

const QUERY_PERCENT_ENCODE: [bool; 128] = encode_set(&[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x22, 0x23, 0x3C, 0x3E, 0x7F,
]);

const FRAGMENT_PERCENT_ENCODE: [bool; 128] = encode_set(&[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x22, 0x3C, 0x3E, 0x60, 0x7F,
]);

const USERINFO_PERCENT_ENCODE: [bool; 128] = encode_set(&[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x22, 0x23, 0x2F, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x5B, 0x5C, 0x5D, 0x5E, 0x60,
    0x7B, 0x7C, 0x7D, 0x7F,
]);

const PATH_PERCENT_ENCODE: [bool; 128] = encode_set(&[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x22, 0x23, 0x3C, 0x3E, 0x3F, 0x5E, 0x60, 0x7B, 0x7D, 0x7F,
]);

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(name: &str, pattern: &str) -> Component {
        Component::compile(pattern, CompileOptions::for_component(name, false))
            .unwrap_or_else(|_| panic!("{name} component did not compile"))
    }

    #[test]
    fn a_literal_pathname_is_an_exact_match() {
        let component = compile("pathname", "/books");
        assert_eq!(component.kind, ComponentType::ExactMatch);
        assert_eq!(component.fast_test("/books"), Some(true));
        assert_eq!(component.fast_test("/book"), Some(false));
    }

    #[test]
    fn an_empty_pattern_is_the_empty_component() {
        let component = compile("pathname", "");
        assert_eq!(component.kind, ComponentType::Empty);
        assert_eq!(component.fast_test(""), Some(true));
        assert_eq!(component.fast_test("/"), Some(false));
    }

    #[test]
    fn a_lone_asterisk_is_a_full_wildcard() {
        let component = compile("pathname", "*");
        assert_eq!(component.kind, ComponentType::FullWildcard);
        assert_eq!(component.group_name_list, ["0"]);
    }

    #[test]
    fn a_named_group_compiles_to_a_segment_wildcard() {
        let component = compile("pathname", "/books/:id");
        assert_eq!(component.group_name_list, ["id"]);
        let source = component.regexp_source().expect("needs a regexp");
        // ada escapes `/` in the regexp it generates, so the segment wildcard is
        // `[^\/]+?` rather than `[^/]+?`; both mean the same thing to a regexp
        // engine, and matching the generated text is what keeps a diff against
        // ada readable.
        assert!(source.starts_with('^'), "{source}");
        assert!(source.contains("[^\\/]+?"), "{source}");
        assert!(source.ends_with('$'), "{source}");
    }

    #[test]
    fn a_regexp_group_is_reported_as_regexp_groups() {
        assert!(compile("pathname", r"/b/(\d+)").has_regexp_groups);
        assert!(!compile("pathname", "/b/:id").has_regexp_groups);
    }

    #[test]
    fn the_pattern_string_round_trips() {
        for (component, pattern) in [
            ("pathname", "/books/:id"),
            ("hostname", "*.example.com"),
            ("protocol", "http{s}?"),
            ("pathname", r"/b/(\d+)"),
        ] {
            let compiled = compile(component, pattern);
            assert_eq!(compiled.pattern, pattern, "{component} {pattern}");
        }
    }

    #[test]
    fn duplicate_group_names_are_rejected() {
        assert!(
            Component::compile("/:a/:a", CompileOptions::for_component("pathname", false)).is_err()
        );
    }

    #[test]
    fn an_unclosed_group_is_rejected() {
        assert!(
            Component::compile("/a{b", CompileOptions::for_component("pathname", false)).is_err()
        );
    }

    #[test]
    fn the_tokenizer_reports_escapes_and_modifiers() {
        let tokens = tokenize("/a*:b?", TokenPolicy::Strict).expect("tokenizes");
        let kinds: Vec<TokenType> = tokens.iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            [
                TokenType::Char,
                TokenType::Char,
                TokenType::Asterisk,
                TokenType::Name,
                TokenType::OtherModifier,
                TokenType::End,
            ]
        );
    }

    #[test]
    fn an_empty_init_is_all_wildcards() {
        let strings = process_init(&Init::default(), ProcessType::Pattern).expect("processes");
        assert!(strings.iter().all(|s| s.is_none()), "{strings:?}");
    }

    #[test]
    fn a_base_url_fills_the_components_it_can() {
        let init = Init {
            base_url: Some("https://example.com/a/b".to_string()),
            pathname: Some("c".to_string()),
            ..Init::default()
        };
        let strings = process_init(&init, ProcessType::Url).expect("processes");
        assert_eq!(strings[0].as_deref(), Some("https"));
        assert_eq!(strings[3].as_deref(), Some("example.com"));
        assert_eq!(strings[5].as_deref(), Some("/a/c"));
    }

    #[test]
    fn a_relative_pathname_merges_onto_the_base_directory() {
        let init = Init {
            base_url: Some("https://example.com/a/b".to_string()),
            pathname: Some("/c".to_string()),
            ..Init::default()
        };
        let strings = process_init(&init, ProcessType::Url).expect("processes");
        assert_eq!(strings[5].as_deref(), Some("/c"));
    }

    #[test]
    fn a_port_equal_to_the_scheme_default_becomes_empty() {
        let init = Init {
            protocol: Some("https".to_string()),
            port: Some("443".to_string()),
            ..Init::default()
        };
        let strings = process_init(&init, ProcessType::Url).expect("processes");
        assert_eq!(strings[4].as_deref(), Some(""));
    }

    #[test]
    fn an_out_of_range_port_is_rejected() {
        let init = Init {
            port: Some("70000".to_string()),
            ..Init::default()
        };
        assert!(process_init(&init, ProcessType::Url).is_err());
    }

    #[test]
    fn a_pathname_percent_encodes_the_path_set() {
        let init = Init {
            pathname: Some("/a b".to_string()),
            ..Init::default()
        };
        let strings = process_init(&init, ProcessType::Url).expect("processes");
        assert_eq!(strings[5].as_deref(), Some("/a%20b"));
    }
}
