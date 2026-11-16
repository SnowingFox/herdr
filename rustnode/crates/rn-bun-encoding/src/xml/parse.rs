//! The XML scanner.
//!
//! Messages are Bun's measured set, and several are specific enough that a
//! generic XML crate's output could not be mapped onto them:
//!
//! ```text
//! <a><b></a>          Expected closing tag </b> but found </a>
//! <a                  Expected an attribute name, '>' or '/>' in the start tag but found end of input
//! <a>                 Missing closing tag for element 'a'
//! <a/><b/>            Only one root element is allowed
//! <a/>t               Unexpected 't' after the root element
//! <a x="1" x="2"/>    Duplicate attribute 'x'
//! <a>&foo;</a>        Entity 'foo' is not declared
//! <a>a & b</a>        Expected an entity name after '&' but found space
//! <a>a < b</a>        Expected an element name after '<' but found space
//! <a/><!DOCTYPE a>    Unexpected '<!DOCTYPE' after the root element
//! ```

use crate::xml::Element;

/// Parses a document into its root element.
pub fn document(input: &str) -> Result<crate::value::Value, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        at: 0,
    };
    if parser.bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        parser.at = 3;
    }
    let root = parser.document()?;
    // The parsed shape is the single top-level key naming the root, not the
    // root's own contents: `XML.parse("<root><a>1</a></root>")` is
    // `{root: {a: "1"}}`, and `stringify` is the inverse of that.
    let name = root.name.clone();
    let mut map = crate::value::Map::new();
    map.push(name, root.to_value());
    Ok(crate::value::Value::map(map))
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

    /// What the cursor is looking at, for a message: the next character, or the
    /// words Bun uses for the end of input.
    fn found(&self) -> String {
        match self.peek() {
            None => "end of input".to_string(),
            // A space is named, not quoted, and a `/` that begins `/>` is
            // reported as the two-character sequence.
            Some(b' ') => "space".to_string(),
            Some(b'/') if self.peek_at(1) == Some(b'>') => "'/>'".to_string(),
            Some(byte) => format!("'{}'", byte as char),
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

    fn document(&mut self) -> Result<Element, String> {
        // The declaration, comments and doctype may precede the root.
        let mut declaration_seen = false;
        loop {
            self.skip_whitespace();
            if self.bytes[self.at..].starts_with(b"<?xml") && !declaration_seen {
                self.declaration()?;
                declaration_seen = true;
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<?") {
                self.processing_instruction()?;
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<!--") {
                self.comment()?;
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<!DOCTYPE") {
                self.doctype()?;
                continue;
            }
            break;
        }
        if self.bytes[self.at..].starts_with(b"<?xml") {
            return Err("'<?xml' is reserved for the XML declaration, which is only allowed at the very start of the document".to_string());
        }
        let Some(byte) = self.peek() else {
            return Err("XML document must have a root element".to_string());
        };
        if byte != b'<' {
            return Err(format!(
                "Expected the root element but found '{}'",
                self.word()
            ));
        }
        let root = self.element()?;
        // Only comments and processing instructions may follow the root.
        loop {
            self.skip_whitespace();
            if self.at >= self.bytes.len() {
                return Ok(root);
            }
            if self.bytes[self.at..].starts_with(b"<!--") {
                self.comment()?;
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<?") {
                self.processing_instruction()?;
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<!DOCTYPE") {
                return Err("Unexpected '<!DOCTYPE' after the root element".to_string());
            }
            if self.bytes[self.at..].starts_with(b"<") {
                return Err("Only one root element is allowed".to_string());
            }
            return Err(format!(
                "Unexpected '{}' after the root element",
                self.peek().map(|byte| byte as char).unwrap_or(' ')
            ));
        }
    }

    /// The run of characters that could be a name, for a message.
    fn word(&mut self) -> String {
        let start = self.at;
        while self.peek().is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
        }) {
            self.at += 1;
        }
        if self.at == start {
            String::from_utf8_lossy(&self.bytes[start..(start + 1).min(self.bytes.len())])
                .into_owned()
        } else {
            String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned()
        }
    }

    fn declaration(&mut self) -> Result<(), String> {
        self.at += "<?xml".len();
        self.skip_whitespace();
        if !self.bytes[self.at..].starts_with(b"version") {
            return Err("The XML declaration must specify the version".to_string());
        }
        // Skip to the closing `?>`.
        while self.at < self.bytes.len() {
            if self.bytes[self.at..].starts_with(b"?>") {
                self.at += 2;
                return Ok(());
            }
            self.at += 1;
        }
        Err("Unterminated XML declaration".to_string())
    }

    fn processing_instruction(&mut self) -> Result<(), String> {
        self.at += 2;
        let target = self.word();
        if target.eq_ignore_ascii_case("xml") {
            return Err("'<?xml' is reserved for the XML declaration, which is only allowed at the very start of the document".to_string());
        }
        loop {
            match self.peek() {
                None => {
                    return Err(
                        "Expected whitespace or '?>' after the processing instruction target but found end of input"
                            .to_string(),
                    )
                }
                Some(b'?') if self.peek_at(1) == Some(b'>') => {
                    self.at += 2;
                    return Ok(());
                }
                Some(b'<') => {
                    return Err(
                        "Expected whitespace or '?>' after the processing instruction target but found '<'"
                            .to_string(),
                    )
                }
                Some(_) => self.at += 1,
            }
        }
    }

    fn comment(&mut self) -> Result<(), String> {
        self.at += "<!--".len();
        loop {
            if self.at >= self.bytes.len() {
                return Err("Unterminated comment".to_string());
            }
            if self.bytes[self.at..].starts_with(b"-->") {
                self.at += 3;
                return Ok(());
            }
            self.at += 1;
        }
    }

    fn doctype(&mut self) -> Result<(), String> {
        self.at += "<!DOCTYPE".len();
        // A doctype may carry an internal subset in `[…]`, which can contain `>`.
        let mut depth = 0usize;
        loop {
            match self.bump() {
                None => return Err("Unterminated document type declaration".to_string()),
                Some(b'[') => depth += 1,
                Some(b']') => depth = depth.saturating_sub(1),
                Some(b'>') if depth == 0 => return Ok(()),
                Some(_) => {}
            }
        }
    }

    /// One element, starting at `<`.
    fn element(&mut self) -> Result<Element, String> {
        self.at += 1;
        let name = self.name("Expected an element name after '<' but found")?;
        let mut element = Element {
            name,
            attributes: Vec::new(),
            children: Vec::new(),
            texts: Vec::new(),
            // One slot for the text before the first child; `element()` pushes a
            // new one whenever a child is added.
            runs: vec![Vec::new()],
        };
        // Attributes, up to `>` or `/>`.
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => {
                    return Err(
                        "Expected an attribute name, '>' or '/>' in the start tag but found end of input"
                            .to_string(),
                    )
                }
                Some(b'>') => {
                    self.at += 1;
                    break;
                }
                Some(b'/') if self.peek_at(1) == Some(b'>') => {
                    self.at += 2;
                    // A self-closing element is empty.
                    return Ok(element);
                }
                Some(byte) if is_name_start(byte) => {
                    // A qualified name keeps its colon: `xmlns:ns="urn:x"` is one
                    // attribute and Bun reports it as `@xmlns:ns`.
                    let attribute = self.name("Expected an attribute name, '>' or '/>' in the start tag but found")?;
                    self.skip_whitespace();
                    if self.peek() != Some(b'=') {
                        return Err(format!(
                            "Expected '=' after the attribute name but found {}",
                            self.found()
                        ));
                    }
                    self.at += 1;
                    self.skip_whitespace();
                    let quote = match self.peek() {
                        Some(b'"') | Some(b'\'') => self.bump().unwrap_or(b'"'),
                        _ => {
                            return Err(format!(
                                "Expected a quoted attribute value but found {}",
                                self.found()
                            ))
                        }
                    };
                    // An attribute value's whitespace is normalised to a single
                    // space: `x="1\n2"` is `"1 2"`.
                    let value = self.attribute_value(quote)?;
                    if element.attributes.iter().any(|(name, _)| *name == attribute) {
                        return Err(format!("Duplicate attribute '{attribute}'"));
                    }
                    element.attributes.push((attribute, value));
                }
                Some(_) => {
                    return Err(format!(
                        "Expected an attribute name, '>' or '/>' in the start tag but found {}",
                        self.found()
                    ))
                }
            }
        }
        // Content.
        loop {
            if self.at >= self.bytes.len() {
                return Err(format!(
                    "Missing closing tag for element '{}'",
                    element.name
                ));
            }
            if self.bytes[self.at..].starts_with(b"</") {
                self.at += 2;
                let closing = self.name("Expected an element name after '</' but found")?;
                self.skip_whitespace();
                if self.peek() != Some(b'>') {
                    return Err(format!(
                        "Expected '>' to end the closing tag but found {}",
                        self.found()
                    ));
                }
                self.at += 1;
                if closing != element.name {
                    return Err(format!(
                        "Expected closing tag </{}> but found </{closing}>",
                        element.name
                    ));
                }
                return Ok(element);
            }
            if self.bytes[self.at..].starts_with(b"<![CDATA[") {
                self.at += "<![CDATA[".len();
                let start = self.at;
                loop {
                    if self.at >= self.bytes.len() {
                        return Err("Unterminated CDATA section".to_string());
                    }
                    if self.bytes[self.at..].starts_with(b"]]>") {
                        let text =
                            String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
                        self.at += 3;
                        push_text(&mut element, text);
                        break;
                    }
                    self.at += 1;
                }
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<!--") {
                self.comment()?;
                continue;
            }
            if self.bytes[self.at..].starts_with(b"<?") {
                self.processing_instruction()?;
                continue;
            }
            if self.peek() == Some(b'<') {
                element.children.push(self.element()?);
                element.runs.push(Vec::new());
                continue;
            }
            let text = self.text()?;
            if !text.is_empty() {
                push_text(&mut element, text);
            }
        }
    }

    /// A name, or the error message given when none is there.
    fn name(&mut self, prefix: &str) -> Result<String, String> {
        let start = self.at;
        if !self.peek().is_some_and(is_name_start) {
            return Err(format!("{prefix} {}", self.found()));
        }
        while self.peek().is_some_and(is_name_part) {
            self.at += 1;
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned())
    }

    fn attribute_value(&mut self, quote: u8) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated attribute value".to_string()),
                Some(byte) if byte == quote => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'&') => out.push_str(&self.entity()?),
                Some(b'<') => {
                    // A raw `<` in an attribute value is not legal XML, and Bun
                    // reports it as an unfinished name rather than allowing it.
                    return Err(format!(
                        "Expected an element name after '<' but found {}",
                        {
                            self.at += 1;
                            self.found()
                        }
                    ));
                }
                // Whitespace inside an attribute value is collapsed to a space,
                // which is XML's attribute-value normalisation.
                Some(b'\n') | Some(b'\r') | Some(b'\t') => {
                    self.at += 1;
                    out.push(' ');
                }
                Some(_) => out.push(self.take_char()),
            }
        }
    }

    /// A run of character data, up to the next markup.
    fn text(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Ok(out),
                Some(b'<') => return Ok(out),
                Some(b'&') => out.push_str(&self.entity()?),
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

    /// An entity or character reference, at `&`.
    fn entity(&mut self) -> Result<String, String> {
        self.at += 1;
        if self.peek() == Some(b'#') {
            self.at += 1;
            let hex = matches!(self.peek(), Some(b'x'));
            if hex {
                self.at += 1;
            }
            let start = self.at;
            while self.peek().is_some_and(|byte| {
                if hex {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
            }) {
                self.at += 1;
            }
            let digits = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
            if self.peek() != Some(b';') {
                return Err(format!(
                    "Invalid character reference: expected a number followed by ';' but found {}",
                    self.found()
                ));
            }
            self.at += 1;
            let radix = if hex { 16 } else { 10 };
            let code = u32::from_str_radix(&digits, radix).map_err(|_| {
                format!(
                    "Invalid character reference: expected a number followed by ';' but found {}",
                    self.found()
                )
            })?;
            return Ok(char::from_u32(code)
                .map(|character| character.to_string())
                .unwrap_or_else(|| "\u{fffd}".to_string()));
        }
        let start = self.at;
        while self.peek().is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
        }) {
            self.at += 1;
        }
        let name = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
        if name.is_empty() {
            return Err(format!(
                "Expected an entity name after '&' but found {}",
                match self.peek() {
                    Some(b' ') => "space".to_string(),
                    None => "end of input".to_string(),
                    Some(byte) => format!("'{}'", byte as char),
                }
            ));
        }
        if self.peek() != Some(b';') {
            return Err(format!(
                "Expected ';' after the entity name but found {}",
                self.found()
            ));
        }
        self.at += 1;
        match name.as_str() {
            "lt" => Ok("<".to_string()),
            "gt" => Ok(">".to_string()),
            "amp" => Ok("&".to_string()),
            "quot" => Ok("\"".to_string()),
            "apos" => Ok("'".to_string()),
            _ => Err(format!("Entity '{name}' is not declared")),
        }
    }
}

/// Records a text run in both the flat list and the positional one.
///
/// `texts` is what the concatenated `#text` is built from; `runs` is what decides
/// where `#text` sits in the key order.
fn push_text(element: &mut Element, text: String) {
    element.texts.push(text.clone());
    if let Some(last) = element.runs.last_mut() {
        last.push(text);
    }
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b':' || byte >= 0x80
}

fn is_name_part(byte: u8) -> bool {
    // `:` belongs to a qualified name, which is why `xmlns:ns` is one attribute
    // named `xmlns:ns` and not a prefix with a colon in it.
    is_name_start(byte) || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
}
