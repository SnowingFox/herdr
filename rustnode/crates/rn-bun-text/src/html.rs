//! `Bun.escapeHTML(text, ...)` and `Bun.stripANSI(text)`.
//!
//! Both are small, and both have a measured detail that a reasonable
//! implementation gets wrong:
//!
//! * `escapeHTML` emits the apostrophe as **`&#x27;`** — hexadecimal — and leaves
//!   the backtick alone. Most templating helpers emit `&#39;` and escape the
//!   backtick too, and either difference alone fails a byte comparison.
//! * `stripANSI` deletes a truncated escape sequence *and everything after it*,
//!   because an unterminated sequence is still a sequence. `"a\x1bb"` is `"a"`.

/// Replaces the five characters Bun escapes, leaving the backtick and everything
/// else alone.
///
/// The order matters only in that `&` is replaced first; doing it last would
/// re-escape the ampersands the other replacements introduce.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Escapes the same set, working on UTF-16 the way a JS string is stored.
///
/// Separate from [`escape_html`] because a JS string can hold a lone surrogate,
/// which `&str` cannot represent; the JS-facing path goes through this one so
/// such a string round-trips instead of being replaced with U+FFFD.
pub fn escape_html_units(units: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(units.len());
    for unit in units {
        match *unit {
            0x26 => out.extend("&amp;".encode_utf16()),
            0x3C => out.extend("&lt;".encode_utf16()),
            0x3E => out.extend("&gt;".encode_utf16()),
            0x22 => out.extend("&quot;".encode_utf16()),
            0x27 => out.extend("&#x27;".encode_utf16()),
            other => out.push(other),
        }
    }
    out
}
