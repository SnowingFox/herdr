//! ANSI sequence parsing, and the style state `wrapAnsi`/`sliceAnsi` carry.
//!
//! Three things live here, and the split between them is the point:
//!
//! * [`strip`] removes escape sequences. It is the only one that changes text.
//! * [`track`] classifies a single sequence: is it an SGR code that opens or
//!   closes a style, or an OSC 8 hyperlink that opens or closes a link? It does
//!   not touch text; it only updates the state a caller carries across a break.
//! * [`close_code`] is the SGR code that ends a given one, which is what makes
//!   `wrapAnsi` re-open and close styles around its inserted newlines.
//!
//! # Why the close codes are not all `0`
//!
//! The measured bytes are the contract here, and they are asymmetric: wrapping
//! `"\x1b[31mred green blue\x1b[0m"` at 5 produces
//!
//! ```text
//! \x1b[31mred\x1b[39m\n\x1b[31mgreen\x1b[39m\n\x1b[31mblue\x1b[0m
//! ```
//!
//! The per-line close is `39` (default foreground), not `0` (reset everything),
//! while the final segment keeps the input's own `\x1b[0m`. An implementation
//! that closed every segment with `0` would still *render* the same and would
//! fail a byte comparison, so the mapping is reproduced exactly and the
//! asymmetry is pinned by a test.

use crate::width::{consume_ansi, is_escape_character};

/// Removes every ANSI escape sequence from `units`.
///
/// A truncated sequence removes the rest of the string: `strip("a\x1bb")` is
/// `"a"` because the `b` is consumed as part of the unterminated sequence, and
/// `strip("\x1b[31")` is `""`. That is Bun's behaviour and the surprising part
/// of it, so it is pinned by tests rather than corrected.
pub fn strip(units: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(units.len());
    let mut at = 0;
    while at < units.len() {
        if is_escape_character(u32::from(units[at])) {
            let end = consume_ansi(units, at);
            if end == at {
                // Nothing starts here (a standalone C1 terminator); keep it.
                out.push(units[at]);
                at += 1;
            } else {
                at = end;
            }
        } else {
            out.push(units[at]);
            at += 1;
        }
    }
    out
}

/// An open OSC 8 hyperlink, as the raw `params;URI` payload to re-open.
///
/// The payload is kept rather than a parsed URI so `id=` parameters survive a
/// re-open. An empty URI closes the link, which is how OSC 8 models nesting.
#[derive(Clone, Default)]
pub struct Hyperlink {
    payload: Vec<u16>,
    open: bool,
}

impl Hyperlink {
    /// Opens the link with a raw `params;URI` payload.
    pub fn open_with(&mut self, payload: Vec<u16>) {
        self.open = true;
        self.payload = payload;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.payload.clear();
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    /// The bytes that re-open this link, or `None` when it is closed.
    pub fn reopen(&self) -> Option<Vec<u16>> {
        if !self.open {
            return None;
        }
        let mut out = vec![0x1B, u16::from(b']'), u16::from(b'8'), u16::from(b';')];
        out.extend_from_slice(&self.payload);
        out.push(0x07);
        Some(out)
    }

    /// The bytes that close this link, or `None` when it is closed.
    pub fn close_sequence(&self) -> Option<Vec<u16>> {
        if !self.open {
            return None;
        }
        Some(vec![
            0x1B,
            u16::from(b']'),
            u16::from(b'8'),
            u16::from(b';'),
            u16::from(b';'),
            0x07,
        ])
    }
}

/// The style state a caller carries while walking a string.
#[derive(Clone, Default)]
pub struct StyleState {
    /// The currently open SGR code, if any. `None` means "no style".
    pub open: Option<u32>,
    pub link: Hyperlink,
}

impl StyleState {
    /// Classifies the sequence starting at `start` and returns its end index.
    ///
    /// Never returns less than `start + 1`, so a caller looping on the result
    /// always makes progress even when the sequence is malformed.
    pub fn track(&mut self, units: &[u16], start: usize) -> usize {
        let end = units.len();
        let first = u32::from(units[start]);
        let (body, is_csi, is_osc);
        match first {
            0x1B => {
                if start + 1 >= end {
                    return end;
                }
                let next = units[start + 1];
                body = start + 2;
                if next == u16::from(b'[') {
                    is_csi = true;
                    is_osc = false;
                } else if next == u16::from(b']') {
                    is_csi = false;
                    is_osc = true;
                } else if next == u16::from(b'P')
                    || next == u16::from(b'X')
                    || next == u16::from(b'^')
                    || next == u16::from(b'_')
                {
                    is_csi = false;
                    is_osc = false;
                } else if (0x20..=0x2F).contains(&next) {
                    // ESC, an intermediate byte, then one more code unit; an ESC
                    // in that position aborts and starts a new sequence.
                    return if end - start >= 3 && units[body] != 0x1B {
                        start + 3
                    } else {
                        body
                    };
                } else if (0x30..=0x7E).contains(&next) {
                    return body;
                } else {
                    return start + 1;
                }
            }
            0x9B => {
                is_csi = true;
                is_osc = false;
                body = start + 1;
            }
            0x9D => {
                is_csi = false;
                is_osc = true;
                body = start + 1;
            }
            0x90 | 0x98 | 0x9E | 0x9F => {
                is_csi = false;
                is_osc = false;
                body = start + 1;
            }
            _ => return start + 1,
        }

        if is_csi {
            // ECMA-48 §5.4: parameters up to a final byte in 0x40-0x7E; ESC, CAN,
            // SUB and the C1 ST abort the sequence.
            let mut sequence_end = end;
            for (at, unit) in units.iter().enumerate().take(end).skip(body) {
                if *unit == 0x1B {
                    sequence_end = at;
                    break;
                }
                if (0x40..=0x7E).contains(unit) || *unit == 0x18 || *unit == 0x1A || *unit == 0x9C {
                    sequence_end = at + 1;
                    break;
                }
            }
            if let Some(code) = parse_sgr(units, body, sequence_end) {
                // `0` and `39` both mean "nothing open any more"; `39` is
                // explicitly the default-foreground reset, and treating it as
                // an open code would emit `\x1b[39m` on every re-open.
                self.open = if code == 0 || code == 39 {
                    None
                } else {
                    Some(code)
                };
            }
            return sequence_end;
        }

        // An OSC ends at BEL; OSC and the control strings end at ST (C1 or
        // ESC \). ESC, CAN and SUB abort the string, discarding its payload.
        let mut sequence_end = end;
        let mut payload_end = end;
        let mut terminated = false;
        for at in body..end {
            let unit = units[at];
            if unit == 0x1B {
                payload_end = at;
                terminated = at + 1 < end && units[at + 1] == u16::from(b'\\');
                sequence_end = if terminated { at + 2 } else { at };
                break;
            }
            if (is_osc && unit == 0x07) || unit == 0x9C {
                payload_end = at;
                sequence_end = at + 1;
                terminated = true;
                break;
            }
            if unit == 0x18 || unit == 0x1A {
                payload_end = at;
                sequence_end = at + 1;
                break;
            }
        }

        // A hyperlink is OSC 8, and only when it is properly terminated: an
        // aborted string leaves the existing link alone.
        if !is_osc
            || !terminated
            || payload_end.saturating_sub(body) < 2
            || units[body] != u16::from(b'8')
            || units[body + 1] != u16::from(b';')
        {
            return sequence_end;
        }

        let params = body + 2;
        let mut uri = params;
        while uri < payload_end && units[uri] != u16::from(b';') {
            uri += 1;
        }
        if uri == payload_end {
            return sequence_end; // malformed: no URI field
        }
        uri += 1;
        if uri == payload_end {
            self.link.close();
        } else {
            self.link.open_with(units[params..payload_end].to_vec());
        }
        sequence_end
    }

    /// The sequences that close the current style and hyperlink, in the order
    /// `wrapAnsi` emits before a newline.
    pub fn close_sequences(&self) -> Vec<u16> {
        let mut out = Vec::new();
        if let Some(close) = self.link.close_sequence() {
            out.extend_from_slice(&close);
        }
        if let Some(code) = self.open {
            if let Some(close) = close_code(code) {
                out.extend_from_slice(&sgr(close));
            }
        }
        out
    }

    /// The sequences that re-open the current style and hyperlink, in the order
    /// `wrapAnsi` emits after a newline.
    pub fn reopen_sequences(&self) -> Vec<u16> {
        let mut out = Vec::new();
        if let Some(code) = self.open {
            if close_code(code).is_some() {
                out.extend_from_slice(&sgr(code));
            }
        }
        if let Some(reopen) = self.link.reopen() {
            out.extend_from_slice(&reopen);
        }
        out
    }
}

/// The escape sequence for one SGR code.
pub fn sgr(code: u32) -> Vec<u16> {
    let mut out = vec![0x1B, u16::from(b'[')];
    out.extend(code.to_string().encode_utf16());
    out.push(u16::from(b'm'));
    out
}

/// Parses a CSI parameter body as a single numeric SGR code.
///
/// Returns `None` for anything that is not digits followed by `m`, which is
/// every non-SGR CSI (`\x1b[2A`, `\x1b[K`): those must not disturb the style.
fn parse_sgr(units: &[u16], body: usize, end: usize) -> Option<u32> {
    let mut code: u32 = 0;
    let mut at = body;
    while at < end {
        let unit = units[at];
        if (u16::from(b'0')..=u16::from(b'9')).contains(&unit) {
            code = code
                .checked_mul(10)?
                .checked_add(u32::from(unit - u16::from(b'0')))?;
        } else if unit == u16::from(b'm') {
            return Some(code);
        } else {
            return None;
        }
        at += 1;
    }
    None
}

/// The SGR code that ends `open`, or `None` when there is no single one.
///
/// `None` is not "no state": it makes a caller fall back to re-emitting nothing
/// and never emitting a close, which is what Bun does for codes it does not know
/// (`\x1b[99m` survives a wrap unchanged and is not re-opened per line).
pub fn close_code(open: u32) -> Option<u32> {
    Some(match open {
        1 | 2 => 22,
        3 | 20 => 23,
        4 | 21 => 24,
        5 | 6 => 25,
        7 => 27,
        8 => 28,
        9 => 29,
        30..=38 | 90..=97 => 39,
        40..=48 | 100..=107 => 49,
        51 | 52 => 54,
        53 => 55,
        58 => 59,
        73 | 74 => 75,
        _ => return None,
    })
}

/// The attribute slot an SGR open code belongs to.
///
/// Styles in the same slot replace each other, so `\x1b[31m` then `\x1b[32m`
/// leaves one foreground active rather than two. The slot is normally the close
/// code — every foreground shares `39` — but the closes that clear *two*
/// independent attributes (`22` bold+dim, `23` italic+fraktur, `24`
/// underline+double-underline, `54` framed+encircled) must be keyed by their open
/// code instead, or turning on bold would silently turn off dim.
pub fn slot_of(open_code: u32) -> u32 {
    match close_code(open_code) {
        Some(close @ (22 | 23 | 24 | 54)) => {
            let _ = close;
            open_code
        }
        Some(close) => close,
        // An unknown code has no close mapping; keying it by itself means it
        // does not displace anything and is closed by a full reset.
        None => open_code,
    }
}
pub fn is_reset_code(code: u32) -> bool {
    matches!(
        code,
        0 | 22 | 23 | 24 | 25 | 27 | 28 | 29 | 39 | 49 | 54 | 55 | 59 | 75
    )
}

/// Encodes a UTF-16 slice for diagnostics, escaping the non-printables.
///
/// Only used by tests and error messages, where `Debug` on a `Vec<u16>` would
/// report code units and hide the fact that a mismatch is one escape byte.
pub fn describe(units: &[u16]) -> String {
    let mut out = String::new();
    for unit in units {
        if *unit < 0x20 || (0x7F..=0xA0).contains(unit) {
            out.push_str(&format!("\\u{{{unit:04X}}}"));
        } else {
            out.push_str(&String::from_utf16_lossy(&[*unit]));
        }
    }
    out
}
