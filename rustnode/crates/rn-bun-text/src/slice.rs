//! `Bun.sliceAnsi(text, start, end, options?)`.
//!
//! Slicing is by **column**, not by code unit, and the result re-asserts the
//! ANSI state that was active at the cut. That is what makes
//! `sliceAnsi("\x1b[31mabcdef\x1b[0m", 1, 3)` produce
//! `"\x1b[31mbc\x1b[39m"`: the foreground is re-opened at the start of the slice
//! and closed at the end with `39`, not `0`.
//!
//! # Style state is a slot set, not one code
//!
//! `wrapAnsi` tracks a single open code; `sliceAnsi` tracks a *set*, keyed by
//! attribute slot, because a slice can begin with several styles active. Closing
//! them must happen in reverse order and a shared close code (`22` ends both bold
//! and dim) is emitted once:
//!
//! ```text
//! sliceAnsi("\x1b[1m\x1b[31mabcdef\x1b[0m", 2, 4)
//!   => "\x1b[1m\x1b[31mcd\x1b[39m\x1b[22m"
//! ```
//!
//! An implementation that closed with a single `\x1b[0m` would render the same
//! and fail a byte comparison, so the slot model is reproduced rather than
//! simplified.
//!
//! # Pending sequences
//!
//! An escape sequence encountered *after* the slice has started is not emitted
//! immediately: the next visible codepoint decides whether it belongs to this
//! slice (then everything is flushed) or to a cut boundary (then only close
//! codes are kept). Deferring is what makes `sliceAnsi("\x1b[31mabc\x1b[0mdef", 1, 5)`
//! keep the interior reset while dropping a trailing opener.

use crate::ansi::{close_code, is_reset_code, sgr, slot_of, StyleState};
use crate::width::{
    codepoint_width, consume_ansi, grapheme_break_state, is_escape_character, visible_width,
    BreakState,
};

/// Options for `sliceAnsi`. The position arguments are already resolved to
/// column bounds by the caller.
#[derive(Clone, Copy, Debug, Default)]
pub struct SliceOptions {
    pub ambiguous_is_narrow: bool,
}

/// One SGR attribute, in the order it was opened.
struct StyleEntry {
    slot: u32,
    open: Vec<u16>,
    close: Vec<u16>,
}

#[derive(Default)]
struct StyleStack {
    entries: Vec<StyleEntry>,
}

impl StyleStack {
    fn reset(&mut self) {
        self.entries.clear();
    }

    fn end(&mut self, code: u32) {
        let close = sgr(code);
        self.entries.retain(|entry| entry.close != close);
    }

    fn start(&mut self, slot: u32, open: Vec<u16>, close: Vec<u16>) {
        self.entries.retain(|entry| entry.slot != slot);
        self.entries.push(StyleEntry { slot, open, close });
    }

    fn open_sequences(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for entry in &self.entries {
            out.extend_from_slice(&entry.open);
        }
        out
    }

    /// Closes in reverse order, emitting a shared close code only once.
    fn close_sequences(&self) -> Vec<u16> {
        let mut out = Vec::new();
        let mut emitted: Vec<&Vec<u16>> = Vec::new();
        for entry in self.entries.iter().rev() {
            if emitted.iter().any(|seen| **seen == entry.close) {
                continue;
            }
            out.extend_from_slice(&entry.close);
            emitted.push(&entry.close);
        }
        out
    }
}

/// Whether a multi-parameter SGR sequence should be kept at a cut boundary.
///
/// Bun keeps a trailing sequence only when it *closes* something that is open.
/// `is_reset_code` covers the single-code form; this covers `\x1b[0;39m` and the
/// extended-colour fragments that also appear as one CSI.
fn closes_something(units: &[u16], body: usize, end: usize, stack: &StyleStack) -> bool {
    let mut code: u32 = 0;
    let mut saw_digit = false;
    let mut at = body;
    while at < end {
        let unit = units[at];
        if (u16::from(b'0')..=u16::from(b'9')).contains(&unit) {
            code = code
                .saturating_mul(10)
                .saturating_add(u32::from(unit - u16::from(b'0')));
            saw_digit = true;
        } else if unit == u16::from(b';') {
            if saw_digit && is_reset_code(code) {
                return true;
            }
            code = 0;
            saw_digit = false;
        } else {
            break;
        }
        at += 1;
    }
    if saw_digit && is_reset_code(code) {
        return true;
    }
    // An unknown close is still an effect if something is open; Bun's fallback
    // is "keep it", and dropping it would leave the slice unterminated.
    !stack.entries.is_empty() && saw_digit
}

/// Applies one CSI SGR sequence to the stack.
fn apply_sgr(stack: &mut StyleStack, units: &[u16], start: usize, end: usize) {
    let is_c1 = units[start] == 0x9B;
    let body = if is_c1 { start + 1 } else { start + 2 };

    // Parse the parameter list. A colon form (`38:2:...`) is opaque: Bun stores
    // it with the close code of its first parameter rather than expanding it.
    let mut codes: Vec<u32> = Vec::new();
    let mut has_colon = false;
    let mut current: u32 = 0;
    let mut saw_digit = false;
    let mut at = body;
    while at < end {
        let unit = units[at];
        if (u16::from(b'0')..=u16::from(b'9')).contains(&unit) {
            current = current
                .saturating_mul(10)
                .saturating_add(u32::from(unit - u16::from(b'0')));
            saw_digit = true;
        } else if unit == u16::from(b';') {
            codes.push(if saw_digit { current } else { 0 });
            current = 0;
            saw_digit = false;
        } else if unit == u16::from(b':') {
            has_colon = true;
        } else {
            break;
        }
        at += 1;
    }
    if saw_digit {
        codes.push(current);
    }
    if codes.is_empty() {
        // `\x1b[m` is `\x1b[0m`.
        codes.push(0);
    }

    if has_colon {
        let first = codes.first().copied().unwrap_or(0);
        let close = close_code(first).unwrap_or(0);
        let open = units[start..end].to_vec();
        let close_sequence = if close == 0 { sgr(0) } else { sgr(close) };
        let slot = if close == 0 { first } else { close };
        stack.start(slot, open, close_sequence);
        return;
    }

    let mut index = 0;
    while index < codes.len() {
        let code = codes[index];
        if code == 0 {
            stack.reset();
            index += 1;
            continue;
        }
        // `38`, `48` and `58` introduce an extended colour whose parameters
        // follow on the stack: `38;5;N` is three parameters and `38;2;R;G;B` is
        // five. Treating them one at a time would store `5` and `196` as
        // separate attributes.
        if code == 38 || code == 48 || code == 58 {
            let close = close_code(code).unwrap_or(0);
            let span = match codes.get(index + 1).copied() {
                Some(5) if index + 2 < codes.len() => 3,
                Some(2) if index + 4 < codes.len() => 5,
                _ => 1,
            };
            let open = if span == 1 {
                sgr(code)
            } else {
                let mut sequence = vec![0x1B, u16::from(b'[')];
                for (offset, component) in codes[index..index + span].iter().enumerate() {
                    if offset > 0 {
                        sequence.push(u16::from(b';'));
                    }
                    sequence.extend(component.to_string().encode_utf16());
                }
                sequence.push(u16::from(b'm'));
                sequence
            };
            stack.start(slot_of(code), open, sgr(close));
            index += span;
            continue;
        }
        if is_reset_code(code) {
            stack.end(code);
            index += 1;
            continue;
        }
        // An open code. A code with no close mapping is closed by a full reset,
        // which is what makes `\x1b[99m` survive a slice and terminate with
        // `\x1b[0m`.
        let close = close_code(code).map(sgr).unwrap_or_else(|| sgr(0));
        stack.start(slot_of(code), sgr(code), close);
        index += 1;
    }
}

/// A deferred escape sequence, and whether it opens or closes a hyperlink.
struct Pending {
    start: usize,
    end: usize,
    is_csi: bool,
    hyperlink: Option<bool>,
}

/// Slices `units` to the columns `[start, end)`.
///
/// `start` and `end` are already resolved from the caller's (possibly negative)
/// doubles; `end` of `usize::MAX` means "to the end of the string".
pub fn slice(
    units: &[u16],
    start_column: usize,
    end_column: usize,
    options: SliceOptions,
) -> Vec<u16> {
    if units.is_empty() {
        return Vec::new();
    }
    let end_unbounded = end_column == usize::MAX;

    let mut result: Vec<u16> = Vec::with_capacity(units.len());
    let mut stack = StyleStack::default();
    let mut link = StyleState::default();
    let mut pending: Vec<Pending> = Vec::new();

    // The column at which the *next* cluster starts.
    let mut position = 0usize;
    let mut include = false;
    let ambiguous_as_wide = !options.ambiguous_is_narrow;
    let mut cluster = ClusterWidth::default();
    let mut break_state = BreakState::default();
    let mut previous_cp: Option<u32> = None;
    let mut saw_cut = false;

    let mut at = 0usize;
    while at < units.len() {
        let unit = units[at];
        if is_escape_character(u32::from(unit)) {
            let sequence_end = consume_ansi(units, at);
            let sequence_end = if sequence_end > at {
                sequence_end
            } else {
                at + 1
            };
            let is_csi = is_csi_sequence(units, at);
            let hyperlink = hyperlink_effect(units, at, sequence_end);
            if !include {
                // Before the slice starts, only the state matters.
                if let Some(opens) = hyperlink {
                    if opens {
                        link.link
                            .open_with(hyperlink_payload(units, at, sequence_end));
                    } else {
                        link.link.close();
                    }
                } else if is_csi {
                    apply_sgr(&mut stack, units, at, sequence_end);
                }
            } else {
                pending.push(Pending {
                    start: at,
                    end: sequence_end,
                    is_csi,
                    hyperlink,
                });
            }
            at = sequence_end;
            continue;
        }

        let Some((cp, length)) = decode_at(units, at) else {
            at += 1;
            continue;
        };

        let should_break = match previous_cp {
            None => true,
            Some(previous_cp) => {
                if previous_cp == 0x0D && cp == 0x0A {
                    false
                } else if previous_cp == 0x0D || previous_cp == 0x0A || cp == 0x0D || cp == 0x0A {
                    break_state = BreakState::default();
                    true
                } else {
                    grapheme_break_state(previous_cp, cp, &mut break_state)
                }
            }
        };

        if should_break {
            position += cluster.width();
            if !end_unbounded && position >= end_column {
                saw_cut = true;
                flush_pending(&pending, true, &mut result, &mut stack, &mut link, units);
                pending.clear();
                break;
            }
            if !include && position >= start_column {
                include = true;
                result.extend_from_slice(&stack.open_sequences());
                if let Some(reopen) = link.link.reopen() {
                    result.extend_from_slice(&reopen);
                }
            }
            if include {
                flush_pending(&pending, false, &mut result, &mut stack, &mut link, units);
                result.extend_from_slice(&units[at..at + length]);
            }
            // Flushed entries must not be emitted again; `pending` is a queue of
            // sequences seen since the last visible codepoint, not a log.
            pending.clear();
            cluster.reset(cp, ambiguous_as_wide);
        } else {
            if include {
                flush_pending(&pending, false, &mut result, &mut stack, &mut link, units);
                result.extend_from_slice(&units[at..at + length]);
            }
            // Flushed entries must not be emitted again; `pending` is a queue of
            // sequences seen since the last visible codepoint, not a log.
            pending.clear();
            cluster.add(cp, ambiguous_as_wide);
        }

        previous_cp = Some(cp);
        at += length;
    }

    if !saw_cut {
        position += cluster.width();
        let at_end = !end_unbounded && position >= end_column;
        // Trailing sequences are kept in full when the whole string fit inside
        // the range, and filtered to close-only codes when it did not.
        flush_pending(&pending, at_end, &mut result, &mut stack, &mut link, units);
    }

    if let Some(close) = link.link.close_sequence() {
        result.extend_from_slice(&close);
    }
    result.extend_from_slice(&stack.close_sequences());

    if !include {
        return Vec::new();
    }
    result
}

fn flush_pending(
    pending: &[Pending],
    close_only: bool,
    result: &mut Vec<u16>,
    stack: &mut StyleStack,
    link: &mut StyleState,
    units: &[u16],
) {
    for entry in pending {
        let emit = match entry.hyperlink {
            Some(opens) => {
                if close_only && (opens || !link.link.is_open()) {
                    false
                } else {
                    if opens {
                        link.link
                            .open_with(hyperlink_payload(units, entry.start, entry.end));
                    } else {
                        link.link.close();
                    }
                    true
                }
            }
            None if entry.is_csi => {
                if close_only {
                    let body = if units[entry.start] == 0x9B {
                        entry.start + 1
                    } else {
                        entry.start + 2
                    };
                    let keep = closes_something(units, body, entry.end.saturating_sub(1), stack);
                    if keep {
                        apply_sgr(stack, units, entry.start, entry.end);
                    }
                    keep
                } else {
                    apply_sgr(stack, units, entry.start, entry.end);
                    true
                }
            }
            // Non-SGR control sequences contribute no style; they are simply
            // passed through unless the slice is being closed off.
            None => !close_only,
        };
        if emit {
            result.extend_from_slice(&units[entry.start..entry.end]);
        }
    }
}

fn is_csi_sequence(units: &[u16], start: usize) -> bool {
    match units[start] {
        0x9B => true,
        0x1B => units.get(start + 1) == Some(&u16::from(b'[')),
        _ => false,
    }
}

/// Whether an OSC 8 sequence opens (`Some(true)`) or closes (`Some(false)`) a
/// hyperlink; `None` for anything else.
fn hyperlink_effect(units: &[u16], start: usize, end: usize) -> Option<bool> {
    let is_osc = match units[start] {
        0x9D => true,
        0x1B => units.get(start + 1) == Some(&u16::from(b']')),
        _ => false,
    };
    if !is_osc {
        return None;
    }
    let body = if units[start] == 0x9D {
        start + 1
    } else {
        start + 2
    };
    // The payload runs to the terminator; BEL and ST both end it.
    let mut payload_end = end;
    if payload_end > body {
        let last = units[payload_end - 1];
        if last == 0x07 {
            payload_end -= 1;
        } else if last == 0x9C {
            payload_end -= 1;
        } else if payload_end >= body + 2 && units[payload_end - 1] == u16::from(b'\\') {
            payload_end -= 2;
        }
    }
    if payload_end < body + 2
        || units[body] != u16::from(b'8')
        || units[body + 1] != u16::from(b';')
    {
        return None;
    }
    let mut uri = body + 2;
    while uri < payload_end && units[uri] != u16::from(b';') {
        uri += 1;
    }
    if uri == payload_end {
        return None;
    }
    Some(uri + 1 < payload_end)
}

fn hyperlink_payload(units: &[u16], start: usize, end: usize) -> Vec<u16> {
    let body = if units[start] == 0x9D {
        start + 1
    } else {
        start + 2
    };
    let mut payload_end = end;
    if payload_end > body {
        let last = units[payload_end - 1];
        if last == 0x07 || last == 0x9C {
            payload_end -= 1;
        } else if payload_end >= body + 2 && units[payload_end - 1] == u16::from(b'\\') {
            payload_end -= 2;
        }
    }
    // `params;URI`, without the leading `8;`.
    units[body + 2..payload_end].to_vec()
}

/// The width a cluster resolves to, mirroring `crate::width`'s accumulator.
#[derive(Default)]
struct ClusterWidth {
    width: usize,
    first: u32,
    count: u32,
    base: u8,
    emoji_base: bool,
    keycap: bool,
    regional_indicator: bool,
    skin_tone: bool,
    zwj: bool,
    vs15: bool,
    vs16: bool,
}

impl ClusterWidth {
    fn reset(&mut self, cp: u32, ambiguous_as_wide: bool) {
        *self = Self::default();
        self.first = cp;
        self.count = 1;
        if cp < 0x80 {
            let width = u8::from((0x20..0x7F).contains(&cp));
            self.base = width;
            self.width = usize::from(width);
            return;
        }
        let width = codepoint_width(cp, ambiguous_as_wide);
        self.base = width;
        self.width = usize::from(width);
        self.emoji_base = crate::width::is_emoji_presentation(cp);
        self.keycap = cp == 0x20E3;
        self.regional_indicator = (0x1F1E6..=0x1F1FF).contains(&cp);
        self.skin_tone = (0x1F3FB..=0x1F3FF).contains(&cp);
        self.zwj = cp == 0x200D;
    }

    fn add(&mut self, cp: u32, ambiguous_as_wide: bool) {
        self.count = self.count.saturating_add(1);
        self.keycap |= cp == 0x20E3;
        self.regional_indicator |= (0x1F1E6..=0x1F1FF).contains(&cp);
        self.skin_tone |= (0x1F3FB..=0x1F3FF).contains(&cp);
        self.zwj |= cp == 0x200D;
        self.vs15 |= cp == 0xFE0E;
        self.vs16 |= cp == 0xFE0F;
        self.width = (self.width + usize::from(codepoint_width(cp, ambiguous_as_wide))).min(1023);
    }

    fn width(&self) -> usize {
        if self.count == 0 {
            return 0;
        }
        if self.regional_indicator && self.count >= 2 {
            return 2;
        }
        if self.keycap {
            return 2;
        }
        if self.regional_indicator {
            return 1;
        }
        if self.emoji_base && (self.skin_tone || self.zwj) {
            return 2;
        }
        if self.vs15 || self.vs16 {
            if self.base == 2
                || (self.vs16 && (self.emoji_base || self.first == 0xA9 || self.first == 0xAE))
            {
                return 2;
            }
            return usize::from(self.base);
        }
        self.width
    }
}

fn decode_at(units: &[u16], at: usize) -> Option<(u32, usize)> {
    let unit = *units.get(at)?;
    if (0xD800..0xDC00).contains(&unit) {
        match units.get(at + 1).copied() {
            Some(trail) if (0xDC00..0xE000).contains(&trail) => Some((
                0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(trail) - 0xDC00),
                2,
            )),
            _ => None,
        }
    } else if (0xDC00..0xE000).contains(&unit) {
        None
    } else {
        Some((u32::from(unit), 1))
    }
}

/// Total visible width, the pre-pass a negative index needs.
pub fn total_width(units: &[u16], options: SliceOptions) -> usize {
    visible_width(units, false, !options.ambiguous_is_narrow)
}
