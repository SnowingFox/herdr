//! `Bun.wrapAnsi(text, columns, options?)`.
//!
//! The algorithm is not "break at the column count". It is a word placer over a
//! *row list*, where each row owns its own bytes (escapes included) and a
//! memoised visible width. Three measured behaviours fall out of that shape:
//!
//! * **A word longer than the width is not split** unless `hard` is set:
//!   `wrapAnsi("abcdefghijklmnop", 5)` is the input unchanged, while
//!   `{hard: true}` gives `"abcde\nfghij\nklmno\np"`.
//! * **Spaces are trimmed from both edges by default**, so `"   hello"` becomes
//!   `"hello"`. `{trim: false}` keeps them, and it also moves where breaks
//!   happen, because trimming changes whether a separator is present.
//! * **Styles are closed before a break and re-opened after it**, with the
//!   asymmetry [`crate::ansi`] documents: the per-line close is the specific
//!   code (`39` for a foreground) while the input's own `\x1b[0m` survives at
//!   the end of the last segment.
//!
//! # Why the width memo matters
//!
//! A row's width is normally the sum of its words' widths plus one space per
//! seam, and the code trusts that sum instead of re-measuring the row. It may
//! only do so at a seam where a grapheme cluster boundary is guaranteed. A word
//! that starts with a combining mark fuses with the space before it, so the row
//! is narrower than the sum and the memo is invalidated. That is why
//! `wrapAnsi("a\u{301}b c", 2)` is `"a\u{301}b\nc"`: measured per word, `c` would
//! fit on the first row.

use crate::ansi::StyleState;
use crate::width::{
    breaks_after_space, codepoint_width, consume_ansi, is_escape_character, visible_width,
};

/// Options, with Bun's defaults.
///
/// `word_wrap` and `trim` default to **on**, so only an explicit `false` turns
/// them off — the `!== false` test Bun uses, not a truthiness test.
#[derive(Clone, Copy, Debug)]
pub struct WrapOptions {
    pub hard: bool,
    pub word_wrap: bool,
    pub trim: bool,
    pub ambiguous_is_narrow: bool,
}

impl Default for WrapOptions {
    fn default() -> Self {
        Self {
            hard: false,
            word_wrap: true,
            trim: true,
            ambiguous_is_narrow: true,
        }
    }
}

fn width_of(units: &[u16], ambiguous_is_narrow: bool) -> usize {
    visible_width(units, false, !ambiguous_is_narrow)
}

/// Wraps `units` at `columns`.
///
/// `columns == 0` and an empty input both return the input unchanged, which is
/// how `wrapAnsi("abc", 0)` and `wrapAnsi("abc", -1)` end up as `"abc"`: the
/// caller treats a non-positive or non-finite width as "no wrapping".
pub fn wrap(units: &[u16], columns: usize, options: WrapOptions) -> Vec<u16> {
    if columns == 0 || units.is_empty() {
        return units.to_vec();
    }

    let mut result = Vec::with_capacity(units.len() + units.len() / 10);
    let mut line_start = 0usize;
    let mut first_line = true;

    loop {
        // A bare `\r`, a `\n`, and a `\r\n` pair each break a line and each emit
        // exactly one `\n`. Bun maps every `\r` to a break, and callers that map
        // wrapped output back to their input rely on that.
        let mut break_at = None;
        for (at, unit) in units.iter().enumerate().take(units.len()).skip(line_start) {
            if *unit == u16::from(b'\n') || *unit == u16::from(b'\r') {
                break_at = Some(at);
                break;
            }
        }
        let line_end = break_at.unwrap_or(units.len());

        if !first_line {
            result.push(u16::from(b'\n'));
        }
        first_line = false;

        let rows = place_line(&units[line_start..line_end], columns, options);
        join_rows(&rows, &mut result);

        if line_end == units.len() {
            break;
        }
        // A `\r\n` pair is one break.
        line_start = if units[line_end] == u16::from(b'\r')
            && line_end + 1 < units.len()
            && units[line_end + 1] == u16::from(b'\n')
        {
            line_end + 2
        } else {
            line_end + 1
        };
    }

    result
}

/// One output row: its bytes, and its visible width once measured.
struct Row {
    data: Vec<u16>,
    width: usize,
}

impl Row {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            width: 0,
        }
    }

    fn append(&mut self, units: &[u16]) {
        self.data.extend_from_slice(units);
    }

    fn measure(&self, ambiguous_is_narrow: bool) -> usize {
        width_of(&self.data, ambiguous_is_narrow)
    }
}

/// The row just pushed, which is always present: `place_words` starts with one.
fn last_mut(rows: &mut [Row]) -> &mut Row {
    let index = rows.len() - 1;
    &mut rows[index]
}

fn place_line(line: &[u16], columns: usize, options: WrapOptions) -> Vec<Row> {
    if options.trim {
        let mut start = 0usize;
        let mut end = line.len();
        while start < end && (line[start] == u16::from(b' ') || line[start] == u16::from(b'\t')) {
            start += 1;
        }
        while end > start && (line[end - 1] == u16::from(b' ') || line[end - 1] == u16::from(b'\t'))
        {
            end -= 1;
        }
        if start >= end {
            // A line that is only whitespace produces no rows at all, which is
            // why `wrapAnsi(" ", 5)` is `""` and not `" "`.
            return Vec::new();
        }
        return place_words(&line[start..end], columns, options);
    }
    place_words(line, columns, options)
}

fn place_words(line: &[u16], columns: usize, options: WrapOptions) -> Vec<Row> {
    let mut rows: Vec<Row> = vec![Row::new()];
    let mut last_row_width = 0usize;
    let mut last_row_width_dirty = false;

    let mut word_start = 0usize;
    let mut word_index = 0usize;
    loop {
        let word_end = find_word_separator(line, word_start);
        let word = &line[word_start..word_end];

        if options.trim {
            // Only leading spaces go here; trailing ones are removed once the
            // whole line is placed.
            let removed = trim_leading(&mut last_mut(&mut rows).data);
            if !last_row_width_dirty {
                last_row_width = last_row_width.saturating_sub(removed);
            }
        }

        if last_row_width_dirty {
            last_row_width = last_mut(&mut rows).measure(options.ambiguous_is_narrow);
            last_row_width_dirty = false;
        }

        let mut row_length = last_row_width;
        let mut space_precedes_word = true;
        let mut row_tail = u16::from(b' ');
        let mut appended_space = false;

        if word_index != 0 {
            if row_length >= columns && (!options.word_wrap || !options.trim) {
                rows.push(Row::new());
                row_length = 0;
            }
            if row_length > 0 || !options.trim {
                last_mut(&mut rows).data.push(u16::from(b' '));
                row_length += 1;
                appended_space = true;
            } else if !last_mut(&mut rows).data.is_empty() {
                space_precedes_word = false;
                row_tail = *last_mut(&mut rows).data.last().unwrap_or(&row_tail);
            }
        }

        let word_length = width_of(word, options.ambiguous_is_narrow);

        // Hard mode is the only path that splits a word.
        if options.hard && word_length > columns {
            hard_wrap_word(&mut rows, word, columns, options);
            last_row_width_dirty = true;
            if word_end == line.len() {
                break;
            }
            word_start = word_end + 1;
            word_index += 1;
            continue;
        }

        if row_length + word_length > columns && row_length > 0 && word_length > 0 {
            if !options.word_wrap && row_length < columns {
                hard_wrap_word(&mut rows, word, columns, options);
                last_row_width_dirty = true;
                if word_end == line.len() {
                    break;
                }
                word_start = word_end + 1;
                word_index += 1;
                continue;
            }
            // The break consumes the separator we just added.
            if appended_space {
                last_mut(&mut rows).data.pop();
            }
            rows.push(Row::new());
            row_length = 0;
        }

        if row_length + word_length > columns && !options.word_wrap {
            hard_wrap_word(&mut rows, word, columns, options);
            last_row_width_dirty = true;
            if word_end == line.len() {
                break;
            }
            word_start = word_end + 1;
            word_index += 1;
            continue;
        }

        last_mut(&mut rows).append(word);
        let additive = if space_precedes_word {
            word_starts_new_cluster(word)
        } else {
            word_seam_is_ascii(row_tail, word)
        };
        if additive {
            last_row_width = row_length + word_length;
        } else {
            last_row_width_dirty = true;
        }

        if word_end == line.len() {
            break;
        }
        word_start = word_end + 1;
        word_index += 1;
    }

    if options.trim {
        for row in rows.iter_mut() {
            row.data = trim_trailing_spaces(&row.data, options.ambiguous_is_narrow);
        }
    }
    rows.retain(|row| !row.data.is_empty());
    for row in rows.iter_mut() {
        row.width = row.measure(options.ambiguous_is_narrow);
    }
    rows
}

/// Appends the word to the last row, starting a new row whenever the next
/// codepoint would overflow `columns`.
///
/// This is Bun's `wrapWord`. Both `hard: true` and `wordWrap: false` reach it,
/// which is why it takes the whole word rather than one grapheme.
fn hard_wrap_word(rows: &mut Vec<Row>, word: &[u16], columns: usize, options: WrapOptions) {
    let mut visible = rows
        .last()
        .map(|row| row.measure(options.ambiguous_is_narrow))
        .unwrap_or(0);
    let mut at = 0usize;
    while at < word.len() {
        if is_escape_character(u32::from(word[at])) {
            // An escape is zero-width and never split across rows.
            let end = consume_ansi(word, at);
            let end = if end > at { end } else { at + 1 };
            last_mut(rows).append(&word[at..end]);
            at = end;
            continue;
        }
        let Some((cp, length)) = decode_at(word, at) else {
            at += 1;
            continue;
        };
        let char_width = usize::from(codepoint_width(cp, !options.ambiguous_is_narrow));
        if visible + char_width > columns {
            rows.push(Row::new());
            visible = 0;
        }
        last_mut(rows).append(&word[at..at + length]);
        visible += char_width;
        at += length;
        if visible == columns && at < word.len() {
            rows.push(Row::new());
            visible = 0;
        }
    }

    // A last row holding nothing but escape codes would print as a blank line,
    // so it is folded back into the row before it.
    if visible == 0 && rows.len() > 1 {
        let last_width = rows
            .last()
            .map(|row| row.measure(options.ambiguous_is_narrow))
            .unwrap_or(0);
        if last_width == 0 {
            let last = rows.pop().expect("checked rows.len() > 1");
            last_mut(rows).append(&last.data);
        }
    }
}

/// Removes leading spaces (and tabs, which cost no columns) from a row.
///
/// Returns the visible width removed. Escape sequences are kept whole: only the
/// separator spaces around them go.
fn trim_leading(data: &mut Vec<u16>) -> usize {
    let mut removed = 0usize;
    let mut read = 0usize;
    let mut out: Vec<u16> = Vec::with_capacity(data.len());
    while read < data.len() {
        let unit = data[read];
        if is_escape_character(u32::from(unit)) {
            let end = consume_ansi(data, read);
            let end = if end > read { end } else { read + 1 };
            out.extend_from_slice(&data[read..end]);
            read = end;
        } else if unit == u16::from(b' ') {
            removed += 1;
            read += 1;
        } else if unit == u16::from(b'\t') {
            read += 1;
        } else {
            out.extend_from_slice(&data[read..]);
            break;
        }
    }
    *data = out;
    removed
}

/// `wrap-ansi`'s `stringVisibleTrimSpacesRight`: past the last word with visible
/// content, drop the separator spaces and keep escapes and zero-width text.
fn trim_trailing_spaces(data: &[u16], ambiguous_is_narrow: bool) -> Vec<u16> {
    let mut last_visible_end = 0usize;
    let mut word_start = 0usize;
    loop {
        let word_end = find_word_separator(data, word_start);
        if width_of(&data[word_start..word_end], ambiguous_is_narrow) > 0 {
            last_visible_end = word_end;
        }
        if word_end == data.len() {
            break;
        }
        word_start = word_end + 1;
    }
    if last_visible_end == data.len() {
        return data.to_vec();
    }

    let mut out = data[..last_visible_end].to_vec();
    let mut at = last_visible_end;
    while at < data.len() {
        if is_escape_character(u32::from(data[at])) {
            let end = consume_ansi(data, at);
            let end = if end > at { end } else { at + 1 };
            out.extend_from_slice(&data[at..end]);
            at = end;
        } else {
            if data[at] != u16::from(b' ') {
                out.push(data[at]);
            }
            at += 1;
        }
    }
    out
}

/// The index of the separator space that ends the word starting at `start`.
///
/// An escape sequence is opaque: a space inside an OSC hyperlink's URI does not
/// separate words.
fn find_word_separator(units: &[u16], start: usize) -> usize {
    let next_space = |from: usize| -> usize {
        let mut at = from;
        while at < units.len() {
            if units[at] == u16::from(b' ') {
                return at;
            }
            at += 1;
        }
        units.len()
    };

    let mut space = next_space(start);
    let mut at = start;
    loop {
        let mut escape = None;
        let mut scan = at;
        while scan < space {
            if is_escape_character(u32::from(units[scan])) {
                escape = Some(scan);
                break;
            }
            scan += 1;
        }
        let Some(escape) = escape else {
            return space;
        };
        let after = consume_ansi(units, escape);
        at = if after > escape { after } else { escape + 1 };
        if at > space {
            space = next_space(at);
        }
    }
}

/// Decodes one codepoint at `at`, returning it and the units it used.
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

/// Whether a grapheme cluster boundary always precedes the word's first
/// codepoint, taking the separator space as the predecessor.
fn word_starts_new_cluster(word: &[u16]) -> bool {
    let Some(start) = skip_leading_ansi(word) else {
        return true;
    };
    let Some((cp, _)) = decode_at(word, start) else {
        return true;
    };
    if cp < 0x80 {
        return true;
    }
    breaks_after_space(cp)
}

/// Without a separator space the row's real predecessor is the word's
/// predecessor, so only an ASCII/ASCII seam keeps the widths additive.
fn word_seam_is_ascii(row_tail: u16, word: &[u16]) -> bool {
    let Some(start) = skip_leading_ansi(word) else {
        return true;
    };
    u32::from(row_tail) < 0x80 && u32::from(word[start]) < 0x80
}

/// Where the first non-escape codepoint is, or `None` when the word is only
/// escapes.
fn skip_leading_ansi(word: &[u16]) -> Option<usize> {
    let mut at = 0usize;
    while at < word.len() {
        if is_escape_character(u32::from(word[at])) {
            let end = consume_ansi(word, at);
            at = if end > at { end } else { at + 1 };
        } else {
            return Some(at);
        }
    }
    None
}

/// Emits `rows` into `result`, closing and re-opening styles around each break.
fn join_rows(rows: &[Row], result: &mut Vec<u16>) {
    let mut state = StyleState::default();

    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            result.push(u16::from(b'\n'));
            result.extend_from_slice(&state.reopen_sequences());
        }

        let mut at = 0usize;
        while at < row.data.len() {
            if is_escape_character(u32::from(row.data[at])) {
                let end = state.track(&row.data, at);
                let end = if end > at { end } else { at + 1 };
                result.extend_from_slice(&row.data[at..end]);
                at = end;
            } else {
                result.push(row.data[at]);
                at += 1;
            }
        }

        if index + 1 < rows.len() {
            result.extend_from_slice(&state.close_sequences());
        }
    }
}
