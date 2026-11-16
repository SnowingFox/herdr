//! Terminal column width and ANSI-aware text measurement.
//!
//! `Bun.stringWidth`, `Bun.wrapAnsi` and `Bun.sliceAnsi` all stand on the same
//! two primitives — how wide a string is in columns, and where its escape
//! sequences begin and end — so they live together here rather than in three
//! copies. This module is pure: no V8, no allocator state, so the whole width
//! algorithm is testable as ordinary Rust.
//!
//! # The two width algorithms are not the same algorithm
//!
//! Bun computes `stringWidth` two ways and the public options pick between
//! them, which is the single easiest thing to get wrong here:
//!
//! * **The default is grapheme clustering.** A cluster's width is decided once,
//!   from the shapes inside it: a regional-indicator *pair* is 2, a keycap
//!   sequence is 2, an emoji with a skin tone or a ZWJ is 2, and a base plus
//!   combining marks is the base's width. `"👨‍👩‍👧‍👦"` is **2**, because the
//!   seven codepoints are one cluster. Summing per-codepoint widths gives 8.
//! * **`{perCodePoint: true}` is Node's `GetColumnWidth`.** Every codepoint is
//!   measured on its own, so the same family emoji is **8**. Bun implements it
//!   over ICU rather than reusing its own table, and the two really do
//!   disagree, so both are reproduced here from the UCD.
//!
//! # Unicode version
//!
//! Bun 1.4.4 pins **17.0.0** and the tables here are generated from it. This
//! matters: East Asian Width `W` grows between releases, so a table from an
//! older Unicode reports `U+4DC0` as 1 where Bun reports 2.
//!
//! The generated **grapheme** classes are not byte-identical to Bun's — 1417
//! codepoints differ, because Bun carries its classes over from an older
//! uucode header instead of regenerating them. Every one of those was measured
//! and none changes a width, which `tests/width_parity.rs` re-checks; see
//! `tools/gen-width-tables.py` for the full account.
//!
//! # ANSI
//!
//! Escape sequences contribute zero columns unless `countAnsiEscapeCodes` asks
//! for their bytes to be counted as columns, which is what makes
//! `stringWidth("\x1b[31mred\x1b[0m")` 3 and the same string with that option
//! 10. The grammar is ECMA-48 and the consumer is a state machine, not a
//! regular expression, because a truncated sequence swallows the rest of the
//! string rather than being ignored — `stripANSI("a\x1bb")` is `"a"`.

use crate::width_tables::{FUSED, PER_CODE_POINT};

/// A packed grapheme-break class, in the ordinals the generated table uses.
///
/// The discriminants are the values stored in bits 0-4 of `FUSED`, so they are
/// part of the generated data's contract, not an internal convenience.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grapheme {
    Other = 0,
    Prepend = 1,
    RegionalIndicator = 2,
    SpacingMark = 3,
    L = 4,
    V = 5,
    T = 6,
    Lv = 7,
    Lvt = 8,
    Zwj = 9,
    Zwnj = 10,
    ExtendedPictographic = 11,
    EmojiModifierBase = 12,
    EmojiModifier = 13,
    IncbExtend = 14,
    IncbLinker = 15,
    IncbConsonant = 16,
}

impl Grapheme {
    fn from_ordinal(ordinal: u8) -> Self {
        match ordinal & 0x1F {
            1 => Self::Prepend,
            2 => Self::RegionalIndicator,
            3 => Self::SpacingMark,
            4 => Self::L,
            5 => Self::V,
            6 => Self::T,
            7 => Self::Lv,
            8 => Self::Lvt,
            9 => Self::Zwj,
            10 => Self::Zwnj,
            11 => Self::ExtendedPictographic,
            12 => Self::EmojiModifierBase,
            13 => Self::EmojiModifier,
            14 => Self::IncbExtend,
            15 => Self::IncbLinker,
            16 => Self::IncbConsonant,
            _ => Self::Other,
        }
    }
}

/// The grapheme-break state carried between two codepoints, per UAX #29.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BreakState {
    #[default]
    Default,
    RegionalIndicator,
    ExtendedPictographic,
    IndicConjunctConsonant,
    IndicConjunctLinker,
}

/// Binary search over a generated `(first, last, value)` table.
fn lookup(table: &[(u32, u32, u8)], cp: u32) -> u8 {
    // The tables cover the whole scalar range including surrogates, so the
    // search always lands on an entry; the fallback exists only so a future
    // table with a hole degrades to "narrow" rather than panicking.
    let mut low = 0;
    let mut high = table.len();
    while low < high {
        let mid = (low + high) / 2;
        if table[mid].0 <= cp {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if low == 0 {
        return 0x20;
    }
    let entry = table[low - 1];
    if cp <= entry.1 {
        entry.2
    } else {
        0x20
    }
}

/// The fused classification byte for one codepoint.
fn fused(cp: u32) -> u8 {
    lookup(FUSED, cp)
}

/// Column width of one codepoint from the fused table.
pub fn codepoint_width(cp: u32, ambiguous_as_wide: bool) -> u8 {
    match (fused(cp) >> 5) & 0x3 {
        3 => {
            if ambiguous_as_wide {
                2
            } else {
                1
            }
        }
        width => width,
    }
}

/// Column width of one codepoint on the `perCodePoint` path.
fn per_code_point_width(cp: u32, ambiguous_as_wide: bool) -> u8 {
    let packed = lookup(PER_CODE_POINT, cp);
    let narrow = packed & 0x3;
    let wide = (packed >> 2) & 0x3;
    if ambiguous_as_wide {
        wide
    } else {
        narrow
    }
}

fn grapheme_of(cp: u32) -> Grapheme {
    Grapheme::from_ordinal(fused(cp))
}

fn is_extended_pictographic(class: Grapheme) -> bool {
    matches!(
        class,
        Grapheme::ExtendedPictographic | Grapheme::EmojiModifierBase
    )
}

/// GB9's `Extend`: ZWNJ, InCB Extend, InCB Linker.
fn is_extend(class: Grapheme) -> bool {
    matches!(
        class,
        Grapheme::Zwnj | Grapheme::IncbExtend | Grapheme::IncbLinker
    )
}

fn is_incb_extend(class: Grapheme) -> bool {
    matches!(class, Grapheme::IncbExtend | Grapheme::Zwj)
}

/// Whether a grapheme cluster boundary falls between `first` and `second`.
///
/// Ported from the UAX #29 rules Bun implements (its
/// `computeGraphemeBreakNoControl`), including GB9c's Indic Conjunct Break,
/// which is why the state machine cannot be collapsed into a pairwise table
/// without also carrying state.
fn grapheme_break(first: Grapheme, second: Grapheme, state: &mut BreakState) -> bool {
    use BreakState as S;
    use Grapheme as G;

    // A pair that leaves a sequence resets the carried state first.
    match *state {
        S::RegionalIndicator => {
            if !(first == G::RegionalIndicator && second == G::RegionalIndicator) {
                *state = S::Default;
            }
        }
        S::ExtendedPictographic => {
            let expected = |class: Grapheme| {
                matches!(
                    class,
                    G::IncbExtend
                        | G::IncbLinker
                        | G::Zwnj
                        | G::Zwj
                        | G::ExtendedPictographic
                        | G::EmojiModifierBase
                        | G::EmojiModifier
                )
            };
            if !expected(first) || !expected(second) {
                *state = S::Default;
            }
        }
        S::IndicConjunctConsonant | S::IndicConjunctLinker => {
            let expected = |class: Grapheme| {
                matches!(
                    class,
                    G::IncbConsonant | G::IncbLinker | G::IncbExtend | G::Zwj
                )
            };
            if !expected(first) || !expected(second) {
                *state = S::Default;
            }
        }
        S::Default => {}
    }

    // GB6: L x (L | V | LV | LVT)
    if first == G::L && matches!(second, G::L | G::V | G::Lv | G::Lvt) {
        return false;
    }
    // GB7: (LV | V) x (V | T)
    if matches!(first, G::Lv | G::V) && matches!(second, G::V | G::T) {
        return false;
    }
    // GB8: (LVT | T) x T
    if matches!(first, G::Lvt | G::T) && second == G::T {
        return false;
    }
    // GB9a: x SpacingMark
    if second == G::SpacingMark {
        return false;
    }
    // GB9b: Prepend x
    if first == G::Prepend {
        return false;
    }

    // GB9c: Indic Conjunct Break.
    if first == G::IncbConsonant {
        if is_incb_extend(second) {
            *state = S::IndicConjunctConsonant;
            return false;
        }
        if second == G::IncbLinker {
            *state = S::IndicConjunctLinker;
            return false;
        }
    } else if *state == S::IndicConjunctConsonant {
        if second == G::IncbLinker {
            *state = S::IndicConjunctLinker;
            return false;
        }
        if is_incb_extend(second) {
            return false;
        }
        *state = S::Default;
    } else if *state == S::IndicConjunctLinker {
        if second == G::IncbLinker || is_incb_extend(second) {
            return false;
        }
        if second == G::IncbConsonant {
            *state = S::Default;
            return false;
        }
        *state = S::Default;
    }

    // GB11: emoji ZWJ sequences and emoji modifier sequences.
    if is_extended_pictographic(first) {
        if is_extend(second) || second == G::Zwj {
            *state = S::ExtendedPictographic;
            return false;
        }
        if first == G::EmojiModifierBase && second == G::EmojiModifier {
            *state = S::ExtendedPictographic;
            return false;
        }
    } else if *state == S::ExtendedPictographic {
        if (is_extend(first) || first == G::EmojiModifier)
            && (is_extend(second) || second == G::Zwj)
        {
            return false;
        }
        if first == G::Zwj && is_extended_pictographic(second) {
            *state = S::Default;
            return false;
        }
        *state = S::Default;
    }

    // GB12/GB13: regional indicators pair off, one pair per flag.
    if first == G::RegionalIndicator && second == G::RegionalIndicator {
        if *state == S::Default {
            *state = S::RegionalIndicator;
            return false;
        }
        *state = S::Default;
        return true;
    }

    // GB9: x (Extend | ZWJ)
    if is_extend(second) || second == G::Zwj {
        return false;
    }

    // GB999
    true
}

fn is_regional_indicator(cp: u32) -> bool {
    (0x1F1E6..=0x1F1FF).contains(&cp)
}

fn is_skin_tone(cp: u32) -> bool {
    (0x1F3FB..=0x1F3FF).contains(&cp)
}

/// One grapheme cluster's accumulated state, and the width it resolves to.
///
/// The width cannot be decided until the cluster ends, because `"❤"` is 1 but
/// `"❤️"` (with VS16) is 2 — the variation selector changes the width of a
/// codepoint that came before it. That is the reason this struct exists
/// instead of a running counter.
#[derive(Default)]
struct Cluster {
    first: u32,
    non_emoji_width: u32,
    base_width: u8,
    count: u32,
    emoji_base: bool,
    keycap: bool,
    regional_indicator: bool,
    skin_tone: bool,
    zwj: bool,
    vs15: bool,
    vs16: bool,
}

impl Cluster {
    fn reset(&mut self, cp: u32, packed: u8, ambiguous_as_wide: bool) {
        *self = Self::default();
        self.first = cp;
        // ASCII needs none of the emoji machinery; Bun short-circuits it and so
        // does this, which also keeps the common case branch-free of the table.
        if cp < 0x80 {
            let width = u8::from((0x20..0x7F).contains(&cp));
            self.count = 1;
            self.base_width = width;
            self.non_emoji_width = u32::from(width);
            return;
        }
        let width = codepoint_width(cp, ambiguous_as_wide);
        self.count = 1;
        self.base_width = width;
        self.non_emoji_width = u32::from(width);
        self.emoji_base = packed & 0x80 != 0;
        self.keycap = cp == 0x20E3;
        self.regional_indicator = is_regional_indicator(cp);
        self.skin_tone = is_skin_tone(cp);
        self.zwj = cp == 0x200D;
    }

    fn add(&mut self, cp: u32, ambiguous_as_wide: bool) {
        self.count = self.count.saturating_add(1);
        self.keycap |= cp == 0x20E3;
        self.regional_indicator |= is_regional_indicator(cp);
        self.skin_tone |= is_skin_tone(cp);
        self.zwj |= cp == 0x200D;
        self.vs15 |= cp == 0xFE0E;
        self.vs16 |= cp == 0xFE0F;
        self.non_emoji_width =
            (self.non_emoji_width + u32::from(codepoint_width(cp, ambiguous_as_wide))).min(1023);
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
            // VS16 promotes a base with the Emoji property to emoji
            // presentation, which is two columns. Zero-width and narrow
            // non-emoji bases keep their own width, and a wide base stays wide.
            if self.base_width == 2
                || (self.vs16 && (self.emoji_base || self.first == 0xA9 || self.first == 0xAE))
            {
                return 2;
            }
            return usize::from(self.base_width);
        }
        self.non_emoji_width as usize
    }
}

/// Accumulates a run of codepoints into a grapheme-cluster width.
pub struct WidthAccumulator {
    total: usize,
    cluster: Cluster,
    previous: Option<Grapheme>,
    break_state: BreakState,
    ambiguous_as_wide: bool,
}

impl WidthAccumulator {
    pub fn new(ambiguous_as_wide: bool) -> Self {
        Self {
            total: 0,
            cluster: Cluster::default(),
            previous: None,
            break_state: BreakState::Default,
            ambiguous_as_wide,
        }
    }

    pub fn push(&mut self, cp: u32) {
        let class = grapheme_of(cp);
        let packed = fused(cp);
        match self.previous {
            None => self.cluster.reset(cp, packed, self.ambiguous_as_wide),
            Some(previous) => {
                if grapheme_break(previous, class, &mut self.break_state) {
                    self.total += self.cluster.width();
                    self.cluster.reset(cp, packed, self.ambiguous_as_wide);
                } else {
                    self.cluster.add(cp, self.ambiguous_as_wide);
                }
            }
        }
        self.previous = Some(class);
    }

    pub fn finish(self) -> usize {
        self.total + self.cluster.width()
    }
}

/// Whether `cp` introduces, terminates, or lies inside an ANSI escape sequence.
///
/// ESC, the C1 introducers (CSI, OSC, DCS, SOS, PM, APC) and the C1 string
/// terminator all count, because each one starts or ends a sequence the width
/// and slicing code must treat as opaque.
pub fn is_escape_character(cp: u32) -> bool {
    matches!(cp, 0x1B | 0x90 | 0x98 | 0x9B | 0x9C | 0x9D | 0x9E | 0x9F)
}

/// Where an escape sequence that starts at `start` ends.
///
/// Returns the index just past the sequence, or the length of the input when the
/// sequence is unterminated: a truncated sequence swallows everything after it,
/// which is why `stripANSI("a\x1bb")` is `"a"` and `stripANSI("\x1b[31")` is
/// `""`. Returns `start` unchanged when there is no sequence there.
///
/// This is Bun's `consumeANSI` reduced to the cases its callers reach: the
/// state machine aborts to ground on CAN (0x18), SUB (0x1A) and the C1 ST, and
/// a nested ESC restarts the sequence rather than ending it.
pub fn consume_ansi(units: &[u16], start: usize) -> usize {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Start,
        GotEsc,
        IgnoreNext,
        InCsi,
        InOsc,
        InOscGotEsc,
        NeedSt,
        NeedStGotEsc,
    }

    let end = units.len();
    let mut state = State::Start;
    let mut at = start;

    while at < end {
        let unit = units[at];
        match state {
            State::Start => match unit {
                0x1B => state = State::GotEsc,
                0x9B => state = State::InCsi,
                0x9D => state = State::InOsc,
                0x90 | 0x98 | 0x9E | 0x9F => state = State::NeedSt,
                _ => return at,
            },
            State::InOscGotEsc | State::NeedStGotEsc => {
                if unit == u16::from(b'\\') {
                    state = State::Start;
                } else {
                    // Any other ESC aborted the payload and starts a new
                    // sequence, so this unit is the one right after that ESC.
                    if unit == 0x1B {
                        state = State::GotEsc;
                    } else if unit == 0x18 || unit == 0x1A {
                        state = State::Start;
                    } else if unit == u16::from(b'[') {
                        state = State::InCsi;
                    } else if unit == u16::from(b']') {
                        state = State::InOsc;
                    } else if matches!(
                        unit,
                        x if x == u16::from(b'P')
                            || x == u16::from(b'X')
                            || x == u16::from(b'^')
                            || x == u16::from(b'_')
                    ) {
                        state = State::NeedSt;
                    } else if (0x20..=0x2F).contains(&unit) {
                        state = State::IgnoreNext;
                    } else if (0x30..=0x7E).contains(&unit) || unit == 0x9C {
                        state = State::Start;
                    } else {
                        return at;
                    }
                }
            }
            State::GotEsc => match unit {
                0x1B => state = State::GotEsc,
                0x18 | 0x1A => state = State::Start,
                x if x == u16::from(b'[') => state = State::InCsi,
                x if x == u16::from(b']') => state = State::InOsc,
                x if x == u16::from(b'P')
                    || x == u16::from(b'X')
                    || x == u16::from(b'^')
                    || x == u16::from(b'_') =>
                {
                    state = State::NeedSt
                }
                _ => {
                    if (0x20..=0x2F).contains(&unit) {
                        state = State::IgnoreNext;
                    } else if (0x30..=0x7E).contains(&unit) || unit == 0x9C {
                        state = State::Start;
                    } else {
                        return at;
                    }
                }
            },
            State::IgnoreNext => {
                state = if unit == 0x1B {
                    State::GotEsc
                } else {
                    State::Start
                };
            }
            State::InCsi => {
                // ECMA-48 §5.4: the final byte is in 0x40-0x7E. ESC, CAN, SUB and
                // the C1 ST abort the sequence, so the sequence ends *before* that
                // byte and the caller sees it as the start of the next one.
                if unit == 0x1B || unit == 0x18 || unit == 0x1A || unit == 0x9C {
                    return at;
                }
                if (0x40..=0x7E).contains(&unit) {
                    return at + 1;
                }
            }
            State::InOsc | State::NeedSt => {
                let osc = state == State::InOsc;
                if unit == 0x1B {
                    state = if osc {
                        State::InOscGotEsc
                    } else {
                        State::NeedStGotEsc
                    };
                } else if (osc && unit == 0x07) || unit == 0x9C || unit == 0x18 || unit == 0x1A {
                    state = State::Start;
                }
            }
        }
        at += 1;
    }

    // Unterminated: the sequence runs to the end of the input.
    end
}

/// Visible column width of a string.
///
/// With `count_ansi` set, escape sequences are measured as ordinary columns
/// instead of being skipped — that is `countAnsiEscapeCodes`, and it is what
/// makes `stringWidth("\x1b[31mred\x1b[0m")` 3 by default and 10 with the
/// option.
///
/// One accumulator spans the whole string even when escapes are skipped, so a
/// combining mark that follows an escape still joins the cluster before it:
/// `"\x1b[31me\u0301\x1b[0m"` is 1 column, not 2.
pub fn visible_width(units: &[u16], count_ansi: bool, ambiguous_as_wide: bool) -> usize {
    let mut accumulator = WidthAccumulator::new(ambiguous_as_wide);
    let mut at = 0;
    while at < units.len() {
        let unit = units[at];
        if !count_ansi && is_escape_character(u32::from(unit)) {
            let end = consume_ansi(units, at);
            // `consume_ansi` returns `at` when nothing starts there, so this
            // makes progress in every case.
            at = if end > at { end } else { at + 1 };
            continue;
        }
        if (0xD800..0xDC00).contains(&unit) {
            let trail = units.get(at + 1).copied();
            match trail {
                Some(trail) if (0xDC00..0xE000).contains(&trail) => {
                    let cp =
                        0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(trail) - 0xDC00);
                    accumulator.push(cp);
                    at += 2;
                }
                _ => at += 1,
            }
            continue;
        }
        if (0xDC00..0xE000).contains(&unit) {
            // A lone trail surrogate is skipped: zero width, no cluster state.
            at += 1;
            continue;
        }
        accumulator.push(u32::from(unit));
        at += 1;
    }
    accumulator.finish()
}

/// Width of a string on the `perCodePoint` path.
pub fn per_code_point_width_of(
    units: &[u16],
    exclude_ansi: bool,
    ambiguous_as_wide: bool,
) -> usize {
    let mut width = 0;
    let mut at = 0;
    while at < units.len() {
        let unit = units[at];
        if exclude_ansi && is_escape_character(u32::from(unit)) {
            at = consume_ansi(units, at);
            continue;
        }
        if (0xD800..0xDC00).contains(&unit) && at + 1 < units.len() {
            let trail = units[at + 1];
            if (0xDC00..0xE000).contains(&trail) {
                let cp = 0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(trail) - 0xDC00);
                width += usize::from(per_code_point_width(cp, ambiguous_as_wide));
                at += 2;
                continue;
            }
        }
        // A lone surrogate is measured as itself, which the table reports as
        // zero width — matching ICU's answer for an unpaired half.
        width += usize::from(per_code_point_width(u32::from(unit), ambiguous_as_wide));
        at += 1;
    }
    width
}

/// Whether a cluster boundary falls immediately before `cp` when the preceding
/// codepoint is a space.
///
/// `wrapAnsi` needs this to decide whether a row's width is the sum of its
/// words' widths. It is false for anything that fuses with a space in front of
/// it — an extending mark, a ZWJ, a variation selector, a keycap or a hangul
/// jamo — and true for everything else.
pub fn breaks_after_space(cp: u32) -> bool {
    let mut state = BreakState::Default;
    grapheme_break(Grapheme::Other, grapheme_of(cp), &mut state)
}

/// The grapheme-break class of one codepoint.
pub fn grapheme_class(cp: u32) -> Grapheme {
    grapheme_of(cp)
}

/// `grapheme_break` for callers that hold codepoints rather than classes.
pub fn grapheme_break_state(first: u32, second: u32, state: &mut BreakState) -> bool {
    grapheme_break(grapheme_of(first), grapheme_of(second), state)
}

/// Whether a codepoint has the Emoji property under Bun's `isEmojiPresentation`
/// early-outs — the same bit the fused table stores in bit 7.
pub fn is_emoji_presentation(cp: u32) -> bool {
    fused(cp) & 0x80 != 0
}
