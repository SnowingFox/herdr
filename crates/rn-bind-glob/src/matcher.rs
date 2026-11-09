//! Matching a compiled pattern against a path.
//!
//! This ports `src/glob/glob_matcher.cc`. The important design point is in
//! `PosSet`: a segment's program is matched by carrying *every* position the
//! program could be at through the subject at once, rather than backtracking.
//! That is what keeps `*(a|aa)*(a|aa)b` linear instead of exponential.
//!
//! The path half is minimatch's `matchOne`: a pattern and a path are both split
//! on `/`, and a `**` part is handled structurally ([`match_globstar`]) rather
//! than by the segment matcher, because its meaning depends on the parts around
//! it.

use crate::ast::Pattern;
use crate::parser::{part_is, CompileFlags, PathPart, Row};
use crate::program::{
    ends_with_lowered, lower_pattern, lower_segment, CharClass, NodeKind, RxNode, SegmentProgram,
    Tier,
};
use crate::unicode::{canonicalize, units_equal_folded};

/// A compiled section of a pattern: what [`crate::parser::parse_pattern`] builds
/// plus the lowered programs.
#[derive(Debug, Clone, Default)]
pub struct CompiledRow {
    pub parts: Vec<PartMatcher>,
    pub has_globstar: bool,
}

/// One compiled path part.
#[derive(Debug, Clone, Default)]
pub struct PartMatcher {
    pub kind: PartKind,
    /// [`PartKind::Literal`]: compares with `===` semantics.
    pub literal: Pattern,
    /// The part's text as it appeared in the pattern.
    ///
    /// The walker keys its visited set on this rather than on the lowered form,
    /// because two parts can lower to the same thing while meaning different
    /// amounts of remaining pattern: `**/*`'s `*` lowers to an empty literal
    /// (it is a [`Tier::Star`] program), which would collide with the empty
    /// suffix after it and make the walk skip a directory it still needs to
    /// descend into.
    pub source: Pattern,
    /// [`PartKind::Program`]: the lowered matcher.
    pub program: SegmentProgram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartKind {
    Globstar,
    Literal,
    #[default]
    Program,
}

/// A fully compiled pattern.
#[derive(Debug, Clone, Default)]
pub struct CompiledPattern {
    /// An empty pattern matches only the empty path.
    pub empty: bool,
    pub flags: CompileFlags,
    pub rows: Vec<CompiledRow>,
}

impl CompiledPattern {
    /// Compiles the rows of an already-parsed pattern.
    pub fn compile(
        parsed: &crate::parser::ParsedPattern,
        flags: CompileFlags,
    ) -> Result<Self, crate::parser::CompileError> {
        let mut out = Self {
            empty: parsed.empty,
            flags,
            rows: Vec::with_capacity(parsed.rows.len()),
        };
        for row in &parsed.rows {
            out.rows.push(compile_row(row, flags)?);
        }
        Ok(out)
    }

    /// Compiles a raw pattern in one step.
    pub fn from_pattern(
        raw: &[u16],
        flags: CompileFlags,
    ) -> Result<Self, crate::parser::CompileError> {
        let parsed = crate::parser::parse_pattern(raw, &flags)?;
        Self::compile(&parsed, flags)
    }
}

fn compile_row(row: &Row, flags: CompileFlags) -> Result<CompiledRow, crate::parser::CompileError> {
    let mut out = CompiledRow::default();
    for part in &row.parts {
        let mut matcher = PartMatcher::default();
        match part {
            PathPart::Globstar => {
                matcher.kind = PartKind::Globstar;
                matcher.source = vec![u16::from(b'*'), u16::from(b'*')];
                out.has_globstar = true;
            }
            PathPart::Literal(literal) => {
                matcher.kind = PartKind::Literal;
                matcher.literal = literal.clone();
                matcher.source = literal.clone();
            }
            PathPart::Segment { source, tree } => {
                matcher.source = source.clone();
                let program = lower_segment(tree, &flags, source);
                if program.invalid_regex {
                    return Err(crate::parser::CompileError::InvalidRegExp);
                }
                match program.tier {
                    // A plain or case-folded literal folds to a `===` part; a
                    // case-folded one stays a program so `test_part` folds it.
                    Tier::Literal if !program.nocase => {
                        matcher.kind = PartKind::Literal;
                        matcher.literal = program.literal.clone();
                    }
                    // minimatch's `parse('')` returns the string `''`, and the
                    // Windows drive detection in `matchOne` depends on the part
                    // being a string.
                    Tier::Empty => {
                        matcher.kind = PartKind::Literal;
                        matcher.literal.clear();
                    }
                    _ => {
                        matcher.kind = PartKind::Program;
                        matcher.program = program;
                    }
                }
            }
        }
        out.parts.push(matcher);
    }
    // A row with no parts still has to behave like the C++ `row.parts` being
    // present: `match_linear` treats an empty pattern as matching only an empty
    // trailing part.
    if out.parts.is_empty() {
        out.parts.push(PartMatcher {
            kind: PartKind::Literal,
            literal: Vec::new(),
            source: Vec::new(),
            program: SegmentProgram::default(),
        });
    }
    Ok(out)
}

/// A sparse set of subject positions, as a bitset.
///
/// Four words hold 256 positions, one more than the longest name common
/// filesystems allow, so only a synthetic subject reaches the heap.
#[derive(Debug, Clone)]
struct PosSet {
    inline: [u64; 4],
    heap: Vec<u64>,
    nwords: usize,
}

impl PosSet {
    fn new(positions: usize) -> Self {
        let nwords = positions.div_ceil(64);
        let mut set = Self {
            inline: [0; 4],
            heap: Vec::new(),
            nwords,
        };
        if nwords > 4 {
            set.heap = vec![0; nwords];
        }
        set
    }

    fn words(&self) -> &[u64] {
        if self.nwords <= 4 {
            &self.inline[..self.nwords]
        } else {
            &self.heap
        }
    }

    fn words_mut(&mut self) -> &mut [u64] {
        if self.nwords <= 4 {
            &mut self.inline[..self.nwords]
        } else {
            &mut self.heap
        }
    }

    fn set(&mut self, index: usize) {
        let word = index >> 6;
        if word < self.nwords {
            self.words_mut()[word] |= 1u64 << (index & 63);
        }
    }

    fn test(&self, index: usize) -> bool {
        let word = index >> 6;
        word < self.nwords && (self.words()[word] >> (index & 63)) & 1 == 1
    }

    fn is_empty(&self) -> bool {
        self.words().iter().all(|&word| word == 0)
    }

    fn for_each(&self, mut visit: impl FnMut(usize)) {
        for (index, &word) in self.words().iter().enumerate() {
            let mut remaining = word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                visit(index * 64 + bit);
                remaining &= remaining - 1;
            }
        }
    }

    fn union_with(&mut self, other: &Self) {
        let words = self.words_mut();
        for (target, source) in words.iter_mut().zip(other.words()) {
            *target |= *source;
        }
    }
}

/// One code point of the subject at `pos`, with its length in code units.
fn char_at(subject: &[u16], pos: usize, uflag: bool) -> (u32, usize) {
    let unit = subject[pos];
    if uflag && (0xD800..0xDC00).contains(&unit) && pos + 1 < subject.len() {
        let trail = subject[pos + 1];
        if (0xDC00..0xE000).contains(&trail) {
            let code = 0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(trail) - 0xDC00);
            return (code, 2);
        }
    }
    (u32::from(unit), 1)
}

/// Matches one segment.
struct SegmentEvaluator<'a> {
    program: &'a SegmentProgram,
    subject: &'a [u16],
    len: usize,
}

impl<'a> SegmentEvaluator<'a> {
    fn new(program: &'a SegmentProgram, subject: &'a [u16]) -> Self {
        Self {
            program,
            subject,
            len: subject.len(),
        }
    }

    fn accepts(&mut self) -> bool {
        if self.program.start_no_traversal && self.is_dot_segment() {
            return false;
        }
        if self.program.start_no_dot && self.subject.first() == Some(&u16::from(b'.')) {
            return false;
        }
        let mut start = PosSet::new(self.len + 1);
        start.set(0);
        let out = self.reach(self.program.root, &start);
        out.test(self.len)
    }

    fn is_dot_segment(&self) -> bool {
        (self.len == 1 && self.subject[0] == u16::from(b'.'))
            || (self.len == 2
                && self.subject[0] == u16::from(b'.')
                && self.subject[1] == u16::from(b'.'))
    }

    fn units_equal_folded(&self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        if !self.program.nocase {
            return false;
        }
        units_equal_folded(a, b, self.program.uflag)
    }

    /// Matches a literal run at `pos`; returns the end position or `None`.
    fn text_at(&self, text: &[u16], pos: usize) -> Option<usize> {
        if !self.program.nocase {
            if pos + text.len() > self.len {
                return None;
            }
            for (index, &expected) in text.iter().enumerate() {
                if self.subject[pos + index] != expected {
                    return None;
                }
            }
            return Some(pos + text.len());
        }
        // A folded comparison, unit-wise (non-`u`) or code-point-wise (`u`).
        let mut ip = pos;
        let mut tp = 0usize;
        while tp < text.len() {
            if ip >= self.len {
                return None;
            }
            if self.program.uflag {
                let (ic, il) = char_at(self.subject, ip, true);
                let head = text[tp];
                let (tc, tl) = if (0xD800..0xDC00).contains(&head) && tp + 1 < text.len() {
                    let trail = text[tp + 1];
                    if (0xDC00..0xE000).contains(&trail) {
                        (
                            0x10000
                                + ((u32::from(head) - 0xD800) << 10)
                                + (u32::from(trail) - 0xDC00),
                            2usize,
                        )
                    } else {
                        (u32::from(head), 1)
                    }
                } else {
                    (u32::from(head), 1)
                };
                if !self.units_equal_folded(ic, tc) {
                    return None;
                }
                ip += il;
                tp += tl;
            } else {
                if !self.units_equal_folded(u32::from(self.subject[ip]), u32::from(text[tp])) {
                    return None;
                }
                ip += 1;
                tp += 1;
            }
        }
        Some(ip)
    }

    /// A class matches when some member is case-equivalent to the subject, and
    /// only then is the polarity applied.
    fn class_matches(&self, class: &CharClass, mut code: u32) -> bool {
        if self.program.nocase && !self.program.uflag {
            code = canonicalize(code, false);
        }
        if class.has_positive && (class.positive.contains(code) != class.negate) {
            return true;
        }
        if class.has_negative && (class.negative.contains(code) == class.negate) {
            return true;
        }
        false
    }

    /// `[^/]*?` expansion from `pos` into `out`.
    fn star_chain(&self, pos: usize, no_empty: bool, out: &mut PosSet) {
        let mut q = pos;
        let mut first = true;
        loop {
            if !first || !no_empty {
                if out.test(q) {
                    // The chain from `q` was already marked.
                    return;
                }
                out.set(q);
            }
            if q >= self.len || self.subject[q] == u16::from(b'/') {
                return;
            }
            let (_, length) = char_at(self.subject, q, self.program.uflag);
            q += length;
            first = false;
        }
    }

    fn guard_matches_to_end(&mut self, node: &RxNode, pos: usize) -> bool {
        let mut start = PosSet::new(self.len + 1);
        start.set(pos);
        for child in &node.children {
            let reached = self.reach(*child, &start);
            if reached.test(self.len) {
                return true;
            }
        }
        false
    }

    /// Kleene closure of `body` applied to `seed`.
    fn closure(&mut self, body: u32, seed: &PosSet) -> PosSet {
        let mut out = seed.clone();
        let mut frontier = seed.clone();
        while !frontier.is_empty() {
            let next = self.reach(body, &frontier);
            let mut fresh = PosSet::new(self.len + 1);
            let mut any = false;
            let mut positions = Vec::new();
            next.for_each(|position| positions.push(position));
            for position in positions {
                if !out.test(position) {
                    fresh.set(position);
                    out.set(position);
                    any = true;
                }
            }
            if !any {
                break;
            }
            frontier = fresh;
        }
        out
    }

    fn reach(&mut self, id: u32, input: &PosSet) -> PosSet {
        let node = self.program.nodes[id as usize].clone();
        let mut out = PosSet::new(self.len + 1);
        match node.kind {
            NodeKind::Empty => input.clone(),
            NodeKind::Assert => {
                let subject = self.subject;
                let len = self.len;
                input.for_each(|pos| {
                    if node.assert_no_dot && pos < len && subject[pos] == u16::from(b'.') {
                        return;
                    }
                    if node.assert_no_traversal && pos == 0 && is_dot_segment_for(subject) {
                        return;
                    }
                    out.set(pos);
                });
                out
            }
            NodeKind::Text => {
                let text = node.text.clone();
                let mut ends = Vec::new();
                input.for_each(|pos| {
                    if let Some(end) = self.text_at(&text, pos) {
                        ends.push(end);
                    }
                });
                for end in ends {
                    out.set(end);
                }
                out
            }
            NodeKind::AnyChar => {
                let subject = self.subject;
                let len = self.len;
                let uflag = self.program.uflag;
                let mut ends = Vec::new();
                input.for_each(|pos| {
                    if pos >= len || subject[pos] == u16::from(b'/') {
                        return;
                    }
                    let (_, length) = char_at(subject, pos, uflag);
                    ends.push(pos + length);
                });
                for end in ends {
                    out.set(end);
                }
                out
            }
            NodeKind::Class => {
                let subject = self.subject;
                let len = self.len;
                let uflag = self.program.uflag;
                let mut ends = Vec::new();
                input.for_each(|pos| {
                    if pos >= len {
                        return;
                    }
                    let (code, length) = char_at(subject, pos, uflag);
                    if self.class_matches(&node.class, code) {
                        ends.push(pos + length);
                    }
                });
                for end in ends {
                    out.set(end);
                }
                out
            }
            NodeKind::StarAny => {
                let mut starts = Vec::new();
                input.for_each(|pos| starts.push(pos));
                for pos in starts {
                    if node.star_no_dot && pos < self.len && self.subject[pos] == u16::from(b'.') {
                        continue;
                    }
                    self.star_chain(pos, node.star_no_empty, &mut out);
                }
                out
            }
            NodeKind::Concat => {
                let mut current = input.clone();
                for child in &node.children {
                    current = self.reach(*child, &current);
                    if current.is_empty() {
                        break;
                    }
                }
                current
            }
            NodeKind::Alt => {
                for child in &node.children {
                    let reached = self.reach(*child, input);
                    out.union_with(&reached);
                }
                out
            }
            NodeKind::Opt => {
                out = input.clone();
                let reached = self.reach(node.children[0], input);
                out.union_with(&reached);
                out
            }
            NodeKind::Star => self.closure(node.children[0], input),
            NodeKind::Plus => {
                let once = self.reach(node.children[0], input);
                self.closure(node.children[0], &once)
            }
            NodeKind::TwoBody => {
                // `(?:first)(?:rest)*?`
                let first = self.reach(node.children[0], input);
                self.closure(node.children[1], &first)
            }
            NodeKind::Neg => {
                let mut starts = Vec::new();
                input.for_each(|pos| starts.push(pos));
                for pos in starts {
                    if node.star_no_dot && pos < self.len && self.subject[pos] == u16::from(b'.') {
                        continue;
                    }
                    if self.guard_matches_to_end(&node, pos) {
                        continue;
                    }
                    self.star_chain(pos, false, &mut out);
                }
                out
            }
        }
    }
}

fn is_dot_segment_for(subject: &[u16]) -> bool {
    (subject.len() == 1 && subject[0] == u16::from(b'.'))
        || (subject.len() == 2 && subject[0] == u16::from(b'.') && subject[1] == u16::from(b'.'))
}

fn is_dots(subject: &[u16]) -> bool {
    is_dot_segment_for(subject)
}

fn equals(part: &[u16], text: &[u16]) -> bool {
    part == text
}

fn equals_folded(part: &[u16], text: &[u16]) -> bool {
    part.len() == text.len()
        && part.iter().zip(text.iter()).all(|(&a, &b)| {
            a == b || canonicalize(u32::from(a), false) == canonicalize(u32::from(b), false)
        })
}

fn ends_with(subject: &[u16], suffix: &[u16]) -> bool {
    subject.len() >= suffix.len() && subject[subject.len() - suffix.len()..] == *suffix
}

/// Tests one segment against one path part.
pub fn test_part(part: &PartMatcher, subject: &[u16]) -> bool {
    match part.kind {
        // Handled structurally by the path matcher.
        PartKind::Globstar => false,
        PartKind::Literal => equals(subject, &part.literal),
        PartKind::Program => test_segment(&part.program, subject),
    }
}

fn test_segment(program: &SegmentProgram, subject: &[u16]) -> bool {
    match program.tier {
        Tier::Empty => subject.is_empty(),
        Tier::Literal => {
            if program.nocase {
                equals_folded(subject, &program.literal)
            } else {
                equals(subject, &program.literal)
            }
        }
        Tier::Star => {
            // `starTest` / `starTestDot`
            if subject.is_empty() {
                return false;
            }
            if program.dot {
                !is_dots(subject)
            } else {
                subject[0] != u16::from(b'.')
            }
        }
        Tier::StarDotExt => {
            if !program.dot && subject.first() == Some(&u16::from(b'.')) {
                return false;
            }
            if program.nocase {
                let rendered = String::from_utf16_lossy(subject);
                ends_with_lowered(&rendered, &program.literal_lower)
            } else {
                ends_with(subject, &program.literal)
            }
        }
        Tier::StarDotStar => {
            let has_dot = subject.contains(&u16::from(b'.'));
            if program.dot {
                !is_dots(subject) && has_dot
            } else {
                subject.first() != Some(&u16::from(b'.')) && has_dot
            }
        }
        Tier::DotStar => !is_dots(subject) && subject.first() == Some(&u16::from(b'.')),
        Tier::Qmarks => {
            if subject.len() != program.qmarks_len {
                return false;
            }
            if program.dot {
                if is_dots(subject) {
                    return false;
                }
            } else if subject.first() == Some(&u16::from(b'.')) {
                return false;
            }
            if program.literal.is_empty() {
                return true;
            }
            if program.nocase {
                let rendered = String::from_utf16_lossy(subject);
                ends_with_lowered(&rendered, &program.literal_lower)
            } else {
                ends_with(subject, &program.literal)
            }
        }
        Tier::Regex => {
            let mut evaluator = SegmentEvaluator::new(program, subject);
            evaluator.accepts()
        }
    }
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

/// Splits a path on `/`, treating a run of separators as one.
fn split_path(text: &[u16], windows: bool) -> Vec<Vec<u16>> {
    crate::parser::slash_split(text, windows)
}

fn normalize_file(file: Vec<Vec<u16>>, flags: &CompileFlags) -> Vec<Vec<u16>> {
    let mut owned = file;
    level_two_file_optimize(&mut owned, flags);
    owned
}

fn index_of(parts: &[Vec<u16>], needle: &str, from: i64) -> i64 {
    let start = if from < 0 { 0 } else { from as usize };
    let begin = start.min(parts.len());
    parts[begin..]
        .iter()
        .position(|part| part_is(part, needle))
        .map_or(-1, |offset| (begin + offset) as i64)
}

fn squeeze_empties_and_dots(parts: &mut Vec<Vec<u16>>) -> bool {
    let mut did_something = false;
    let mut i = 1usize;
    while i + 1 < parts.len() {
        let empty = parts[i].is_empty();
        if i == 1 && empty && parts[0].is_empty() {
            i += 1;
            continue;
        }
        if part_is(&parts[i], ".") || empty {
            did_something = true;
            parts.remove(i);
        } else {
            i += 1;
        }
    }
    if parts.len() == 2
        && part_is(&parts[0], ".")
        && (part_is(&parts[1], ".") || parts[1].is_empty())
    {
        did_something = true;
        parts.pop();
    }
    did_something
}

fn level_two_file_optimize(parts: &mut Vec<Vec<u16>>, flags: &CompileFlags) {
    loop {
        let mut did_something = squeeze_empties_and_dots(parts);
        let mut dd: i64 = 0;
        loop {
            dd = index_of(parts, "..", dd + 1);
            if dd < 0 {
                break;
            }
            if dd == 0 {
                continue;
            }
            let previous = parts[dd as usize - 1].clone();
            if previous.is_empty()
                || part_is(&previous, ".")
                || part_is(&previous, "..")
                || part_is(&previous, "**")
                || (flags.windows && crate::parser::is_windows_drive(&previous))
            {
                continue;
            }
            did_something = true;
            let start = dd as usize - 1;
            parts.drain(start..start + 2);
            dd -= 2;
        }
        if !did_something {
            break;
        }
    }
    if parts.is_empty() {
        parts.push(Vec::new());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    False,
    Null,
    True,
}

struct Section {
    begin: usize,
    end: usize,
    after: i64,
    non_gs: usize,
}

fn part_is_literal(part: &PartMatcher, text: &str) -> bool {
    part.kind == PartKind::Literal && part_is(&part.literal, text)
}

/// Matches one compiled pattern against a whole path.
pub fn match_pattern(pattern: &CompiledPattern, path: &[u16]) -> bool {
    if pattern.empty {
        return path.is_empty();
    }
    // On Windows a path may arrive with `\` separators; matching always uses
    // `/`, which the compiler produced.
    let normalized_path: Vec<u16> = if pattern.flags.windows && path.contains(&u16::from(b'\\')) {
        path.iter()
            .map(|&unit| {
                if unit == u16::from(b'\\') {
                    u16::from(b'/')
                } else {
                    unit
                }
            })
            .collect()
    } else {
        path.to_vec()
    };
    let mut parts = split_path(&normalized_path, pattern.flags.windows);

    let mut basename: Vec<u16> = Vec::new();
    if pattern.flags.match_base {
        for part in parts.iter().rev() {
            if !part.is_empty() {
                basename = part.clone();
                break;
            }
        }
    }
    // `parts` is only rewritten when it actually contains `.` or `..`; a plain
    // path is matched as it was split, which is what minimatch does.
    if parts.iter().any(|part| is_dots(part)) {
        parts = normalize_file(parts, &pattern.flags);
    }

    for row in &pattern.rows {
        if pattern.flags.match_base && row.parts.len() == 1 {
            let only = [basename.clone()];
            if match_one(&only, row, pattern.flags) {
                return true;
            }
            continue;
        }
        if match_one(&parts, row, pattern.flags) {
            return true;
        }
    }
    false
}

fn match_one(file_parts: &[Vec<u16>], row: &CompiledRow, flags: CompileFlags) -> bool {
    let file: &[Vec<u16>] = file_parts;
    let pattern = &row.parts;
    let mut file_start = 0usize;
    let mut pattern_start = 0usize;

    if flags.windows {
        let file_drive = file
            .first()
            .is_some_and(|part| crate::parser::is_windows_drive(part));
        let file_unc = !file_drive
            && file.len() > 3
            && file[0].is_empty()
            && file[1].is_empty()
            && file[2].len() == 1
            && file[2][0] == u16::from(b'?')
            && crate::parser::is_windows_drive(&file[3]);
        let pattern_drive = pattern.first().is_some_and(|part| {
            part.kind == PartKind::Literal && crate::parser::is_windows_drive(&part.literal)
        });
        let pattern_unc = !pattern_drive
            && pattern.len() > 3
            && part_is_literal(&pattern[0], "")
            && part_is_literal(&pattern[1], "")
            && part_is_literal(&pattern[2], "?")
            && pattern[3].kind == PartKind::Literal
            && crate::parser::is_windows_drive(&pattern[3].literal);
        let fdi: i64 = if file_unc {
            3
        } else if file_drive {
            0
        } else {
            -1
        };
        let pdi: i64 = if pattern_unc {
            3
        } else if pattern_drive {
            0
        } else {
            -1
        };
        if fdi >= 0 && pdi >= 0 {
            let fd = &file[fdi as usize];
            let pd = &pattern[pdi as usize].literal;
            if fd.len() == pd.len()
                && crate::unicode::ascii_lower(u32::from(fd[0]))
                    == crate::unicode::ascii_lower(u32::from(pd[0]))
                && fd[1] == pd[1]
            {
                pattern_start = pdi as usize + 1;
                file_start = fdi as usize + 1;
            }
        }
    }

    if row.has_globstar {
        return match_globstar(file, pattern, file_start, pattern_start, flags) == Tri::True;
    }
    match_linear(
        file,
        file.len(),
        pattern,
        pattern_start,
        pattern.len(),
        file_start,
    )
}

/// `#matchOne(file.slice(0, f_end), pattern.slice(p_begin, p_end), partial, ...)`
fn match_linear(
    file: &[Vec<u16>],
    f_end: usize,
    pattern: &[PartMatcher],
    p_begin: usize,
    p_end: usize,
    f_index: usize,
) -> bool {
    let mut fi = f_index;
    let mut pi = p_begin;
    let fl = f_end;
    let pl = p_end;
    while fi < fl && pi < pl {
        let part = &pattern[pi];
        if part.kind == PartKind::Globstar {
            return false;
        }
        if fi >= file.len() {
            return false;
        }
        if !test_part(part, &file[fi]) {
            return false;
        }
        fi += 1;
        pi += 1;
    }
    if fi == fl && pi == pl {
        return true;
    }
    if fi == fl {
        return false;
    }
    if pi == pl {
        return fi == fl - 1 && fi < file.len() && file[fi].is_empty();
    }
    false
}

fn match_globstar(
    file: &[Vec<u16>],
    pattern: &[PartMatcher],
    file_index: usize,
    pattern_index: usize,
    flags: CompileFlags,
) -> Tri {
    // Locate the first (from `pattern_index`) and last globstar.
    let mut firstgs = pattern_index;
    while firstgs < pattern.len() && pattern[firstgs].kind != PartKind::Globstar {
        firstgs += 1;
    }
    let mut lastgs = pattern.len();
    for index in (0..pattern.len()).rev() {
        if pattern[index].kind == PartKind::Globstar {
            lastgs = index;
            break;
        }
    }
    if firstgs >= pattern.len() {
        // No globstar at or after `pattern_index`: fall back to the linear
        // match, which is what the C++ reaches through the same arithmetic.
        return Tri::False;
    }

    let head_begin = pattern_index;
    let head_end = firstgs;
    let body_begin = firstgs + 1;
    let body_end = lastgs.max(body_begin);
    let tail_begin = lastgs + 1;
    let tail_end = pattern.len();
    let head_len = head_end - head_begin;

    let mut fi = file_index;
    if head_len > 0 {
        let slice_end = file.len().min(fi + head_len);
        if !match_linear(file, slice_end, pattern, head_begin, head_end, fi) {
            return Tri::False;
        }
        fi += head_len;
    }

    let tail_len = tail_end - tail_begin;
    let mut file_tail_match = 0usize;
    if tail_len > 0 {
        if tail_len + fi > file.len() {
            return Tri::False;
        }
        let mut tail_start = file.len() - tail_len;
        if match_linear(file, file.len(), pattern, tail_begin, tail_end, tail_start) {
            file_tail_match = tail_len;
        } else {
            // The `a/**/*` matching `a/b/` affordance.
            if file.is_empty() || !file.last().is_some_and(|part| part.is_empty()) {
                return Tri::False;
            }
            if fi + tail_len == file.len() || tail_start == 0 {
                return Tri::False;
            }
            tail_start -= 1;
            if !match_linear(file, file.len(), pattern, tail_begin, tail_end, tail_start) {
                return Tri::False;
            }
            file_tail_match = tail_len + 1;
        }
    }

    let body_len = body_end - body_begin;
    if body_len == 0 {
        let mut saw_some = file_tail_match != 0;
        let scan_end = file.len().saturating_sub(file_tail_match);
        for part in &file[fi..scan_end.max(fi).min(file.len())] {
            saw_some = true;
            if is_dots(part) || (!flags.dot && part.first() == Some(&u16::from(b'.'))) {
                return Tri::False;
            }
        }
        return if saw_some { Tri::True } else { Tri::False };
    }

    // Split the body into globstar-delimited sections, each remembering the
    // last file index it can start at.
    let mut sections: Vec<Section> = Vec::new();
    sections.push(Section {
        begin: body_begin,
        end: body_begin,
        after: 0,
        non_gs: 0,
    });
    let mut non_gs = 0usize;
    for (index, part) in pattern.iter().enumerate().take(body_end).skip(body_begin) {
        if part.kind == PartKind::Globstar {
            sections.push(Section {
                begin: index + 1,
                end: index + 1,
                after: 0,
                non_gs,
            });
        } else {
            if let Some(last) = sections.last_mut() {
                last.end = index + 1;
            }
            non_gs += 1;
        }
    }
    let file_length = file.len() as i64 - file_tail_match as i64;
    // The JS walks the sections from the end, pairing each section's own span
    // with the `nonGs` count of the section `i` places from the end. Both reads
    // are taken from a snapshot so the loop can write in place.
    let trailing: Vec<i64> = sections
        .iter()
        .map(|section| section.non_gs as i64)
        .collect();
    let count = sections.len();
    for (offset, section) in sections.iter_mut().enumerate() {
        let span = (section.end - section.begin) as i64;
        section.after = file_length - (trailing[count - 1 - offset] + span);
    }

    match_body_sections(
        file,
        pattern,
        &sections,
        fi,
        0,
        0,
        file_tail_match != 0,
        flags,
    )
}

#[allow(clippy::too_many_arguments)]
fn match_body_sections(
    file: &[Vec<u16>],
    pattern: &[PartMatcher],
    sections: &[Section],
    file_index: usize,
    body_index: usize,
    globstar_depth: i32,
    saw_tail: bool,
    flags: CompileFlags,
) -> Tri {
    let mut saw_tail = saw_tail;
    if body_index >= sections.len() {
        // Make sure there is no bad dots left.
        for part in &file[file_index.min(file.len())..] {
            saw_tail = true;
            if is_dots(part) || (!flags.dot && part.first() == Some(&u16::from(b'.'))) {
                return Tri::False;
            }
        }
        return if saw_tail { Tri::True } else { Tri::False };
    }
    let section = &sections[body_index];
    let body_len = section.end - section.begin;
    let mut fi = file_index;
    while (fi as i64) <= section.after {
        let slice_end = file.len().min(fi + body_len);
        let matched = match_linear(file, slice_end, pattern, section.begin, section.end, fi);
        // Exceeding the cap is an intentional false negative, for security.
        if matched && globstar_depth < crate::parser::MAX_EXTGLOB_RECURSION * 100 {
            let sub = match_body_sections(
                file,
                pattern,
                sections,
                fi + body_len,
                body_index + 1,
                globstar_depth + 1,
                saw_tail,
                flags,
            );
            if sub != Tri::False {
                return sub;
            }
        }
        if fi >= file.len() {
            return Tri::False;
        }
        let part = &file[fi];
        if is_dots(part) || (!flags.dot && part.first() == Some(&u16::from(b'.'))) {
            return Tri::False;
        }
        fi += 1;
    }
    Tri::Null
}

/// Compiles a pattern and matches it against a path in one call.
pub fn matches(
    pattern: &[u16],
    path: &[u16],
    flags: CompileFlags,
) -> Result<bool, crate::parser::CompileError> {
    let compiled = CompiledPattern::from_pattern(pattern, flags)?;
    Ok(match_pattern(&compiled, path))
}

/// Lowercases a pattern for the case-insensitive fast paths.
pub fn lowered(text: &[u16]) -> String {
    lower_pattern(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::pattern;

    fn flags() -> CompileFlags {
        CompileFlags {
            nocase_magic_only: true,
            ..CompileFlags::default()
        }
    }

    fn is_match(pattern_text: &str, path: &str) -> bool {
        let mut f = flags();
        // Test on the platform-independent spelling so the assertions hold on
        // any host.
        f.windows = false;
        f.nocase = false;
        matches(&pattern(pattern_text), &pattern(path), f).expect("compiles")
    }

    #[test]
    fn literals_match_exactly() {
        assert!(is_match("a/b.js", "a/b.js"));
        assert!(!is_match("a/b.js", "a/c.js"));
        // Confirmed against Node 27: a trailing separator on the path is
        // normalised away, so `a/b.js/` still matches `a/b.js`.
        assert!(is_match("a/b.js", "a/b.js/"));
        assert!(!is_match("a/b.js/", "a/b.js"));
    }

    #[test]
    fn a_star_matches_within_one_segment() {
        assert!(is_match("*.js", "a.js"));
        // Node 27: `matchesGlob('.hidden.js', '*.js')` is false.
        assert!(!is_match("*.js", ".hidden.js"));
        assert!(!is_match("*.js", "a/b.js"));
    }

    #[test]
    fn a_globstar_crosses_segments() {
        assert!(is_match("**/*.js", "a/b.js"));
        assert!(is_match("**/*.js", "b.js"));
        assert!(is_match("a/**/b", "a/x/y/b"));
        assert!(is_match("a/**/b", "a/b"));
    }

    #[test]
    fn a_dot_at_the_start_is_not_matched_by_a_wildcard() {
        assert!(!is_match("*", ".hidden"));
        assert!(!is_match("a/*", "a/.hidden"));
        // But a literal dot matches it.
        assert!(is_match(".*", ".hidden"));
        assert!(is_match("a/.*", "a/.hidden"));
    }

    #[test]
    fn dot_segments_are_never_wildcard_matches() {
        assert!(!is_match("a/*", "a/."));
        assert!(!is_match("a/*", "a/.."));
        assert!(!is_match("a/**", "a/../b"));
    }

    #[test]
    fn globstar_ending_patterns_include_the_directory() {
        // Node 27: `a/**` does not match `a` itself, but does match `a/`, which
        // normalises to the same directory. The trailing empty part is what
        // `state_is_last` recognises.
        assert!(!is_match("a/**", "a"));
        assert!(is_match("a/**", "a/"));
        assert!(is_match("a/**", "a/b"));
        assert!(is_match("a/**", "a/b/"));
    }

    #[test]
    fn question_marks_match_one_character() {
        assert!(is_match("a?c", "abc"));
        assert!(!is_match("a?c", "ac"));
        assert!(!is_match("a?c", "a/c"));
    }

    #[test]
    fn bracket_classes_match_a_member() {
        assert!(is_match("[abc]x", "ax"));
        assert!(is_match("[a-c]x", "bx"));
        assert!(!is_match("[a-c]x", "dx"));
        assert!(is_match("[!a-c]x", "dx"));
        assert!(!is_match("[!a-c]x", "bx"));
    }

    #[test]
    fn extglobs_match_their_alternatives() {
        assert!(is_match("@(a|b).js", "a.js"));
        assert!(is_match("@(a|b).js", "b.js"));
        assert!(!is_match("@(a|b).js", "c.js"));
        assert!(is_match("*(ab|cd)", "abcd"));
        assert!(is_match("+(a|b)", "ab"));
        assert!(!is_match("+(a|b)", ""));
        assert!(is_match("a?(b)c", "ac"));
        assert!(is_match("a?(b)c", "abc"));
    }

    #[test]
    fn a_negated_extglob_rejects_its_alternatives() {
        assert!(!is_match("!(a).js", "a.js"));
        assert!(is_match("!(a).js", "b.js"));
    }

    #[test]
    fn braces_expand_before_matching() {
        assert!(is_match("a{b,c}", "ab"));
        assert!(is_match("a{b,c}", "ac"));
        assert!(!is_match("a{b,c}", "ad"));
        assert!(is_match("x{1..3}", "x2"));
    }

    #[test]
    fn nocase_folds_magic_segments() {
        let mut f = flags();
        f.nocase = true;
        f.windows = false;
        assert!(matches(&pattern("*.TXT"), &pattern("file.txt"), f).expect("compiles"));
        // A literal segment stays exact under `nocase_magic_only`.
        assert!(!matches(&pattern("FILE.txt"), &pattern("file.txt"), f).expect("compiles"));
    }

    #[test]
    fn dot_flag_lets_wildcards_match_hidden_names() {
        let mut f = flags();
        f.dot = true;
        f.windows = false;
        f.nocase = false;
        assert!(matches(&pattern("*"), &pattern(".hidden"), f).expect("compiles"));
        // `.` and `..` still never match.
        assert!(!matches(&pattern("*"), &pattern("."), f).expect("compiles"));
    }

    #[test]
    fn match_base_compares_only_the_basename() {
        let mut f = flags();
        f.match_base = true;
        f.windows = false;
        f.nocase = false;
        assert!(matches(&pattern("*.js"), &pattern("a/b/c.js"), f).expect("compiles"));
        assert!(matches(&pattern("c.js"), &pattern("a/b/c.js"), f).expect("compiles"));
        // A pattern with a separator is not basename-matched.
        assert!(!matches(&pattern("b/*.js"), &pattern("a/b/c.js"), f).expect("compiles"));
    }

    #[test]
    fn a_pathological_pattern_stays_linear() {
        // `*(a|aa)*(a|aa)b` against a long run of `a`s is the shape that
        // backtracks exponentially in a naive matcher.
        let subject: String = std::iter::repeat_n('a', 60).collect::<String>() + "b";
        let mut f = flags();
        f.windows = false;
        f.nocase = false;
        assert!(matches(&pattern("*(a|aa)*(a|aa)b"), &pattern(&subject), f).expect("compiles"));
        let miss = std::iter::repeat_n('a', 60).collect::<String>() + "c";
        assert!(!matches(&pattern("*(a|aa)*(a|aa)b"), &pattern(&miss), f).expect("compiles"));
    }

    #[test]
    fn an_empty_pattern_matches_only_the_empty_path() {
        let mut f = flags();
        f.windows = false;
        f.nocase = false;
        assert!(matches(&[], &[], f).expect("compiles"));
        assert!(!matches(&[], &pattern("a"), f).expect("compiles"));
    }

    #[test]
    fn a_trailing_separator_needs_the_slash_affordance() {
        assert!(is_match("a/**", "a/b/"));
    }
}
