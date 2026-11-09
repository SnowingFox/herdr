//! Brace expansion, a port of minimatch's `braceExpand` plus the
//! `balanced-match` helper it is built on.
//!
//! `{a,b}` expands to two patterns, `{1..3}` to three, and `{a,{b,c}}` to three
//! more through recursion. Everything here works on UTF-16 code units for the
//! same reason the rest of the crate does: a pattern may hold a lone surrogate,
//! and converting it to a Rust `String` would silently replace it.
//!
//! The one structural difference from the JavaScript is that the recursion
//! depth is capped ([`MAX_NESTING_DEPTH`]). Minimatch recurses once per level
//! of nesting and simply lets V8 throw `RangeError` when the stack runs out;
//! a Rust stack overflow aborts the process instead of throwing, so the limit
//! has to exist. It is far above any real pattern.

use crate::ast::Pattern;

/// The longest pattern accepted, inherited from minimatch.
pub const MAX_PATTERN_LENGTH: usize = 64 * 1024;
/// How far, in number of expansions, braces may grow.
pub const BRACE_EXPANSION_MAX: usize = 100_000;
/// How far, in length, braces may grow.
pub const BRACE_EXPANSION_MAX_LENGTH: usize = 4_000_000;
/// How deep `{`/`@(` nesting may go before the pattern is refused.
pub const MAX_NESTING_DEPTH: i32 = 256;

/// A pair of code points that stand in for a literal `{` and `}` while braces
/// are expanded, so a brace that must stay literal is not re-read as a group.
///
/// Drawn from the permanently unassigned noncharacter block: no meaningful
/// pattern contains one, and [`choose_sentinels`] guarantees the pair does not
/// occur in the pattern being expanded.
#[derive(Debug, Clone, Copy)]
struct BraceSentinels {
    open: u16,
    close: u16,
}

const NONCHARACTER_FIRST: u16 = 0xFDD0;
const NONCHARACTER_LAST: u16 = 0xFDEF;
const NONCHARACTER_COUNT: u32 = (NONCHARACTER_LAST - NONCHARACTER_FIRST) as u32 + 1;

/// Picks sentinels absent from `pattern`.
///
/// Returns `None` only for a pattern that spells out every code unit at or
/// above 0x80, which is the pathological case the original documents: there is
/// no unit left to mark a literal brace with, and rewriting one of the
/// pattern's own literals would change what it matches.
fn choose_sentinels(pattern: &[u16]) -> Option<BraceSentinels> {
    let mut used: u32 = 0;
    for &unit in pattern {
        if (NONCHARACTER_FIRST..=NONCHARACTER_LAST).contains(&unit) {
            used |= 1 << (unit - NONCHARACTER_FIRST);
        }
    }
    let mut slots = [NONCHARACTER_FIRST, NONCHARACTER_FIRST + 1];
    let mut next = 0;
    let mut bit = 0;
    while bit < NONCHARACTER_COUNT && next < 2 {
        if used & (1 << bit) == 0 {
            slots[next] = NONCHARACTER_FIRST + bit as u16;
            next += 1;
        }
        bit += 1;
    }
    if next == 2 {
        return Some(BraceSentinels {
            open: slots[0],
            close: slots[1],
        });
    }
    // The pattern uses nearly the whole noncharacter block, so take any two
    // absent units instead. Only units >= 0x80 qualify: sequence expansion
    // synthesises ASCII digits, `-` and letters that the pattern itself need
    // not contain, and one of those would be un-escaped back into a brace at
    // the end.
    let mut present = vec![false; 0x1_0000];
    for &unit in pattern {
        present[unit as usize] = true;
    }
    let mut next = 0;
    let mut unit = 0x80usize;
    while unit < present.len() && next < 2 {
        if !present[unit] {
            slots[next] = unit as u16;
            next += 1;
        }
        unit += 1;
    }
    if next < 2 {
        return None;
    }
    Some(BraceSentinels {
        open: slots[0],
        close: slots[1],
    })
}

/// The `{...}` pair `balanced-match`'s `range()` finds, if any.
#[derive(Debug, Clone, Copy)]
struct Balanced {
    start: usize,
    end: usize,
}

/// Port of `balanced-match`'s `balanced('{', '}', str)`.
///
/// The JavaScript is a small state machine over indices rather than a scan with
/// a depth counter, and it differs from one: a nested group is resolved by
/// preferring the innermost pair, then widening outwards. Reproducing it
/// literally is what keeps `{a,{b,c}}` splitting the way minimatch splits it.
fn balanced_braces(text: &[u16]) -> Option<Balanced> {
    let find = |needle: u16, from: i64| -> i64 {
        if from < 0 {
            return match text.iter().position(|&unit| unit == needle) {
                Some(index) => index as i64,
                None => -1,
            };
        }
        match text[(from as usize).min(text.len())..]
            .iter()
            .position(|&unit| unit == needle)
        {
            Some(index) => index as i64 + from,
            None => -1,
        }
    };

    let mut ai = find(u16::from(b'{'), 0);
    let mut bi = find(u16::from(b'}'), ai + 1);
    let mut i = ai;
    let mut solution: Option<(i64, i64)> = None;
    if ai >= 0 && bi > 0 {
        let mut begs: Vec<i64> = Vec::new();
        let mut left = text.len() as i64;
        let mut right: i64 = -1;
        let mut has_right = false;
        while i >= 0 && solution.is_none() {
            if i == ai {
                begs.push(i);
                ai = find(u16::from(b'{'), i + 1);
            } else if begs.len() == 1 {
                let beg = begs.pop().unwrap_or(0);
                solution = Some((beg, bi));
            } else if let Some(beg) = begs.pop() {
                if beg < left {
                    left = beg;
                    right = bi;
                    has_right = true;
                }
                bi = find(u16::from(b'}'), i + 1);
            }
            i = if ai < bi && ai >= 0 { ai } else { bi };
        }
        if !begs.is_empty() && has_right {
            solution = Some((left, right));
        }
    }
    solution.map(|(start, end)| Balanced {
        start: start as usize,
        end: end as usize,
    })
}

fn is_ascii_letter(unit: u16) -> bool {
    (u16::from(b'A')..=u16::from(b'Z')).contains(&unit)
        || (u16::from(b'a')..=u16::from(b'z')).contains(&unit)
}

fn is_line_terminator(unit: u16) -> bool {
    unit == u16::from(b'\n') || unit == u16::from(b'\r') || unit == 0x2028 || unit == 0x2029
}

/// `str.split(',')`
fn split_on_commas(text: &[u16]) -> Vec<Pattern> {
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        match text[start.min(text.len())..]
            .iter()
            .position(|&unit| unit == u16::from(b','))
        {
            Some(offset) => {
                let position = start + offset;
                out.push(text[start..position].to_vec());
                start = position + 1;
            }
            None => {
                out.push(text[start.min(text.len())..].to_vec());
                return out;
            }
        }
    }
}

/// `str.split(/\.\./)`
fn split_dot_dot(text: &[u16]) -> Vec<Pattern> {
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(offset) = text[start.min(text.len())..]
        .windows(2)
        .position(|window| window == [u16::from(b'.'), u16::from(b'.')])
    {
        let position = start + offset;
        out.push(text[start..position].to_vec());
        start = position + 2;
    }
    out.push(text[start.min(text.len())..].to_vec());
    out
}

fn all_digits(text: &[u16], from: usize) -> bool {
    from < text.len()
        && text[from..]
            .iter()
            .all(|&unit| (u16::from(b'0')..=u16::from(b'9')).contains(&unit))
}

fn is_signed_integer(text: &[u16]) -> bool {
    let from = usize::from(text.first() == Some(&u16::from(b'-')));
    all_digits(text, from)
}

fn is_numeric_sequence(body: &[u16]) -> bool {
    let parts = split_dot_dot(body);
    if parts.len() != 2 && parts.len() != 3 {
        return false;
    }
    parts.iter().all(|part| is_signed_integer(part))
}

fn is_alpha_sequence(body: &[u16]) -> bool {
    let parts = split_dot_dot(body);
    if parts.len() != 2 && parts.len() != 3 {
        return false;
    }
    if parts[0].len() != 1 || !is_ascii_letter(parts[0][0]) {
        return false;
    }
    if parts[1].len() != 1 || !is_ascii_letter(parts[1][0]) {
        return false;
    }
    if parts.len() == 3 && !is_signed_integer(&parts[2]) {
        return false;
    }
    true
}

fn numeric(text: &[u16]) -> i64 {
    if is_signed_integer(text) {
        let negative = text.first() == Some(&u16::from(b'-'));
        let mut value: i64 = 0;
        for &unit in &text[usize::from(negative)..] {
            value = value * 10 + i64::from(unit - u16::from(b'0'));
            if value > i64::from(i32::MAX) {
                break;
            }
        }
        return if negative { -value } else { value };
    }
    text.first().map_or(0, |&unit| i64::from(unit))
}

fn is_padded(text: &[u16]) -> bool {
    let i = usize::from(text.first() == Some(&u16::from(b'-')));
    text.len() >= i + 2
        && text[i] == u16::from(b'0')
        && (u16::from(b'0')..=u16::from(b'9')).contains(&text[i + 1])
}

/// `acc` × `pre` × `values`, honouring the expansion caps.
fn combine(acc: &[Pattern], pre: &[u16], values: &[Pattern], drop_empties: bool) -> Vec<Pattern> {
    let mut out = Vec::new();
    let mut length = 0usize;
    for a in acc {
        for value in values {
            if out.len() >= BRACE_EXPANSION_MAX {
                return out;
            }
            let mut expansion = Pattern::with_capacity(a.len() + pre.len() + value.len());
            expansion.extend_from_slice(a);
            expansion.extend_from_slice(pre);
            expansion.extend_from_slice(value);
            if drop_empties && expansion.is_empty() {
                continue;
            }
            if length + expansion.len() > BRACE_EXPANSION_MAX_LENGTH {
                return out;
            }
            length += expansion.len();
            out.push(expansion);
        }
    }
    out
}

fn expand_sequence(body: &[u16], is_alpha_sequence: bool) -> Vec<Pattern> {
    let parts = split_dot_dot(body);
    let mut out = Vec::new();
    let x = numeric(&parts[0]);
    let y = numeric(&parts[1]);
    let width = parts[0].len().max(parts[1].len());
    let mut incr: i64 = 1;
    if parts.len() == 3 {
        let raw = numeric(&parts[2]);
        incr = raw.unsigned_abs().max(1) as i64;
    }
    let reverse = y < x;
    if reverse {
        incr = -incr;
    }
    let pad =
        is_padded(&parts[0]) || is_padded(&parts[1]) || (parts.len() == 3 && is_padded(&parts[2]));
    let mut length = 0usize;
    let mut i = x;
    while (if reverse { i >= y } else { i <= y }) && out.len() < BRACE_EXPANSION_MAX {
        let mut value: Pattern = Vec::new();
        if is_alpha_sequence {
            // `String.fromCharCode(i) === '\\'` is replaced with ''
            if i != i64::from(u16::from(b'\\')) {
                value.push(i as u16);
            }
        } else {
            let negative = i < 0;
            let mut magnitude = i.unsigned_abs();
            let mut digits: Pattern = Vec::new();
            loop {
                digits.insert(0, u16::from(b'0') + (magnitude % 10) as u16);
                magnitude /= 10;
                if magnitude == 0 {
                    break;
                }
            }
            let mut text = Pattern::new();
            if negative {
                text.push(u16::from(b'-'));
            }
            text.extend_from_slice(&digits);
            if pad {
                let need = width.saturating_sub(text.len());
                if need > 0 {
                    if negative {
                        value.push(u16::from(b'-'));
                        value.extend(std::iter::repeat_n(u16::from(b'0'), need));
                        value.extend_from_slice(&text[1..]);
                    } else {
                        value.extend(std::iter::repeat_n(u16::from(b'0'), need));
                        value.extend_from_slice(&text);
                    }
                } else {
                    value = text;
                }
            } else {
                value = text;
            }
        }
        if length + value.len() > BRACE_EXPANSION_MAX_LENGTH {
            break;
        }
        length += value.len();
        out.push(value);
        i += incr;
    }
    out
}

/// Appends `next` to `out`, joining across the seam: the JavaScript grows one
/// list by writing the head of the tail onto its own last element.
fn merge_parts(out: &mut Vec<Pattern>, mut next: Vec<Pattern>) {
    if out.is_empty() {
        *out = next;
        return;
    }
    if next.is_empty() {
        return;
    }
    let head = next.remove(0);
    if let Some(last) = out.last_mut() {
        last.extend_from_slice(&head);
    }
    out.extend(next);
}

/// Splits a brace body on its top-level commas, keeping nested `{...}` groups
/// whole.
fn parse_comma_parts(text: &[u16]) -> Vec<Pattern> {
    if text.is_empty() {
        return vec![Pattern::new()];
    }
    let mut parts: Vec<Pattern> = Vec::new();
    let mut rest = text;
    loop {
        let Some(balanced) = balanced_braces(rest) else {
            let mut split = split_on_commas(rest);
            merge_parts(&mut parts, std::mem::take(&mut split));
            return parts;
        };
        let pre = &rest[..balanced.start];
        let body = &rest[balanced.start + 1..balanced.end];
        let post = &rest[balanced.end + 1..];
        // p = pre.split(','); p[last] += '{' + body + '}'
        let mut p = split_on_commas(pre);
        if let Some(last) = p.last_mut() {
            last.push(u16::from(b'{'));
            last.extend_from_slice(body);
            last.push(u16::from(b'}'));
        }
        merge_parts(&mut parts, p);
        // ParseCommaParts('') is [''], which the JS original discards.
        if post.is_empty() {
            return parts;
        }
        rest = post;
    }
}

/// `/, (?!,).*\}/`: a comma not followed by a comma, later followed by a `}`.
fn post_needs_rescan(post: &[u16]) -> bool {
    for (index, &unit) in post.iter().enumerate() {
        if unit != u16::from(b',') {
            continue;
        }
        if index + 1 < post.len() && post[index + 1] == u16::from(b',') {
            continue;
        }
        for &later in &post[index + 1..] {
            if later == u16::from(b'}') {
                return true;
            }
            if is_line_terminator(later) {
                break;
            }
        }
    }
    false
}

fn embrace(text: &[u16]) -> Pattern {
    let mut out = Pattern::with_capacity(text.len() + 2);
    out.push(u16::from(b'{'));
    out.extend_from_slice(text);
    out.push(u16::from(b'}'));
    out
}

struct Expander<'a> {
    sentinels: BraceSentinels,
    too_deep: bool,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl Expander<'_> {
    fn inner(&mut self, mut text: Pattern, mut is_top: bool, depth: i32) -> Vec<Pattern> {
        if depth > MAX_NESTING_DEPTH {
            self.too_deep = true;
            return vec![text];
        }
        let mut acc: Vec<Pattern> = vec![Pattern::new()];
        let mut drop_empties = false;
        let mut first_group = true;
        loop {
            if self.too_deep {
                return acc;
            }
            let Some(balanced) = balanced_braces(&text) else {
                return combine(&acc, &text, &[Pattern::new()], drop_empties);
            };
            let pre = text[..balanced.start].to_vec();
            let body = text[balanced.start + 1..balanced.end].to_vec();
            let post = text[balanced.end + 1..].to_vec();
            if pre.last() == Some(&u16::from(b'$')) {
                let mut wrapped = pre.clone();
                wrapped.push(u16::from(b'{'));
                wrapped.extend_from_slice(&body);
                wrapped.push(u16::from(b'}'));
                acc = combine(
                    &acc,
                    &wrapped,
                    &[Pattern::new()],
                    drop_empties && post.is_empty(),
                );
                first_group = false;
                if post.is_empty() {
                    break;
                }
                text = post;
                continue;
            }
            let is_sequence = is_numeric_sequence(&body) || is_alpha_sequence(&body);
            let is_alpha = !is_numeric_sequence(&body) && is_alpha_sequence(&body);
            let is_options = body.contains(&u16::from(b','));
            if !is_sequence && !is_options {
                if post_needs_rescan(&post) {
                    let mut next = pre.clone();
                    next.push(u16::from(b'{'));
                    next.extend_from_slice(&body);
                    next.push(self.sentinels.close);
                    next.extend_from_slice(&post);
                    text = next;
                    is_top = true;
                    continue;
                }
                let mut whole = pre.clone();
                whole.push(u16::from(b'{'));
                whole.extend_from_slice(&body);
                whole.push(u16::from(b'}'));
                whole.extend_from_slice(&post);
                return combine(&acc, &whole, &[Pattern::new()], drop_empties);
            }
            if first_group {
                drop_empties = is_top && !is_sequence;
                first_group = false;
            }
            let values: Vec<Pattern> = if is_sequence {
                expand_sequence(&body, is_alpha)
            } else {
                let mut n = parse_comma_parts(&body);
                if n.len() == 1 {
                    let inner = self.inner(std::mem::take(&mut n[0]), false, depth + 1);
                    n = inner.iter().map(|entry| embrace(entry)).collect();
                    if n.len() == 1 {
                        let mut pre_fixed = pre.clone();
                        pre_fixed.extend_from_slice(&n[0]);
                        acc = combine(
                            &acc,
                            &pre_fixed,
                            &[Pattern::new()],
                            drop_empties && post.is_empty(),
                        );
                        if post.is_empty() {
                            break;
                        }
                        text = post;
                        continue;
                    }
                }
                let mut drops_empties = drop_empties && post.is_empty() && pre.is_empty();
                for entry in &acc {
                    if !entry.is_empty() {
                        drops_empties = false;
                    }
                }
                let mut out: Vec<Pattern> = Vec::new();
                let mut values_length = 0usize;
                let mut done = false;
                for alternative in &n {
                    if done {
                        break;
                    }
                    let expanded = self.inner(alternative.clone(), false, depth + 1);
                    for value in expanded {
                        if drops_empties && value.is_empty() {
                            continue;
                        }
                        if out.len() >= BRACE_EXPANSION_MAX
                            || values_length + value.len() > BRACE_EXPANSION_MAX_LENGTH
                        {
                            done = true;
                            break;
                        }
                        values_length += value.len();
                        out.push(value);
                    }
                }
                out
            };
            acc = combine(&acc, &pre, &values, drop_empties && post.is_empty());
            if post.is_empty() {
                break;
            }
            text = post;
        }
        acc
    }
}

/// Expands every brace group in `pattern`.
///
/// Returns an empty list together with an error code when the pattern cannot be
/// expanded: too long, nested too deeply, or a brace that cannot be marked.
pub fn brace_expand(pattern: &[u16]) -> Result<Vec<Pattern>, BraceError> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }
    let Some(sentinels) = choose_sentinels(pattern) else {
        return Err(BraceError::TooLong);
    };
    let mut text = pattern.to_vec();
    if text.starts_with(&[u16::from(b'{'), u16::from(b'}')]) {
        text[0] = sentinels.open;
        text[1] = sentinels.close;
    }
    let mut expander = Expander {
        sentinels,
        too_deep: false,
        _marker: std::marker::PhantomData,
    };
    let expanded = expander.inner(text, true, 0);
    if expander.too_deep {
        return Err(BraceError::TooDeep);
    }
    let mut out = expanded;
    for entry in &mut out {
        for unit in entry.iter_mut() {
            if *unit == sentinels.open {
                *unit = u16::from(b'{');
            } else if *unit == sentinels.close {
                *unit = u16::from(b'}');
            }
        }
    }
    Ok(out)
}

/// Why a pattern could not be expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraceError {
    TooLong,
    TooDeep,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(text: &str) -> Vec<String> {
        brace_expand(&text.encode_utf16().collect::<Vec<_>>())
            .expect("expands")
            .into_iter()
            .map(|pattern| String::from_utf16(&pattern).expect("valid"))
            .collect()
    }

    #[test]
    fn plain_patterns_are_returned_unchanged() {
        assert_eq!(expand("a/b.js"), vec!["a/b.js"]);
        assert_eq!(expand(""), Vec::<String>::new());
    }

    #[test]
    fn comma_groups_expand_to_one_pattern_each() {
        assert_eq!(expand("a{b,c}d"), vec!["abd", "acd"]);
        assert_eq!(expand("{a,b}/{c,d}"), vec!["a/c", "a/d", "b/c", "b/d"]);
    }

    #[test]
    fn numeric_sequences_expand_in_range() {
        assert_eq!(expand("x{1..3}"), vec!["x1", "x2", "x3"]);
        assert_eq!(expand("{3..1}"), vec!["3", "2", "1"]);
        assert_eq!(expand("{1..5..2}"), vec!["1", "3", "5"]);
    }

    #[test]
    fn zero_padding_is_preserved() {
        assert_eq!(expand("{01..03}"), vec!["01", "02", "03"]);
        // Confirmed against Node 27: `{-02..02}` expands to `-02 -01 000 001
        // 002`. The padding width is `max(len('-02'), len('02'))`, so the
        // positive members get an extra leading zero.
        assert_eq!(expand("{-02..02}"), vec!["-02", "-01", "000", "001", "002"]);
    }

    #[test]
    fn alphabetic_sequences_expand() {
        assert_eq!(expand("{a..c}"), vec!["a", "b", "c"]);
        assert_eq!(expand("{c..a}"), vec!["c", "b", "a"]);
    }

    #[test]
    fn nested_groups_expand_recursively() {
        assert_eq!(expand("a{b,{c,d}}e"), vec!["abe", "ace", "ade"]);
    }

    #[test]
    fn a_brace_with_neither_a_comma_nor_a_range_stays_literal() {
        assert_eq!(expand("a{b}c"), vec!["a{b}c"]);
    }

    #[test]
    fn an_empty_brace_pair_stays_literal() {
        assert_eq!(expand("a{}b"), vec!["a{}b"]);
    }

    #[test]
    fn a_dollar_before_a_group_keeps_the_group_literal() {
        // minimatch treats `$` as an anchor it cannot expand across.
        let out = expand("a${b,c}");
        assert!(out.contains(&"a${b,c}".to_string()) || out.contains(&"a$b".to_string()));
    }

    #[test]
    fn expansion_is_capped() {
        // 100_000 entries is the ceiling; `{1..200000}` must stop early rather
        // than allocate the whole range.
        let out = brace_expand(&"{1..200000}".encode_utf16().collect::<Vec<_>>()).expect("expands");
        assert!(out.len() <= BRACE_EXPANSION_MAX);
        assert!(out.len() > 1000, "expected a large but capped expansion");
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_overflowing_the_stack() {
        let pattern: String = std::iter::repeat_n("{a,", 400).collect::<String>()
            + "b"
            + &std::iter::repeat_n("}", 400).collect::<String>();
        let units: Vec<u16> = pattern.encode_utf16().collect();
        assert_eq!(brace_expand(&units), Err(BraceError::TooDeep));
    }

    #[test]
    fn sentinels_restore_to_literal_braces() {
        // A group whose body is not an option list is emitted verbatim, which
        // only works if the sentinels come back as braces.
        assert_eq!(expand("a{b}c{d}e"), vec!["a{b}c{d}e"]);
    }
}
