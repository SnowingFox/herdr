//! The segment AST parser and full-pattern compiler.
//!
//! This ports `ParseSegmentAst`/`#parseAST`, `#flatten`, `#fillNegs` and
//! `ParsePattern` from `src/glob/glob_parser.cc`.
//!
//! The AST exists because extglobs nest and because `!(...)` is defined by its
//! surroundings: a `!` group's alternatives absorb whatever follows it in the
//! enclosing sequence. That absorption is what [`flatten`] and [`fill_negs`]
//! implement, and getting them wrong changes which paths match rather than how
//! fast they match.

use crate::ast::{Node, Part, Pattern, SegmentTree};
use crate::brace::{brace_expand, BraceError, MAX_NESTING_DEPTH, MAX_PATTERN_LENGTH};
use crate::unicode::is_line_terminator;

/// How deeply extglobs may nest through *adoption* before the depth counter
/// starts increasing. `*(@(...))` re-enters without consuming depth.
pub const MAX_EXTGLOB_RECURSION: i32 = 2;

/// Compile flags, the Rust form of `CompileFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompileFlags {
    /// `path.win32` matching: separators may be `\`, drives are recognised.
    pub windows: bool,
    /// Case-insensitive matching.
    pub nocase: bool,
    /// With `nocase`, fold case in magic segments only and keep literal
    /// segments exact. `fs.glob` and `path.matchesGlob` set this; exclude
    /// patterns clear it.
    pub nocase_magic_only: bool,
    /// Let wildcards match a leading dot.
    pub dot: bool,
    /// A pattern with no separator matches the path's basename.
    pub match_base: bool,
}

/// Whether the host folds case by default.
pub fn host_nocase() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// Whether the host's paths use `\` and drive letters.
pub fn host_windows() -> bool {
    cfg!(windows)
}

impl CompileFlags {
    /// The flags `hasMagic` uses: the host's own walk rules.
    pub fn host_walk() -> Self {
        Self {
            windows: host_windows(),
            nocase: host_nocase(),
            nocase_magic_only: true,
            dot: false,
            match_base: false,
        }
    }

    /// The flags `matchesGlob` uses: the host's case rules plus the caller's
    /// platform choice.
    pub fn host_match(windows: bool, dot: bool) -> Self {
        Self {
            windows,
            nocase: host_nocase(),
            nocase_magic_only: true,
            dot,
            match_base: false,
        }
    }
}

/// Why a pattern failed to compile, matching `CompileError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileError {
    PatternTooLong,
    PatternTooDeep,
    InvalidRegExp,
}

impl CompileError {
    /// The message Node throws for this error, and whether it is a `SyntaxError`.
    pub fn message(self) -> (&'static str, bool) {
        match self {
            Self::PatternTooDeep => ("pattern nests too deeply", false),
            Self::InvalidRegExp => ("invalid generated regular expression", true),
            Self::PatternTooLong => ("pattern is too long", false),
        }
    }
}

impl From<BraceError> for CompileError {
    fn from(error: BraceError) -> Self {
        match error {
            BraceError::TooLong => Self::PatternTooLong,
            BraceError::TooDeep => Self::PatternTooDeep,
        }
    }
}

/// One part of a path after splitting on `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPart {
    /// A run of `**`.
    Globstar,
    /// A part that must compare equal, used for forced-literal Windows roots.
    Literal(Pattern),
    /// A parsed segment with its own AST.
    Segment { source: Pattern, tree: SegmentTree },
}

/// One row: a brace-expanded path pattern split into parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    pub parts: Vec<PathPart>,
}

/// A pattern compiled down to rows of path parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedPattern {
    pub rows: Vec<Row>,
    /// An empty pattern matches only the empty path.
    pub empty: bool,
}

/// Splits on `/`, treating a run of separators as one, with the Windows
/// drive-relative `//server` quirk.
pub fn slash_split(text: &[u16], windows: bool) -> Vec<Pattern> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    if windows
        && text.len() >= 3
        && text[0] == u16::from(b'/')
        && text[1] == u16::from(b'/')
        && text[2] != u16::from(b'/')
    {
        out.push(Pattern::new());
    }
    while index < text.len() {
        if text[index] != u16::from(b'/') {
            index += 1;
            continue;
        }
        out.push(text[start..index].to_vec());
        while index < text.len() && text[index] == u16::from(b'/') {
            index += 1;
        }
        start = index;
    }
    out.push(text[start..].to_vec());
    out
}

/// Compares a part against an ASCII literal.
pub fn part_is(part: &[u16], text: &str) -> bool {
    part.len() == text.len() && text.encode_utf16().eq(part.iter().copied())
}

fn index_of_part(parts: &[Pattern], needle: &str, from: i64) -> i64 {
    let start = if from < 0 { 0 } else { from as usize };
    let begin = start.min(parts.len());
    parts[begin..]
        .iter()
        .position(|part| part_is(part, needle))
        .map_or(-1, |offset| (begin + offset) as i64)
}

fn dot_part() -> Pattern {
    vec![u16::from(b'.')]
}

fn globstar_part() -> Pattern {
    vec![u16::from(b'*'), u16::from(b'*')]
}

/// `<pre>/<e>/<rest>` → `<pre>/<rest>`, plus the `./.`-tail rule.
fn squeeze_empties_and_dots(parts: &mut Vec<Pattern>) -> bool {
    let mut did_something = false;
    let mut i = 1usize;
    while i + 1 < parts.len() {
        let empty = parts[i].is_empty();
        // A UNC root keeps its leading empty part.
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

/// Whether `text` is a Windows drive designator: `c:`.
pub fn is_windows_drive(text: &[u16]) -> bool {
    text.len() == 2 && text[1] == u16::from(b':') && is_ascii_letter_unit(text[0])
}

fn is_ascii_letter_unit(unit: u16) -> bool {
    (u16::from(b'A')..=u16::from(b'Z')).contains(&unit)
        || (u16::from(b'a')..=u16::from(b'z')).contains(&unit)
}

/// Collapses `**` runs and splits `/**/../` into two rows.
fn first_phase_pre_process(glob_parts: &mut Vec<Vec<Pattern>>) {
    loop {
        let mut did_something = false;
        let mut row = 0;
        while row < glob_parts.len() {
            // The row is processed through an owned buffer: the JavaScript
            // re-reads its row pointer because pushing to the outer array can
            // reallocate, and a buffer makes that impossible to get wrong.
            let mut parts = glob_parts[row].clone();
            let mut gs: i64 = -1;
            loop {
                gs = index_of_part(&parts, "**", gs + 1);
                if gs < 0 {
                    break;
                }
                let gs_index = gs as usize;
                let mut gss = gs_index;
                while gss + 1 < parts.len() && part_is(&parts[gss + 1], "**") {
                    gss += 1;
                }
                if gss > gs_index {
                    parts.drain(gs_index + 1..gss + 1);
                }
                if gs_index + 1 >= parts.len() || !part_is(&parts[gs_index + 1], "..") {
                    continue;
                }
                let p_ok = gs_index + 2 < parts.len()
                    && !parts[gs_index + 2].is_empty()
                    && !part_is(&parts[gs_index + 2], ".")
                    && !part_is(&parts[gs_index + 2], "..");
                let p2_ok = gs_index + 3 < parts.len()
                    && !parts[gs_index + 3].is_empty()
                    && !part_is(&parts[gs_index + 3], ".")
                    && !part_is(&parts[gs_index + 3], "..");
                if !p_ok || !p2_ok {
                    continue;
                }
                did_something = true;
                // `<pre>/**/../<p>/<p>/<rest>`
                //   -> {<pre>/../<p>/<p>/<rest>, <pre>/**/<p>/<p>/<rest>}
                parts.remove(gs_index);
                let mut other = parts.clone();
                other[gs_index] = globstar_part();
                glob_parts.push(other);
                gs -= 1;
            }
            if squeeze_empties_and_dots(&mut parts) {
                did_something = true;
            }
            let mut dd: i64 = 0;
            loop {
                dd = index_of_part(&parts, "..", dd + 1);
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
                {
                    continue;
                }
                did_something = true;
                let start = dd as usize - 1;
                let need_dot = dd == 1
                    && (dd as usize + 1) < parts.len()
                    && part_is(&parts[dd as usize + 1], "**");
                parts.drain(start..start + 2);
                if need_dot {
                    parts.insert(start, dot_part());
                }
                if parts.is_empty() {
                    parts.push(Pattern::new());
                }
                dd -= 2;
            }
            glob_parts[row] = parts;
            row += 1;
        }
        if !did_something {
            return;
        }
    }
}

/// `partsMatch(a, b, emptyGSMatch = true)`
fn parts_match(a: &[Pattern], b: &[Pattern], dot: bool, result: &mut Vec<Pattern>) -> bool {
    let mut ai = 0usize;
    let mut bi = 0usize;
    result.clear();
    let mut which = '\0';
    while ai < a.len() && bi < b.len() {
        if a[ai] == b[bi] {
            result.push(if which == 'b' {
                b[bi].clone()
            } else {
                a[ai].clone()
            });
            ai += 1;
            bi += 1;
        } else if part_is(&a[ai], "**") && bi < b.len() && ai + 1 < a.len() && b[bi] == a[ai + 1] {
            result.push(a[ai].clone());
            ai += 1;
        } else if part_is(&b[bi], "**") && ai < a.len() && bi + 1 < b.len() && a[ai] == b[bi + 1] {
            result.push(b[bi].clone());
            bi += 1;
        } else if part_is(&a[ai], "*")
            && !b[bi].is_empty()
            && (dot || b[bi][0] != u16::from(b'.'))
            && !part_is(&b[bi], "**")
        {
            if which == 'b' {
                return false;
            }
            which = 'a';
            result.push(a[ai].clone());
            ai += 1;
            bi += 1;
        } else if part_is(&b[bi], "*")
            && !a[ai].is_empty()
            && (dot || a[ai][0] != u16::from(b'.'))
            && !part_is(&a[ai], "**")
        {
            if which == 'a' {
                return false;
            }
            which = 'b';
            result.push(b[bi].clone());
            ai += 1;
            bi += 1;
        } else {
            return false;
        }
    }
    a.len() == b.len()
}

/// Folds a duplicate row into the later one that subsumes it.
fn second_phase_pre_process(glob_parts: &mut Vec<Vec<Pattern>>, flags: &CompileFlags) {
    let mut matched = Vec::new();
    let mut i = 0usize;
    while i + 1 < glob_parts.len() {
        for j in i + 1..glob_parts.len() {
            if parts_match(&glob_parts[i], &glob_parts[j], flags.dot, &mut matched) {
                glob_parts[i].clear();
                glob_parts[j] = matched.clone();
                break;
            }
        }
        i += 1;
    }
    glob_parts.retain(|row| !row.is_empty());
}

/// Minimatch's `preprocess` at optimization level 2.
pub fn preprocess_level2(glob_parts: &mut Vec<Vec<Pattern>>, flags: &CompileFlags) {
    first_phase_pre_process(glob_parts);
    second_phase_pre_process(glob_parts, flags);
}

fn is_extglob_type(unit: u16) -> bool {
    unit == u16::from(b'!')
        || unit == u16::from(b'?')
        || unit == u16::from(b'+')
        || unit == u16::from(b'*')
        || unit == u16::from(b'@')
}

/// `adoptionMap` / `adoptionWithSpaceMap` / `adoptionAnyMap`, keyed by `which`.
fn can_adopt_type(parent: char, child: char, which: u8) -> bool {
    let contains = |set: &str| set.contains(child);
    match which {
        0 => match parent {
            '!' => contains("@"),
            '?' => contains("?@"),
            '@' => contains("@"),
            '*' => contains("*+?@"),
            '+' => contains("+@"),
            _ => false,
        },
        1 => match parent {
            '!' => contains("?"),
            '@' => contains("?"),
            '+' => contains("?*"),
            _ => false,
        },
        _ => match parent {
            '!' => contains("?@"),
            '?' => contains("?@"),
            '@' => contains("?@"),
            '*' => contains("*+?@"),
            '+' => contains("+@?*"),
            _ => false,
        },
    }
}

/// `usurpMap`
fn usurp_result(parent: char, child: char) -> char {
    match parent {
        '!' if child == '!' => '@',
        '!' => '\0',
        '?' => {
            if child == '*' || child == '+' {
                '*'
            } else {
                '\0'
            }
        }
        '@' => match child {
            '!' | '?' | '@' | '*' | '+' => child,
            _ => '\0',
        },
        '+' if child == '?' || child == '*' => '*',
        '+' => '\0',
        _ => '\0',
    }
}

/// The mutable state one segment's parse accumulates: the node arena and the
/// `!` nodes waiting for `fill_negs`.
struct ParseCtx {
    nodes: Vec<Node>,
    negs: Vec<usize>,
    too_deep: bool,
}

impl ParseCtx {
    fn new_node(&mut self, kind: char, parent: Option<usize>) -> usize {
        let parent_index = parent.map_or(0, |index| self.nodes[index].parts.len());
        let index = self.nodes.len();
        self.nodes.push(Node {
            kind,
            parts: Vec::new(),
            empty_ext: false,
            parent,
            parent_index,
        });
        if kind == '!' {
            self.negs.push(index);
        }
        index
    }

    fn push_text(&mut self, node: usize, text: Pattern) {
        // `AST.push` skips ''
        if !text.is_empty() {
            self.nodes[node].parts.push(Part::Text(text));
        }
    }

    fn push_child(&mut self, node: usize, child: usize) {
        self.nodes[node].parts.push(Part::Child(child));
    }
}

fn char_of(unit: u16) -> char {
    char::from_u32(u32::from(unit)).unwrap_or('\0')
}

/// `#parseAST(str, ast, pos, opt, extDepth)`, plus the depth guard.
///
/// The two halves of the original — a plain sequence and an extglob body — are
/// kept in one function because the recursion alternates between them, and they
/// share the escape and bracket-tracking state machine verbatim.
fn parse_ast_inner(
    text: &[u16],
    ast: usize,
    mut pos: usize,
    ctx: &mut ParseCtx,
    ext_depth: i32,
    depth: i32,
) -> usize {
    let mut escaping = false;
    let mut in_brace = false;
    let mut brace_start = 0usize;
    let mut brace_neg = false;

    // A plain sequence: accumulate text and recurse into any extglob it finds.
    if ctx.nodes[ast].kind == '\0' {
        let mut i = pos;
        let mut acc: Pattern = Vec::new();
        while i < text.len() {
            let c = text[i];
            i += 1;
            if escaping || c == u16::from(b'\\') {
                escaping = !escaping;
                acc.push(c);
                continue;
            }
            if in_brace {
                if i == brace_start + 1 {
                    if c == u16::from(b'^') || c == u16::from(b'!') {
                        brace_neg = true;
                    }
                } else if c == u16::from(b']') && !(i == brace_start + 2 && brace_neg) {
                    in_brace = false;
                }
                acc.push(c);
                continue;
            } else if c == u16::from(b'[') {
                in_brace = true;
                brace_start = i;
                brace_neg = false;
                acc.push(c);
                continue;
            }
            let do_recurse = is_extglob_type(c)
                && i < text.len()
                && text[i] == u16::from(b'(')
                && ext_depth <= MAX_EXTGLOB_RECURSION;
            if do_recurse {
                if depth >= MAX_NESTING_DEPTH {
                    ctx.too_deep = true;
                    return i;
                }
                ctx.push_text(ast, std::mem::take(&mut acc));
                let ext = ctx.new_node(char_of(c), Some(ast));
                i = parse_ast_inner(text, ext, i, ctx, ext_depth + 1, depth + 1);
                ctx.push_child(ast, ext);
                if ctx.too_deep {
                    return i;
                }
                continue;
            }
            acc.push(c);
        }
        pos = i;
        ctx.push_text(ast, acc);
        return pos;
    }

    // An extglob body; `pos` is at the '('.
    let mut i = pos + 1;
    let mut part = ctx.new_node('\0', Some(ast));
    let mut parts: Vec<usize> = Vec::new();
    let mut acc: Pattern = Vec::new();
    while i < text.len() {
        let c = text[i];
        i += 1;
        if escaping || c == u16::from(b'\\') {
            escaping = !escaping;
            acc.push(c);
            continue;
        }
        if in_brace {
            if i == brace_start + 1 {
                if c == u16::from(b'^') || c == u16::from(b'!') {
                    brace_neg = true;
                }
            } else if c == u16::from(b']') && !(i == brace_start + 2 && brace_neg) {
                in_brace = false;
            }
            acc.push(c);
            continue;
        } else if c == u16::from(b'[') {
            in_brace = true;
            brace_start = i;
            brace_neg = false;
            acc.push(c);
            continue;
        }
        let parent_kind = ctx.nodes[ast].kind;
        let adoptable = can_adopt_type(parent_kind, char_of(c), 2);
        let do_recurse = is_extglob_type(c)
            && i < text.len()
            && text[i] == u16::from(b'(')
            && (ext_depth <= MAX_EXTGLOB_RECURSION || adoptable);
        if do_recurse {
            if depth >= MAX_NESTING_DEPTH {
                ctx.too_deep = true;
                return i;
            }
            let depth_add = i32::from(!adoptable);
            ctx.push_text(part, std::mem::take(&mut acc));
            let ext = ctx.new_node(char_of(c), Some(part));
            ctx.push_child(part, ext);
            i = parse_ast_inner(text, ext, i, ctx, ext_depth + depth_add, depth + 1);
            if ctx.too_deep {
                return i;
            }
            continue;
        }
        if c == u16::from(b'|') {
            ctx.push_text(part, std::mem::take(&mut acc));
            parts.push(part);
            part = ctx.new_node('\0', Some(ast));
            continue;
        }
        if c == u16::from(b')') {
            if acc.is_empty() && ctx.nodes[ast].parts.is_empty() {
                ctx.nodes[ast].empty_ext = true;
            }
            ctx.push_text(part, std::mem::take(&mut acc));
            for previous in std::mem::take(&mut parts) {
                ctx.push_child(ast, previous);
            }
            ctx.push_child(ast, part);
            return i;
        }
        acc.push(c);
    }
    // Unfinished extglob: revert this node to plain text from the type char on.
    ctx.nodes[ast].kind = '\0';
    ctx.nodes[ast].parts.clear();
    ctx.nodes[ast]
        .parts
        .push(Part::Text(text[pos - 1..].to_vec()));
    i
}

/// Whether `parts[index]` of `parent` is a child whose grandchild `parent` can
/// adopt, per minimatch's `#canAdopt` / `#canAdoptWithSpace`.
fn adoptable_grandchild(nodes: &[Node], parent: usize, index: usize, which: u8) -> Option<usize> {
    let self_kind = nodes[parent].kind;
    if self_kind == '\0' {
        return None;
    }
    let Part::Child(child) = nodes[parent].parts[index] else {
        return None;
    };
    let middle = &nodes[child];
    if middle.kind != '\0' || middle.parts.len() != 1 {
        return None;
    }
    let Part::Child(grandchild) = middle.parts[0] else {
        return None;
    };
    let grandchild_kind = nodes[grandchild].kind;
    if grandchild_kind == '\0' {
        return None;
    }
    if !can_adopt_type(self_kind, grandchild_kind, which) {
        return None;
    }
    Some(grandchild)
}

// ---------------------------------------------------------------------------
// Flatten
// ---------------------------------------------------------------------------

/// `#adopt`: replaces a child with its grandchild's parts.
///
/// Takes `&mut [Node]` rather than `&mut Vec<Node>`: it only reorders parts and
/// repoints parents, so no node is ever added and the arena cannot grow.
fn adopt(nodes: &mut [Node], parent: usize, index: usize) {
    let Part::Child(child) = nodes[parent].parts[index] else {
        return;
    };
    let Part::Child(grandchild) = nodes[child].parts[0] else {
        return;
    };
    let moved = nodes[grandchild].parts.clone();
    nodes[parent].parts.remove(index);
    for (offset, part) in moved.into_iter().enumerate() {
        if let Part::Child(moved_child) = part {
            nodes[moved_child].parent = Some(parent);
        }
        nodes[parent].parts.insert(index + offset, part);
    }
}

/// `#adoptWithSpace`: adopts, but leaves an empty alternative behind so the
/// group can still match nothing.
fn adopt_with_space(nodes: &mut Vec<Node>, parent: usize, index: usize) {
    let Part::Child(child) = nodes[parent].parts[index] else {
        return;
    };
    let Part::Child(grandchild) = nodes[child].parts[0] else {
        return;
    };
    let blank_index = nodes.len();
    let blank_position = nodes[grandchild].parts.len();
    nodes.push(Node {
        kind: '\0',
        parts: vec![Part::Text(Pattern::new())],
        empty_ext: false,
        parent: Some(grandchild),
        parent_index: blank_position,
    });
    nodes[grandchild].parts.push(Part::Child(blank_index));
    adopt(nodes, parent, index);
}

/// `#canUsurp`
fn can_usurp(nodes: &[Node], index: usize) -> bool {
    let node = &nodes[index];
    if node.kind == '\0' || node.parts.len() != 1 {
        return false;
    }
    let Part::Child(child) = node.parts[0] else {
        return false;
    };
    let middle = &nodes[child];
    if middle.kind != '\0' || middle.parts.len() != 1 {
        return false;
    }
    let Part::Child(grandchild) = middle.parts[0] else {
        return false;
    };
    if nodes[grandchild].kind == '\0' {
        return false;
    }
    usurp_result(node.kind, nodes[grandchild].kind) != '\0'
}

/// `#usurp`: the grandchild's alternatives replace the node's.
///
/// The detached `!` husk stays registered for `fill_negs`, which must write
/// through it into the usurper's alternatives: `!(!(x))y` depends on it.
fn usurp(nodes: &mut [Node], index: usize) {
    let Part::Child(child) = nodes[index].parts[0] else {
        return;
    };
    let Part::Child(grandchild) = nodes[child].parts[0] else {
        return;
    };
    let new_kind = usurp_result(nodes[index].kind, nodes[grandchild].kind);
    let moved = nodes[grandchild].parts.clone();
    for part in &moved {
        if let Part::Child(moved_child) = part {
            nodes[*moved_child].parent = Some(index);
        }
    }
    nodes[index].parts = moved;
    nodes[index].kind = new_kind;
    nodes[index].empty_ext = false;
}

const MAX_FLATTEN_PASSES: i32 = 10;

/// `#flatten`: collapses single-child extglob chains.
fn flatten(nodes: &mut Vec<Node>, index: usize) {
    if nodes[index].kind == '\0' {
        let children: Vec<usize> = nodes[index]
            .parts
            .iter()
            .filter_map(|part| match part {
                Part::Child(child) => Some(*child),
                Part::Text(_) => None,
            })
            .collect();
        for child in children {
            flatten(nodes, child);
        }
        return;
    }
    let mut iterations = 0i32;
    loop {
        let mut done = true;
        let mut i = 0usize;
        while i < nodes[index].parts.len() {
            let Part::Child(child) = nodes[index].parts[i] else {
                i += 1;
                continue;
            };
            flatten(nodes, child);
            if adoptable_grandchild(nodes, index, i, 0).is_some() {
                done = false;
                adopt(nodes, index, i);
            } else if adoptable_grandchild(nodes, index, i, 1).is_some() {
                done = false;
                adopt_with_space(nodes, index, i);
            } else if nodes[index].parts.len() == 1 && can_usurp(nodes, index) {
                done = false;
                usurp(nodes, index);
            }
            i += 1;
        }
        iterations += 1;
        if done || iterations >= MAX_FLATTEN_PASSES {
            return;
        }
    }
}

/// `#fillNegs`: copies what follows a `!` group into each of its alternatives.
///
/// `!` means "the rest of the segment is not this", so the alternatives have to
/// see the text after the group. Copying it in (rather than looking ahead at
/// match time) is what minimatch does, and what makes `!(a)b` reject `ab`.
fn fill_negs(nodes: &mut Vec<Node>, negs: &mut Vec<usize>) {
    while let Some(neg) = negs.pop() {
        if nodes[neg].kind != '!' {
            continue;
        }
        let mut p = neg;
        let mut parent = nodes[p].parent;
        while let Some(grandparent) = parent {
            if nodes[grandparent].kind == '\0' {
                let start = nodes[p].parent_index + 1;
                let source: Vec<Part> = if start < nodes[grandparent].parts.len() {
                    nodes[grandparent].parts[start..].to_vec()
                } else {
                    Vec::new()
                };
                let alternatives: Vec<usize> = nodes[neg]
                    .parts
                    .iter()
                    .filter_map(|part| match part {
                        Part::Child(child) => Some(*child),
                        Part::Text(_) => None,
                    })
                    .collect();
                for alternative in alternatives {
                    for part in &source {
                        match part {
                            Part::Child(child) => {
                                let copy = clone_into(nodes, *child, alternative);
                                nodes[alternative].parts.push(Part::Child(copy));
                            }
                            Part::Text(text) => {
                                nodes[alternative].parts.push(Part::Text(text.clone()))
                            }
                        }
                    }
                }
            }
            p = grandparent;
            parent = nodes[p].parent;
        }
    }
}

/// `CloneNode` against a live arena.
fn clone_into(nodes: &mut Vec<Node>, source: usize, parent: usize) -> usize {
    let (kind, empty_ext, parts) = {
        let node = &nodes[source];
        (node.kind, node.empty_ext, node.parts.clone())
    };
    let position = nodes[parent].parts.len();
    let index = nodes.len();
    nodes.push(Node {
        kind,
        parts: Vec::new(),
        empty_ext,
        parent: Some(parent),
        parent_index: position,
    });
    for part in parts {
        match part {
            Part::Child(child) => {
                let copy = clone_into(nodes, child, index);
                nodes[index].parts.push(Part::Child(copy));
            }
            // `copyIn` goes through `push()`, which skips ''
            Part::Text(text) => {
                if !text.is_empty() {
                    nodes[index].parts.push(Part::Text(text));
                }
            }
        }
    }
    index
}

/// Parses one segment into its AST, then flattens and fills negations.
pub fn parse_segment_ast(part: &[u16]) -> Result<SegmentTree, CompileError> {
    let mut ctx = ParseCtx {
        nodes: Vec::new(),
        negs: Vec::new(),
        too_deep: false,
    };
    let root = ctx.new_node('\0', None);
    let _ = parse_ast_inner(part, root, 0, &mut ctx, 0, 0);
    if ctx.too_deep {
        return Err(CompileError::PatternTooDeep);
    }
    flatten(&mut ctx.nodes, root);
    let mut negs = ctx.negs.clone();
    fill_negs(&mut ctx.nodes, &mut negs);
    Ok(SegmentTree { nodes: ctx.nodes })
}

/// Whether the segment is anything more than a literal path.
pub fn has_glob_magic(text: &[u16]) -> bool {
    for (index, &unit) in text.iter().enumerate() {
        if unit == u16::from(b'?')
            || unit == u16::from(b'*')
            || unit == u16::from(b'[')
            || unit == u16::from(b']')
        {
            return true;
        }
        if (unit == u16::from(b'+') || unit == u16::from(b'@') || unit == u16::from(b'!'))
            && index + 1 < text.len()
            && text[index + 1] == u16::from(b'(')
        {
            for &later in &text[index + 2..] {
                if later == u16::from(b')') {
                    return true;
                }
                if is_line_terminator(later) {
                    break;
                }
            }
        }
    }
    false
}

/// Compiles a raw pattern, brace-expanding and splitting it into rows.
pub fn parse_pattern(raw: &[u16], flags: &CompileFlags) -> Result<ParsedPattern, CompileError> {
    if raw.len() > MAX_PATTERN_LENGTH {
        return Err(CompileError::PatternTooLong);
    }
    // `windowsPathsNoEscape`: every backslash becomes a slash, on all
    // platforms, so a pattern produced by `path.join()` on Windows still works.
    let pattern: Pattern = raw
        .iter()
        .map(|&unit| {
            if unit == u16::from(b'\\') {
                u16::from(b'/')
            } else {
                unit
            }
        })
        .collect();
    if pattern.is_empty() {
        return Ok(ParsedPattern {
            rows: Vec::new(),
            empty: true,
        });
    }
    let glob_set = brace_expand(&pattern)?;
    // `globSet = [...new Set(braceExpand(pattern))]`
    let mut deduped: Vec<Pattern> = Vec::with_capacity(glob_set.len());
    for entry in glob_set {
        if !deduped.contains(&entry) {
            deduped.push(entry);
        }
    }
    let mut glob_parts: Vec<Vec<Pattern>> = deduped
        .iter()
        .map(|entry| slash_split(entry, flags.windows))
        .collect();
    preprocess_level2(&mut glob_parts, flags);

    // `windowsNoMagicRoot = isWindows && nocase`
    let windows_no_magic_root = flags.windows && flags.nocase;
    // `'//server/share/'` splits into `['', '', 'server', 'share']`.
    const UNC_ROOT_PARTS: usize = 4;

    let magic_at = |parts: &[Pattern], index: usize| -> bool {
        parts.get(index).is_some_and(|part| has_glob_magic(part))
    };

    let mut rows = Vec::with_capacity(glob_parts.len());
    for parts in &glob_parts {
        let mut literal_prefix = 0usize;
        if windows_no_magic_root {
            let is_unc = parts.len() >= 2
                && parts[0].is_empty()
                && parts[1].is_empty()
                && ((parts.len() > 2 && parts[2] == [u16::from(b'?')]) || !magic_at(parts, 2))
                && !magic_at(parts, 3);
            let is_drive = parts.first().is_some_and(|part| is_windows_drive(part));
            if is_unc {
                literal_prefix = UNC_ROOT_PARTS.min(parts.len());
            } else if is_drive {
                literal_prefix = 1;
            }
        }
        let mut row = Row::default();
        for (index, source) in parts.iter().enumerate() {
            if index < literal_prefix {
                // A forced-literal Windows root part compares with `===`.
                row.parts.push(PathPart::Literal(source.clone()));
                continue;
            }
            if source.len() > MAX_PATTERN_LENGTH {
                return Err(CompileError::PatternTooLong);
            }
            // Only a segment that is exactly `**` is a globstar; elsewhere the
            // extra stars are redundant with `*`, so `a/**b` compiles as `a/*b`.
            if part_is(source, "**") {
                row.parts.push(PathPart::Globstar);
            } else {
                let tree = parse_segment_ast(source)?;
                row.parts.push(PathPart::Segment {
                    source: source.clone(),
                    tree,
                });
            }
        }
        // The UNC `?` restore quirk: `//?/c:/...` keeps its `?` literal.
        if row.parts.len() >= UNC_ROOT_PARTS
            && matches!(&row.parts[0], PathPart::Literal(literal) if literal.is_empty())
            && matches!(&row.parts[1], PathPart::Literal(literal) if literal.is_empty())
            && matches!(&row.parts[2], PathPart::Literal(literal) if *literal == [u16::from(b'?')])
            && matches!(&row.parts[3], PathPart::Literal(literal) if is_windows_drive(literal))
        {
            row.parts[2] = PathPart::Literal(vec![u16::from(b'?')]);
        }
        rows.push(row);
    }
    Ok(ParsedPattern { rows, empty: false })
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

    fn text(part: &Pattern) -> String {
        String::from_utf16(part).expect("valid utf-16")
    }

    #[test]
    fn magic_is_detected_for_wildcards_and_extglobs() {
        assert!(!has_glob_magic(&pattern("a/b")));
        assert!(has_glob_magic(&pattern("*.js")));
        assert!(has_glob_magic(&pattern("a?")));
        assert!(has_glob_magic(&pattern("[abc]")));
        assert!(has_glob_magic(&pattern("@(a|b)")));
        // Braces alone are not magic: they expand before matching.
        assert!(!has_glob_magic(&pattern("{a,b}")));
        // A `+` without `(` is a literal plus.
        assert!(!has_glob_magic(&pattern("a+b")));
    }

    #[test]
    fn splitting_keeps_empty_parts() {
        assert_eq!(
            slash_split(&pattern("a/b/c"), false)
                .iter()
                .map(text)
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            slash_split(&pattern("/a//b/"), false)
                .iter()
                .map(text)
                .collect::<Vec<_>>(),
            vec!["", "a", "b", ""]
        );
    }

    #[test]
    fn globstar_runs_collapse() {
        let mut rows = vec![vec![
            pattern("a"),
            pattern("**"),
            pattern("**"),
            pattern("b"),
        ]];
        preprocess_level2(&mut rows, &flags());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].iter().map(text).collect::<Vec<_>>(),
            vec!["a", "**", "b"]
        );
    }

    #[test]
    fn parsing_marks_globstars() {
        let parsed = parse_pattern(&pattern("a/**/b"), &flags()).expect("parses");
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].parts.len(), 3);
        assert!(matches!(parsed.rows[0].parts[0], PathPart::Segment { .. }));
        assert!(matches!(parsed.rows[0].parts[1], PathPart::Globstar));
        assert!(matches!(parsed.rows[0].parts[2], PathPart::Segment { .. }));
    }

    #[test]
    fn an_empty_pattern_matches_only_the_empty_path() {
        let parsed = parse_pattern(&[], &flags()).expect("parses");
        assert!(parsed.empty);
        assert!(parsed.rows.is_empty());
    }

    #[test]
    fn brace_expansion_produces_one_row_per_alternative() {
        let parsed = parse_pattern(&pattern("{a,b}/c"), &flags()).expect("parses");
        assert_eq!(parsed.rows.len(), 2);
    }

    #[test]
    fn too_long_a_pattern_is_refused() {
        let long = vec![u16::from(b'a'); MAX_PATTERN_LENGTH + 1];
        assert_eq!(
            parse_pattern(&long, &flags()),
            Err(CompileError::PatternTooLong)
        );
    }

    #[test]
    fn backslashes_become_separators() {
        // `windowsPathsNoEscape` applies on every platform, so a pattern built
        // with `path.join()` on Windows is usable here.
        let parsed = parse_pattern(&pattern("a\\b"), &flags()).expect("parses");
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].parts.len(), 2);
    }

    #[test]
    fn extglob_parsing_records_alternatives() {
        let tree = parse_segment_ast(&pattern("@(a|b)")).expect("parses");
        // Node 0 is the sequence root; the `@` group is its only child.
        assert_eq!(tree.nodes[0].kind, '\0');
        let Part::Child(group) = tree.nodes[0].parts[0] else {
            panic!("expected a child node");
        };
        assert!(tree.nodes[group].is_extglob());
        assert_eq!(tree.nodes[group].kind, '@');
        // Two alternatives, each a child node.
        assert_eq!(tree.nodes[group].parts.len(), 2);
    }

    #[test]
    fn an_unclosed_extglob_falls_back_to_literal_text() {
        let tree = parse_segment_ast(&pattern("@(a")).expect("parses");
        assert_eq!(tree.nodes[0].kind, '\0');
        let rendered = tree.nodes[0].to_pattern(&tree.nodes);
        assert_eq!(text(&rendered), "@(a");
    }
}
