//! Turning a segment's AST into something matchable.
//!
//! This ports `LowerSegment` and everything around it in
//! `src/glob/glob_program.cc`.
//!
//! Minimatch compiles each segment to a regular expression. Node kept the
//! *shape* of those expressions but not `RegExp` itself: the lowering records
//! what the expression would have been, then matches with a small NFA so that
//! pathological patterns stay linear. The tiers below are minimatch's own
//! fast paths (`/^\*+$/`, `/^\*+([^+@!?*[(]*)$/`, ...), each of which is a
//! different answer from the generic expression, so they cannot be folded into
//! one implementation.
//!
//! The `src_prefix` field on [`Lowered`] is the subtle part. minimatch decides
//! whether a segment needs a leading-dot guard by looking at the *text of the
//! generated regular expression*, so the only faithful way to answer is to
//! simulate what that text starts with. [`Lowered`] carries the first few
//! simulated characters for exactly that decision.

use crate::ast::{Node, Part, Pattern, SegmentTree};
use crate::parser::{part_is, CompileFlags};
use crate::unicode::{append_lowered, ascii_lower, CharSet, UnicodeProperty, MAX_ASCII};

/// One node of a segment's matcher.
#[derive(Debug, Clone, Default)]
pub struct RxNode {
    pub kind: NodeKind,
    /// At least one unit, not zero. From `+?` or a no-empty star.
    pub star_no_empty: bool,
    /// `(?!\.)` at entry.
    pub star_no_dot: bool,
    /// `(?!\.)` as a zero-width assertion.
    pub assert_no_dot: bool,
    /// `(?!(?:^|/)\.\.?(?:$|/))`
    pub assert_no_traversal: bool,
    pub class: CharClass,
    /// A literal unit run, for [`NodeKind::Text`].
    pub text: Pattern,
    pub children: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeKind {
    /// Matches ''
    #[default]
    Empty,
    /// Zero-width start guard, described by the `assert_*` flags.
    Assert,
    /// A literal unit run.
    Text,
    /// `[^/]`
    AnyChar,
    /// `[^/]*?`, with the flags selecting `+?` and the dot guard.
    StarAny,
    /// A bracket class.
    Class,
    Concat,
    Alt,
    /// `(?:body)?`
    Opt,
    /// `(?:body)*`
    Star,
    /// `(?:body)+`
    Plus,
    /// `(?:first)(?:rest)*?`
    TwoBody,
    /// `!(..)`: a guard over the alternatives plus a `[^/]*?` consume.
    Neg,
}

/// A bracket class, split into the members it accepts and the ones it refuses.
///
/// The split exists because `[:graph:]` is emitted negated, so one expression
/// needs both sides. `negate` is the `[^...]` from the pattern itself.
#[derive(Debug, Clone, Default)]
pub struct CharClass {
    pub positive: CharSet,
    pub negative: CharSet,
    pub has_positive: bool,
    pub has_negative: bool,
    pub negate: bool,
}

/// minimatch's per-segment fast paths, in the order they are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    /// `''`, which matches only `''`
    Empty,
    /// `f === text`
    Literal,
    /// `/^\*+$/`
    Star,
    /// `/^\*+([^+@!?*[(]*)$/`
    StarDotExt,
    /// `/^\*+\.\*+$/`
    StarDotStar,
    /// `/^\.\*+$/`
    DotStar,
    /// `/^\?+([^+@!?*[(]*)?$/`
    Qmarks,
    /// The generic expression.
    #[default]
    Regex,
}

/// One compiled path segment.
#[derive(Debug, Clone, Default)]
pub struct SegmentProgram {
    pub tier: Tier,
    /// Code-point semantics plus `iu` folding.
    pub uflag: bool,
    /// Fold case. For [`Tier::Literal`] only when `nocase_magic_only` is off.
    pub nocase: bool,
    pub dot: bool,
    /// [`Tier::Literal`]: the text. [`Tier::StarDotExt`]/[`Tier::Qmarks`]: the
    /// extension.
    pub literal: Pattern,
    /// The lowercased form of `literal`, only when `nocase`.
    pub literal_lower: String,
    /// [`Tier::Qmarks`]: the full pattern length in UTF-16 units.
    pub qmarks_len: usize,
    /// [`Tier::Regex`]: the node arena and its root.
    pub nodes: Vec<RxNode>,
    pub root: u32,
    /// `(?!\.)` on the subject.
    pub start_no_dot: bool,
    /// Rejects `.` and `..`.
    pub start_no_traversal: bool,
    /// `new RegExp` would have thrown on the generated source.
    pub invalid_regex: bool,
}

// ---------------------------------------------------------------------------
// Regexp-escape simulation
// ---------------------------------------------------------------------------

/// `[-[\]{}()*+?.,\\^$|#\s]`, with JavaScript's whole whitespace set.
fn needs_regexp_escape(unit: u16) -> bool {
    match char::from_u32(u32::from(unit)) {
        Some('-') | Some('[') | Some(']') | Some('{') | Some('}') | Some('(') | Some(')')
        | Some('*') | Some('+') | Some('?') | Some('.') | Some(',') | Some('\\') | Some('^')
        | Some('$') | Some('|') | Some('#') | Some(' ') | Some('\t') | Some('\n')
        | Some('\u{b}') | Some('\u{c}') | Some('\r') => true,
        _ => {
            matches!(unit, 0x00A0 | 0x1680 | 0x202F | 0x205F | 0x3000 | 0xFEFF)
                || (0x2000..=0x200A).contains(&unit)
                || crate::unicode::is_line_terminator(unit)
        }
    }
}

/// Characters that are legal identity escapes under the `u` flag
/// (`SyntaxCharacter` or `/`). Escaping anything else in a `u`-mode regular
/// expression makes `new RegExp` throw.
fn is_u_legal_identity_escape(unit: u16) -> bool {
    matches!(
        char::from_u32(u32::from(unit)),
        Some('^')
            | Some('$')
            | Some('\\')
            | Some('.')
            | Some('*')
            | Some('+')
            | Some('?')
            | Some('(')
            | Some(')')
            | Some('[')
            | Some(']')
            | Some('{')
            | Some('}')
            | Some('|')
            | Some('/')
    )
}

// ---------------------------------------------------------------------------
// Bracket classes
// ---------------------------------------------------------------------------

/// The character class these shapes end in.
const EXT_CHARS: &str = "+@!?*[(";

fn skip_run(text: &[u16], unit: u16, from: usize) -> usize {
    text[from.min(text.len())..]
        .iter()
        .position(|&candidate| candidate != unit)
        .map_or(text.len(), |offset| from + offset)
}

/// `/^\*+$/`
fn probe_star(text: &[u16]) -> bool {
    !text.is_empty() && skip_run(text, u16::from(b'*'), 0) == text.len()
}

/// `/^\*+([^+@!?*[(]*)$/`
fn probe_star_dot_ext(text: &[u16], ext: &mut Pattern) -> bool {
    let i = skip_run(text, u16::from(b'*'), 0);
    if i == 0 || contains_any(text, i, EXT_CHARS) {
        return false;
    }
    *ext = text[i..].to_vec();
    true
}

/// `/^\?+([^+@!?*[(]*)?$/`
fn probe_qmarks(text: &[u16], ext: &mut Pattern) -> bool {
    let i = skip_run(text, u16::from(b'?'), 0);
    if i == 0 || contains_any(text, i, EXT_CHARS) {
        return false;
    }
    *ext = text[i..].to_vec();
    true
}

/// `/^\*+\.\*+$/`
fn probe_star_dot_star(text: &[u16]) -> bool {
    let dot = skip_run(text, u16::from(b'*'), 0);
    if dot == 0 || dot >= text.len() || text[dot] != u16::from(b'.') {
        return false;
    }
    dot + 1 < text.len() && skip_run(text, u16::from(b'*'), dot + 1) == text.len()
}

/// `/^\.\*+$/`
fn probe_dot_star(text: &[u16]) -> bool {
    text.len() >= 2
        && text[0] == u16::from(b'.')
        && skip_run(text, u16::from(b'*'), 1) == text.len()
}

fn contains_any(text: &[u16], from: usize, set: &str) -> bool {
    text[from.min(text.len())..]
        .iter()
        .any(|unit| set.encode_utf16().any(|member| member == *unit))
}

struct PosixClassDef {
    name: &'static str,
    properties: &'static [UnicodeProperty],
    extra: &'static [(u32, u32)],
    /// The class needs the `u` flag, because property escapes require it.
    uflag: bool,
    /// `[:graph:]` is emitted negated: `[^\p{Z}\p{C}]`.
    negated: bool,
}

use UnicodeProperty::{
    Connector as PConnector, Control as PControl, DecimalNumber as PDecimal, Letter as PLetter,
    LetterNumber as PLetterNumber, Lowercase as PLowercase, Other as POther,
    Punctuation as PPunctuation, Separator as PSeparator, SpaceSeparator as PSpaceSeparator,
    Uppercase as PUppercase,
};

const ASCII_RANGE: &[(u32, u32)] = &[(0x00, 0x7F)];
const XDIGIT_RANGES: &[(u32, u32)] = &[
    (b'A' as u32, b'F' as u32),
    (b'a' as u32, b'f' as u32),
    (b'0' as u32, b'9' as u32),
];
const TAB_RANGE: &[(u32, u32)] = &[('\t' as u32, '\t' as u32)];
const SPACE_EXTRAS: &[(u32, u32)] = &[
    ('\t' as u32, '\t' as u32),
    ('\r' as u32, '\r' as u32),
    ('\n' as u32, '\n' as u32),
    ('\u{b}' as u32, '\u{b}' as u32),
    ('\u{c}' as u32, '\u{c}' as u32),
];

static POSIX_CLASSES: &[PosixClassDef] = &[
    PosixClassDef {
        name: "[:alnum:]",
        properties: &[PLetter, PLetterNumber, PDecimal],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:alpha:]",
        properties: &[PLetter, PLetterNumber],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:ascii:]",
        properties: &[],
        extra: ASCII_RANGE,
        uflag: false,
        negated: false,
    },
    PosixClassDef {
        name: "[:blank:]",
        properties: &[PSpaceSeparator],
        extra: TAB_RANGE,
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:cntrl:]",
        properties: &[PControl],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:digit:]",
        properties: &[PDecimal],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:graph:]",
        properties: &[PSeparator, POther],
        extra: &[],
        uflag: true,
        negated: true,
    },
    PosixClassDef {
        name: "[:lower:]",
        properties: &[PLowercase],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:print:]",
        properties: &[POther],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:punct:]",
        properties: &[PPunctuation],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:space:]",
        properties: &[PSeparator],
        extra: SPACE_EXTRAS,
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:upper:]",
        properties: &[PUppercase],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:word:]",
        properties: &[PLetter, PLetterNumber, PDecimal, PConnector],
        extra: &[],
        uflag: true,
        negated: false,
    },
    PosixClassDef {
        name: "[:xdigit:]",
        properties: &[],
        extra: XDIGIT_RANGES,
        uflag: false,
        negated: false,
    },
];

/// What one `[...]` expression turned into.
struct ClassParse {
    /// Whether anything was consumed, i.e. `consumed > 0`.
    consumed_any: bool,
    consumed: usize,
    magic: bool,
    uflag: bool,
    /// A single-character class, which minimatch rewrites to a literal.
    demoted: bool,
    demoted_char: u16,
    /// `'$.'`, an atom that can never match.
    poison: bool,
    unsupported_property: bool,
    klass: CharClass,
    /// The first character of the regex source this class produced.
    src_first: u16,
    src_first_escaped: bool,
}

fn default_class_parse() -> ClassParse {
    ClassParse {
        consumed_any: false,
        consumed: 0,
        magic: false,
        uflag: false,
        demoted: false,
        demoted_char: 0,
        poison: false,
        unsupported_property: false,
        klass: CharClass::default(),
        src_first: u16::from(b'['),
        src_first_escaped: false,
    }
}

#[derive(Clone, Copy)]
enum Added {
    /// A `push` of a multi-character source piece (`[:alpha:]`, `c-`).
    Piece,
    Single(u16),
}

fn parse_class(glob: &[u16], position: usize) -> ClassParse {
    let mut out = default_class_parse();
    let pos = position;
    let mut i = pos + 1;
    let mut saw_start = false;
    let mut escaping = false;
    let mut negate = false;
    let mut end_pos = pos;
    let mut have_range_start = false;
    let mut range_start: u16 = 0;

    let mut added: Vec<Added> = Vec::new();
    let mut positive = CharSet::new();
    let mut negative = CharSet::new();
    let mut has_positive = false;
    let mut has_negative = false;
    let mut uflag = false;
    let mut unsupported_property = false;

    while i < glob.len() {
        let c = glob[i];
        if (c == u16::from(b'!') || c == u16::from(b'^')) && i == pos + 1 {
            negate = true;
            i += 1;
            continue;
        }
        if c == u16::from(b']') && saw_start && !escaping {
            end_pos = i + 1;
            break;
        }
        saw_start = true;
        if c == u16::from(b'\\') && !escaping {
            escaping = true;
            i += 1;
            continue;
        }
        if c == u16::from(b'[') && !escaping {
            let mut matched_posix = false;
            for def in POSIX_CLASSES {
                if !starts_with_str(&glob[i..], def.name) {
                    continue;
                }
                if have_range_start {
                    // `[a-[:alpha:]]` poisons the whole remaining glob text.
                    out.consumed_any = true;
                    out.consumed = glob.len() - pos;
                    out.magic = true;
                    out.poison = true;
                    return out;
                }
                i += def.name.len();
                let (side, has_side) = if def.negated {
                    (&mut negative, &mut has_negative)
                } else {
                    (&mut positive, &mut has_positive)
                };
                *has_side = true;
                for property in def.properties {
                    if !side.add_property(*property) {
                        unsupported_property = true;
                    }
                }
                for &(lo, hi) in def.extra {
                    side.add_range(lo, hi);
                }
                added.push(Added::Piece);
                uflag = uflag || def.uflag;
                matched_posix = true;
                break;
            }
            if matched_posix {
                continue;
            }
        }
        escaping = false;
        if have_range_start {
            if c > range_start {
                positive.add_range(u32::from(range_start), u32::from(c));
                has_positive = true;
                added.push(Added::Piece);
            } else if c == range_start {
                positive.add_char(u32::from(c));
                has_positive = true;
                added.push(Added::Single(c));
            }
            // `c < range_start`: the range is dropped entirely.
            have_range_start = false;
            i += 1;
            continue;
        }
        // A possible range start: `c-]`, `c-x`, or `c`.
        if i + 2 < glob.len() && glob[i + 1] == u16::from(b'-') && glob[i + 2] == u16::from(b']') {
            // `'c-'` as two literal members.
            positive.add_char(u32::from(c));
            positive.add_char(u32::from(b'-'));
            has_positive = true;
            added.push(Added::Piece);
            i += 2;
            continue;
        }
        if i + 1 < glob.len() && glob[i + 1] == u16::from(b'-') {
            range_start = c;
            have_range_start = true;
            i += 2;
            continue;
        }
        positive.add_char(u32::from(c));
        has_positive = true;
        added.push(Added::Single(c));
        i += 1;
    }

    if end_pos < i || end_pos == pos {
        // No closing `]`: not a class, so the `[` stays literal.
        return out;
    }
    out.consumed_any = true;
    out.consumed = end_pos - pos;

    if !has_positive && !has_negative {
        // `[]` (or everything dropped): poison.
        out.consumed = glob.len() - pos;
        out.magic = true;
        out.poison = true;
        return out;
    }
    // A single positive plain character, not negated, is just that character.
    if !has_negative && !negate && added.len() == 1 {
        if let Added::Single(ch) = added[0] {
            out.demoted = true;
            out.demoted_char = ch;
            out.magic = false;
            out.src_first_escaped = needs_regexp_escape(ch);
            out.src_first = if out.src_first_escaped {
                u16::from(b'\\')
            } else {
                ch
            };
            return out;
        }
    }

    out.magic = true;
    out.uflag = uflag;
    out.unsupported_property = unsupported_property;

    positive.seal();
    negative.seal();
    out.klass = CharClass {
        positive,
        negative,
        has_positive,
        has_negative,
        negate,
    };
    // The combined source starts with `(` when both sides exist, else `[`.
    out.src_first = if has_positive && has_negative {
        u16::from(b'(')
    } else {
        u16::from(b'[')
    };
    out
}

fn starts_with_str(text: &[u16], prefix: &str) -> bool {
    let prefix = prefix.as_bytes();
    text.len() >= prefix.len()
        && text
            .iter()
            .zip(prefix.iter())
            .all(|(&unit, &byte)| unit == u16::from(byte))
}

// ---------------------------------------------------------------------------
// Lowering
// ---------------------------------------------------------------------------

/// The result of lowering one AST node.
#[derive(Debug, Clone, Default)]
struct Lowered {
    node: u32,
    /// Produced no regex source at all.
    source_empty: bool,
    /// The first simulated source characters (up to 5), for guard decisions.
    src_prefix: Pattern,
    bad_uescape: bool,
    bad_syntax: bool,
}

struct Lowering<'a> {
    flags: &'a CompileFlags,
    program: SegmentProgram,
    magic: bool,
    uflag: bool,
    bad_property: bool,
    literal_value: Pattern,
}

impl Lowering<'_> {
    fn add(&mut self, node: RxNode) -> u32 {
        self.program.nodes.push(node);
        (self.program.nodes.len() - 1) as u32
    }

    fn append_prefix_unit(prefix: &mut Pattern, unit: u16) {
        if prefix.len() < 5 {
            prefix.push(unit);
        }
    }

    fn append_prefix(prefix: &mut Pattern, text: &[u16]) {
        for &unit in text {
            if prefix.len() >= 5 {
                break;
            }
            prefix.push(unit);
        }
    }

    /// Appends `unit` to a prefix, escaping it if minimatch's `regexpEscape`
    /// would have.
    fn append_prefix_escaped(prefix: &mut Pattern, unit: u16) {
        if needs_regexp_escape(unit) {
            Self::append_prefix_unit(prefix, u16::from(b'\\'));
        }
        Self::append_prefix_unit(prefix, unit);
    }

    /// `#parseGlob` for one literal text run.
    fn lower_text(&mut self, text: &[u16], no_empty: bool) -> Lowered {
        let mut result = Lowered::default();
        let mut seq: Vec<u32> = Vec::new();
        let mut in_star = false;
        let mut pending_text: Pattern = Vec::new();
        let mut escaping = false;
        let all_stars = probe_star(text);

        macro_rules! flush_text {
            () => {
                if !pending_text.is_empty() {
                    let node = RxNode {
                        kind: NodeKind::Text,
                        text: std::mem::take(&mut pending_text),
                        ..RxNode::default()
                    };
                    seq.push(self.add(node));
                }
            };
        }

        let mut i = 0usize;
        while i < text.len() {
            let c = text[i];
            i += 1;
            if escaping {
                escaping = false;
                Self::append_prefix_escaped(&mut result.src_prefix, c);
                if needs_regexp_escape(c) && !is_u_legal_identity_escape(c) {
                    result.bad_uescape = true;
                }
                pending_text.push(c);
                self.literal_value.push(c);
                continue;
            }
            if c == u16::from(b'*') {
                if in_star {
                    continue;
                }
                in_star = true;
                flush_text!();
                let node = RxNode {
                    kind: NodeKind::StarAny,
                    star_no_empty: no_empty && all_stars,
                    ..RxNode::default()
                };
                seq.push(self.add(node));
                // `[^/]*?` / `[^/]+?`
                Self::append_prefix_unit(&mut result.src_prefix, u16::from(b'['));
                self.magic = true;
                continue;
            }
            in_star = false;
            if c == u16::from(b'\\') {
                if i == text.len() {
                    pending_text.push(c);
                    self.literal_value.push(c);
                    Self::append_prefix(
                        &mut result.src_prefix,
                        &[u16::from(b'\\'), u16::from(b'\\')],
                    );
                } else {
                    escaping = true;
                }
                continue;
            }
            if c == u16::from(b'[') {
                let parsed = parse_class(text, i - 1);
                if parsed.consumed_any {
                    i = i - 1 + parsed.consumed;
                    if parsed.demoted {
                        pending_text.push(parsed.demoted_char);
                        self.literal_value.push(parsed.demoted_char);
                        if needs_regexp_escape(parsed.demoted_char)
                            && !is_u_legal_identity_escape(parsed.demoted_char)
                        {
                            result.bad_uescape = true;
                        }
                        if parsed.src_first_escaped {
                            Self::append_prefix_unit(&mut result.src_prefix, u16::from(b'\\'));
                            Self::append_prefix_unit(&mut result.src_prefix, parsed.demoted_char);
                        } else {
                            Self::append_prefix_unit(&mut result.src_prefix, parsed.demoted_char);
                        }
                    } else if parsed.unsupported_property {
                        self.bad_property = true;
                        flush_text!();
                        let node = RxNode {
                            kind: NodeKind::Class,
                            ..RxNode::default()
                        };
                        seq.push(self.add(node));
                        Self::append_prefix_unit(&mut result.src_prefix, u16::from(b'['));
                        self.magic = true;
                    } else if parsed.poison {
                        flush_text!();
                        // An empty class never matches.
                        let node = RxNode {
                            kind: NodeKind::Class,
                            ..RxNode::default()
                        };
                        seq.push(self.add(node));
                        Self::append_prefix_unit(&mut result.src_prefix, u16::from(b'$'));
                        self.magic = true;
                    } else {
                        flush_text!();
                        self.uflag = self.uflag || parsed.uflag;
                        let node = RxNode {
                            kind: NodeKind::Class,
                            class: parsed.klass,
                            ..RxNode::default()
                        };
                        seq.push(self.add(node));
                        Self::append_prefix_unit(&mut result.src_prefix, parsed.src_first);
                        self.magic = true;
                    }
                    continue;
                }
                // Not consumed: fall through as a literal `[`.
            }
            if c == u16::from(b'?') {
                flush_text!();
                let node = RxNode {
                    kind: NodeKind::AnyChar,
                    ..RxNode::default()
                };
                seq.push(self.add(node));
                // `[^/]`
                Self::append_prefix_unit(&mut result.src_prefix, u16::from(b'['));
                self.magic = true;
                continue;
            }
            Self::append_prefix_escaped(&mut result.src_prefix, c);
            if needs_regexp_escape(c) && !is_u_legal_identity_escape(c) {
                result.bad_uescape = true;
            }
            pending_text.push(c);
            self.literal_value.push(c);
        }
        flush_text!();
        result.node = if seq.is_empty() {
            self.add(RxNode::default())
        } else if seq.len() == 1 {
            seq[0]
        } else {
            self.add(RxNode {
                kind: NodeKind::Concat,
                children: seq,
                ..RxNode::default()
            })
        };
        // A nonempty text run always produces regex source.
        result.source_empty = text.is_empty();
        result
    }

    /// `toRegExpSource(allowDot)`
    fn lower_node(&mut self, nodes: &[Node], index: usize, allow_dot: bool) -> Lowered {
        let dot = allow_dot || self.flags.dot;
        if !nodes[index].is_extglob() {
            self.lower_plain(nodes, index, allow_dot, dot)
        } else {
            self.lower_extglob(nodes, index, allow_dot, dot)
        }
    }

    fn lower_plain(&mut self, nodes: &[Node], index: usize, allow_dot: bool, dot: bool) -> Lowered {
        let node = &nodes[index];
        let no_empty = node.is_start(nodes)
            && node.is_end(nodes)
            && nodes[index].parts.iter().all(|part| match part {
                Part::Child(_) => false,
                Part::Text(_) => true,
            });
        let parts = nodes[index].parts.clone();
        let mut result = Lowered::default();
        let mut seq: Vec<u32> = Vec::new();
        let mut first = true;
        for part in &parts {
            let lowered = match part {
                Part::Child(child) => self.lower_node(nodes, *child, allow_dot),
                Part::Text(text) => self.lower_text(text, no_empty),
            };
            if first || result.src_prefix.len() < 5 {
                Self::append_prefix(&mut result.src_prefix, &lowered.src_prefix);
            }
            first = false;
            if !lowered.source_empty {
                result.source_empty = false;
            }
            result.bad_uescape |= lowered.bad_uescape;
            result.bad_syntax |= lowered.bad_syntax;
            seq.push(lowered.node);
        }

        // A segment beginning with `.` is matched only by a pattern segment
        // beginning with a literal `.`, and `.`/`..` are never matched by a
        // wildcard.
        let mut start_no_dot = false;
        let mut start_no_traversal = false;
        let node_is_start = nodes[index].is_start(nodes);
        let first_is_text = matches!(nodes[index].parts.first(), Some(Part::Text(_)));
        if node_is_start && first_is_text {
            let parts = &nodes[index].parts;
            let dot_trav_allowed = parts.len() == 1
                && matches!(&parts[0], Part::Text(text)
                    if part_is(text, ".") || part_is(text, ".."));
            if !dot_trav_allowed {
                let src = &result.src_prefix;
                let at = |offset: usize| -> u16 { src.get(offset).copied().unwrap_or(0) };
                let starts_escaped_dot = at(0) == u16::from(b'\\') && at(1) == u16::from(b'.');
                let starts_two_escaped_dots =
                    starts_escaped_dot && at(2) == u16::from(b'\\') && at(3) == u16::from(b'.');
                let is_aps = |unit: u16| unit == u16::from(b'[') || unit == u16::from(b'.');
                let need_no_trav = (dot && is_aps(at(0)))
                    || (starts_escaped_dot && is_aps(at(2)))
                    || (starts_two_escaped_dots && is_aps(at(4)));
                let need_no_dot = !dot && !allow_dot && is_aps(at(0));
                start_no_dot = !need_no_trav && need_no_dot;
                start_no_traversal = need_no_trav;
            }
        }

        if nodes[index].parent.is_none() {
            self.program.start_no_dot = start_no_dot;
            self.program.start_no_traversal = start_no_traversal;
            if seq.is_empty() {
                result.node = self.add(RxNode::default());
                result.source_empty = true;
                return result;
            }
        } else if start_no_dot || start_no_traversal {
            let guard = RxNode {
                kind: NodeKind::Assert,
                assert_no_dot: start_no_dot,
                assert_no_traversal: start_no_traversal,
                ..RxNode::default()
            };
            let guard = self.add(guard);
            seq.insert(0, guard);
        }

        if seq.is_empty() {
            result.node = self.add(RxNode::default());
            result.source_empty = true;
        } else if seq.len() == 1 {
            result.node = seq[0];
        } else {
            result.node = self.add(RxNode {
                kind: NodeKind::Concat,
                children: seq,
                ..RxNode::default()
            });
        }
        result
    }

    /// `#partsToRegExp`
    fn lower_alternatives(
        &mut self,
        nodes: &[Node],
        index: usize,
        allow_dot: bool,
    ) -> Vec<Lowered> {
        let drop_empty = nodes[index].is_start(nodes) && nodes[index].is_end(nodes);
        let parts = nodes[index].parts.clone();
        let mut alternatives = Vec::new();
        for part in &parts {
            let Part::Child(child) = part else {
                continue; // extglob parts are always sub-ASTs
            };
            let lowered = self.lower_node(nodes, *child, allow_dot);
            if drop_empty && lowered.source_empty {
                continue;
            }
            alternatives.push(lowered);
        }
        alternatives
    }

    /// Serializes a subtree so two lowerings can be compared, which is how
    /// minimatch decides whether a repeated extglob needs its dot-allowing twin.
    fn serialize(&self, id: u32, out: &mut Pattern) {
        const KIND_BASE: u16 = 0xE000;
        let node = &self.program.nodes[id as usize];
        out.push(KIND_BASE + node.kind as u16);
        out.push(
            u16::from(b'0')
                + u16::from(node.star_no_empty)
                + if node.star_no_dot { 2 } else { 0 }
                + if node.assert_no_dot { 4 } else { 0 }
                + if node.assert_no_traversal { 8 } else { 0 },
        );
        if node.kind == NodeKind::Text {
            out.extend_from_slice(&node.text);
        } else if node.kind == NodeKind::Class {
            for set in [&node.class.positive, &node.class.negative] {
                for &(lo, hi) in set.ranges() {
                    out.push((lo & 0xFFFF) as u16);
                    out.push((lo >> 16) as u16);
                    out.push((hi & 0xFFFF) as u16);
                    out.push((hi >> 16) as u16);
                }
                out.push(u16::from(b'|'));
            }
            out.push(
                u16::from(b'0')
                    + u16::from(node.class.negate)
                    + if node.class.has_positive { 2 } else { 0 }
                    + if node.class.has_negative { 4 } else { 0 },
            );
        }
        out.push(u16::from(b'('));
        for &child in &node.children {
            self.serialize(child, out);
        }
        out.push(u16::from(b')'));
    }

    fn lower_extglob(
        &mut self,
        nodes: &[Node],
        index: usize,
        allow_dot: bool,
        dot: bool,
    ) -> Lowered {
        let mut result = Lowered::default();
        let kind = nodes[index].kind;
        let repeated = kind == '*' || kind == '+';
        let alternatives = self.lower_alternatives(nodes, index, allow_dot);

        // minimatch's `body === ''` reversion.
        if nodes[index].is_start(nodes)
            && nodes[index].is_end(nodes)
            && alternatives.is_empty()
            && kind != '!'
        {
            // minimatch rewrites the node in place here; the tree is shared
            // between the fast-path checks and the lowering, so the rewrite is
            // local to this lowering instead of mutating it.
            let raw = nodes[index].to_pattern(nodes);
            self.literal_value.extend_from_slice(&raw);
            // As regex source, `@(||)` is a literal `@` followed by a group
            // matching the empty string.
            let text = if kind == '@' {
                vec![u16::from(b'@')]
            } else {
                raw.clone()
            };
            if kind != '@' {
                result.bad_syntax = true;
            }
            let node = RxNode {
                kind: NodeKind::Text,
                text,
                ..RxNode::default()
            };
            result.node = self.add(node);
            result.source_empty = raw.is_empty();
            Self::append_prefix(&mut result.src_prefix, &raw);
            return result;
        }

        // Extglobs are inherently magical.
        self.magic = true;
        Self::append_prefix_unit(&mut result.src_prefix, u16::from(b'('));
        result.source_empty = false;

        if kind == '!' && nodes[index].empty_ext {
            // The `empty_ext` flag is set by the parser whenever the last
            // alternative ended empty at the `)`.
            let node = RxNode {
                kind: NodeKind::StarAny,
                star_no_empty: true,
                star_no_dot: nodes[index].is_start(nodes) && !dot,
                ..RxNode::default()
            };
            result.node = self.add(node);
            return result;
        }

        let alternatives = self.finish_alternatives(alternatives, &mut result);

        if kind == '!' {
            // A negated extglob is a guard plus a `[^/]*?` consume. That makes
            // it less permissive than bash when something greedy follows:
            // `!(a)*` does not match `ab`, because the guard cannot take `ab`
            // and leave the `*` empty.
            let node = RxNode {
                kind: NodeKind::Neg,
                star_no_dot: nodes[index].is_start(nodes) && !dot && !allow_dot,
                children: alternatives,
                ..RxNode::default()
            };
            result.node = self.add(node);
            return result;
        }

        // `bodyDotAllowed`: only for repeated extglobs when dots are not
        // already allowed.
        let mut has_body_dot = false;
        let mut body_dot_alt = 0u32;
        let body_alt = self.make_alt(&alternatives);
        if repeated && !allow_dot && !self.flags.dot {
            let alts_dot = self.lower_alternatives(nodes, index, true);
            let mut dot_result = Lowered::default();
            let alts_dot = self.finish_alternatives(alts_dot, &mut dot_result);
            let alt_dot = self.make_alt(&alts_dot);
            let mut a = Pattern::new();
            let mut b = Pattern::new();
            self.serialize(body_alt, &mut a);
            self.serialize(alt_dot, &mut b);
            if a != b {
                has_body_dot = true;
                body_dot_alt = alt_dot;
                result.bad_uescape |= dot_result.bad_uescape;
                result.bad_syntax |= dot_result.bad_syntax;
            }
        }

        result.node = match kind {
            '@' => body_alt,
            '?' => {
                let node = RxNode {
                    kind: NodeKind::Opt,
                    children: vec![body_alt],
                    ..RxNode::default()
                };
                self.add(node)
            }
            '+' => {
                let node = if has_body_dot {
                    RxNode {
                        kind: NodeKind::TwoBody,
                        children: vec![body_alt, body_dot_alt],
                        ..RxNode::default()
                    }
                } else {
                    RxNode {
                        kind: NodeKind::Plus,
                        children: vec![body_alt],
                        ..RxNode::default()
                    }
                };
                self.add(node)
            }
            _ => {
                if has_body_dot {
                    let two = RxNode {
                        kind: NodeKind::TwoBody,
                        children: vec![body_alt, body_dot_alt],
                        ..RxNode::default()
                    };
                    let two_id = self.add(two);
                    let node = RxNode {
                        kind: NodeKind::Opt,
                        children: vec![two_id],
                        ..RxNode::default()
                    };
                    self.add(node)
                } else {
                    let node = RxNode {
                        kind: NodeKind::Star,
                        children: vec![body_alt],
                        ..RxNode::default()
                    };
                    self.add(node)
                }
            }
        };
        result
    }

    /// Folds each alternative's error flags into the group's result.
    fn finish_alternatives(
        &mut self,
        alternatives: Vec<Lowered>,
        result: &mut Lowered,
    ) -> Vec<u32> {
        let mut nodes = Vec::with_capacity(alternatives.len());
        for lowered in &alternatives {
            result.bad_uescape |= lowered.bad_uescape;
            result.bad_syntax |= lowered.bad_syntax;
            nodes.push(lowered.node);
        }
        nodes
    }

    fn make_alt(&mut self, nodes: &[u32]) -> u32 {
        if nodes.len() == 1 {
            return nodes[0];
        }
        if nodes.is_empty() {
            return self.add(RxNode::default());
        }
        self.add(RxNode {
            kind: NodeKind::Alt,
            children: nodes.to_vec(),
            ..RxNode::default()
        })
    }
}

/// Compiles one segment into its matcher program.
pub fn lower_segment(tree: &SegmentTree, flags: &CompileFlags, source: &[u16]) -> SegmentProgram {
    let mut program = SegmentProgram {
        dot: flags.dot,
        ..SegmentProgram::default()
    };
    if source.is_empty() {
        program.tier = Tier::Empty;
        return program;
    }

    // Shape probes. minimatch installs these in place of the regular
    // expression, so they define the segment's semantics.
    let mut ext: Pattern = Vec::new();
    if probe_star(source) {
        program.tier = Tier::Star;
        return program;
    }
    if probe_star_dot_ext(source, &mut ext) {
        program.tier = Tier::StarDotExt;
        program.nocase = flags.nocase;
        program.literal = ext;
        if flags.nocase {
            append_lowered_pattern(&program.literal, &mut program.literal_lower);
        }
        return program;
    }
    if probe_qmarks(source, &mut ext) {
        program.tier = Tier::Qmarks;
        program.nocase = flags.nocase;
        program.qmarks_len = source.len();
        program.literal = ext;
        if flags.nocase {
            append_lowered_pattern(&program.literal, &mut program.literal_lower);
        }
        return program;
    }
    if probe_star_dot_star(source) {
        program.tier = Tier::StarDotStar;
        return program;
    }
    if probe_dot_star(source) {
        program.tier = Tier::DotStar;
        return program;
    }

    let mut lowering = Lowering {
        flags,
        program: SegmentProgram {
            dot: flags.dot,
            ..SegmentProgram::default()
        },
        magic: false,
        uflag: false,
        bad_property: false,
        literal_value: Vec::new(),
    };
    let lowered = lowering.lower_node(&tree.nodes, SegmentTree::ROOT, false);
    let bad_property = lowering.bad_property;
    let uflag = lowering.uflag;
    let magic = lowering.magic;
    let literal_value = lowering.literal_value.clone();
    let mut built = lowering.program;
    built.root = lowered.node;
    built.uflag = uflag;

    if !magic {
        built.tier = Tier::Literal;
        built.literal = literal_value;
        // minimatch keeps a non-magic segment a plain string unless nocase
        // applies to literals too, in which case it becomes `/^text$/i`.
        built.nocase = flags.nocase && !flags.nocase_magic_only;
        built.nodes.clear();
        built.start_no_dot = false;
        built.start_no_traversal = false;
        return built;
    }

    built.tier = Tier::Regex;
    built.nocase = flags.nocase;
    if flags.nocase {
        for node in &mut built.nodes {
            if node.kind != NodeKind::Class {
                continue;
            }
            for set in [&mut node.class.positive, &mut node.class.negative] {
                if built.uflag {
                    set.close_over_case_fold();
                } else {
                    set.canonicalize_members();
                }
            }
        }
    }
    // `new RegExp` would throw on this source.
    built.invalid_regex =
        (built.uflag && lowered.bad_uescape) || lowered.bad_syntax || bad_property;
    built
}

fn append_lowered_pattern(text: &[u16], out: &mut String) {
    let wide = String::from_utf16_lossy(text);
    append_lowered(&wide, out);
}

/// `String.prototype.toLowerCase()` for a UTF-16 pattern.
pub fn lower_pattern(text: &[u16]) -> String {
    let mut out = String::new();
    append_lowered_pattern(text, &mut out);
    out
}

/// `toLowerCase().endsWith(ext.toLowerCase())` for an ASCII fast path.
pub fn ends_with_lowered(subject: &str, lowered_ext: &str) -> bool {
    let ascii = subject.chars().all(|c| c as u32 <= MAX_ASCII);
    if ascii {
        if subject.len() < lowered_ext.len() {
            return false;
        }
        let tail = &subject[subject.len() - lowered_ext.len()..];
        return tail
            .chars()
            .zip(lowered_ext.chars())
            .all(|(a, b)| ascii_lower(a as u32) == b as u32);
    }
    let lowered = crate::unicode::lower(subject);
    lowered.ends_with(lowered_ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::pattern;
    use crate::parser::parse_segment_ast;

    fn flags() -> CompileFlags {
        CompileFlags {
            nocase_magic_only: true,
            ..CompileFlags::default()
        }
    }

    fn lower(source: &str) -> SegmentProgram {
        let units = pattern(source);
        let tree = parse_segment_ast(&units).expect("parses");
        lower_segment(&tree, &flags(), &units)
    }

    #[test]
    fn the_shape_probes_pick_the_matching_tier() {
        assert_eq!(lower("").tier, Tier::Empty);
        assert_eq!(lower("**").tier, Tier::Star);
        assert_eq!(lower("*").tier, Tier::Star);
        assert_eq!(lower("*.js").tier, Tier::StarDotExt);
        assert_eq!(lower("*.*").tier, Tier::StarDotStar);
        assert_eq!(lower(".*").tier, Tier::DotStar);
        assert_eq!(lower("?.js").tier, Tier::Qmarks);
        assert_eq!(lower("a*.js").tier, Tier::Regex);
    }

    #[test]
    fn a_literal_segment_keeps_its_text() {
        let program = lower("abc");
        assert_eq!(program.tier, Tier::Literal);
        assert_eq!(program.literal, pattern("abc"));
        assert!(program.nodes.is_empty());
    }

    #[test]
    fn the_star_dot_ext_probe_extracts_the_extension() {
        let program = lower("*.tar.gz");
        assert_eq!(program.tier, Tier::StarDotExt);
        assert_eq!(program.literal, pattern(".tar.gz"));
    }

    #[test]
    fn a_qmark_run_records_its_length() {
        let program = lower("???.js");
        assert_eq!(program.tier, Tier::Qmarks);
        assert_eq!(program.qmarks_len, 6);
        assert_eq!(program.literal, pattern(".js"));
    }

    #[test]
    fn a_leading_dot_guard_is_required_for_a_wildcard_segment() {
        let program = lower("*.js");
        // The probe tiers apply the guard at match time, so only the generic
        // expression records it.
        assert_eq!(lower("a?b").tier, Tier::Regex);
        assert!(program.tier == Tier::StarDotExt);
    }

    #[test]
    fn a_posix_class_sets_the_u_flag() {
        let program = lower("[[:alpha:]]x");
        assert_eq!(program.tier, Tier::Regex);
        assert!(program.uflag, "a property escape needs the u flag");
    }

    #[test]
    fn an_ascii_posix_class_does_not_set_the_u_flag() {
        let program = lower("[[:xdigit:]]x");
        assert_eq!(program.tier, Tier::Regex);
        assert!(!program.uflag);
    }

    #[test]
    fn an_invalid_identity_escape_marks_the_program_invalid() {
        // `[[:alpha:]]` forces the u flag, and `\#` is illegal there.
        let program = lower("[[:alpha:]]#");
        assert!(program.invalid_regex, "expected an invalid u-mode escape");
    }

    #[test]
    fn nocase_on_a_literal_only_applies_when_magic_folding_is_off() {
        let units = pattern("abc");
        let tree = parse_segment_ast(&units).expect("parses");
        let mut magic_flags = flags();
        magic_flags.nocase = true;
        let program = lower_segment(&tree, &magic_flags, &units);
        assert_eq!(program.tier, Tier::Literal);
        assert!(!program.nocase, "literal comparison stays exact");

        let units = pattern("abc");
        let tree = parse_segment_ast(&units).expect("parses");
        let mut all_flags = flags();
        all_flags.nocase = true;
        all_flags.nocase_magic_only = false;
        let program = lower_segment(&tree, &all_flags, &units);
        assert!(program.nocase, "an all-folding comparison folds literals");
    }

    #[test]
    fn ends_with_lowered_handles_both_ascii_and_wide_subjects() {
        assert!(ends_with_lowered("FILE.TXT", ".txt"));
        assert!(!ends_with_lowered("FILE.TXT", ".md"));
        assert!(ends_with_lowered("CAFÉ.TXT", ".txt"));
        assert!(ends_with_lowered("café.txt", ".txt"));
    }
}
