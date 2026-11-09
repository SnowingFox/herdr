//! The compiled form of a pattern, mirroring `src/glob/glob_ast.h`.
//!
//! A pattern is not one automaton. It first splits on `/` into path parts, each
//! of which is either a literal, a run of `**`, or a *segment*: a mini pattern
//! with its own AST, because `@(a|b)`, `!(x)` and friends nest.
//!
//! Keeping the AST (rather than compiling straight to a matcher) matters for
//! two reasons. `hasMagic` has to answer whether any part is more than a
//! literal path, which is a question about the parsed shape. And minimatch's
//! `!(a)` semantics depend on a node's position in the tree, which
//! [`Node::is_start`] and [`Node::is_end`] expose.

/// A pattern, held as UTF-16 so a lone surrogate round-trips.
///
/// Node hands the native layer `v8::TwoByteValue`, which is UTF-16. A Rust
/// `String` cannot hold an unpaired surrogate, so patterns and path segments
/// travel as `Vec<u16>` and are only converted at the boundary. A pattern that
/// contains a lone surrogate is legal input; it simply never matches a file
/// name, and converting through `String` would lose that.
pub type Pattern = Vec<u16>;

/// Convenience for building a pattern from an ASCII literal in tests and code.
pub fn pattern(text: &str) -> Pattern {
    text.encode_utf16().collect()
}

/// One node of a segment's extglob AST.
///
/// `kind` is 0 for a plain sequence and otherwise one of `!`, `?`, `+`, `*`,
/// `@`: the extglob operator that produced this node. `parts` holds either text
/// runs or child nodes, in source order; a node with `kind != 0` treats each
/// child as one alternative of the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub kind: char,
    pub parts: Vec<Part>,
    /// Set when an extglob closed with no contents at all: `!()`, `@()`, ...
    pub empty_ext: bool,
    pub parent: Option<usize>,
    pub parent_index: usize,
}

/// One entry in a node's part list: either a text run or a child node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Text(Pattern),
    Child(usize),
}

impl Node {
    pub fn is_extglob(&self) -> bool {
        self.kind != '\0'
    }

    /// Whether the node starts its enclosing sequence, ignoring `!` parents.
    ///
    /// This is minimatch's `isStart()`. It is what lets `!(a)` know that a
    /// leading-dot guard applies only at the beginning of a segment.
    pub fn is_start(&self, nodes: &[Node]) -> bool {
        let Some(parent) = self.parent else {
            return true;
        };
        if !nodes[parent].is_start(nodes) {
            return false;
        }
        if self.parent_index == 0 {
            return true;
        }
        let limit = self.parent_index.min(nodes[parent].parts.len());
        nodes[parent].parts[..limit].iter().all(|part| match part {
            Part::Child(index) => nodes[*index].kind != '!',
            Part::Text(_) => false,
        })
    }

    /// Whether the node ends its enclosing sequence.
    pub fn is_end(&self, nodes: &[Node]) -> bool {
        let Some(parent) = self.parent else {
            return true;
        };
        if nodes[parent].kind == '!' {
            return true;
        }
        if !nodes[parent].is_end(nodes) {
            return false;
        }
        if self.kind == '\0' {
            return true;
        }
        self.parent_index + 1 == nodes[parent].parts.len()
    }

    /// Reconstructs the source text of this subtree.
    pub fn to_pattern(&self, nodes: &[Node]) -> Pattern {
        let mut out = Pattern::new();
        if self.kind != '\0' {
            out.push(self.kind as u16);
            out.push(u16::from(b'('));
        }
        let mut first = true;
        for part in &self.parts {
            if self.kind != '\0' && !first {
                out.push(u16::from(b'|'));
            }
            first = false;
            match part {
                Part::Child(index) => out.extend(nodes[*index].to_pattern(nodes)),
                Part::Text(text) => out.extend_from_slice(text),
            }
        }
        if self.kind != '\0' {
            out.push(u16::from(b')'));
        }
        out
    }
}

/// A parsed segment: its node arena, with index 0 as the root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentTree {
    pub nodes: Vec<Node>,
}

impl SegmentTree {
    /// The root's index, 0. Kept as a method so call sites read like the C++.
    pub const ROOT: usize = 0;
}
