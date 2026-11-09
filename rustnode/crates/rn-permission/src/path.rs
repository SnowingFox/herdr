//! POSIX path resolution and the `--allow-fs-*` matcher.
//!
//! Both are ports of Node's C++ helpers so the JavaScript layer sees the same
//! answers:
//!
//! * resolution mirrors `node::PathResolve` (`src/path.cc`), which is
//!   `path.resolve()` semantics without the JavaScript call;
//! * matching mirrors `FSPermission::RadixTree` (`src/permission/fs_permission.cc`),
//!   including its quirks: a `*` ends the pattern, a pattern that names an
//!   existing directory is stored with a trailing `/*`, and the trailing
//!   separator of an intermediate node is optional.
//!
//! Everything works on bytes rather than `str`. Node compares `std::string_view`
//! of the raw path, and `lib/internal/process/permission.js` deliberately
//! forwards `Uint8Array` references untouched because "paths are not guaranteed
//! to be valid UTF-8". Byte comparison reproduces that and, since `*` and `/`
//! are ASCII, matches the same paths a UTF-8-aware implementation would.
//!
//! Nothing here reads the filesystem. [`is_existing_directory`] is the one
//! exception, called once per grant at startup, never per check.

use std::path::Path;

const SEPARATOR: u8 = b'/';
const WILDCARD: u8 = b'*';

/// Resolves `path` against `cwd` the way `path.resolve()` does.
///
/// Returns an absolute, lexically normalised path. Symlinks are not resolved:
/// Node's permission model compares unresolved paths and documents symlink
/// following as a limitation of the model.
pub fn resolve_path_bytes(cwd: &[u8], path: &[u8]) -> Vec<u8> {
    if path.first() == Some(&SEPARATOR) {
        return normalize_absolute_bytes(path);
    }
    let mut joined = Vec::with_capacity(cwd.len() + path.len() + 1);
    if !cwd.is_empty() {
        joined.extend_from_slice(cwd);
    }
    joined.push(SEPARATOR);
    joined.extend_from_slice(path);
    normalize_absolute_bytes(&joined)
}

/// [`resolve_path_bytes`] for callers that have UTF-8 paths.
pub fn resolve_path(cwd: &str, path: &str) -> String {
    let resolved = resolve_path_bytes(cwd.as_bytes(), path.as_bytes());
    String::from_utf8_lossy(&resolved).into_owned()
}

/// Lexically normalises an absolute path: collapses `.` and `..`, repeated
/// separators and a trailing separator. `/` stays `/`.
pub fn normalize_absolute_bytes(path: &[u8]) -> Vec<u8> {
    let mut segments: Vec<&[u8]> = Vec::new();
    for segment in path.split(|byte| *byte == SEPARATOR) {
        match segment {
            b"" | b"." => {}
            b".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut out = Vec::with_capacity(path.len());
    for segment in &segments {
        out.push(SEPARATOR);
        out.extend_from_slice(segment);
    }
    if out.is_empty() {
        out.push(SEPARATOR);
    }
    out
}

/// Strips a trailing separator unless the path is the root.
pub fn strip_trailing_separator(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == SEPARATOR {
        end -= 1;
    }
    &path[..end]
}

/// Appends the wildcard Node adds when a grant names an existing directory.
///
/// `FSPermission::Apply` calls `WildcardIfDir()` before storing a path, so
/// `--allow-fs-read=/tmp` grants everything below `/tmp` when `/tmp` exists and
/// only `/tmp` itself when it does not.
pub fn wildcard_if_dir_bytes(resolved: &[u8], is_directory: bool) -> Vec<u8> {
    if !is_directory {
        return resolved.to_vec();
    }
    let trimmed = strip_trailing_separator(resolved);
    // Node appends `*` directly when the path already ends in a separator, so
    // the root grant is `/*` rather than `//*`.
    if trimmed == b"/" {
        return b"/*".to_vec();
    }
    let mut out = trimmed.to_vec();
    out.extend_from_slice(b"/*");
    out
}

/// [`wildcard_if_dir_bytes`] for callers with UTF-8 paths.
pub fn wildcard_if_dir(resolved: &str, is_directory: bool) -> String {
    String::from_utf8_lossy(&wildcard_if_dir_bytes(resolved.as_bytes(), is_directory)).into_owned()
}

/// Whether `path` is an existing directory, following symlinks.
///
/// This is the only filesystem access in this module and it happens once per
/// grant, at startup, never per check.
pub fn is_existing_directory_bytes(path: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(path) else {
        return false;
    };
    Path::new(text).is_dir()
}

/// [`is_existing_directory_bytes`] for callers with UTF-8 paths.
pub fn is_existing_directory(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// `FSPermission::RadixTree`: a compressed prefix tree where `*` terminates a
/// pattern.
///
/// The structure is a direct port, so the matching quirks Node's tests depend on
/// are reproduced rather than re-derived:
///
/// * everything after the first `*` of a stored pattern is ignored;
/// * a node that ends a pattern still accepts deeper paths when the stored
///   pattern has more characters after it;
/// * a `*` child wins over a literal child when both exist.
#[derive(Debug, Default, Clone)]
pub struct RadixTree {
    root: Node,
}

#[derive(Debug, Default, Clone)]
struct Node {
    prefix: Vec<u8>,
    children: Vec<(u8, Node)>,
    wildcard_child: Option<Box<Node>>,
    is_leaf: bool,
}

impl Node {
    fn with_prefix(prefix: &[u8]) -> Self {
        Self {
            prefix: prefix.to_vec(),
            children: Vec::new(),
            wildcard_child: None,
            is_leaf: false,
        }
    }

    fn find_child(&self, label: u8) -> Option<&Node> {
        self.children
            .iter()
            .find(|(candidate, _)| *candidate == label)
            .map(|(_, node)| node)
    }

    fn find_child_mut(&mut self, label: u8) -> Option<&mut Node> {
        self.children
            .iter_mut()
            .find(|(candidate, _)| *candidate == label)
            .map(|(_, node)| node)
    }

    fn set_child(&mut self, label: u8, node: Node) {
        match self.find_child_mut(label) {
            Some(existing) => *existing = node,
            None => self.children.push((label, node)),
        }
    }

    fn create_child(&mut self, path_prefix: &[u8]) -> &mut Node {
        let Some(label) = path_prefix.first().copied() else {
            self.is_leaf = true;
            return self;
        };

        if self.find_child(label).is_none() {
            self.children.push((label, Node::with_prefix(path_prefix)));
            return self.find_child_mut(label).expect("child was just inserted");
        }

        let existing = self.find_child(label).expect("child exists");
        let child_was_end_node = existing.is_end_node();
        let shared = existing
            .prefix
            .iter()
            .zip(path_prefix.iter())
            .take_while(|(left, right)| left == right)
            .count();

        if shared < existing.prefix.len() {
            // The new prefix diverges inside this child, so the child has to be
            // split at the shared start and re-hung under a new parent node.
            let (_, detached) = self
                .children
                .iter()
                .position(|(candidate, _)| *candidate == label)
                .map(|index| self.children.remove(index))
                .expect("child exists");

            let parent_prefix = detached.prefix[..shared].to_vec();
            let mut split_child = Node::with_prefix(&parent_prefix);
            let remainder = detached.prefix[shared..].to_vec();
            if let Some(first) = remainder.first().copied() {
                let mut detached = detached;
                detached.prefix = remainder;
                split_child.children.push((first, detached));
            }

            let split_label = parent_prefix[0];
            self.set_child(split_label, split_child);
            let split = self
                .find_child_mut(split_label)
                .expect("split child was just inserted");
            return split.create_child(&path_prefix[shared..]);
        }

        let child = self.find_child_mut(label).expect("child exists");
        if child_was_end_node {
            child.is_leaf = true;
        }
        child.create_child(&path_prefix[shared..])
    }

    fn create_wildcard_child(&mut self) -> &mut Node {
        self.wildcard_child
            .get_or_insert_with(|| Box::new(Node::default()))
    }

    fn next_node(&self, path: &[u8], index: usize) -> Option<&Node> {
        if index >= path.len() {
            return None;
        }

        // A wildcard sibling wins over the literal one.
        if self.children.len() > 1 {
            if let Some(wildcard) = self.find_child(WILDCARD) {
                return Some(wildcard);
            }
        }

        let child = self.find_child(path[index])?;
        let mut cursor = index;
        for expected in &child.prefix {
            if *expected == WILDCARD {
                return Some(child);
            }
            if cursor >= path.len() {
                // The path is exhausted but the prefix expects more. A
                // separator is the one character Node tolerates missing, which
                // is what makes `/folder/*` match `/folder`.
                if *expected == SEPARATOR {
                    continue;
                }
                return None;
            }
            if path[cursor] != *expected {
                return None;
            }
            cursor += 1;
        }
        Some(child)
    }

    fn is_end_node(&self) -> bool {
        self.children.is_empty() || self.is_leaf
    }
}

impl RadixTree {
    /// Builds a tree from already-resolved, wildcard-expanded grants.
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut tree = Self::default();
        for pattern in patterns {
            tree.insert(pattern.as_ref());
        }
        tree
    }

    /// Port of `RadixTree::Insert`. A `*` truncates the stored pattern because
    /// "after passing a wildcard character, all subsequent characters are
    /// ignored".
    pub fn insert(&mut self, path: &[u8]) {
        let mut current = &mut self.root;
        let mut parent_node_prefix_len = current.prefix.len();

        for index in 1..=path.len() {
            let is_wildcard_node = path[index - 1] == WILDCARD;
            let is_last_char = index == path.len();

            if is_wildcard_node || is_last_char {
                let start = parent_node_prefix_len.min(index);
                current = current.create_child(&path[start..index]);
            }

            if is_wildcard_node {
                current = current.create_wildcard_child();
                parent_node_prefix_len = index;
            }
        }
    }

    /// Port of `RadixTree::Lookup`. Node passes `when_empty_return = true` for
    /// filesystem lookups: a tree without patterns grants nothing.
    pub fn lookup(&self, path: &[u8]) -> bool {
        if self.root.children.is_empty() {
            return false;
        }
        let mut current = &self.root;
        let mut parent_node_prefix_len = current.prefix.len();

        loop {
            if parent_node_prefix_len == path.len() && current.is_end_node() {
                return true;
            }

            let Some(node) = current.next_node(path, parent_node_prefix_len) else {
                return false;
            };
            current = node;
            parent_node_prefix_len += current.prefix.len();

            if current.wildcard_child.is_some()
                && path.len() >= parent_node_prefix_len.saturating_sub(2)
            {
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(patterns: &[&str]) -> RadixTree {
        RadixTree::from_patterns(patterns.iter().copied())
    }

    #[test]
    fn resolves_relative_against_the_working_directory() {
        assert_eq!(resolve_path("/home/app", "index.js"), "/home/app/index.js");
        assert_eq!(
            resolve_path("/home/app", "./index.js"),
            "/home/app/index.js"
        );
        assert_eq!(resolve_path("/home/app", "../x/./y"), "/home/x/y");
        assert_eq!(resolve_path("/home/app", "/etc/passwd"), "/etc/passwd");
        assert_eq!(resolve_path("/home/app", "/"), "/");
        assert_eq!(resolve_path("/", "x"), "/x");
        // Resolution strips a trailing separator, which is why `has()` on
        // `/files/index.js/` still matches the `/files/index.js` grant.
        assert_eq!(resolve_path("/", "/files/index.js/"), "/files/index.js");
    }

    #[test]
    fn normalises_without_touching_the_filesystem() {
        assert_eq!(normalize_absolute_bytes(b"/a//b/./c/../d/"), b"/a/b/d");
        assert_eq!(normalize_absolute_bytes(b"/.."), b"/");
        assert_eq!(normalize_absolute_bytes(b"/../.."), b"/");
    }

    #[test]
    fn byte_paths_keep_non_utf8_sequences_intact() {
        // A path is not required to be valid UTF-8; resolution and matching must
        // treat it as opaque bytes, as Node's `std::string` does.
        let cwd = b"/work";
        let path = b"/work/caf\xe9.txt";
        assert_eq!(resolve_path_bytes(cwd, path), path);

        let grants = RadixTree::from_patterns([b"/work/*".as_slice()]);
        assert!(grants.lookup(path));
    }

    #[test]
    fn directory_grants_gain_a_wildcard() {
        assert_eq!(wildcard_if_dir("/tmp", true), "/tmp/*");
        assert_eq!(wildcard_if_dir("/tmp/", true), "/tmp/*");
        assert_eq!(wildcard_if_dir("/", true), "/*");
        assert_eq!(wildcard_if_dir("/tmp", false), "/tmp");
        assert_eq!(wildcard_if_dir("/tmp/f.txt", false), "/tmp/f.txt");
    }

    #[test]
    fn exact_file_grant_matches_the_file_only() {
        // `has()` resolves the probe first, so a trailing separator is gone by
        // the time the tree is consulted and still matches (Node answers `true`
        // for `/files/index.js/`). A child path is never covered.
        let grants = tree(&["/files/index.js"]);
        assert!(grants.lookup(b"/files/index.js"));
        assert!(!grants.lookup(b"/files/index.js/x"));
        assert!(!grants.lookup(b"/files/index.j"));
        assert!(!grants.lookup(b"/files/index.jsonx"));
    }

    #[test]
    fn directory_pattern_matches_below_itself() {
        let grants = tree(&["/folder/*"]);
        assert!(grants.lookup(b"/folder"));
        assert!(grants.lookup(b"/folder/"));
        assert!(grants.lookup(b"/folder/a"));
        assert!(grants.lookup(b"/folder/a/subfolder/b"));
        assert!(!grants.lookup(b"/folde"));
    }

    #[test]
    fn a_wildcard_ends_the_pattern() {
        // `/home/*.js` behaves like `/home/*`, matching the documented "after
        // passing a wildcard character all subsequent characters are ignored"
        // rule.
        let grants = tree(&["/home/*.js"]);
        assert!(grants.lookup(b"/home/x.js"));
        assert!(grants.lookup(b"/home/y.md"));
        assert!(grants.lookup(b"/home/"));
    }

    #[test]
    fn prefix_wildcards_keep_the_literal_prefix() {
        let grants = tree(&["/tmp/test*"]);
        assert!(grants.lookup(b"/tmp/test"));
        assert!(grants.lookup(b"/tmp/test/"));
        assert!(grants.lookup(b"/tmp/test/x"));
        assert!(grants.lookup(b"/tmp/test2"));
        assert!(!grants.lookup(b"/tmp/tes"));
        assert!(!grants.lookup(b"/tmp/t"));
    }

    #[test]
    fn an_empty_tree_grants_nothing() {
        assert!(!tree(&[]).lookup(b"/"));
        assert!(!tree(&[]).lookup(b"/x"));
    }

    #[test]
    fn sibling_wildcards_and_leaf_nodes_coexist() {
        // Mixing `*` and literal children under one node must keep both
        // reachable, and a leaf must not shadow its descendants.
        let grants = tree(&["/show", "/show/*", "/slower", "/slown"]);
        assert!(grants.lookup(b"/show"));
        assert!(grants.lookup(b"/show/deep/path"));
        assert!(grants.lookup(b"/slower"));
        assert!(grants.lookup(b"/slown"));
        assert!(!grants.lookup(b"/slow"));
        assert!(!grants.lookup(b"/slows"));
    }

    #[test]
    fn sibling_grants_split_into_shared_prefixes() {
        // `/a/bar` and `/a/baz` share `/a/ba`, which forces a node split.
        let grants = tree(&["/a/bar", "/a/baz"]);
        assert!(grants.lookup(b"/a/bar"));
        assert!(grants.lookup(b"/a/baz"));
        assert!(!grants.lookup(b"/a/ba"));
        assert!(!grants.lookup(b"/a/baq"));

        // The same shape with one path a strict prefix of the other.
        let grants = tree(&["/a/b", "/a/bc"]);
        assert!(grants.lookup(b"/a/b"));
        assert!(grants.lookup(b"/a/bc"));
        assert!(!grants.lookup(b"/a/"));
    }
}
