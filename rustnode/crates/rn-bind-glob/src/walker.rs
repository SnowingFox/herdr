//! Walking the filesystem for `globSync` and `globStart`.
//!
//! This ports `src/glob/glob_walker.cc`. The C++ spreads a visit across a scan
//! pool and a sequencer so a large tree is scanned in parallel; rustnode runs
//! every visit inline. The *traversal* and the *output order* are the same,
//! because both are observable: `globSync` returns an array and Node's tests
//! compare it.
//!
//! Two details are easy to get wrong:
//!
//! * **Order.** Pending visits form a stack. Children are pushed in directory
//!   order and popped from the end, so a directory's subdirectories are visited
//!   in reverse listing order while files in the directory itself still come
//!   out in listing order. That is what Node produces.
//! * **The seen set.** A path can be reached with more than one pattern index
//!   (`**/**`, `a/../a`). The set is keyed by path *and the remaining pattern
//!   suffix*, so a revisit that has more of the pattern to match still runs.

use std::collections::{HashMap, HashSet};

use crate::ast::Pattern;
use crate::matcher::{match_pattern, test_part, CompiledPattern, PartKind};
use crate::parser::part_is;

/// `UV_DIRENT_*` values, which `lib/internal/fs/glob.js` turns into `Dirent`s.
pub const DIRENT_UNKNOWN: i32 = 0;
pub const DIRENT_FILE: i32 = 1;
pub const DIRENT_DIR: i32 = 2;
pub const DIRENT_LINK: i32 = 3;
pub const DIRENT_FIFO: i32 = 4;
pub const DIRENT_SOCKET: i32 = 5;
pub const DIRENT_CHAR: i32 = 6;
pub const DIRENT_BLOCK: i32 = 7;

/// One result of a walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Relative to the walk's cwd, using the platform separator.
    pub path: String,
    /// One of the `DIRENT_*` values.
    pub kind: i32,
}

/// How a walk was asked to behave, from `options` in `lib/internal/fs/glob.js`.
#[derive(Debug, Clone, Default)]
pub struct WalkOptions {
    /// `options.cwd`, or `"."`.
    pub cwd: String,
    pub follow_symlinks: bool,
    pub with_file_types: bool,
    /// How many directory levels below `cwd` a result may sit. `None` is no
    /// limit.
    pub max_depth: Option<usize>,
}

impl WalkOptions {
    pub fn new(cwd: impl Into<String>, follow_symlinks: bool, max_depth: Option<usize>) -> Self {
        Self {
            cwd: cwd.into(),
            follow_symlinks,
            with_file_types: false,
            max_depth,
        }
    }
}

/// The JavaScript `exclude` callback, as the walk sees it.
///
/// `globSync` runs on the main thread, so the callback is called directly. The
/// C++ `Question`/`Answer` protocol exists only because its walk runs on a pool
/// thread that cannot enter V8; the observable sequence of calls is identical.
pub trait ExcludeFilter {
    /// A path relative to the walk's cwd.
    fn excludes_path(&mut self, path: &str) -> Result<bool, String>;
    /// A directory entry: its name, the absolute path of the directory holding
    /// it, and its dirent type.
    fn excludes_entry(&mut self, name: &str, parent: &str, kind: i32) -> Result<bool, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatInfo {
    exists: bool,
    is_dir: bool,
    is_link: bool,
    kind: i32,
}

impl StatInfo {
    const MISSING: Self = Self {
        exists: false,
        is_dir: false,
        is_link: false,
        kind: DIRENT_UNKNOWN,
    };

    fn dirent_kind(&self) -> i32 {
        if self.kind != DIRENT_UNKNOWN {
            self.kind
        } else if self.is_link {
            DIRENT_LINK
        } else if self.is_dir {
            DIRENT_DIR
        } else {
            DIRENT_FILE
        }
    }
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    kind: i32,
}

// ---------------------------------------------------------------------------
// Path helpers
//
// These mirror Node's `path` on the host rather than calling into it, because a
// binding cannot re-enter JavaScript. They are the subset the walker needs.
// ---------------------------------------------------------------------------

#[cfg(windows)]
const SEPARATOR: char = '\\';
#[cfg(not(windows))]
const SEPARATOR: char = '/';

fn is_separator(character: char) -> bool {
    character == '/' || (cfg!(windows) && character == '\\')
}

fn is_absolute(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if path.chars().next().is_some_and(is_separator) {
        return true;
    }
    if cfg!(windows) {
        let chars: Vec<char> = path.chars().take(3).collect();
        if chars.len() >= 3
            && chars[0].is_ascii_alphabetic()
            && chars[1] == ':'
            && is_separator(chars[2])
        {
            return true;
        }
    }
    false
}

/// `path.normalize()` for the host's rules.
///
/// A relative path may step above its own start, so `..` segments have to be
/// kept until there is something to cancel. The bug this replaces collapsed
/// `"../"` to `""`, which silently turned a parent-relative redirect into a
/// visit of the directory it started from.
fn normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = is_absolute(path);
    let trailing = path.chars().last().is_some_and(is_separator);

    let mut root = String::new();
    let mut body = path;
    #[cfg(windows)]
    if cfg!(windows) {
        let chars: Vec<char> = path.chars().collect();
        if chars.len() >= 2 && chars[0].is_ascii_alphabetic() && chars[1] == ':' {
            root = chars[..2].iter().collect();
            body = &path[2..];
            if let Some(first) = body.chars().next() {
                if is_separator(first) {
                    root.push(SEPARATOR);
                    body = &body[1..];
                }
            }
        } else if absolute {
            root.push(SEPARATOR);
            body = &path[1..];
            if body.starts_with(SEPARATOR) {
                root.push(SEPARATOR);
                body = &body[1..];
            }
        }
    }
    #[cfg(not(windows))]
    if absolute {
        root.push('/');
        body = &path[1..];
    }

    // A rooted path cannot step above its root, so `..` there is dropped. A
    // relative path may, so its `..` segments accumulate.
    let allow_above_root = root.is_empty();
    let mut segments: Vec<&str> = Vec::new();
    for segment in body.split(is_separator) {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            if segments.last().is_some_and(|last| *last != "..") {
                segments.pop();
            } else if allow_above_root {
                segments.push("..");
            }
            // A rooted path drops a `..` that would escape the root.
            continue;
        }
        segments.push(segment);
    }
    let mut normalized = segments.join(&SEPARATOR.to_string());
    if normalized.is_empty() && root.is_empty() {
        normalized = ".".to_string();
    }
    if !normalized.is_empty() && trailing {
        normalized.push(SEPARATOR);
    }
    format!("{root}{normalized}")
}

/// `path.join()`
fn join(a: &str, b: &str) -> String {
    if a.is_empty() {
        return if b.is_empty() {
            ".".to_string()
        } else {
            normalize(b)
        };
    }
    if b.is_empty() {
        return normalize(a);
    }
    normalize(&format!("{a}{SEPARATOR}{b}"))
}

/// Joins a directory and one entry name without normalising the directory.
fn join_entry(dir: &str, name: &str) -> String {
    if dir == "." {
        return name.to_string();
    }
    let mut out = dir.to_string();
    if !dir.is_empty() && !dir.chars().last().is_some_and(is_separator) {
        out.push(SEPARATOR);
    }
    out.push_str(name);
    out
}

/// `path.resolve(root, p)`
fn resolve(root_absolute: &str, path: &str) -> String {
    let mut resolved = if is_absolute(path) {
        normalize(path)
    } else {
        join(root_absolute, path)
    };
    while resolved.len() > 1
        && resolved.chars().last().is_some_and(is_separator)
        && !(cfg!(windows) && resolved.len() == 3 && resolved.chars().nth(1) == Some(':'))
    {
        resolved.pop();
    }
    resolved
}

/// `path.resolve(p)` against the process working directory.
fn resolve_with_cwd(path: &str) -> Result<String, String> {
    if is_absolute(path) {
        return Ok(resolve("/", path));
    }
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    let cwd = cwd.to_string_lossy().into_owned();
    Ok(join(&normalize(&cwd), path))
}

/// The depth of a walk path that never leaves `cwd`.
fn plain_depth(path: &str) -> Option<usize> {
    if path == "." {
        return Some(0);
    }
    if is_absolute(path) {
        return None;
    }
    let mut depth = 0usize;
    for segment in path.split(is_separator) {
        if segment == ".." {
            return None;
        }
        if !segment.is_empty() && segment != "." {
            depth += 1;
        }
    }
    Some(depth)
}

/// `path.relative(from, to)`, comparing segments exactly.
fn relative(from: &str, to: &str) -> String {
    if from == to {
        return String::new();
    }
    let from_parts: Vec<&str> = from.split(is_separator).collect();
    let to_parts: Vec<&str> = to.split(is_separator).collect();
    let mut common = 0usize;
    while common < from_parts.len()
        && common < to_parts.len()
        && from_parts[common] == to_parts[common]
    {
        common += 1;
    }
    let mut out = String::new();
    for _ in common..from_parts.len() {
        if !out.is_empty() {
            out.push(SEPARATOR);
        }
        out.push_str("..");
    }
    for part in &to_parts[common..] {
        if !out.is_empty() {
            out.push(SEPARATOR);
        }
        out.push_str(part);
    }
    out
}

/// `path.relative` with both sides folded, which is what the depth limit uses
/// on a case-insensitive host.
fn relative_folded(from: &str, to: &str) -> String {
    relative(&from.to_lowercase(), &to.to_lowercase())
}

/// A relative path that leaves the directory it is relative to.
fn is_outside_path(rel: &str) -> bool {
    is_absolute(rel)
        || rel == ".."
        || (rel.len() > 2 && rel.starts_with("..") && rel.chars().nth(2).is_some_and(is_separator))
}

fn path_depth(rel: &str) -> usize {
    if rel.is_empty() {
        return 0;
    }
    if is_absolute(rel) {
        return usize::MAX;
    }
    rel.split(is_separator)
        .filter(|segment| !segment.is_empty())
        .count()
}

// ---------------------------------------------------------------------------
// Filesystem access
// ---------------------------------------------------------------------------

fn stat_path(path: &str, follow: bool) -> StatInfo {
    let result = if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    };
    match result {
        Ok(metadata) => StatInfo {
            exists: true,
            is_dir: metadata.is_dir(),
            is_link: metadata.file_type().is_symlink(),
            kind: kind_of(&metadata),
        },
        Err(_) => StatInfo::MISSING,
    }
}

fn kind_of(metadata: &std::fs::Metadata) -> i32 {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return DIRENT_LINK;
    }
    if file_type.is_dir() {
        return DIRENT_DIR;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_fifo() {
            return DIRENT_FIFO;
        }
        if file_type.is_socket() {
            return DIRENT_SOCKET;
        }
        if file_type.is_char_device() {
            return DIRENT_CHAR;
        }
        if file_type.is_block_device() {
            return DIRENT_BLOCK;
        }
    }
    DIRENT_FILE
}

/// One `scandir`. Entries keep the order the OS returns them in, which is
/// observable in `globSync`'s result array.
fn read_dir(path: &str) -> Vec<DirEntry> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // `uv_fs_scandir` reports whatever type the directory entry carries and
        // `Unknown` when it carries none, which the walker then stats.
        let kind = match entry.file_type() {
            Ok(file_type) if file_type.is_symlink() => DIRENT_LINK,
            Ok(file_type) if file_type.is_dir() => DIRENT_DIR,
            Ok(_) => DIRENT_FILE,
            Err(_) => DIRENT_UNKNOWN,
        };
        out.push(DirEntry { name, kind });
    }
    // `uv_fs_scandir` sorts with `alphasort`, so `fs.readdir` — and therefore
    // `fs.globSync` — reports names in byte order rather than readdir order.
    // Sorting here is what makes the two agree.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ---------------------------------------------------------------------------
// Pattern state
// ---------------------------------------------------------------------------

/// An insertion-ordered set of small indexes, matching the C++ `IndexSet`.
#[derive(Debug, Clone, Default)]
struct IndexSet {
    values: Vec<usize>,
}

impl IndexSet {
    fn add(&mut self, value: usize) {
        if !self.values.contains(&value) {
            self.values.push(value);
        }
    }

    fn has(&self, value: usize) -> bool {
        self.values.contains(&value)
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.values.iter().copied()
    }
}

/// Where the walk is in one pattern row.
#[derive(Debug, Clone)]
struct PatternState {
    /// Index into the walk's flat row list.
    row: usize,
    absolute: bool,
    indexes: IndexSet,
    symlinks: IndexSet,
    /// The absolute paths already resolved on the way down, for cycle
    /// detection while following symlinks. Shared, because the JS clones it
    /// only when it grows.
    realpaths: std::rc::Rc<Vec<String>>,
}

impl PatternState {
    fn child(&self, indexes: IndexSet, symlinks: IndexSet) -> Self {
        Self {
            row: self.row,
            absolute: self.absolute,
            indexes,
            symlinks,
            realpaths: std::rc::Rc::clone(&self.realpaths),
        }
    }
}

fn is_literal(part: Option<&crate::matcher::PartMatcher>) -> bool {
    matches!(part, Some(part) if part.kind == PartKind::Literal)
}

fn is_globstar(part: Option<&crate::matcher::PartMatcher>) -> bool {
    matches!(part, Some(part) if part.kind == PartKind::Globstar)
}

/// `isAbsolute(globParts.join(sep))`
fn row_is_absolute(row: &crate::matcher::CompiledRow) -> bool {
    let Some(head) = row.parts.first() else {
        return false;
    };
    if head.kind != PartKind::Literal {
        return false;
    }
    if head.literal.is_empty() {
        return true;
    }
    cfg!(windows) && row.parts.len() > 1 && crate::parser::is_windows_drive(&head.literal)
}

/// `pattern.at(0) === '.'`
fn is_dot_first_part(state: &PatternState, rows: &[crate::matcher::CompiledRow]) -> bool {
    matches!(
        rows[state.row].parts.first(),
        Some(part) if part.kind == PartKind::Literal && part_is(&part.literal, ".")
    )
}

fn state_at<'a>(
    rows: &'a [crate::matcher::CompiledRow],
    state: &PatternState,
    index: i64,
) -> Option<&'a crate::matcher::PartMatcher> {
    let parts = &rows[state.row].parts;
    let size = parts.len() as i64;
    let resolved = if index < 0 { size + index } else { index };
    if resolved < 0 || resolved >= size {
        return None;
    }
    parts.get(resolved as usize)
}

fn state_is_last(
    rows: &[crate::matcher::CompiledRow],
    state: &PatternState,
    is_directory: bool,
) -> bool {
    let parts = &rows[state.row].parts;
    let last = parts.len() - 1;
    if state.indexes.has(last) {
        return true;
    }
    let tail = state_at(rows, state, -1);
    let before = state_at(rows, state, -2);
    matches!(tail, Some(part) if part.kind == PartKind::Literal && part.literal.is_empty())
        && is_directory
        && last > 0
        && state.indexes.has(last - 1)
        && is_globstar(before)
}

fn state_has_seen_symlinks(state: &PatternState) -> bool {
    state.indexes.iter().any(|index| !state.symlinks.has(index))
}

/// `TestIndex`: a globstar position always matches.
fn test_index(rows: &[crate::matcher::CompiledRow], row: usize, index: usize, name: &str) -> bool {
    let Some(part) = rows[row].parts.get(index) else {
        return false;
    };
    if part.kind == PartKind::Globstar {
        return true;
    }
    let subject: Pattern = name.encode_utf16().collect();
    test_part(part, &subject)
}

#[derive(Debug, Default)]
struct Visit {
    path: String,
    patterns: Vec<PatternState>,
}

/// A pending subpattern: the path to visit and the states to visit it under.
type Subpatterns = Vec<(String, Vec<PatternState>)>;

fn push_sub(subpatterns: &mut Subpatterns, path: String, pattern: PatternState) {
    if let Some((_, patterns)) = subpatterns.iter_mut().find(|(pending, _)| *pending == path) {
        patterns.push(pattern);
    } else {
        subpatterns.push((path, vec![pattern]));
    }
}

struct Walk<'a> {
    options: &'a WalkOptions,
    /// Every include row, flattened across patterns, which is the C++ `rows_`.
    rows: Vec<crate::matcher::CompiledRow>,
    /// Per row, the interned id of each remaining suffix.
    row_suffix_ids: Vec<Vec<u32>>,
    excludes: &'a [CompiledPattern],
    /// The flags exclude patterns were compiled with. Exclude matching is a
    /// pure string comparison with no filesystem lookups, so on a
    /// case-insensitive host its literal segments fold too, unlike an include
    /// pattern's.
    exclude_flags: crate::parser::CompileFlags,
    root_absolute: String,
    filter: Option<&'a mut dyn ExcludeFilter>,

    results: Vec<WalkEntry>,
    result_set: HashSet<String>,

    seen: HashMap<String, HashSet<u32>>,
    stat_cache: HashMap<String, StatInfo>,
    follow_stat_cache: HashMap<String, bool>,
    realpath_cache: HashMap<String, String>,
    readdir_cache: HashMap<String, Vec<DirEntry>>,
    depth_cache: HashMap<String, usize>,
    ancestor_cache: HashMap<String, bool>,

    aborted: bool,
}

impl<'a> Walk<'a> {
    fn new(
        options: &'a WalkOptions,
        includes: &[CompiledPattern],
        excludes: &'a [CompiledPattern],
        exclude_flags: crate::parser::CompileFlags,
        filter: Option<&'a mut dyn ExcludeFilter>,
    ) -> Result<Self, String> {
        let root_absolute = resolve_with_cwd(&options.cwd)?;
        let mut rows = Vec::new();
        for compiled in includes {
            rows.extend(compiled.rows.iter().cloned());
        }
        // `cacheKey(index)` is interned to an id so the visited set stores
        // integers instead of rebuilt strings.
        let mut table: HashMap<String, u32> = HashMap::new();
        let mut row_suffix_ids = Vec::with_capacity(rows.len());
        for row in &rows {
            row_suffix_ids.push(intern_suffixes(&row.parts, &mut table));
        }
        Ok(Self {
            options,
            rows,
            row_suffix_ids,
            excludes,
            exclude_flags,
            root_absolute,
            filter,
            results: Vec::new(),
            result_set: HashSet::new(),
            seen: HashMap::new(),
            stat_cache: HashMap::new(),
            follow_stat_cache: HashMap::new(),
            realpath_cache: HashMap::new(),
            readdir_cache: HashMap::new(),
            depth_cache: HashMap::new(),
            ancestor_cache: HashMap::new(),
            aborted: false,
        })
    }

    fn run(&mut self) -> Result<(), String> {
        let mut queue: Vec<Visit> = Vec::new();
        let mut initial = Visit {
            path: ".".to_string(),
            patterns: Vec::new(),
        };
        for row in 0..self.rows.len() {
            let mut indexes = IndexSet::default();
            indexes.add(0);
            initial.patterns.push(PatternState {
                row,
                absolute: row_is_absolute(&self.rows[row]),
                indexes,
                symlinks: IndexSet::default(),
                realpaths: std::rc::Rc::new(Vec::new()),
            });
        }
        queue.push(initial);

        while let Some(visit) = queue.pop() {
            if self.aborted {
                return Ok(());
            }
            let mut subpatterns: Subpatterns = Vec::new();
            for state in visit.patterns {
                if self.aborted {
                    return Ok(());
                }
                self.visit_directory(&visit.path, state, &mut subpatterns)?;
            }
            // Pushed in directory order and popped from the end, so the last
            // subdirectory is visited first. That is the order Node emits.
            for (path, patterns) in subpatterns {
                queue.push(Visit { path, patterns });
            }
        }
        Ok(())
    }

    fn visit_directory(
        &mut self,
        path: &str,
        pattern: PatternState,
        subpatterns: &mut Subpatterns,
    ) -> Result<(), String> {
        if self.mark_seen(path, &pattern) {
            return Ok(());
        }

        let fullpath = resolve(&self.root_absolute, path);
        let stat = self.stat_sync(&fullpath);
        let parts_len = self.rows[pattern.row].parts.len();
        let last = parts_len - 1;
        let mut is_directory = stat.is_dir;
        if !is_directory && stat.is_link {
            is_directory = if self.options.follow_symlinks {
                self.follow_stat_is_directory(&fullpath)
            } else {
                state_has_seen_symlinks(&pattern)
            };
        }

        if self.excluded_full(&fullpath) {
            return Ok(());
        }

        let is_first = pattern.indexes.has(0);
        if is_first {
            if let Some(first) = state_at(&self.rows, &pattern, 0) {
                if first.kind == PartKind::Literal {
                    if first.literal.is_empty() {
                        let mut next = IndexSet::default();
                        next.add(1);
                        self.push_subpattern(
                            subpatterns,
                            "/".to_string(),
                            pattern.child(next, IndexSet::default()),
                        )?;
                        return Ok(());
                    }
                    if part_is(&first.literal, "..") {
                        let mut next = IndexSet::default();
                        next.add(1);
                        self.push_subpattern(
                            subpatterns,
                            "../".to_string(),
                            pattern.child(next, IndexSet::default()),
                        )?;
                        return Ok(());
                    }
                    if part_is(&first.literal, ".") {
                        let mut next = IndexSet::default();
                        next.add(1);
                        self.push_subpattern(
                            subpatterns,
                            ".".to_string(),
                            pattern.child(next, IndexSet::default()),
                        )?;
                        return Ok(());
                    }
                }
            }
        }

        let tail = state_at(&self.rows, &pattern, -1).cloned();
        if state_is_last(&self.rows, &pattern, is_directory) && is_literal(tail.as_ref()) {
            let tail = tail.expect("checked literal");
            let name = String::from_utf16_lossy(&tail.literal);
            let tail_stat = self.stat_sync(&join(&fullpath, &name));
            if tail_stat.exists && (!name.is_empty() || is_directory) {
                self.add_result(join(path, &name), tail_stat.dirent_kind());
            }
            if pattern.indexes.len() == 1 && pattern.indexes.has(last) {
                return Ok(());
            }
        } else if state_is_last(&self.rows, &pattern, is_directory)
            && is_globstar(tail.as_ref())
            && (path != "."
                || is_dot_first_part(&pattern, &self.rows)
                || (last == 0 && stat.exists))
        {
            // A pattern ending in `**` returns the directory itself, except for
            // `.` unless the pattern starts with `.` or is exactly `**`.
            self.add_result(path.to_string(), stat.dirent_kind());
        }

        if !is_directory || !self.may_descend(path, &pattern) {
            return Ok(());
        }
        if self.is_cyclic(&fullpath, is_directory, &pattern) {
            return Ok(());
        }
        let next_realpaths = self.next_realpaths(&fullpath, is_directory, &pattern);

        // When exactly one literal position is live, probe that child directly
        // instead of enumerating the directory.
        let mut literal_child: Vec<DirEntry> = Vec::new();
        let mut probed = false;
        if pattern.indexes.len() == 1 {
            let index = pattern.indexes.iter().next().unwrap_or(0) as i64;
            if let Some(part) = state_at(&self.rows, &pattern, index) {
                if part.kind == PartKind::Literal {
                    let name = String::from_utf16_lossy(&part.literal);
                    let info = self.stat_sync(&join(&fullpath, &name));
                    if !info.exists {
                        return Ok(());
                    }
                    literal_child.push(DirEntry {
                        name,
                        kind: info.dirent_kind(),
                    });
                    probed = true;
                }
            }
        }
        let entries: Vec<DirEntry> = if probed {
            literal_child
        } else {
            self.readdir_sync(&fullpath)
        };

        for entry in entries {
            if self.aborted {
                return Ok(());
            }
            let entry_path = join_entry(path, &entry.name);
            let entry_stat = StatInfo {
                exists: true,
                is_dir: entry.kind == DIRENT_DIR,
                is_link: entry.kind == DIRENT_LINK,
                kind: entry.kind,
            };
            // The absolute path is only needed for entries the walk can
            // descend into.
            let mut entry_is_directory = entry_stat.is_dir;
            if entry_stat.is_dir || entry_stat.is_link {
                let entry_fullpath = join_entry(&fullpath, &entry.name);
                self.note_child_stat(&entry_fullpath, entry_stat);
                if !entry_is_directory && self.options.follow_symlinks {
                    entry_is_directory = self.follow_stat_is_directory(&entry_fullpath);
                }
            }

            let mut sub_patterns = IndexSet::default();
            let mut next_symlinks = IndexSet::default();
            let indexes: Vec<usize> = pattern.indexes.iter().collect();
            for index in indexes {
                let current = state_at(&self.rows, &pattern, index as i64).cloned();
                let next_index = index + 1;
                let next = state_at(&self.rows, &pattern, next_index as i64).cloned();
                let from_symlink = !self.options.follow_symlinks && pattern.symlinks.has(index);

                if is_globstar(current.as_ref()) {
                    let is_dot = entry.name.starts_with('.');
                    let next_matches = test_index(&self.rows, pattern.row, next_index, &entry.name);
                    let mut next_non_glob = next_index;
                    while is_globstar(state_at(&self.rows, &pattern, next_non_glob as i64)) {
                        next_non_glob += 1;
                    }
                    let matches_dot =
                        is_dot && test_index(&self.rows, pattern.row, next_non_glob, &entry.name);

                    if is_dot && !matches_dot {
                        continue;
                    }
                    if self.filter.is_some() {
                        let excluded = self.filter_entry(&entry.name, &fullpath, entry.kind)?;
                        if self.aborted {
                            return Ok(());
                        }
                        if excluded {
                            continue;
                        }
                    }

                    if !from_symlink && entry_is_directory {
                        sub_patterns.add(index);
                    } else if !from_symlink && index == last {
                        self.add_result(entry_path.clone(), entry.kind);
                    }

                    if next_matches
                        && next_index == last
                        && !state_is_last(&self.rows, &pattern, is_directory)
                    {
                        self.add_result(entry_path.clone(), entry.kind);
                    } else if next_matches && entry_is_directory {
                        sub_patterns.add(index + 2);
                    }
                    if (next_matches || is_dot_first_part(&pattern, &self.rows))
                        && entry_is_directory
                        && !from_symlink
                    {
                        sub_patterns.add(next_index);
                    }

                    if !self.options.follow_symlinks && entry_stat.is_link {
                        next_symlinks.add(index);
                    }

                    // `"**/.."`: both this directory and its parent stay live.
                    if is_literal(next.as_ref())
                        && matches!(next, Some(part) if part_is(&part.literal, ".."))
                        && entry_is_directory
                    {
                        let parent = join(path, "..");
                        if next_index < last {
                            let mut forward = IndexSet::default();
                            forward.add(next_index + 1);
                            if !subpatterns.iter().any(|(pending, _)| pending == path)
                                && !self.seen_at(path, &pattern, next_index + 1)
                            {
                                push_sub(
                                    subpatterns,
                                    path.to_string(),
                                    pattern.child(forward.clone(), IndexSet::default()),
                                );
                            }
                            if !subpatterns.iter().any(|(pending, _)| *pending == parent)
                                && !self.seen_at(&parent, &pattern, next_index + 1)
                            {
                                push_sub(
                                    subpatterns,
                                    parent.clone(),
                                    pattern.child(forward, IndexSet::default()),
                                );
                            }
                        } else {
                            let mut at_next = IndexSet::default();
                            at_next.add(next_index);
                            if !self.seen_at(path, &pattern, next_index) {
                                let child = pattern.child(at_next.clone(), IndexSet::default());
                                self.mark_seen(path, &child);
                                self.add_result(path.to_string(), stat.dirent_kind());
                            }
                            if !self.seen_at(path, &pattern, next_index)
                                || !self.seen_at(&parent, &pattern, next_index)
                            {
                                let child = pattern.child(at_next, IndexSet::default());
                                self.mark_seen(&parent, &child);
                                let kind = self.type_of_resolved(&parent);
                                self.add_result(parent.clone(), kind);
                            }
                        }
                    }
                }

                if is_literal(current.as_ref()) {
                    let current_literal = current
                        .as_ref()
                        .map(|part| part.literal.clone())
                        .unwrap_or_default();
                    if test_index(&self.rows, pattern.row, index, &entry.name) && index != last {
                        sub_patterns.add(next_index);
                    } else if part_is(&current_literal, ".")
                        && test_index(&self.rows, pattern.row, next_index, &entry.name)
                    {
                        if next_index == last {
                            self.add_result(entry_path.clone(), entry.kind);
                        } else {
                            sub_patterns.add(next_index + 1);
                        }
                    }
                }

                if matches!(current, Some(part) if part.kind == PartKind::Program)
                    && test_index(&self.rows, pattern.row, index, &entry.name)
                {
                    if index == last {
                        self.add_result(entry_path.clone(), entry.kind);
                    } else if entry_is_directory {
                        sub_patterns.add(next_index);
                    }
                }
            }

            if !sub_patterns.is_empty() {
                let mut child = pattern.child(sub_patterns, next_symlinks);
                child.realpaths = std::rc::Rc::clone(&next_realpaths);
                // Every child directory goes through `AddSubpattern`, which is
                // where excludes and the exclude callback prune a subtree
                // before it is scanned.
                self.push_subpattern(subpatterns, entry_path, child)?;
            }
        }
        Ok(())
    }

    /// Matches `path` against every exclude pattern as given.
    fn excluded_full(&mut self, path: &str) -> bool {
        if self.excludes.is_empty() {
            return false;
        }
        let _ = self.exclude_flags;
        let pattern: Pattern = path.encode_utf16().collect();
        self.excludes
            .iter()
            .any(|exclude| match_pattern(exclude, &pattern))
    }

    /// The exclude check a result gets.
    ///
    /// Exclude patterns are resolved against `cwd` before they reach the walker
    /// (`lib/internal/fs/glob.js` does `resolve(this.#root, pattern)`), and
    /// `AddResult` compares the *resolved* path. `AddSubpattern`, by contrast,
    /// compares the bare and slash-suffixed forms through `IsExcluded`, which
    /// resolves internally, so pruning sees both.
    fn is_excluded(&mut self, path: &str) -> bool {
        if self.excludes.is_empty() {
            return false;
        }
        let full = resolve(&self.root_absolute, path);
        self.excluded_full(&full)
    }

    /// The exclude check a subdirectory gets before the walk descends into it.
    ///
    /// Both tests use the *resolved* path, matching `AddSubpattern`: the bare
    /// form catches `a/sub`, and the trailing-separator form catches the
    /// directory itself so `a/**` prunes `a/` rather than descending and
    /// filtering every child individually.
    fn should_prune(&mut self, path: &str) -> bool {
        if self.excludes.is_empty() {
            return false;
        }
        // `AddSubpattern` prunes with the walk-relative path, then with the
        // resolved path and a trailing separator. The two forms are not
        // redundant: `a/**` matches the relative `a/sub` and so prunes the
        // directory, while a *file* sibling is only excluded if the resolved
        // form matches (see `add_result`). Node reaches the same split through
        // `IsExcluded`, which does not resolve, and `MatchFullPath`, which the
        // result path goes through after `Resolve`.
        if self.excluded_full(path) {
            return true;
        }
        let full = resolve(&self.root_absolute, path);
        self.excluded_full(&format!("{full}/")) && self.stat_sync(&full).is_dir
    }

    fn filter_entry(&mut self, name: &str, parent: &str, kind: i32) -> Result<bool, String> {
        let Some(filter) = self.filter.as_deref_mut() else {
            return Ok(false);
        };
        match filter.excludes_entry(name, parent, kind) {
            Ok(excluded) => Ok(excluded),
            Err(error) => {
                self.aborted = true;
                Err(error)
            }
        }
    }

    fn filter_path(&mut self, path: &str) -> Result<bool, String> {
        let Some(filter) = self.filter.as_deref_mut() else {
            return Ok(false);
        };
        match filter.excludes_path(path) {
            Ok(excluded) => Ok(excluded),
            Err(error) => {
                self.aborted = true;
                Err(error)
            }
        }
    }

    fn push_subpattern(
        &mut self,
        subpatterns: &mut Subpatterns,
        path: String,
        pattern: PatternState,
    ) -> Result<(), String> {
        if self.should_prune(&path) {
            return Ok(());
        }
        if self.filter.is_some() {
            let excluded = self.filter_path(&path)?;
            if self.aborted || excluded {
                return Ok(());
            }
        }
        push_sub(subpatterns, path, pattern);
        Ok(())
    }

    fn add_result(&mut self, path: String, kind: i32) {
        if !self.within_depth(&path) {
            return;
        }
        if !self.excludes.is_empty() && self.is_excluded(&path) {
            return;
        }
        if self.result_set.insert(path.clone()) {
            self.results.push(WalkEntry { path, kind });
        }
    }

    /// `Cache#add`: records the pattern suffixes this path was visited with and
    /// reports whether all of them were already known.
    fn mark_seen(&mut self, path: &str, pattern: &PatternState) -> bool {
        let original = self.seen.get(path).map_or(0, HashSet::len);
        let suffix_ids = self.row_suffix_ids[pattern.row].clone();
        let keys = self.seen.entry(path.to_string()).or_default();
        for index in pattern.indexes.iter() {
            let clamped = index.min(suffix_ids.len().saturating_sub(1));
            if let Some(&id) = suffix_ids.get(clamped) {
                keys.insert(id);
            }
        }
        keys.len() != original + pattern.indexes.len()
    }

    fn seen_at(&self, path: &str, pattern: &PatternState, index: usize) -> bool {
        let Some(keys) = self.seen.get(path) else {
            return false;
        };
        let suffix_ids = &self.row_suffix_ids[pattern.row];
        let clamped = index.min(suffix_ids.len().saturating_sub(1));
        suffix_ids.get(clamped).is_some_and(|id| keys.contains(id))
    }

    /// Whether a path is a directory above cwd, which an absolute pattern has to
    /// pass through on its way down.
    fn is_ancestor_of_root(&mut self, path: &str) -> bool {
        if let Some(&cached) = self.ancestor_cache.get(path) {
            return cached;
        }
        let fullpath = resolve(&self.root_absolute, path);
        let mut candidate = {
            let rel = relative(&fullpath, &self.root_absolute);
            !rel.is_empty() && !is_outside_path(&rel)
        };
        let mut needs_identity = cfg!(windows);
        if cfg!(target_os = "macos") && !candidate {
            candidate = {
                let rel = relative_folded(&fullpath, &self.root_absolute);
                !rel.is_empty() && !is_outside_path(&rel)
            };
            needs_identity = true;
        }
        let mut result = candidate;
        if candidate && needs_identity {
            let real_root = self.realpath_sync(&self.root_absolute.clone());
            let real_full = self.realpath_sync(&fullpath);
            let rel = relative(&real_full, &real_root);
            result = !real_root.is_empty()
                && !real_full.is_empty()
                && !rel.is_empty()
                && !is_outside_path(&rel);
        }
        self.ancestor_cache.insert(path.to_string(), result);
        result
    }

    fn depth_from_root(&mut self, path: &str) -> usize {
        if let Some(depth) = plain_depth(path) {
            return depth;
        }
        if let Some(&cached) = self.depth_cache.get(path) {
            return cached;
        }
        let fullpath = resolve(&self.root_absolute, path);
        let rel = relative(&self.root_absolute, &fullpath);
        let depth = path_depth(&rel);
        self.depth_cache.insert(path.to_string(), depth);
        depth
    }

    fn within_depth(&mut self, path: &str) -> bool {
        match self.options.max_depth {
            None => true,
            Some(limit) => self.depth_from_root(path) <= limit,
        }
    }

    fn may_descend(&mut self, path: &str, pattern: &PatternState) -> bool {
        let Some(limit) = self.options.max_depth else {
            return true;
        };
        if pattern.absolute && self.is_ancestor_of_root(path) {
            return true;
        }
        self.depth_from_root(path) < limit
    }

    fn is_cyclic(&mut self, path: &str, is_directory: bool, pattern: &PatternState) -> bool {
        if !self.options.follow_symlinks || !is_directory {
            return false;
        }
        let real = self.realpath_sync(path);
        if real.is_empty() {
            return false;
        }
        pattern.realpaths.contains(&real)
    }

    fn next_realpaths(
        &mut self,
        path: &str,
        is_directory: bool,
        pattern: &PatternState,
    ) -> std::rc::Rc<Vec<String>> {
        if !self.options.follow_symlinks || !is_directory {
            return std::rc::Rc::clone(&pattern.realpaths);
        }
        let real = self.realpath_sync(path);
        if real.is_empty() {
            return std::rc::Rc::clone(&pattern.realpaths);
        }
        let mut next = (*pattern.realpaths).clone();
        if !next.contains(&real) {
            next.push(real);
        }
        std::rc::Rc::new(next)
    }

    fn type_of_resolved(&mut self, path: &str) -> i32 {
        let full = resolve(&self.root_absolute, path);
        let info = self.stat_sync(&full);
        info.dirent_kind()
    }

    fn stat_sync(&mut self, path: &str) -> StatInfo {
        if let Some(&cached) = self.stat_cache.get(path) {
            return cached;
        }
        let info = stat_path(path, false);
        self.stat_cache.insert(path.to_string(), info);
        info
    }

    fn note_child_stat(&mut self, path: &str, info: StatInfo) {
        self.stat_cache.insert(path.to_string(), info);
    }

    fn follow_stat_is_directory(&mut self, path: &str) -> bool {
        if let Some(&cached) = self.follow_stat_cache.get(path) {
            return cached;
        }
        let is_dir = stat_path(path, true).is_dir;
        self.follow_stat_cache.insert(path.to_string(), is_dir);
        is_dir
    }

    fn realpath_sync(&mut self, path: &str) -> String {
        if let Some(cached) = self.realpath_cache.get(path) {
            return cached.clone();
        }
        let real = std::fs::canonicalize(path)
            .map(|resolved| resolved.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.realpath_cache.insert(path.to_string(), real.clone());
        real
    }

    fn readdir_sync(&mut self, path: &str) -> Vec<DirEntry> {
        if let Some(cached) = self.readdir_cache.get(path) {
            return cached.clone();
        }
        let mut entries = read_dir(path);
        for entry in &mut entries {
            if entry.kind != DIRENT_UNKNOWN {
                continue;
            }
            let info = self.stat_sync(&join(path, &entry.name));
            entry.kind = info.dirent_kind();
        }
        self.readdir_cache.insert(path.to_string(), entries.clone());
        entries
    }
}

/// `cacheKey(index)`: `globStrings[index..].join('/')`, interned to a small id.
fn intern_suffixes(
    parts: &[crate::matcher::PartMatcher],
    table: &mut HashMap<String, u32>,
) -> Vec<u32> {
    let mut ids = Vec::with_capacity(parts.len() + 1);
    for index in 0..=parts.len() {
        let mut key = String::new();
        for (offset, part) in parts[index..].iter().enumerate() {
            // The part's own text, not its lowered form: two parts may lower
            // to the same thing while standing for different amounts of
            // remaining pattern.
            key.push_str(&String::from_utf16_lossy(&part.source));
            if index + offset + 1 != parts.len() {
                key.push('/');
            }
        }
        let next = table.len() as u32;
        ids.push(*table.entry(key).or_insert(next));
    }
    ids
}

/// Runs a walk to completion, returning every result in order.
pub fn glob_sync<'a>(
    options: &'a WalkOptions,
    includes: &'a [CompiledPattern],
    excludes: &'a [CompiledPattern],
    exclude_flags: crate::parser::CompileFlags,
    filter: Option<&'a mut dyn ExcludeFilter>,
) -> Result<Vec<WalkEntry>, String> {
    let mut walk = Walk::new(options, includes, excludes, exclude_flags, filter)?;
    walk.run()?;
    Ok(walk.results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_paths() {
        println!("resolve(a, ../) = {:?}", resolve("/tmp/tree/t2/a", "../"));
        println!("resolve(a, ../x) = {:?}", resolve("/tmp/tree/t2/a", "../x"));
        println!("join(a, ..) = {:?}", join("/tmp/tree/t2/a", ".."));
        println!("normalize(../) = {:?}", normalize("../"));
        println!("resolve(a, .) = {:?}", resolve("/tmp/tree/t2/a", "."));
    }
    #[test]
    fn debug_walk() {
        use crate::matcher::CompiledPattern;
        use crate::parser::CompileFlags;
        use crate::walker::{glob_sync, WalkOptions};
        let flags = CompileFlags {
            windows: false,
            nocase: false,
            nocase_magic_only: true,
            dot: false,
            match_base: false,
        };
        for pat in ["*", "**/*"] {
            let compiled =
                CompiledPattern::from_pattern(&pat.encode_utf16().collect::<Vec<_>>(), flags)
                    .expect("compiles");
            let options = WalkOptions {
                cwd: "/tmp/tree/t1".into(),
                follow_symlinks: false,
                with_file_types: false,
                max_depth: None,
            };
            let out = glob_sync(&options, std::slice::from_ref(&compiled), &[], flags, None)
                .expect("walks");
            println!(
                "{pat} => {:?}",
                out.iter().map(|e| e.path.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn join_and_normalize_follow_the_path_module() {
        assert_eq!(join(".", "a"), "a");
        assert_eq!(join("a", "b"), "a/b");
        assert_eq!(join("a/", "b"), "a/b");
        assert_eq!(normalize("a//b/./c"), "a/b/c");
        assert_eq!(normalize("a/b/../c"), "a/c");
        assert_eq!(normalize(""), ".");
    }

    #[test]
    fn relative_produces_dot_dot_hops() {
        assert_eq!(relative("/a/b", "/a/b/c"), "c");
        assert_eq!(relative("/a/c", "/a/b"), "../b");
        assert_eq!(relative("/a", "/a"), "");
    }

    #[test]
    fn plain_depth_counts_segments() {
        assert_eq!(plain_depth("."), Some(0));
        assert_eq!(plain_depth("a"), Some(1));
        assert_eq!(plain_depth("a/b/c"), Some(3));
        assert_eq!(plain_depth("../a"), None);
    }

    #[test]
    fn outside_paths_are_detected() {
        assert!(is_outside_path(".."));
        assert!(is_outside_path("../a"));
        assert!(is_outside_path("/abs"));
        assert!(!is_outside_path("..a"));
        assert!(!is_outside_path("a/b"));
    }
}
