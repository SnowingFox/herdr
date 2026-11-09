//! The id and source-type scheme Node's `js2c` applies to `lib/**`.
//!
//! This module is compiled twice: into the library, and into `build.rs` through
//! `#[path]`. Keeping one copy is deliberate — the generator and the tests must
//! never be able to disagree about how an id is derived.
//!
//! Every rule here is transcribed from the Node revision pinned in
//! `tools/node-pin.toml` (commit `f344e7f552e`):
//!
//! | Rule | Node source |
//! | --- | --- |
//! | id derivation | `tools/js2c.cc::GetFileId` |
//! | source-type classification | `src/builtin_info.cc::GetBuiltinSourceType` |
//! | compile parameters per type | `src/builtin_info.h::BuiltinInfo::parameter_map` |
//! | core vs internal split | `lib/internal/bootstrap/realm.js` |
//!
//! Node 28 deleted the numeric `node_builtin_ids.h` enum that older releases
//! generated. The authoritative id is the string key of the `BuiltinSourceMap`
//! (`src/node_builtins.h`), which is also what the JavaScript layer receives as
//! `internalBinding('builtins').builtinIds`. So a builtin id here is a string,
//! not an integer, and `ids()` ordering is the `std::map` order Node uses.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Number of `.js` builtin files Node 28 ships under `lib/**`.
///
/// Matches `[counts] builtin_files` in `tools/node-pin.toml` and the line count
/// of `vendor/libnode-js/LIBJS.sha256`. Both the generator and the tests treat a
/// mismatch as a build failure, so a re-pin cannot land half-wired.
///
/// This is the count for `lib/**` alone and stays that number: the `deps/` tree
/// Node's js2c also embeds is a separate set with its own count
/// ([`DEPS_FILE_COUNT`]), so a file landing in one tree can never be explained
/// away by the other one's total.
pub const BUILTIN_FILE_COUNT: usize = 435;

/// Number of `.js` builtin files vendored from `deps/**`, which is exactly the
/// one self-contained bundle `lib/**` requires as
/// `internal/deps/undici/undici`.
///
/// Node's `node.gyp` lists `deps_files` explicitly instead of globbing that
/// tree, because undici's own source tree is thousands of files and only the
/// esbuild output is a builtin. rustnode vendors the same single file for the
/// same reason, so this count is 1 rather than "however many files are there":
/// it is a check, and a second `deps/` file appearing must be a deliberate
/// change to this constant, `tools/node-pin.toml`, `LIBJS.sha256`, and the
/// build error that names it.
pub const DEPS_FILE_COUNT: usize = 1;

/// Node's js2c root-relative location of the builtin tree.
pub const VENDOR_LIB_RELATIVE: &str = "../../vendor/libnode-js/lib";

/// Node's js2c root-relative location of the vendored `deps/**` builtin tree.
///
/// One directory level below the vendor root, so a file here is checked against
/// the same `LIBJS.sha256` as `lib/**` using its `deps/...` js2c path.
pub const VENDOR_DEPS_RELATIVE: &str = "../../vendor/libnode-js/deps";

/// Node's js2c root-relative location of the freeze manifest.
pub const VENDOR_SHA256_RELATIVE: &str = "../../vendor/libnode-js/LIBJS.sha256";

/// The one `.mjs` file Node's js2c drops, by exact path.
///
/// `tools/js2c.cc` searches for `.mjs` files and then erases this entry before
/// generating. It is eslint configuration, not a builtin, and it is present in
/// the vendored tree, so it must be skipped here too rather than treated as an
/// unsupported file.
const EXCLUDED_MJS: &str = "lib/eslint.config_partial.mjs";

/// How V8 compiles a builtin and which parameters wrap its source.
///
/// Mirrors `node::builtins::BuiltinSourceType`. The variant order and the
/// `as_str` spellings match `src/builtin_info.cc` so both can be read side by
/// side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltinKind {
    /// `internal/bootstrap/realm`: creates the loaders every other builtin uses.
    BootstrapRealm,
    /// `internal/bootstrap/*`: one per realm, after `realm`.
    BootstrapScript,
    /// `internal/per_context/*`: compiles into each context's primordials.
    PerContextScript,
    /// `internal/main/*`: the entry point for a single `node` invocation.
    MainScript,
    /// Everything else: an ordinary CommonJS function.
    Function,
    /// ESM source, compiled with `ScriptCompiler::CompileModule`.
    SourceTextModule,
}

impl BuiltinKind {
    /// Node's C++ enumerator name, for cross-referencing against `src/`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapRealm => "kBootstrapRealm",
            Self::BootstrapScript => "kBootstrapScript",
            Self::PerContextScript => "kPerContextScript",
            Self::MainScript => "kMainScript",
            Self::Function => "kFunction",
            Self::SourceTextModule => "kSourceTextModule",
        }
    }

    /// Parameter names V8 wraps the source in when compiling this kind.
    ///
    /// This is `BuiltinInfo::parameter_map`, verbatim. Getting it wrong is not a
    /// crash: the builtin compiles and then fails at run time with a
    /// `ReferenceError` for a global that should have been an argument.
    pub const fn parameters(self) -> &'static [&'static str] {
        match self {
            Self::BootstrapRealm => &[
                "process",
                "getLinkedBinding",
                "getInternalBinding",
                "primordials",
            ],
            Self::BootstrapScript | Self::MainScript => {
                &["process", "require", "internalBinding", "primordials"]
            }
            Self::PerContextScript => &[
                "exports",
                "primordials",
                "privateSymbols",
                "perIsolateSymbols",
            ],
            Self::Function => &[
                "exports",
                "require",
                "module",
                "process",
                "internalBinding",
                "primordials",
            ],
            // Compiled as a module: no wrapper parameters exist.
            Self::SourceTextModule => &[],
        }
    }

    /// Whether V8 compiles this as an ES module instead of a function.
    pub const fn is_module(self) -> bool {
        matches!(self, Self::SourceTextModule)
    }
}

/// Whether user code may reach a builtin.
///
/// `lib/internal/bootstrap/realm.js` derives exactly this split from the id
/// prefix: `internalBuiltinIds` is every id starting with `internal/` except
/// `internal/bootstrap/realm` itself, and `publicBuiltinIds` is everything else.
/// Runtime option gating (`--experimental-*`) is applied on top of this in
/// JavaScript and is therefore not data this crate can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltinCategory {
    /// Reachable as `require(id)` / `node:<id>` without `--expose-internals`.
    Core,
    /// Reachable only from Node's own bootstrap or with `--expose-internals`.
    Internal,
}

impl BuiltinCategory {
    /// Lowercase spelling, for diagnostics and digests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Internal => "internal",
        }
    }
}

/// Which vendored tree a builtin came from.
///
/// Node's js2c is given `lib/**` as a directory plus an explicit list of
/// `deps/**` files, and their js2c paths differ in prefix. rustnode vendors the
/// same two trees as two directories, so a builtin has to remember which one it
/// was read from: the freeze manifest path, the `include_str!` directory, and
/// the js2c path all follow from it.
///
/// Keeping the tree on the record rather than re-deriving it from the path means
/// the generator cannot silently emit an `include_str!` pointing at the wrong
/// directory for a file whose id happens to look like the other tree's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltinTree {
    /// `vendor/libnode-js/lib/**`, js2c paths `lib/...`.
    Lib,
    /// `vendor/libnode-js/deps/**`, js2c paths `deps/...`.
    Deps,
}

impl BuiltinTree {
    /// The js2c path prefix this tree's files carry.
    pub const fn js2c_prefix(self) -> &'static str {
        match self {
            Self::Lib => "lib/",
            Self::Deps => "deps/",
        }
    }

    /// The tree's location relative to `crates/rn-js2c`.
    pub const fn vendor_relative(self) -> &'static str {
        match self {
            Self::Lib => VENDOR_LIB_RELATIVE,
            Self::Deps => VENDOR_DEPS_RELATIVE,
        }
    }
}

/// One file found in the vendored tree, before its source is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// `BuiltinLoader` id, for example `internal/fs/promises`.
    pub id: String,
    /// Path exactly as Node's js2c receives it, for example
    /// `lib/internal/fs/promises.js` or `deps/undici/undici.js`. Type
    /// classification reads this, because Node keys `.mjs` detection off the
    /// filename rather than the id.
    pub js2c_path: String,
    /// Path on disk.
    pub path: PathBuf,
    /// Path relative to the root of the tree it was found in
    /// (`internal/fs/promises.js`, or `undici/undici.js` for `deps/`). The
    /// generator joins this with [`SourceFile::tree`]'s vendored directory so
    /// the emitted `include_str!` is anchored at the crate rather than at this
    /// machine.
    pub tree_relative: String,
    /// Which vendored tree the file came from.
    pub tree: BuiltinTree,
}

/// `tools/js2c.cc::GetFileId`.
///
/// ```text
/// lib/assert.js                          -> assert
/// lib/internal/fs/promises.js            -> internal/fs/promises
/// deps/acorn/acorn/dist/acorn.js         -> internal/deps/acorn/acorn/dist/acorn
/// deps/v8/tools/tickprocessor-driver.mjs -> internal/deps/v8/tools/tickprocessor-driver
/// ```
///
/// The `.js`/`.mjs` suffix is stripped first, then a `deps/` prefix is rewritten
/// to `internal/deps/` and a `lib/` prefix is dropped. Nothing else is
/// normalised: case is preserved (`internal/readline/emitKeypressEvents`) and a
/// dot that is not the file suffix survives, because the id is the string the
/// JavaScript layer passes to `require()` and must match what `lib/**` writes.
pub fn get_file_id(filename: &str) -> String {
    let stripped = filename
        .strip_suffix(".mjs")
        .or_else(|| filename.strip_suffix(".js"))
        .unwrap_or(filename);

    if let Some(rest) = stripped.strip_prefix("deps/") {
        format!("internal/deps/{rest}")
    } else if let Some(rest) = stripped.strip_prefix("lib/") {
        rest.to_string()
    } else {
        stripped.to_string()
    }
}

/// The inverse of [`get_file_id`]: the js2c path a builtin id was derived from.
///
/// ```text
/// assert                                 -> lib/assert.js
/// internal/fs/promises                   -> lib/internal/fs/promises.js
/// internal/deps/acorn/acorn/dist/acorn   -> deps/acorn/acorn/dist/acorn.js
/// internal/deps/undici/undici            -> deps/undici/undici.js
/// ```
///
/// This exists so a builtin's manifest key can be recomputed from the embedded
/// table alone. `internal/deps/` is the one id prefix that does not map back
/// under `lib/`: it is written by `get_file_id` for a file that lives in
/// `deps/`, and reading it back as `lib/internal/deps/...` would look up a path
/// no vendored tree holds.
///
/// Only ids produced by `get_file_id` are meaningful here, and `.js` is assumed
/// because every builtin this crate embeds comes from a `.js` file (Node's one
/// `.mjs` builtin is excluded by js2c itself).
pub fn js2c_path_for(id: &str) -> String {
    match id.strip_prefix("internal/deps/") {
        Some(rest) => format!("deps/{rest}.js"),
        None => format!("lib/{id}.js"),
    }
}

/// `src/builtin_info.cc::GetBuiltinSourceType`, in Node's evaluation order.
///
/// `js2c_path` is the path as js2c receives it, because the `.mjs` test is a
/// filename test, not an id test.
pub fn kind_for(id: &str, js2c_path: &str) -> BuiltinKind {
    if js2c_path.ends_with(".mjs") {
        return BuiltinKind::SourceTextModule;
    }
    if id.starts_with("internal/bootstrap/realm") {
        return BuiltinKind::BootstrapRealm;
    }
    if id.starts_with("internal/bootstrap/") {
        return BuiltinKind::BootstrapScript;
    }
    if id.starts_with("internal/per_context/") {
        return BuiltinKind::PerContextScript;
    }
    if id.starts_with("internal/main/") {
        return BuiltinKind::MainScript;
    }
    if id.starts_with("internal/deps/v8/tools/") {
        return BuiltinKind::SourceTextModule;
    }
    BuiltinKind::Function
}

/// Core or internal, by id prefix, as `internal/bootstrap/realm.js` splits them.
pub fn category_for(id: &str) -> BuiltinCategory {
    if id.starts_with("internal/") {
        BuiltinCategory::Internal
    } else {
        BuiltinCategory::Core
    }
}

/// Walks one vendored tree and returns every builtin, ordered by id.
///
/// Ordering is `BTreeMap` ordering by id, which is what Node gets for free from
/// `using BuiltinSourceMap = std::map<std::string, BuiltinSource>`. It defines
/// the order of `internalBinding('builtins').builtinIds`, so it is part of the
/// contract rather than a cosmetic choice.
///
/// Fails on a duplicate id, a non-UTF-8 name, or an `.mjs` file Node does not
/// exclude: each means the vendored tree changed shape and the generator would
/// otherwise emit something Node would not.
///
/// `tree` says which of the two vendored trees `dir` is the root of, because the
/// js2c path prefix and the `include_str!` directory both follow from it.
pub fn collect(dir: &Path, tree: BuiltinTree) -> Result<Vec<SourceFile>, String> {
    let mut by_id: BTreeMap<String, SourceFile> = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    let prefix = tree.js2c_prefix();

    while let Some(current) = pending.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|error| format!("cannot read directory {}: {error}", current.display()))?;

        for entry in entries {
            let entry = entry
                .map_err(|error| format!("cannot read entry in {}: {error}", current.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;

            if file_type.is_dir() {
                pending.push(path);
                continue;
            }

            let relative = path
                .strip_prefix(dir)
                .map_err(|error| {
                    format!("{} is outside {}: {error}", path.display(), dir.display())
                })?
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 builtin path: {}", path.display()))?
                .replace('\\', "/");

            if relative.ends_with(".mjs") {
                if format!("{prefix}{relative}") == EXCLUDED_MJS {
                    continue;
                }
                return Err(format!(
                    "{} is an unexcluded ES module; Node's js2c would embed it as a \
                     SourceTextModule and rn-js2c does not cover that yet",
                    path.display()
                ));
            }
            if !relative.ends_with(".js") {
                continue;
            }

            // js2c sees a path rooted at `lib/` or `deps/` depending on which
            // tree the file came from, so rebuild that prefix instead of handing
            // GetFileId a root-relative path.
            let js2c_path = format!("{prefix}{relative}");
            let id = get_file_id(&js2c_path);
            let source = SourceFile {
                id: id.clone(),
                js2c_path,
                path,
                tree_relative: relative,
                tree,
            };
            if let Some(previous) = by_id.insert(id.clone(), source) {
                return Err(format!(
                    "builtin id `{id}` is produced twice: {} and {}",
                    previous.path.display(),
                    by_id
                        .get(&id)
                        .map(|s| s.path.display().to_string())
                        .unwrap_or_default()
                ));
            }
        }
    }

    Ok(by_id.into_values().collect())
}

/// Walks both vendored trees and returns every builtin, ordered by id.
///
/// Node's js2c embeds `lib/**` and the `deps_files` list as one flat
/// `BuiltinSourceMap`, so the two trees are merged here into a single ordered
/// table rather than kept apart. The merge is an id collision check, not a
/// concatenation: `deps/x/y.js` derives `internal/deps/x/y`, and a `lib/` file
/// that ever produced the same id would be two files Node cannot distinguish.
///
/// Each tree keeps its own expected count. A single combined total would let one
/// tree gain a file while the other lost one and still balance, which is exactly
/// the drift the counts exist to catch.
pub fn collect_all(
    lib_dir: &Path,
    deps_dir: &Path,
    lib_count: usize,
    deps_count: usize,
) -> Result<Vec<SourceFile>, String> {
    let lib = collect(lib_dir, BuiltinTree::Lib)?;
    if lib.len() != lib_count {
        return Err(format!(
            "expected {lib_count} builtin files under {}, found {}",
            lib_dir.display(),
            lib.len()
        ));
    }

    let deps = collect(deps_dir, BuiltinTree::Deps)?;
    if deps.len() != deps_count {
        return Err(format!(
            "expected {deps_count} builtin files under {}, found {}",
            deps_dir.display(),
            deps.len()
        ));
    }

    let mut by_id: BTreeMap<String, SourceFile> = BTreeMap::new();
    for file in lib.into_iter().chain(deps) {
        let id = file.id.clone();
        if let Some(previous) = by_id.insert(id.clone(), file) {
            let current = by_id
                .get(&id)
                .map(|f| f.js2c_path.clone())
                .unwrap_or_default();
            return Err(format!(
                "builtin id `{id}` is produced twice across the vendored trees: \
                 {} and {current}",
                previous.js2c_path
            ));
        }
    }

    Ok(by_id.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_id_matches_node_js2c() {
        // Straight from the comment above GetFileId in tools/js2c.cc.
        assert_eq!(get_file_id("lib/assert.js"), "assert");
        assert_eq!(get_file_id("lib/internal/url.js"), "internal/url");
        assert_eq!(
            get_file_id("deps/acorn/acorn/dist/acorn.js"),
            "internal/deps/acorn/acorn/dist/acorn"
        );
        assert_eq!(
            get_file_id("deps/v8/tools/tickprocessor-driver.mjs"),
            "internal/deps/v8/tools/tickprocessor-driver"
        );
    }

    #[test]
    fn file_id_preserves_case_and_strips_only_the_suffix() {
        assert_eq!(
            get_file_id("lib/internal/readline/emitKeypressEvents.js"),
            "internal/readline/emitKeypressEvents"
        );
        // A dot before the suffix is not a suffix and must survive.
        assert_eq!(
            get_file_id("lib/internal/errors/err.js"),
            "internal/errors/err"
        );
        // Stripping `.js` from a name that also contains `.mjs`.
        assert_eq!(get_file_id("lib/x.mjs.js"), "x.mjs");
        // No known prefix: the path is used as-is.
        assert_eq!(get_file_id("elsewhere/y.js"), "elsewhere/y");
    }

    #[test]
    fn kind_matches_node_builtin_info() {
        assert_eq!(
            kind_for(
                "internal/bootstrap/realm",
                "lib/internal/bootstrap/realm.js"
            ),
            BuiltinKind::BootstrapRealm
        );
        // Node's first check is `starts_with("internal/bootstrap/realm")`, a
        // prefix rather than an equality, so a hypothetical sibling id also
        // lands in the realm bucket. Faithful on purpose.
        assert_eq!(
            kind_for(
                "internal/bootstrap/realm_extra",
                "lib/internal/bootstrap/realm_extra.js"
            ),
            BuiltinKind::BootstrapRealm
        );
        assert_eq!(
            kind_for("internal/bootstrap/node", "lib/internal/bootstrap/node.js"),
            BuiltinKind::BootstrapScript
        );
        assert_eq!(
            kind_for(
                "internal/per_context/primordials",
                "lib/internal/per_context/primordials.js"
            ),
            BuiltinKind::PerContextScript
        );
        assert_eq!(
            kind_for(
                "internal/main/eval_string",
                "lib/internal/main/eval_string.js"
            ),
            BuiltinKind::MainScript
        );
        assert_eq!(
            kind_for("internal/deps/v8/tools/foo", "deps/v8/tools/foo.mjs"),
            BuiltinKind::SourceTextModule
        );
        assert_eq!(
            kind_for("internal/util", "lib/internal/util.js"),
            BuiltinKind::Function
        );
        assert_eq!(kind_for("fs", "lib/fs.js"), BuiltinKind::Function);
    }

    #[test]
    fn kind_parameters_match_builtin_info_header() {
        assert_eq!(
            BuiltinKind::BootstrapRealm.parameters(),
            [
                "process",
                "getLinkedBinding",
                "getInternalBinding",
                "primordials"
            ]
        );
        assert_eq!(
            BuiltinKind::BootstrapScript.parameters(),
            ["process", "require", "internalBinding", "primordials"]
        );
        assert_eq!(
            BuiltinKind::MainScript.parameters(),
            BuiltinKind::BootstrapScript.parameters()
        );
        assert_eq!(
            BuiltinKind::PerContextScript.parameters(),
            [
                "exports",
                "primordials",
                "privateSymbols",
                "perIsolateSymbols"
            ]
        );
        assert_eq!(
            BuiltinKind::Function.parameters(),
            [
                "exports",
                "require",
                "module",
                "process",
                "internalBinding",
                "primordials"
            ]
        );
        assert!(BuiltinKind::SourceTextModule.parameters().is_empty());
        assert!(BuiltinKind::SourceTextModule.is_module());
        assert!(!BuiltinKind::Function.is_module());
    }

    #[test]
    fn category_follows_the_internal_prefix() {
        assert_eq!(category_for("fs"), BuiltinCategory::Core);
        assert_eq!(
            category_for("internal/fs/promises"),
            BuiltinCategory::Internal
        );
        // The realm bootstrap is the one internal id realm.js keeps out of its
        // own internal list; it is still an internal binding.
        assert_eq!(
            category_for("internal/bootstrap/realm"),
            BuiltinCategory::Internal
        );
    }

    /// Builds a throwaway directory holding `files`, so the tree walkers can be
    /// exercised without touching the real vendored trees.
    fn scratch_tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rn-js2c-tree-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (relative, contents) in files {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create scratch subdir");
            }
            fs::write(&path, contents).expect("write scratch file");
        }
        fs::create_dir_all(&root).expect("create scratch root");
        root
    }

    #[test]
    fn the_deps_tree_derives_internal_deps_ids() {
        // The whole reason the `deps/` tree is walked at all: js2c rewrites a
        // `deps/` prefix to `internal/deps/`, and `lib/**` requires exactly that
        // id. Getting this wrong would embed the file under an id nothing asks
        // for, which looks like success until the first require throws.
        let root = scratch_tree("deps", &[("undici/undici.js", "module.exports = {};")]);
        let files = collect(&root, BuiltinTree::Deps).expect("collect deps tree");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].id, "internal/deps/undici/undici");
        assert_eq!(files[0].js2c_path, "deps/undici/undici.js");
        assert_eq!(files[0].tree_relative, "undici/undici.js");
        assert_eq!(files[0].tree, BuiltinTree::Deps);
        // A `deps/` builtin is reachable only from Node's own code, so it must
        // classify as internal. That is what keeps it out of the core id list
        // `realm.js` hands user land.
        assert_eq!(category_for(&files[0].id), BuiltinCategory::Internal);
        assert_eq!(
            kind_for(&files[0].id, &files[0].js2c_path),
            BuiltinKind::Function,
            "the undici bundle is an ordinary CommonJS function, not a module"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_lib_file_keeps_its_lib_relative_path() {
        // The two trees differ only in prefix and root, so pin both halves: a
        // lib file must not pick up the deps root, and vice versa.
        let root = scratch_tree("libtree", &[("internal/fs/promises.js", "exports.x = 1;")]);
        let files = collect(&root, BuiltinTree::Lib).expect("collect lib tree");
        assert_eq!(files[0].id, "internal/fs/promises");
        assert_eq!(files[0].js2c_path, "lib/internal/fs/promises.js");
        assert_eq!(files[0].tree_relative, "internal/fs/promises.js");
        assert_eq!(files[0].tree, BuiltinTree::Lib);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_all_merges_both_trees_in_id_order() {
        let lib = scratch_tree(
            "merge-lib",
            &[("fs.js", "a"), ("internal/util.js", "b"), ("zlib.js", "c")],
        );
        let deps = scratch_tree(
            "merge-deps",
            &[
                ("undici/undici.js", "d"),
                ("acorn/acorn/dist/acorn.js", "e"),
            ],
        );

        let files = collect_all(&lib, &deps, 3, 2).expect("both trees collect");
        assert_eq!(
            files.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            [
                "fs",
                "internal/deps/acorn/acorn/dist/acorn",
                "internal/deps/undici/undici",
                "internal/util",
                "zlib",
            ]
        );
        // Ordering is by id, not by tree, which is what Node's std::map does.
        let _ = fs::remove_dir_all(&lib);
        let _ = fs::remove_dir_all(&deps);
    }

    #[test]
    fn each_tree_count_is_checked_independently() {
        let lib = scratch_tree("count-lib", &[("fs.js", "a")]);
        let deps = scratch_tree("count-deps", &[("undici/undici.js", "b")]);

        let error = collect_all(&lib, &deps, 2, 1).expect_err("a wrong lib count must fail");
        assert!(error.contains("expected 2 builtin files"), "{error}");

        let error = collect_all(&lib, &deps, 1, 2).expect_err("a wrong deps count must fail");
        assert!(error.contains("expected 2 builtin files"), "{error}");

        // The point of separate counts: a tree that gains a file while the other
        // loses one still fails, even though the total is unchanged.
        fs::write(deps.join("undici/undici.js"), "b").expect("keep deps file");
        let only_deps = scratch_tree("count-deps2", &[("undici/undici.js", "b")]);
        let error = collect_all(&lib, &only_deps, 1, 2).expect_err("deps count is separate");
        assert!(error.contains("expected 2 builtin files"), "{error}");

        let _ = fs::remove_dir_all(&lib);
        let _ = fs::remove_dir_all(&deps);
        let _ = fs::remove_dir_all(&only_deps);
    }

    #[test]
    fn an_id_collision_across_trees_is_reported_by_path() {
        // A `lib/internal/deps/undici/undici.js` would derive the same id as the
        // vendored bundle. Two files, one id: Node has no way to pick.
        let lib = scratch_tree("collide-lib", &[("internal/deps/undici/undici.js", "a")]);
        let deps = scratch_tree("collide-deps", &[("undici/undici.js", "b")]);

        let error = collect_all(&lib, &deps, 1, 1).expect_err("a cross-tree collision must fail");
        assert!(error.contains("internal/deps/undici/undici"), "{error}");
        assert!(error.contains("twice"), "{error}");

        let _ = fs::remove_dir_all(&lib);
        let _ = fs::remove_dir_all(&deps);
    }

    #[test]
    fn the_one_excluded_es_module_is_only_excluded_from_the_lib_tree() {
        // `lib/eslint.config_partial.mjs` is a Node exclusion by exact js2c path.
        // A same-named file in the deps tree is a different js2c path and must
        // stay loud rather than silently inherit that exemption.
        let deps = scratch_tree("mjs-deps", &[("eslint.config_partial.mjs", "export {};")]);
        let error = collect(&deps, BuiltinTree::Deps)
            .expect_err("the exclusion is a full js2c path, not a basename");
        assert!(error.contains("eslint.config_partial.mjs"), "{error}");
        let _ = fs::remove_dir_all(&deps);
    }
}
