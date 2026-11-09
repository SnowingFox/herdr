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
pub const BUILTIN_FILE_COUNT: usize = 435;

/// Node's js2c root-relative location of the builtin tree.
pub const VENDOR_LIB_RELATIVE: &str = "../../vendor/libnode-js/lib";

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

/// One file found in the vendored tree, before its source is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// `BuiltinLoader` id, for example `internal/fs/promises`.
    pub id: String,
    /// Path exactly as Node's js2c receives it, for example
    /// `lib/internal/fs/promises.js`. Type classification reads this, because
    /// Node keys `.mjs` detection off the filename rather than the id.
    pub js2c_path: String,
    /// Path on disk.
    pub path: PathBuf,
    /// Path relative to the root of `lib/` (`internal/fs/promises.js`). The
    /// generator joins this with `VENDOR_LIB_RELATIVE` so the emitted
    /// `include_str!` is anchored at the crate rather than at this machine.
    pub lib_relative: String,
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

/// Walks `dir` and returns every builtin, ordered by id.
///
/// Ordering is `BTreeMap` ordering by id, which is what Node gets for free from
/// `using BuiltinSourceMap = std::map<std::string, BuiltinSource>`. It defines
/// the order of `internalBinding('builtins').builtinIds`, so it is part of the
/// contract rather than a cosmetic choice.
///
/// Fails on a duplicate id, a non-UTF-8 name, or an `.mjs` file Node does not
/// exclude: each means the vendored tree changed shape and the generator would
/// otherwise emit something Node would not.
pub fn collect(dir: &Path) -> Result<Vec<SourceFile>, String> {
    let mut by_id: BTreeMap<String, SourceFile> = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];

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
                if format!("lib/{relative}") == EXCLUDED_MJS {
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

            // js2c always sees the tree rooted at `lib/`, so rebuild that prefix
            // instead of handing GetFileId a root-relative path.
            let js2c_path = format!("lib/{relative}");
            let id = get_file_id(&js2c_path);
            let source = SourceFile {
                id: id.clone(),
                js2c_path,
                path,
                lib_relative: relative,
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
}
