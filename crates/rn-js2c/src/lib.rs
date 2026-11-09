//! Node's `js2c` step, as Rust data.
//!
//! Node does not ship its `lib/**` JavaScript as separate files: `tools/js2c.cc`
//! reads every builtin, turns it into a static byte array in a generated
//! `node_javascript.cc`, and `BuiltinLoader` looks builtins up from a
//! `BuiltinSourceMap` keyed by id. rustnode reproduces the same step at build
//! time, in Rust, so the runtime never performs file I/O to load a builtin and
//! the embedded text is the frozen vendored copy.
//!
//! Both Node and rustnode end up with the same three facts per builtin, and this
//! crate is where rustnode keeps them:
//!
//! 1. the **id** — the string key of Node's `BuiltinSourceMap`, also what
//!    `lib/internals` passes to `require()`;
//! 2. the **source text** — byte-identical to `vendor/libnode-js/lib/**` and
//!    `vendor/libnode-js/deps/**`;
//! 3. the **kind** — determines how V8 compiles it and which parameters wrap it
//!    (`node::builtins::BuiltinSourceType`).
//!
//! On top of those it records whether a builtin is a **core** module or an
//! **internal** one, which is the split `lib/internal/bootstrap/realm.js`
//! derives from the id prefix to decide what `require('node:...')` may reach.
//!
//! # Matching `internalBinding('builtins')`
//!
//! In the pinned revision, `BuiltinLoader::CreatePerIsolateProperties`
//! (`src/node_builtins.cc`) exposes exactly this shape:
//!
//! | member | Node type | provided here by |
//! | --- | --- | --- |
//! | `config` | `config.gypi` JSON string | not this crate — no `config.gypi` is vendored |
//! | `builtinIds` | sorted id list | [`builtin_ids`] |
//! | `builtinCategories` | `{canBeRequired, cannotBeRequired}` | [`core_ids`] / [`internal_ids`] |
//! | `natives` | `{id: source}` | [`natives`] |
//! | `getCacheUsage`, `compileFunction`, `hasCachedBuiltins`, `setInternalLoaders`, `importBuiltinSourceTextModule` | functions | not data — `rn-bindings` installs them |
//!
//! There is no `internalBindingSources` member in Node 28; older releases had
//! one, and it was removed once internal binding sources stopped being shipped
//! to JS. Native *binding* namespaces are reached through `getInternalBinding`,
//! not through this object, so this crate deliberately does not invent one.
//!
//! `config` and `configs` are the two members with no source here. Neither is an
//! omission in this crate: `config` is `config.gypi`, which Node generates from
//! its build configuration and rustnode does not vendor, and `configs` is not a
//! binding property at all — `lib/internal/legacy/processbinding.js` destructures
//! it from this object and assigns it onto `natives`, so on a real `node` it is
//! `undefined`. Both need a build-configuration decision rather than a js2c one.
//!
//! # Why the source is not compressed
//!
//! V8 wants a `v8::String` of JavaScript source; every consumer of [`Builtin`]
//! hands the text straight to `ScriptCompiler`. A compressed blob would need a
//! decoder on the startup path for a payload whose pages are only touched for the
//! builtins actually compiled, so decompression would trade cheap demand paging
//! for CPU on every first require, and would make the embedded bytes unverifiable
//! against `LIBJS.sha256`. Plain `&'static str` also lets rustc deduplicate and
//! place the data in rodata with no custom linker work.
//!
//! # The two vendored trees
//!
//! Node's js2c is handed `lib/**` and an explicit `deps_files` list, and it
//! embeds both into one flat map. rustnode vendors the same two trees and merges
//! them the same way, so `require('internal/deps/undici/undici')` resolves out of
//! the same table as `require('fs')`.
//!
//! They stay separate everywhere a count is checked
//! ([`scheme::BUILTIN_FILE_COUNT`] for `lib/**`, [`scheme::DEPS_FILE_COUNT`] for
//! `deps/**`), because one combined total could stay constant while a file moved
//! from one tree to the other, and the freeze would report success for a tree
//! Node's js2c would no longer reproduce.

#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

pub mod generate;
pub mod scheme;
pub mod sha256;

pub use scheme::{BuiltinCategory, BuiltinKind};

/// One builtin: the unit Node's `BuiltinSource` describes.
///
/// The table lives in generated code; this type only gives it a name. Fields are
/// private so the id/kind pair cannot be edited after generation, and every
/// accessor borrows the embedded text rather than copying it.
#[derive(Debug)]
pub struct Builtin {
    id: &'static str,
    kind: BuiltinKind,
    category: BuiltinCategory,
    source: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/builtins.rs"));

impl Builtin {
    /// The id, exactly as `lib/**` passes it to `require()`.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// The source text, byte-identical to the vendored file.
    pub fn source(&self) -> &'static str {
        self.source
    }

    /// How V8 must compile this builtin.
    pub fn kind(&self) -> BuiltinKind {
        self.kind
    }

    /// Whether user code may reach this builtin without `--expose-internals`.
    pub fn category(&self) -> BuiltinCategory {
        self.category
    }

    /// Whether this is a core module (`true`) or an internal one.
    pub fn is_core(&self) -> bool {
        self.category == BuiltinCategory::Core
    }

    /// Parameter names V8 wraps the source in. Empty for ES modules.
    pub fn parameters(&self) -> &'static [&'static str] {
        self.kind.parameters()
    }

    /// Length of the source in bytes.
    pub fn source_len(&self) -> usize {
        self.source.len()
    }
}

/// Every builtin, ordered by id.
///
/// The order is the one Node's `std::map`-backed `BuiltinSourceMap` yields, and
/// it is the order `internalBinding('builtins').builtinIds` must present, so
/// callers should preserve it rather than re-sorting.
pub fn builtin_sources() -> &'static [Builtin] {
    &BUILTINS
}

/// The builtin with this id, or `None`.
///
/// One binary search over the sorted table; no allocation, no file I/O. This is
/// the counterpart of `BuiltinLoader::Exists` plus a map lookup.
pub fn builtin_by_id(id: &str) -> Option<&'static Builtin> {
    IDS.binary_search(&id).ok().map(|index| &BUILTINS[index])
}

/// The source text for `id`, or `None`.
pub fn source(id: &str) -> Option<&'static str> {
    builtin_by_id(id).map(Builtin::source)
}

/// Whether `id` names a builtin.
pub fn exists(id: &str) -> bool {
    IDS.binary_search(&id).is_ok()
}

/// All ids, ordered as Node orders them.
///
/// This is what `internalBinding('builtins').builtinIds` returns, and what
/// `lib/internal/bootstrap/realm.js` filters into its public and internal sets.
pub fn builtin_ids() -> &'static [&'static str] {
    &IDS
}

/// Ids of core modules, in table order.
pub fn core_ids() -> impl Iterator<Item = &'static str> {
    BUILTINS
        .iter()
        .filter(|builtin| builtin.is_core())
        .map(Builtin::id)
}

/// Ids of internal modules, in table order.
pub fn internal_ids() -> impl Iterator<Item = &'static str> {
    BUILTINS
        .iter()
        .filter(|builtin| builtin.category == BuiltinCategory::Internal)
        .map(Builtin::id)
}

/// `(id, source)` pairs for the legacy `natives` object.
///
/// `BuiltinLoader::GetNatives` builds a plain object mapping every id to its
/// source text; `lib/internal/legacy/processbinding.js` then exposes it as
/// `process.binding('natives')`. Iterating this in order reproduces that object.
pub fn natives() -> impl Iterator<Item = (&'static str, &'static str)> {
    BUILTINS.iter().map(|builtin| (builtin.id, builtin.source))
}

/// Number of embedded builtins.
pub fn builtin_count() -> usize {
    BUILTINS.len()
}

/// Total bytes of embedded source text.
pub fn source_bytes() -> usize {
    BUILTINS.iter().map(Builtin::source_len).sum()
}

/// One way the embedded table disagrees with `LIBJS.sha256`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestMismatch {
    /// The file is embedded but the manifest does not record it.
    Unlisted {
        /// Builtin id.
        id: &'static str,
    },
    /// The manifest records a file that is not embedded.
    Missing {
        /// js2c path from the manifest, for example `lib/fs.js`.
        js2c_path: String,
    },
    /// The embedded text hashes differently from the manifest.
    Content {
        /// Builtin id.
        id: &'static str,
        /// Digest recorded in the manifest.
        expected: String,
        /// Digest of the embedded text.
        actual: String,
    },
    /// A manifest line is not `<64 hex digits><two spaces><path>`.
    Malformed {
        /// Zero-based line number.
        line: usize,
    },
}

impl std::fmt::Display for ManifestMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlisted { id } => {
                write!(formatter, "`{id}` is embedded but absent from LIBJS.sha256")
            }
            Self::Missing { js2c_path } => {
                write!(formatter, "`{js2c_path}` is listed but not embedded")
            }
            Self::Content {
                id,
                expected,
                actual,
            } => write!(
                formatter,
                "`{id}` does not match LIBJS.sha256 (recorded {expected}, embedded {actual})"
            ),
            Self::Malformed { line } => {
                write!(formatter, "LIBJS.sha256 line {} is malformed", line + 1)
            }
        }
    }
}

/// Checks the embedded table against the contents of `vendor/libnode-js/LIBJS.sha256`.
///
/// This is the runtime-side half of the freeze: `build.rs` refuses to generate a
/// table from a drifted tree, and this reports the same fact for a tree that was
/// copied or modified after the crate was compiled. Both are needed because the
/// generator cannot see edits made after it ran, and the build error is not
/// available to a compat report.
///
/// The manifest covers both vendored trees, keyed by js2c path, so this walks the
/// whole embedded table rather than only `lib/`: a `deps/` builtin whose file was
/// removed or edited after the build is reported here like any other.
///
/// `manifest` is the file's text; passing it in keeps this free of file I/O so
/// it can also validate a manifest captured from a release.
pub fn verify_against_manifest(manifest: &str) -> Result<(), Vec<ManifestMismatch>> {
    let mut recorded: Vec<(String, String)> = Vec::new();
    let mut mismatches = Vec::new();

    for (line, text) in manifest.lines().enumerate() {
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        match text.split_once("  ") {
            Some((digest, path))
                if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                recorded.push((path.to_string(), digest.to_ascii_lowercase()));
            }
            _ => mismatches.push(ManifestMismatch::Malformed { line }),
        }
    }

    let recorded: BTreeMap<String, String> = recorded.into_iter().collect();

    for builtin in BUILTINS.iter() {
        let js2c_path = scheme::js2c_path_for(builtin.id);
        match recorded.get(&js2c_path) {
            None => mismatches.push(ManifestMismatch::Unlisted { id: builtin.id }),
            Some(expected) => {
                let actual = sha256::digest_hex(builtin.source.as_bytes());
                if &actual != expected {
                    mismatches.push(ManifestMismatch::Content {
                        id: builtin.id,
                        expected: expected.clone(),
                        actual,
                    });
                }
            }
        }
    }

    let embedded: BTreeSet<&str> = BUILTINS.iter().map(Builtin::id).collect();
    for js2c_path in recorded.keys() {
        let id = scheme::get_file_id(js2c_path);
        if !embedded.contains(id.as_str()) {
            mismatches.push(ManifestMismatch::Missing {
                js2c_path: js2c_path.clone(),
            });
        }
    }

    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches)
    }
}

/// SHA-256 over the ordered identity of every builtin.
///
/// Cheap identity for the whole table: two builds with the same digest expose
/// the same builtins, with the same text, the same compile treatment, and the
/// same core/internal classification. Tests pin it so an accidental id or
/// classification change cannot pass unnoticed, and `rn-compat` can report it
/// alongside a binding mismatch.
///
/// The category is included deliberately. `LIBJS.sha256` only sees file bytes, so
/// flipping a builtin from core to internal would keep every manifest check green
/// while changing what `require('node:...')` can reach; only a digest that covers
/// the classification can catch that.
pub fn table_digest() -> String {
    let mut hasher_input = String::with_capacity(source_bytes() + builtin_count() * 64);
    for builtin in BUILTINS.iter() {
        hasher_input.push_str(builtin.id);
        hasher_input.push('\u{0}');
        hasher_input.push_str(builtin.kind.as_str());
        hasher_input.push('\u{0}');
        hasher_input.push_str(builtin.category.as_str());
        hasher_input.push('\u{0}');
        hasher_input.push_str(&builtin.source_len().to_string());
        hasher_input.push('\u{0}');
        hasher_input.push_str(builtin.source);
        hasher_input.push('\n');
    }
    sha256::digest_hex(hasher_input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{BUILTIN_FILE_COUNT, DEPS_FILE_COUNT};

    /// Every builtin, because a manifest is checked across both vendored trees.
    const TOTAL_BUILTINS: usize = BUILTIN_FILE_COUNT + DEPS_FILE_COUNT;

    /// First few manifest lines for real builtins, so the positive case does not
    /// need the whole file. The js2c path comes from the same inverse rule the
    /// check uses, so the fixture cannot hide a wrong path mapping.
    fn manifest_prefix() -> String {
        let mut out = String::new();
        for builtin in BUILTINS.iter().take(3) {
            let digest = sha256::digest_hex(builtin.source.as_bytes());
            out.push_str(&format!(
                "{digest}  {}\n",
                scheme::js2c_path_for(builtin.id)
            ));
        }
        out
    }

    #[test]
    fn manifest_check_reports_unlisted_builtins() {
        // A manifest covering only the first three builtins: every other one must
        // be reported by name, not just counted.
        let mismatches = verify_against_manifest(&manifest_prefix()).expect_err("must not pass");
        assert_eq!(mismatches.len(), TOTAL_BUILTINS - 3);
        assert!(
            mismatches
                .iter()
                .all(|m| matches!(m, ManifestMismatch::Unlisted { .. })),
            "unexpected mismatch kinds: {mismatches:?}"
        );
        assert!(
            mismatches
                .iter()
                .any(|m| matches!(m, ManifestMismatch::Unlisted { id: "zlib" })),
            "the last builtin must be reported: {mismatches:?}"
        );
        // The deps builtin is the one entry a lib-only walk could never produce,
        // so requiring it by name is what makes the check cover both trees.
        assert!(
            mismatches.iter().any(|m| matches!(
                m,
                ManifestMismatch::Unlisted {
                    id: "internal/deps/undici/undici"
                }
            )),
            "the deps builtin must be reported too: {mismatches:?}"
        );
    }

    #[test]
    fn manifest_check_reports_edited_content() {
        // Reuse a real line but flip one hex digit: the size, path and entry
        // count all still match, so only a per-file digest can catch this.
        let mut manifest = String::new();
        for builtin in BUILTINS.iter() {
            let digest = sha256::digest_hex(builtin.source.as_bytes());
            let digest = if builtin.id == "fs" {
                // Flip the first nibble to a different hex digit.
                let first = if digest.starts_with('a') { 'b' } else { 'a' };
                format!("{first}{}", &digest[1..])
            } else {
                digest
            };
            manifest.push_str(&format!(
                "{digest}  {}\n",
                scheme::js2c_path_for(builtin.id)
            ));
        }

        let mismatches = verify_against_manifest(&manifest).expect_err("must not pass");
        assert_eq!(mismatches.len(), 1, "only `fs` was altered: {mismatches:?}");
        assert!(matches!(
            mismatches[0],
            ManifestMismatch::Content { id: "fs", .. }
        ));
        assert!(
            mismatches[0].to_string().contains("fs"),
            "the message must name the file: {}",
            mismatches[0]
        );
    }

    #[test]
    fn manifest_check_reports_stale_entries() {
        // A manifest that still lists a file the vendored tree no longer has:
        // this is what a partial re-pin looks like.
        let mut manifest = String::new();
        for builtin in BUILTINS.iter() {
            let digest = sha256::digest_hex(builtin.source.as_bytes());
            manifest.push_str(&format!(
                "{digest}  {}\n",
                scheme::js2c_path_for(builtin.id)
            ));
        }
        manifest.push_str(&format!("{}  lib/removed_builtin.js\n", "0".repeat(64)));

        let mismatches = verify_against_manifest(&manifest).expect_err("must not pass");
        assert_eq!(mismatches.len(), 1, "{mismatches:?}");
        assert!(matches!(
            &mismatches[0],
            ManifestMismatch::Missing { js2c_path } if js2c_path == "lib/removed_builtin.js"
        ));
    }

    #[test]
    fn manifest_check_rejects_malformed_lines() {
        let mismatches = verify_against_manifest("not a manifest line\n").expect_err("must fail");
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, ManifestMismatch::Malformed { line: 0 })));

        // A short digest and a single-space separator are both malformed.
        let mismatches = verify_against_manifest("abc  lib/fs.js\n").expect_err("must fail");
        assert!(matches!(
            mismatches[0],
            ManifestMismatch::Malformed { line: 0 }
        ));

        let full_len_but_not_hex = "z".repeat(64);
        let line = format!("{full_len_but_not_hex}  lib/fs.js\n");
        let mismatches = verify_against_manifest(&line).expect_err("must fail");
        assert!(matches!(
            mismatches[0],
            ManifestMismatch::Malformed { line: 0 }
        ));

        // The single-space form is NOT accepted: `sha256sum` writes two spaces,
        // and splitting on one would silently accept a path with a leading space.
        let digest = sha256::digest_hex(BUILTINS[0].source.as_bytes());
        let first_path = scheme::js2c_path_for(BUILTINS[0].id);
        let line = format!("{digest} {first_path}\n");
        let mismatches = verify_against_manifest(&line).expect_err("must fail");
        assert!(matches!(
            mismatches[0],
            ManifestMismatch::Malformed { line: 0 }
        ));
    }

    #[test]
    fn manifest_check_accepts_a_complete_manifest() {
        let mut manifest = String::new();
        for builtin in BUILTINS.iter() {
            let digest = sha256::digest_hex(builtin.source.as_bytes());
            manifest.push_str(&format!(
                "{digest}  {}\n",
                scheme::js2c_path_for(builtin.id)
            ));
        }
        // Blank lines are tolerated, as the real file may end with one.
        manifest.push('\n');
        assert_eq!(verify_against_manifest(&manifest), Ok(()));
    }

    #[test]
    fn table_digest_covers_every_entry() {
        // Two calls agree, and dropping any entry from the hashed input changes
        // the digest, which proves every entry contributes.
        let full = table_digest();
        assert_eq!(full, table_digest());
        assert_eq!(full.len(), 64);

        let mut truncated = String::new();
        for builtin in BUILTINS.iter().take(BUILTINS.len() - 1) {
            truncated.push_str(builtin.id);
            truncated.push('\u{0}');
            truncated.push_str(builtin.kind.as_str());
            truncated.push('\u{0}');
            truncated.push_str(builtin.category.as_str());
            truncated.push('\u{0}');
            truncated.push_str(&builtin.source_len().to_string());
            truncated.push('\u{0}');
            truncated.push_str(builtin.source);
            truncated.push('\n');
        }
        assert_ne!(full, sha256::digest_hex(truncated.as_bytes()));
    }

    #[test]
    fn table_digest_separates_kind_and_category() {
        // The two facts a re-pin can change without touching file bytes. Hash a
        // one-entry table under each variant and require distinct digests, which
        // is what makes TABLE_DIGEST able to catch a misclassification that
        // LIBJS.sha256 cannot see.
        fn hash(id: &str, kind: BuiltinKind, category: BuiltinCategory) -> String {
            let input = format!(
                "{id}\u{0}{}\u{0}{}\u{0}1\u{0}x\n",
                kind.as_str(),
                category.as_str()
            );
            sha256::digest_hex(input.as_bytes())
        }

        let baseline = hash("fs", BuiltinKind::Function, BuiltinCategory::Core);
        assert_ne!(
            baseline,
            hash("fs", BuiltinKind::Function, BuiltinCategory::Internal)
        );
        assert_ne!(
            baseline,
            hash("fs", BuiltinKind::MainScript, BuiltinCategory::Core)
        );
        assert_ne!(
            baseline,
            hash("internal/fs", BuiltinKind::Function, BuiltinCategory::Core)
        );
    }
}
