//! Behavioural tests for the embedded builtin table.
//!
//! These compile against the real generated table, so they exercise the same
//! data the runtime will use at startup. Nothing here mocks the generator: the
//! point is to catch a vendored tree, a `LIBJS.sha256`, or an id rule drifting
//! out of agreement with what is embedded.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use rn_js2c::{builtin_by_id, builtin_ids, builtin_sources, BuiltinCategory, BuiltinKind};

/// Same count `./tools/verify-libjs.sh` asserts and `tools/node-pin.toml`
/// records. Repeated literally on purpose: an accidental change to the crate's
/// constant must not be able to move this test's expectation with it.
const EXPECTED_BUILTINS: usize = 435;

fn rustnode_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is rustnode/crates/rn-js2c. Walk up instead of assuming
    // a fixed depth, so the crate still finds the vendored tree if it is moved
    // within the workspace or checked out under a different nesting.
    let start = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("the crate directory exists");
    let mut candidate = start.as_path();
    loop {
        if candidate.join("vendor/libnode-js/LIBJS.sha256").is_file() {
            return candidate.to_path_buf();
        }
        candidate = candidate.parent().unwrap_or_else(|| {
            panic!(
                "no rustnode root above {}: expected a parent holding vendor/libnode-js/LIBJS.sha256",
                start.display()
            )
        });
    }
}

fn vendored_lib() -> PathBuf {
    rustnode_root().join("vendor/libnode-js/lib")
}

/// Every `.js` file under the vendored tree, as `lib/<relative>` js2c paths.
fn vendored_js_paths() -> BTreeSet<String> {
    let root = vendored_lib();
    let mut out = BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("vendored tree is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "js") {
                let relative = path
                    .strip_prefix(&root)
                    .expect("path is under the vendored root")
                    .to_str()
                    .expect("vendored paths are UTF-8");
                out.insert(format!("lib/{relative}"));
            }
        }
    }
    out
}

#[test]
fn every_vendored_file_is_embedded_exactly_once() {
    assert_eq!(
        builtin_sources().len(),
        EXPECTED_BUILTINS,
        "embedded builtin count must match the pinned Node tree"
    );

    let on_disk = vendored_js_paths();
    assert_eq!(
        on_disk.len(),
        EXPECTED_BUILTINS,
        "vendor/libnode-js/lib must still hold {} .js files",
        EXPECTED_BUILTINS
    );

    let embedded: BTreeSet<String> = builtin_sources()
        .iter()
        .map(|b| b.id().to_string())
        .collect();
    assert_eq!(
        embedded.len(),
        EXPECTED_BUILTINS,
        "every builtin id must be unique; a duplicate means two files collapsed onto one id"
    );

    // Rebuild the id each embedded entry must have from the file on disk, and
    // require the two sets to be equal. A file added to the vendored tree
    // without regenerating fails here with the missing id named.
    let expected_ids: BTreeSet<String> = on_disk.iter().map(|p| id_for_js2c_path(p)).collect();
    assert_eq!(
        embedded,
        expected_ids,
        "embedded ids and vendored files disagree: missing = {:?}, extra = {:?}",
        expected_ids.difference(&embedded).collect::<Vec<_>>(),
        embedded.difference(&expected_ids).collect::<Vec<_>>()
    );
}

/// The id rule, restated independently of the crate's implementation so a bug in
/// `scheme::get_file_id` cannot satisfy this test trivially.
fn id_for_js2c_path(js2c_path: &str) -> String {
    js2c_path
        .strip_prefix("lib/")
        .expect("js2c path starts with lib/")
        .strip_suffix(".js")
        .expect("js2c path ends with .js")
        .to_string()
}

#[test]
fn each_builtin_source_is_byte_identical_to_the_vendored_file() {
    let root = vendored_lib();
    for builtin in builtin_sources() {
        let path = root.join(format!("{}.js", builtin.id()));
        let on_disk = fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let on_disk = String::from_utf8(on_disk)
            .unwrap_or_else(|error| panic!("{} is not UTF-8: {error}", path.display()));
        assert_eq!(
            builtin.source(),
            on_disk,
            "embedded source for `{}` differs from {}",
            builtin.id(),
            path.display()
        );
    }
}

#[test]
fn ids_are_sorted_so_lookup_is_a_binary_search() {
    let ids = builtin_ids();
    assert_eq!(ids.len(), EXPECTED_BUILTINS);
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        ids,
        sorted.as_slice(),
        "ids must be in Node's std::map order"
    );
    assert_eq!(
        builtin_sources().iter().map(|b| b.id()).collect::<Vec<_>>(),
        ids,
        "the id index must line up with the table"
    );
}

#[test]
fn ids_are_stable_pins() {
    // These ids are what `lib/**` and Node's C++ bootstrap ask for by string.
    // `src/node.cc` calls StartExecution with the main scripts, and
    // `src/node_realm.cc` executes the realm bootstrap first. If any of these
    // stop resolving, the runtime cannot boot, so pin the specific ones rather
    // than only the count.
    let required = [
        "internal/bootstrap/realm",
        "internal/bootstrap/node",
        "internal/bootstrap/shadow_realm",
        "internal/bootstrap/switches/does_own_process_state",
        "internal/bootstrap/switches/does_not_own_process_state",
        "internal/bootstrap/switches/is_main_thread",
        "internal/bootstrap/switches/is_not_main_thread",
        "internal/bootstrap/web/exposed-wildcard",
        "internal/bootstrap/web/exposed-window-or-worker",
        "internal/per_context/primordials",
        "internal/per_context/domexception",
        "internal/per_context/messageport",
        "internal/main/eval_string",
        "internal/main/run_main_module",
        "internal/main/repl",
        "internal/main/print_help",
        "internal/main/worker_thread",
        "internal/main/mksnapshot",
        "internal/main/embedding",
        "internal/main/bench_runner",
        "internal/main/test_runner",
        "internal/main/watch_mode",
        "internal/main/inspect",
        "internal/main/check_syntax",
        "internal/main/prof_process",
        "internal/modules/cjs/loader",
        "internal/modules/esm/module_job",
        "internal/process/pre_execution",
        "internal/legacy/processbinding",
        "fs",
        "assert",
        "events",
        "path",
        "stream",
        "util",
    ];
    let missing: Vec<_> = required
        .iter()
        .filter(|id| builtin_by_id(id).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "missing required builtin ids: {missing:?}"
    );
}

#[test]
fn kinds_match_the_ids_node_classifies() {
    // Spot-check one member of each kind, plus the one .mjs file Node excludes.
    // `internal/deps/v8/tools/*` is the only id-based module bucket and the
    // vendored tree holds no such file, so nothing here should be a module.
    let expectations = [
        (
            "internal/bootstrap/realm",
            BuiltinKind::BootstrapRealm,
            BuiltinCategory::Internal,
        ),
        (
            "internal/bootstrap/node",
            BuiltinKind::BootstrapScript,
            BuiltinCategory::Internal,
        ),
        (
            "internal/per_context/primordials",
            BuiltinKind::PerContextScript,
            BuiltinCategory::Internal,
        ),
        (
            "internal/main/eval_string",
            BuiltinKind::MainScript,
            BuiltinCategory::Internal,
        ),
        (
            "internal/util",
            BuiltinKind::Function,
            BuiltinCategory::Internal,
        ),
        ("fs", BuiltinKind::Function, BuiltinCategory::Core),
    ];
    for (id, kind, category) in expectations {
        let builtin = builtin_by_id(id).unwrap_or_else(|| panic!("{id} is embedded"));
        assert_eq!(builtin.kind(), kind, "kind for {id}");
        assert_eq!(builtin.category(), category, "category for {id}");
    }

    assert!(
        builtin_sources()
            .iter()
            .all(|b| b.kind() != BuiltinKind::SourceTextModule),
        "the vendored tree must contain no ES-module builtin; \
         lib/eslint.config_partial.mjs is the only .mjs and Node's js2c drops it"
    );

    let modules: Vec<_> = builtin_sources()
        .iter()
        .filter(|b| b.kind() != BuiltinKind::Function && b.kind() != BuiltinKind::SourceTextModule)
        .map(|b| b.id())
        .collect();
    assert!(
        modules.iter().all(|id| id.starts_with("internal/")),
        "bootstrap and main scripts are all internal ids: {modules:?}"
    );

    // The exact per-kind distribution, derived independently from
    // `tools/js2c.cc::GetFileId` + `src/builtin_info.cc::GetBuiltinSourceType`
    // over the vendored tree. A single file moving between kinds — say a new
    // `internal/main/*` script — changes one of these numbers, which is the
    // fastest way to notice the tree and the rules drifted apart.
    let counts = |kind: BuiltinKind| {
        builtin_sources()
            .iter()
            .filter(|b| b.kind() == kind)
            .count()
    };
    assert_eq!(
        counts(BuiltinKind::BootstrapRealm),
        1,
        "only one realm bootstrap exists"
    );
    assert_eq!(counts(BuiltinKind::BootstrapScript), 8);
    assert_eq!(counts(BuiltinKind::PerContextScript), 3);
    assert_eq!(counts(BuiltinKind::MainScript), 14);
    assert_eq!(counts(BuiltinKind::Function), 409);
}

#[test]
fn core_and_internal_split_matches_realm_bootstrap() {
    let core: Vec<_> = rn_js2c::core_ids().collect();
    let internal: Vec<_> = rn_js2c::internal_ids().collect();

    assert_eq!(core.len() + internal.len(), EXPECTED_BUILTINS);
    assert!(
        core.iter().all(|id| !id.starts_with("internal/")),
        "no core module may live under internal/"
    );
    assert!(
        internal.iter().all(|id| id.starts_with("internal/")),
        "every internal module must live under internal/"
    );
    // Node's `lib/` has 73 top-level core modules; that number is stable enough
    // to catch a whole directory being classified the wrong way round.
    assert_eq!(core.len(), 73, "core module count: {core:?}");
}

#[test]
fn source_text_and_metadata_are_consistent_per_entry() {
    for builtin in builtin_sources() {
        assert_eq!(
            builtin.is_core(),
            builtin.category() == BuiltinCategory::Core
        );
        assert_eq!(builtin.source_len(), builtin.source().len());
        assert!(
            !builtin.source().is_empty(),
            "{} has no source",
            builtin.id()
        );
        // A builtin id never carries the file extension; the extension is added
        // when the id is mapped back to a path or a `node:` URL.
        assert!(
            !builtin.id().ends_with(".js"),
            "{} ends with .js",
            builtin.id()
        );
        assert!(builtin.id().is_ascii(), "{} is not ASCII", builtin.id());
        if !builtin.kind().is_module() {
            assert!(
                !builtin.parameters().is_empty(),
                "{} must be compiled with wrapper parameters",
                builtin.id()
            );
        }
    }
}

#[test]
fn lookup_misses_are_clean() {
    assert!(builtin_by_id("").is_none());
    assert!(builtin_by_id("internal/does-not-exist").is_none());
    assert!(
        builtin_by_id("fs.js").is_none(),
        "ids never carry the extension"
    );
    assert!(
        builtin_by_id("node:fs").is_none(),
        "the node: scheme is stripped earlier"
    );
    assert!(builtin_by_id("FS").is_none(), "lookup is case-sensitive");
    assert!(rn_js2c::exists("fs"));
    assert!(!rn_js2c::exists("nope"));
    assert_eq!(
        rn_js2c::source("fs"),
        builtin_by_id("fs").map(|b| b.source())
    );
    assert_eq!(rn_js2c::source("nope"), None);
}

#[test]
fn natives_covers_every_id_once() {
    // `BuiltinLoader::GetNatives` builds an object over the whole map, so the
    // legacy `process.binding('natives')` view must have exactly the same
    // entries in the same order.
    let natives: BTreeMap<_, _> = rn_js2c::natives().collect();
    assert_eq!(natives.len(), EXPECTED_BUILTINS);
    for builtin in builtin_sources() {
        assert_eq!(natives.get(builtin.id()), Some(&builtin.source()));
    }
    assert_eq!(
        rn_js2c::natives().map(|(id, _)| id).collect::<Vec<_>>(),
        builtin_ids()
    );
}

#[test]
fn totals_are_plausible() {
    assert_eq!(rn_js2c::builtin_count(), EXPECTED_BUILTINS);
    let total = rn_js2c::source_bytes();
    // The vendored tree is ~5.9 MB now. Assert a band rather than an exact byte
    // count: a Node re-pin moves this number legitimately, while a generator
    // that silently dropped or duplicated payloads would fall out of it.
    assert!(
        (5_000_000..8_000_000).contains(&total),
        "embedded source is {total} bytes, outside the expected band"
    );
    assert_eq!(
        total,
        builtin_sources()
            .iter()
            .map(|b| b.source_len())
            .sum::<usize>()
    );
}

/// Fails when the vendored tree is regenerated or edited without rebuilding.
///
/// Three independent checks, because they fail for different mistakes:
///
/// 1. The embedded file set must equal the set `LIBJS.sha256` describes. Editing
///    a builtin without updating the manifest breaks this, and so does updating
///    the manifest without re-copying the file.
/// 2. Every embedded byte must hash to the digest recorded in `LIBJS.sha256`.
///    The generator runs the same check; repeating it here also catches a test
///    build that reused a stale `OUT_DIR`.
/// 3. The table digest is pinned. It covers ids, kinds and text, so a re-pin that
///    adds, removes, renames or reclassifies a builtin cannot pass silently even
///    if the manifest were regenerated to match — a manifest of hashes cannot see
///    a change in how a builtin is classified.
///
/// On an intentional re-pin: update `tools/node-pin.toml`, re-copy `lib/**`,
/// regenerate `LIBJS.sha256`, then replace the digest below with the value the
/// failure prints. All of that belongs in one commit.
#[test]
fn vendored_tree_matches_the_embedded_copy() {
    let manifest = rustnode_root().join("vendor/libnode-js/LIBJS.sha256");
    let text = fs::read_to_string(&manifest)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", manifest.display()));

    // Checks 1 and 2, through the same entry point the compat tooling uses.
    if let Err(mismatches) = rn_js2c::verify_against_manifest(&text) {
        let detail: Vec<String> = mismatches.iter().map(ToString::to_string).collect();
        panic!(
            "embedded builtins disagree with {}:\n  {}",
            manifest.display(),
            detail.join("\n  ")
        );
    }

    // Check 3. Do not update the constant to silence an unexplained failure.
    assert_eq!(
        rn_js2c::table_digest(),
        TABLE_DIGEST,
        "the builtin table changed (ids, kinds or source); if this came from an \
         intentional Node re-pin, update TABLE_DIGEST in this test"
    );
}

/// Digest of the whole table: 435 builtins, 5,948,693 source bytes, 73 core.
/// Covers id, kind, category, source length and source text for every entry.
const TABLE_DIGEST: &str = "f75326383d78953099ba32bea6eb84e7e9ca52423d939cb3b3f870e05ddb0915";
