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
/// records for `lib/**`. Repeated literally on purpose: an accidental change to
/// the crate's constant must not be able to move this test's expectation with it.
///
/// This is `lib/**` only, and it stays 435. The `deps/**` tree Node's js2c also
/// embeds is counted separately ([`EXPECTED_DEPS_BUILTINS`]) so the two can
/// never explain each other's drift.
const EXPECTED_BUILTINS: usize = 435;

/// Number of builtins vendored from `deps/**`, which is the one esbuild bundle
/// `lib/**` requires as `internal/deps/undici/undici`. Node's `node.gyp` lists
/// its `deps_files` explicitly, so this is a pinned number rather than a glob.
const EXPECTED_DEPS_BUILTINS: usize = 1;

/// Total embedded entries: the `lib/**` tree plus the `deps/**` tree.
const EXPECTED_TOTAL: usize = EXPECTED_BUILTINS + EXPECTED_DEPS_BUILTINS;

/// The one builtin id that comes from `deps/**`.
const UNDICI_ID: &str = "internal/deps/undici/undici";

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

fn vendored_deps() -> PathBuf {
    rustnode_root().join("vendor/libnode-js/deps")
}

/// Whether an embedded id came from the `deps/**` tree.
///
/// The id prefix is the only thing the id itself can say about its origin, so
/// this is the same rule `rn_js2c::scheme::js2c_path_for` inverts.
fn is_deps_id(id: &str) -> bool {
    id.starts_with("internal/deps/")
}

/// Every `.js` file under one vendored tree, as `<prefix><relative>` js2c paths.
fn vendored_js_paths(root: &Path, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("vendored tree is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "js") {
                let relative = path
                    .strip_prefix(root)
                    .expect("path is under the vendored root")
                    .to_str()
                    .expect("vendored paths are UTF-8");
                out.insert(format!("{prefix}{relative}"));
            }
        }
    }
    out
}

/// On-disk path of the file behind an embedded id, in whichever tree holds it.
fn path_for_id(id: &str) -> PathBuf {
    if let Some(rest) = id.strip_prefix("internal/deps/") {
        vendored_deps().join(format!("{rest}.js"))
    } else {
        vendored_lib().join(format!("{id}.js"))
    }
}

#[test]
fn every_vendored_file_is_embedded_exactly_once() {
    assert_eq!(
        builtin_sources().len(),
        EXPECTED_TOTAL,
        "embedded builtin count must match both pinned Node trees \
         ({} under lib/ plus {} under deps/)",
        EXPECTED_BUILTINS,
        EXPECTED_DEPS_BUILTINS
    );

    // Each tree is counted where it is, so one gaining a file while the other
    // loses one cannot balance out into a passing total.
    let lib_on_disk = vendored_js_paths(&vendored_lib(), "lib/");
    assert_eq!(
        lib_on_disk.len(),
        EXPECTED_BUILTINS,
        "vendor/libnode-js/lib must still hold {} .js files",
        EXPECTED_BUILTINS
    );
    let deps_on_disk = vendored_js_paths(&vendored_deps(), "deps/");
    assert_eq!(
        deps_on_disk.len(),
        EXPECTED_DEPS_BUILTINS,
        "vendor/libnode-js/deps must still hold {} .js file",
        EXPECTED_DEPS_BUILTINS
    );

    let embedded: BTreeSet<String> = builtin_sources()
        .iter()
        .map(|b| b.id().to_string())
        .collect();
    assert_eq!(
        embedded.len(),
        EXPECTED_TOTAL,
        "every builtin id must be unique; a duplicate means two files collapsed onto one id"
    );
    assert_eq!(
        embedded
            .iter()
            .filter(|id| is_deps_id(id))
            .collect::<Vec<_>>(),
        vec![&UNDICI_ID.to_string()],
        "exactly one builtin must come from deps/, and it must be the undici bundle"
    );

    // Rebuild the id each embedded entry must have from the file on disk, and
    // require the two sets to be equal. A file added to either vendored tree
    // without regenerating fails here with the missing id named.
    let expected_ids: BTreeSet<String> = lib_on_disk
        .iter()
        .chain(deps_on_disk.iter())
        .map(|p| id_for_js2c_path(p))
        .collect();
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
///
/// Both vendored trees are handled, because js2c rewrites a `deps/` prefix to
/// `internal/deps/` and the crate's `get_file_id` must agree with that.
fn id_for_js2c_path(js2c_path: &str) -> String {
    let stripped = js2c_path
        .strip_suffix(".js")
        .expect("js2c path ends with .js");
    if let Some(rest) = stripped.strip_prefix("deps/") {
        format!("internal/deps/{rest}")
    } else {
        stripped
            .strip_prefix("lib/")
            .expect("js2c path starts with lib/ or deps/")
            .to_string()
    }
}

#[test]
fn each_builtin_source_is_byte_identical_to_the_vendored_file() {
    for builtin in builtin_sources() {
        let path = path_for_id(builtin.id());
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
    assert_eq!(ids.len(), EXPECTED_TOTAL);
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
    // 409 of the `lib/` functions plus the undici bundle from `deps/`, which
    // Node classifies as `kFunction` too (it is the one `deps/` id whose path is
    // not under `internal/deps/v8/tools/`, the only module bucket).
    assert_eq!(counts(BuiltinKind::Function), 409 + EXPECTED_DEPS_BUILTINS);

    // The undici bundle is the one entry a `lib/`-only generator could never
    // produce, so pin its classification explicitly rather than only the totals.
    let undici = builtin_by_id(UNDICI_ID).expect("the deps bundle is embedded");
    assert_eq!(undici.kind(), BuiltinKind::Function);
    assert_eq!(
        undici.category(),
        BuiltinCategory::Internal,
        "a deps builtin may never be reachable as a core module"
    );
    assert_eq!(
        undici.parameters(),
        BuiltinKind::Function.parameters(),
        "it is compiled as an ordinary CommonJS function"
    );
}

#[test]
fn core_and_internal_split_matches_realm_bootstrap() {
    let core: Vec<_> = rn_js2c::core_ids().collect();
    let internal: Vec<_> = rn_js2c::internal_ids().collect();

    assert_eq!(core.len() + internal.len(), EXPECTED_TOTAL);
    assert!(
        core.iter().all(|id| !id.starts_with("internal/")),
        "no core module may live under internal/"
    );
    assert!(
        internal.iter().all(|id| id.starts_with("internal/")),
        "every internal module must live under internal/"
    );
    // Node's `lib/` has 73 top-level core modules; that number is stable enough
    // to catch a whole directory being classified the wrong way round. It is
    // unchanged by the deps tree: every `deps/` id starts with `internal/`, so a
    // core count that moved here would mean the split, not the tree, changed.
    assert_eq!(core.len(), 73, "core module count: {core:?}");
    assert!(
        core.iter().all(|id| !is_deps_id(id)),
        "no deps builtin may be reachable as a core module: {core:?}"
    );
    assert!(
        internal.len() == EXPECTED_TOTAL - 73,
        "the internal side must hold every non-core builtin, deps included"
    );
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
    // The deps bundle is reachable by its js2c id and by nothing else: the
    // filesystem path that produced it is not a second way to ask for it.
    assert!(rn_js2c::exists(UNDICI_ID));
    assert!(
        builtin_by_id("deps/undici/undici").is_none(),
        "the js2c path is not an id"
    );
    assert!(
        builtin_by_id("undici").is_none(),
        "the bundle is not a core module"
    );
}

#[test]
fn natives_covers_every_id_once() {
    // `BuiltinLoader::GetNatives` builds an object over the whole map, so the
    // legacy `process.binding('natives')` view must have exactly the same
    // entries in the same order.
    let natives: BTreeMap<_, _> = rn_js2c::natives().collect();
    assert_eq!(natives.len(), EXPECTED_TOTAL);
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
    assert_eq!(rn_js2c::builtin_count(), EXPECTED_TOTAL);
    let total = rn_js2c::source_bytes();
    // The vendored trees are ~6.8 MB now: ~5.9 MB of `lib/**` plus the 831,314
    // byte undici bundle. Assert a band rather than an exact byte count: a Node
    // re-pin moves this number legitimately, while a generator that silently
    // dropped or duplicated payloads would fall out of it.
    assert!(
        (6_000_000..9_000_000).contains(&total),
        "embedded source is {total} bytes, outside the expected band"
    );
    assert_eq!(
        total,
        builtin_sources()
            .iter()
            .map(|b| b.source_len())
            .sum::<usize>()
    );

    // The bundle is the single largest entry, and it is the one whose absence
    // would otherwise show up only as a runtime `Missing internal module`. Pin
    // its size so a truncated download or a half-written copy fails here.
    let undici = builtin_by_id(UNDICI_ID).expect("the deps bundle is embedded");
    assert_eq!(
        undici.source_len(),
        831_314,
        "the undici bundle is not the size the pinned revision ships"
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
/// On an intentional re-pin: update `tools/node-pin.toml`, re-copy `lib/**` and
/// `deps/**`, regenerate `LIBJS.sha256`, then replace the digest below with the
/// value the failure prints. All of that belongs in one commit.
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

/// Digest of the whole table: 436 builtins (435 under `lib/`, 1 under `deps/`),
/// 73 core. Covers id, kind, category, source length and source text for every
/// entry.
const TABLE_DIGEST: &str = "039aab74a8b77710dab83e3ebaa3724aaa1209eeb6176192b03325aec741d577";
