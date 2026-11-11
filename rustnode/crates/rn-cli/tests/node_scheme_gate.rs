//! The `node:`-scheme branch of `require()` must ask the builtin allow-list.
//!
//! `realm.js` keeps every option-gated builtin in `builtinModulePolicies` and
//! exposes an entry only when its option is true, which
//! `BuiltinModule.allowOptionGatedBuiltins(getOptionValue)` applies from the
//! parsed command line. That builds the allow-list; the `node:` resolution
//! branch is what enforces it.
//!
//! It is applied exactly once, by Node's own
//! `prepareMainThreadExecution` (`setupOptionGatedBuiltins()` at
//! `internal/process/pre_execution.js:121`), which `rn_realm::prepare_execution`
//! invokes. An earlier duplicate call in `main.rs` applied it a second time
//! before pre-execution; nothing between the two needed a gated builtin, so it
//! was removed rather than kept as harmless. These tests therefore cover the
//! single Node-shaped call.
//!
//! rustnode used to route a `node:` id to the realm's *internal* loader, which
//! has no allow-list by design — Node's own internals require gated modules at
//! their own scope — so `canBeRequiredByUsers('quic')` said false and
//! `require('node:quic')` loaded it anyway. The schemeless branch was correct
//! throughout, which is what narrows this to the scheme branch rather than to
//! the policy table: `require('quic')` already failed with `MODULE_NOT_FOUND`.
//!
//! These tests assert the observable boundary, because that is what a caller
//! sees. They deliberately do not enumerate the vendored policy table: a
//! re-pin that adds a gated builtin must not fail here, and a new *ungated*
//! builtin must not be pinned as unloadable.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Runs `-e` with `flags` and returns trimmed stdout, failing with stderr.
fn eval(flags: &[&str], code: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(flags)
        .arg("-e")
        .arg(code)
        .output()
        .expect("rustnode runs");
    assert!(
        out.status.success(),
        "the probe exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// The `code` a `require(id)` throws, or `LOADS` when it does not throw.
///
/// The error is read through `e.code` and nothing else: a bare message would not
/// distinguish `ERR_UNKNOWN_BUILTIN_MODULE` from #23's `ERR_INVALID_MODULE`, and
/// those two mean different things to a caller.
fn outcome(flags: &[&str], id: &str) -> String {
    eval(
        flags,
        &format!(
            "try {{ require({id:?}); console.log('LOADS'); }}\n\
             catch (error) {{ console.log(String(error && error.code)); }}"
        ),
    )
}

/// A scratch directory, removed on drop, so the file-entry tests can run a real
/// script rather than `-e`: `-e` and a file differ here, because `-e` also
/// installs lazy builtin globals.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rustnode-node-scheme-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the fixture directory");
        Self { root }
    }

    fn script(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, contents).expect("write the fixture script");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run_script(path: &Path) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg(path)
        .output()
        .expect("rustnode runs");
    (
        String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
        out.status.success(),
    )
}

#[test]
fn gated_builtins_are_unknown_through_the_scheme() {
    // The four `schemeOnly` builtins whose option is off in a default build, so
    // each is an id the table knows and the allow-list withholds. `ffi` behaves
    // the same way with no flags.
    //
    // `node:vfs` is deliberately *not* here. The pin defines
    // `experimental_vfs = true` and passes `true` as the `AddOption` default, so
    // a stock Node 28 exposes `node:vfs` with no flags, and rustnode's table
    // reproduces that. Gating it would be a divergence from the pin, not a fix;
    // `--no-experimental-vfs` is the supported way to withhold it.
    for id in ["node:quic", "node:bench", "node:dtls", "node:ffi"] {
        assert_eq!(
            outcome(&[], id),
            "ERR_UNKNOWN_BUILTIN_MODULE",
            "{id} must be unknown to a default build"
        );
    }
}

#[test]
fn vfs_is_exposed_by_default_and_gated_by_its_option() {
    // The counterexample that keeps this fix from being "gate everything in the
    // policy table". `vfs` sits in that table beside `quic`, and the only thing
    // separating them is the option value the pin defaults.
    assert_eq!(outcome(&[], "node:vfs"), "LOADS");
    assert_eq!(
        outcome(&["--no-experimental-vfs"], "node:vfs"),
        "ERR_UNKNOWN_BUILTIN_MODULE"
    );
}

#[test]
fn the_same_ids_stay_unknown_without_the_scheme() {
    // The reference the fix was copied from: the schemeless branch never had the
    // defect, and it reports `MODULE_NOT_FOUND` because no builtin matched, so
    // the id then goes to disk. Pinning both branches together is what makes a
    // regression in either one visible rather than only the scheme branch.
    for id in ["quic", "bench", "vfs", "dtls", "ffi"] {
        assert_eq!(
            outcome(&[], id),
            "MODULE_NOT_FOUND",
            "{id} must not resolve without the scheme"
        );
    }
}

#[test]
fn sqlite_loads_by_default_because_the_pin_defaults_it_on() {
    // The regression this guards against is the reason the fix is scoped to a
    // predicate call rather than to a hand-written list: `sqlite` and `quic` sit
    // in the same policy table, and the pin defaults `--experimental-sqlite` to
    // `HAVE_SQLITE`, which this build sets. A gate that keyed off "is this id in
    // the policy table" rather than off the option would make sqlite unreachable.
    assert_eq!(outcome(&[], "node:sqlite"), "LOADS");
    // The schemeless form stays blocked, because `sqlite` is `schemeOnly`.
    assert_eq!(outcome(&[], "sqlite"), "MODULE_NOT_FOUND");

    // A real round trip, so a fix cannot pass by exposing an empty stub.
    let printed = eval(
        &[],
        "const { DatabaseSync } = require('node:sqlite');\n\
         const db = new DatabaseSync(':memory:');\n\
         db.exec('CREATE TABLE t (a INTEGER)');\n\
         db.exec('INSERT INTO t VALUES (7)');\n\
         console.log(db.prepare('SELECT a FROM t').get().a);",
    );
    assert_eq!(printed, "7");
}

#[test]
fn with_no_experimental_sqlite_the_option_gates_sqlite() {
    // Node 22 gives `ERR_UNKNOWN_BUILTIN_MODULE` here too. This is the assertion
    // that the option store, `realm.js`'s policy table and the `node:` branch are
    // actually connected end to end instead of each being right on its own.
    assert_eq!(
        outcome(&["--no-experimental-sqlite"], "node:sqlite"),
        "ERR_UNKNOWN_BUILTIN_MODULE"
    );
}

#[test]
fn an_enabled_option_makes_its_builtin_reachable_again() {
    // The complement of the gate: it must be the option value that decides, not
    // the id appearing in the policy table. `bench` has a working module behind
    // it, so this also proves the allowing direction still functions.
    assert_eq!(outcome(&["--experimental-bench"], "node:bench"), "LOADS");
}

#[test]
fn ordinary_builtins_are_unaffected() {
    for id in [
        "fs",
        "node:fs",
        "path",
        "node:path",
        "assert",
        "node:assert",
    ] {
        assert_eq!(outcome(&[], id), "LOADS", "{id} must keep working");
    }
}

#[test]
fn an_unknown_scheme_id_reports_unknown_rather_than_crashing() {
    // Before the fix this already worked, because the realm loader's
    // `Missing internal module` fell through to the file loader, which then
    // normalized and rejected the id. It is pinned because the fallback is what
    // the fix changed: if the scheme branch ever stopped reaching the file
    // loader, this would become a crash or a mis-coded error instead.
    assert_eq!(
        outcome(&[], "node:nonexistent"),
        "ERR_UNKNOWN_BUILTIN_MODULE"
    );
    assert_eq!(
        outcome(&[], "node:internal/nonexistent"),
        "ERR_UNKNOWN_BUILTIN_MODULE"
    );
}

#[test]
fn a_missing_binding_is_distinguishable_from_a_missing_module() {
    // Two different failures, two different codes, and #23's fix is what put the
    // first one here. `node:ffi` is withheld by the policy table so it never
    // reaches its binding; `node:sea` is exposed (``schemeOnly`, no option) and
    // fails on the namespace itself. Keeping them distinct is what lets a caller
    // tell "this build does not expose it" from "this build cannot implement it".
    assert_eq!(outcome(&[], "node:ffi"), "ERR_UNKNOWN_BUILTIN_MODULE");
    assert_eq!(outcome(&[], "node:sea"), "ERR_INVALID_MODULE");
}

#[test]
fn the_scheme_gate_holds_for_a_file_entry_point_too() {
    // `-e` is not the only entry point, and it is not the most common one. A
    // file's own `require` comes from the CommonJS module wrapper rather than
    // the global, so both paths are pinned. `node:vfs` is included as the
    // loadable control, so a blanket gate cannot pass this.
    let fixture = Fixture::new("file-entry");
    let script = fixture.script(
        "probe.js",
        "const ids = ['node:quic', 'node:bench', 'node:dtls', 'node:ffi',\n\
         \x20            'node:sqlite', 'node:vfs', 'node:fs', 'node:nonexistent'];\n\
         for (const id of ids) {\n\
         \x20 try { require(id); console.log(id + ' LOADS'); }\n\
         \x20 catch (error) { console.log(id + ' ' + String(error && error.code)); }\n\
         }",
    );
    let (stdout, ok) = run_script(&script);
    assert!(ok, "the script failed");
    assert_eq!(
        stdout,
        "node:quic ERR_UNKNOWN_BUILTIN_MODULE\n\
         node:bench ERR_UNKNOWN_BUILTIN_MODULE\n\
         node:dtls ERR_UNKNOWN_BUILTIN_MODULE\n\
         node:ffi ERR_UNKNOWN_BUILTIN_MODULE\n\
         node:sqlite LOADS\n\
         node:vfs LOADS\n\
         node:fs LOADS\n\
         node:nonexistent ERR_UNKNOWN_BUILTIN_MODULE"
    );
}

#[test]
fn a_worker_applies_the_same_gate() {
    // `rn-bind-worker` builds its own realm and installs the same wrappers. A
    // fix applied only on the main thread would leave a worker as a way around
    // the policy, which is worse than not gating at all.
    //
    // Each outcome is emitted as one line and read back line by line rather than
    // compared to the whole of stdout: a worker startup also logs a tracing
    // `WARN` from `rn_bind_inspector`, and that channel writes to stdout, so an
    // exact-stdout assertion would fail for a reason that has nothing to do with
    // the policy under test.
    let printed = eval(
        &[],
        "const { Worker } = require('node:worker_threads');\n\
         const worker = new Worker(\n\
         \x20 \"const { parentPort } = require('node:worker_threads');\\n\" +\n\
         \x20 \"const ids = ['node:quic', 'node:sqlite', 'node:fs'];\\n\" +\n\
         \x20 \"for (const id of ids) {\\n\" +\n\
         \x20 \"  try { require(id); parentPort.postMessage('OUTCOME ' + id + ' LOADS'); }\\n\" +\n\
         \x20 \"  catch (error) { parentPort.postMessage('OUTCOME ' + id + ' ' + String(error && error.code)); }\\n\" +\n\
         \x20 \"}\",\n\
         \x20 { eval: true });\n\
         const lines = [];\n\
         worker.on('message', (line) => {\n\
         \x20 lines.push(line);\n\
         \x20 if (lines.length === 3) { console.log(lines.join('\\n')); worker.terminate(); }\n\
         });\n\
         worker.on('error', (error) => { console.log('OUTCOME worker error ' + error.message); });",
    );
    let outcomes: Vec<&str> = printed
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("OUTCOME "))
        .collect();
    assert_eq!(
        outcomes,
        [
            "node:quic ERR_UNKNOWN_BUILTIN_MODULE",
            "node:sqlite LOADS",
            "node:fs LOADS"
        ]
    );
}

#[test]
fn the_realm_loader_still_serves_the_ids_only_it_can() {
    // `internal/bootstrap/realm` is the one id `realm.js` keeps out of the list
    // the CJS loader consults, so it must still come from the realm loader. If
    // the scheme branch stopped falling back to it, every one of these would
    // break — and with `--expose-internals` node's own test helpers depend on it.
    assert_eq!(
        eval(
            &["--expose-internals"],
            "const realm = require('internal/bootstrap/realm');\n\
             console.log(typeof realm.BuiltinModule, typeof realm.internalBinding);",
        ),
        "function function"
    );
    assert_eq!(
        eval(
            &["--expose-internals"],
            "console.log(typeof require('internal/util'), typeof require('node:internal/util'));",
        ),
        "object object"
    );
}
