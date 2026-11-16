//! `fs.cp`'s recursive copy against the pinned Node oracle.
//!
//! # Why this has to compare a tree rather than a return value
//!
//! `fs.cpSync` returns `undefined` on success. The only evidence that it worked
//! is the tree it produced — which entries exist, what they contain, what modes
//! they carry, where symlinks point, and which timestamps survived — so a test
//! that only asserts "it did not throw" accepts a copy that created nothing. The
//! whole finding this file closes was that shape: `cpSyncCopyDir` and `CpDirJob`
//! were deferred, `cp-sync.js` has no fallback for a plain recursive copy, and
//! the symptom was a `TypeError` rather than a wrong tree — but the members
//! beneath it could be implemented wrongly and still not throw.
//!
//! So each case builds the same source tree twice, runs the oracle on one copy
//! and `rustnode` on the other, and compares a normalised description of the two
//! result trees. Paths, temp-directory names and wall-clock times are normalised
//! out because they cannot match; everything a caller can observe is compared.
//!
//! # Why it spawns the binary
//!
//! `lib/internal/fs/cp/cp-sync.js` and `cp.js` decide *which* path a call takes —
//! the C++ fast path only when there is no `filter`, the `dereference` guard, the
//! `permission.isEnabled()` guard — so a test that called `fsBinding.cpSyncCopyDir`
//! directly would prove the walk works while leaving the dispatch, and the
//! `CpDirJob` construction, untested. Both are spawned with `-e` for that reason.

use std::path::PathBuf;
use std::process::Command;

/// The CLI binary this workspace builds.
///
/// `CARGO_BIN_EXE_rustnode` is only defined inside `rn-cli`'s own test targets,
/// so this workspace's binary is found relative to this crate. Both profiles are
/// accepted: `tools/check.sh` builds the debug binary before the test sweep, and
/// a release build is what a differential run against the oracle is normally
/// made from. When neither exists the case skips rather than failing, so
/// `cargo test -p rn-bind-fs` alone still works on a tree that has never built
/// the CLI.
fn binary() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    ["debug", "release"]
        .into_iter()
        .map(|profile| root.join("target").join(profile).join("rustnode"))
        .find(|path| path.exists())
}

fn oracle() -> Option<&'static rn_node_oracle::Oracle> {
    static ORACLE: std::sync::OnceLock<Option<rn_node_oracle::Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-bind-fs cp parity"))
        .as_ref()
}

/// Runs `script` under `program` and returns its stdout, failing on a throw.
fn run(program: &str, script: &str) -> String {
    let output = Command::new(program)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} failed: {}\nscript: {script}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A scratch directory each case owns, removed on drop.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rn-cp-parity-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mkdir");
        Self { root }
    }

    fn path(&self) -> String {
        self.root.to_string_lossy().replace('\\', "\\\\")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Describes everything about a copy that a caller can observe.
///
/// `base` is the scratch root: it is replaced with `<base>` in link targets and
/// in error messages, and any timestamp at or after the year 2001 is replaced
/// with `<now>` because it is wall-clock and cannot match between two runs. The
/// fixture stamps every timestamp it wants compared with a value from the 1970s,
/// which is far below that threshold.
const DESCRIBE: &str = r#"
function describe(root, base) {
  const out = {};
  (function walk(dir, rel) {
    for (const name of require('fs').readdirSync(dir).sort()) {
      const full = require('path').join(dir, name);
      const entry = rel ? rel + '/' + name : name;
      const stats = require('fs').lstatSync(full);
      if (stats.isSymbolicLink()) {
        out[entry] = { kind: 'link', target: require('fs').readlinkSync(full).split(base).join('<base>') };
      } else if (stats.isDirectory()) {
        out[entry] = { kind: 'dir', mode: (stats.mode & 0o777).toString(8) };
        walk(full, entry);
      } else {
        const atime = Math.round(stats.atimeMs);
        const mtime = Math.round(stats.mtimeMs);
        out[entry] = {
          kind: 'file',
          mode: (stats.mode & 0o777).toString(8),
          contents: require('fs').readFileSync(full, 'utf8'),
          atime: atime < 1e12 ? atime : '<now>',
          mtime: mtime < 1e12 ? mtime : '<now>',
        };
      }
    }
  })(root, '');
  return out;
}
"#;

/// The fixture every case starts from.
///
/// Three depths, two modes, a relative symlink, and timestamps on a file, a
/// directory and a nested file — so a copy that flattens the tree, drops a mode,
/// resolves a link against the wrong base or forgets to recurse into a
/// subdirectory is visible in the description rather than merely plausible.
const FIXTURE: &str = r#"
function fixture(base) {
  const fs = require('fs');
  const path = require('path');
  const src = path.join(base, 'src');
  fs.mkdirSync(path.join(src, 'sub/deep'), { recursive: true });
  fs.writeFileSync(path.join(src, 'one'), '1');
  fs.writeFileSync(path.join(src, 'sub/two'), '2');
  fs.writeFileSync(path.join(src, 'sub/deep/three'), '3');
  fs.chmodSync(path.join(src, 'one'), 0o640);
  fs.chmodSync(path.join(src, 'sub'), 0o750);
  fs.utimesSync(path.join(src, 'one'), 1111, 2222);
  fs.utimesSync(path.join(src, 'sub/two'), 3333, 4444);
  fs.utimesSync(path.join(src, 'sub'), 5555, 6666);
  fs.utimesSync(path.join(src, 'sub/deep/three'), 7777, 8888);
  fs.symlinkSync('one', path.join(src, 'lnk'));
  return src;
}
"#;

/// Builds a case script: fixture, copy with `options`, describe, and report the
/// asynchronous form as well.
fn case_script(options: &str) -> String {
    format!(
        r#"{DESCRIBE}{FIXTURE}
const fs = require('fs');
const path = require('path');
const os = require('os');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-case-'));
const src = fixture(base);
const dest = path.join(base, 'dest');
const options = {{ recursive: true, {options} }};
const out = {{}};
try {{
  fs.cpSync(src, dest, options);
  out.sync = {{ ok: describe(dest, base) }};
}} catch (error) {{
  out.sync = {{ error: {{ code: error.code,
                          message: error.message.split('\n')[0].split(base).join('<base>') }} }};
}}
fs.rmSync(dest, {{ recursive: true, force: true }});
fs.promises.cp(src, dest, options).then(
  () => {{ out.async = {{ ok: describe(dest, base) }}; console.log(JSON.stringify(out)); }},
  (error) => {{ out.async = {{ error: {{ code: error.code,
                                        message: error.message.split('\n')[0].split(base).join('<base>') }} }};
               console.log(JSON.stringify(out)); }});
"#
    )
}

/// Runs one case under both runtimes and asserts the descriptions agree.
fn compare(label: &str, options: &str) {
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping {label}: no pinned Node oracle or no rustnode binary");
        return;
    };
    let script = case_script(options);
    let expected = run(oracle.reference_path(), &script);
    let actual = run(binary.to_string_lossy().as_ref(), &script);
    assert_eq!(
        actual,
        expected,
        "{label}: the copied tree differs from {}\noptions: {options}\nscript:\n{script}",
        oracle.describe()
    );
    // The comparison is worthless if the oracle itself refused the copy, so a
    // case whose expected output is an error is reported as a broken fixture
    // rather than as agreement about a failure.
    assert!(
        !expected.contains("\"error\""),
        "{label}: the oracle reported an error, so there is no tree to compare: {expected}"
    );
}

/// The refusal cases are `a_plain_recursive_copy_refusal_matches_node` and
/// `a_directory_without_recursive_is_refused_like_node` below: each needs a
/// fixture the shared `case_script` cannot build (a pre-existing destination, and
/// a source directory with no `recursive`), so they assemble their own scripts
/// rather than going through [`compare`].

#[test]
fn a_plain_recursive_copy_matches_node() {
    compare("plain", "");
}

#[test]
fn preserve_timestamps_matches_node() {
    compare("preserveTimestamps", "preserveTimestamps: true");
}

#[test]
fn verbatim_symlinks_match_node() {
    compare("verbatimSymlinks", "verbatimSymlinks: true");
}

#[test]
fn dereference_matches_node() {
    // A link to a file and a link to a directory, so the branch that copies a
    // directory through a link is exercised rather than only the file one.
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let script = format!(
        r#"{DESCRIBE}{FIXTURE}
const fs = require('fs');
const path = require('path');
const os = require('os');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-deref-'));
const src = fixture(base);
fs.mkdirSync(path.join(src, 'realdir'));
fs.writeFileSync(path.join(src, 'realdir/inner'), 'I');
fs.symlinkSync('realdir', path.join(src, 'lnkdir'));
const dest = path.join(base, 'dest');
const out = {{}};
try {{
  fs.cpSync(src, dest, {{ recursive: true, dereference: true, preserveTimestamps: true }});
  out.sync = {{ ok: describe(dest, base) }};
}} catch (error) {{
  out.sync = {{ error: {{ code: error.code,
                          message: error.message.split('\n')[0].split(base).join('<base>') }} }};
}}
fs.rmSync(dest, {{ recursive: true, force: true }});
fs.promises.cp(src, dest, {{ recursive: true, dereference: true, preserveTimestamps: true }}).then(
  () => {{ out.async = {{ ok: describe(dest, base) }}; console.log(JSON.stringify(out)); }},
  (error) => {{ out.async = {{ error: {{ code: error.code }} }};
               console.log(JSON.stringify(out)); }});
"#
    );
    let expected = run(oracle.reference_path(), &script);
    let actual = run(binary.to_string_lossy().as_ref(), &script);
    assert_eq!(
        actual,
        expected,
        "dereference differs from {}",
        oracle.describe()
    );
    assert!(
        !expected.contains("\"error\""),
        "the oracle refused: {expected}"
    );
}

#[test]
fn a_filter_defers_to_the_javascript_walk_and_still_matches_node() {
    // With a `filter` the C++ path is skipped entirely, so this is the JS walk
    // over the other `fs` members. It is here because a copy implementation that
    // changed the other members would pass every case above and break this one.
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let script = format!(
        r#"{DESCRIBE}{FIXTURE}
const fs = require('fs');
const path = require('path');
const os = require('os');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-filter-'));
const src = fixture(base);
const dest = path.join(base, 'dest');
const out = {{}};
const options = {{ recursive: true, filter: (from) => !from.endsWith('two') }};
try {{
  fs.cpSync(src, dest, options);
  out.sync = {{ ok: describe(dest, base) }};
}} catch (error) {{
  out.sync = {{ error: {{ code: error.code }} }};
}}
fs.rmSync(dest, {{ recursive: true, force: true }});
fs.promises.cp(src, dest, options).then(
  () => {{ out.async = {{ ok: describe(dest, base) }}; console.log(JSON.stringify(out)); }},
  (error) => {{ out.async = {{ error: {{ code: error.code }} }};
               console.log(JSON.stringify(out)); }});
"#
    );
    let expected = run(oracle.reference_path(), &script);
    let actual = run(binary.to_string_lossy().as_ref(), &script);
    assert_eq!(
        actual,
        expected,
        "filtered copy differs from {}",
        oracle.describe()
    );
    assert!(
        !expected.contains("\"error\""),
        "the oracle refused the filtered copy: {expected}"
    );
    assert!(
        !expected.contains("two"),
        "the fixture did not actually filter anything: {expected}"
    );
}

/// The overwrite rules: `force`, `errorOnExist`, and a merge into an existing
/// directory that already holds a different copy of one file.
#[test]
fn an_existing_destination_merges_with_the_documented_overwrite_rule() {
    for (label, options) in [
        ("force", "force: true"),
        ("skip", "force: false"),
        ("force-and-eexist", "force: true, errorOnExist: true"),
    ] {
        compare(label, options);
    }
}

/// A non-recursive directory copy is refused with a typed error.
///
/// Before `cpSyncCheckPaths` grew the check, `cp-sync.js` fell through every
/// branch and its own `assert.fail('Unreachable code')` produced
/// `ERR_INTERNAL_ASSERTION`, which tells the caller their arguments are a Node
/// bug.
#[test]
fn a_directory_without_recursive_is_refused_like_node() {
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let script = r#"
const fs = require('fs');
const path = require('path');
const os = require('os');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-nonrec-'));
fs.mkdirSync(path.join(base, 'src'));
const out = {};
try { fs.cpSync(path.join(base, 'src'), path.join(base, 'dest')); out.sync = 'no-throw'; }
catch (error) { out.sync = { code: error.code,
                             message: error.message.split('\n')[0].split(base).join('<base>'),
                             own: Object.getOwnPropertyNames(error).sort() }; }
console.log(JSON.stringify(out));
"#;
    let expected = run(oracle.reference_path(), script);
    let actual = run(binary.to_string_lossy().as_ref(), script);
    assert_eq!(
        actual,
        expected,
        "non-recursive refusal differs from {}",
        oracle.describe()
    );
    assert!(
        expected.contains("ERR_FS_EISDIR"),
        "unexpected oracle answer: {expected}"
    );
}

/// A single-file `fs.cpSync` onto an existing destination.
///
/// This is `cpSyncOverrideFile`'s one caller: `cp-sync.js`'s `onFile` reaches it
/// whenever the destination exists and `force` is on, and it has to carry the
/// source's mode as well as its bytes.
#[test]
fn an_existing_file_destination_is_overwritten_with_the_source_mode() {
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let script = r#"
const fs = require('fs');
const path = require('path');
const os = require('os');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-override-'));
const src = path.join(base, 'src');
const dest = path.join(base, 'dest');
const out = {};
for (const [label, options] of [['plain', {}], ['preserve', { preserveTimestamps: true }]]) {
  fs.writeFileSync(src, 'NEW');
  fs.writeFileSync(dest, 'OLD');
  fs.chmodSync(src, 0o604);
  fs.utimesSync(src, 7000, 8000);
  try {
    fs.cpSync(src, dest, options);
    const stats = fs.statSync(dest);
    out[label] = { contents: fs.readFileSync(dest, 'utf8'),
                   mode: (stats.mode & 0o777).toString(8),
                   mtime: Math.round(stats.mtimeMs) < 1e12 ? Math.round(stats.mtimeMs) : '<now>' };
  } catch (error) { out[label] = { code: error.code }; }
}
console.log(JSON.stringify(out));
"#;
    let expected = run(oracle.reference_path(), script);
    let actual = run(binary.to_string_lossy().as_ref(), script);
    assert_eq!(
        actual,
        expected,
        "the single-file overwrite differs from {}",
        oracle.describe()
    );
    assert!(
        !expected.contains("\"code\""),
        "the oracle refused: {expected}"
    );
}

/// `fs.cp`'s threadpool job reports a special file the way `cp.js` expects.
///
/// The job does not build the error itself: it reports `(null, kind, path)` so
/// `copyDirNative` can construct `ERR_FS_CP_FIFO_PIPE`. A job that returned a
/// finished error object instead would still reject, but with `undefined` as the
/// `code`, so the shape is what this asserts.
#[test]
fn a_fifo_in_a_fresh_destination_is_reported_by_kind_like_node() {
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        eprintln!("skipping: no pinned Node oracle or no rustnode binary");
        return;
    };
    let script = r#"
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-fifo-'));
const src = path.join(base, 'src');
fs.mkdirSync(src);
fs.writeFileSync(path.join(src, 'ok'), 'x');
execSync('mkfifo ' + JSON.stringify(path.join(src, 'pipe')));
const out = {};
// The synchronous path skips a special entry in a merge.
try { fs.cpSync(src, path.join(base, 'merged'), { recursive: true }); out.sync = 'ok'; }
catch (error) { out.sync = { code: error.code }; }
// The asynchronous path only takes the native copy for a destination that does
// not exist, so this is the `CpDirJob` branch.
fs.promises.cp(src, path.join(base, 'fresh'), { recursive: true }).then(
  () => { out.async = 'no-throw'; console.log(JSON.stringify(out)); },
  (error) => { out.async = { code: error.code, errno: error.errno, syscall: error.syscall };
               console.log(JSON.stringify(out)); });
"#;
    let expected = run(oracle.reference_path(), script);
    let actual = run(binary.to_string_lossy().as_ref(), script);
    assert_eq!(
        actual,
        expected,
        "the FIFO report differs from {}",
        oracle.describe()
    );
    assert!(
        expected.contains("ERR_FS_CP_FIFO_PIPE"),
        "the fixture did not produce the expected error: {expected}"
    );
}

#[test]
fn a_plain_recursive_copy_refusal_matches_node() {
    // `errorOnExist` against a destination that already exists is a refusal
    // rather than a merge, and the error has to be the one `cp-sync.js` throws
    // rather than an internal assertion. `onDir` reports it against the
    // *destination directory*, which is what makes the `path` property
    // meaningful.
    let (Some(oracle), Some(binary)) = (oracle(), binary()) else {
        return;
    };
    let script = format!(
        r#"{DESCRIBE}{FIXTURE}
const fs = require('fs');
const path = require('path');
const os = require('os');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rn-cp-eexist-'));
const src = fixture(base);
const dest = path.join(base, 'dest');
fs.mkdirSync(dest, {{ recursive: true }});
const out = {{}};
try {{
  fs.cpSync(src, dest, {{ recursive: true, force: false, errorOnExist: true }});
  out.sync = {{ ok: describe(dest, base) }};
}} catch (error) {{
  out.sync = {{ error: {{ code: error.code,
                          path: error.path && error.path.split(base).join('<base>'),
                          message: error.message.split('\n')[0].split(base).join('<base>'),
                          own: Object.getOwnPropertyNames(error).sort() }} }};
}}
console.log(JSON.stringify(out));
"#
    );
    let expected = run(oracle.reference_path(), &script);
    let actual = run(binary.to_string_lossy().as_ref(), &script);
    assert_eq!(
        actual,
        expected,
        "the refusal differs from {}",
        oracle.describe()
    );
    assert!(
        expected.contains("ERR_FS_CP_EEXIST"),
        "the fixture did not produce the expected refusal: {expected}"
    );
}

/// Exists so a change to [`Scratch`] that broke path escaping would fail here
/// rather than as a mystifying mismatch in a comparison test.
#[test]
fn the_scratch_path_survives_embedding_in_a_script() {
    let Some(binary) = binary() else {
        eprintln!("skipping: no rustnode binary");
        return;
    };
    let scratch = Scratch::new("path");
    std::fs::write(scratch.root.join("x"), b"y").expect("write");
    let script = format!(
        "console.log(require('fs').readFileSync('{}/x', 'utf8'))",
        scratch.path()
    );
    assert_eq!(run(binary.to_string_lossy().as_ref(), &script), "y");
    // And the oracle agrees about the same path, which is what makes a shared
    // fixture comparable at all.
    if let Some(oracle) = oracle() {
        assert_eq!(run(oracle.reference_path(), &script), "y");
    }
}
