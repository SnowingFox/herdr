//! The binding as the real binary exposes it.
//!
//! The unit and differential tests drive the Rust engine directly, which cannot
//! see mistakes in the V8 surface: a member installed under the wrong name, a
//! result array shaped differently from Node's, a compile error reported as a
//! value instead of a throw. These tests spawn `target/debug/rustnode` and check
//! what `lib/internal/fs/glob.js` would actually receive.
//!
//! The binary is built by `tools/check.sh` before the test sweep precisely so a
//! test like this cannot read a stale one. When the binary is absent the tests
//! skip rather than fail, so `cargo test -p rn-bind-glob` alone still works.

use std::path::PathBuf;
use std::process::Command;

/// The CLI binary this workspace builds.
fn binary() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    let path = root.join("target").join("debug").join("rustnode");
    path.exists().then_some(path)
}

/// Runs a script through the binary and returns its stdout, failing on a throw.
fn run(script: &str) -> String {
    let Some(binary) = binary() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return String::new();
    };
    let output = Command::new(&binary)
        .arg("-e")
        .arg(script)
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Uncaught"),
        "the script threw: {stderr}\nscript: {script}"
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn available() -> bool {
    binary().is_some()
}

/// A temporary directory the test owns, removed on drop.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn build(label: &str, dirs: &[&str], files: &[&str]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rn-glob-surface-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mkdir");
        for dir in dirs {
            std::fs::create_dir_all(root.join(dir)).expect("mkdir");
        }
        for file in files {
            std::fs::write(root.join(file), b"").expect("write");
        }
        Self { root }
    }

    fn js_path(&self) -> String {
        self.root.to_string_lossy().replace('\\', "\\\\")
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Reaches the namespace the same way `lib/internal/fs/glob.js` does.
const PRELUDE: &str = "const { internalBinding } = require('internal/bootstrap/realm'); \
                       const g = internalBinding('glob');";

#[test]
fn the_namespace_has_exactly_the_contract_members() {
    if !available() {
        return;
    }
    let out = run(&format!(
        "{PRELUDE} \
         console.log(JSON.stringify(Object.getOwnPropertyNames(g).sort()));"
    ));
    assert_eq!(
        out,
        r#"["globStart","globSync","hasMagic","kFlagDot","kFlagFollowSymlinks","kFlagMatchBase","kFlagWindows","kFlagWithFileTypes","matchesGlob"]"#
    );
}

#[test]
fn the_flag_constants_are_nodes_values() {
    if !available() {
        return;
    }
    // These are the numbers `lib/internal/fs/glob.js` ORs together, so a wrong
    // one silently changes what a flag means rather than raising.
    let out = run(&format!(
        "{PRELUDE} console.log(JSON.stringify([g.kFlagWindows, g.kFlagDot, \
         g.kFlagFollowSymlinks, g.kFlagWithFileTypes, g.kFlagMatchBase]));"
    ));
    assert_eq!(out, "[1,4,8,16,32]");
}

#[test]
fn has_magic_says_what_node_says() {
    if !available() {
        return;
    }
    // Verified against the v27 recorder binary.
    let out = run(&format!(
        "{PRELUDE} console.log(JSON.stringify(\
         ['*.js','a/b','{{a,b}}','@(x)','[abc]','a+b','.x'].map((p) => g.hasMagic(p))));"
    ));
    assert_eq!(out, "[true,false,false,true,true,false,false]");
}

#[test]
fn matches_glob_honours_each_flag() {
    if !available() {
        return;
    }
    let out = run(&format!(
        "{PRELUDE} console.log(JSON.stringify([\
         g.matchesGlob('a/b.js','**/*.js',0),\
         g.matchesGlob('.hidden','*',0),\
         g.matchesGlob('.hidden','*',g.kFlagDot),\
         g.matchesGlob('a/b/c.js','*.js',g.kFlagMatchBase),\
         g.matchesGlob('C:\\\\a\\\\b.js','**/*.js',g.kFlagWindows)]));"
    ));
    assert_eq!(out, "[true,false,true,true,true]");
}

#[test]
fn a_pattern_that_cannot_compile_throws_rather_than_returning_false() {
    if !available() {
        return;
    }
    // Beyond `kMaxPatternLength` Node throws a `TypeError`, and the JavaScript
    // layer treats that as an error rather than as "no match".
    let out = run(&format!(
        "{PRELUDE} try {{ g.hasMagic('a'.repeat(65537)); console.log('no-throw'); }} \
         catch (e) {{ console.log(e.name + ':' + e.message); }}"
    ));
    assert_eq!(out, "TypeError:pattern is too long");
}

#[test]
fn glob_sync_returns_a_path_array_and_a_types_pair() {
    if !available() {
        return;
    }
    // The tree is built from Rust: `fs` and `os` still need the `url` namespace,
    // which is another workstream's, and this test is about glob.
    let tree = TempTree::build("sync", &["sub"], &["a.js", "sub/b.js", "note.txt"]);
    let out = run(&format!(
        "{PRELUDE} const plain = g.globSync('{dir}', ['**/*.js'], [], 0, undefined, Infinity); \
         const pair = g.globSync('{dir}', ['**/*'], [], g.kFlagWithFileTypes, undefined, Infinity); \
         console.log(JSON.stringify([plain, pair[0], pair[1]]));",
        dir = tree.js_path()
    ));
    // `1` is `UV_DIRENT_FILE`; `2` would be a directory.
    assert_eq!(
        out,
        r#"[["a.js","sub/b.js"],["a.js","note.txt","sub","sub/b.js"],[1,1,2,1]]"#
    );
}

#[test]
fn glob_start_serves_batches_through_promises() {
    if !available() {
        return;
    }
    let tree = TempTree::build("async", &[], &["a.js"]);
    let out = run(&format!(
        "{PRELUDE} \
         const handle = g.globStart('{dir}', ['*.js'], [], 0, undefined, Infinity); \
         handle.all().then(([paths, types, done]) => console.log(JSON.stringify([paths, types === undefined, done])));",
        dir = tree.js_path()
    ));
    assert_eq!(out, r#"[["a.js"],true,true]"#);
}

#[test]
fn the_exclude_callback_prunes_results() {
    if !available() {
        return;
    }
    let tree = TempTree::build("exclude", &["sub"], &["keep.js", "sub/drop.js"]);
    // `#excludeAdapter()` calls the user callback with the entry's value, so
    // returning true for a name prunes it.
    let script = format!(
        "{PRELUDE} const excluded = g.globSync('{dir}', ['**/*.js'], [], 0, (entry, value) => value.endsWith('drop.js'), Infinity); console.log(JSON.stringify(excluded));",
        dir = tree.js_path()
    );
    let out = run(&script);
    assert_eq!(out, r#"["keep.js"]"#);
}
