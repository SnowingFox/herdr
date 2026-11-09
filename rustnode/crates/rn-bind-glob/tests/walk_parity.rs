//! The walker, checked against a real directory tree.
//!
//! `tests/corpus/walk.json` records what Node 27's own
//! `internalBinding('glob').globSync` returned for a tree with nested
//! directories, dotfiles, a relative symlink and an absolute symlink. The test
//! rebuilds that tree in a temporary directory and checks the walker reproduces
//! every entry, in order.
//!
//! The order matters as much as the set: `globSync` returns an array and Node's
//! own tests compare it, so a different traversal order is a different answer.
//!
//! The recorded paths are relative to the tree root, and the exclude patterns
//! were recorded already resolved against it, which is what
//! `lib/internal/fs/glob.js` does before calling the binding.

use std::path::{Path, PathBuf};

use rn_bind_glob::matcher::CompiledPattern;
use rn_bind_glob::parser::CompileFlags;
use rn_bind_glob::walker::{glob_sync, WalkOptions, DIRENT_DIR, DIRENT_FILE, DIRENT_LINK};

/// One recorded walk: the arguments and Node's answer.
struct Case {
    label: String,
    pattern: String,
    exclude: Vec<String>,
    max_depth: Option<usize>,
    option: Option<String>,
    expected: Vec<String>,
}

/// A temporary directory that removes itself.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    /// Builds the tree the fixture was recorded from.
    fn build(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rn-bind-glob-walk-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["a/sub", "b/sub", "c", ".git/objects"] {
            std::fs::create_dir_all(root.join(dir)).expect("mkdir");
        }
        for file in [
            "top.js",
            "a/one.js",
            "a/sub/two.js",
            "b/sub/three.js",
            "c/four.txt",
            ".dot.js",
            ".git/objects/o.js",
        ] {
            std::fs::write(root.join(file), b"").expect("write");
        }
        // A relative link to a directory and an absolute one, so following and
        // not following them are both observable.
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("../a", root.join("b/linktoa"));
            let _ = std::os::unix::fs::symlink(root.join("c"), root.join("abslink"));
        }
        Self { root }
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn load_cases() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("walk.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let value: serde_json::Value = serde_json::from_str(&text).expect("walk.json parses");
    let entries = value["entries"].as_array().expect("entries array");
    entries
        .iter()
        .map(|entry| Case {
            label: entry["label"].as_str().unwrap_or_default().to_string(),
            pattern: entry["pattern"].as_str().unwrap_or_default().to_string(),
            exclude: entry["exclude"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            max_depth: entry["maxDepth"].as_u64().map(|depth| depth as usize),
            option: entry["option"].as_str().map(str::to_string),
            expected: entry["expected"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

fn flags_for(option: Option<&str>, windows: bool) -> CompileFlags {
    let nocase = cfg!(any(windows, target_os = "macos"));
    match option {
        Some("dot") => CompileFlags {
            windows,
            nocase,
            nocase_magic_only: true,
            dot: true,
            match_base: false,
        },
        _ => CompileFlags {
            windows,
            nocase,
            nocase_magic_only: true,
            dot: false,
            match_base: false,
        },
    }
}

#[test]
fn every_recorded_walk_matches_node() {
    // Only the symlink cases depend on the host, and only `unix` can create
    // them; on other platforms the fixture's link entries cannot exist.
    if !cfg!(unix) {
        eprintln!("skipping: the recorded tree uses symlinks");
        return;
    }
    let cases = load_cases();
    assert!(!cases.is_empty(), "expected recorded walk cases");

    let tree = TempTree::build("walk");
    let mut failures = Vec::new();
    for case in &cases {
        let cwd = match case.option.as_deref() {
            Some("cwd:a") => tree.root.join("a").to_string_lossy().into_owned(),
            _ => tree.root.to_string_lossy().into_owned(),
        };
        let follow = case.option.as_deref() == Some("follow");
        let windowless = cfg!(windows);
        let flags = flags_for(case.option.as_deref(), windowless);
        let include =
            CompiledPattern::from_pattern(&case.pattern.encode_utf16().collect::<Vec<_>>(), flags)
                .expect("the recorded pattern compiles");

        // The fixture's excludes were resolved against the recorded cwd, so the
        // same substitution is applied to this temporary tree.
        let mut exclude_flags = flags;
        exclude_flags.nocase_magic_only = false;
        let excludes: Vec<CompiledPattern> = case
            .exclude
            .iter()
            .map(|pattern| {
                let resolved = pattern.replace("/tmp/tree/t2", &tree.root.to_string_lossy());
                CompiledPattern::from_pattern(
                    &resolved.encode_utf16().collect::<Vec<_>>(),
                    exclude_flags,
                )
                .expect("the recorded exclude compiles")
            })
            .collect();

        let options = WalkOptions {
            cwd: cwd.clone(),
            follow_symlinks: follow,
            with_file_types: false,
            max_depth: case.max_depth,
        };
        let entries = glob_sync(
            &options,
            std::slice::from_ref(&include),
            &excludes,
            exclude_flags,
            None,
        )
        .expect("walk completes");
        let actual: Vec<String> = entries.iter().map(|entry| entry.path.clone()).collect();
        if actual != case.expected {
            failures.push(format!(
                "{}\n    expected {:?}\n    actual   {:?}",
                case.label, case.expected, actual
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} walks disagree with node:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn file_types_distinguish_directories_files_and_links() {
    if !cfg!(unix) {
        eprintln!("skipping: the recorded tree uses symlinks");
        return;
    }
    let tree = TempTree::build("types");
    let flags = flags_for(None, cfg!(windows));
    let include = CompiledPattern::from_pattern(&"*".encode_utf16().collect::<Vec<_>>(), flags)
        .expect("compiles");
    let options = WalkOptions {
        cwd: tree.root.to_string_lossy().into_owned(),
        follow_symlinks: false,
        with_file_types: true,
        max_depth: None,
    };
    let entries = glob_sync(&options, std::slice::from_ref(&include), &[], flags, None)
        .expect("walk completes");
    let find = |name: &str| {
        entries
            .iter()
            .find(|entry| entry.path == name)
            .unwrap_or_else(|| panic!("expected {name} in the walk"))
            .kind
    };
    assert_eq!(find("a"), DIRENT_DIR);
    assert_eq!(find("top.js"), DIRENT_FILE);
    assert_eq!(find("abslink"), DIRENT_LINK);
}

#[test]
fn a_dotfile_is_hidden_unless_the_dot_flag_is_set() {
    if !cfg!(unix) {
        return;
    }
    let tree = TempTree::build("dot");
    let plain = flags_for(None, cfg!(windows));
    let dotted = flags_for(Some("dot"), cfg!(windows));
    let options = WalkOptions {
        cwd: tree.root.to_string_lossy().into_owned(),
        follow_symlinks: false,
        with_file_types: false,
        max_depth: None,
    };
    let run = |flags: CompileFlags| {
        let include = CompiledPattern::from_pattern(&"*".encode_utf16().collect::<Vec<_>>(), flags)
            .expect("compiles");
        glob_sync(&options, std::slice::from_ref(&include), &[], flags, None)
            .expect("walk completes")
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>()
    };
    assert!(!run(plain).iter().any(|path| path == ".dot.js"));
    assert!(run(dotted).iter().any(|path| path == ".dot.js"));
}
