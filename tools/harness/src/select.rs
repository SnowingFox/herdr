//! Finds Node test files under a checked-out `test/` tree.
//!
//! Node's own runner treats every `test-*.js` and `test-*.mjs` file as a test
//! and ignores `testcfg.py`, status files and the `common/` helper tree. This
//! module applies the same rule so the two runners select the same files.
//!
//! Selection happens in one of two modes. An explicit path list ([`Filter::only`])
//! is resolved as given, so a named subset such as [`SMOKE_SUBSET`] is stable
//! and reproducible. Otherwise suites are walked in [`SUITES`] order with the
//! name filter applied and the limit taken last.

use std::path::Path;

/// Suites this harness knows how to run, in the order the dashboard shows them.
///
/// `addons`, `js-native-api` and `node-api` are compiled C++ fixtures and
/// `cctest`/`fuzzers` are not JavaScript at all, so they are deliberately absent.
pub const SUITES: &[&str] = &[
    "parallel",
    "sequential",
    "es-module",
    "internet",
    "pummel",
    "message",
    "known_issues",
];

/// Suites that are safe to run concurrently.
///
/// `sequential` exists precisely because those tests cannot share a machine with
/// their siblings, so it is the one suite a parallel run still runs alone.
pub const PARALLEL_SAFE_SUITES: &[&str] = &["parallel", "es-module", "internet", "message"];

/// Small default subset that finishes in seconds.
///
/// It spans the subsystems the first binding workstreams touch — `assert`,
/// `buffer`, `fs`, `path`, `util`, `events`, `querystring`, `string_decoder`,
/// `timers` and one ES module test — so a green run says the runtime can load a
/// builtin and report a result, not that Node compatibility is close.
pub const SMOKE_SUBSET: &[&str] = &[
    "parallel/test-assert.js",
    "parallel/test-buffer-bytelength.js",
    "parallel/test-fs-open.js",
    "parallel/test-path-parse-format.js",
    "parallel/test-util-inspect.js",
    "parallel/test-events-once.js",
    "parallel/test-querystring-escape.js",
    "parallel/test-string-decoder.js",
    "parallel/test-timers-ordering.js",
    "es-module/test-esm-import-meta.mjs",
];

/// A selected test file plus the flags its own header asks for.
#[derive(Debug, Clone)]
pub struct TestFile {
    /// Path relative to the test root, with `/` separators.
    pub relative: String,
    /// `// Flags:` values, in the order Node's runner would pass them.
    pub flags: Vec<String>,
}

/// Everything a run needs to know about which tests it is about to execute.
#[derive(Debug, Clone)]
pub struct Selection {
    pub tests: Vec<TestFile>,
}

/// Filters applied while collecting test files.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Suites to include; empty means every suite in [`SUITES`].
    pub suites: Vec<String>,
    /// Case-insensitive substrings; a file must match at least one.
    pub names: Vec<String>,
    /// Exact relative paths to select, ignoring every other filter.
    pub only: Vec<String>,
    /// Optional cap on the number of selected files.
    pub limit: Option<usize>,
}

impl Filter {
    fn allows_suite(&self, suite: &str) -> bool {
        self.suites.is_empty() || self.suites.iter().any(|wanted| wanted == suite)
    }

    fn allows_name(&self, relative: &str) -> bool {
        if self.names.is_empty() {
            return true;
        }
        let haystack = relative.to_ascii_lowercase();
        self.names
            .iter()
            .any(|needle| haystack.contains(&needle.to_ascii_lowercase()))
    }
}

/// Collects the test files matching `filter` under `root`.
///
/// The order is stable — suite, then path — so `--limit` always selects the same
/// files and two runs are comparable.
pub fn collect(root: &Path, filter: &Filter) -> Result<Selection, String> {
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    if !filter.only.is_empty() {
        return collect_explicit(root, filter);
    }
    let mut tests = Vec::new();
    for suite in SUITES {
        if !filter.allows_suite(suite) {
            continue;
        }
        let suite_dir = root.join(suite);
        if !suite_dir.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        walk(&suite_dir, root, &mut files)?;
        files.sort();
        for relative in files {
            if !filter.allows_name(&relative) {
                continue;
            }
            let flags = read_flags(&root.join(&relative));
            tests.push(TestFile { relative, flags });
        }
    }
    if let Some(limit) = filter.limit {
        tests.truncate(limit);
    }
    Ok(Selection { tests })
}

/// Resolves an explicit list of test paths, in the order given.
///
/// A missing path is an error rather than a silently shorter run, so a named
/// subset that drifts from the pinned Node revision fails loudly.
fn collect_explicit(root: &Path, filter: &Filter) -> Result<Selection, String> {
    let mut tests = Vec::new();
    let mut missing = Vec::new();
    for relative in &filter.only {
        let absolute = root.join(relative);
        if !absolute.is_file() {
            missing.push(relative.clone());
            continue;
        }
        let flags = read_flags(&absolute);
        tests.push(TestFile {
            relative: relative.clone(),
            flags,
        });
    }
    if !missing.is_empty() {
        return Err(format!(
            "{} test path(s) do not exist under {}: {}",
            missing.len(),
            root.display(),
            missing.join(", ")
        ));
    }
    if let Some(limit) = filter.limit {
        tests.truncate(limit);
    }
    Ok(Selection { tests })
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, out)?;
            continue;
        }
        if !is_test_file(&path) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("{} is outside {}", path.display(), root.display()))?;
        out.push(relative.to_string_lossy().replace('\\', "/"));
    }
    Ok(())
}

/// Mirrors Node's `LS_RE`: only `test-*.js` and `test-*.mjs` are tests.
fn is_test_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !name.starts_with("test-") {
        return false;
    }
    name.ends_with(".js") || name.ends_with(".mjs")
}

/// Reads the first `// Flags:` line the way Node's runner does.
///
/// Node takes only the first match in the file, splits it on whitespace, and
/// passes the whole list to the runtime before the script path.
pub fn read_flags(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_flags(&text)
}

/// Extracts `// Flags:` values from source text; public so tests can drive it.
pub fn parse_flags(source: &str) -> Vec<String> {
    for line in source.lines() {
        let Some(rest) = line.trim_start().strip_prefix("//") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("Flags:") else {
            continue;
        };
        return rest.split_whitespace().map(str::to_string).collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(path, body).expect("write");
    }

    fn fixture() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rn-harness-collect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        write(&dir, "parallel/test-fs-open.js", "// Flags: --expose-gc\n");
        write(&dir, "parallel/test-path-parse.js", "'use strict';\n");
        write(&dir, "parallel/helper.js", "// not a test\n");
        write(&dir, "parallel/testcfg.py", "# not a test\n");
        write(&dir, "es-module/test-esm-import.mjs", "export {};\n");
        write(&dir, "sequential/test-fs-watch.js", "");
        dir
    }

    #[test]
    fn collects_only_test_prefixed_scripts() {
        let root = fixture();
        let selection = collect(&root, &Filter::default()).expect("collect");
        let names: Vec<&str> = selection
            .tests
            .iter()
            .map(|t| t.relative.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "parallel/test-fs-open.js",
                "parallel/test-path-parse.js",
                "sequential/test-fs-watch.js",
                "es-module/test-esm-import.mjs",
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn suite_filter_narrows_to_requested_directories() {
        let root = fixture();
        let filter = Filter {
            suites: vec!["sequential".into()],
            ..Filter::default()
        };
        let selection = collect(&root, &filter).expect("collect");
        assert_eq!(selection.tests.len(), 1);
        assert_eq!(selection.tests[0].relative, "sequential/test-fs-watch.js");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn name_filter_is_a_case_insensitive_substring() {
        let root = fixture();
        let filter = Filter {
            names: vec!["FS-".into()],
            ..Filter::default()
        };
        let selection = collect(&root, &filter).expect("collect");
        let names: Vec<&str> = selection
            .tests
            .iter()
            .map(|t| t.relative.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["parallel/test-fs-open.js", "sequential/test-fs-watch.js"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn limit_truncates_after_a_stable_sort() {
        let root = fixture();
        let filter = Filter {
            limit: Some(2),
            ..Filter::default()
        };
        let first = collect(&root, &filter).expect("collect");
        let second = collect(&root, &filter).expect("collect");
        assert_eq!(first.tests[0].relative, second.tests[0].relative);
        assert_eq!(first.tests.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_suite_selects_nothing_instead_of_failing() {
        let root = fixture();
        let filter = Filter {
            suites: vec!["nope".into()],
            ..Filter::default()
        };
        let selection = collect(&root, &filter).expect("collect");
        assert!(selection.tests.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn flags_come_from_the_first_flags_line() {
        let flags = parse_flags("// Flags: --expose-gc --no-warnings\n// Flags: --ignored\n");
        assert_eq!(flags, vec!["--expose-gc", "--no-warnings"]);
    }

    #[test]
    fn flags_default_to_empty() {
        assert!(parse_flags("'use strict';\n").is_empty());
        assert!(parse_flags("  // Flags:\n").is_empty());
    }

    #[test]
    fn missing_test_tree_is_an_error() {
        let error = collect(
            Path::new("/nonexistent/rustnode-harness"),
            &Filter::default(),
        )
        .expect_err("must fail");
        assert!(error.contains("is not a directory"), "{error}");
    }

    #[test]
    fn explicit_paths_keep_the_given_order() {
        let root = fixture();
        let filter = Filter {
            only: vec![
                "sequential/test-fs-watch.js".into(),
                "parallel/test-path-parse.js".into(),
            ],
            // Explicit selection wins over the other filters.
            suites: vec!["parallel".into()],
            names: vec!["nothing-matches-this".into()],
            limit: None,
        };
        let selection = collect(&root, &filter).expect("collect");
        let names: Vec<&str> = selection
            .tests
            .iter()
            .map(|t| t.relative.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["sequential/test-fs-watch.js", "parallel/test-path-parse.js"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_paths_that_do_not_exist_are_reported() {
        let root = fixture();
        let filter = Filter {
            only: vec![
                "parallel/test-path-parse.js".into(),
                "parallel/test-gone.js".into(),
            ],
            ..Filter::default()
        };
        let error = collect(&root, &filter).expect_err("must fail");
        assert!(error.contains("parallel/test-gone.js"), "{error}");
        assert!(!error.contains("test-path-parse.js"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_flags_are_read_from_each_file() {
        let root = fixture();
        let filter = Filter {
            only: vec!["parallel/test-fs-open.js".into()],
            ..Filter::default()
        };
        let selection = collect(&root, &filter).expect("collect");
        assert_eq!(selection.tests[0].flags, vec!["--expose-gc"]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
