//! One recorded test outcome, shared by the runner and the dashboard.

use serde::{Deserialize, Serialize};

/// Outcome of running a single Node test file against the rustnode binary.
///
/// The file is written as a one-element JSON array so the dashboard can read
/// every `*.json` in a result directory without knowing which runner produced
/// it. Fields added later are optional so old result files keep loading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    /// Path relative to the Node test root, for example `parallel/test-fs-open.js`.
    pub file: String,
    /// First path segment of `file`, for example `parallel`.
    #[serde(default)]
    pub suite: String,
    pub passed: bool,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub timed_out: bool,
    /// `// Flags:` header values passed to the runtime, in order.
    #[serde(default)]
    pub flags: Vec<String>,
    /// First couple of KiB of stdout, where Node's reporters write summaries.
    #[serde(default)]
    pub stdout_head: String,
    /// First couple of KiB of stderr, enough to see why a file failed.
    #[serde(default)]
    pub stderr_head: String,
}

impl FileResult {
    /// Builds a result for a test that never got to run.
    pub fn not_run(file: &str, reason: impl Into<String>) -> Self {
        let (suite, _) = split_path(file);
        Self {
            file: file.to_string(),
            suite: suite.to_string(),
            passed: false,
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            flags: Vec::new(),
            stdout_head: String::new(),
            stderr_head: reason.into(),
        }
    }
}

/// Splits `parallel/test-fs-open.js` into (`parallel`, `test-fs-open.js`).
pub fn split_path(file: &str) -> (&str, &str) {
    match file.split_once('/') {
        Some((suite, rest)) => (suite, rest),
        None => ("", file),
    }
}

/// The suite directory a test file lives in, for example `es-module`.
pub fn suite_of(file: &str) -> String {
    split_path(file).0.to_string()
}

/// Groups a test file by the subsystem its name advertises.
///
/// `parallel/test-fs-open.js` and `es-module/test-fs-import.mjs` both land in
/// `fs`, which is the unit a binding workstream owns.
pub fn cluster_of(file: &str) -> String {
    let (_, base) = split_path(file);
    let name = base.strip_prefix("test-").unwrap_or(base);
    let name = name
        .strip_suffix(".mjs")
        .or_else(|| name.strip_suffix(".js"))
        .unwrap_or(name);
    let cluster = name.split('-').next().unwrap_or("").trim();
    if cluster.is_empty() {
        "unknown".to_string()
    } else {
        cluster.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_uses_the_first_name_segment() {
        assert_eq!(cluster_of("parallel/test-fs-open.js"), "fs");
        assert_eq!(
            cluster_of("parallel/test-abortcontroller.js"),
            "abortcontroller"
        );
        assert_eq!(cluster_of("es-module/test-esm-loader.mjs"), "esm");
        assert_eq!(cluster_of("internet/test-dgram-connect.js"), "dgram");
    }

    #[test]
    fn cluster_survives_odd_names() {
        assert_eq!(cluster_of("parallel/test-.js"), "unknown");
        assert_eq!(cluster_of("sequential/test-fs-watch.js"), "fs");
    }

    #[test]
    fn result_without_optional_fields_still_loads() {
        let json = r#"[{"file":"parallel/test-x.js","passed":true}]"#;
        let parsed: Vec<FileResult> = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].passed);
        assert_eq!(parsed[0].duration_ms, 0);
        assert!(parsed[0].flags.is_empty());
    }
}
