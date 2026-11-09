//! Splits the raw recording from `tools/contract-gen/record.cjs` into one
//! contract file per `internalBinding()` namespace.
//!
//! Regenerate every contract with:
//!
//! ```bash
//! cd rustnode && ./tools/contract-gen/generate.sh
//! ```
//!
//! which runs the recorder, then this emitter, then the `rn-compat` shape check.
//!
//! The recorded schema is deliberately small so `rn-compat` can read it:
//!
//! ```json
//! { "namespace": "fs", "members": { "open": { "kind": "function", "arity": 4 } } }
//! ```
//!
//! Two provenance fields are carried alongside and ignored by the checker:
//! `reachable` (false when the recording Node was compiled without the
//! namespace) and per-member `origin` (`runtime`, `static`, or `both`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Contract schema version. Bump when a reader would misinterpret an older
/// file, never for an additive field.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceContract {
    pub namespace: String,
    /// False when the recording binary did not expose the namespace, so the
    /// member list came from the static scan of `lib/**` alone.
    #[serde(default = "default_true")]
    pub reachable: bool,
    /// Why the namespace could not be reached at runtime, when it could not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unreachable_reason: Option<String>,
    pub members: BTreeMap<String, MemberContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberContract {
    /// `function`, `number`, `string`, `object`, `symbol`, `bigint`,
    /// `boolean`, `undefined` or `unknown`.
    pub kind: String,
    /// Observed arity for functions reached at runtime.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub arity: Option<u32>,
    /// Property names observed on returned objects.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<String>,
    /// Where this member's shape came from: `runtime`, `static` or `both`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin: Option<String>,
}

fn default_true() -> bool {
    true
}

/// The `meta` block the recorder writes; kept loosely typed because it is
/// provenance, not contract data.
#[derive(Debug, Default, Deserialize)]
pub struct RecordedMeta {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub builtin_files: usize,
    #[serde(default)]
    pub namespaces: usize,
    #[serde(default)]
    pub members: usize,
    #[serde(default)]
    pub unreachable: usize,
}

#[derive(Debug, Deserialize)]
pub struct Recorded {
    #[serde(default)]
    pub meta: RecordedMeta,
    pub namespaces: BTreeMap<String, NamespaceContract>,
}

/// Reads a recording produced by `record.cjs`.
pub fn load(path: &Path) -> Result<Recorded, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let recorded: Recorded = serde_json::from_str(&raw)?;
    if recorded.namespaces.is_empty() {
        return Err(
            "recording contains no namespaces; run the recorder against a real Node".into(),
        );
    }
    Ok(recorded)
}

/// Writes one pretty-printed JSON contract per namespace, sorted by name.
/// Existing files for namespaces that are no longer present are left alone:
/// removing a contract is a deliberate change, not a side effect of a rerun.
pub fn write_all(recorded: &Recorded, out: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    for (name, contract) in &recorded.namespaces {
        let path = out.join(format!("{name}.json"));
        let mut body = serde_json::to_string_pretty(contract)?;
        body.push('\n');
        std::fs::write(&path, body)?;
    }
    Ok(recorded.namespaces.len())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (input, output) = match args.as_slice() {
        [input, flag, output] if flag == "--out" => (PathBuf::from(input), PathBuf::from(output)),
        _ => {
            eprintln!("usage: contract-gen <recorded.json> --out <contracts-dir>");
            std::process::exit(2);
        }
    };

    let recorded = load(&input)?;
    let written = write_all(&recorded, &output)?;
    let members: usize = recorded.namespaces.values().map(|c| c.members.len()).sum();
    let unreachable: Vec<&str> = recorded
        .namespaces
        .values()
        .filter(|c| !c.reachable)
        .map(|c| c.namespace.as_str())
        .collect();

    println!(
        "wrote {written} namespace contracts ({members} members) to {}",
        output.display()
    );
    if !unreachable.is_empty() {
        println!(
            "{} namespace(s) recorded from the static scan only: {}",
            unreachable.len(),
            unreachable.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "meta": { "schema_version": 1, "builtin_files": 435, "namespaces": 2, "members": 2, "unreachable": 1 },
      "namespaces": {
        "fs": {
          "namespace": "fs",
          "reachable": true,
          "members": {
            "open": { "kind": "function", "arity": 4, "origin": "runtime" },
            "statfs": { "kind": "unknown", "origin": "static" }
          }
        },
        "quic": {
          "namespace": "quic",
          "reachable": false,
          "unreachable_reason": "No such binding: quic",
          "members": { "Endpoint": { "kind": "function", "origin": "static" } }
        }
      }
    }"#;

    fn parse(raw: &str) -> Recorded {
        serde_json::from_str(raw).expect("fixture parses")
    }

    #[test]
    fn reads_reachable_and_static_only_namespaces() {
        let recorded = parse(FIXTURE);
        assert_eq!(recorded.namespaces.len(), 2);
        assert_eq!(recorded.meta.builtin_files, 435);

        let fs = &recorded.namespaces["fs"];
        assert!(fs.reachable);
        assert_eq!(fs.members.len(), 2);
        assert_eq!(fs.members["open"].kind, "function");
        assert_eq!(fs.members["open"].arity, Some(4));

        let quic = &recorded.namespaces["quic"];
        assert!(!quic.reachable);
        assert_eq!(
            quic.unreachable_reason.as_deref(),
            Some("No such binding: quic")
        );
        assert_eq!(quic.members["Endpoint"].kind, "function");
    }

    #[test]
    fn reachable_defaults_to_true_when_absent() {
        let raw = r#"{"namespaces":{"x":{"namespace":"x","members":{}}}}"#;
        let recorded = parse(raw);
        assert!(recorded.namespaces["x"].reachable);
        assert!(recorded.namespaces["x"].unreachable_reason.is_none());
    }

    #[test]
    fn writes_one_file_per_namespace() {
        let dir = std::env::temp_dir().join(format!(
            "contract-gen-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let recorded = parse(FIXTURE);
        let written = write_all(&recorded, &dir).expect("writes");
        assert_eq!(written, 2);

        let fs = std::fs::read_to_string(dir.join("fs.json")).expect("fs contract");
        assert!(fs.contains("\"arity\": 4"));
        // Optional fields stay out of the file instead of becoming null.
        assert!(!fs.contains("null"));

        let quic = std::fs::read_to_string(dir.join("quic.json")).expect("quic contract");
        assert!(quic.contains("\"reachable\": false"));
        assert!(quic.contains("No such binding: quic"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_recording_is_an_error() {
        let dir = std::env::temp_dir().join(format!("contract-gen-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("recorded.json");
        std::fs::write(&path, r#"{"namespaces":{}}"#).expect("write fixture");

        let error = load(&path).expect_err("empty recording must not be accepted");
        assert!(error.to_string().contains("no namespaces"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
