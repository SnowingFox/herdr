//! Checks Rust binding namespaces against the generated contracts in
//! `rustnode/contracts/`.
//!
//! ```bash
//! cargo run -p rn-compat -- contracts            # fail on real mismatches
//! cargo run -p rn-compat -- contracts --report   # table, always exit 0
//! cargo run -p rn-compat -- contracts <dir>      # alternate contracts dir
//! ```
//!
//! Exit codes:
//!   0  contracts absent (nothing to check), all registered namespaces
//!      satisfied their contract, or `--report` was given
//!   1  a namespace that claims members does not cover its contract
//!   2  usage error, or a contract file that cannot be read
//!
//! Most namespaces have no Rust implementation yet. An unregistered namespace
//! and an empty placeholder registration (`Namespace::empty`) are bring-up
//! state and never fail the check; a namespace that claims *some* members must
//! claim all of them, so a partial implementation is a real mismatch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rn_core::Namespace;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NamespaceContract {
    namespace: String,
    /// False when the recording binary was compiled without the namespace, so
    /// the contract comes from the static scan only.
    #[serde(default = "default_true")]
    reachable: bool,
    members: BTreeMap<String, MemberContract>,
}

#[derive(Debug, Deserialize)]
struct MemberContract {
    /// Recorded kind; shown by `--report` so a mismatch is diagnosable without
    /// opening the contract file.
    #[serde(default = "default_kind")]
    kind: String,
}

fn default_true() -> bool {
    true
}

fn default_kind() -> String {
    "unknown".to_string()
}

#[derive(Debug, Default)]
struct Options {
    contracts_dir: PathBuf,
    report: bool,
    fail_on_unimplemented: bool,
    quiet: bool,
}

/// One namespace's outcome after checking.
#[derive(Debug)]
struct Row {
    namespace: String,
    /// False when the Rust registry has no such namespace at all.
    implemented: bool,
    /// False for a placeholder registration (`Namespace::empty`), which claims
    /// no members yet. Placeholder gaps are bring-up work, not mismatches;
    /// once a namespace claims any member it must claim all of them.
    claimed: bool,
    missing: Vec<String>,
    /// Recorded kind per missing member, for the problem lines.
    missing_kinds: Vec<String>,
    required: usize,
    reachable: bool,
}

const USAGE: &str = "\
usage: rn-compat contracts [<contracts-dir>] [--report] [--fail-on-unimplemented] [--quiet]

  contracts                  check the Rust registry against contracts/
  contracts <dir>            check against another directory
  --report                   print a per-namespace table, always exit 0
                             (unless --fail-on-unimplemented also finds gaps)
  --fail-on-unimplemented    with --report, exit 1 when a contract has no
                             Rust namespace yet
  --quiet                    only print problems";

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        contracts_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts"),
        ..Options::default()
    };
    let mut saw_subcommand = false;
    for arg in args {
        match arg.as_str() {
            "contracts" if !saw_subcommand => saw_subcommand = true,
            "--report" => options.report = true,
            "--fail-on-unimplemented" => options.fail_on_unimplemented = true,
            "--quiet" => options.quiet = true,
            "-h" | "--help" => return Err(USAGE.to_string()),
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}\n\n{USAGE}"));
            }
            other => options.contracts_dir = PathBuf::from(other),
        }
    }
    if !saw_subcommand {
        return Err(format!("missing 'contracts' subcommand\n\n{USAGE}"));
    }
    Ok(options)
}

fn load_contracts(dir: &Path) -> Result<Vec<NamespaceContract>, Box<dyn std::error::Error>> {
    let mut contracts = Vec::new();
    // A missing directory is not an error: the checker is a no-op until the
    // recorder has run at least once.
    if !dir.is_dir() {
        return Ok(contracts);
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    for path in paths {
        let raw = std::fs::read_to_string(&path)?;
        let contract: NamespaceContract =
            serde_json::from_str(&raw).map_err(|error| format!("{}: {error}", path.display()))?;
        contracts.push(contract);
    }
    Ok(contracts)
}

fn check(contracts: &[NamespaceContract], registry: &[Namespace]) -> Vec<Row> {
    let implemented: BTreeMap<&str, &Namespace> =
        registry.iter().map(|ns| (ns.name.as_str(), ns)).collect();

    let mut rows = Vec::with_capacity(contracts.len());
    for contract in contracts {
        let Some(namespace) = implemented.get(contract.namespace.as_str()) else {
            rows.push(Row {
                namespace: contract.namespace.clone(),
                implemented: false,
                claimed: false,
                missing: Vec::new(),
                missing_kinds: Vec::new(),
                required: contract.members.len(),
                reachable: contract.reachable,
            });
            continue;
        };
        let missing: Vec<(&String, &MemberContract)> = contract
            .members
            .iter()
            .filter(|(member, _)| !namespace.members.contains(*member))
            .collect();
        rows.push(Row {
            namespace: contract.namespace.clone(),
            implemented: true,
            claimed: !namespace.members.is_empty(),
            missing: missing.iter().map(|(name, _)| (*name).clone()).collect(),
            missing_kinds: missing
                .iter()
                .map(|(_, member)| member.kind.clone())
                .collect(),
            required: contract.members.len(),
            reachable: contract.reachable,
        });
    }
    rows
}

fn print_report(rows: &[Row]) {
    let width = rows
        .iter()
        .map(|row| row.namespace.len())
        .max()
        .unwrap_or(9)
        .max("namespace".len());

    println!(
        "{:<width$}  {:>9}  {:>7}  status",
        "namespace",
        "recorded",
        "missing",
        width = width
    );
    println!("{}", "-".repeat(width + 30));
    for row in rows {
        let status = if !row.implemented {
            if row.reachable {
                "not implemented"
            } else {
                "not implemented (static-only contract)"
            }
        } else if row.missing.is_empty() {
            "ok"
        } else if row.claimed {
            "MISMATCH"
        } else {
            "placeholder"
        };
        let missing = row.missing_count().to_string();
        println!(
            "{:<width$}  {:>9}  {:>7}  {status}",
            row.namespace,
            row.required,
            missing,
            width = width
        );
    }

    let implemented = rows.iter().filter(|row| row.implemented).count();
    let satisfied = rows
        .iter()
        .filter(|row| row.implemented && row.missing.is_empty())
        .count();
    let recorded: usize = rows.iter().map(|row| row.required).sum();
    let missing: usize = rows.iter().map(Row::missing_count).sum();
    let mismatched = rows.iter().filter(|row| row.is_mismatch()).count();
    println!("{}", "-".repeat(width + 30));
    println!(
        "{implemented}/{} namespaces registered, {satisfied} satisfied, {mismatched} mismatched, \
         {recorded} members recorded, {missing} missing",
        rows.len()
    );
}

impl Row {
    /// Recorded members this namespace does not provide. An unregistered
    /// namespace is missing all of them; a placeholder is missing all of them
    /// too, because it claims none.
    fn missing_count(&self) -> usize {
        if self.implemented {
            self.missing.len()
        } else {
            self.required
        }
    }

    /// True when a namespace claims members but does not cover its contract.
    /// A placeholder registration and an absent namespace are bring-up state.
    fn is_mismatch(&self) -> bool {
        self.implemented && self.claimed && !self.missing.is_empty()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_args(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let contracts = match load_contracts(&options.contracts_dir) {
        Ok(contracts) => contracts,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    if contracts.is_empty() {
        println!(
            "no contracts in {}; shape check skipped",
            options.contracts_dir.display()
        );
        return Ok(());
    }

    let mut registry = rn_core::BindingRegistry::new();
    rn_bindings::install_all(&mut registry);
    let namespaces = registry.namespaces().to_vec();
    let rows = check(&contracts, &namespaces);

    let mismatches: Vec<&Row> = rows.iter().filter(|row| row.is_mismatch()).collect();
    let unregistered = rows.iter().filter(|row| !row.implemented).count();
    let placeholders = rows
        .iter()
        .filter(|row| row.implemented && !row.claimed)
        .count();

    if options.report {
        print_report(&rows);
        for row in &mismatches {
            eprintln!(
                "'{}' is missing {} member(s): {}",
                row.namespace,
                row.missing.len(),
                row.missing
                    .iter()
                    .zip(&row.missing_kinds)
                    .map(|(name, kind)| format!("{name} ({kind})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if options.fail_on_unimplemented && unregistered > 0 {
            eprintln!("{unregistered} namespace(s) have no Rust implementation");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Every namespace's status is summarised on one line each, so the plain
    // mode answers "how many recorded members are missing" for all 73 without
    // needing --report. Only a claimed-but-incomplete namespace fails.
    if !options.quiet {
        for row in &rows {
            let status = if !row.implemented {
                "unregistered"
            } else if row.missing.is_empty() {
                "ok"
            } else if row.claimed {
                "MISMATCH"
            } else {
                "placeholder"
            };
            println!(
                "{:<24} {:>4} recorded  {:>4} missing  {status}",
                row.namespace,
                row.required,
                row.missing_count()
            );
        }
    }

    if mismatches.is_empty() {
        if !options.quiet {
            println!(
                "binding shapes match {} contracts \
                 ({unregistered} namespace(s) unregistered, {placeholders} placeholder)",
                options.contracts_dir.display()
            );
        }
        return Ok(());
    }

    for row in &mismatches {
        for (member, kind) in row.missing.iter().zip(&row.missing_kinds) {
            eprintln!("'{}' is missing member '{member}' ({kind})", row.namespace);
        }
    }
    eprintln!("{} namespace(s) failed their contract", mismatches.len());
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(namespace: &str, members: &[&str]) -> NamespaceContract {
        NamespaceContract {
            namespace: namespace.to_string(),
            reachable: true,
            members: members
                .iter()
                .map(|name| {
                    (
                        (*name).to_string(),
                        MemberContract {
                            kind: "function".to_string(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn registry(namespaces: &[(&str, &[&str])]) -> Vec<Namespace> {
        namespaces
            .iter()
            .map(|(name, members)| Namespace::new(*name, members))
            .collect()
    }

    #[test]
    fn complete_namespace_has_no_missing_members() {
        let rows = check(
            &[contract("fs", &["open", "close"])],
            &registry(&[("fs", &["open", "close", "extra"])]),
        );
        assert_eq!(rows.len(), 1);
        assert!(rows[0].implemented);
        assert!(rows[0].claimed);
        assert!(rows[0].missing.is_empty());
        assert!(!rows[0].is_mismatch());
    }

    #[test]
    fn missing_members_are_reported_per_namespace() {
        let rows = check(
            &[contract("fs", &["open", "readFileUtf8"])],
            &registry(&[("fs", &["open"])]),
        );
        assert_eq!(rows[0].missing, vec!["readFileUtf8".to_string()]);
        assert_eq!(rows[0].required, 2);
        assert!(
            rows[0].is_mismatch(),
            "a partial implementation is a mismatch"
        );
    }

    #[test]
    fn unimplemented_namespace_is_not_a_member_mismatch() {
        let rows = check(&[contract("quic", &["Endpoint"])], &registry(&[]));
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].implemented);
        // No fabricated member-level failure: the whole namespace is absent.
        assert!(rows[0].missing.is_empty());
        assert_eq!(rows[0].required, 1);
        assert!(!rows[0].is_mismatch(), "bring-up state is not a failure");
    }

    #[test]
    fn placeholder_registration_is_not_a_mismatch() {
        // `Namespace::empty("util")` claims no members yet, so every recorded
        // member is missing but nothing is contradicted.
        let rows = check(
            &[contract("util", &["a", "b"])],
            &registry(&[("util", &[])]),
        );
        assert!(rows[0].implemented);
        assert!(!rows[0].claimed);
        assert_eq!(rows[0].missing, vec!["a".to_string(), "b".to_string()]);
        assert!(!rows[0].is_mismatch());
    }

    #[test]
    fn static_only_contract_still_checks_when_claimed() {
        let mut contract = contract("quic", &["Endpoint"]);
        contract.reachable = false;
        let rows = check(&[contract], &registry(&[("quic", &["Endpoint"])]));
        assert!(rows[0].implemented);
        assert!(!rows[0].reachable);
        assert!(rows[0].missing.is_empty());
        assert!(!rows[0].is_mismatch());
    }

    #[test]
    fn missing_count_includes_whole_contract_for_unregistered() {
        // An unregistered namespace provides none of its members; reporting 0
        // would misrepresent the gap.
        let rows = check(
            &[contract("quic", &["Endpoint", "sendHeaders"])],
            &registry(&[]),
        );
        assert_eq!(rows[0].missing.len(), 0, "no per-member accounting exists");
        assert_eq!(rows[0].missing_count(), 2, "but both members are absent");

        let rows = check(
            &[contract("util", &["a", "b"])],
            &registry(&[("util", &[])]),
        );
        assert_eq!(rows[0].missing_count(), 2);

        let rows = check(&[contract("fs", &["a", "b"])], &registry(&[("fs", &["a"])]));
        assert_eq!(rows[0].missing_count(), 1);
    }

    #[test]
    fn rows_are_sorted_by_contract_order_from_disk() {
        // `load_contracts` sorts paths, which `check` preserves, so the report
        // is stable no matter what order the filesystem returns entries in.
        let rows = check(
            &[contract("async_wrap", &["a"]), contract("zlib", &["b"])],
            &registry(&[("async_wrap", &["a"]), ("zlib", &["b"])]),
        );
        assert_eq!(rows[0].namespace, "async_wrap");
        assert_eq!(rows[1].namespace, "zlib");
    }

    #[test]
    fn absent_directory_yields_no_contracts() {
        let missing = std::env::temp_dir().join("rn-compat-no-such-dir-xyz");
        let contracts = load_contracts(&missing).expect("absent dir is not an error");
        assert!(contracts.is_empty());
    }

    #[test]
    fn contract_without_reachable_flag_defaults_to_reachable() {
        let raw = r#"{"namespace":"fs","members":{"open":{"kind":"function"}}}"#;
        let parsed: NamespaceContract = serde_json::from_str(raw).expect("parses");
        assert!(parsed.reachable);
        assert_eq!(parsed.members["open"].kind, "function");

        // A member written without a kind still parses.
        let raw = r#"{"namespace":"fs","members":{"open":{}}}"#;
        let parsed: NamespaceContract = serde_json::from_str(raw).expect("parses");
        assert_eq!(parsed.members["open"].kind, "unknown");
    }

    #[test]
    fn parses_the_subcommand_and_flags() {
        let args: Vec<String> = ["contracts", "--report"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let options = parse_args(&args).expect("valid");
        assert!(options.report);
        assert!(!options.fail_on_unimplemented);

        let args: Vec<String> = ["contracts", "/tmp/x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            parse_args(&args).expect("valid").contracts_dir,
            PathBuf::from("/tmp/x")
        );

        let args: Vec<String> = std::iter::empty::<String>().collect();
        assert!(parse_args(&args).is_err(), "subcommand is required");

        let args: Vec<String> = ["--report"].iter().map(|s| s.to_string()).collect();
        assert!(parse_args(&args).is_err(), "flags alone are not enough");

        let args: Vec<String> = ["contracts", "--nope"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_args(&args).is_err(), "unknown flags are rejected");
    }
}
