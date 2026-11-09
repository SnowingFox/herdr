//! Checks Rust binding namespaces against contracts recorded from a real Node
//! binary.
//!
//! Policy, which exists because the namespaces land one workstream at a time:
//!
//! - A namespace that is registered but incomplete is a hard failure. Claiming
//!   part of a namespace is worse than claiming none, because the JavaScript
//!   layer reads the missing members and silently gets `undefined`.
//! - A namespace that is not registered at all is reported, not failed. CI
//!   cannot be red for seventy not-yet-written bindings.
//! - `--strict` closes the gap for release gating: every contract must be
//!   implemented and complete.
//! - `--report` never fails; it prints the coverage table.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rn_core::Namespace;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NamespaceContract {
    namespace: String,
    members: BTreeMap<String, MemberContract>,
}

#[derive(Debug, Deserialize)]
struct MemberContract {
    #[allow(dead_code)]
    kind: String,
}

struct Options {
    contracts_dir: PathBuf,
    strict: bool,
    report: bool,
}

fn parse_options() -> Options {
    let mut contracts_dir = None;
    let mut strict = false;
    let mut report = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--strict" => strict = true,
            "--report" => report = true,
            other if other.starts_with("--") => {
                eprintln!("unknown option {other}");
                std::process::exit(2);
            },
            other => contracts_dir = Some(PathBuf::from(other)),
        }
    }

    Options {
        contracts_dir: contracts_dir.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
        }),
        strict,
        report,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_options();

    let mut registry = rn_core::BindingRegistry::new();
    rn_bindings::install_all(&mut registry);

    let implemented: BTreeMap<String, Namespace> = registry
        .namespaces()
        .iter()
        .map(|namespace| (namespace.name.clone(), namespace.clone()))
        .collect();

    if !options.contracts_dir.is_dir() {
        println!(
            "no contracts in {}; shape check skipped",
            options.contracts_dir.display()
        );
        return Ok(());
    }

    let mut contracts = Vec::new();
    for entry in std::fs::read_dir(&options.contracts_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        contracts.push(serde_json::from_str::<NamespaceContract>(
            &std::fs::read_to_string(&path)?,
        )?);
    }
    contracts.sort_by(|a, b| a.namespace.cmp(&b.namespace));

    let mut incomplete = Vec::new();
    let mut absent = Vec::new();
    let mut complete = 0usize;
    let mut recorded_members = 0usize;
    let mut covered_members = 0usize;

    for contract in &contracts {
        let expected = contract.members.len();
        recorded_members += expected;
        match implemented.get(&contract.namespace) {
            Some(namespace) => {
                let missing: Vec<&String> = contract
                    .members
                    .keys()
                    .filter(|member| !namespace.members.contains(*member))
                    .collect();
                covered_members += expected - missing.len();
                if missing.is_empty() {
                    complete += 1;
                } else {
                    incomplete.push((contract.namespace.clone(), expected, missing));
                }
            },
            None => absent.push((contract.namespace.clone(), expected)),
        }
    }

    if options.report {
        print_report(contracts.len(), complete, &incomplete, &absent);
        return Ok(());
    }

    for (namespace, expected, missing) in &incomplete {
        eprintln!(
            "'{namespace}' registers {} of {expected} recorded members and is missing: {}",
            expected - missing.len(),
            missing
                .iter()
                .map(|member| member.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for (namespace, expected) in &absent {
        eprintln!("'{namespace}' is not implemented yet ({expected} recorded members)");
    }

    let mut failed = !incomplete.is_empty() || (options.strict && !absent.is_empty());
    if options.strict && !absent.is_empty() {
        failed = true;
    }

    if failed {
        return Err(format!(
            "{} namespace(s) incomplete, {} not implemented, {} complete of {}",
            incomplete.len(),
            absent.len(),
            complete,
            contracts.len()
        )
        .into());
    }

    println!(
        "binding shapes ok: {complete} namespace(s) complete, {} recorded members, \
         {} namespace(s) still to implement",
        recorded_members,
        absent.len()
    );
    let _ = covered_members;
    Ok(())
}

fn print_report(
    total: usize,
    complete: usize,
    incomplete: &[(String, usize, Vec<&String>)],
    absent: &[(String, usize)],
) {
    println!(
        "{:<24} {:>8} {:>8}  {}",
        "namespace", "recorded", "missing", "status"
    );
    for (namespace, expected, missing) in incomplete {
        println!(
            "{:<24} {:>8} {:>8}  incomplete",
            namespace,
            expected,
            missing.len()
        );
    }
    for (namespace, expected) in absent {
        println!("{:<24} {:>8} {:>8}  not started", namespace, expected, expected);
    }
    println!(
        "\n{complete} of {total} namespaces complete, {} incomplete, {} not started",
        incomplete.len(),
        absent.len()
    );
}
