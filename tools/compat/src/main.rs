//! Fails when a Rust binding namespace does not satisfy its recorded contract.

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let contracts_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts"));

    let mut registry = rn_core::BindingRegistry::new();
    rn_bindings::install_all(&mut registry);

    let mut implemented: BTreeMap<String, Namespace> = BTreeMap::new();
    for namespace in registry.namespaces() {
        implemented.insert(namespace.name.clone(), namespace.clone());
    }

    let mut problems = Vec::new();
    if contracts_dir.is_dir() {
        for entry in std::fs::read_dir(&contracts_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let contract: NamespaceContract =
                serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            let Some(namespace) = implemented.get(&contract.namespace) else {
                problems.push(format!(
                    "namespace '{}' is not implemented",
                    contract.namespace
                ));
                continue;
            };
            for member in contract.members.keys() {
                if !namespace.members.contains(member) {
                    problems.push(format!(
                        "'{}' is missing member '{member}'",
                        contract.namespace
                    ));
                }
            }
        }
    } else {
        println!(
            "no contracts in {}; shape check skipped",
            contracts_dir.display()
        );
        return Ok(());
    }

    if problems.is_empty() {
        println!("binding shapes match {} contracts", contracts_dir.display());
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("{problem}");
        }
        std::process::exit(1);
    }
}
