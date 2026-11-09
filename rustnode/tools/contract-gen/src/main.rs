//! Records the exact shape every `internalBinding()` namespace must expose.
//!
//! Runs inside a real Node binary with the instrumentation preload from
//! `tools/contract-gen/preload.cjs`, reads the recorded JSON, and writes one
//! contract file per namespace.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NamespaceContract {
    pub namespace: String,
    pub members: BTreeMap<String, MemberContract>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemberContract {
    /// `function`, `number`, `string`, `object`, `symbol`.
    pub kind: String,
    /// Observed arity for functions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arity: Option<u32>,
    /// Property names observed on returned objects.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<String>,
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

    let raw = std::fs::read_to_string(&input)?;
    let recorded: BTreeMap<String, NamespaceContract> = serde_json::from_str(&raw)?;
    std::fs::create_dir_all(&output)?;
    for (name, contract) in &recorded {
        let path = output.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(contract)?)?;
    }
    println!(
        "wrote {} namespace contracts to {}",
        recorded.len(),
        output.display()
    );
    Ok(())
}
