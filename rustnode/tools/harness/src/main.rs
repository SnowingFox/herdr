//! Pass-rate dashboard over Node's own `test/` suite.
//!
//! Reads the recorded per-file results from `tools/harness/results/` and prints
//! a per-cluster summary so each tracking task can see what turned green.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FileResult {
    file: String,
    passed: bool,
}

fn cluster_of(file: &str) -> String {
    let name = file.trim_start_matches("test-");
    name.split('-').next().unwrap_or("unknown").to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results"));

    let mut totals: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    if !dir.is_dir() {
        println!("no results in {}; run the suite first", dir.display());
        return Ok(());
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();

    for path in files {
        let results: Vec<FileResult> = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        for result in results {
            let entry = totals.entry(cluster_of(&result.file)).or_insert((0, 0));
            entry.1 += 1;
            if result.passed {
                entry.0 += 1;
            }
        }
    }

    let mut passed_total = 0;
    let mut total = 0;
    println!(
        "{:<24} {:>8} {:>8} {:>8}",
        "cluster", "passed", "total", "rate"
    );
    for (cluster, (passed, count)) in &totals {
        passed_total += passed;
        total += count;
        println!(
            "{:<24} {:>8} {:>8} {:>7.1}%",
            cluster,
            passed,
            count,
            *passed as f64 / *count as f64 * 100.0
        );
    }
    if total > 0 {
        println!(
            "{:<24} {:>8} {:>8} {:>7.1}%",
            "TOTAL",
            passed_total,
            total,
            passed_total as f64 / total as f64 * 100.0
        );
    }
    Ok(())
}
