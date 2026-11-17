//! Worker stack limits must affect recursion depth.
//!
//! Before the fix, `stackSizeMb` was ignored by the worker runtime path, so a
//! small and a large stack limit produced nearly identical call depths.

use std::path::PathBuf;
use std::process::Command;

/// The `rustnode` binary this test should execute.
fn rustnode() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTNODE_BIN") {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("rustnode");
    path.exists().then_some(path)
}

fn run(source: &str) -> Option<(i32, String, String)> {
    let binary = rustnode()?;
    let output = Command::new(binary).arg("-e").arg(source).output().ok()?;
    Some((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

#[test]
fn worker_stack_size_mb_changes_the_stack_overflow_depth() {
    let source = r#"
      const { Worker } = require('worker_threads');
      const sizes = [0.5, 8];
      const workerSource = `
        const { parentPort, resourceLimits } = require('worker_threads');
        let depth = 0;
        function dive() { depth += 1; dive(); }
        try {
          dive();
        } catch (error) {
          parentPort.postMessage({
            stackSizeMb: resourceLimits.stackSizeMb,
            name: error && error.name,
            message: error && error.message,
            depth,
          });
        }
      `;

      (async () => {
        for (const stackSizeMb of sizes) {
          const result = await new Promise((resolve, reject) => {
            const worker = new Worker(workerSource, {
              eval: true,
              resourceLimits: { stackSizeMb },
            });
            worker.once('message', resolve);
            worker.once('error', reject);
          });
          console.log(JSON.stringify({ input: stackSizeMb, ...result }));
        }
      })().catch((error) => {
        console.error(error && error.stack || error);
        process.exitCode = 1;
      });
    "#;

    let Some((code, stdout, stderr)) = run(source) else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return;
    };
    assert_eq!(code, 0, "stderr: {stderr}");

    let rows: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}")))
        .collect();
    assert_eq!(rows.len(), 2, "stdout: {stdout:?}");

    let by_input = |input: f64| {
        rows.iter()
            .find(|row| row.get("input").and_then(serde_json::Value::as_f64) == Some(input))
            .unwrap_or_else(|| panic!("missing row for input {input}: {stdout}"))
    };
    let low = by_input(0.5);
    let high = by_input(8.0);
    for row in [low, high] {
        assert_eq!(row["name"].as_str(), Some("RangeError"), "row: {row}");
        assert_eq!(
            row["message"].as_str(),
            Some("Maximum call stack size exceeded"),
            "row: {row}"
        );
    }

    let low_depth = low["depth"].as_u64().unwrap_or(0);
    let high_depth = high["depth"].as_u64().unwrap_or(0);
    assert!(
        high_depth > low_depth.saturating_mul(4),
        "expected 8 MiB to allow far deeper recursion than 0.5 MiB; \
         low={low_depth}, high={high_depth}, stdout={stdout:?}"
    );
}
