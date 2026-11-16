//! `process`'s own-property set equals the oracle's, per population.
//!
//! The "17 missing members" finding was a hand count, and it was wrong twice
//! over: eleven of the seventeen had already been implemented by the time it was
//! worked on, and four of the rest (`channel`, `connected`, `disconnect`, `send`)
//! are not missing at all outside a child process. A count is not a measurement.
//!
//! # Why this test is population-parameterised
//!
//! `process.channel`, `process.connected`, `process.disconnect` and
//! `process.send` exist only where there is an IPC channel — a forked child
//! (`NODE_CHANNEL_FD`) or, in a degraded form, a worker. `process.permission`
//! exists only under `--permission`. A comparison that samples one population
//! reports those as missing on a runtime that is correct. Measured in the union
//! of the populations where each name exists, rustnode matches the oracle exactly.
//!
//! # What it does not assert
//!
//! Not that every *documented* name is present. `channel`, `connected`,
//! `disconnect`, `send`, `permission` and the four deprecation aliases are all
//! absent from a plain main-thread `process` **on both runtimes**, so requiring
//! them would be requiring Node to differ from itself. The set that matters is
//! `oracle - rustnode`, and it is empty.

use std::process::Command;

/// The probe, which reports one population's names as JSON.
///
/// `HERDR_PROBE_POPULATION` selects the population, so one file measures all
/// three and both runtimes run identical code.
const PROBE: &str = r#"
const names = () => Object.getOwnPropertyNames(process).sort();
const population = process.env.HERDR_PROBE_POPULATION;
if (population === 'worker-child' || population === 'main') {
  process.stdout.write(JSON.stringify({ names: names() }) + '\n');
} else if (population === 'worker') {
  const { Worker } = require('node:worker_threads');
  const worker = new Worker(__filename, {
    env: { ...process.env, HERDR_PROBE_POPULATION: 'worker-child' },
  });
  let text = '';
  worker.stdout.on('data', (chunk) => { text += chunk; });
  worker.on('exit', () => {
    const parsed = text.trim() ? JSON.parse(text.trim()) : { names: null };
    process.stdout.write(JSON.stringify({ names: parsed.names }) + '\n');
  });
} else if (population === 'forked') {
  const { fork } = require('child_process');
  const child = fork(__filename, {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    env: { ...process.env, HERDR_PROBE_POPULATION: 'forked-child' },
  });
  child.on('message', (message) => {
    process.stdout.write(JSON.stringify({ names: message.names }) + '\n');
    child.kill();
  });
  child.on('error', (error) => {
    process.stdout.write(JSON.stringify({ names: null, error: String(error) }) + '\n');
  });
} else {
  process.send({ names: names() }, () => process.exit(0));
}
"#;

/// Writes the probe under a name unique to `tag` and returns its path.
///
/// The tag matters: both tests in this file run concurrently, and a shared path
/// meant one test's cleanup deleted the file the other was still forking. The
/// failure looked like a product defect (`MODULE_NOT_FOUND` from the oracle) and
/// was a fixture race, which is worth the two lines.
fn probe(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "herdr-process-member-parity-{tag}-{}.cjs",
        std::process::id()
    ));
    std::fs::write(&path, PROBE).expect("the probe is writable");
    path
}

/// Runs `binary` for `population` and returns its own-property names.
fn measure(binary: &str, probe: &std::path::Path, population: &str) -> Vec<String> {
    let out = Command::new(binary)
        .arg(probe)
        .env("HERDR_PROBE_POPULATION", population)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("the probe produced JSON");
        assert!(
            parsed["error"].is_null(),
            "{binary} ({population}) failed: {}",
            parsed["error"]
        );
        return parsed["names"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
    }
    panic!(
        "{binary} ({population}) produced no JSON: stdout {:?} stderr {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Each population's own-property set equals the oracle's, exactly.
///
/// Asserted per population rather than on a union: a union would pass if
/// rustnode had `send` on the main thread, where Node has it only in a child. The
/// per-population comparison is what makes a misplaced member fail.
#[test]
fn every_process_population_matches_the_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("process member parity") else {
        return;
    };
    let probe = probe("populations");
    let mut failures = Vec::new();

    for population in ["main", "worker", "forked"] {
        let theirs = measure(oracle.reference_path(), &probe, population);
        let ours = measure(env!("CARGO_BIN_EXE_rustnode"), &probe, population);
        let theirs: std::collections::BTreeSet<&str> = theirs.iter().map(String::as_str).collect();
        let ours: std::collections::BTreeSet<&str> = ours.iter().map(String::as_str).collect();

        let missing: Vec<&&str> = theirs.difference(&ours).collect();
        let extra: Vec<&&str> = ours.difference(&theirs).collect();
        if !missing.is_empty() || !extra.is_empty() {
            failures.push(format!(
                "{population}: missing {missing:?}, extra {extra:?} \
                 (oracle {} names, rustnode {} names)",
                theirs.len(),
                ours.len()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "the process own-property set differs from the oracle:\n  {}",
        failures.join("\n  ")
    );
    let _ = std::fs::remove_file(&probe);
}

/// The four IPC members exist on both runtimes in a forked child, and on neither
/// as a plain main thread.
///
/// This is the assertion that would have stopped the "17 missing members" count
/// from being believed: in the population the finding was measured in, these are
/// absent from **Node too**.
#[test]
fn the_ipc_members_exist_only_where_node_puts_them() {
    let Some(oracle) = rn_node_oracle::require_oracle("process IPC member presence") else {
        return;
    };
    let probe = probe("ipc");
    let ipc = ["channel", "connected", "disconnect", "send"];

    for (population, expected) in [("main", false), ("forked", true)] {
        for binary in [
            oracle.reference_path().to_string(),
            env!("CARGO_BIN_EXE_rustnode").to_string(),
        ] {
            let names = measure(&binary, &probe, population);
            for member in ipc {
                let present = names.iter().any(|name| name == member);
                assert_eq!(
                    present, expected,
                    "{binary}: process.{member} in the {population} population should be \
                     {expected}, the other runtime and this one have to agree"
                );
            }
        }
    }
    let _ = std::fs::remove_file(&probe);
}
