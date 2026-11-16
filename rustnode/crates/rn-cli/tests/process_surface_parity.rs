//! The `process` surface compared against the pinned Node oracle, at runtime.
//!
//! `process_bootstrap.rs` is a transcription: it names each property and the
//! shape Node reports, which is a copy of `internal/bootstrap/node.js` that can
//! drift from it in exactly the way the copy it replaced did. This file removes
//! the transcription. It runs the same probe under both binaries and compares
//! the results, so the reference is whatever the pinned Node actually does.
//!
//! # What is compared, and why it is the descriptor
//!
//! Every own property of `process`, with the descriptor of each — `enumerable`,
//! `writable`, `configurable`, and whether it is a get/set pair. A value-only
//! probe is not enough here and has already produced a false pass: `exitCode`
//! read the right value from a plain data property while Node has an accessor
//! with `configurable: false`, and `title` read the right string while the
//! setter did nothing to the process.
//!
//! # Why the globals are sampled twice
//!
//! `globalThis` differs depending on where in the bootstrap it is read, so the
//! comparison is on the sets rather than on a snapshot taken at one arbitrary
//! moment: a name rustnode has that the oracle does not is the defect (`require`
//! and `primordials` were both), and a name the oracle has that rustnode does not
//! is a gap this file reports without failing, because the Web Streams and
//! `perf_hooks` globals are a separate body of work.

use std::process::Command;

/// The probe, run under both binaries.
///
/// Everything it needs comes from the running engine: no expected value is
/// written down here, which is the property that makes this a differential test
/// rather than a second transcription.
const PROBE: &str = r#"
const descriptorOf = (target, key) => {
  const d = Object.getOwnPropertyDescriptor(target, key);
  if (!d) return null;
  return {
    kind: d.get || d.set ? 'accessor' : 'data',
    enumerable: d.enumerable,
    writable: d.writable === undefined ? null : d.writable,
    configurable: d.configurable,
    hasGet: typeof d.get === 'function',
    hasSet: typeof d.set === 'function',
    valueType: d.get || d.set ? null : typeof d.value,
  };
};
const members = {};
for (const key of Object.getOwnPropertyNames(process)) {
  members[key] = descriptorOf(process, key);
}
const tag = descriptorOf(process, Symbol.toStringTag);
const globals = Object.getOwnPropertyNames(globalThis).sort();

process.stdout.write(JSON.stringify({
  version: process.version,
  members,
  toStringTag: tag,
  globals,
  // Values that are cheap to compare and load-bearing for behaviour.
  values: {
    titleType: typeof process.title,
    debugPortType: typeof process.debugPort,
    domainIsNull: process.domain === null,
    sourceMaps: process.sourceMapsEnabled,
    setSourceMapsType: typeof process.setSourceMapsEnabled,
    exitCodeUnset: process.exitCode === undefined,
    maxListenersUnset: process._maxListeners === undefined,
  },
}));
"#;

fn run(binary: &str, args: &[&str], source: &str) -> String {
    let out = Command::new(binary)
        .args(args)
        .arg("-e")
        .arg(source)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    assert!(
        out.status.success(),
        "{binary} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The pinned oracle, or `None` when it is absent.
///
/// Absence is a skip with a message, not a silent pass: `rn_node_oracle` resolves
/// the pin from `tools/node-pin.toml`, so a missing oracle means the gate's
/// fetch step did not run and there is nothing to compare against.
fn oracle() -> Option<rn_node_oracle::Oracle> {
    rn_node_oracle::require_oracle("rn-cli process surface")
}

/// Runs the probe under both binaries and returns the parsed pair.
fn both() -> Option<(serde_json::Value, serde_json::Value)> {
    let oracle = oracle()?;
    let ours = run(
        env!("CARGO_BIN_EXE_rustnode"),
        &["--expose-internals"],
        PROBE,
    );
    let theirs = run(oracle.reference_path(), &["--expose-internals"], PROBE);
    Some((
        serde_json::from_str(&ours).expect("rustnode probe produced JSON"),
        serde_json::from_str(&theirs).expect("oracle probe produced JSON"),
    ))
}

/// Every own `process` property Node has, rustnode has, with the same descriptor.
///
/// This is the assertion the 17-missing-members finding needed: it cannot go
/// stale, because the expected set is read from the oracle on every run rather
/// than copied from it. It is also what caught `exitCode` and `_exiting`
/// reporting as data properties after they had been made to exist.
#[test]
fn every_process_member_matches_the_oracle_descriptor() {
    let Some((ours, theirs)) = both() else {
        return;
    };
    let ours = ours["members"].as_object().expect("a member map");
    let theirs = theirs["members"].as_object().expect("a member map");

    let mut problems = Vec::new();
    for (name, expected) in theirs {
        match ours.get(name) {
            None => problems.push(format!("{name}: missing")),
            Some(actual) if actual != expected => {
                problems.push(format!("{name}: {actual} != oracle {expected}"))
            }
            Some(_) => {}
        }
    }
    for name in ours.keys() {
        if !theirs.contains_key(name) {
            problems.push(format!("{name}: present here, absent in the oracle"));
        }
    }
    assert!(
        problems.is_empty(),
        "the process surface differs from the oracle on {} member(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

/// `process[Symbol.toStringTag]` matches, including `configurable: false`.
#[test]
fn the_process_to_string_tag_matches_the_oracle() {
    let Some((ours, theirs)) = both() else {
        return;
    };
    assert_eq!(
        ours["toStringTag"], theirs["toStringTag"],
        "the Symbol.toStringTag descriptor differs from the oracle"
    );
    assert_eq!(
        ours["toStringTag"]["valueType"], "string",
        "the tag has to be a string"
    );
}

/// The values behind the descriptors.
#[test]
fn the_process_values_match_the_oracle() {
    let Some((ours, theirs)) = both() else {
        return;
    };
    assert_eq!(
        ours["values"], theirs["values"],
        "the process values differ from the oracle"
    );
}

/// `globalThis` has no name the oracle does not, except the allowlisted additions.
///
/// The direction that matters is the first one: a leaked `primordials` or
/// `require` is an *extra* name, and `test/common/index.js` fails any test whose
/// process has one. A missing name is reported rather than failed, because the
/// Web Streams and `perf_hooks` globals are a separate gap.
///
/// # Why `Bun` is allowed here
///
/// `Bun` is the one global rustnode adds on purpose, and it is not a leak. It is
/// installed by `rn-realm::install_early_globals` in every mode, it is
/// non-enumerable so `common/index.js`'s audit does not see it, and
/// `crates/rn-cli/tests/m0_foundation.rs` pins the enumerable count at 9 with it
/// present. Listing it here is what makes the test's claim precise: every name
/// other than `Bun` must be one Node has too, and `Bun` must be the *only*
/// exception. A second entry here would be a second exception nobody reviewed.
const DELIBERATE_ADDITIONS: &[&str] = &["Bun"];

#[test]
fn global_this_leaks_nothing_the_oracle_hides() {
    let Some((ours, theirs)) = both() else {
        return;
    };
    let ours: Vec<&str> = ours["globals"]
        .as_array()
        .expect("a name list")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();
    let theirs: Vec<&str> = theirs["globals"]
        .as_array()
        .expect("a name list")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();

    let extra: Vec<&&str> = ours
        .iter()
        .filter(|name| !theirs.contains(name))
        .filter(|name| !DELIBERATE_ADDITIONS.contains(name))
        .collect();
    assert!(
        extra.is_empty(),
        "globalThis has {} name(s) the oracle hides: {extra:?}",
        extra.len()
    );

    // The allowlist is a claim, not an escape hatch: a name in it that is *not*
    // present would mean the allowed exception stopped existing, and the entry
    // would sit here pretending the surface still adds it.
    for name in DELIBERATE_ADDITIONS {
        assert!(
            ours.contains(name),
            "{name} is allowlisted as a deliberate addition but is not on \
             globalThis, so the allowlist is stale"
        );
    }

    let missing: Vec<&&str> = theirs.iter().filter(|name| !ours.contains(name)).collect();
    if !missing.is_empty() {
        eprintln!(
            "note: globalThis is missing {} name(s) the oracle has, which is a \
             separate gap from a leak: {missing:?}",
            missing.len()
        );
    }
}

/// The `-e` mode is the one place Node *does* expose a global `require`.
#[test]
fn eval_mode_exposes_require_and_a_file_does_not() {
    let Some(oracle) = oracle() else {
        return;
    };
    let probe = r#"process.stdout.write(String(
      Object.prototype.hasOwnProperty.call(globalThis, 'require')));"#;

    // `run` already passes `-e`, so this asks the same question of both runtimes
    // with no extra flags and compares the answers.
    let ours = run(env!("CARGO_BIN_EXE_rustnode"), &[], probe);
    let theirs = run(oracle.reference_path(), &[], probe);
    assert_eq!(
        ours, theirs,
        "-e mode: the global `require` presence differs from the oracle"
    );
    assert_eq!(ours, "true", "-e mode: Node exposes `require` as a global");

    // A file entry point is a module, whose `require` is the wrapper's
    // parameter: the global must be absent in both.
    let dir = std::env::temp_dir().join(format!("herdr-proc-globals-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let script = dir.join("entry.cjs");
    std::fs::write(
        &script,
        "console.log(Object.prototype.hasOwnProperty.call(globalThis,'require'),
                     Object.prototype.hasOwnProperty.call(globalThis,'primordials'));
",
    )
    .expect("the script is written");

    for binary in [
        env!("CARGO_BIN_EXE_rustnode").to_string(),
        oracle.reference_path().to_string(),
    ] {
        let out = Command::new(&binary)
            .arg(&script)
            .output()
            .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "false false",
            "{binary} leaks a global in file mode"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
