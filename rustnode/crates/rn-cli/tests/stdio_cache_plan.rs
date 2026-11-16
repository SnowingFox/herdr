//! The builtin code-cache plan has to cover the stdio path.
//!
//! # Why this is a test and not a comment
//!
//! `crates/rn-builtins/src/cache_plan.rs` decides which builtins ship a V8 code
//! cache. A builtin missing from it still works — it compiles from source — so a
//! gap costs startup time and nothing else, and nothing fails. That is exactly
//! the kind of regression that survives review, and it did: `net`, `stream` and
//! the `internal/streams/**` stack they pull in were absent for a long time, so
//! the first `process.stdout` read paid about 4 ms of parse that no phase timer
//! could attribute.
//!
//! # What is asserted
//!
//! The binary is asked to report every builtin it compiled, over two runs: one
//! that does nothing, and one that touches `process.stdout`. Every id in both
//! lists must be in the plan. The first run is the startup set the plan's doc
//! comment describes; the second is the stdio set.
//!
//! `process.stdout` is the case that matters because it is lazy, so a script
//! that never prints does not pay for it and a script that prints once pays for
//! all of it. `net` is covered by the same list: `createWritableStdioStream`
//! reaches it for a `PIPE` handle, which is a redirected descriptor.
//!
//! # It cannot see the other handles
//!
//! `internal/tty` and `internal/fs/sync_write_stream` are compiled only when
//! stdout is a tty or a regular file, which a test runner does not have. They
//! are in the plan because those are the same first read under a different
//! `guessHandleType()` answer, and their absence would be invisible here. That
//! is a documented limit of this check, not a claim that the three cases are
//! equally covered.

use std::process::Command;

/// The plan, read from the crate that owns it rather than restated.
fn plan() -> &'static [&'static str] {
    rn_builtins::cache_plan::CACHED_BUILTINS
}

/// Runs `script` under the built binary and returns the builtin ids it compiled.
///
/// `RN_PROFILE_BUILTIN_COMPILE` is the instrument `rn-builtins` already had for
/// this: it writes one line per compile to stderr. Parsing it here rather than
/// adding a second reporting path keeps the production binary unchanged.
fn compiled_builtins(script: &str) -> Vec<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("-e")
        .arg(script)
        .env("RN_PROFILE_BUILTIN_COMPILE", "1")
        .output()
        .unwrap_or_else(|error| panic!("cannot run rustnode: {error}"));
    assert!(
        output.status.success(),
        "rustnode failed on {script:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut ids = Vec::new();
    for line in stderr.lines() {
        // Format: `builtin compile  1.159 ms  cache=false  <id>`.
        if let Some(rest) = line.strip_prefix("builtin compile ") {
            if let Some((_, id)) = rest.rsplit_once("  ") {
                ids.push(id.trim().to_string());
            }
        }
    }
    ids
}

/// Fails naming every id that was compiled without a cache.
fn assert_covered(script: &str, ids: &[String]) {
    let plan = plan();
    let missing: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| !plan.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "these builtins are compiled by `{script}` but have no code cache, so they \
         are parsed from source on every start: {missing:?}\n\
         add them to crates/rn-builtins/src/cache_plan.rs"
    );
}

#[test]
fn the_cache_plan_covers_what_a_bare_start_compiles() {
    // The instrument has to be working at all, or this test passes by parsing
    // nothing. An empty run compiles dozens of builtins, so an empty list means
    // the reporting path broke rather than that the plan is complete.
    let ids = compiled_builtins("void 0");
    assert!(
        ids.len() > 40,
        "expected the startup builtins to be reported, got {}: {ids:?}",
        ids.len()
    );
    assert_covered("void 0", &ids);
}

#[test]
fn the_cache_plan_covers_the_stdio_path() {
    // The whole point: `process.stdout` is a lazy getter, so this read is what
    // makes a printing script pay for `net` and the streams stack. With stdout
    // redirected to a pipe that is a `net.Socket`; the parse for it is the cost
    // this test exists to keep cached.
    let ids = compiled_builtins("process.stdout");
    assert!(
        ids.iter().any(|id| id == "net"),
        "`process.stdout` should reach `net`; reported: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id == "internal/streams/readable"),
        "`process.stdout` should reach the streams stack; reported: {ids:?}"
    );
    assert_covered("process.stdout", &ids);
}
