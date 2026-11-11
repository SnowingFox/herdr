//! The namespace shape, checked against `contracts/inspector.json`.
//!
//! These are the weaker tests, and they are labelled so: a namespace can satisfy every
//! one of them while its members do nothing. `tests/protocol.rs` and `tests/coverage.rs`
//! are the ones that prove the members work. What these add is the coverage ratchet —
//! a member that stops being registered fails here, rather than being noticed by
//! `rn-compat` after a release.

use rn_bind_inspector::{Inspector, Profiler, DEFERRED, MEMBERS, PROFILER_MEMBERS};
use rn_core::{BindingModule, BindingRegistry};

/// The members `contracts/inspector.json` records, sorted.
///
/// Kept as a literal rather than read from the JSON so a change to either side has to
/// be deliberate: reading the contract would make the test agree with whatever the
/// contract says, including after a bad edit.
const CONTRACT: &[&str] = &[
    "Connection",
    "MainThreadConnection",
    "asyncTaskCanceled",
    "asyncTaskFinished",
    "asyncTaskScheduled",
    "asyncTaskStarted",
    "callAndPauseOnStart",
    "console",
    "consoleCall",
    "emitProtocolEvent",
    "isEnabled",
    "open",
    "putNetworkResource",
    "registerAsyncHook",
    "setConsoleExtensionInstaller",
    "setupNetworkTracking",
    "url",
    "waitForDebugger",
];

/// The members `contracts/profiler.json` records, sorted.
const PROFILER_CONTRACT: &[&str] = &[
    "endCoverage",
    "setCoverageDirectory",
    "setSourceMapCacheGetter",
    "startCoverage",
    "stopCoverage",
    "takeCoverage",
];

#[test]
fn every_contract_member_is_installed() {
    let mut declared: Vec<&str> = MEMBERS.to_vec();
    declared.sort_unstable();
    let mut expected: Vec<&str> = CONTRACT.to_vec();
    expected.sort_unstable();
    assert_eq!(
        declared, expected,
        "the inspector namespace must install exactly the recorded members"
    );
}

#[test]
fn the_profiler_contract_is_installed() {
    let mut declared: Vec<&str> = PROFILER_MEMBERS.to_vec();
    declared.sort_unstable();
    let mut expected: Vec<&str> = PROFILER_CONTRACT.to_vec();
    expected.sort_unstable();
    assert_eq!(
        declared, expected,
        "the profiler namespace must install exactly the recorded members"
    );
}

#[test]
fn nothing_is_declared_deferred() {
    // A deferral is a claim that the member is known and absent. Every member here
    // works, so an entry would be a stale apology — and it would also silence the
    // contract check for that member.
    assert!(
        DEFERRED.is_empty(),
        "these deferrals are stale: {DEFERRED:?}"
    );
}

#[test]
fn both_namespaces_register_with_the_runtime() {
    let mut registry = BindingRegistry::new();
    rn_bind_inspector::register(&mut registry);

    let inspector = registry
        .get("inspector")
        .expect("inspector must be registered");
    assert_eq!(
        inspector.members.len(),
        CONTRACT.len(),
        "every contract member must be registered, got {:?}",
        inspector.members
    );
    assert!(
        registry.can_install("inspector"),
        "inspector must be installable, not a contract-only placeholder"
    );

    let profiler = registry
        .get("profiler")
        .expect("profiler must be registered");
    assert_eq!(
        profiler.members.len(),
        PROFILER_CONTRACT.len(),
        "every profiler member must be registered, got {:?}",
        profiler.members
    );
    assert!(
        registry.can_install("profiler"),
        "profiler must be installable: lib/v8.js reads it at module scope"
    );
}

#[test]
fn the_namespace_names_are_the_ones_lib_reaches_for() {
    // `internalBinding('inspector')` and `internalBinding('profiler')` are the two
    // spellings in `lib/**`; a typo here makes `require('inspector')` throw
    // ERR_INSPECTOR_NOT_AVAILABLE with no hint about which half is missing.
    assert_eq!(Inspector.namespace(), "inspector");
    assert_eq!(Profiler.namespace(), "profiler");
}
