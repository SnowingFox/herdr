//! End-to-end checks that drive `async_wrap` through the CLI.
//!
//! `lib/internal/async_hooks.js` reads and writes these shared arrays directly,
//! so the tests write from JavaScript and read back from Rust. A copy on either
//! side would break the async id sequence, which shows up as `async_hooks`
//! reporting the wrong parent rather than as an obvious error.

use std::path::PathBuf;
use std::process::Command;

fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

fn run(script: &str) -> String {
    let output = Command::new(rustnode())
        .arg("--expose-internals")
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be built first");
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

const PRELUDE: &str = "const realm = require('internal/bootstrap/realm');\
const aw = realm.internalBinding('async_wrap');\
const { constants } = aw;";

#[test]
fn the_shared_arrays_have_node_types_and_lengths() {
    let output = run(&format!(
        "{PRELUDE}
        console.log(aw.async_hook_fields.constructor.name, aw.async_hook_fields.length);
        console.log(aw.async_id_fields.constructor.name, aw.async_id_fields.length);
        console.log(aw.async_ids_stack.constructor.name, aw.async_ids_stack.length);"
    ));
    // The types are load-bearing: ids are doubles because kInvalidAsyncId is -1,
    // and a Float64Array is the only type that can hold both.
    assert_eq!(output, "Uint32Array 9\nFloat64Array 4\nFloat64Array 32");
}

#[test]
fn the_id_counter_starts_at_one_and_ids_start_invalid() {
    let output = run(&format!(
        "{PRELUDE}
        console.log(aw.async_id_fields[constants.kExecutionAsyncId],
                    aw.async_id_fields[constants.kAsyncIdCounter]);"
    ));
    assert_eq!(output, "-1 1");
}

#[test]
fn the_constants_index_the_arrays_they_describe() {
    let output = run(&format!(
        "{PRELUDE}
        console.log(constants.kInit, constants.kBefore, constants.kAfter,
                    constants.kDestroy, constants.kPromiseResolve, constants.kStackLength);"
    ));
    assert_eq!(output, "0 1 2 3 4 7");
}

#[test]
fn pushing_and_popping_moves_the_stack_length() {
    let output = run(&format!(
        "{PRELUDE}
        const depth = () => aw.async_hook_fields[constants.kStackLength];
        const before = depth();
        aw.pushAsyncContext(null, 7, 3);
        const during = depth();
        const popped = aw.popAsyncContext(7);
        const after = depth();
        const wrong = aw.popAsyncContext(999);
        console.log(before, during, popped, after, wrong);"
    ));
    // A pop with the wrong id must not change the depth: that check is what
    // stops a mismatched pair from corrupting the context.
    assert_eq!(output, "0 1 true 0 false");
}

#[test]
fn the_stack_stores_the_id_pair_it_was_given() {
    let output = run(&format!(
        "{PRELUDE}
        aw.pushAsyncContext(null, 11, 5);
        console.log(aw.async_ids_stack[0], aw.async_ids_stack[1]);"
    ));
    assert_eq!(output, "11 5");
}

#[test]
fn clearing_the_stack_resets_the_depth() {
    let output = run(&format!(
        "{PRELUDE}
        aw.pushAsyncContext(null, 1, 2);
        aw.pushAsyncContext(null, 3, 4);
        const before = aw.async_hook_fields[constants.kStackLength];
        aw.clearAsyncIdStack();
        console.log(before, aw.async_hook_fields[constants.kStackLength]);"
    ));
    assert_eq!(output, "2 0");
}

#[test]
fn the_provider_table_covers_every_async_resource_kind() {
    let output = run(&format!(
        "{PRELUDE}
        const names = Object.keys(aw.Providers);
        console.log(names.length, names[0], aw.Providers.NONE,
                    aw.Providers.PROMISE, typeof aw.Providers.TCPWRAP);"
    ));
    // 70 from Node 28's header, including the QUIC and DTLS providers that
    // Node 22's build does not have. `PROMISE` sits at 29 in Node 28 and at 26
    // in Node 22, which is exactly the kind of drift a hand-written table
    // would get wrong.
    assert_eq!(output, "70 NONE 0 29 number");
}

#[test]
fn setup_hooks_accepts_the_five_callbacks() {
    let output = run(&format!(
        "{PRELUDE}
        let called = false;
        aw.setupHooks(() => {{ called = true; }}, null, null, null, null);
        console.log(typeof aw.setupHooks, called);"
    ));
    // Registering must not invoke.
    assert_eq!(output, "function false");
}

#[test]
fn javascript_writes_to_the_id_fields_are_visible_to_rust() {
    // A later `pushAsyncContext` uses the same array, so the value JavaScript
    // wrote has to be the one the binding sees.
    let output = run(&format!(
        "{PRELUDE}
        aw.async_id_fields[constants.kExecutionAsyncId] = 42;
        console.log(aw.async_id_fields[constants.kExecutionAsyncId]);"
    ));
    assert_eq!(output, "42");
}

#[test]
fn the_generated_provider_names_match_the_recorded_contract() {
    // The contract records the names a real Node binary exposes. Comparing the
    // sorted sets catches a provider the header parse missed or invented, which
    // a count alone would not.
    let contract = std::fs::read_to_string(format!(
        "{}/../../contracts/async_wrap.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the async_wrap contract must exist");
    let recorded: Vec<&str> = contract
        .split("\"properties\"")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .map(|list| list.split('"').skip(1).step_by(2).collect::<Vec<&str>>())
        .expect("the Providers property list");

    let generated: Vec<&str> = rn_bind_async_wrap::PROVIDERS
        .iter()
        .map(|(name, _)| *name)
        .collect();

    let mut missing: Vec<&str> = recorded
        .iter()
        .copied()
        .filter(|name| !generated.contains(name))
        .collect();
    let mut extra: Vec<&str> = generated
        .iter()
        .copied()
        .filter(|name| !recorded.contains(name))
        .collect();
    missing.sort_unstable();
    extra.sort_unstable();
    assert!(missing.is_empty(), "not generated: {missing:?}");
    assert!(extra.is_empty(), "generated but not recorded: {extra:?}");
}
