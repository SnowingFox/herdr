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
fn the_top_level_context_matches_node() {
    // Node runs the entry point inside `InternalCallbackScope(env, obj,
    // { 1, 0 }, kSkipAsyncHooks)` (`src/node.cc:287-293`), which pushes async
    // id 1 and trigger 0. Measured against `node --expose-internals`:
    //
    //     exec 1 trig 0 ctr 2 depth 1 check 1
    //
    // The four values that are invariant are the ids, the depth and the check
    // flag. The counter is *not*: it counts the resources the bootstrap
    // created, so it differs between `node -e`, a script file, and a build with
    // a different startup path. Asserting an exact counter would pin this test
    // to one bootstrap shape rather than to the contract.
    let output = run(&format!(
        "{PRELUDE}
        console.log(aw.async_id_fields[constants.kExecutionAsyncId],
                    aw.async_id_fields[constants.kTriggerAsyncId],
                    aw.async_hook_fields[constants.kStackLength],
                    aw.async_hook_fields[constants.kCheck]);"
    ));
    assert_eq!(output, "1 0 1 1");
}

#[test]
fn the_public_execution_ids_are_one_and_zero_at_top_level() {
    // What the three failing Node tests actually read. Before this was fixed
    // `-1 !== 1` was the recorded assertion in
    // `test-async-hooks-promise.js`, `-triggerid.js` and
    // `-top-level-clearimmediate.js`.
    let output = run("const ah = require('async_hooks');\
         const seen = [];\
         ah.createHook({ init(id, type, tid) { seen.push([id, type, tid]); } }).enable();\
         Promise.resolve(1);\
         console.log(ah.executionAsyncId(), ah.triggerAsyncId(), JSON.stringify(seen));");
    // `node -e` on the same script prints `1 0 [[2,"PROMISE",1]]`.
    assert_eq!(output, r#"1 0 [[2,"PROMISE",1]]"#);
}

#[test]
fn execution_async_resource_is_truthy_at_top_level() {
    // `test-async-hooks-execution-async-resource.js:11` asserts exactly this.
    // The scope's resource object is what `executionAsyncResource()` answers
    // for the whole script body.
    let output = run("const { executionAsyncResource } = require('async_hooks');\
         console.log(Boolean(executionAsyncResource()));");
    assert_eq!(output, "true");
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
        aw.pushAsyncContext(7, 3);
        const during = depth();
        const exec = aw.async_id_fields[constants.kExecutionAsyncId];
        const trig = aw.async_id_fields[constants.kTriggerAsyncId];
        const popped = aw.popAsyncContext(7);
        const after = depth();
        console.log(before, during, exec, trig, popped, after);"
    ));
    // `PushAsyncContext` reads args 0 and 1 (`src/async_wrap.cc:277-285`), and
    // installing the pair is the point of the call: it used to read args 1/2
    // and never wrote the ids at all, so `executionAsyncId()` inside the pushed
    // context answered the caller's id rather than the callee's.
    assert_eq!(output, "1 2 7 3 true 1");
}

#[test]
fn popping_restores_the_context_the_push_replaced() {
    // This is the bug the `19 !== 18` assertion came from: the stack must hold
    // the *outgoing* pair, because that is what a pop restores.
    let output = run(&format!(
        "{PRELUDE}
        const exec = () => aw.async_id_fields[constants.kExecutionAsyncId];
        const trig = () => aw.async_id_fields[constants.kTriggerAsyncId];
        const outer = [exec(), trig()];
        aw.pushAsyncContext(11, 5);
        const inner = [exec(), trig()];
        aw.popAsyncContext(11);
        const back = [exec(), trig()];
        console.log(outer.join(','), inner.join(','), back.join(','));"
    ));
    assert_eq!(output, "1,0 11,5 1,0");
}

#[test]
fn the_stack_stores_the_outgoing_id_pair() {
    let output = run(&format!(
        "{PRELUDE}
        aw.pushAsyncContext(11, 5);
        console.log(aw.async_ids_stack[0], aw.async_ids_stack[1],
                    aw.async_ids_stack[2], aw.async_ids_stack[3]);"
    ));
    // The top-level scope already occupies entry 0, so this push lands at entry
    // 1 — slots 2 and 3 — and stores the pair that was executing before it.
    // The old code stored the *incoming* pair there, so a pop restored the ids
    // that had just been pushed instead of the ones they replaced.
    assert_eq!(output, "0 0 1 0");
}

#[test]
fn a_deep_stack_grows_instead_of_dropping_frames() {
    // `test-async-hooks-recursive-stack-runInAsyncScope.js` recurses 1000 deep
    // and asserts `executionAsyncId()` all the way back out. The array starts
    // at 16 entries and `grow_async_ids_stack` triples it, so the depth has to
    // survive past the initial extent.
    let output = run(&format!(
        "{PRELUDE}
        for (let i = 0; i < 200; i++) aw.pushAsyncContext(i + 100, 1);
        const depth = aw.async_hook_fields[constants.kStackLength];
        const top = aw.async_id_fields[constants.kExecutionAsyncId];
        const extent = aw.async_ids_stack.length;
        console.log(depth, top, extent > 32);"
    ));
    assert_eq!(output, "201 299 true");
}

#[test]
fn clearing_the_stack_resets_the_depth_and_the_ids() {
    let output = run(&format!(
        "{PRELUDE}
        aw.pushAsyncContext(1, 2);
        aw.pushAsyncContext(3, 4);
        const before = aw.async_hook_fields[constants.kStackLength];
        aw.clearAsyncIdStack();
        console.log(before, aw.async_hook_fields[constants.kStackLength],
                    aw.async_id_fields[constants.kExecutionAsyncId],
                    aw.async_id_fields[constants.kTriggerAsyncId]);"
    ));
    // `AsyncHooks::clear_async_id_stack` resets the ids to 0 as well as the
    // depth (`src/env.cc:232-237`). Resetting only the depth left the execution
    // id pointing at a resource whose callback had already unwound.
    assert_eq!(output, "3 0 0 0");
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

/// `setupHooks` refuses a second call, whatever it is given.
///
/// `SetupHooks` starts with `CHECK(args[0]->IsObject())` and then
/// `CHECK(env->async_hooks_init_function().IsEmpty())`, so by the time a script
/// can reach the binding the bootstrap has already filled the table and any
/// further call is a programming error. The five-positional-argument form this
/// binding used to accept was not Node's signature at all — `SetupHooks` reads
/// one object with named properties — so a positional call installed nothing
/// while looking like it worked.
#[test]
fn setup_hooks_refuses_a_second_call() {
    let output = run(&format!(
        "{PRELUDE}
        const results = [];
        for (const argument of [undefined, 1, 'x', {{ init() {{}} }}]) {{
          try {{ aw.setupHooks(argument); results.push('accepted'); }}
          catch (error) {{ results.push(error.constructor.name); }}
        }}
        console.log(results.join(','));"
    ));
    let output = output.trim().to_string();
    // A function is an object to V8, so `IsObject()` admits it; the guard that
    // refuses every one of these is the already-installed check, which is what
    // stops the bootstrap's table being replaced.
    assert_eq!(output, "TypeError,TypeError,TypeError,TypeError");
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

/// `setupHooks` is called once, by the bootstrap, with Node's own `nativeHooks`.
///
/// `src/async_wrap.cc::SetupHooks` reads `args[0]` as an object and pulls
/// `init`, `before`, `after`, `destroy` and `promise_resolve` off it by name, and
/// `CHECK(env->async_hooks_init_function().IsEmpty())` makes a second call a
/// hard error. `internal/bootstrap/node.js` is the only caller:
///
///     const { nativeHooks } = require('internal/async_hooks');
///     internalBinding('async_wrap').setupHooks(nativeHooks);
///
/// rustnode reads positional arguments instead of that object, which left every
/// slot empty: `async_hook_fields` still counted the enabled hooks, so
/// `async_hooks` looked enabled while `EmitAsyncInit` and `EmitDestroy` had no
/// function to call. This asserts the table is populated, because that is what a
/// second `setupHooks` call now refuses to overwrite.
#[test]
fn the_bootstrap_installs_the_native_hook_table_once() {
    let output = run(&format!(
        "{PRELUDE}
        let second = 'none';
        try {{ aw.setupHooks({{ init() {{}} }}); }}
        catch (error) {{ second = error.constructor.name; }}
        console.log(typeof aw.setupHooks, second);"
    ));
    // A second call is refused, which is only possible when the first one
    // installed a function.
    assert_eq!(output, "function TypeError");
}

/// A native `init` reaches the hooks a script enabled, with Node's four
/// arguments.
///
/// The provider, id and trigger id are checked together because they are the
/// three things `EmitAsyncInit` supplies; an implementation that passed the
/// resource where the id belongs would still call the function.
#[test]
fn a_native_init_reaches_the_enabled_hook() {
    let output = run(&format!(
        "{PRELUDE}
        const ah = require('async_hooks');
        const events = [];
        ah.createHook({{
          init(async_id, type, trigger, resource) {{
            events.push([async_id, type, typeof trigger, typeof resource]);
          }},
        }}).enable();
        const tcp = realm.internalBinding('tcp_wrap');
        const handle = new tcp.TCP(tcp.constants.SOCKET);
        const first = handle.getAsyncId();
        handle.asyncReset({{ tag: 'reused' }});
        const second = handle.getAsyncId();
        handle.close();
        const seen = events.filter((event) => event[1] === 'TCPWRAP');
        console.log(JSON.stringify({{ seen, first, second }}));"
    ));
    let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
    let seen = value["seen"].as_array().expect("init events");
    // One `init` from the constructor's own `AsyncReset`, one from the explicit
    // `asyncReset`, matching Node: a handle is a resource from construction, not
    // from its first reuse.
    assert_eq!(seen.len(), 2, "one init per reset: {seen:?}");
    let first = value["first"].as_f64().expect("first id");
    let second = value["second"].as_f64().expect("second id");
    assert!(first > 0.0, "a handle is born with an id, not -1");
    assert!(second > first, "a reset allocates a larger id");
    assert_eq!(seen[0][0].as_f64(), Some(first));
    assert_eq!(seen[1][0].as_f64(), Some(second));
    // `triggerAsyncId` and `resource` both have to be real values: Node passes a
    // number and the resource object the caller handed over.
    assert_eq!(seen[0][2], serde_json::json!("number"));
    assert_eq!(seen[0][3], serde_json::json!("object"));
}

/// `queueDestroyAsyncId` queues the id for the `destroy` hook instead of
/// dropping it.
///
/// `lib/internal/async_hooks.js::emitDestroyScript` calls this whenever a
/// resource reports it is gone, so a no-op implementation here means no
/// `destroy` hook ever fires for anything — which is what rustnode shipped
/// before. The hook is called from the check phase rather than inline, matching
/// `AsyncWrap::EmitDestroy`'s deferral through `destroy_async_id_list`.
#[test]
fn queue_destroy_async_id_is_deferred_and_then_called() {
    let output = run(&format!(
        "{PRELUDE}
        const ah = require('async_hooks');
        const seen = [];
        ah.createHook({{ destroy(id) {{ seen.push(id); }} }}).enable();
        aw.queueDestroyAsyncId(4242);
        console.log('sync', seen.length);
        setImmediate(() => console.log('deferred', seen.join(',')));"
    ));
    // Deferred, not inline: Node queues the id and drains it from the check
    // phase, so the synchronous read sees nothing. The `setImmediate` is itself
    // an async resource, so its id is destroyed in the same phase and appears
    // too; what matters is that 4242 arrives and the explicit `setImmediate`
    // callback ran after the queue drained.
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines[0], "sync 0");
    let deferred = lines[1].strip_prefix("deferred ").expect("deferred line");
    assert!(
        deferred.split(',').any(|id| id == "4242"),
        "queueDestroyAsyncId must reach the destroy hook: {output}"
    );
}

/// `queueDestroyAsyncId` requires a number, as `CHECK(args[0]->IsNumber())` does.
///
/// The type is checked rather than converted: `number_value` would read `'42'`
/// as 42, and a binding that coerces hides the caller's bug.
#[test]
fn queue_destroy_async_id_requires_a_number() {
    let output = run(&format!(
        "{PRELUDE}
        try {{ aw.queueDestroyAsyncId('not a number'); console.log('accepted'); }}
        catch (error) {{ console.log(error.constructor.name); }}"
    ));
    assert_eq!(output, "TypeError");
}
