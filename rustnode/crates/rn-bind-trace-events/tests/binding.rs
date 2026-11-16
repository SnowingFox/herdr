//! End-to-end checks that drive `trace_events` through the CLI.
//!
//! `require('trace_events')` is the whole contract: `lib/trace_events.js`
//! refuses to load unless `config.hasTracing`, `ownsProcessState` and
//! `trace_events.hasAgent()` all hold, and it throws
//! `ERR_TRACE_EVENTS_UNAVAILABLE` otherwise. Before the namespace owned its
//! category state, `hasAgent()` answered `false` against a `hasTracing` of
//! `true`, so the module was present and unreachable.

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

#[test]
fn the_module_loads_and_exposes_the_public_surface() {
    // The regression this pins: `require('trace_events')` threw
    // ERR_TRACE_EVENTS_UNAVAILABLE because `hasAgent()` was false.
    let output = run("const t = require('trace_events');
        console.log(typeof t.createTracing, typeof t.getEnabledCategories);");
    assert_eq!(output, "function function");
}

#[test]
fn has_agent_agrees_with_has_tracing() {
    // The two bindings have to agree: Node's guard requires both, and the only
    // failing combination is `hasTracing: true` with `hasAgent(): false`.
    let output = run("const realm = require('internal/bootstrap/realm');
        const { hasTracing } = realm.internalBinding('config');
        const { hasAgent } = realm.internalBinding('trace_events');
        console.log(hasTracing === hasAgent());");
    assert_eq!(output, "true");
}

#[test]
fn enabling_and_disabling_a_category_set_moves_the_enabled_list() {
    let output = run("const t = require('trace_events');
        const tr = t.createTracing({ categories: ['node.perf'] });
        const before = t.getEnabledCategories();
        tr.enable();
        const during = t.getEnabledCategories();
        const enabledFlag = tr.enabled;
        tr.disable();
        console.log(before, during, enabledFlag, t.getEnabledCategories());");
    // Node reports `undefined` when nothing is enabled rather than an empty
    // string, and the list is a sorted join.
    assert_eq!(output, "undefined node.perf true undefined");
}

#[test]
fn the_enabled_list_is_sorted_rather_than_in_enable_order() {
    let output = run("const t = require('trace_events');
        const tr = t.createTracing({ categories: ['v8', 'node.perf'] });
        tr.enable();
        console.log(t.getEnabledCategories());
        tr.disable();");
    assert_eq!(output, "node.perf,v8");
}

#[test]
fn a_category_enabled_by_two_sets_stays_enabled_until_both_disable_it() {
    // Node keeps one flag per category in the tracing controller and one writer
    // handle per `CategorySet`, so the flag is the union of the sets.
    let output = run("const t = require('trace_events');
        const a = t.createTracing({ categories: ['x', 'y'] });
        const b = t.createTracing({ categories: ['y'] });
        a.enable(); b.enable();
        const both = t.getEnabledCategories();
        a.disable();
        const afterA = t.getEnabledCategories();
        b.disable();
        console.log(both, afterA, t.getEnabledCategories());");
    assert_eq!(output, "x,y y undefined");
}

#[test]
fn the_category_flag_buffer_is_a_live_view_with_stable_identity() {
    // `internal/trace_events.js`'s `categoryEnabledChecker` caches the buffer and
    // reads `buffer[0]`, so a second call has to return the same array and that
    // array has to see the enable.
    let output = run("const realm = require('internal/bootstrap/realm');
        const te = realm.internalBinding('trace_events');
        const first = te.getCategoryEnabledBuffer('node.perf');
        const before = first[0];
        const set = new te.CategorySet(['node.perf']);
        set.enable();
        const after = first[0];
        const same = te.getCategoryEnabledBuffer('node.perf') === first;
        set.disable();
        console.log(first.constructor.name, first.length, before, after, same, first[0]);");
    // `before` is read before the enable and `after` after it; the trailing value
    // is the same array read again after `disable()`, which is what proves the
    // view stays live in both directions.
    assert_eq!(output, "Uint8Array 1 0 1 true 0");
}

#[test]
fn the_category_enabled_checker_follows_the_flag() {
    // The public, observable consequence: `internal/trace_events.js` builds every
    // trace call site's guard from this checker, so a stale answer here is what
    // would make tracing silently record nothing.
    let output = run("const ite = require('internal/trace_events');
        const t = require('trace_events');
        const checker = ite.categoryEnabledChecker('node.perf');
        const before = checker();
        const tr = t.createTracing({ categories: ['node.perf'] });
        tr.enable();
        const during = checker();
        tr.disable();
        console.log(before, during, checker());");
    assert_eq!(output, "false true false");
}

#[test]
fn enabling_the_async_hooks_category_notifies_the_state_handler() {
    // `TrackingTraceStateObserver::UpdateTraceCategoryState` calls the installed
    // handler with `isTraceCategoryEnabled('node.async_hooks')`, which is how
    // `toggleTraceCategoryState` starts the async-hook tracer. Node installs
    // that handler in `internal/bootstrap/node.js`.
    let output = run("const realm = require('internal/bootstrap/realm');
        const te = realm.internalBinding('trace_events');
        const seen = [];
        te.setTraceCategoryStateUpdateHandler((enabled) => seen.push(enabled));
        const tr = require('trace_events').createTracing({ categories: ['node.async_hooks'] });
        tr.enable();
        tr.disable();
        console.log(seen.join(','));");
    assert_eq!(output, "true,false");
}

#[test]
fn a_rejected_category_list_throws_the_documented_codes() {
    let output = run("const t = require('trace_events');
        try { t.createTracing({ categories: [] }); } catch (e) { console.log(e.code); }
        try { t.createTracing({}); } catch (e) { console.log(e.code); }");
    assert_eq!(
        output,
        "ERR_TRACE_EVENTS_CATEGORY_REQUIRED\nERR_INVALID_ARG_TYPE"
    );
}

#[test]
fn use_perfetto_matches_the_build() {
    // rustnode does not link Perfetto, so the internal layer must take the
    // legacy `node,<category>` labelling branch.
    let output = run("const ite = require('internal/trace_events');
        console.log(ite.usePerfetto, ite.nodeTraceEventCategory('v8'));");
    assert_eq!(output, "false node,v8");
}
