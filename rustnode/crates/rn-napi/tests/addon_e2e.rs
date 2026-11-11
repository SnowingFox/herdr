//! End-to-end: a real `.node` addon loads and runs against the rustnode binary.
//!
//! These tests spawn the built `rustnode` binary rather than driving an isolate
//! directly, because the claim being tested is the one a user makes: `require()` of
//! a compiled addon works. That needs the real CLI bootstrap (so `process.dlopen`
//! is installed), the real CommonJS loader, and the real exported symbol table.
//!
//! Every test calls [`support::build_addon_or_abort`] first, which compiles the
//! addon from source on every run and aborts the process if the compile fails. That
//! is intentional: a stale binary has produced a false PASS in this project before,
//! and a check that a failed build cannot satisfy is worth the bluntness.

mod support;

use std::path::PathBuf;
use std::process::Command;

/// The `rustnode` binary `cargo test` built alongside this test.
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

/// Runs a script through the CLI and returns `(stdout, stderr, success)`.
fn run(script: &str) -> (String, String, bool) {
    let binary = rustnode();
    assert!(
        binary.is_file(),
        "{} does not exist; the CLI must be built before these tests (the gate does this)",
        binary.display()
    );
    let output = Command::new(&binary)
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be runnable");
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
        output.status.success(),
    )
}

/// Runs a script and asserts it succeeded, returning stdout.
fn run_ok(script: &str) -> String {
    let (stdout, stderr, success) = run(script);
    assert!(success, "script failed: {stderr}");
    stdout
}

/// Runs a script with `--expose-gc`, so `global.gc()` is available.
///
/// The finalizer tests need to force collection: the whole point is that a wrap
/// which frees its payload too early (or twice) looks correct until a collection
/// the test did not ask for happens. Forcing it makes the failure deterministic
/// instead of dependent on whether the child happened to collect.
fn run_with_gc(script: &str) -> String {
    let binary = rustnode();
    assert!(
        binary.is_file(),
        "{} does not exist; the CLI must be built before these tests",
        binary.display()
    );
    let output = Command::new(&binary)
        .arg("--expose-gc")
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be runnable");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    assert!(output.status.success(), "script failed: {stderr}");
    stdout
}

/// JSON-escapes a path so it can be embedded in a script literal.
fn literal(path: &std::path::Path) -> String {
    format!("{:?}", path.to_string_lossy())
}

#[test]
fn a_real_addon_loads_and_computes_a_value() {
    // The headline claim: `add(2, 3)` is a JavaScript call into C, which produces a
    // JavaScript number. Nothing about it works if the `napi_value` bridge, the
    // entry point lookup, or the symbol resolution is wrong.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.addonName, addon.add(2, 3), addon.add(0.5, 0.25));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "rustnode-test-addon 5 0.75");
}

#[test]
fn a_native_function_calls_a_javascript_callback() {
    // The other direction of the bridge, and the one a value-table implementation
    // gets wrong: the string the callback receives was created by
    // `napi_create_string_utf8` inside C, and the callback's return value travelled
    // back out through `napi_call_function`.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.callWithNativeArgument((text) => '<' + text + '>'));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "<from native code>");
}

#[test]
fn nested_native_to_javascript_calls_work() {
    // `applyTwice(fn, value)` calls back into JavaScript twice from one native
    // frame, so a scope that is torn down after the first call fails here.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.applyTwice((x) => x * 2, 5));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "20");
}

#[test]
fn objects_arrays_and_typed_classification_cross_the_boundary() {
    // Object creation, named property set, array-with-length, element set and
    // `napi_typeof`, in one call. A bridge that only handled primitives would leave
    // every one of these unproven.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(JSON.stringify(addon.describe(42)));\n\
         console.log(JSON.stringify(addon.describe('text')));",
        literal(&build.path)
    ));
    assert_eq!(
        stdout,
        "{\"kind\":\"number\",\"multiples\":[0,7,14]}\n\
         {\"kind\":\"string\",\"multiples\":[0,7,14]}"
    );
}

#[test]
fn a_property_name_passes_from_javascript_into_native_code() {
    // The key crosses too: `readProperty` receives the name as a JavaScript string,
    // reads it with `napi_get_value_string_utf8`, and looks the property up.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.readProperty({{ greeting: 'hi', n: 7 }}, 'greeting'),\n\
                     addon.readProperty({{ greeting: 'hi', n: 7 }}, 'n'),\n\
                     addon.readProperty({{}}, 'absent'));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "hi 7 undefined");
}

#[test]
fn an_addon_error_surfaces_as_a_catchable_javascript_error() {
    // `napi_throw_type_error` from C must reach a JavaScript `catch` with the
    // `name` and `code` the addon asked for. A thrown error that V8 swallowed would
    // make the whole error path untrustworthy.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         try {{ addon.fail('custom message'); }}\n\
         catch (e) {{ console.log(e.name, e.code, e.message); }}",
        literal(&build.path)
    ));
    assert_eq!(stdout, "TypeError ERR_ADDON_FAILED custom message");
}

#[test]
fn the_addon_reports_the_runtimes_napi_and_node_version() {
    // `napi_get_version` and `napi_get_node_version` are what an addon uses to
    // decide what it may call, and `node_api_get_module_file_name` must be the
    // percent-encoded `file://` URL rather than a bare path.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const info = addon.versionInfo();\n\
         console.log(info.napiVersion, info.nodeMajor,\n\
                     info.moduleFilename === require('url').pathToFileURL({}).href);",
        literal(&build.path),
        literal(&build.path)
    ));
    assert_eq!(stdout, "10 28 true");
}

#[test]
fn a_descriptor_table_registers_methods_and_values() {
    // `napi_define_properties` with an array of `napi_property_descriptor`s is how
    // almost every real addon registers, and it is what `1_hello_world` needs. Both
    // non-accessor descriptor forms are covered: `method` and `value`.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.addFromTable(20, 22), addon.tableMarker);\n\
         console.log(JSON.stringify(addon.describeProperties()));\n\
         // `napi_default_method` is writable|configurable without enumerable, so a\n\
         // method registered that way must not appear in Object.keys.\n\
         console.log(Object.keys(addon).includes('addFromTable'));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "42 table\n{\"label\":\"descriptor\"}\nfalse");
}

#[test]
fn require_of_a_dot_node_file_goes_through_the_commonjs_loader() {
    // The real-world path: `Module._extensions['.node']` calls `process.dlopen`. The
    // module is cached by the loader afterwards, which both runtimes do, so this
    // asserts the load happened and the export works rather than anything about the
    // cache.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const first = require({path});\n\
         const second = require({path});\n\
         console.log(first.add(1, 2), second.add(1, 2), first === second);",
        path = literal(&build.path)
    ));
    assert_eq!(stdout, "3 3 true");
}

#[test]
fn a_missing_addon_file_reports_dlopen_failed() {
    // Verified against real Node: `process.dlopen` on a nonexistent path produces
    // `ERR_DLOPEN_FAILED` with the loader's own text. `require` of the same path
    // produces `MODULE_NOT_FOUND` instead, because the loader checks first — the next
    // test pins that difference so the two are never conflated.
    let (stdout, _stderr, success) = run(
        "try { process.dlopen({ exports: {} }, '/definitely/not/here/addon.node'); }\n\
         catch (e) { console.log(e.name, e.code); console.log(e.message); }",
    );
    assert!(success);
    assert_eq!(
        stdout,
        "Error ERR_DLOPEN_FAILED\n\
         /definitely/not/here/addon.node: cannot open shared object file: No such file or directory"
    );
}

#[test]
fn a_non_shared_object_reports_the_loaders_message() {
    // A file that exists but is not an ELF shared object. The text comes from the
    // dynamic loader and is part of what a user compares against Node.
    let scratch = std::env::temp_dir().join(format!(
        "rn-napi-notso-{}-{:?}.node",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&scratch, b"this is not a shared object").expect("write");
    let (stdout, _stderr, success) = run(&format!(
        "try {{ process.dlopen({{ exports: {{}} }}, {}); }}\n\
         catch (e) {{ console.log(e.code, e.message); }}",
        literal(&scratch)
    ));
    let _ = std::fs::remove_file(&scratch);
    assert!(success);
    assert_eq!(
        stdout,
        format!("ERR_DLOPEN_FAILED {}: file too short", scratch.display())
    );
}

#[test]
fn a_shared_object_without_an_entry_point_reports_no_self_registration() {
    // The third error shape acceptance requires, and the one that distinguishes "this
    // is a library but not an addon" from "this file is broken". The message is
    // Node's, word for word, including the period inside the quotes.
    let scratch = std::env::temp_dir().join(format!(
        "rn-napi-nosym-{}-{:?}.node",
        std::process::id(),
        std::thread::current().id()
    ));
    let source = scratch.with_extension("c");
    std::fs::write(&source, b"int not_an_addon(void) { return 1; }\n").expect("write");
    let compiled = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&scratch)
        .arg(&source)
        .status()
        .expect("cc must be available");
    assert!(compiled.success(), "the fixture must compile");

    let (stdout, _stderr, success) = run(&format!(
        "try {{ process.dlopen({{ exports: {{}} }}, {}); }}\n\
         catch (e) {{ console.log(e.code); console.log(e.message); }}",
        literal(&scratch)
    ));
    let _ = std::fs::remove_file(&scratch);
    let _ = std::fs::remove_file(&source);
    assert!(success);
    assert_eq!(
        stdout,
        format!(
            "ERR_DLOPEN_FAILED\nModule did not self-register: '{}'.",
            scratch.display()
        )
    );
}

#[test]
fn dlopen_with_too_few_arguments_reports_missing_args() {
    // Node's `THROW_ERR_MISSING_ARGS`, matched exactly: a `TypeError` named
    // `ERR_MISSING_ARGS` with that message.
    let (stdout, _stderr, success) = run("try { process.dlopen(); }\n\
         catch (e) { console.log(e.name, e.code, e.message); }");
    assert!(success);
    assert_eq!(
        stdout,
        "TypeError ERR_MISSING_ARGS process.dlopen needs at least 2 arguments"
    );
}

#[test]
fn dlopen_twice_gives_each_load_its_own_exports_object_and_functions() {
    // Node's `1_hello_world` asserts that two loads of one addon produce two
    // distinct function objects, because `napi_create_function` must create a new
    // function each time rather than caching one per name. `require` hides this by
    // caching the module, so `process.dlopen` is called directly.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const path = {};\n\
         const first = {{ exports: {{}} }};\n\
         const second = {{ exports: {{}} }};\n\
         process.dlopen(first, path);\n\
         process.dlopen(second, path);\n\
         console.log(first.exports !== second.exports,\n\
                     first.exports.add !== second.exports.add,\n\
                     first.exports.add(2, 2), second.exports.add(2, 2));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "true true 4 4");
}

#[test]
fn async_work_runs_on_a_pool_thread_and_completes_on_the_loop_thread() {
    // The claim is two-part, and the second half is what a synchronous stand-in
    // would fail: `execute` must run somewhere other than the isolate's thread,
    // and `complete` must deliver its result back through a JavaScript callback.
    //
    // The addon reports `executedOffThread` from inside `execute`, where it
    // compares `pthread_self()` against the thread that created the work. A shim
    // that ran `execute` inline would compute the right `value` and report
    // `false`, so the value alone is not sufficient evidence and is not treated
    // as such.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         addon.runAsyncWork(7, (result) => {{\n\
           console.log(result.value, result.executedOffThread);\n\
         }});",
        literal(&build.path)
    ));
    assert_eq!(stdout, "21 true");
}

#[test]
fn async_work_delivers_several_independent_completions() {
    // One work item per call, each with its own carrier and its own reference.
    // A shim that reused a single slot per environment would hand two callbacks
    // the same data, which this catches: the three inputs produce three distinct
    // products, and all three must arrive.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const seen = [];\n\
         const done = (value) => {{\n\
           seen.push(value);\n\
           if (seen.length === 3) console.log(seen.sort((a, b) => a - b).join(','));\n\
         }};\n\
         addon.runAsyncWork(1, (r) => done(r.value));\n\
         addon.runAsyncWork(2, (r) => done(r.value));\n\
         addon.runAsyncWork(3, (r) => done(r.value));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "3,6,9");
}

#[test]
fn cancelled_async_work_reports_napi_cancelled_to_its_completion() {
    // `napi_cancel_async_work` has to reach libuv's queue. The addon saturates
    // the pool, queues one more request and cancels it, so the request never
    // starts and its `complete` runs with `napi_cancelled` — which the addon turns
    // into the `cancelled` flag the assertion reads.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         addon.queueAndCancel((result) => console.log(result.cancelled));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "true");
}

#[test]
fn a_threadsafe_function_delivers_every_value_from_a_real_thread() {
    // The headline claim for thread-safe functions: a POSIX thread created by the
    // addon pushes 50 integers through `napi_call_threadsafe_function`, and
    // JavaScript receives all 50, in order, on the loop's thread.
    //
    // "In order" is the part that matters for a queue: a shim that ran the callback
    // on the calling thread would be a data race on V8, and one that used a stack
    // would reorder. The finalize callback's count catches a value lost at
    // teardown, which is the other way this silently under-delivers.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const received = [];\n\
         addon.startThreadSafeProducer(\n\
           (value) => received.push(value),\n\
           50,\n\
           (pushed) => console.log(received.length,\n\
                                received.every((value, index) => value === index),\n\
                                pushed));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "50 true 50");
}

#[test]
fn a_threadsafe_functions_context_is_readable_from_the_producing_thread() {
    // `napi_get_threadsafe_function_context` is documented for use on the thread
    // that calls in, not on the thread that created the function. The addon
    // compares the pointer it reads from its producer thread against the one it
    // passed at creation, and reports whether they are equal.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         addon.threadSafeFunctionContext((matched) => console.log(matched));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "1");
}

#[test]
fn a_threadsafe_function_keeps_the_process_alive_until_it_is_released() {
    // A live TSFN holds a ref'd `uv_async_t`, so the process must stay alive while
    // values are still queued even though nothing else is pending. Reaching the
    // finalizer at all proves the loop kept running; a version that unref'd the
    // handle at creation would exit before the producer's first push.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         let count = 0;\n\
         addon.startThreadSafeProducer(\n\
           () => {{ count += 1; }},\n\
           20,\n\
           (pushed) => console.log('finalized', count, pushed));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "finalized 20 20");
}

#[test]
fn a_throw_from_a_threadsafe_callback_reaches_the_uncaught_exception_listener() {
    // A thread-safe function's callback runs with no JavaScript frame above it, so
    // a throw there has nowhere to propagate. Node routes it through
    // `env->CallbackIntoModule`, which lands in `TriggerUncaughtException`: the
    // `uncaughtException` listener gets the error and the process keeps running.
    //
    // Before this was implemented the throw was left pending and V8's default
    // reporter printed `Uncaught Error: ...` while the process still exited 0, so
    // the error reached nobody who could handle it. The assertion below fails if
    // that regresses, because the listener would never record a message.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const seen = [];\n\
         process.on('uncaughtException', (error) => seen.push(error.message));\n\
         addon.startThreadSafeProducer(\n\
           () => {{ throw new Error('callback boom'); }},\n\
           2,\n\
           () => setTimeout(() => console.log('seen=' + seen.join(',')), 60));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "seen=callback boom,callback boom");
}

#[test]
fn a_throw_from_a_threadsafe_finalizer_reaches_the_uncaught_exception_listener() {
    // The finalizer is addon code too, and Node runs it through `CallFinalizer`
    // with the same exception handling as a value callback.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const seen = [];\n\
         process.on('uncaughtException', (error) => seen.push(error.message));\n\
         addon.startThreadSafeProducer(\n\
           () => {{}},\n\
           1,\n\
           () => {{\n\
             queueMicrotask(() =>\n\
               setTimeout(() => console.log('seen=' + seen.join(',')), 40));\n\
             throw new Error('finalizer boom');\n\
           }});",
        literal(&build.path)
    ));
    assert_eq!(stdout, "seen=finalizer boom");
}

#[test]
fn a_throw_from_a_threadsafe_callback_reaches_the_listener_before_pending_microtasks() {
    // The ordering is Node's, and it is not the intuitive one. `InternalMakeCallback`
    // returns early with `MarkAsFailed()` when the callback throws, so
    // `InternalCallbackScope::Close` hits `if (failed_) return;` and its
    // `PerformCheckpoint` never runs. The uncaught trigger therefore precedes a
    // microtask the throwing callback queued.
    //
    // Verified against real Node 22 with `--force-node-api-uncaught-exceptions-policy`,
    // which reports `callback,listener,microtask`. A fix that "drained microtasks
    // first" would produce the opposite order and be wrong.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const order = [];\n\
         process.on('uncaughtException', () => order.push('listener'));\n\
         addon.startThreadSafeProducer(\n\
           () => {{\n\
             order.push('callback');\n\
             queueMicrotask(() => order.push('microtask'));\n\
             throw new Error('boom');\n\
           }},\n\
           1,\n\
           () => setTimeout(() => console.log(order.join(',')), 60));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "callback,listener,microtask");
}

#[test]
fn a_wrap_survives_gc_while_referenced_and_its_finalizer_runs_once_after() {
    // The case a get/set round trip cannot prove. `napi_unwrap` must keep working
    // across forced collections, and after the object is dropped the finalizer must
    // free the payload exactly once — not zero times (a leak) and not twice (a
    // double free that only shows up under GC timing).
    let build = support::build_addon_or_abort();
    let stdout = run_with_gc(&format!(
        "const addon = require({});\n\
         const before = addon.counters().wrapFinalized;\n\
         let object = addon.wrapWithFinalizer(99);\n\
         // Collect with the object alive: the wrap must survive.\n\
         for (let round = 0; round < 3; round += 1) {{ global.gc(); }}\n\
         const read = addon.readWrapped(object);\n\
         object = null;\n\
         // Collect until the finalizer runs, then look at the counter.\n\
         let settled = 0;\n\
         const timer = setInterval(() => {{\n\
           const junk = [];\n\
           for (let i = 0; i < 20000; i += 1) junk.push({{ i }});\n\
           global.gc();\n\
           const counters = addon.counters();\n\
           if (counters.wrapFinalized > before || ++settled > 20) {{\n\
             clearInterval(timer);\n\
             console.log(read,\n\
                         counters.wrapFinalized - before,\n\
                         counters.doubleFree);\n\
           }}\n\
         }}, 5);",
        literal(&build.path)
    ));
    assert_eq!(stdout, "99 1 0");
}

#[test]
fn an_external_value_and_a_wrap_over_one_allocation_free_it_exactly_once() {
    // The specific hazard: an external's finalizer and a wrap's finalizer both
    // pointing at one allocation. Only the external owns it, so exactly one free
    // happens. Two would be a double free visible only under GC timing, and the
    // fixture counts frees rather than crashing so this can assert it.
    let build = support::build_addon_or_abort();
    let stdout = run_with_gc(&format!(
        "const addon = require({});\n\
         const before = addon.counters();\n\
         let object = addon.externalWithWrap();\n\
         // Read the payload through the wrap while the external still owns it.\n\
         const value = addon.readExternalViaWrap(object);\n\
         object = null;\n\
         let settled = 0;\n\
         const timer = setInterval(() => {{\n\
           const junk = [];\n\
           for (let i = 0; i < 20000; i += 1) junk.push({{ i }});\n\
           global.gc();\n\
           const counters = addon.counters();\n\
           const freed = counters.externalFreed - before.externalFreed;\n\
           const wrapRan = counters.wrapFinalized - before.wrapFinalized;\n\
           if (freed > 0 || ++settled > 20) {{\n\
             clearInterval(timer);\n\
             console.log(value, freed, wrapRan, counters.doubleFree);\n\
           }}\n\
         }}, 5);",
        literal(&build.path)
    ));
    // One free, no wrap finalizer (the wrap does not own the pointer), no double
    // free.
    assert_eq!(stdout, "4242 1 0 0");
}

#[test]
fn unwrap_rejects_an_object_that_was_never_wrapped() {
    // Node reports `napi_invalid_arg` here, and an addon distinguishes "not mine"
    // from "mine" by exactly that status.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         console.log(addon.unwrappedRejects({{}}), addon.unwrappedRejects([]));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "true true");
}

#[test]
fn removing_a_wrap_detaches_it_so_a_second_unwrap_fails() {
    // `napi_remove_wrap` hands the pointer to the addon and detaches it. A second
    // unwrap must fail rather than return a pointer the addon may already have
    // freed.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const object = addon.wrapWithFinalizer(7);\n\
         const taken = addon.removeWrapped(object);\n\
         let second;\n\
         try {{ addon.readWrapped(object); second = 'no-throw'; }}\n\
         catch (error) {{ second = error.code || error.name; }}\n\
         console.log(taken, second, addon.unwrappedRejects(object));",
        literal(&build.path)
    ));
    assert_eq!(stdout, "7 ERR_ADDON_UNWRAP true");
}

#[test]
fn a_buffer_surface_round_trip_carries_the_bytes() {
    // The owned-buffer path: an `ArrayBuffer` created natively, viewed as a
    // `Uint8Array`, written through `napi_get_buffer_info`'s pointer and read back
    // by JavaScript. A shim that returned a different allocation would fail here.
    let build = support::build_addon_or_abort();
    let stdout = run_ok(&format!(
        "const addon = require({});\n\
         const described = addon.bufferInfo();\n\
         console.log(described.isBuffer, described.length, described.first,\n\
                     described.hasData, described.arrayBufferIsBuffer);",
        literal(&build.path)
    ));
    assert_eq!(stdout, "true 8 7 true false");
}
