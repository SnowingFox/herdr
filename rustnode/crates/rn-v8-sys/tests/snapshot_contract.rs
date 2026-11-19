//! What a V8 snapshot creator can and cannot do, pinned.
//!
//! These are properties of the linked V8, not of rustnode: every assertion here
//! is a `SnapshotCreator` behaviour that a startup-snapshot build has to design
//! around, and each one was found by a failing build rather than by reading
//! documentation. Pinning them means the next attempt starts from the wall
//! instead of rediscovering it.
//!
//! The walls, in the order a build path meets them:
//!
//! 1. **A default context is mandatory, and it cannot be the context you load.**
//!    `SnapshotCreatorImpl::CreateBlob` opens with `CHECK(contexts_
//!    [kDefaultContextIndex].handle_location != nullptr)`, so a blob with no
//!    default context aborts. That default context's global proxy is the one V8
//!    does *not* serialise, so `Context::from_snapshot` on its index aborts
//!    instead. The shape that works is the one Node uses: a throwaway default
//!    context plus a real context added afterwards, and the load path
//!    instantiates the added one.
//!
//! 2. **External references must be recorded, and there is no way to sweep them
//!    up afterwards.** `v8::FunctionTemplate::builder` with any callback
//!    produces a function whose code embeds the address of the generated `c_fn`
//!    thunk. Serialising an isolate that holds one aborts with `Unknown external
//!    reference 0x...`, because V8 cannot record an address it has not been told
//!    to expect. `CreateParams::external_references` is that list, and it has to
//!    hold *every* such thunk the bootstrapped isolate retains.
//!
//!    The address is obtainable — `MapFnTo::map_fn_to` on a callback function
//!    item yields it, and `FunctionTemplate::builder_raw` takes it back — but
//!    only from the item, never from a template that already exists:
//!    `v8::FunctionTemplate` has `SetCallHandler` and no `GetCallHandler`, so a
//!    built template cannot be asked what callback it holds. There is therefore
//!    no "walk the isolate and collect the thunks" API to build on, and the
//!    addresses have to be captured where templates are created.
//!
//!    That makes this a table problem rather than a generator problem: every
//!    callback-bearing template has to go through a funnel that records the
//!    address as it builds. rustnode has 358 `FunctionTemplate::builder` /
//!    `Function::builder` call sites; 511 already route through `rn_core`'s
//!    builders, and 63 across 38 files call the v8 API directly and would each
//!    have to move behind that funnel. The test below proves the mechanism
//!    works end to end, so the remaining work is mechanical rather than unknown.
//!
//! 3. **A serializer-enabled isolate and the experimental globals.** V8's
//!    `Genesis::InitializeGlobal` installs `InitializeExperimentalGlobal()`
//!    only `if (!isolate->serializer_enabled())`, with the comment "Do not
//!    include them into the snapshot as we should be able to turn them off at
//!    runtime". A snapshot creator calls `enable_serializer()` before the
//!    isolate is initialised, so a creator isolate lacks every *flag-gated*
//!    intrinsic.
//!
//!    Which intrinsics that covers is engine-specific, and this is the wall
//!    that a 15.2 build hit and a 15.6 build does not. On V8 15.2
//!    `Float16Array` was flag-gated: it lived in `TYPED_ARRAYS_FLOAT16` and was
//!    installed from `InitializeGlobal_js_float16array`, which only
//!    `InitializeExperimentalGlobal` called. A creator isolate therefore
//!    reported `typeof Float16Array === 'undefined'`, and
//!    `internal/per_context/primordials.js`, which reads `Float16Array`
//!    unconditionally, threw `TypeError: Reflect.ownKeys called on non-object`.
//!    No snapshot of a rustnode realm could be built on 15.2 at all.
//!
//!    On V8 15.6 (what Node 28 ships) `Float16Array` moved into
//!    `TYPED_ARRAYS_BASE` and is installed unconditionally in
//!    `InitializeGlobal`, so a creator isolate has it. This crate now links a
//!    15.6.75 engine, and the test below records that the wall is gone rather
//!    than that it was worked around.
//!
//!    A *deserialised* context gets the flag-gated intrinsics back either way,
//!    because the load path re-runs Genesis with `serializer_enabled()` false.
//!
//! 4. **Rust-side `v8::Global` caches are not serialisable — and the wall is
//!    reachable, and it names every offending handle.**
//!
//!    `CreateBlob` runs `SerializedHandleChecker::CheckGlobalAndEternalHandles`
//!    and aborts for every global handle that is neither reachable from a
//!    serialised context nor from a serialised embedder object. rustnode keeps
//!    per-isolate identity in thread-local `v8::Global` caches, and none of them
//!    are reachable from a context, so the build has to drop all of them first —
//!    and the load path has to recreate them, which works for anything derived
//!    deterministically (`v8::Symbol::for_key` is stable per description) but not
//!    for a `v8::Global` wrapping a `Function` the snapshot had rooted.
//!
//!    **Correction to an earlier note in this file:** the checker does *not*
//!    abort anonymously. A real `--build-snapshot` on a bootstrapped realm prints
//!    one line per unreachable handle before the fatal, with the handle's type:
//!
//!    ```text
//!    (Global handles) handle not serialized: 0x22afee524b51 <JSObject>
//!    (Global handles) handle not serialized: 0x22afee51b771 <JSFunction internalBinding (sfi = 0x…b5b1)>
//!    (Global handles) handle not serialized: 0x0ef3cd4a3469 <Uint8Array map = 0x…45f9>
//!    # Fatal error
//!    # CheckGlobalAndEternalHandles failed
//!    ```
//!
//!    That list is the work item: it is what a drain has to empty before a realm
//!    snapshot can be built, and it is why this wall is measurable rather than
//!    speculative. A first attempt on 15.6.75 named 39 handles, deterministically
//!    across repetitions. Walls 1 and 2 are *not* in the way: the bare blobs in
//!    the tests below build and load, so the abort is attributable to this one.
//!
//!    Two handles in that sample are worth naming because they are load-bearing
//!    rather than incidental: `JSFunction internalBinding` and
//!    `JSFunction requireBuiltin`. Those are the realm's loader entry points, so
//!    whatever drains the caches has to keep them reachable from a serialised
//!    context rather than simply dropping them — a build that dropped them would
//!    produce a blob that loads and cannot resolve a builtin.

use std::borrow::Cow;
use std::io::Write;

use rn_v8_sys::v8;

/// Initialises V8 once for the whole test binary.
///
/// `V8::initialize` is process-global and must run once, so this is a
/// `Once` rather than a per-test call.
fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // `v8::setFlagsFromString` is a public API (`lib/v8.js` exports it) and
        // a snapshot build sets flags before initialising, exactly as the CLI
        // does. Without this the flag list freezes during `V8::initialize` and
        // a later `setFlagsFromString` trips V8's own `CHECK`.
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Runs `body` with V8 initialised and no other test in this file running.
///
/// A snapshot creator enters an isolate for as long as it lives, so two tests
/// running concurrently would enter two isolates at once and abort inside V8.
/// That is a crash in the test binary rather than a failed assertion, which is
/// exactly what a suite running in parallel produced. `rn-bind-config`'s tests
/// serialize on a mutex for the same reason.
fn with_v8<T>(body: impl FnOnce() -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();
    let result = body();
    drop(guard);
    result
}

fn say(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

fn no_references() -> Cow<'static, [v8::ExternalReference]> {
    Cow::Owned(Vec::new())
}

fn probe_callback(
    _scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
}

/// Builds a blob whose default context is a throwaway and whose added context is
/// the one a load path instantiates, and returns `(blob, added index)`.
///
/// `build` runs inside the added context, so it can install whatever the caller
/// needs serialised.
fn build_blob(
    references: &[v8::ExternalReference],
    build: impl FnOnce(&mut v8::PinScope<'_, '_>),
) -> (v8::StartupData, usize) {
    let params = v8::CreateParams::default().external_references(Cow::Owned(references.to_vec()));
    let mut creator = v8::Isolate::snapshot_creator(None, Some(params));
    let index = {
        let scope = std::pin::pin!(v8::HandleScope::new(&mut creator));
        let scope = &mut scope.init();
        // Wall 1: the default context is what `CreateBlob` checks for, and the
        // context the load path instantiates has to be one *added* to the blob.
        let default_context = v8::Context::new(scope, Default::default());
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        build(scope);
        scope.set_default_context(default_context);
        scope.add_context(context)
    };
    let blob = creator
        .create_blob(v8::FunctionCodeHandling::Clear)
        .expect("a blob");
    (blob, index)
}

/// Wall 2 is a *recording* problem, not an API wall: the address is obtainable
/// from a function item, but never from a built template.
///
/// This is the measurement that decides the shape of the fix, so it is asserted
/// rather than argued. There are two halves:
///
/// * `MapFnTo::map_fn_to()` on a callback *function item* yields exactly the
///   address V8 embeds in the code object, and `FunctionTemplate::builder_raw`
///   accepts that address back. So a site that captures the address while it
///   builds its template needs no new V8 API at all. This test proves that by
///   building a template from a captured raw pointer, registering the pointer,
///   and requiring the function to still be callable after a snapshot
///   round-trip — which is the whole mechanism a recording funnel would use.
///
/// * `v8::FunctionTemplate` exposes no readback. Its public API has
///   `SetCallHandler` but no `GetCallHandler`, so once a template exists its
///   callback cannot be recovered from it. That is why the address has to be
///   captured at construction time rather than swept up afterwards: there is no
///   "walk the isolate and collect every thunk" API to build on.
///
/// The consequence for rustnode is a table, not a generator: every site that
/// creates a callback-bearing template has to go through a funnel that records
/// the address. 511 call sites already funnel through `rn_core`'s builders; 63
/// across 38 files call `v8::FunctionTemplate::builder` / `Function::builder`
/// directly and would each need to move behind that funnel.
#[test]
fn a_captured_callback_address_rebuilds_a_working_function_after_a_snapshot() {
    with_v8(|| {
        // The address as a site would capture it while building its template.
        let captured: v8::FunctionCallback = v8::MapFnTo::map_fn_to(probe_callback);
        say(&format!("captured thunk {:#x}", captured as usize));
        assert!(
            !(captured as usize == 0),
            "a callback's thunk address is never null"
        );
        // The same function item yields the same address on every call, which is
        // what makes it safe to record once and reuse for the whole build.
        let again: v8::FunctionCallback = v8::MapFnTo::map_fn_to(probe_callback);
        assert_eq!(
            captured as usize, again as usize,
            "the address is a property of the monomorphised thunk, not of the call"
        );

        let references = vec![v8::ExternalReference {
            pointer: captured as *mut std::ffi::c_void,
        }];

        // `builder_raw` is the half that makes a recording funnel possible: the
        // template is built from the recorded address rather than from the item,
        // so the registry and the template cannot disagree.
        let (blob, index) = build_blob(&references, |scope| {
            let global = scope.get_current_context().global(scope);
            let template = v8::FunctionTemplate::builder_raw(captured)
                .constructor_behavior(v8::ConstructorBehavior::Throw)
                .length(0)
                .build(scope);
            let function = template.get_function(scope).expect("a function");
            let name = v8::String::new(scope, "rawNative").expect("a name");
            global.set(scope, name.into(), function.into());
        });
        say(&format!("raw-built blob {} bytes", blob.len()));

        let params = v8::CreateParams::default()
            .external_references(Cow::Owned(references))
            .snapshot_blob(blob);
        let mut isolate = v8::Isolate::new(params);
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::from_snapshot(scope, index, Default::default())
            .expect("a context from the snapshot");
        let scope = &mut v8::ContextScope::new(scope, context);
        let source = v8::String::new(scope, "rawNative(); 'called'").expect("a source");
        let script = v8::Script::compile(scope, source, None).expect("a script");
        let value = script.run(scope).expect("the raw-built function to run");
        assert_eq!(
            value.to_rust_string_lossy(scope),
            "called",
            "a function built from a recorded raw address survives the round trip"
        );
    });
}

/// Wall 2: a builder-created callback makes the blob unbuildable unless its
/// thunk address is registered as an external reference.
///
/// This is why the build path needs a way to enumerate every callback address
/// before it can serialise a real realm.
#[test]
fn an_api_function_needs_its_thunk_as_an_external_reference() {
    with_v8(|| {
        // Without the reference the process aborts inside V8 (`Unknown external
        // reference`), which cannot be caught. So the assertion is the positive
        // case: with the thunk registered the blob builds, and the function is
        // still callable after a load. The negative case is recorded in this
        // test's doc comment rather than asserted, because a V8 fatal takes the
        // whole test binary with it.
        let raw: unsafe extern "C" fn(*const v8::FunctionCallbackInfo) =
            v8::MapFnTo::map_fn_to(probe_callback);
        say(&format!("callback thunk {:#x}", raw as usize));
        let references = vec![v8::ExternalReference {
            pointer: raw as *mut std::ffi::c_void,
        }];

        let (blob, index) = build_blob(&references, |scope| {
            let global = scope.get_current_context().global(scope);
            let template = v8::FunctionTemplate::builder(probe_callback).build(scope);
            let function = template.get_function(scope).expect("a function");
            let name = v8::String::new(scope, "native").expect("a name");
            global.set(scope, name.into(), function.into());
        });
        say(&format!("blob {} bytes", blob.len()));

        let params = v8::CreateParams::default()
            .external_references(Cow::Owned(references))
            .snapshot_blob(blob);
        let mut isolate = v8::Isolate::new(params);
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::from_snapshot(scope, index, Default::default())
            .expect("a context from the snapshot");
        let scope = &mut v8::ContextScope::new(scope, context);
        let source = v8::String::new(scope, "native(); 'called'").expect("a source");
        let script = v8::Script::compile(scope, source, None).expect("a script");
        let value = script.run(scope).expect("the native function to run");
        assert_eq!(value.to_rust_string_lossy(scope), "called");
    });
}

/// Wall 3: a serializer-enabled creator isolate no longer lacks `Float16Array`,
/// because V8 15.6 installs it outside the experimental set.
///
/// On V8 15.2 this test asserted the opposite. 15.2 kept `Float16Array` in a
/// separate `TYPED_ARRAYS_FLOAT16` macro reachable only from
/// `InitializeExperimentalGlobal`, so a creator isolate reported
/// `typeof Float16Array === 'undefined'` and `primordials.js` threw while
/// building a realm snapshot. 15.6 moved it into `TYPED_ARRAYS_BASE` and
/// installed it unconditionally in `InitializeGlobal`, so all three isolates
/// below — ordinary, build-time, and loaded — now report `function`.
///
/// That removes the wall, and the assertion records which engine it holds on
/// rather than assuming the 15.2 behaviour still applies.
#[test]
fn every_isolate_has_the_typed_array_intrinsics() {
    with_v8(|| {
        const REPORT: &str = "'Float16Array=' + typeof globalThis.Float16Array";
        fn report(scope: &mut v8::PinScope<'_, '_>) -> String {
            let source = v8::String::new(scope, REPORT).expect("a source");
            let script = v8::Script::compile(scope, source, None).expect("a script");
            script
                .run(scope)
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "threw".to_string())
        }

        let mut plain = v8::Isolate::new(Default::default());
        let ordinary = {
            let scope = std::pin::pin!(v8::HandleScope::new(&mut plain));
            let scope = &mut scope.init();
            let context = v8::Context::new(scope, Default::default());
            let scope = &mut v8::ContextScope::new(scope, context);
            report(scope)
        };
        drop(plain);

        let mut building = String::new();
        let (blob, index) = build_blob(&[], |scope| {
            building = report(scope);
        });
        let params = v8::CreateParams::default()
            .external_references(no_references())
            .snapshot_blob(blob);
        let mut isolate = v8::Isolate::new(params);
        let loaded = {
            let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
            let scope = &mut scope.init();
            let context = v8::Context::from_snapshot(scope, index, Default::default())
                .expect("a context from the snapshot");
            let scope = &mut v8::ContextScope::new(scope, context);
            report(scope)
        };

        say(&format!(
            "ordinary isolate: {ordinary}; build-time context: {building}; loaded context: {loaded}"
        ));
        assert_eq!(
            ordinary, "Float16Array=function",
            "an ordinary isolate installs the intrinsics"
        );
        assert_eq!(
            building, "Float16Array=function",
            "V8 15.6 installs Float16Array outside the experimental set, so a \
             serializer-enabled isolate has it too — this is what makes a realm \
             snapshot buildable at all"
        );
        assert_eq!(
            loaded, "Float16Array=function",
            "deserialisation re-runs Genesis, so they are present here as well"
        );
    });
}

/// Wall 4: a `v8::Global` that no serialised context reaches aborts the blob.
///
/// The abort is a V8 fatal, so the test records the positive control — a blob
/// with no live globals builds — and leaves the failing case to the comment.
/// rustnode's per-isolate caches have to be drained before `create_blob`; that
/// is the same requirement Node meets by running `ForEachRealm(VerifyNoStrong
/// BaseObjects)` and dropping every `Global` before serialising.
///
/// The failing case is recorded as its exact output in the module docs rather
/// than asserted here, because a V8 fatal takes the whole test binary with it. It
/// is deterministic: a `--build-snapshot` on a bootstrapped realm names 39
/// handles, 3 runs of 3 identical.
#[test]
fn a_blob_builds_only_when_no_unreachable_globals_are_alive() {
    with_v8(|| {
        let (blob, _index) = build_blob(&[], |scope| {
            // A symbol is the smallest handle a binding can cache, and it is
            // exactly the case `rn-core`'s per-isolate symbol table hits.
            let name = v8::String::new(scope, "probe:unreachable").expect("a name");
            let cached = v8::Global::new(scope, v8::Symbol::for_key(scope, name));
            // Dropping the handle before the blob builds is what unblocks it.
            // With it alive, `create_blob` aborts with
            // `(Global handles) handle not serialized` and
            // `CheckGlobalAndEternalHandles failed`.
            drop(cached);
        });
        say(&format!("blob {} bytes", blob.len()));
        assert!(!blob.is_empty());
    });
}

/// Walls 1 and 2 are not what blocks a realm snapshot: a bare blob builds and a
/// *second* isolate instantiates the added context from it and runs code.
///
/// This is the load half exercised end to end, in a separate isolate from the
/// one that built it — which is the only thing that proves a blob is portable
/// rather than a handle table V8 happens to share. It is worth pinning precisely
/// because the real `--build-snapshot` abort is *not* attributable to either of
/// these walls: the build path reaches wall 4 with the contexts and external
/// references in exactly the shape this test uses.
///
/// `--snapshot-blob` on a normal run is what a CLI load would use; this is the
/// API-level equivalent, and it is what a fixed build path would hand to
/// `Context::from_snapshot`.
#[test]
fn a_bare_blob_round_trips_into_a_second_isolate() {
    with_v8(|| {
        // Built in one isolate: a global the load has to see.
        let (blob, index) = build_blob(&[], |scope| {
            let global = scope.get_current_context().global(scope);
            let source = v8::String::new(scope, "globalThis.ported = 'yes'").expect("a source");
            let script = v8::Script::compile(scope, source, None).expect("a script");
            let _ = script.run(scope).expect("the build-time script runs");
            let _ = global;
        });
        say(&format!(
            "ported blob {} bytes at index {index}",
            blob.len()
        ));
        assert!(!blob.is_empty(), "the build produced a blob");

        // Loaded in a fresh isolate. `from_snapshot` on the added index is the
        // half wall 1 is about: index 0 is the default context's, whose global
        // proxy V8 does not serialise.
        let params = v8::CreateParams::default()
            .external_references(no_references())
            .snapshot_blob(blob);
        let mut isolate = v8::Isolate::new(params);
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::from_snapshot(scope, index, Default::default())
            .expect("the added context deserialises");
        let scope = &mut v8::ContextScope::new(scope, context);
        let source = v8::String::new(scope, "globalThis.ported").expect("a source");
        let script = v8::Script::compile(scope, source, None).expect("a script");
        let value = script.run(scope).expect("the loaded script runs");
        assert_eq!(
            value.to_rust_string_lossy(scope),
            "yes",
            "a global set while building is present after loading"
        );
    });
}
