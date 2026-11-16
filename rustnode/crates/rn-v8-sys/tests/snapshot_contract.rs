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
//! 2. **External references are mandatory.** `v8::FunctionTemplate::builder`
//!    with any callback produces a function whose code embeds the address of the
//!    generated `c_fn` thunk. Serialising an isolate that holds one aborts with
//!    `Unknown external reference 0x...`, because V8 cannot record an address it
//!    has not been told to expect. `CreateParams::external_references` is that
//!    list, and it has to hold *every* such thunk the bootstrapped isolate
//!    retains. rustnode has 358 `FunctionTemplate::builder` /
//!    `Function::builder` call sites, the thunks are monomorphised per callback
//!    (so ~1045 distinct addresses in a release build), and none of them are
//!    currently enumerable from Rust: `MapFnFrom`/`MapFnTo` are the only way to
//!    obtain one, and they are invoked inside the v8 crate's `FunctionBuilder`,
//!    which discards the value after handing it to V8.
//!
//! 3. **A serializer-enabled isolate has no experimental globals.** V8's
//!    `Genesis::InitializeGlobal` installs `InitializeExperimentalGlobal()`
//!    only `if (!isolate->serializer_enabled())`, with the comment
//!    "Do not include them into the snapshot as we should be able to turn them
//!    off at runtime". A snapshot creator calls `enable_serializer()` before the
//!    isolate is initialised, so a from-scratch creator isolate is missing every
//!    flag-gated intrinsic. On the linked V8 that includes `Float16Array`, and
//!    `internal/per_context/primordials.js` reads it, so the bootstrap throws
//!    `TypeError: Reflect.ownKeys called on non-object` before any of Node's own
//!    code runs. A *deserialised* context gets them back: the load path
//!    re-runs Genesis with `serializer_enabled()` false.
//!
//! 4. **Rust-side `v8::Global` caches are not serialisable.** `CreateBlob` runs
//!    `SerializedHandleChecker::CheckGlobalAndEternalHandles` and aborts with
//!    `handle not serialized` for every global handle that is neither reachable
//!    from a serialised context nor from a serialised embedder object. rustnode
//!    keeps per-isolate identity in thread-local `v8::Global` caches across ~48
//!    crates (per-isolate symbols, timer callbacks, the builtins lazy cache, the
//!    hook slots, ...), and none of them are reachable from a context, so the
//!    build has to drop all of them first — and the load path has to recreate
//!    them, which works for anything derived deterministically (`v8::Symbol::
//!    for_key` is stable per description) but not for a `v8::Global` wrapping a
//!    `Function` that the snapshot had rooted.

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

/// Wall 3: a from-scratch creator isolate lacks the flag-gated intrinsics that
/// the same V8 installs in an ordinary isolate, and a loaded context has them
/// again.
///
/// The middle arm is the one that matters: it is why `primordials.js` throws
/// during a build unless the build installs the missing globals itself.
#[test]
fn a_creator_isolate_omits_experimental_globals_a_loaded_one_has() {
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
            "an ordinary isolate installs the flag-gated intrinsics"
        );
        assert_eq!(
            building, "Float16Array=undefined",
            "a serializer-enabled isolate omits them, which is what breaks primordials"
        );
        assert_eq!(
            loaded, "Float16Array=function",
            "deserialisation re-runs Genesis without the serializer, so they come back"
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
