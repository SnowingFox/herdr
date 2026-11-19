//! `internalBinding('internal_only_v8').queryObjects`, driven through a real V8
//! isolate.
//!
//! # Why this file exists
//!
//! `queryObjects` crosses FFI into a hand-written shim
//! (`rn-v8-sys/src/query_objects.cc`) because the `v8` crate binds no
//! `HeapProfiler::QueryObjects`. The shim re-declares `v8::Global`,
//! `v8::Local`, `QueryObjectPredicate` and — the one that broke — the memory
//! layout of `std::__Cr::vector`.
//!
//! It was written against libc++ as V8 15.2 built it, where `vector` was
//! `{begin, end, capacity_end}`. V8 15.6's libc++ sets
//! `_LIBCPP_ABI_VECTOR_LAYOUT_SIZE_BASED`, so the same mangled type name now
//! denotes `{begin, size, capacity}`. The linker cannot tell those apart, so the
//! shim kept compiling and then read `end` and `capacity` as pointers when they
//! were counts — walking `[begin, 0x1)` and aborting the process with SIGABRT
//! and no message.
//!
//! The property that made that bug survive a green suite is that it needs a
//! **match**. An empty result leaves the vector as `{nullptr, 0, 0}`, and
//! treating `0` as a pointer walks nothing, so `queryObjects(SomeClass)` on a
//! heap with no instance answered `0` correctly. `test-v8-query-objects.js` only
//! failed at the step that allocates an instance first.
//!
//! So every test below that exercises the walk installs at least one matching
//! object. A version of this file that only queried an empty heap would have
//! passed against the broken shim, which is the trap being closed.

use std::pin::pin;

use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // `setFlagsFromString` aborts inside V8 once the flag list is frozen,
        // which happens during `V8::Initialize`. The CLI disables the freeze for
        // the same reason.
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Runs `body` with a live isolate, a context, and `__internal_only_v8` bound in
/// the global object.
fn with_namespace<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // The guard outlives the isolate: releasing it first would let another test
    // call `V8::initialize` concurrently.
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let mut scope = pin!(v8::ContextScope::new(&mut scope, context));

    // Installed through the module trait rather than `internalBinding`, so the
    // test needs no bootstrap JS. `queryObjects` is a plain member of the
    // namespace object.
    let object = rn_bind_heap_utils::InternalOnlyV8
        .install(
            &mut scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing internal_only_v8 must not fail");
    // `scope` reborrows immutably here: `global`, `get_current_context` and
    // `Object::set` all take `&PinScope`, so passing `&mut` would be a
    // needless-borrow that clippy rejects.
    let global = scope.get_current_context().global(&scope);
    let key = v8::String::new(&scope, "__v8").expect("allocating __v8");
    global.set(&scope, key.into(), object.into());

    body(&mut scope)
}

/// Compiles and runs `source`, returning its completion value as a string.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let text = v8::String::new(scope, source).expect("a source string");
    let script = v8::Script::compile(scope, text, None).expect("the script compiles");
    script
        .run(scope)
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "<threw>".to_string())
}

/// A class and one instance of it, so the heap holds a match.
const ONE_MATCH: &str = "
globalThis.ProbeClass = class ProbeClass {};
globalThis.ProbeInstance = new ProbeClass();
'ok'
";

/// A class with no instances, so the vector stays empty.
const NO_MATCH: &str = "
globalThis.ProbeClass = class ProbeClass {};
'ok'
";

#[test]
fn an_empty_heap_returns_an_empty_array() {
    with_namespace(|scope| {
        assert_eq!(run(scope, NO_MATCH), "ok");
        // An empty vector is `{nullptr, 0, 0}`, so reading `0` as an address
        // walks nothing even under the broken layout. This answers correctly
        // either way, which is why the next test is the one that matters.
        //
        // The member takes `ctor.prototype` and returns the matching objects as
        // an Array — `lib/internal/heap_utils.js` turns that into a count. See
        // `queryObjects` there; asserting a count here would be testing the JS
        // side's arithmetic rather than the shim.
        let found = run(scope, "__v8.queryObjects(ProbeClass.prototype).length");
        assert_eq!(found, "0", "a heap with no instance reports no matches");
    });
}

/// The case that crashed: at least one object matches, so the shim walks a
/// non-empty vector.
///
/// Under the size-based layout read as three pointers, the walk's bound is
/// `end` reinterpreted as an address, and the process aborts with SIGABRT. A
/// green run here is the regression test for that abort.
#[test]
fn a_matched_instance_is_returned_without_aborting() {
    with_namespace(|scope| {
        assert_eq!(run(scope, ONE_MATCH), "ok");
        let found = run(scope, "__v8.queryObjects(ProbeClass.prototype).length");
        assert_eq!(found, "1", "exactly one ProbeClass instance is on the heap");
    });
}

/// Two matches put more than one element in the vector, so an `end`-as-pointer
/// layout reads the second slot as an address rather than an element.
#[test]
fn two_matches_are_each_returned() {
    with_namespace(|scope| {
        assert_eq!(
            run(
                scope,
                "
globalThis.ProbeClass = class ProbeClass {};
globalThis.A = new ProbeClass();
globalThis.B = new ProbeClass();
'ok'
"
            ),
            "ok"
        );
        let found = run(scope, "__v8.queryObjects(ProbeClass.prototype).length");
        assert_eq!(found, "2", "two instances were allocated");
    });
}

/// A constructor with no instances is distinguished from one with instances,
/// which is the pair of calls `test-v8-query-objects.js` makes in sequence.
///
/// Running them in one isolate is what the real test does, and a shim that
/// releases the vector's globals incorrectly on the first call corrupts the
/// global-handle free list that the second call's allocation then uses.
#[test]
fn an_empty_query_then_a_matched_one_both_answer() {
    with_namespace(|scope| {
        assert_eq!(run(scope, NO_MATCH), "ok");
        assert_eq!(
            run(scope, "__v8.queryObjects(ProbeClass.prototype).length"),
            "0"
        );
        assert_eq!(
            run(scope, "globalThis.ProbeInstance = new ProbeClass(); 'ok'"),
            "ok"
        );
        assert_eq!(
            run(scope, "__v8.queryObjects(ProbeClass.prototype).length"),
            "1"
        );
    });
}

/// A search value that is not an object yields an empty array rather than
/// walking the heap.
///
/// The member answers `[]` for a non-object search; the `ERR_INVALID_ARG_TYPE`
/// that `test-v8-query-objects.js` expects is raised by the JavaScript wrapper
/// in `lib/internal/heap_utils.js`, before this member is reached. Pinned so a
/// future change cannot start dereferencing a bad `search`.
#[test]
fn a_non_object_search_does_not_walk_the_heap() {
    with_namespace(|scope| {
        let outcome = run(
            scope,
            "JSON.stringify(__v8.queryObjects(1)) + '|' + typeof __v8.queryObjects(1)",
        );
        assert_eq!(
            outcome, "[]|object",
            "a non-object search is answered with an empty array"
        );
    });
}
