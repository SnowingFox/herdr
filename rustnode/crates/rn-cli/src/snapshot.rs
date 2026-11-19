//! `--build-snapshot`: serialise a bootstrapped realm with `SnapshotCreator`.
//!
//! This is the build half of Node's `SnapshotBuilder::Generate`
//! (`src/node_snapshotable.cc`). Node's flow is: create a snapshot-creator
//! isolate, bootstrap the environment into it, optionally run a builder script,
//! then `CreateBlob`. The load half (`--snapshot-blob` on a normal run) reads the
//! blob back and instantiates an *added* context from it.
//!
//! # Why this is its own isolate rather than a mode of `main`'s
//!
//! `v8::OwnedIsolate::create_blob` takes `self` **by value** and its doc comment
//! says it "must not be called from within a handle scope". In `main` the handle
//! scope is pinned for the whole function, so the isolate that scope borrows
//! cannot be moved out of it — the borrow checker enforces V8's rule for free, but
//! it also means `create_blob` cannot be called from anywhere inside `main`. A
//! separate function that owns its isolate and its scope in one body is the shape
//! that has both: the scope ends with the body, and the isolate outlives it.
//!
//! # Why a creator isolate rather than converting the running one
//!
//! `SnapshotCreator` enables the serializer before V8 initialises, and that
//! changes Genesis: a creator isolate skips `InitializeExperimentalGlobal`. An
//! isolate cannot be converted after initialisation, so a build starts from a
//! creator and runs the ordinary bootstrap into it.
//!
//! # Why the build bootstraps twice
//!
//! `CreateParams::external_references` is consumed when the isolate is
//! **created**, but the table it has to hold is only complete once the realm's
//! templates have been **built**, which happens during bootstrap — after the
//! isolate exists. Node has the same order and solves it the same way, by
//! keeping its registry (`src/node_external_reference.h:38`) alive across the two
//! phases. So [`build`] runs:
//!
//! 1. a **discovery** creator, whose only product is the filled table;
//! 2. a **serialising** creator, created with that table in `CreateParams`, which
//!    bootstraps the realm again and then serialises it.
//!
//! The second bootstrap is what makes the addresses recorded in the first pass
//! meaningful: the templates it builds are built from those same addresses
//! (`rn_core::function`'s funnel), so the table and the serialised code agree by
//! construction rather than by agreement between two lists.
//!
//! # What this module does not do
//!
//! It does not paper over a wall. If V8 aborts, the process dies with V8's own
//! message and that message is the report. A blob that serialised by dropping
//! state would load and then misbehave, which is worse than no blob.
//!
//! `crates/rn-v8-sys/tests/snapshot_contract.rs` pins each wall, in the order a
//! build meets them. Read it before changing anything here.

use std::borrow::Cow;

use rn_v8_sys::v8;

/// The blob path Node uses: `--snapshot-blob` if given, else `snapshot.blob` in
/// the working directory (`src/node.cc`, `GenerateAndWriteSnapshotData`).
pub fn blob_path(configured: Option<&str>) -> String {
    match configured {
        Some(path) if !path.is_empty() => path.to_string(),
        _ => "snapshot.blob".to_string(),
    }
}

/// Builds a snapshot of a freshly bootstrapped realm and writes it to `path`.
///
/// `params` produces the isolate configuration a normal run uses, so the snapshot
/// captures a realm built under the same heap limits and allocator. It is called
/// twice, once per pass, because `CreateParams` is consumed by
/// `Isolate::snapshot_creator` and holds a `SharedPtr` allocator that a `Clone`
/// would alias between two live isolates. The second call's result is given the
/// external-reference table; the first's is not, which is the whole point of
/// running it first.
///
/// `bootstrap` runs inside the added context with a `&mut PinScope`, which is
/// where the realm is built. It runs twice — see the module docs — so it has to
/// be callable more than once and must not depend on state it left the first time.
/// It must not run a user program: Node serialises the environment the bootstrap
/// produced, not whatever a script left behind.
///
/// Returns the blob's size in bytes.
///
/// # Aborts
///
/// A V8 fatal inside `create_blob` ends the process without returning. The three
/// that are reachable here are pinned in `snapshot_contract.rs`: a missing
/// default context, an unregistered external reference, and an unserialised
/// thread-local handle. None can be caught.
pub fn build(
    params: impl Fn() -> v8::CreateParams,
    bootstrap: impl Fn(&mut v8::PinScope<'_, '_>),
    path: &str,
) -> Result<usize, String> {
    // Pass one: discover the external-reference table. The isolate is thrown away
    // — nothing it built is serialised — and the only product is the registry the
    // bootstrap filled while building templates.
    //
    // A *plain* isolate rather than a snapshot creator, deliberately:
    // `OwnedIsolate::drop` panics for a creator ("you should use create_blob
    // before dropping an isolate"), and calling `create_blob` here would be wrong
    // twice over — it would run the serializer over a table that is by definition
    // still incomplete, and it is exactly the check this pass exists to avoid.
    // A plain isolate builds the same templates, which is all the registry needs:
    // the address of a monomorphised thunk is a property of the code, not of the
    // isolate that used it.
    //
    // # Why the discovery pass is followed by a drain
    //
    // Bootstrapping a realm fills thread-local `v8::Global` caches — the binding
    // registry's installed objects, `hook_slot`'s loaders and primordials, the
    // per-realm hook tables. Those handles belong to the discovery isolate, which
    // is destroyed the moment this pass ends. Left in place they are stale handles
    // into a disposed isolate, and pass two faults on the first one it reads:
    // `attempt to access Handle hosted by disposed Isolate`, from
    // `BindingRegistry::install` — which finds the discovery realm's cached object
    // by realm id and hands it back.
    //
    // So the caches are dropped here, before pass two. Pass two then starts with
    // empty caches, exactly as a fresh process would, and refills them with
    // handles that belong to the isolate that will be serialised.
    discovery_pass(&params, &bootstrap);
    rn_core::snapshot_drain::drop_realm_handles();
    let references = external_reference_table();
    if references.is_empty() {
        return Err(
            "the realm bootstrap recorded no external references, so a blob built from it \
             could not be reloaded"
                .to_string(),
        );
    }
    eprintln!(
        "rustnode: recording {} external reference(s) for the snapshot",
        recorded_reference_count()
    );

    // Pass two: the isolate that is actually serialised. Its `CreateParams` carry
    // the table, which is what lets V8 resolve a recorded thunk to its index at
    // serialisation time and back at load time.
    let params = params().external_references(Cow::Owned(references));
    let mut creator = v8::Isolate::snapshot_creator(None, Some(params));

    let index = {
        let scope = std::pin::pin!(v8::HandleScope::new(&mut creator));
        let scope = &mut scope.init();
        // Wall 1: `CreateBlob` requires a default context, and that context's
        // global proxy is the one V8 does not serialise. The context a load
        // instantiates has to be one *added* afterwards.
        let default_context = v8::Context::new(scope, Default::default());
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        bootstrap(scope);
        // Attach the state the blob must carry, before anything is drained: a
        // provider reads the handles its crate kept during bootstrap, and the
        // drain drops some of them.
        let carried = rn_core::snapshot_data::attach_all(scope, context);
        eprintln!("rustnode: attached {carried} value(s) of realm state to the blob");
        // Reached through `AsMut<Isolate>` on the scope, which is the borrow that
        // already exists; `creator` itself is borrowed by `scope`.
        let isolate: &mut v8::Isolate = (*scope).as_mut();
        isolate.set_default_context(default_context);
        isolate.add_context(context)
    };

    // Wall 4: `CreateBlob` aborts on every thread-local `v8::Global` it cannot
    // reach from a serialised context, and this bootstrap filled those caches the
    // same way the discovery pass did. Dropping them here is what the abort list
    // asks for, and it happens after the scope has ended so the handle scope is
    // not live while their slots are cleared.
    //
    // Safe to do before `create_blob` for the same reason it is safe in the
    // discovery pass: every slot dropped is a cache or a per-realm object that the
    // blob's own serialised copies replace, and the load path reinstalls the
    // loaders. See `rn_core::snapshot_drain`.
    let drained = rn_core::snapshot_drain::drop_realm_handles();
    eprintln!("rustnode: dropped the realm's handles through {drained} drain(s)");
    // Node keeps its contexts at fixed indices, but this build has one, so the
    // added index must be 0. Anything else means a load would instantiate the
    // wrong realm.
    if index != 0 {
        return Err(format!(
            "the added context landed at index {index}, not 0 — a load would \
             instantiate the wrong realm"
        ));
    }

    // The scope has ended with the block above, which is what makes this legal:
    // `create_blob` consumes the isolate and must not run inside a handle scope.
    // `FunctionCodeHandling::Clear` rather than `Keep`, matching Node unless a
    // code cache is asked for: a blob that keeps function code is tied to the
    // exact bytecode this build produced.
    let blob = creator
        .create_blob(v8::FunctionCodeHandling::Clear)
        .ok_or_else(|| "CreateBlob returned no data".to_string())?;

    // Node refuses a blob that cannot be rehashed
    // (`src/node_snapshotable.cc`, `CanBeRehashed`): such a blob fixes V8's hash
    // seed at build time, which is a hash-flooding hazard rather than a build
    // defect.
    if !blob.can_be_rehashed() {
        return Err(
            "the blob cannot be rehashed, so its hash seed would be fixed at build time"
                .to_string(),
        );
    }

    // `StartupData` derefs to `[u8]` and owns the V8-allocated buffer until it is
    // dropped, so the bytes are written while it is alive.
    let bytes = blob.len();
    std::fs::write(path, &*blob)
        .map_err(|error| format!("Cannot open {path} for writing a snapshot: {error}"))?;
    Ok(bytes)
}

/// The external-reference table the discovery pass recorded.
///
/// Deduplicated and in first-seen order by `rn_core::external_references`, which
/// is also where the ordering is measured rather than assumed.
fn external_reference_table() -> Vec<v8::ExternalReference> {
    rn_core::external_references::table()
}

/// Clears the recorded table so a later discovery pass starts from nothing.
///
/// Called by the CLI before its first pass: a process that had already
/// bootstrapped a realm would otherwise carry that realm's addresses into the
/// table, and they describe an isolate the blob does not contain.
pub fn forget_recorded_references() {
    rn_core::external_references::clear();
}

/// How many addresses the last discovery pass recorded, for reporting.
pub fn recorded_reference_count() -> usize {
    rn_core::external_references::recorded_count()
}

/// Runs the bootstrap once in a throwaway isolate, for its registry side effect.
///
/// See the call site for why this is a plain isolate and not a snapshot creator.
/// The realm it builds is discarded with the isolate; the bootstrap is required to
/// be repeatable, which `build`'s contract already states.
fn discovery_pass(
    params: &impl Fn() -> v8::CreateParams,
    bootstrap: impl FnOnce(&mut v8::PinScope<'_, '_>),
) {
    let mut isolate = v8::Isolate::new(params());
    {
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        bootstrap(scope);
    }
    // Collect this isolate's garbage before disposing it, so anything the
    // bootstrap left reachable only through it is reclaimed here rather than
    // counted against the next isolate. `low_memory_notification` is the public
    // form of a full collection; `request_garbage_collection_for_testing` is the
    // same thing but V8 fatals unless `--expose-gc` is set, which a build must not
    // require of its own runtime.
    isolate.low_memory_notification();
}
