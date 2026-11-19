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
//! # What this module does not do
//!
//! It does not paper over a wall. If V8 aborts, the process dies with V8's own
//! message and that message is the report. A blob that serialised by dropping
//! state would load and then misbehave, which is worse than no blob.
//!
//! `crates/rn-v8-sys/tests/snapshot_contract.rs` pins each wall, in the order a
//! build meets them. Read it before changing anything here.

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
/// `bootstrap` runs inside the added context with a `&mut PinScope`, which is
/// where the realm is built. It must not run a user program: Node serialises the
/// environment the bootstrap produced, not whatever a script left behind.
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
    params: v8::CreateParams,
    bootstrap: impl FnOnce(&mut v8::PinScope<'_, '_>),
    path: &str,
) -> Result<usize, String> {
    // Wall 2: the external-reference list. The vendored crate exposes the
    // `ExternalReference` type and `CreateParams::external_references`, but no
    // table of this build's callback thunks, and V8 offers no way to read one back
    // out of a built template. So the list is empty here and V8 names the first
    // function it cannot account for — that message is the report.
    //
    // `snapshot_contract.rs` proves the mechanism a table would use
    // (`MapFnTo::map_fn_to` gives the address, `builder_raw` takes it back), so
    // filling this is mechanical work rather than an open question.
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
        // Reached through `AsMut<Isolate>` on the scope, which is the borrow that
        // already exists; `creator` itself is borrowed by `scope`.
        let isolate: &mut v8::Isolate = (*scope).as_mut();
        isolate.set_default_context(default_context);
        isolate.add_context(context)
    };
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
