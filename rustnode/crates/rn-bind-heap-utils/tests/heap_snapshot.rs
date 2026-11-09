//! The `heap_utils` snapshot stream, driven through a real V8 isolate.
//!
//! Two members are under test and the difference between them matters:
//!
//! * `triggerHeapSnapshot` writes V8's JSON straight to a file.
//! * `createHeapSnapshotStream` hands the same JSON to a `StreamBase` handle,
//!   which `lib/internal/stream_base_commons.js`'s `onStreamRead` reads through
//!   `streamBaseState` and `handle.onread`.
//!
//! The second one is easy to fake: a stream that emits a fixed string, or that
//! emits once and ends, looks like a snapshot until something parses it. So these
//! tests parse the bytes, check the document against the shape V8 produces, and
//! check the chunking and the read protocol against what a real Node binary does.
//!
//! # Why the read protocol is asserted rather than assumed
//!
//! `HeapSnapshotStream::GetChunkSize()` is 65536 and `WriteAsciiChunk` ignores
//! backpressure, so one `readStart` pushes the whole document as 64 KiB chunks
//! followed by one `UV_EOF`. That is observable from JavaScript, and it is what
//! distinguishes this from a stub: a stub has one chunk and no `readStop` calls.

use rn_bind_heap_utils::{stream, HeapUtils};
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
///
/// V8's platform and initialisation are process-global, so the tests serialise on
/// a mutex instead of each calling `V8::initialize`.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // The guard must outlive the isolate: dropping it would let a second test
    // enter `V8::initialize` concurrently.
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    // `take_heap_snapshot` needs an `Isolate` outside a callback scope, which is
    // exactly the pointer `set_snapshot_isolate` records. The CLI does the same
    // immediately after creating its isolate.
    rn_bind_heap_utils::set_snapshot_isolate(&mut isolate);
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let scope = std::pin::pin!(v8::ContextScope::new(&mut scope, context));
    let mut scope = scope;
    body(&mut scope)
}

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // `setFlagsFromString` — reached through `lib/v8.js` — aborts inside V8
        // once the flag list is frozen, which happens during `V8::Initialize`.
        // The CLI disables the freeze for the same reason.
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace and binds it to `__heap` in the global object.
///
/// `streamBaseState` is created by the install too, because `onStreamRead` reads
/// it before it looks at the `ArrayBuffer` it is handed.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = HeapUtils
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the heap_utils namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__heap").expect("allocating __heap");
    global.set(scope, key.into(), object.into());
}

/// Compiles and runs `source`, returning its completion value as a string.
///
/// A thrown exception is reported as the test's failure with its message, because
/// a V8 `TryCatch` that swallowed one would make every assertion below pass on a
/// `undefined` result.
fn run(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let source = v8::String::new(scope, source).expect("allocating the script");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let try_catch = try_catch.init();
    let script = v8::Script::compile(&try_catch, source, None).expect("the script must compile");
    let result = script.run(&try_catch);
    if try_catch.has_caught() {
        let exception = try_catch.exception().expect("a caught exception");
        panic!(
            "the script threw: {}",
            exception.to_rust_string_lossy(&try_catch)
        );
    }
    result
        .map(|value| value.to_rust_string_lossy(&try_catch))
        .unwrap_or_default()
}

/// JavaScript helpers the cases below share.
///
/// `collect` drives the handle the way `HeapSnapshotStream` in
/// `lib/internal/heap_utils.js` does — assign `onread`, call `readStart` — and
/// returns the chunks. It deliberately does *not* go through
/// `internal/stream_base_commons.js`; that file is exercised by the CLI tests,
/// and reaching it here would need the whole `stream` machinery.
///
/// Chunks are joined into one byte array in Rust rather than with
/// `TextDecoder`/`Buffer`, neither of which a bare isolate has.
const HELPERS: &str = r#"
globalThis.collect = function collect(handle) {
  const chunks = [];
  let ended = false;
  handle.onread = function (arrayBuffer) {
    const state = __streamBaseState();
    const nread = state[0];
    const offset = state[1];
    if (nread === 0) return;
    if (nread < 0) { ended = true; return; }
    chunks.push(new Uint8Array(arrayBuffer, offset, nread).slice());
  };
  const status = handle.readStart();
  return { chunks, ended, status };
};
globalThis.concat = function concat(chunks) {
  let length = 0;
  for (const chunk of chunks) length += chunk.length;
  const out = new Uint8Array(length);
  let position = 0;
  for (const chunk of chunks) { out.set(chunk, position); position += chunk.length; }
  return out;
};
"#;

/// Binds `streamBaseState` and the helper functions into the global object.
fn install_helpers(scope: &mut v8::PinScope<'_, '_>) {
    let state = rn_uv::stream::state_array(scope).expect("streamBaseState must be creatable");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__streamBaseState").expect("allocating __streamBaseState");
    let state = v8::Local::<v8::Function>::try_from(make_thunk(scope, state))
        .expect("the state thunk must be a function");
    global.set(scope, key.into(), state.into());
    run(scope, HELPERS);
}

/// Wraps a value in a function returning it, so JavaScript can read
/// `streamBaseState` without this crate publishing it on the namespace.
fn make_thunk<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> v8::Local<'s, v8::Value> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__thunkValue").expect("allocating __thunkValue");
    global.set(scope, key.into(), value);
    let source =
        v8::String::new(scope, "() => globalThis.__thunkValue").expect("allocating source");
    let script = v8::Script::compile(scope, source, None).expect("the thunk must compile");
    script.run(scope).expect("the thunk must run")
}

/// Reads the `Uint8Array` the last script left in the global `__document` and
/// parses it as JSON.
///
/// The bytes travel as bytes rather than through a JavaScript string because a
/// bare isolate has no `TextDecoder`/`Buffer`, and decoding a 5 MiB UTF-8
/// document inside V8 would make this test slower than the snapshot it checks.
fn parse_document(scope: &mut v8::PinScope<'_, '_>) -> serde_json::Value {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__document").expect("allocating __document");
    let value = global
        .get(scope, key.into())
        .expect("__document must be set");
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value)
        .expect("__document must be an ArrayBufferView");
    let length = view.byte_length();
    let base = view.data().cast::<u8>().cast_const();
    assert!(!base.is_null(), "__document has no backing store");
    // SAFETY: `data()` describes `length` bytes of the view's backing store,
    // which the `value` local keeps alive for the duration of this call.
    let bytes = unsafe { std::slice::from_raw_parts(base, length) };
    serde_json::from_slice(bytes).expect("the snapshot must be valid JSON")
}

#[test]
fn every_contract_member_is_installed_or_deferred() {
    // A member that is neither installed nor declared is the failure `rn-compat`
    // calls an undeclared gap, and `deferred-reach.py` then asks whether `lib/**`
    // calls it at load time. Both are reported rather than left to a `require()`
    // failure somewhere else.
    let mut installed = Vec::new();
    let deferred: Vec<&str> = rn_bind_heap_utils::DEFERRED
        .iter()
        .map(|(name, _)| *name)
        .collect();
    // `install` decides what exists at runtime, so the check is against its
    // result rather than against `MEMBERS`, which is the contract's list.
    with_context(|scope| {
        install(scope);
        let script = "Object.keys(globalThis.__heap).sort().join(',')";
        installed = run(scope, script).split(',').map(str::to_string).collect();
    });
    assert_eq!(
        installed,
        ["createHeapSnapshotStream", "triggerHeapSnapshot"]
    );
    for name in &installed {
        assert!(
            !deferred.contains(&name.as_str()),
            "{name} is installed and also declared deferred"
        );
    }
    assert_eq!(deferred, ["buildEmbedderGraph"]);
}

#[test]
fn the_deferred_reason_names_the_missing_api() {
    // The point of a declared deferral is that the reason is actionable: it has to
    // say which V8 entry point is absent, not that the feature "is not supported".
    let (_, reason) = rn_bind_heap_utils::DEFERRED[0];
    assert!(
        reason.contains("AddBuildEmbedderGraphCallback"),
        "the reason must name the missing V8 API: {reason}"
    );
    assert!(
        reason.contains("EmbedderGraph"),
        "the reason must name the type it needs: {reason}"
    );
}

#[test]
fn the_stream_is_a_real_snapshot_document() {
    with_context(|scope| {
        install(scope);
        install_helpers(scope);
        // Leave the joined snapshot in `__document` for Rust to decode, and
        // report the pieces that only a real snapshot has.
        let script = r#"
          (() => {
            const handle = __heap.createHeapSnapshotStream(new Uint8Array([0, 0]));
            const result = collect(handle);
            globalThis.__document = concat(result.chunks);
            return JSON.stringify({
              ended: result.ended,
              status: result.status,
              chunks: result.chunks.length,
              largestChunk: Math.max(...result.chunks.map((c) => c.length)),
              bytesRead: handle.bytesRead,
              isStreamBase: handle.isStreamBase,
              fd: handle.fd,
            });
          })()
        "#;
        let report = run(scope, script);
        let report: serde_json::Value =
            serde_json::from_str(&report).expect("the driver must return JSON");
        let document = parse_document(scope);

        assert_eq!(report["ended"], true, "the stream must report EOF");
        assert_eq!(report["status"], 0, "readStart returns 0");
        assert_eq!(report["isStreamBase"], true);
        assert_eq!(report["fd"], -1, "StreamBase::GetFD is -1");

        // The chunking is `GetChunkSize()` applied to one buffered document, so
        // every chunk but the last is exactly 64 KiB. More than one chunk is what
        // proves the document went through the read protocol rather than being
        // handed over in one piece.
        assert_eq!(report["largestChunk"], stream::CHUNK_SIZE);
        assert!(report["chunks"].as_u64().unwrap_or(0) > 1);

        // The sections a `.heapsnapshot` must have for DevTools to load it.
        let mut keys: Vec<&str> = document
            .as_object()
            .expect("the document is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "edges",
                "locations",
                "nodes",
                "samples",
                "snapshot",
                "strings",
                "trace_function_infos",
                "trace_tree"
            ]
        );

        assert_eq!(document["strings"][0], "<dummy>");
        let node_count = document["snapshot"]["node_count"].as_u64().unwrap_or(0);
        let edge_count = document["snapshot"]["edge_count"].as_u64().unwrap_or(0);
        assert!(
            node_count > 100,
            "a real heap has more than a hundred nodes"
        );
        assert!(edge_count > 0);

        // The two length relations that prove the arrays are the flattened form
        // V8 documents: one entry per node per field.
        let node_fields = document["snapshot"]["meta"]["node_fields"]
            .as_array()
            .expect("node_fields is an array")
            .len();
        assert_eq!(
            document["nodes"]
                .as_array()
                .expect("nodes is an array")
                .len(),
            node_count as usize * node_fields
        );
        let edge_fields = document["snapshot"]["meta"]["edge_fields"]
            .as_array()
            .expect("edge_fields is an array")
            .len();
        assert_eq!(
            document["edges"]
                .as_array()
                .expect("edges is an array")
                .len(),
            edge_count as usize * edge_fields
        );

        // `bytesRead` counts what was delivered, which `StreamBase::EmitRead`
        // increments before the listener runs.
        assert!(
            report["bytesRead"].as_u64().unwrap_or(0) > 1000,
            "bytesRead must count the snapshot: {}",
            report["bytesRead"]
        );
    });
}

#[test]
fn a_second_read_after_eof_delivers_nothing() {
    // Node `CHECK`s the snapshot is non-null in `ReadStart`, so this path is a
    // caller bug either way; what matters is that it returns without pushing the
    // document twice, which would append a second JSON object to the stream.
    with_context(|scope| {
        install(scope);
        install_helpers(scope);
        let script = r#"
          (() => {
            const handle = __heap.createHeapSnapshotStream(new Uint8Array([0, 0]));
            const first = collect(handle);
            const second = collect(handle);
            return JSON.stringify({
              firstChunks: first.chunks.length,
              secondChunks: second.chunks.length,
              secondEnded: second.ended,
              secondStatus: second.status,
            });
          })()
        "#;
        let report: serde_json::Value =
            serde_json::from_str(&run(scope, script)).expect("the driver must return JSON");
        assert!(report["firstChunks"].as_u64().unwrap_or(0) > 1);
        assert_eq!(report["secondChunks"], 0);
        // Node `CHECK`s the snapshot is non-null and aborts; this returns 0
        // without emitting anything, so a caller is not handed a second `end`
        // for a stream that already ended.
        assert_eq!(report["secondStatus"], 0);
        assert_eq!(report["secondEnded"], false);
    });
}

#[test]
fn two_streams_are_independent() {
    // `parallel/test-v8-getheapsnapshot-twice.js` exists because the first
    // snapshot must be collectable while the second is created. Two live handles
    // therefore have to keep two separate documents, and each must start at
    // offset 0 of its own buffer rather than sharing one.
    with_context(|scope| {
        install(scope);
        install_helpers(scope);
        // Each stream is parsed by leaving it in `__document` and handing the
        // bytes back, so the two documents are compared as JSON rather than as
        // strings this isolate cannot decode.
        let first = r#"
          (() => {
            const handle = __heap.createHeapSnapshotStream(new Uint8Array([0, 0]));
            const result = collect(handle);
            globalThis.__document = concat(result.chunks);
            return JSON.stringify({ bytes: handle.bytesRead, ended: result.ended });
          })()
        "#;
        let first_report: serde_json::Value =
            serde_json::from_str(&run(scope, first)).expect("the driver must return JSON");
        let first_document = parse_document(scope);
        let second_report: serde_json::Value =
            serde_json::from_str(&run(scope, first)).expect("the driver must return JSON");
        let second_document = parse_document(scope);

        // Both are complete, independently parsed snapshots.
        for (label, report, document) in [
            ("first", &first_report, &first_document),
            ("second", &second_report, &second_document),
        ] {
            assert_eq!(report["ended"], true, "{label} must report EOF");
            assert!(
                report["bytes"].as_u64().unwrap_or(0) > 1000,
                "{label} delivered {} bytes",
                report["bytes"]
            );
            assert!(
                document["snapshot"]["node_count"].as_u64().unwrap_or(0) > 100,
                "{label} is not a real snapshot"
            );
            assert!(document["nodes"].as_array().is_some_and(|n| !n.is_empty()));
        }
        // The second snapshot describes a heap that now contains the first
        // document's arrays, so it cannot be identical to the first.
        assert_ne!(
            first_report["bytes"], second_report["bytes"],
            "a second snapshot must describe the heap as it is then"
        );
    });
}

#[test]
fn trigger_heap_snapshot_writes_the_same_document() {
    // The two members share V8's serializer, so a file written by
    // `triggerHeapSnapshot` and a stream from `createHeapSnapshotStream` must have
    // the same top-level shape. This pins that they are one implementation rather
    // than two that agree by accident.
    let directory = std::env::temp_dir().join(format!("rn-heap-utils-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("creating the scratch directory");
    let path = directory.join("heap.heapsnapshot");
    let path_text = path.to_string_lossy().into_owned();

    with_context(|scope| {
        install(scope);
        let script = format!(
            "String(__heap.triggerHeapSnapshot({}))",
            json_quote(&path_text)
        );
        assert_eq!(run(scope, &script), path_text, "the filename is returned");
    });

    let written = std::fs::read_to_string(&path).expect("the snapshot file must exist");
    let document: serde_json::Value =
        serde_json::from_str(&written).expect("the file must be valid JSON");
    assert!(
        document.get("snapshot").is_some(),
        "the file has a snapshot"
    );
    assert!(document.get("nodes").is_some());
    assert!(document.get("edges").is_some());
    let node_count = document["snapshot"]["node_count"].as_u64().unwrap_or(0);
    assert!(node_count > 100, "node_count is {node_count}");

    // `WriteSnapshot` opens `O_WRONLY | O_CREAT | O_TRUNC` at `0600`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("the file must be readable")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the file mode is {mode:o}");
    }

    std::fs::remove_dir_all(&directory).ok();
}

/// A JSON string literal, so a temporary path survives the trip into JavaScript.
fn json_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
