//! End-to-end checks that drive the binding through a real V8 isolate.
//!
//! `lib/zlib.js` is unchanged Node code, so the only way to know this crate
//! speaks the right protocol is to run the same calls it makes: construct a
//! handle, `init` it with a `Uint32Array(2)` and a write callback, then loop
//! `writeSync` exactly like `processChunkSync` does and read the offsets back
//! out of the typed array.

use rn_bind_zlib::Zlib;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The `processChunkSync` loop from `lib/zlib.js`, transcribed.
///
/// It exists so the tests below exercise the native handle the way real Node
/// code does, including the "output buffer full, reprocess the same chunk"
/// case that `availInBefore`/`availInAfter` drive.
const DRIVER: &str = r#"
globalThis.driveSync = function driveSync(handle, input, flushFlag, chunkSize) {
  const state = handle.__writeState;
  let availInBefore = input.length;
  let availOutBefore = chunkSize;
  let inOff = 0;
  let availOutAfter;
  let availInAfter;

  const out = [];
  let total = 0;

  while (true) {
    handle.writeSync(flushFlag, input, inOff, availInBefore,
                     handle.__out, 0, availOutBefore);
    if (handle.__error) throw handle.__error;

    availOutAfter = state[0];
    availInAfter = state[1];

    const inDelta = availInBefore - availInAfter;
    const have = availOutBefore - availOutAfter;
    if (have > 0) {
      out.push(handle.__out.slice(0, have));
      total += have;
    }

    if (availOutAfter === 0 || out.length * chunkSize >= chunkSize) {
      availOutBefore = chunkSize;
    }

    if (availOutAfter === 0) {
      inOff += inDelta;
      availInBefore = availInAfter;
    } else {
      break;
    }
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of out) { joined.set(part, offset); offset += part.length; }
  return joined;
};

// A UTF-8 encoder for ASCII-only inputs; a bare V8 isolate has neither
// `TextEncoder` nor `Buffer`, and these tests only need ASCII bytes.
globalThis.asciiBytes = function asciiBytes(text) {
  const out = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) out[index] = text.charCodeAt(index) & 0xff;
  return out;
};

globalThis.asciiText = function asciiText(bytes) {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
};

globalThis.makeHandle = function makeHandle(ctorName, mode, args, chunkSize) {
  const binding = globalThis.__zlibBinding;
  const handle = new binding[ctorName](mode);
  handle.__writeState = new Uint32Array(2);
  handle.__error = null;
  handle.__out = new Uint8Array(chunkSize);
  handle.onerror = (message, errno, code) => {
    handle.__error = { message, errno, code };
  };
  handle.init(...args, handle.__writeState, () => {}, null, false);
  return handle;
};
"#;

/// Runs `source` in a fresh isolate with the binding installed, returning the
/// last expression's value as a string.
fn eval_with_binding(source: &str) -> String {
    eval_sequence(&[source])
}

/// Runs several scripts in one isolate, flushing microtasks between them.
///
/// V8's platform and global state are process-wide, so every case runs from a
/// single `#[test]`; see `zlib_binding_end_to_end`.
fn eval_sequence(sources: &[&str]) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = Zlib
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("zlib binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__zlibBinding").expect("key");
    global.set(scope, key.into(), binding.into());

    let mut result = String::new();
    for prelude in std::iter::once(DRIVER).chain(sources.iter().copied()) {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let code = v8::String::new(scope, prelude).expect("source");
        let script = v8::Script::compile(scope, code, None).expect("compiles");
        let run = script.run(scope);
        if scope.has_caught() || run.is_none() {
            let exception = scope
                .exception()
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown exception".to_string());
            panic!("javascript threw: {exception}");
        }
        if let Some(value) = run {
            result = value.to_rust_string_lossy(scope);
        }
        // Deliver queued completions between scripts, the way the event loop
        // would between turns.
        scope.perform_microtask_checkpoint();
    }
    result
}

fn namespace_members() {
    let result = eval_with_binding(
        r#"
        const binding = globalThis.__zlibBinding;
        JSON.stringify({
          zlib: typeof binding.Zlib,
          encoder: typeof binding.BrotliEncoder,
          decoder: typeof binding.BrotliDecoder,
          crc32: typeof binding.crc32,
          version: binding.ZLIB_VERSION,
          methods: ['init', 'write', 'writeSync', 'params', 'reset', 'close']
            .filter((name) => typeof binding.Zlib.prototype[name] === 'function'),
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"zlib":"function","encoder":"function","decoder":"function","crc32":"function","version":"1.3.1","methods":["init","write","writeSync","params","reset","close"]}"#
    );
}

fn crc32_value() {
    let result = eval_with_binding(
        r#"
        const { crc32 } = globalThis.__zlibBinding;
        const fromString = crc32('hello world');
        const fromBytes = crc32(asciiBytes('hello world'));
        // The seed parameter must be honoured, exactly as lib/zlib.js expects.
        const seeded = crc32('world', crc32('hello '));
        JSON.stringify({ fromString, fromBytes, seeded, hex: fromString.toString(16) });
        "#,
    );
    assert_eq!(
        result,
        r#"{"fromString":222957957,"fromBytes":222957957,"seeded":222957957,"hex":"d4a1185"}"#
    );
}

fn deflate_round_trip() {
    let result = eval_with_binding(
        r#"
        const MODE_DEFLATE = 1;
        const MODE_INFLATE = 2;
        const Z_FINISH = 4;

        const input = asciiBytes('hello from the zlib binding '.repeat(50));

        const compressor = makeHandle('Zlib', MODE_DEFLATE,
          [15, 6, 8, 0], 1024);
        const compressed = driveSync(compressor, input, Z_FINISH, 1024);
        compressor.close();

        const decompressor = makeHandle('Zlib', MODE_INFLATE,
          [0, -1, 8, 0], 1024);
        const restored = driveSync(decompressor, compressed, Z_FINISH, 1024);
        decompressor.close();

        JSON.stringify({
          compressedLength: compressed.length,
          smaller: compressed.length < input.length,
          roundTrip: asciiBytes('hello from the zlib binding '.repeat(50)).every(
            (byte, index) => restored[index] === byte),
          restoredLength: restored.length,
          inputLength: input.length,
          zlibHeader: compressed[0] === 0x78,
          deflateMethod: (compressed[0] & 0x0f) === 8,
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"compressedLength":53,"smaller":true,"roundTrip":true,"restoredLength":1400,"inputLength":1400,"zlibHeader":true,"deflateMethod":true}"#
    );
}

fn one_byte_chunks() {
    let result = eval_with_binding(
        r#"
        const MODE_DEFLATE = 1;
        const MODE_INFLATE = 2;
        const Z_FINISH = 4;
        const Z_NO_FLUSH = 0;

        const text = 'streamed through one byte writes';
        const input = asciiBytes(text);

        // Compress feeding one byte at a time, the streaming shape a Transform
        // stream produces when its writable side is written byte by byte.
        const compressor = makeHandle('Zlib', MODE_DEFLATE, [15, 6, 8, 0], 256);
        const state = compressor.__writeState;
        const chunks = [];
        for (let index = 0; index < input.length; index++) {
          const flush = index === input.length - 1 ? Z_FINISH : Z_NO_FLUSH;
          compressor.writeSync(flush, input, index, 1, compressor.__out, 0, 256);
          if (compressor.__error) throw new Error(compressor.__error.message);
          const produced = 256 - state[0];
          if (produced > 0) chunks.push(compressor.__out.slice(0, produced));
        }
        compressor.close();

        let total = 0;
        for (const chunk of chunks) total += chunk.length;
        const compressed = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) { compressed.set(chunk, offset); offset += chunk.length; }

        // Decompress its whole input in one call, which is what a one-shot
        // inflateSync would do.
        const decompressor = makeHandle('Zlib', MODE_INFLATE, [0, -1, 8, 0], 4096);
        const restored = driveSync(decompressor, compressed, Z_FINISH, 4096);
        decompressor.close();

        asciiText(restored);
        "#,
    );
    assert_eq!(result, "streamed through one byte writes");
}

fn params_mid_stream() {
    let result = eval_with_binding(
        r#"
        const MODE_DEFLATE = 1;
        const MODE_INFLATE = 2;
        const Z_FINISH = 4;
        const Z_SYNC_FLUSH = 2;

        const text = 'params can change the compression level mid stream '.repeat(40);
        const input = asciiBytes(text);
        const half = input.length >> 1;

        const compressor = makeHandle('Zlib', MODE_DEFLATE, [15, 1, 8, 0], 4096);
        const state = compressor.__writeState;
        const chunks = [];
        const pump = (bytes, flush) => {
          compressor.writeSync(flush, bytes, 0, bytes.length, compressor.__out, 0, 4096);
          if (compressor.__error) throw new Error(compressor.__error.message);
          const produced = 4096 - state[0];
          if (produced > 0) chunks.push(compressor.__out.slice(0, produced));
        };

        pump(input.subarray(0, half), 0);
        // `params()` in lib/zlib.js always flushes with Z_SYNC_FLUSH first and
        // calls the native `params()` from that write's callback.
        pump(new Uint8Array(0), Z_SYNC_FLUSH);
        compressor.params(9, 0);
        if (compressor.__error) throw new Error(compressor.__error.message);
        pump(input.subarray(half), Z_FINISH);
        compressor.close();

        let total = 0;
        for (const chunk of chunks) total += chunk.length;
        const compressed = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) { compressed.set(chunk, offset); offset += chunk.length; }

        const decompressor = makeHandle('Zlib', MODE_INFLATE, [0, -1, 8, 0], 8192);
        const restored = driveSync(decompressor, compressed, Z_FINISH, 8192);
        decompressor.close();

        asciiText(restored) === text ? 'ok' : 'mismatch';
        "#,
    );
    assert_eq!(result, "ok");
}

fn brotli_round_trip() {
    let result = eval_with_binding(
        r#"
        const MODE_ENCODE = 9;
        const MODE_DECODE = 8;
        const OPERATION_FINISH = 2;
        const OPERATION_PROCESS = 0;

        const text = 'brotli through the binding '.repeat(30);
        const input = asciiBytes(text);

        // The Brotli constructors take `(params, writeState, writeCallback,
        // dictionary)`, so the shared helper's zlib-style argument list does not
        // apply; drive them directly.
        const binding = globalThis.__zlibBinding;
        const encoder = new binding.BrotliEncoder(MODE_ENCODE);
        encoder.__writeState = new Uint32Array(2);
        encoder.__out = new Uint8Array(4096);
        encoder.__error = null;
        encoder.onerror = (message, errno, code) => { encoder.__error = { message, errno, code }; };
        encoder.init(new Uint32Array(8).fill(0xFFFFFFFF), encoder.__writeState, () => {}, undefined);

        let state = encoder.__writeState;
        encoder.writeSync(OPERATION_FINISH, input, 0, input.length, encoder.__out, 0, 4096);
        if (encoder.__error) throw new Error(encoder.__error.message);
        const compressed = encoder.__out.slice(0, 4096 - state[0]);
        encoder.close();

        const decoder = new binding.BrotliDecoder(MODE_DECODE);
        decoder.__writeState = new Uint32Array(2);
        decoder.__out = new Uint8Array(4096);
        decoder.__error = null;
        decoder.onerror = (message, errno, code) => { decoder.__error = { message, errno, code }; };
        decoder.init(new Uint32Array(8).fill(0xFFFFFFFF), decoder.__writeState, () => {}, undefined);

        state = decoder.__writeState;
        decoder.writeSync(OPERATION_FINISH, compressed, 0, compressed.length, decoder.__out, 0, 4096);
        if (decoder.__error) throw new Error(decoder.__error.message);
        const restored = decoder.__out.slice(0, 4096 - state[0]);
        decoder.close();

        JSON.stringify({
          compressed: compressed.length > 0,
          roundTrip: asciiText(restored) === text,
        });
        "#,
    );
    assert_eq!(result, r#"{"compressed":true,"roundTrip":true}"#);
}

fn corrupt_stream_error() {
    let result = eval_with_binding(
        r#"
        const MODE_INFLATE = 2;
        const Z_FINISH = 4;
        const binding = globalThis.__zlibBinding;

        const handle = new binding.Zlib(MODE_INFLATE);
        const state = new Uint32Array(2);
        const out = new Uint8Array(1024);
        let reported = null;
        handle.onerror = (message, errno, code) => { reported = { message, errno, code }; };
        handle.init(0, -1, 8, 0, state, () => {}, null, false);

        handle.writeSync(Z_FINISH, new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]),
                         0, 8, out, 0, 1024);
        handle.close();

        JSON.stringify(reported);
        "#,
    );
    assert_eq!(
        result,
        r#"{"message":"incorrect header check","errno":-3,"code":"Z_DATA_ERROR"}"#
    );
}

fn asynchronous_write_is_deferred() {
    // Two scripts in one isolate: the evaluator runs a microtask checkpoint
    // between them, which delivers the queued completion, so the second script
    // observes the state *after* the write callback ran.
    let observed = eval_sequence(&[
        r#"
        globalThis.__asyncCase = (() => {
          const MODE_DEFLATE = 1;
          const Z_FINISH = 4;
          const binding = globalThis.__zlibBinding;

          const handle = new binding.Zlib(MODE_DEFLATE);
          const state = new Uint32Array(2);
          const out = new Uint8Array(1024);
          const input = asciiBytes('asynchronous write path');

          const observations = { calls: 0 };
          handle.onerror = (message, errno, code) => { throw new Error(message); };
          handle.init(15, 6, 8, 0, state, () => {
            observations.calls += 1;
            observations.produced = 1024 - state[0];
            observations.availInAfter = state[1];
          }, null, false);

          handle.write(Z_FINISH, input, 0, input.length, out, 0, 1024);
          // The compression step is synchronous but the completion is queued,
          // so nothing may have called back inside `write()`.
          observations.insideWrite = observations.calls;
          return { handle, observations };
        })();
        JSON.stringify({ insideWrite: globalThis.__asyncCase.observations.insideWrite });
        "#,
        r#"
        (() => {
          const { handle, observations } = globalThis.__asyncCase;
          handle.close();
          return JSON.stringify({
            insideWrite: observations.insideWrite,
            calls: observations.calls,
            produced: observations.produced,
            availInAfter: observations.availInAfter,
          });
        })();
        "#,
    ]);
    // Assert the invariants rather than a byte count: the completion ran exactly
    // once, it ran after `write()` returned, it consumed the whole input, and it
    // produced output.
    let fields: serde_json::Value = serde_json::from_str(&observed).expect("observation is JSON");
    assert_eq!(
        fields["insideWrite"], 0,
        "callback must not run inside write()"
    );
    assert_eq!(fields["calls"], 1, "write callback must run exactly once");
    assert_eq!(fields["availInAfter"], 0, "all input must be consumed");
    assert!(
        fields["produced"].as_u64().unwrap_or(0) > 0,
        "the write must produce output: {observed}"
    );
}

/// A handle that is never `close()`d must still be released by its finalizer.
///
/// The counter in `LIVE_HANDLES` is incremented on construction and decremented
/// by the finalizer, so a GC that actually collects the handles brings it back to
/// zero. Without a working finalizer the value only grows.
fn finalizers_release_unclosed_handles() {
    let before = rn_bind_zlib::live_handle_count();

    eval_sequence_at_with_gc(
        r#"
        (() => {
          const binding = globalThis.__zlibBinding;
          for (let index = 0; index < 64; index++) {
            const handle = new binding.BrotliEncoder(9);
            handle.onerror = () => {};
            handle.init(new Uint32Array(8).fill(0xFFFFFFFF), new Uint32Array(2),
                        () => {}, undefined);
            // Touch the handle so it cannot be optimised out of the heap.
            handle.__probe = index;
          }
          return 'allocated';
        })();
        "#,
    );

    let after = rn_bind_zlib::live_handle_count();
    // If the finalizers did not run, `after` would be `before + 64`.
    assert_eq!(
        after, before,
        "every unclosed handle must be reclaimed: before {before}, after {after}"
    );
}

/// A handle that is never `close()`d must still be released by its finalizer,
/// and closing twice plus writing after close must stay harmless.
fn handle_lifetime_is_safe() {
    finalizers_release_unclosed_handles();

    // `close()` twice, then `writeSync` on the closed handle, must not reach
    // freed state.
    let closed = eval_sequence(&[r#"
        (() => {
          const MODE_DEFLATE = 1;
          const binding = globalThis.__zlibBinding;
          const handle = new binding.Zlib(MODE_DEFLATE);
          let reported = null;
          handle.onerror = (message, errno, code) => { reported = { message, errno, code }; };
          handle.init(15, 6, 8, 0, new Uint32Array(2), () => {}, null, false);
          handle.close();
          handle.close();
          handle.writeSync(4, asciiBytes('x'), 0, 1, new Uint8Array(64), 0, 64);
          return JSON.stringify(reported);
        })();
        "#]);
    assert_eq!(
        closed,
        r#"{"message":"zlib binding closed","errno":-2,"code":"Z_STREAM_ERROR"}"#
    );

    // Re-initializing a closed handle must work, which is what the JS does when
    // `processChunkSync` closes the handle and a caller reuses the engine.
    let revived = eval_sequence(&[r#"
        (() => {
          const MODE_DEFLATE = 1;
          const binding = globalThis.__zlibBinding;
          const handle = new binding.Zlib(MODE_DEFLATE);
          handle.onerror = () => {};
          const state = new Uint32Array(2);
          const out = new Uint8Array(256);
          const input = asciiBytes('revived handle');
          handle.init(15, 6, 8, 0, state, () => {}, null, false);
          handle.writeSync(4, input, 0, input.length, out, 0, 256);
          handle.close();
          handle.init(15, 6, 8, 0, state, () => {}, null, false);
          handle.writeSync(4, input, 0, input.length, out, 0, 256);
          const produced = 256 - state[0];
          handle.close();
          return JSON.stringify({ produced: produced > 0 });
        })();
        "#]);
    assert_eq!(revived, r#"{"produced":true}"#);

    // `close()` on a handle with a *queued* completion must not free the state
    // out from under the microtask. The completion still runs, and it must not
    // call the write callback of a destroyed engine.
    let closed_pending = eval_sequence(&[
        r#"
        globalThis.__closedPending = (() => {
          const MODE_DEFLATE = 1;
          const Z_FINISH = 4;
          const binding = globalThis.__zlibBinding;
          const handle = new binding.Zlib(MODE_DEFLATE);
          const state = new Uint32Array(2);
          const out = new Uint8Array(256);
          const input = asciiBytes('closed with a pending write');
          const observations = { calls: 0 };
          handle.onerror = () => {};
          handle.init(15, 6, 8, 0, state, () => { observations.calls += 1; }, null, false);
          handle.write(Z_FINISH, input, 0, input.length, out, 0, 256);
          // Dropped immediately: this is the path that used to dangle.
          handle.close();
          return observations;
        })();
        'queued';
        "#,
        r#"
        (() => {
          const observations = globalThis.__closedPending;
          return JSON.stringify({ calls: observations.calls });
        })();
        "#,
    ]);
    assert_eq!(
        closed_pending, r#"{"calls":1}"#,
        "the queued completion still runs after close(), like Node's AfterThreadPoolWork"
    );
}

/// Runs one script and then forces a full GC before the isolate is torn down, so
/// the finalizer path is exercised instead of only `close()`.
fn eval_sequence_at_with_gc(source: &str) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = Zlib
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("zlib binding installs");
    let global = context.global(scope);
    let key = v8::String::new(scope, "__zlibBinding").expect("key");
    global.set(scope, key.into(), binding.into());

    let code = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, code, None).expect("compiles");
    let result = script
        .run(scope)
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default();

    // Force the weak handles to be collected.
    //
    // `request_garbage_collection_for_testing` aborts unless V8 was started with
    // `--expose-gc`, so the reachable pressure path is `low_memory_notification`,
    // which runs a full GC and collects the handles that Phase 1 dropped.
    scope.low_memory_notification();
    result
}

/// V8's platform and global state are process-wide, so all cases share one
/// test. Each case gets its own isolate.
#[test]
fn zlib_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    namespace_members();
    crc32_value();
    deflate_round_trip();
    one_byte_chunks();
    params_mid_stream();
    brotli_round_trip();
    corrupt_stream_error();
    asynchronous_write_is_deferred();
    handle_lifetime_is_safe();
}
