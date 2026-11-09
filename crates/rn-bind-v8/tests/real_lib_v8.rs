//! Drives the **unmodified** `lib/v8.js` against this binding.
//!
//! `tests/binding.rs` transcribes the parts of that file that touch the
//! namespace, which is convenient but circular: if the transcription and the
//! binding share a misreading of Node's protocol, both stay green. This test
//! removes the transcription. It loads the frozen vendor file itself and stubs
//! only the three things it needs from other namespaces.
//!
//! What that proves, beyond the transcribed tests:
//!
//! * the member names `lib/v8.js` destructures at module scope are the ones
//!   installed, and nothing it destructures is missing — which is the failure
//!   `deferred-reach.py` exists to catch, checked here against the real file
//!   rather than a guess about it;
//! * `getHeapStatistics()` reads the buffers through the index constants and
//!   produces Node's documented object, both names and meanings;
//! * `getHeapSpaceStatistics()` really walks `kHeapSpaces` and calls
//!   `updateHeapSpaceStatisticsBuffer(i)` once per space;
//! * `getHeapCodeStatistics()` reads the four code indexes;
//! * `setFlagsFromString` validates and forwards;
//! * the deferred profilers do not stop the module from loading, so
//!   `require('v8')` works without them.
//!
//! The stubs are deliberately thin and are the parts of `lib/v8.js` that are
//! *not* this namespace: `serdes` (which `v8.serialize` needs),
//! `heap_utils` (which `v8.writeHeapSnapshot` needs) and `profiler` (inspector
//! coverage). None of them participate in the statistics APIs under test.

use std::path::Path;

use rn_bind_v8::V8;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Reads the frozen Node source that `internalBinding('v8')` exists to serve.
fn lib_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/libnode-js/lib/v8.js");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The CommonJS shims `lib/v8.js` needs from everything except this namespace.
///
/// `internalBinding` resolves `v8` to the real object and `config` to the
/// handful of flags the file reads; anything else throws, because a stub that
/// silently returned `undefined` would make this test pass for the wrong
/// reason.
const SHIMS: &str = r#"
globalThis.__primordials = (function buildPrimordials() {
  // `lib/v8.js` destructures twenty intrinsics. Most are constructors that are
  // also globals, but four are not — `ArrayBufferIsView`, `JSONParse`,
  // `ObjectPrototypeToString` and `SymbolDispose` are the un-curried forms Node
  // keeps so that user code patching globals cannot affect builtins. Mapping
  // them by hand is what `internal/per_context/primordials` does for real.
  const direct = {
    ArrayBufferIsView: (value) => ArrayBuffer.isView(value),
    JSONParse: (text) => JSON.parse(text),
    ObjectDefineProperty: (target, key, descriptor) =>
      Object.defineProperty(target, key, descriptor),
    ObjectPrototypeToString: (value) => Object.prototype.toString.call(value),
    SymbolDispose: Symbol.dispose ?? Symbol('dispose'),
  };
  const p = new Proxy(direct, {
    get(target, name) {
      if (name in target) return target[name];
      const key = String(name);
      const intrinsic = globalThis[key];
      if (intrinsic === undefined) throw new Error('primordial not found: ' + key);
      return intrinsic;
    },
    has() { return true; },
  });
  return p;
})();

const __config = { hasInspector: false, hasOpenSSL: false };
globalThis.internalBinding = function internalBinding(name) {
  if (name === 'v8') return globalThis.__v8Binding;
  if (name === 'config') return __config;
  // `lib/v8.js` only reaches these through functions this test never calls.
  if (name === 'serdes') return { Serializer: class {}, Deserializer: class {} };
  if (name === 'heap_utils') {
    return { createHeapSnapshotStream() {}, triggerHeapSnapshot() {} };
  }
  if (name === 'profiler') return {};
  throw new Error('unexpected internalBinding: ' + name);
};

globalThis.__require = function require(name) {
  switch (name) {
    case 'buffer':
      return { Buffer: globalThis.Buffer };
    case 'internal/validators':
      // The four validators `lib/v8.js` calls, reduced to the checks the
      // statistics APIs actually make. A wrong type is a caller bug in Node
      // too, so throwing is faithful for the cases under test.
      return {
        validateString(value, name) {
          if (typeof value !== 'string') throw new TypeError(name + ' must be a string');
        },
        validateOneOf(value, name, oneOf) {
          if (!oneOf.includes(value)) throw new TypeError(name + ' must be one of ' + oneOf);
        },
        validateUint32(value, name) {
          if (!Number.isInteger(value) || value < 0) throw new TypeError(name + ' must be a uint32');
        },
        validateObject(value, name) {
          if (typeof value !== 'object' || value === null) throw new TypeError(name + ' must be an object');
        },
      };
    case 'internal/v8/heap_profile':
      return { normalizeHeapProfileOptions: () => ({ sampleInterval: 1, stackDepth: 0, flags: 0 }) };
    case 'internal/v8/cpu_profiler':
      return { normalizeCpuProfileOptions: () => ({ samplingIntervalMicros: 0, maxSamples: 0 }) };
    case 'internal/v8/startup_snapshot':
      return { namespace: {} };
    case 'internal/assert':
      return function assert(value) { if (!value) throw new Error('assertion failed'); };
    case 'internal/errors':
      return { codes: { ERR_INVALID_STATE: class extends Error {} } };
    case 'internal/util/inspect':
      return { inspect: (value) => String(value) };
    case 'internal/buffer':
      return { FastBuffer: Uint8Array };
    case 'internal/fs/utils':
      return { getValidatedPath: (path) => path };
    case 'internal/heap_utils':
      return { HeapSnapshotStream: class {}, getHeapSnapshotOptions: () => [], queryObjects() {} };
    case 'internal/promise_hooks':
      return { createHook: () => ({}) };
    case 'internal/options':
      return { getOptionValue: () => 0 };
    default:
      throw new Error('unexpected require: ' + name);
  }
};
"#;

/// Loads `lib/v8.js` as a CommonJS module and publishes its exports.
fn load_module_script(source: &str) -> String {
    format!(
        r#"
const source = {source_literal};
const module = {{ exports: {{}} }};
const factory = new Function('exports', 'require', 'module', 'primordials', source);
factory(module.exports, globalThis.__require, module, globalThis.__primordials);
globalThis.v8module = module.exports;
"#,
        source_literal = json_quote(source)
    )
}

/// A JSON string literal for `text`, so the vendored source survives the trip
/// into JavaScript unchanged including its license header.
fn json_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Runs the shims, the real module and then `scripts`, returning the last
/// script's printed value.
fn eval_with_real_module(scripts: &[&str]) -> String {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // `v8.setFlagsFromString` — the public API `lib/v8.js` exports — aborts
        // inside V8 once the flag list is frozen, which happens during
        // `V8::Initialize`. The CLI disables the freeze before initializing for
        // the same reason, and this test binary has to agree with it or the
        // `setFlagsFromString` case would kill the process instead of failing a
        // test.
        v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = V8
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("the v8 binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__v8Binding").expect("key");
    global.set(scope, key.into(), binding.into());

    let module_script = load_module_script(&lib_source());
    for source in std::iter::once(SHIMS.to_string())
        .chain(std::iter::once(module_script))
        .chain(scripts.iter().map(|script| (*script).to_string()))
    {
        let source = v8::String::new(scope, &source).expect("source");
        let script =
            v8::Script::compile(scope, source, None).expect("the script must compile and run");
        script.run(scope).expect("the script must run");
    }

    // Each script assigns its answer to `__result` rather than relying on the
    // script's completion value, which is the last statement's value in V8 and
    // therefore `undefined` for a script ending in `console.log`.
    let key = v8::String::new(scope, "__result").expect("key");
    match global.get(scope, key.into()) {
        Some(value) => value.to_rust_string_lossy(scope),
        None => String::new(),
    }
}

#[test]
fn the_real_lib_v8_loads_against_this_binding() {
    // Loading it at all is the assertion: every member it destructures at module
    // scope has to be present, or the destructuring yields `undefined` and the
    // first call through it throws. `deferred-reach.py` makes the same check
    // statically; this one runs the file.
    let output =
        eval_with_real_module(&["globalThis.__result = typeof v8module.getHeapStatistics;"]);
    assert_eq!(output, "function");
}

#[test]
fn get_heap_statistics_returns_nodes_documented_object() {
    // The key list is Node's, and every value has to be a plausible number:
    // a missed index would show up as `undefined`, and a swapped pair as a size
    // that is smaller than the one it contains.
    let output = eval_with_real_module(&[r#"
const stats = v8module.getHeapStatistics();
const keys = Object.keys(stats);
const shape =
  keys.join(',') === 'total_heap_size,total_heap_size_executable,total_physical_size,' +
    'total_available_size,used_heap_size,heap_size_limit,malloced_memory,' +
    'peak_malloced_memory,does_zap_garbage,number_of_native_contexts,' +
    'number_of_detached_contexts,total_global_handles_size,' +
    'used_global_handles_size,external_memory,total_allocated_bytes';
const numbers = keys.every((key) => typeof stats[key] === 'number');
const order =
  stats.used_heap_size > 0 &&
  stats.used_heap_size <= stats.total_heap_size &&
  stats.total_heap_size <= stats.heap_size_limit &&
  stats.heap_size_limit > 0 &&
  stats.total_allocated_bytes > 0;
globalThis.__result = [shape, numbers, order].join(' ');
"#]);
    assert_eq!(output, "true true true");
}

#[test]
fn get_heap_statistics_tracks_allocation_through_the_shared_buffer() {
    // `getHeapStatistics` reads `heapStatisticsBuffer` after calling
    // `updateHeapStatisticsBuffer()`. If the buffer were a copy, or the update
    // wrote elsewhere, these two readings would not move.
    let output = eval_with_real_module(&[r#"
const before = v8module.getHeapStatistics().used_heap_size;
const keep = [];
for (let i = 0; i < 200000; i++) keep.push({ i, text: 'filler-' + i });
const after = v8module.getHeapStatistics().used_heap_size;
globalThis.__result = [after > before, keep.length].join(' ');
"#]);
    assert_eq!(output, "true 200000");
}

#[test]
fn get_heap_space_statistics_walks_the_public_space_names() {
    // The public API returns `space_name`, which has to be one of V8's names,
    // and `kHeapSpaces` comes from `Isolate::NumberOfHeapSpaces` rather than
    // from a constant in this crate.
    let output = eval_with_real_module(&[r#"
const spaces = v8module.getHeapSpaceStatistics();
const names = spaces.map((space) => space.space_name);
const shape = spaces.every((space) =>
  Object.keys(space).join(',') ===
    'space_name,space_size,space_used_size,space_available_size,physical_space_size');
globalThis.__result = [
  Array.isArray(spaces),
  spaces.length,
  shape,
  names.includes('new_space'),
  names.includes('old_space'),
  new Set(names).size === names.length
].join(' ');
"#]);
    assert_eq!(output, "true 11 true true true true");
}

#[test]
fn get_heap_code_statistics_returns_nodes_four_fields() {
    let output = eval_with_real_module(&[r#"
const stats = v8module.getHeapCodeStatistics();
globalThis.__result = [
  Object.keys(stats).join(','),
  stats.code_and_metadata_size > 0,
  stats.bytecode_and_metadata_size > 0
].join(' ');
"#]);
    assert_eq!(
        output,
        "code_and_metadata_size,bytecode_and_metadata_size,external_script_source_size,\
         cpu_profiler_metadata_size true true"
    );
}

#[test]
fn set_flags_from_string_validates_and_forwards() {
    // `v8.setFlagsFromString` is the only place the raw `setFlagsFromString`
    // reaches user code, and it validates first. A non-string must be a
    // `TypeError` before it can reach V8.
    let output = eval_with_real_module(&[r#"
v8module.setFlagsFromString('--allow-natives-syntax');
let threw = false;
try { v8module.setFlagsFromString(42); } catch (error) { threw = error instanceof TypeError; }
globalThis.__result = ['accepted', threw].join(' ');
"#]);
    assert_eq!(output, "accepted true");
}

#[test]
fn is_string_one_byte_representation_is_exported_and_correct() {
    let output = eval_with_real_module(&[r#"
globalThis.__result = [
  v8module.isStringOneByteRepresentation('abc'),
  v8module.isStringOneByteRepresentation('\u0100')
].join(' ');
"#]);
    assert_eq!(output, "true false");
}

#[test]
fn cached_data_version_tag_is_exported_as_a_number() {
    let output =
        eval_with_real_module(&["globalThis.__result = typeof v8module.cachedDataVersionTag();"]);
    assert_eq!(output, "number");
}

#[test]
fn the_deferred_profilers_do_not_prevent_the_module_from_loading() {
    // The point of checking `lib/v8.js` rather than assuming: `startCpuProfile`
    // and `startHeapProfile` are exported as functions that call the deferred
    // binding members, so the module loads and only a call fails. That is the
    // difference between a visible gap and a broken `require('v8')`.
    let output = eval_with_real_module(&[r#"
const exported = [
  typeof v8module.startCpuProfile,
  typeof v8module.startHeapProfile,
  typeof v8module.getHeapStatistics,
];
let message = 'none';
try { v8module.startCpuProfile(); } catch (error) { message = error.message; }
globalThis.__result = [exported.join(' '), message.includes('not a function')].join(' ');
"#]);
    assert_eq!(output, "function function function true");
}

#[test]
fn detail_level_is_what_get_cpp_heap_statistics_accepts() {
    // `getCppHeapStatistics` maps `'brief'`/`'detailed'` through the binding's
    // `detailLevel` object and adds `detail_level` to the result.
    let output = eval_with_real_module(&[r#"
const brief = v8module.getCppHeapStatistics('brief');
const detailed = v8module.getCppHeapStatistics('detailed');
globalThis.__result = [
  brief.detail_level,
  detailed.detail_level,
  typeof brief.committed_size_bytes,
  Array.isArray(brief.space_statistics)
].join(' ');
"#]);
    assert_eq!(output, "brief detailed number true");
}

#[test]
fn get_cpp_heap_statistics_rejects_an_unknown_type() {
    let output = eval_with_real_module(&[r#"
let threw = false;
try { v8module.getCppHeapStatistics('nonsense'); } catch (error) { threw = true; }
globalThis.__result = String(threw);
"#]);
    assert_eq!(output, "true");
}

#[test]
fn the_gc_profiler_class_completes_a_real_profile_through_the_public_api() {
    // `lib/v8.js` wraps the constructor in a `GCProfiler` class whose `stop()`
    // does `JSON.parse`. Both layers have to agree for this to return an object.
    let output = eval_with_real_module(&[r#"
const profiler = new v8module.GCProfiler();
profiler.start();
const keep = [];
for (let i = 0; i < 300000; i++) keep.push({ i, text: 'x' + i });
keep.length = 0;
const document = profiler.stop();
globalThis.__result = [
  typeof document,
  document.version,
  Array.isArray(document.statistics),
  typeof document.endTime
].join(' ');
"#]);
    assert_eq!(output, "object 1 true number");
}
