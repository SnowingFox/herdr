//! Drives the **unmodified** `lib/string_decoder.js` against this binding.
//!
//! `tests/binding.rs` transcribes the parts of that file that touch the
//! namespace, which is convenient but circular: if the transcription and the
//! binding share a misreading of Node's protocol, both stay green. This test
//! removes the transcription. It loads the frozen vendor file itself, gives it
//! the four `require()` results it asks for as stubs, and then uses the
//! resulting `StringDecoder` exactly as user code would.
//!
//! What that proves, beyond the transcribed tests:
//!
//! * the member names and the `k*Field` offsets are the ones the real file
//!   destructures and indexes with;
//! * `Buffer.alloc(kSize)` is exactly big enough for the state `decode` writes;
//! * `end()` only calls `flush` under the condition the real file uses;
//! * `lastChar` really is a subarray of the caller's buffer, so the getters
//!   read the state this crate wrote.
//!
//! The stubs are deliberately thin. `internal/util`'s `normalizeEncoding` is a
//! reimplementation covering the encodings these cases use, and `internal/errors`
//! provides the three error codes the file imports; neither participates in the
//! decoding behaviour under test.

use std::path::Path;
use std::process::Command;

use rn_bind_string_decoder::StringDecoder;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Reads the frozen Node source that `internalBinding('string_decoder')` exists
/// to serve.
fn lib_source() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/libnode-js/lib/string_decoder.js");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The CommonJS shims the real file needs.
///
/// `primordials` entries map to the intrinsics V8 already provides. `Buffer` is
/// only used for `Buffer.alloc(kSize)` and `buf.slice(offset)`, so a
/// `Uint8Array` return is faithful for both. `internalBinding` is Node's
/// bootstrap global; here it resolves the one namespace this crate implements
/// and refuses anything else rather than pretending to be a full runtime.
const SHIMS: &str = r#"
globalThis.__primordials = {
  ArrayBufferIsView: (value) => ArrayBuffer.isView(value),
  ObjectDefineProperties: (target, descriptors) => Object.defineProperties(target, descriptors),
  Symbol,
  TypedArrayPrototypeSubarray: (view, start, end) => view.subarray(start, end),
};

globalThis.internalBinding = function internalBinding(name) {
  if (name === 'string_decoder') return globalThis.__binding;
  throw new Error('unexpected internalBinding: ' + name);
};

globalThis.__require = function require(name) {
  switch (name) {
    case 'buffer':
      return { Buffer: { alloc: (size) => new Uint8Array(size) } };
    case 'internal/util':
      return {
        encodingsMap: globalThis.__encodingsMap,
        normalizeEncoding: globalThis.__normalizeEncoding,
      };
    case 'internal/errors':
      return {
        codes: {
          ERR_INVALID_ARG_TYPE: class ERR_INVALID_ARG_TYPE extends Error {
            constructor() { super('invalid argument type'); this.code = 'ERR_INVALID_ARG_TYPE'; }
          },
          ERR_INVALID_THIS: class ERR_INVALID_THIS extends Error {
            constructor() { super('invalid this'); this.code = 'ERR_INVALID_THIS'; }
          },
          ERR_UNKNOWN_ENCODING: class ERR_UNKNOWN_ENCODING extends Error {
            constructor(encoding) {
              super('Unknown encoding: ' + encoding);
              this.code = 'ERR_UNKNOWN_ENCODING';
            }
          },
        },
      };
    default:
      throw new Error('unexpected require: ' + name);
  }
};
"#;

/// Loads `lib/string_decoder.js` as a CommonJS module and returns its
/// `StringDecoder`.
///
/// The source is embedded with `JSON.stringify` so it survives the trip into
/// JavaScript unchanged, including its license comment and `'use strict'`.
fn load_module_script(source: &str) -> String {
    format!(
        r#"
const source = {};
const module = {{ exports: {{}} }};
const factory = new Function('exports', 'require', 'module', 'primordials', source);
factory(module.exports, globalThis.__require, module, globalThis.__primordials);
globalThis.StringDecoder = module.exports.StringDecoder;
"#,
        serde_json_quote(source)
    )
}

/// A JSON string literal for `text`.
///
/// `serde_json` is not a dependency of this crate, so this escapes the
/// characters that matter for embedding a source file: quotes, backslashes and
/// control characters. The vendor file is UTF-8 without embedded NULs.
fn serde_json_quote(text: &str) -> String {
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

/// The `encodingsMap` the real file imports, built from the binding's own
/// `encodings` array exactly as `lib/internal/util.js` builds it.
const ENCODINGS_SETUP: &str = r#"
globalThis.__encodingsMap = { __proto__: null };
for (let i = 0; i < globalThis.__binding.encodings.length; ++i) {
  globalThis.__encodingsMap[globalThis.__binding.encodings[i]] = i;
}

// `normalizeEncoding` from lib/internal/util.js, reduced to a case-insensitive
// lookup plus the aliases these cases exercise. It only decides which entry of
// `encodings` the decoder starts in, so an alias that is not used here cannot
// mask a decoding difference.
globalThis.__normalizeEncoding = function normalizeEncoding(encoding) {
  if (encoding == null || encoding === 'utf8' || encoding === 'utf-8') return 'utf8';
  if (typeof encoding !== 'string') return undefined;
  const lower = encoding.toLowerCase();
  switch (lower) {
    case 'utf8': case 'utf-8': return 'utf8';
    case 'ucs2': case 'ucs-2': case 'utf16le': case 'utf-16le': return 'utf16le';
    case 'base64': return 'base64';
    case 'base64url': return 'base64url';
    case 'hex': return 'hex';
    case 'ascii': return 'ascii';
    case 'latin1': case 'binary': return 'latin1';
    default: return undefined;
  }
};
"#;

/// Runs `sources` in one isolate with the real module loaded, returning the last
/// script's value.
fn eval_with_real_module(sources: &[&str]) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = StringDecoder
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("string_decoder binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__binding").expect("key");
    global.set(scope, key.into(), binding.into());

    // `Uint8Array` is the chunk type the real `write()` path accepts from
    // `ArrayBufferIsView`, and the type `Buffer` would be.
    let module_script = load_module_script(&lib_source());
    let preludes = [
        SHIMS.to_string(),
        ENCODINGS_SETUP.to_string(),
        module_script,
    ];

    let mut result = String::new();
    for source in preludes
        .iter()
        .map(String::as_str)
        .chain(sources.iter().copied())
    {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let code = v8::String::new(scope, source).expect("source");
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
    }
    result
}

fn eval(source: &str) -> String {
    eval_with_real_module(&[source])
}

/// The module exports a constructor whose prototype has `write`, `end`, `text`
/// and the three legacy getters — i.e. the binding gave it everything it
/// destructures at load time. A missing member would have thrown on load, so
/// reaching this assertion at all is most of the result.
fn module_loads_and_exposes_the_class() {
    let result = eval(
        r#"
        const methods = ['write', 'end', 'text'];
        const descriptors = ['lastChar', 'lastNeed', 'lastTotal'];
        JSON.stringify({
          isFunction: typeof StringDecoder === 'function',
          encoding: new StringDecoder('utf8').encoding,
          methods: methods.filter((name) =>
            typeof StringDecoder.prototype[name] === 'function'),
          getters: descriptors.filter((name) => {
            const descriptor = Object.getOwnPropertyDescriptor(
              StringDecoder.prototype, name);
            return descriptor && typeof descriptor.get === 'function';
          }),
          bufferIsUint8: new StringDecoder('utf8')[Object.getOwnPropertySymbols(
            new StringDecoder('utf8'))[0]] instanceof Uint8Array,
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"isFunction":true,"encoding":"utf8","methods":["write","end","text"],"getters":["lastChar","lastNeed","lastTotal"],"bufferIsUint8":true}"#
    );
}

/// The headline case through the real file: a four-byte codepoint split across
/// two `write()` calls.
fn real_write_and_end_split_emoji() {
    let result = eval(
        r#"
        const decoder = new StringDecoder('utf8');
        const emoji = [0xf0, 0x9f, 0x98, 0x80];
        const first = decoder.write(new Uint8Array(emoji.slice(0, 2)));
        const lastChar = Array.from(decoder.lastChar);
        const lastNeed = decoder.lastNeed;
        const lastTotal = decoder.lastTotal;
        const second = decoder.write(new Uint8Array(emoji.slice(2)));
        const joined = first + second + decoder.end();
        const units = [];
        for (let i = 0; i < joined.length; i++) units.push(joined.charCodeAt(i));
        JSON.stringify({
          first, lastChar, lastNeed, lastTotal, second, units,
          afterNeed: decoder.lastNeed,
          afterTotal: decoder.lastTotal,
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"first":"","lastChar":[240,159,0,0],"lastNeed":2,"lastTotal":4,"second":"😀","units":[55357,56832],"afterNeed":0,"afterTotal":0}"#
    );
}

/// `end()` with no argument, and `end(buf)` decoding a final chunk. The second
/// form is the one that combines a write with a flush.
fn real_end_with_and_without_arguments() {
    let result = eval(
        r#"
        const a = new StringDecoder('utf8');
        a.write(new Uint8Array([0x61, 0xe2]));
        const flushed = a.end();

        const b = new StringDecoder('utf8');
        const withChunk = b.end(new Uint8Array([0x68, 0x69]));

        const c = new StringDecoder('utf8');
        const empty = c.end();

        JSON.stringify({ flushed, withChunk, empty });
        "#,
    );
    assert_eq!(
        result,
        "{\"flushed\":\"\u{fffd}\",\"withChunk\":\"hi\",\"empty\":\"\"}"
    );
}

/// `lastChar` has to alias the caller's buffer, because the getter is
/// `subarray(kIncompleteCharactersStart, kIncompleteCharactersEnd)` over the
/// same `Uint8Array` passed to `decode`. If this crate stored its state anywhere
/// else the getter would show zeros.
fn real_last_char_aliases_the_state_buffer() {
    let result = eval(
        r#"
        const decoder = new StringDecoder('utf8');
        const symbol = Object.getOwnPropertySymbols(decoder)[0];
        const state = decoder[symbol];
        decoder.write(new Uint8Array([0xf0, 0x9f]));
        const throughGetter = Array.from(decoder.lastChar);
        const throughBuffer = Array.from(state.subarray(0, 4));
        // Mutating the buffer is visible through the getter: same memory.
        state[0] = 0x00;
        const afterMutation = Array.from(decoder.lastChar);
        JSON.stringify({ throughGetter, throughBuffer, afterMutation });
        "#,
    );
    assert_eq!(
        result,
        r#"{"throughGetter":[240,159,0,0],"throughBuffer":[240,159,0,0],"afterMutation":[0,159,0,0]}"#
    );
}

/// `text(buf, offset)` clears the counters and then writes `buf.slice(offset)`.
/// It is legacy, but it is part of the file and it reaches both `kMissingBytes`
/// and `kBufferedBytes` from JavaScript, so the offsets have to be right.
fn real_text_clears_state_and_slices() {
    let result = eval(
        r#"
        const decoder = new StringDecoder('utf8');
        decoder.write(new Uint8Array([0x61, 0xf0]));   // leaves a pending byte
        const pending = decoder.lastNeed;
        const text = decoder.text(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]), 2);
        JSON.stringify({ pending, text, afterNeed: decoder.lastNeed });
        "#,
    );
    assert_eq!(result, r#"{"pending":3,"text":"llo","afterNeed":0}"#);
}

/// `write` returning a string unchanged, which is the first branch of the real
/// `write` and never reaches the binding.
fn real_string_passthrough() {
    let result = eval(
        r#"
        const decoder = new StringDecoder('utf8');
        JSON.stringify({ value: decoder.write('unchanged') });
        "#,
    );
    assert_eq!(result, r#"{"value":"unchanged"}"#);
}

/// A non-view argument is rejected by the real `write` before the binding is
/// called, which proves the `ArrayBufferIsView` path is the one in use.
fn real_write_rejects_non_views() {
    let result = eval(
        r#"
        const decoder = new StringDecoder('utf8');
        let code = '';
        try {
          decoder.write(42);
        } catch (error) {
          code = error.code;
        }
        JSON.stringify({ code });
        "#,
    );
    assert_eq!(result, r#"{"code":"ERR_INVALID_ARG_TYPE"}"#);
}

/// An unknown encoding is rejected by the constructor, again before the binding
/// sees it — the encoder lookup is what the `encodings` member feeds.
fn real_unknown_encoding_is_rejected() {
    let result = eval(
        r#"
        let code = '';
        try {
          new StringDecoder('nonsense');
        } catch (error) {
          code = error.code;
        }
        JSON.stringify({ code });
        "#,
    );
    assert_eq!(result, r#"{"code":"ERR_UNKNOWN_ENCODING"}"#);
}

/// Every encoding the contract lists except `buffer` decodes through the real
/// file, and the results match Node.
fn real_every_encoding_decodes() {
    let result = eval(
        r#"
        const cases = [
          ['ascii',   [0x41, 0xff, 0x42]],
          ['latin1',  [0x41, 0xff, 0x42]],
          ['hex',     [0xde, 0xad, 0xbe, 0xef]],
          ['utf8',    [0x61, 0xf0, 0x9f, 0x98, 0x80]],
          ['utf16le', [0x41, 0x00, 0x3d, 0xd8, 0x00, 0xde]],
          ['base64',  [0x41, 0x42, 0x43]],
          ['base64url', [0x41, 0x42, 0x43]],
        ];
        const out = {};
        for (const [encoding, bytes] of cases) {
          const decoder = new StringDecoder(encoding);
          const text = decoder.write(new Uint8Array(bytes)) + decoder.end();
          // Code units, so U+007F from `ascii` is visible in the assertion
          // rather than an invisible character inside the expected literal.
          const units = [];
          for (let i = 0; i < text.length; i++) units.push(text.charCodeAt(i));
          out[encoding] = units;
        }
        JSON.stringify(out);
        "#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"ascii":[65,127,66],"latin1":[65,255,66],"#,
            r#""hex":[100,101,97,100,98,101,101,102],"#,
            r#""utf8":[97,55357,56832],"utf16le":[65,55357,56832],"#,
            r#""base64":[81,85,74,68],"base64url":[81,85,74,68]}"#
        )
    );
}

/// Compares the real module against real Node for a set of decoders driven
/// through `write`/`end`. Skipped when no `node` is on `PATH`.
fn real_module_matches_node() {
    let node_available = Command::new("node")
        .arg("-e")
        .arg("0")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !node_available {
        eprintln!("skipping: no node on PATH");
        return;
    }

    // (encoding, chunks, flush) — the same shape `tests/node_parity.rs` uses.
    let cases: &[(&str, &[&[u8]], bool)] = &[
        ("utf8", &[&[0xF0, 0x9F], &[0x98, 0x80]], true),
        ("utf8", &[&[0xF0], &[0x9F, 0x98], &[0x80]], true),
        ("utf8", &[&[0x61, 0xE2]], true),
        ("utf8", &[&[0x61, 0xF0, 0x9F], &[0x41]], true),
        ("utf16le", &[&[0x3D, 0xD8], &[0x00, 0xDE]], true),
        ("utf16le", &[&[0x41]], true),
        ("base64", &[&[0x41]], true),
        (
            "base64",
            &[&[0x41], &[0x42, 0x43], &[0x44, 0x45, 0x46, 0x47]],
            true,
        ),
        ("base64url", &[&[0x41], &[0xFB, 0xFF, 0xFF]], true),
        ("hex", &[&[0x01], &[0x23]], true),
        ("latin1", &[&[0x41, 0xFF, 0x42, 0x80]], true),
        ("ascii", &[&[0x41, 0xFF, 0x42, 0x80]], true),
        ("utf8", &[&[0x61, 0xF0, 0x9F, 0x98, 0x80, 0x62]], false),
    ];

    let mut literal = String::from("const cases = [\n");
    for (encoding, chunks, flush) in cases {
        literal.push_str(&format!("  {{ encoding: {encoding:?}, chunks: ["));
        for chunk in *chunks {
            let bytes: Vec<String> = chunk.iter().map(|byte| byte.to_string()).collect();
            literal.push('[');
            literal.push_str(&bytes.join(","));
            literal.push_str("],");
        }
        literal.push_str(&format!("], flush: {flush} }},"));
        literal.push('\n');
    }
    literal.push_str("];\n");

    // Node's answer.
    let node_script = format!(
        r#"
const {{ StringDecoder }} = require('string_decoder');
{literal}
const out = [];
for (const testCase of cases) {{
  const decoder = new StringDecoder(testCase.encoding);
  const parts = [];
  for (const chunk of testCase.chunks) parts.push(decoder.write(Buffer.from(chunk)));
  if (testCase.flush) parts.push(decoder.end());
  const units = [];
  for (const part of parts) for (let i = 0; i < part.length; i++) units.push(part.charCodeAt(i));
  out.push(units);
}}
process.stdout.write(JSON.stringify(out));
"#
    );
    let output = Command::new("node")
        .arg("-e")
        .arg(&node_script)
        .output()
        .expect("node runs");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let node_raw = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // The real module's answer, produced in one script so the literals stay in
    // JavaScript and avoid a second JSON round trip.
    let binding_script = format!(
        r#"
{literal}
const out = [];
for (const testCase of cases) {{
  const decoder = new StringDecoder(testCase.encoding);
  const parts = [];
  for (const chunk of testCase.chunks) parts.push(decoder.write(new Uint8Array(chunk)));
  if (testCase.flush) parts.push(decoder.end());
  const units = [];
  for (const part of parts) for (let i = 0; i < part.length; i++) units.push(part.charCodeAt(i));
  out.push(units);
}}
JSON.stringify(out);
"#
    );
    let binding_raw = eval(&binding_script);

    let parse = |raw: &str| -> Vec<Vec<u16>> {
        let body = raw
            .strip_prefix("[[")
            .and_then(|rest| rest.strip_suffix("]]"))
            .unwrap_or_else(|| panic!("unexpected output: {raw}"));
        if body.is_empty() {
            return Vec::new();
        }
        body.split("],[")
            .map(|group| {
                group
                    .split(',')
                    .filter(|part| !part.is_empty())
                    .map(|part| part.parse::<u16>().expect("code unit"))
                    .collect()
            })
            .collect()
    };

    let expected = parse(&node_raw);
    let actual = parse(&binding_raw);
    assert_eq!(actual.len(), expected.len(), "one result per case");
    for (index, (encoding, _, _)) in cases.iter().enumerate() {
        assert_eq!(
            actual[index], expected[index],
            "real lib/string_decoder.js case {index} ({encoding}) differs from node"
        );
    }
}

/// V8's platform and global state are process-wide, so all cases share one test.
#[test]
fn real_lib_string_decoder_matches_node() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    module_loads_and_exposes_the_class();
    real_write_and_end_split_emoji();
    real_end_with_and_without_arguments();
    real_last_char_aliases_the_state_buffer();
    real_text_clears_state_and_slices();
    real_string_passthrough();
    real_write_rejects_non_views();
    real_unknown_encoding_is_rejected();
    real_every_encoding_decodes();
    real_module_matches_node();
}
