//! End-to-end checks that drive the binding through a real V8 isolate.
//!
//! `lib/string_decoder.js` is unchanged Node code, so the only way to know this
//! crate speaks the right protocol is to run the calls it makes. The harness
//! below is that file's native half, transcribed:
//!
//! ```js
//! this[kNativeDecoder] = Buffer.alloc(kSize);
//! this[kNativeDecoder][kEncodingField] = encodingsMap[this.encoding];
//! ...
//! return decode(this[kNativeDecoder], buf);
//! if (this[kNativeDecoder][kBufferedBytes] > 0) return ret + flush(state);
//! ```
//!
//! A bare isolate has neither `Buffer` nor `TextDecoder`, so the harness builds
//! the state with `new Uint8Array(binding.kSize)` — the same bytes
//! `Buffer.alloc(kSize)` returns — and results are compared through `asciiJson`,
//! which escapes every non-ASCII UTF-16 unit. That keeps emoji, U+FFFD and
//! U+007F visible in a diff instead of hiding in the test source.
//!
//! Expected values were recorded from a real `node`, not invented; the module
//! docs on each assertion say which command produced them.

use rn_bind_string_decoder::StringDecoder;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The native half of `lib/string_decoder.js`, plus small utilities.
///
/// `decoder(encoding)` reproduces the constructor and the two prototype methods
/// that touch the binding (`write` and `end`). `rawState()` lets a test drive
/// `decode`/`flush` directly.
const HARNESS: &str = r#"
const binding = globalThis.__stringDecoderBinding;

// `encodingsMap` from lib/internal/util.js: the array index is the field value.
const encodingsMap = { __proto__: null };
for (let i = 0; i < binding.encodings.length; ++i) {
  encodingsMap[binding.encodings[i]] = i;
}

// lib/string_decoder.js: StringDecoder(encoding)
globalThis.decoder = function decoder(encoding) {
  const self = {};
  self.encoding = encoding;
  self.state = new Uint8Array(binding.kSize);
  self.state[binding.kEncodingField] = encodingsMap[encoding];
  self.write = function write(buf) {
    if (typeof buf === 'string') return buf;
    return binding.decode(self.state, buf);
  };
  self.end = function end(buf) {
    const ret = buf === undefined ? '' : self.write(buf);
    if (self.state[binding.kBufferedBytes] > 0) return ret + binding.flush(self.state);
    return ret;
  };
  return self;
};

// A state buffer driven directly, for decode/flush tests.
globalThis.rawState = function rawState(encoding) {
  const state = new Uint8Array(binding.kSize);
  state[binding.kEncodingField] = encodingsMap[encoding];
  return state;
};

// Reads back a string as an array of UTF-16 code units.
globalThis.units = function units(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) out.push(text.charCodeAt(i));
  return out;
};

// JSON with every unit outside printable ASCII written as \uXXXX, so the
// expected strings in the Rust test stay ASCII and diff readably.
globalThis.asciiJson = function asciiJson(value) {
  return JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (ch) => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
};
"#;

/// Runs `sources` in one isolate with the binding installed, returning the last
/// script's value as a string.
///
/// V8's platform and global state are process-wide, so every case runs from a
/// single `#[test]`; each case gets its own isolate.
fn eval_sequence(sources: &[&str]) -> String {
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
    let key = v8::String::new(scope, "__stringDecoderBinding").expect("key");
    global.set(scope, key.into(), binding.into());

    let mut result = String::new();
    for source in std::iter::once(HARNESS).chain(sources.iter().copied()) {
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
    eval_sequence(&[source])
}

// ---------------------------------------------------------------------------
// Member shape
// ---------------------------------------------------------------------------

fn namespace_members() {
    let result = eval(
        r#"
        const b = globalThis.__stringDecoderBinding;
        JSON.stringify({
          decode: typeof b.decode,
          flush: typeof b.flush,
          encodingsType: typeof b.encodings,
          encodings: b.encodings,
          encodingsLength: b.encodings.length,
          kSize: b.kSize,
          kNumFields: b.kNumFields,
          kIncompleteCharactersStart: b.kIncompleteCharactersStart,
          kIncompleteCharactersEnd: b.kIncompleteCharactersEnd,
          kMissingBytes: b.kMissingBytes,
          kBufferedBytes: b.kBufferedBytes,
          kEncodingField: b.kEncodingField,
          ownKeys: Object.keys(b).sort(),
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"decode":"function","flush":"function","encodingsType":"object","encodings":["ascii","utf8","base64","utf16le","latin1","hex","buffer","base64url"],"encodingsLength":8,"kSize":7,"kNumFields":7,"kIncompleteCharactersStart":0,"kIncompleteCharactersEnd":4,"kMissingBytes":4,"kBufferedBytes":5,"kEncodingField":6,"ownKeys":["decode","encodings","flush","kBufferedBytes","kEncodingField","kIncompleteCharactersEnd","kIncompleteCharactersStart","kMissingBytes","kNumFields","kSize"]}"#
    );
}

/// `kSize` has to be a real upper bound: the JS allocates exactly that many
/// bytes, and `decode` writes through `kIncompleteCharactersStart..End` plus the
/// three counters, so the largest index must be `kSize - 1`.
fn state_buffer_fits() {
    let result = eval(
        r#"
        const b = globalThis.__stringDecoderBinding;
        JSON.stringify({
          largestIndex: Math.max(b.kIncompleteCharactersEnd - 1,
                                 b.kMissingBytes, b.kBufferedBytes,
                                 b.kEncodingField),
          size: b.kSize,
          fields: b.kNumFields,
        });
        "#,
    );
    assert_eq!(result, r#"{"largestIndex":6,"size":7,"fields":7}"#);
}

// ---------------------------------------------------------------------------
// The retention cases
// ---------------------------------------------------------------------------

/// A four-byte codepoint split across two writes. This is the whole point of
/// the class, and the assertion is on the *complete* output, not just the second
/// write: the first write must produce nothing and retain both bytes.
fn split_four_byte_codepoint() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const emoji = [0xf0, 0x9f, 0x98, 0x80];   // U+1F600
        const first = d.write(new Uint8Array(emoji.slice(0, 2)));
        const retained = {
          buffered: d.state[binding.kBufferedBytes],
          missing: d.state[binding.kMissingBytes],
          lastChar: Array.from(d.state.subarray(
            binding.kIncompleteCharactersStart,
            binding.kIncompleteCharactersEnd)),
        };
        const second = d.write(new Uint8Array(emoji.slice(2)));
        asciiJson({
          first,
          retained,
          second,
          secondUnits: units(second),
          completeUnits: units(first + second),
          drained: {
            buffered: d.state[binding.kBufferedBytes],
            missing: d.state[binding.kMissingBytes],
          },
          end: d.end(),
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"first":"","retained":{"buffered":2,"missing":2,"lastChar":[240,159,0,0]},"second":"\ud83d\ude00","secondUnits":[55357,56832],"completeUnits":[55357,56832],"drained":{"buffered":0,"missing":0},"end":""}"#
    );
}

/// Split one byte earlier, so the lead byte is alone and three bytes are still
/// needed; then the middle two, leaving one.
fn split_at_one_and_three() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const emoji = [0xf0, 0x9f, 0x98, 0x80];
        const a = d.write(new Uint8Array(emoji.slice(0, 1)));
        const after1 = [d.state[binding.kBufferedBytes], d.state[binding.kMissingBytes]];
        const b = d.write(new Uint8Array(emoji.slice(1, 3)));
        const after3 = [d.state[binding.kBufferedBytes], d.state[binding.kMissingBytes]];
        const c = d.write(new Uint8Array(emoji.slice(3)));
        asciiJson({ a, after1, b, after3, c, completeUnits: units(a + b + c) });
        "#,
    );
    assert_eq!(
        result,
        r#"{"a":"","after1":[1,3],"b":"","after3":[3,1],"c":"\ud83d\ude00","completeUnits":[55357,56832]}"#
    );
}

/// A lone trailing partial byte followed by `end()`. Recorded from Node:
/// `w: "a"`, `lastChar: [226,0,0,0]`, `lastNeed: 2`, `lastTotal: 3`,
/// `end: "\uFFFD"`.
fn lone_partial_byte_then_end() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const written = d.write(new Uint8Array([0x61, 0xe2]));
        // Read the counters before end(): flush clears them, and Node's
        // recorded `lastNeed`/`lastTotal` are the values a caller sees while
        // the character is still pending.
        const lastChar = Array.from(d.state.subarray(
          binding.kIncompleteCharactersStart, binding.kIncompleteCharactersEnd));
        const lastNeed = d.state[binding.kMissingBytes];
        const lastTotal = d.state[binding.kBufferedBytes] + d.state[binding.kMissingBytes];
        const ended = d.end();
        asciiJson({
          written,
          lastChar,
          lastNeed,
          lastTotal,
          ended,
          endedUnits: units(ended),
          after: [d.state[binding.kBufferedBytes], d.state[binding.kMissingBytes]],
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"written":"a","lastChar":[226,0,0,0],"lastNeed":2,"lastTotal":3,"ended":"\ufffd","endedUnits":[65533],"after":[0,0]}"#
    );
}

/// UTF-16LE surrogate pairs split across writes.
fn utf16_surrogates_split() {
    let result = eval(
        r#"
        const d = decoder('utf16le');
        const pair = [0x3d, 0xd8, 0x00, 0xde];    // U+1F600 little-endian
        const first = d.write(new Uint8Array(pair.slice(0, 2)));
        const retained = {
          buffered: d.state[binding.kBufferedBytes],
          missing: d.state[binding.kMissingBytes],
        };
        const second = d.write(new Uint8Array(pair.slice(2)));
        asciiJson({
          first, retained, second,
          secondUnits: units(second),
          completeUnits: units(first + second),
          end: d.end(),
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"first":"","retained":{"buffered":2,"missing":2},"second":"\ud83d\ude00","secondUnits":[55357,56832],"completeUnits":[55357,56832],"end":""}"#
    );
}

/// A single byte of UTF-16LE is half a code unit. Node drops it in `flush`
/// rather than emitting a replacement character.
fn utf16_odd_byte_is_dropped() {
    let result = eval(
        r#"
        const d = decoder('utf16le');
        const written = d.write(new Uint8Array([0x41]));
        const held = [d.state[binding.kBufferedBytes], d.state[binding.kMissingBytes]];
        asciiJson({ written, held, ended: d.end(), after: d.state[binding.kBufferedBytes] });
        "#,
    );
    assert_eq!(
        result,
        r#"{"written":"","held":[1,1],"ended":"","after":0}"#
    );
}

/// Base64 retains one or two bytes so that every emitted group is a whole
/// three-byte group. Recorded from Node for 1..5 input bytes.
fn base64_retention() {
    let expected = [
        (1, "", "QQ=="),
        (2, "", "QUI="),
        (3, "QUJD", ""),
        (4, "QUJD", "RA=="),
        (5, "QUJD", "REU="),
    ];
    for (length, written, flushed) in expected {
        let source = format!(
            r#"
            const d = decoder('base64');
            const chunk = [];
            for (let i = 0; i < {length}; i++) chunk.push(0x41 + i);
            const written = d.write(new Uint8Array(chunk));
            JSON.stringify([written, d.end()]);
            "#
        );
        assert_eq!(
            eval(&source),
            format!(r#"["{written}","{flushed}"]"#),
            "base64 over {length} bytes"
        );
    }
}

/// Base64 across several writes, so a group is completed from retained bytes.
fn base64_across_writes() {
    let result = eval(
        r#"
        const d = decoder('base64');
        const a = d.write(new Uint8Array([0x41]));
        const b = d.write(new Uint8Array([0x42, 0x43]));
        const c = d.write(new Uint8Array([0x44, 0x45, 0x46, 0x47]));
        JSON.stringify({ a, b, c, end: d.end() });
        "#,
    );
    assert_eq!(result, r#"{"a":"","b":"QUJD","c":"REVG","end":"Rw=="}"#);
}

/// `base64url` uses the URL alphabet and never pads. Recorded from Node for
/// `[0x41]` then `[0xfb,0xff,0xff]`: `{"a":"","b":"Qfv_","end":"_w"}`.
fn base64url_retention() {
    let result = eval(
        r#"
        const d = decoder('base64url');
        const a = d.write(new Uint8Array([0x41]));
        const b = d.write(new Uint8Array([0xfb, 0xff, 0xff]));
        JSON.stringify({ a, b, end: d.end() });
        "#,
    );
    assert_eq!(result, r#"{"a":"","b":"Qfv_","end":"_w"}"#);
}

/// Hex maps two digits per byte and retains nothing, so a one-byte write already
/// produces output.
fn hex_retention() {
    let result = eval(
        r#"
        const d = decoder('hex');
        const a = d.write(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
        const buffered = d.state[binding.kBufferedBytes];
        const e = decoder('hex');
        const b = e.write(new Uint8Array([0x01]));
        const c = e.write(new Uint8Array([0x23]));
        JSON.stringify({ a, buffered, b, c, end: e.end() });
        "#,
    );
    assert_eq!(
        result,
        r#"{"a":"deadbeef","buffered":0,"b":"01","c":"23","end":""}"#
    );
}

/// `ascii` masks the high bit (0xFF becomes U+007F) while `latin1` does not.
fn ascii_and_latin1() {
    let result = eval(
        r#"
        const a = decoder('ascii');
        const l = decoder('latin1');
        JSON.stringify({
          ascii: units(a.write(new Uint8Array([0x41, 0xff, 0x42]))),
          latin1: units(l.write(new Uint8Array([0x41, 0xff, 0x42]))),
        });
        "#,
    );
    assert_eq!(result, r#"{"ascii":[65,127,66],"latin1":[65,255,66]}"#);
}

// ---------------------------------------------------------------------------
// Parity with Node's own decoder
// ---------------------------------------------------------------------------

/// A mixed stream in one write: the emoji are whole, so nothing is retained.
fn mixed_stream_in_one_write() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const input = [0x61, 0xf0, 0x9f, 0x98, 0x80, 0x62, 0xf0, 0x9f, 0x98, 0x80, 0x63];
        const parts = d.write(new Uint8Array(input));
        JSON.stringify({ units: units(parts), end: d.end() });
        "#,
    );
    assert_eq!(
        result,
        r#"{"units":[97,55357,56832,98,55357,56832,99],"end":""}"#
    );
}

/// The literal per-byte sequence Node produces for `"a😀b😀c"`.
fn per_byte_writes_match_node() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const input = [0x61, 0xf0, 0x9f, 0x98, 0x80, 0x62, 0xf0, 0x9f, 0x98, 0x80, 0x63];
        const parts = [];
        for (const byte of input) parts.push(d.write(new Uint8Array([byte])));
        parts.push(d.end());
        asciiJson(parts);
        "#,
    );
    assert_eq!(
        result,
        r#"["a","","","","\ud83d\ude00","b","","","","\ud83d\ude00","c",""]"#
    );
}

/// Invalid UTF-8 falls through to V8's decoder, which emits one replacement
/// character per maximal subpart — the same strings Node produces.
fn invalid_utf8_matches_node() {
    let result = eval(
        r#"
        const a = decoder('utf8');
        const invalid = a.write(new Uint8Array([0x61, 0xff, 0x62]));

        const b = decoder('utf8');
        const truncated = b.write(new Uint8Array([0x61, 0xf0, 0x9f]));
        const truncatedEnd = b.end();

        // A byte that should be a continuation byte but is not: Node ends the
        // pending character there and lets the new byte start a fresh one.
        const c = decoder('utf8');
        c.write(new Uint8Array([0xf0, 0x9f]));
        const misaligned = c.write(new Uint8Array([0x41]));

        asciiJson({ invalid, truncated, truncatedEnd, misaligned });
        "#,
    );
    assert_eq!(
        result,
        r#"{"invalid":"a\ufffdb","truncated":"a","truncatedEnd":"\ufffd","misaligned":"\ufffdA"}"#
    );
}

/// The full record, field for field, for the input sequence recorded from Node:
///
/// ```text
/// node -e "const {StringDecoder}=require('string_decoder'); ..."
/// ```
///
/// covering every encoding the contract lists except `buffer`.
fn node_parity_record() {
    let result = eval(
        r#"
        const out = {};

        // 4-byte codepoint split in the middle.
        {
          const d = decoder('utf8');
          const b = [0xf0, 0x9f, 0x98, 0x80];
          out.emoji_split = [d.write(new Uint8Array(b.slice(0, 2))),
                             d.write(new Uint8Array(b.slice(2))), d.end()];
        }
        // Lone trailing partial byte then end().
        {
          const d = decoder('utf8');
          out.lone_state = {
            w: d.write(new Uint8Array([0x61, 0xe2])),
            lastChar: Array.from(d.state.subarray(binding.kIncompleteCharactersStart,
                                                  binding.kIncompleteCharactersEnd)),
            lastNeed: d.state[binding.kMissingBytes],
            lastTotal: d.state[binding.kBufferedBytes] + d.state[binding.kMissingBytes],
            end: d.end(),
          };
        }
        // UTF-16LE surrogate pair split across writes.
        {
          const d = decoder('utf16le');
          const b = [0x3d, 0xd8, 0x00, 0xde];
          out.utf16_split = [d.write(new Uint8Array(b.slice(0, 2))),
                             d.write(new Uint8Array(b.slice(2))), d.end()];
        }
        // Base64 retention at every length modulo three.
        for (const n of [1, 2, 3, 4, 5]) {
          const d = decoder('base64');
          const chunk = [];
          for (let i = 0; i < n; i++) chunk.push(0x41 + i);
          out['b64_' + n] = [d.write(new Uint8Array(chunk)), d.end()];
        }
        {
          const d = decoder('base64');
          const b = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
          out.b64_split = [d.write(new Uint8Array(b.slice(0, 1))),
                           d.write(new Uint8Array(b.slice(1, 3))),
                           d.write(new Uint8Array(b.slice(3))), d.end()];
        }
        // Hex, one write and two.
        {
          const d = decoder('hex');
          out.hex_basic = [d.write(new Uint8Array([0xde, 0xad, 0xbe, 0xef])), d.end()];
          const e = decoder('hex');
          out.hex_split = [e.write(new Uint8Array([0x01])),
                           e.write(new Uint8Array([0x23])), e.end()];
        }
        // ascii and latin1 over 0xFF.
        {
          const a = decoder('ascii');
          out.ascii = units(a.write(new Uint8Array([0x41, 0xff, 0x42])));
          const l = decoder('latin1');
          out.latin1 = units(l.write(new Uint8Array([0x41, 0xff, 0x42])));
        }
        // "a😀b😀c" one byte at a time.
        {
          const d = decoder('utf8');
          const b = [0x61, 0xf0, 0x9f, 0x98, 0x80, 0x62, 0xf0, 0x9f, 0x98, 0x80, 0x63];
          const parts = [];
          for (const byte of b) parts.push(d.write(new Uint8Array([byte])));
          parts.push(d.end());
          out.byte_by_byte = parts;
        }
        // Invalid UTF-8, complete and truncated.
        {
          const d = decoder('utf8');
          out.invalid_utf8 = [d.write(new Uint8Array([0x61, 0xff, 0x62])), d.end()];
          const e = decoder('utf8');
          out.invalid_partial = [e.write(new Uint8Array([0x61, 0xf0, 0x9f])), e.end()];
        }
        // A non-continuation byte where one was expected.
        {
          const d = decoder('utf8');
          out.misaligned = [d.write(new Uint8Array([0xf0, 0x9f])),
                            d.write(new Uint8Array([0x41])), d.end()];
        }
        // UTF-16LE odd byte, alone and mid-stream.
        {
          const d = decoder('utf16le');
          out.utf16_odd = [d.write(new Uint8Array([0x41])), d.end()];
          const e = decoder('utf16le');
          out.utf16_odd_mid = [e.write(new Uint8Array([0x41, 0x00, 0x42])), e.end()];
        }
        // write(string) passthrough and end() with no argument.
        {
          const d = decoder('utf8');
          out.string_passthrough = d.write('hello');
          out.end_empty = d.end();
        }
        asciiJson(out);
        "#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"emoji_split":["","\ud83d\ude00",""],"#,
            r#""lone_state":{"w":"a","lastChar":[226,0,0,0],"lastNeed":2,"lastTotal":3,"end":"\ufffd"},"#,
            r#""utf16_split":["","\ud83d\ude00",""],"#,
            r#""b64_1":["","QQ=="],"b64_2":["","QUI="],"b64_3":["QUJD",""],"#,
            r#""b64_4":["QUJD","RA=="],"b64_5":["QUJD","REU="],"#,
            r#""b64_split":["","QUJD","REVG","Rw=="],"#,
            r#""hex_basic":["deadbeef",""],"hex_split":["01","23",""],"#,
            r#""ascii":[65,127,66],"latin1":[65,255,66],"#,
            r#""byte_by_byte":["a","","","","\ud83d\ude00","b","","","","\ud83d\ude00","c",""],"#,
            r#""invalid_utf8":["a\ufffdb",""],"invalid_partial":["a","\ufffd"],"#,
            r#""misaligned":["","\ufffdA",""],"#,
            r#""utf16_odd":["",""],"utf16_odd_mid":["A",""],"#,
            r#""string_passthrough":"hello","end_empty":""}"#
        )
    );
}

// ---------------------------------------------------------------------------
// State-buffer protocol
// ---------------------------------------------------------------------------

/// `decode` and `flush` driven directly, without the JavaScript wrapper: this is
/// what proves the state really lives in the caller's buffer and not in a hidden
/// native registry. Two decoders are interleaved to make that explicit.
fn state_lives_in_the_caller_buffer() {
    let result = eval(
        r#"
        const first = rawState('utf8');
        const second = rawState('utf8');

        const a = binding.decode(first, new Uint8Array([0xf0, 0x9f]));
        const b = binding.decode(second, new Uint8Array([0xe2, 0x82]));
        const c = binding.decode(first, new Uint8Array([0x98, 0x80]));
        const d = binding.decode(second, new Uint8Array([0xac]));

        // The whole state, byte for byte, after both decoders drained.
        asciiJson({
          a, b, c, d,
          firstState: Array.from(first),
          secondState: Array.from(second),
        });
        "#,
    );
    assert_eq!(
        result,
        r#"{"a":"","b":"","c":"\ud83d\ude00","d":"\u20ac","firstState":[240,159,152,128,0,0,1],"secondState":[226,130,172,0,0,0,1]}"#
    );
}

/// A copy of the state decodes independently, which is the property that lets
/// the JavaScript keep the state in a plain buffer.
fn state_is_plain_bytes() {
    let result = eval(
        r#"
        const state = rawState('utf8');
        binding.decode(state, new Uint8Array([0xf0, 0x9f]));
        const copy = new Uint8Array(state);
        // Drain the original; the copy keeps the retained bytes.
        const original = binding.decode(state, new Uint8Array([0x98, 0x80]));
        const fromCopy = binding.decode(copy, new Uint8Array([0x98, 0x80]));
        asciiJson({ original, fromCopy });
        "#,
    );
    assert_eq!(
        result,
        r#"{"original":"\ud83d\ude00","fromCopy":"\ud83d\ude00"}"#
    );
}

/// `flush` on a state with nothing retained returns the empty string and leaves
/// the state usable, which is what `end()` relies on when reusing a decoder.
fn flush_is_idempotent() {
    let result = eval(
        r#"
        const state = rawState('utf8');
        const empty = binding.flush(state);
        const stillEmpty = binding.flush(state);
        const after = binding.decode(state, new Uint8Array([0x68, 0x69]));
        JSON.stringify({ empty, stillEmpty, after });
        "#,
    );
    assert_eq!(result, r#"{"empty":"","stillEmpty":"","after":"hi"}"#);
}

/// An empty chunk is legal and must not disturb retained bytes.
fn empty_chunk_keeps_pending_bytes() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const wrote = d.write(new Uint8Array([0x61, 0xf0]));
        const empty = d.write(new Uint8Array([]));
        const buffered = d.state[binding.kBufferedBytes];
        asciiJson({ wrote, empty, buffered, end: d.end() });
        "#,
    );
    assert_eq!(
        result,
        r#"{"wrote":"a","empty":"","buffered":1,"end":"\ufffd"}"#
    );
}

/// A state buffer shorter than `kSize` is refused instead of read past.
fn short_state_buffer_is_rejected() {
    let result = eval(
        r#"
        let message = '';
        try {
          binding.decode(new Uint8Array(3), new Uint8Array([0x61]));
        } catch (error) {
          message = error.message;
        }
        JSON.stringify({ message });
        "#,
    );
    assert!(
        result.contains("kSize"),
        "a short state buffer reports a TypeError: {result}"
    );
}

/// A DataView is a valid chunk, because `ArrayBufferIsView` accepts one.
fn data_view_chunk_works() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const backing = new Uint8Array([0x00, 0x68, 0x69, 0x00]);
        const view = new DataView(backing.buffer, 1, 2);
        JSON.stringify({ text: d.write(view), end: d.end() });
        "#,
    );
    assert_eq!(result, r#"{"text":"hi","end":""}"#);
}

/// Subarray views are read from their own offset, not from the parent buffer.
fn subarray_chunk_works() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const parent = new Uint8Array([0xff, 0xff, 0x68, 0x69]);
        JSON.stringify({ text: d.write(parent.subarray(2)), end: d.end() });
        "#,
    );
    assert_eq!(result, r#"{"text":"hi","end":""}"#);
}

/// A long stream through many splits stays complete: 64 four-byte codepoints,
/// two bytes per write.
fn long_stream_stays_aligned() {
    let result = eval(
        r#"
        const d = decoder('utf8');
        const expected = '\ud83d\ude00'.repeat(64);
        let out = '';
        for (let i = 0; i < 64; i++) {
          out += d.write(new Uint8Array([0xf0, 0x9f]));
          out += d.write(new Uint8Array([0x98, 0x80]));
        }
        JSON.stringify({
          length: out.length,
          matches: out === expected,
          end: d.end(),
        });
        "#,
    );
    assert_eq!(result, r#"{"length":128,"matches":true,"end":""}"#);
}

/// V8's platform and global state are process-wide, so all cases share one test.
#[test]
fn string_decoder_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    namespace_members();
    state_buffer_fits();
    split_four_byte_codepoint();
    split_at_one_and_three();
    lone_partial_byte_then_end();
    utf16_surrogates_split();
    utf16_odd_byte_is_dropped();
    base64_retention();
    base64_across_writes();
    base64url_retention();
    hex_retention();
    ascii_and_latin1();
    mixed_stream_in_one_write();
    per_byte_writes_match_node();
    invalid_utf8_matches_node();
    node_parity_record();
    state_lives_in_the_caller_buffer();
    state_is_plain_bytes();
    flush_is_idempotent();
    empty_chunk_keeps_pending_bytes();
    short_state_buffer_is_rejected();
    data_view_chunk_works();
    subarray_chunk_works();
    long_stream_stays_aligned();
}
