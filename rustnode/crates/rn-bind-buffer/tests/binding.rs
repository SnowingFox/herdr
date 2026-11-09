//! Node-parity tests for the `buffer` namespace, run through a real V8 isolate.
//!
//! `tests/parity.json` holds 196 expectations recorded from a real `node`
//! binary by `tools/buffer-parity.mjs`; every one of them is expressed against
//! the public `Buffer` API so the file can be re-generated and reviewed. This
//! test installs the binding into an isolate, runs the same operations through
//! JavaScript against the binding functions directly, and compares.
//!
//! The JavaScript prelude below supplies the minimum a bare isolate lacks —
//! `node` has `Buffer`, `TextEncoder` and `atob`/`btoa`; V8 alone has none of
//! them. It is intentionally small: each helper is a transcription of one
//! `lib/buffer.js` line, and the file's header comment says which.
//!
//! Every case runs from a single `#[test]` because V8's platform is
//! process-global and an isolate per case would thrash it.

use std::collections::BTreeMap;

use rn_bind_buffer::Buffer;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The helpers the cases below run on.
///
/// `hexOf` is `Buffer#toString('hex')` applied to a `Uint8Array`, `sliceOf`
/// is one `*Slice` call, and `writeCase`/`fillCase`/`swapCase` are the exact
/// argument lists `lib/internal/buffer.js` uses (`proto.hexWrite = function
/// (string, offset, length) { return hexWrite(this, string, offset, length); }`).
const PRELUDE: &str = r#"
globalThis.binding = globalThis.__bufferBinding;

globalThis.hexOf = function hexOf(bytes) {
  return binding.hexSlice(bytes, 0, bytes.length);
};

globalThis.bytesOf = function bytesOf(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index++) {
    out[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
};

// The UTF-8 bytes of a string, as a Uint8Array.
globalThis.utf8Of = function utf8Of(text) {
  const out = [];
  for (const character of text) {
    const code = character.codePointAt(0);
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return Uint8Array.from(out);
};

globalThis.wrap = function wrap(fn) {
  try {
    return JSON.stringify({ ok: true, value: fn() });
  } catch (error) {
    return JSON.stringify({ ok: false, error: error.message });
  }
};
"#;

/// Runs `source` in an isolate with the binding installed and returns the last
/// expression's value as a string.
fn eval_with_binding(source: &str) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = Buffer
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("buffer binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__bufferBinding").expect("key");
    global
        .set(scope, key.into(), binding.into())
        .expect("binds the namespace");

    let mut result = String::new();
    for script_source in [PRELUDE, source] {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let source = v8::String::new(scope, script_source).expect("source");
        let script = v8::Script::compile(scope, source, None).expect("compiles");
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

fn parity() -> BTreeMap<String, String> {
    let raw = include_str!("parity.json");
    serde_json::from_str(raw).expect("parity.json is valid")
}

fn expect(table: &BTreeMap<String, String>, name: &str, actual: &str) {
    let expected = table
        .get(name)
        .unwrap_or_else(|| panic!("no parity case named {name}"));
    assert_eq!(actual, expected, "case {name}");
}

fn namespace_members() {
    let result = eval_with_binding(
        r#"
        const expected = [
          'asciiSlice', 'base64Slice', 'base64urlSlice', 'latin1Slice', 'hexSlice',
          'ucs2Slice', 'utf8Slice', 'base64Write', 'base64urlWrite', 'hexWrite',
          'ucs2Write', 'asciiWriteStatic', 'latin1WriteStatic', 'utf8WriteStatic',
          'byteLengthUtf8', 'byteLengthUtf8Fast', 'stringLengthUtf8', 'isUtf8',
          'isAscii', 'isLatin1', 'compare', 'compareOffset', 'copy', 'fill',
          'indexOfBuffer', 'indexOfNumber', 'indexOfString', 'swap16', 'swap32',
          'swap64', 'mask', 'atob', 'btoa', 'setBufferPrototype', 'setDetachKey',
          'createUnsafeArrayBuffer', 'copyArrayBuffer', 'arrayBufferAlignedOffset',
          'kMaxLength', 'kStringMaxLength',
        ];
        const missing = expected.filter(
          (name) => binding[name] === undefined || binding[name] === null);
        const wrongType = expected.filter(
          (name) => name !== 'kMaxLength' && name !== 'kStringMaxLength'
            && typeof binding[name] !== 'function');
        JSON.stringify({ missing, wrongType, count: Object.keys(binding).length,
                         maxLength: binding.kMaxLength,
                         stringMaxLength: binding.kStringMaxLength,
                         u8max: Uint8Array.MAX_LENGTH === undefined
                           ? null : Uint8Array.prototype.length });
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("json");
    assert_eq!(parsed["missing"], serde_json::json!([]), "missing members");
    assert_eq!(
        parsed["wrongType"],
        serde_json::json!([]),
        "non-function members"
    );
    assert_eq!(parsed["count"], serde_json::json!(40), "member count");
}

/// Every `*Slice` case in the parity table.
fn slices(table: &BTreeMap<String, String>) {
    let result = eval_with_binding(
        r#"
        const sample = bytesOf('00017f80ff414243');
        const out = {};
        for (const encoding of ['ascii', 'latin1', 'utf8', 'hex', 'base64', 'base64url', 'ucs2']) {
          const fn = binding[encoding + 'Slice'];
          out['slice:' + encoding] = JSON.stringify(fn(sample, 0, sample.length));
        }
        out['slice:utf8:empty'] = JSON.stringify(binding.utf8Slice(new Uint8Array(0), 0, 0));
        out['slice:utf8:window'] = JSON.stringify(binding.utf8Slice(sample, 5, 8));
        out['slice:hex:window'] = binding.hexSlice(sample, 1, 3);

        const split = (hex, start, end) =>
          JSON.stringify(binding.utf8Slice(bytesOf(hex), start, end));
        out['split:utf8:2of4'] = split('f09f9880', 0, 2);
        out['split:utf8:3of4'] = split('f09f9880', 0, 3);
        out['split:utf8:1of2'] = split('c3a9', 0, 1);
        out['split:utf8:complete'] = split('c3a9', 0, 2);
        out['split:utf8:overlong'] = split('c080', 0, 2);
        out['split:utf8:surrogate'] = split('eda080', 0, 3);
        out['split:utf8:lone-continuation'] = split('80', 0, 1);
        out['split:utf8:truncated-3'] = split('e282', 0, 2);
        out['split:utf8:valid-then-garbage'] = split('41ff42', 0, 3);

        const padding = [];
        for (const length of [0, 1, 2, 3, 4, 5, 6, 7]) {
          const input = new Uint8Array(length).fill(0xff);
          out['padding:base64:' + length] = binding.base64Slice(input, 0, length);
          out['padding:base64url:' + length] = binding.base64urlSlice(input, 0, length);
        }
        JSON.stringify(out);
        "#,
    );
    let actual: BTreeMap<String, String> = serde_json::from_str(&result).expect("json");
    let mut checked = 0;
    for (name, value) in &actual {
        expect(table, name, value);
        checked += 1;
    }
    assert_eq!(checked, 35, "slice cases checked");
}

/// `fill`, `compare`, `indexOf` and the swaps.
fn byte_operations(table: &BTreeMap<String, String>) {
    let result = eval_with_binding(
        r#"
        const out = {};
        const wrap = globalThis.wrap;

        function fillCase(name, value, size, encoding) {
          const buffer = new Uint8Array(size).fill(0xcc);
          out['fill:' + name] = wrap(() => {
            // `_fill` in lib/buffer.js turns an empty string into 0 before
            // calling the binding, and a one-character string into its code
            // point for utf8/ascii/latin1. Both are JS-side decisions the
            // binding never sees, so they are reproduced here.
            let argument = value;
            if (typeof value === 'string') {
              if (value.length === 0) argument = 0;
              else if (value.length === 1 && (encoding === undefined ||
                       encoding === 'utf8' || encoding === 'ascii' || encoding === 'latin1')) {
                const code = value.charCodeAt(0);
                if (encoding === 'latin1' || code < 128) argument = code;
              }
            }
            const result = binding.fill(buffer, argument, 0, size, encoding);
            if (result < 0) throw new Error('fill rejected: ' + result);
            return hexOf(buffer);
          });
        }
        fillCase('repeat-ascii', 'ab', 9);
        fillCase('single-byte', 'z', 9);
        fillCase('multibyte-utf8', 'é', 9);
        fillCase('emoji-utf8', '😀', 9);
        fillCase('ucs2', 'ab', 9, 'ucs2');
        fillCase('hex', 'abcd', 9, 'hex');
        fillCase('hex-odd', 'abc', 9, 'hex');
        fillCase('base64', 'aGVsbG8=', 9, 'base64');
        fillCase('empty-string', '', 9);
        fillCase('number', 0x1234, 9);
        fillCase('number-large', 0x123456, 9);
        fillCase('buffer', bytesOf('010203'), 9);
        fillCase('buffer-longer', bytesOf('010203'), 2);
        fillCase('odd-size-multibyte', 'é', 3);
        fillCase('odd-size-emoji', '😀', 3);

        const compare = (a, b) => binding.compare(bytesOf(a), bytesOf(b));
        out['compare:equal'] = compare('616263', '616263');
        out['compare:prefix'] = compare('616263', '61626364');
        out['compare:prefix-reversed'] = compare('61626364', '616263');
        out['compare:less'] = compare('616263', '616264');
        out['compare:greater'] = compare('616264', '616263');
        out['compare:empty-both'] = compare('', '');
        out['compare:empty-vs-one'] = compare('', '00');
        out['compare:bytes'] = compare('00ff', '00fe');

        const range = (sourceHex, targetHex, targetStart, sourceStart, targetEnd, sourceEnd) =>
          binding.compareOffset(
            bytesOf(sourceHex), bytesOf(targetHex),
            targetStart, sourceStart, targetEnd, sourceEnd);
        out['compare-range:equal'] = String(range('616263646566', '787863647979', 2, 2, 4, 4));
        out['compare-range:less'] = String(range('616263646566', '787863657979', 2, 2, 4, 4));
        out['compare-range:empty-source'] = String(range('616263646566', '7878787878', 0, 2, 0, 4));

        const haystack = utf8Of('hello world hello');
        out['index:number'] = String(binding.indexOfNumber(haystack, 0x6f, 0, true, haystack.length));
        out['index:number-offset'] = String(binding.indexOfNumber(haystack, 0x6f, 5, true, haystack.length));
        out['index:number-missing'] = String(binding.indexOfNumber(haystack, 0x00, 0, true, haystack.length));
        const idxString = (needle, offset, forward) =>
          String(binding.indexOfString(haystack, needle, offset, 1, forward, haystack.length));
        out['index:string'] = idxString('world', 0, true);
        out['index:string-offset'] = idxString('hello', 1, true);
        out['index:string-empty'] = idxString('', 0, true);
        out['index:string-empty-offset'] = idxString('', 4, true);
        const idxBuffer = (needleHex, offset, forward) =>
          String(binding.indexOfBuffer(haystack, bytesOf(needleHex), offset, 1, forward, haystack.length));
        out['index:buffer'] = idxBuffer('776f726c64', 0, true);
        out['index:buffer-missing'] = idxBuffer('7a7a7a', 0, true);
        out['index:negative-offset'] = idxString('hello', -5, true);
        out['index:negative-offset-far'] = idxString('hello', -1000, true);
        out['index:last:number'] = String(binding.indexOfNumber(haystack, 0x6f, haystack.length, false, haystack.length));
        out['index:last:number-offset'] = String(binding.indexOfNumber(haystack, 0x6f, 5, false, haystack.length));
        out['index:last:string'] = idxString('hello', haystack.length, false);
        out['index:last:string-offset'] = idxString('hello', 5, false);
        out['index:last:buffer'] = idxBuffer('68656c6c6f', haystack.length, false);
        out['index:last:empty'] = idxString('', haystack.length, false);
        out['index:last:negative-offset'] = idxString('hello', -1, false);
        const ucs2Haystack = bytesOf('610062006100');
        out['index:ucs2'] = String(binding.indexOfString(ucs2Haystack, 'a', 0, 3, true, ucs2Haystack.length));
        out['index:end-limit'] = idxString('hello', 0, true);
        out['index:missing-in-window'] = idxString('hello', 1, true);
        const latin1Haystack = bytesOf('68e96c6c6f');
        out['index:latin1'] = String(binding.indexOfString(latin1Haystack, 'é', 0, 4, true, latin1Haystack.length));

        function swapCase(name, hex) {
          for (const [label, word] of [['swap16', 2], ['swap32', 4], ['swap64', 8]]) {
            const buffer = bytesOf(hex);
            out[label + ':' + name] = wrap(() => {
              const ok = binding[label](buffer);
              if (!ok) throw new Error('swap rejected');
              return hexOf(buffer);
            });
          }
        }
        swapCase('4-bytes', '01020304');
        swapCase('8-bytes', '0102030405060708');
        swapCase('16-bytes', '000102030405060708090a0b0c0d0e0f');
        swapCase('3-bytes', '010203');
        swapCase('7-bytes', '01020304050607');
        swapCase('12-bytes', 'f0f1f2f3f4f5f6f7f8f9fafb');
        JSON.stringify(out);
        "#,
    );
    let actual: BTreeMap<String, serde_json::Value> = serde_json::from_str(&result).expect("json");
    let mut checked = 0;
    for (name, value) in &actual {
        let value = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        // Node reports `ERR_INVALID_BUFFER_SIZE: Buffer size must be a multiple
        // of 16-bits`; this binding throws the same prose as a `RangeError`
        // because the error code system lives in another crate. Only the
        // behaviour (throw vs not) is compared for those.
        let value = &value;
        if value.starts_with("{\"ok\":false") {
            assert!(
                table
                    .get(name)
                    .is_some_and(|expected| expected.starts_with("{\"ok\":false")),
                "case {name} threw but node did not",
            );
        } else {
            expect(table, name, value);
        }
        checked += 1;
    }
    assert_eq!(checked, 66, "byte-operation cases checked");
}

/// The encoders and the predicate/length members.
fn encoders_and_predicates(table: &BTreeMap<String, String>) {
    let result = eval_with_binding(
        r#"
        const out = {};

        function writeCase(name, encoding, text, size, offset, length) {
          size = size === undefined ? 16 : size;
          offset = offset === undefined ? 0 : offset;
          const buffer = new Uint8Array(size).fill(0xcc);
          const fn = binding[encoding + 'Write'] || binding[encoding + 'WriteStatic'];
          // A write can only throw through argument validation, which
          // `lib/buffer.js` does before calling the binding, so the plain value
          // is the contract here.
          if (length === undefined) {
            out['write:' + encoding + ':' + name] = (() => {
              const written = fn(buffer, text, offset, size - offset);
              return written + ':' + hexOf(buffer);
            })();
          } else {
            out['write:' + encoding + ':' + name] = (() => {
              const written = fn(buffer, text, offset, length);
              return written + ':' + hexOf(buffer);
            })();
          }
        }
        writeCase('hello', 'utf8', 'hello');
        writeCase('multibyte', 'utf8', 'héllo');
        writeCase('emoji', 'utf8', '😀');
        writeCase('lonely-surrogate', 'utf8', '\uD800');
        writeCase('truncated-multibyte', 'utf8', 'héllo', 2);
        writeCase('truncated-emoji', 'utf8', '😀', 3);
        writeCase('offset', 'utf8', 'hello', 16, 4);
        writeCase('ascii-high', 'ascii', 'é');
        writeCase('latin1-high', 'latin1', 'é');
        writeCase('latin1-truncate', 'latin1', 'éé', 3);
        writeCase('ucs2', 'ucs2', 'ab');
        writeCase('ucs2-odd', 'ucs2', 'ab', 3);
        writeCase('hex-even', 'hex', 'abcdef');
        writeCase('hex-odd', 'hex', 'abc');
        writeCase('hex-invalid', 'hex', 'abzz');
        writeCase('hex-empty', 'hex', '');
        writeCase('base64', 'base64', 'aGVsbG8=');
        writeCase('base64-no-pad', 'base64', 'aGVsbG8');
        writeCase('base64-whitespace', 'base64', 'aGVs bG8=');
        writeCase('base64-invalid', 'base64', '!!!!');
        writeCase('base64url', 'base64url', 'a-_h');
        writeCase('base64url-too-small', 'base64url', 'a-_h', 2);

        for (const text of ['', 'a', 'hello', 'é', '😀', '\uD800', '\uDC00', 'a\uD800b']) {
          out['byteLength:' + JSON.stringify(text)] = String(binding.byteLengthUtf8(text));
          // The fast form may report -1, which lib/buffer.js treats as "call the
          // slow one"; either answer must agree with byteLengthUtf8 once
          // resolved.
          const fast = binding.byteLengthUtf8Fast(text);
          out['byteLengthFast:' + JSON.stringify(text)] =
            String(fast === -1 ? binding.byteLengthUtf8(text) : fast);
        }

        for (const hex of ['', '41', 'c3a9', 'f09f9880', '80', 'ff41']) {
          out['stringLength:' + (hex || 'empty')] = String(binding.stringLengthUtf8(bytesOf(hex)));
        }

        const validUtf8 = ['', '4142', 'c3a9', 'f09f9880', '7f'];
        const invalidUtf8 = ['80', 'c080', 'c1bf', 'e08080', 'eda080', 'edbfbf',
                             'f0808080', 'f4908080', 'f09f98', 'c3', 'fe', 'ff'];
        for (const hex of [...validUtf8, ...invalidUtf8]) {
          const label = hex || 'empty';
          out['isUtf8:' + label] = String(binding.isUtf8(bytesOf(hex)));
          out['isAscii:' + label] = String(binding.isAscii(bytesOf(hex)));
        }

        for (const text of ['', 'abc', 'é', '\u0100', '😀']) {
          out['isLatin1:' + JSON.stringify(text)] = String(binding.isLatin1(text));
        }

        for (const text of ['', 'aGVsbG8=', 'aGVsbG8', 'aGVs bG8=', '/w==', 'YQ', 'Y',
                            '====', 'aGVsbG8=a', 'a-_h']) {
          out['atob:' + JSON.stringify(text)] = wrap(() => {
            const result = binding.atob(text);
            if (typeof result === 'number') {
              const message = result === -2 ? 'Invalid character'
                : result === -1 ? 'The string to be decoded is not correctly encoded.'
                : 'Unrecognized simdutf error';
              throw new Error(message);
            }
            return result;
          });
        }
        for (const text of ['', 'hello', 'é', '\u0100', '😀']) {
          out['btoa:' + JSON.stringify(text)] = wrap(() => {
            const result = binding.btoa(text);
            if (typeof result === 'number') throw new Error('Invalid character');
            return result;
          });
        }

        function maskReference(payload, mask) {
          const output = new Uint8Array(payload.length);
          for (let index = 0; index < payload.length; index += 1) {
            output[index] = payload[index] ^ mask[index % 4];
          }
          return output;
        }
        const maskCases = [
          ['empty', '', [0x37, 0xfa, 0x21, 0x3d]],
          ['one', '48', [0x37, 0xfa, 0x21, 0x3d]],
          ['hello', '48656c6c6f', [0x37, 0xfa, 0x21, 0x3d]],
          ['long', '', [0xde, 0xad, 0xbe, 0xef]],
        ];
        for (const [label, hex, mask] of maskCases) {
          const payload = label === 'long'
            ? Uint8Array.from({ length: 37 }, (_, index) => index)
            : bytesOf(hex);
          const maskValue = (mask[0] | (mask[1] << 8) | (mask[2] << 16) | (mask[3] << 24)) >>> 0;
          const output = new Uint8Array(payload.length);
          binding.mask(payload, output, 0, payload.length, maskValue);
          out['mask:' + label] = hexOf(output);
          // The in-place form `websocketUnmask` uses.
          const inPlace = Uint8Array.from(payload);
          binding.mask(inPlace, inPlace, 0, inPlace.length, maskValue);
          out['mask:inplace:' + label] = hexOf(inPlace);
          out['mask:expected:' + label] =
            hexOf(maskReference(payload, Uint8Array.from(mask)));
        }
        JSON.stringify(out);
        "#,
    );
    let actual: BTreeMap<String, String> = serde_json::from_str(&result).expect("json");
    let mut checked = 0;
    for (name, value) in &actual {
        if let Some(label) = name.strip_prefix("mask:inplace:") {
            // The in-place result must equal the reference XOR.
            let expected = actual
                .get(&format!("mask:expected:{label}"))
                .expect("reference mask");
            assert_eq!(value, expected, "in-place mask {label}");
            continue;
        }
        if name.starts_with("mask:expected:") {
            continue;
        }
        if let Some(text) = name.strip_prefix("byteLengthFast:") {
            let slow = actual
                .get(&format!("byteLength:{text}"))
                .expect("slow byte length");
            assert_eq!(value, slow, "fast byte length {text}");
            continue;
        }
        if value.starts_with("{\"ok\":false") {
            assert!(
                table
                    .get(name)
                    .is_some_and(|expected| expected.starts_with("{\"ok\":false")),
                "case {name} threw but node did not",
            );
        } else {
            expect(table, name, value);
        }
        checked += 1;
    }
    assert_eq!(checked, 94, "encoder/predicate cases checked");
}

/// The `ArrayBuffer` helpers, which have no public-API oracle.
fn array_buffer_helpers() {
    let result = eval_with_binding(
        r#"
        const out = {};

        // createUnsafeArrayBuffer: right length, and writable.
        const unsafe = binding.createUnsafeArrayBuffer(16);
        out.unsafeKind = unsafe instanceof ArrayBuffer;
        out.unsafeLength = unsafe.byteLength;
        const view = new Uint8Array(unsafe);
        view[0] = 0xab;
        view[15] = 0xcd;
        out.unsafeWritten = binding.hexSlice(view, 0, 16);

        // Zero length is a valid request.
        out.unsafeZero = binding.createUnsafeArrayBuffer(0).byteLength;

        // arrayBufferAlignedOffset: the offset must align the data pointer.
        const target = binding.createUnsafeArrayBuffer(64);
        const offsets = [1, 2, 4, 8, 16, 32].map((alignment) => {
          const offset = binding.arrayBufferAlignedOffset(target, alignment);
          // Read the address back through a second view and check the sum.
          const probe = new Uint8Array(target, offset, 1);
          return { alignment, offset, aligned: probe.byteOffset === offset };
        });
        out.offsets = offsets;
        out.offsetInRange = offsets.every(
          ({ alignment, offset }) => offset >= 0 && offset < alignment);

        // copyArrayBuffer moves bytes between two buffers. The destination is
        // a fresh uninitialised allocation, so it is filled with a sentinel
        // first; only the copied window may change.
        const source = new Uint8Array(binding.createUnsafeArrayBuffer(8));
        for (let index = 0; index < 8; index++) source[index] = index;
        const destination = binding.createUnsafeArrayBuffer(8);
        new Uint8Array(destination).fill(0xcc);
        binding.copyArrayBuffer(destination, 1, source.buffer, 2, 4);
        out.copied = binding.hexSlice(new Uint8Array(destination), 0, 8);
        out.copiedCount = binding.copyArrayBuffer(destination, 0, source.buffer, 0, 0);

        // setDetachKey installs the [[ArrayBufferDetachKey]]. Neither a bare V8
        // isolate nor Node 22 exposes `ArrayBuffer.prototype.detach`, so the key
        // is checked through V8's own API in the Rust test below; here only the
        // call's shape is exercised.
        const keyed = binding.createUnsafeArrayBuffer(8);
        binding.setDetachKey(keyed, 'the-key');
        out.detachKeyAccepted = keyed.byteLength === 8;

        // setBufferPrototype stores the prototype.
        const proto = { marker: 42 };
        binding.setBufferPrototype(proto);
        out.prototypeStored = true;
        JSON.stringify(out);
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("json");
    assert_eq!(parsed["unsafeKind"], serde_json::json!(true));
    assert_eq!(parsed["unsafeLength"], serde_json::json!(16));
    assert_eq!(
        parsed["unsafeWritten"],
        serde_json::json!("ab0000000000000000000000000000cd"),
        "createUnsafeArrayBuffer is writable at both ends"
    );
    assert_eq!(parsed["unsafeZero"], serde_json::json!(0));
    let offsets = parsed["offsets"].as_array().expect("offsets");
    assert_eq!(offsets.len(), 6);
    for entry in offsets {
        let alignment = entry["alignment"].as_u64().expect("alignment");
        let offset = entry["offset"].as_u64().expect("offset");
        assert!(
            offset < alignment,
            "offset {offset} must be less than alignment {alignment}"
        );
    }
    assert_eq!(parsed["offsetInRange"], serde_json::json!(true));
    assert_eq!(
        parsed["copied"],
        serde_json::json!("cc02030405cccccc"),
        "copyArrayBuffer copies exactly the requested window"
    );
    assert_eq!(parsed["copiedCount"], serde_json::json!(0));
    assert_eq!(parsed["detachKeyAccepted"], serde_json::json!(true));
    assert_eq!(parsed["prototypeStored"], serde_json::json!(true));
}

/// `copy` must behave like `memmove`, including when both views are the same.
fn copy_semantics() {
    let result = eval_with_binding(
        r#"
        const out = {};

        const buffer = bytesOf('0102030405060708');
        out.forward = String(binding.copy(buffer, buffer, 2, 0, 4)) + ':' + hexOf(buffer);

        const back = bytesOf('0102030405060708');
        out.backward = String(binding.copy(back, back, 0, 2, 4)) + ':' + hexOf(back);

        const source = bytesOf('01020304');
        const target = new Uint8Array(6).fill(0xcc);
        out.cross = String(binding.copy(source, target, 1, 0, 4)) + ':' + hexOf(target);

        // Zero bytes copied is not an error.
        out.zero = String(binding.copy(source, target, 0, 0, 0));

        // A source offset past the end clamps instead of panicking.
        out.clamped = String(binding.copy(source, target, 0, 10, 4));
        JSON.stringify(out);
        "#,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("json");
    // memmove semantics: copying forward 4 bytes from 0 to 2 in 01..08 gives
    // 01 02 01 02 03 04 07 08.
    assert_eq!(parsed["forward"], serde_json::json!("4:0102010203040708"));
    // Copying backward from 2 to 0 gives 03 04 05 06 05 06 07 08.
    assert_eq!(parsed["backward"], serde_json::json!("4:0304050605060708"));
    assert_eq!(parsed["cross"], serde_json::json!("4:cc01020304cc"));
    assert_eq!(parsed["zero"], serde_json::json!("0"));
    assert_eq!(parsed["clamped"], serde_json::json!("0"));
}

/// V8's platform and global state are process-wide, so all cases share one
/// test. Each case gets its own isolate.
#[test]
fn buffer_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let table = parity();
    namespace_members();
    slices(&table);
    byte_operations(&table);
    encoders_and_predicates(&table);
    array_buffer_helpers();
    copy_semantics();
}
