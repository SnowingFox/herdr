'use strict';
// Differential probe for `TextEncoder#encodeInto`.
//
// One JSON line per case, so the output can be diffed between two runtimes:
// `read`, `written` and the destination's bytes are the whole observable
// contract of the operation, and any divergence is a behaviour change.
//
// The same file runs three ways and produces the same bytes each time:
//
//   node tests/encode-into-cases.js            # the reference
//   rustnode tests/encode-into-cases.js        # the binary
//   an in-process isolate                      # `tests/binding.rs`
//
// The third has no `TextEncoder`, so it supplies this file's `makeShim`: a
// transcription of the four lines `lib/internal/encoding.js` puts around the
// binding. Every case therefore runs through the public surface on all three,
// which is the only surface the reference has.

function makeShim(binding) {
  return {
    encode(source) {
      binding.encodeInto(source, shimScratch);
      const written = binding.encodeIntoResults[1];
      const result = new Uint8Array(written);
      for (let index = 0; index < written; index++) {
        result[index] = shimScratch[index];
      }
      return result;
    },
    encodeInto(source, destination) {
      // `TextEncoder.prototype.encodeInto` validates before it reaches the
      // binding. Reproduced here so the shim rejects the same arguments with
      // the same `code`; `validateString` is `lib/internal/validators.js` and
      // the message text is not part of the contract this file compares.
      if (typeof source !== 'string') {
        throw invalidArgType('The "src" argument must be of type string.');
      }
      if (!(destination instanceof Uint8Array)) {
        throw invalidArgType('The "dest" argument must be an instance of Uint8Array.');
      }
      binding.encodeInto(source, destination);
      const read = binding.encodeIntoResults[0];
      const written = binding.encodeIntoResults[1];
      return { read, written };
    },
  };
}

function invalidArgType(message) {
  const error = new TypeError(message);
  error.code = 'ERR_INVALID_ARG_TYPE';
  return error;
}

// `encode()`'s destination for the shim, sized like `smallEncodeScratch` in
// `lib/internal/encoding.js` (it is 1024 bytes there; no case here is longer).
const shimScratch = new Uint8Array(65536);

const encoder =
  typeof TextEncoder === 'function'
    ? new TextEncoder()
    : makeShim(globalThis.__encodingBinding);

const out = [];

function record(name, fn) {
  let entry;
  try {
    entry = { name, ok: true, ...fn() };
  } catch (error) {
    entry = { name, ok: false, error: `${error.code || error.name}` };
  }
  out.push(entry);
}

// Comparing hex makes the unwritten tail of the destination visible: it is
// prefilled with 0xcc and anything the encoder did not touch stays that way.
function hex(bytes) {
  let text = '';
  for (let index = 0; index < bytes.length; index++) {
    text += bytes[index].toString(16).padStart(2, '0');
  }
  return text;
}

// `source` into a `size`-byte destination, through the public surface.
function encodeIntoCase(name, source, size) {
  record(name, () => {
    const destination = new Uint8Array(size).fill(0xcc);
    const result = encoder.encodeInto(source, destination);
    return {
      read: result.read,
      written: result.written,
      bytes: hex(destination),
    };
  });
}

// --- the boundary cases -----------------------------------------------------

encodeIntoCase('exact-ascii', 'abc', 3);
encodeIntoCase('short-by-1-ascii', 'abc', 2);
encodeIntoCase('short-by-2-ascii', 'abc', 1);
encodeIntoCase('zero-dest', 'abc', 0);
encodeIntoCase('empty-source', '', 8);
encodeIntoCase('empty-source-empty-dest', '', 0);
encodeIntoCase('exact-latin1', '\u00e9\u00e9', 4);
encodeIntoCase('short-by-1-latin1', '\u00e9\u00e9', 3);
encodeIntoCase('short-by-2-latin1', '\u00e9\u00e9', 2);
encodeIntoCase('exact-cjk', '\u4f60\u597d', 6);
encodeIntoCase('short-by-1-cjk', '\u4f60\u597d', 5);
encodeIntoCase('astral-fits', '\u{1f600}', 4);
encodeIntoCase('astral-short-by-1', '\u{1f600}', 3);
encodeIntoCase('astral-short-by-2', '\u{1f600}', 2);
encodeIntoCase('astral-short-by-3', '\u{1f600}', 1);
encodeIntoCase('astral-after-ascii-exact', 'a\u{1f600}', 5);
encodeIntoCase('astral-after-ascii-short', 'a\u{1f600}', 4);

// A mix of 1/2/3/4-byte characters at every destination size that straddles
// one of the boundaries. `a` + `é` + `你` + `😀` is 1+2+3+4 = 10 bytes and 5
// UTF-16 code units, so `read` and `written` diverge on every case that stops
// inside it.
encodeIntoCase('mixed-exact', 'a\u00e9\u4f60\u{1f600}', 10);
for (let size = 0; size <= 10; size++) {
  encodeIntoCase(`mixed-${size}`, 'a\u00e9\u4f60\u{1f600}', size);
}

// The same sweep over a long string, which is where a chunked encoder is most
// likely to disagree about where the last whole code point ends.
{
  const long = 'a\u00e9\u4f60\u{1f600}'.repeat(20);
  for (let size = 0; size <= 24; size++) {
    encodeIntoCase(`long-mixed-${size}`, long, size);
  }
  encodeIntoCase('long-mixed-exact', long, 200);
  encodeIntoCase('long-mixed-short-1', long, 199);
  encodeIntoCase('long-mixed-short-2', long, 198);
}

// --- lone surrogates (JavaScript strings are WTF-16) ------------------------

encodeIntoCase('lone-lead-alone', '\ud800', 8);
encodeIntoCase('lone-lead-then-ascii', '\ud800a', 8);
encodeIntoCase('lone-lead-short', '\ud800a', 3);
encodeIntoCase('lone-trail-alone', '\udc00', 8);
encodeIntoCase('lone-trail-then-ascii', '\udc00a', 8);
encodeIntoCase('pair-exact', '\ud83d\ude00', 4);
encodeIntoCase('pair-short-by-1', '\ud83d\ude00', 3);
encodeIntoCase('pair-short-by-2', '\ud83d\ude00', 2);
encodeIntoCase('lead-then-pair', '\ud800\ud83d\ude00', 8);
encodeIntoCase('lead-then-pair-short', '\ud800\ud83d\ude00', 4);

// `node` switches to its simdutf path above 32 code units and repairs
// ill-formed UTF-16 with `to_well_formed_utf16` there, so long strings with
// unpaired surrogates are a different code path from the short ones above and
// have to agree with it.
encodeIntoCase('long-lone-lead', `${'a'.repeat(40)}\ud800`, 64);
encodeIntoCase('long-lone-lead-roomy', `${'a'.repeat(40)}\ud800`, 8);
encodeIntoCase('long-lone-trail', `${'a'.repeat(40)}\udc00`, 64);
encodeIntoCase('long-lone-surrogates-mixed', `${'\ud800a\udc00b'.repeat(12)}`, 128);
encodeIntoCase('long-lone-surrogates-mixed-tight', `${'\ud800a\udc00b'.repeat(12)}`, 41);
encodeIntoCase('long-lone-surrogates-mixed-exact', `${'\ud800a\udc00b'.repeat(12)}`, 72);
encodeIntoCase('long-trailing-lead-truncated', `${'a'.repeat(50)}\ud83d`, 51);
encodeIntoCase('long-pair-at-boundary-roomy', `${'a'.repeat(50)}\ud83d\ude00`, 51);

// --- long strings -----------------------------------------------------------

encodeIntoCase('long-ascii-exact', 'a'.repeat(256), 256);
encodeIntoCase('long-ascii-short-1', 'a'.repeat(256), 255);
encodeIntoCase('long-ascii-short-2', 'a'.repeat(256), 254);
encodeIntoCase('long-latin1-exact', '\u00ff'.repeat(120), 240);
encodeIntoCase('long-latin1-short-1', '\u00ff'.repeat(120), 239);
encodeIntoCase('long-cjk-exact', '\u4f60'.repeat(100), 300);
encodeIntoCase('long-cjk-short-2', '\u4f60'.repeat(100), 298);
encodeIntoCase('long-astral-exact', '\u{1f600}'.repeat(64), 256);
encodeIntoCase('long-astral-short-1', '\u{1f600}'.repeat(64), 255);
encodeIntoCase('long-astral-short-3', '\u{1f600}'.repeat(64), 253);
encodeIntoCase('long-pair-straddle', `${'a'.repeat(60)}\ud83d\ude00`, 63);
encodeIntoCase('long-pair-straddle-exact', `${'a'.repeat(60)}\ud83d\ude00`, 64);
// Long enough to cross the 4096-byte fusion thresholds in both encoders.
encodeIntoCase('very-long-ascii', 'a'.repeat(8192), 8000);
encodeIntoCase('very-long-latin1', '\u00ff'.repeat(4096), 8000);
encodeIntoCase('very-long-latin1-tight', '\u00ff'.repeat(4096), 8189);
encodeIntoCase('very-long-cjk', '\u4f60'.repeat(2730), 8190);

// --- destination shapes -----------------------------------------------------

// A subarray has a non-zero byte offset; the write must land inside the view
// and not at the start of its backing store.
record('subarray-offset', () => {
  const backing = new Uint8Array(12).fill(0xcc);
  const result = encoder.encodeInto('abcd', backing.subarray(4, 8));
  return { read: result.read, written: result.written, bytes: hex(backing) };
});

record('subarray-partial', () => {
  const backing = new Uint8Array(12).fill(0xcc);
  const result = encoder.encodeInto('abcdef', backing.subarray(4, 8));
  return { read: result.read, written: result.written, bytes: hex(backing) };
});

// A detached destination reports zeros and does not throw.
record('detached-dest', () => {
  const buffer = new ArrayBuffer(8);
  const destination = new Uint8Array(buffer);
  buffer.transfer();
  const result = encoder.encodeInto('abc', destination);
  return {
    read: result.read,
    written: result.written,
    length: destination.byteLength,
  };
});

record('detached-dest-empty-source', () => {
  const buffer = new ArrayBuffer(8);
  const destination = new Uint8Array(buffer);
  buffer.transfer();
  const result = encoder.encodeInto('', destination);
  return {
    read: result.read,
    written: result.written,
    length: destination.byteLength,
  };
});

// --- the public API's own validation, which is JavaScript and must not move --

record('public-non-string-source', () => {
  encoder.encodeInto(1234, new Uint8Array(4));
  return { read: -1, written: -1 };
});

record('public-non-uint8-dest', () => {
  encoder.encodeInto('abc', new Uint16Array(4));
  return { read: -1, written: -1 };
});

record('public-null-dest', () => {
  encoder.encodeInto('abc', null);
  return { read: -1, written: -1 };
});

// --- encode() must be untouched ---------------------------------------------

function encodeCase(name, source) {
  record(name, () => ({
    read: encoder.encode(source).length,
    written: hex(encoder.encode(source)),
  }));
}

encodeCase('encode:ascii', 'abc');
encodeCase('encode:latin1', '\u00e9\u00ff');
encodeCase('encode:cjk', '\u4f60\u597d');
encodeCase('encode:astral', '\u{1f600}');
encodeCase('encode:mixed', 'a\u00e9\u4f60\u{1f600}');
encodeCase('encode:empty', '');
encodeCase('encode:lone-lead', '\ud800');
encodeCase('encode:lone-trail', '\udc00');
encodeCase('encode:long-mixed', 'a\u00e9\u4f60\u{1f600}'.repeat(1000));

for (const entry of out) {
  console.log(JSON.stringify(entry));
}
