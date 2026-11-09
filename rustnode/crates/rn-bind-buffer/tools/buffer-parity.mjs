#!/usr/bin/env node
// Records the expected values for the buffer binding's Node-parity table.
//
// Every case is expressed against the *public* Buffer API, because that is the
// behaviour the binding exists to serve. The one function with no public
// equivalent is `byteLengthUtf8Fast`, whose contract is
// `byteLengthUtf8`-or-`-1`; both are checked directly against
// `byteLengthUtf8`.
//
// Run with: node tools/buffer-parity.mjs > crates/rn-bind-buffer/tests/parity.json
// (the JSON is committed; this script exists so it can be regenerated and
// reviewed).

const cases = [];

function record(name, value) {
  cases.push({ name, value });
}

function hex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

function attempt(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error: `${error.code || error.name}: ${error.message}` };
  }
}

// --- slice encodings --------------------------------------------------------

const sample = Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xff, 0x41, 0x42, 0x43]);
for (const encoding of ['ascii', 'latin1', 'utf8', 'hex', 'base64', 'base64url']) {
  record(`slice:${encoding}`, JSON.stringify(sample.toString(encoding)));
}
record('slice:ucs2', JSON.stringify(sample.toString('ucs2')));
record('slice:utf8:empty', JSON.stringify(Buffer.alloc(0).toString('utf8')));
record('slice:utf8:window', JSON.stringify(sample.toString('utf8', 5, 8)));
record('slice:hex:window', sample.toString('hex', 1, 3));

// Multi-byte UTF-8 split across the slice boundary. `toString` on a subarray is
// exactly "decode these bytes", so this is the split behaviour the binding
// must reproduce.
record('split:utf8:2of4', JSON.stringify(Buffer.from([0xf0, 0x9f, 0x98, 0x80]).subarray(0, 2).toString('utf8')));
record('split:utf8:3of4', JSON.stringify(Buffer.from([0xf0, 0x9f, 0x98, 0x80]).subarray(0, 3).toString('utf8')));
record('split:utf8:1of2', JSON.stringify(Buffer.from([0xc3, 0xa9]).subarray(0, 1).toString('utf8')));
record('split:utf8:complete', JSON.stringify(Buffer.from([0xc3, 0xa9]).toString('utf8')));
record('split:utf8:overlong', JSON.stringify(Buffer.from([0xc0, 0x80]).toString('utf8')));
record('split:utf8:surrogate', JSON.stringify(Buffer.from([0xed, 0xa0, 0x80]).toString('utf8')));
record('split:utf8:lone-continuation', JSON.stringify(Buffer.from([0x80]).toString('utf8')));
record('split:utf8:truncated-3', JSON.stringify(Buffer.from([0xe2, 0x82]).toString('utf8')));
record('split:utf8:valid-then-garbage', JSON.stringify(Buffer.from([0x41, 0xff, 0x42]).toString('utf8')));

// --- base64url padding ------------------------------------------------------

for (const length of [0, 1, 2, 3, 4, 5, 6, 7]) {
  const input = Buffer.alloc(length, 0xff);
  record(`padding:base64:${length}`, input.toString('base64'));
  record(`padding:base64url:${length}`, input.toString('base64url'));
}

// --- writes -----------------------------------------------------------------

function writeCase(name, encoding, text, size = 16, offset = 0, length) {
  const buffer = Buffer.alloc(size, 0xcc);
  const written = length === undefined
    ? buffer.write(text, offset, encoding)
    : buffer.write(text, offset, length, encoding);
  record(`write:${encoding}:${name}`, `${written}:${hex(buffer)}`);
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

// --- fill -------------------------------------------------------------------

function fillCase(name, value, size = 9, encoding) {
  const buffer = Buffer.alloc(size, 0xcc);
  const result = attempt(() => {
    buffer.fill(value, 0, size, encoding);
    return hex(buffer);
  });
  record(`fill:${name}`, JSON.stringify(result));
}

fillCase('repeat-ascii', 'ab');
fillCase('single-byte', 'z');
fillCase('multibyte-utf8', 'é');
fillCase('emoji-utf8', '😀');
fillCase('ucs2', 'ab', 9, 'ucs2');
fillCase('hex', 'abcd', 9, 'hex');
fillCase('hex-odd', 'abc', 9, 'hex');
fillCase('base64', 'aGVsbG8=', 9, 'base64');
fillCase('empty-string', '');
fillCase('number', 0x1234);
fillCase('number-large', 0x123456);
fillCase('buffer', Buffer.from([1, 2, 3]));
fillCase('buffer-longer', Buffer.from([1, 2, 3]), 2);
fillCase('odd-size-multibyte', 'é', 3);
fillCase('odd-size-emoji', '😀', 3);

// --- compare ----------------------------------------------------------------

record('compare:equal', String(Buffer.compare(Buffer.from('abc'), Buffer.from('abc'))));
record('compare:prefix', String(Buffer.compare(Buffer.from('abc'), Buffer.from('abcd'))));
record('compare:prefix-reversed', String(Buffer.compare(Buffer.from('abcd'), Buffer.from('abc'))));
record('compare:less', String(Buffer.compare(Buffer.from('abc'), Buffer.from('abd'))));
record('compare:greater', String(Buffer.compare(Buffer.from('abd'), Buffer.from('abc'))));
record('compare:empty-both', String(Buffer.compare(Buffer.alloc(0), Buffer.alloc(0))));
record('compare:empty-vs-one', String(Buffer.compare(Buffer.alloc(0), Buffer.from([0]))));
record('compare:bytes', String(Buffer.compare(Buffer.from([0x00, 0xff]), Buffer.from([0x00, 0xfe]))));

// --- compare sub-ranges -----------------------------------------------------

record(
  'compare-range:equal',
  String(Buffer.from('abcdef').compare(Buffer.from('xxcdyy'), 2, 4, 2, 4)),
);
record(
  'compare-range:less',
  String(Buffer.from('abcdef').compare(Buffer.from('xxceyy'), 2, 4, 2, 4)),
);
record(
  'compare-range:empty-source',
  String(Buffer.from('abcdef').compare(Buffer.from('xxxxxx'), 0, 0, 2, 4)),
);

// --- indexOf ----------------------------------------------------------------

const haystack = Buffer.from('hello world hello');
record('index:number', String(haystack.indexOf(0x6f))); // 'o'
record('index:number-offset', String(haystack.indexOf(0x6f, 5)));
record('index:number-missing', String(haystack.indexOf(0x00)));
record('index:string', String(haystack.indexOf('world')));
record('index:string-offset', String(haystack.indexOf('hello', 1)));
record('index:string-empty', String(haystack.indexOf('')));
record('index:string-empty-offset', String(haystack.indexOf('', 4)));
record('index:buffer', String(haystack.indexOf(Buffer.from('world'))));
record('index:buffer-missing', String(haystack.indexOf(Buffer.from('zzz'))));
record('index:negative-offset', String(haystack.indexOf('hello', -5)));
record('index:negative-offset-far', String(haystack.indexOf('hello', -1000)));
record('index:last:number', String(haystack.lastIndexOf(0x6f)));
record('index:last:number-offset', String(haystack.lastIndexOf(0x6f, 5)));
record('index:last:string', String(haystack.lastIndexOf('hello')));
record('index:last:string-offset', String(haystack.lastIndexOf('hello', 5)));
record('index:last:buffer', String(haystack.lastIndexOf(Buffer.from('hello'))));
record('index:last:empty', String(haystack.lastIndexOf('')));
record('index:last:negative-offset', String(haystack.lastIndexOf('hello', -1)));
record('index:ucs2', String(Buffer.from('a\u0000b\u0000a\u0000', 'latin1').indexOf('a', 0, 'ucs2')));
record('index:end-limit', String(haystack.indexOf('hello', 0, 'utf8')));
record('index:missing-in-window', String(haystack.indexOf('hello', 1, 'utf8')));
record('index:latin1', String(Buffer.from('héllo', 'latin1').indexOf('é', 0, 'latin1')));

// --- swaps ------------------------------------------------------------------

function swapCase(name, encoding, bytes) {
  const buffer = Buffer.from(bytes);
  const result = attempt(() => {
    buffer.swap16();
    return hex(buffer);
  });
  const result32 = attempt(() => {
    const copy = Buffer.from(bytes);
    copy.swap32();
    return hex(copy);
  });
  const result64 = attempt(() => {
    const copy = Buffer.from(bytes);
    copy.swap64();
    return hex(copy);
  });
  record(`swap16:${name}`, JSON.stringify(result));
  record(`swap32:${name}`, JSON.stringify(result32));
  record(`swap64:${name}`, JSON.stringify(result64));
  void encoding;
}

swapCase('4-bytes', null, [1, 2, 3, 4]);
swapCase('8-bytes', null, [1, 2, 3, 4, 5, 6, 7, 8]);
swapCase('16-bytes', null, Array.from({ length: 16 }, (_, index) => index));
swapCase('3-bytes', null, [1, 2, 3]);
swapCase('7-bytes', null, [1, 2, 3, 4, 5, 6, 7]);
swapCase('12-bytes', null, Array.from({ length: 12 }, (_, index) => 0xf0 + index));

// --- byte length ------------------------------------------------------------

for (const text of ['', 'a', 'hello', 'é', '😀', '\uD800', '\uDC00', 'a\uD800b']) {
  record(`byteLength:${JSON.stringify(text)}`, String(Buffer.byteLength(text, 'utf8')));
}

// --- string length ----------------------------------------------------------

for (const bytes of [[], [0x41], [0xc3, 0xa9], [0xf0, 0x9f, 0x98, 0x80], [0x80], [0xff, 0x41]]) {
  const label = bytes.length === 0
    ? 'empty'
    : bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  record(`stringLength:${label}`, String(Buffer.from(bytes).toString('utf8').length));
}

// --- isUtf8 / isAscii -------------------------------------------------------

const validUtf8 = [
  [],
  [0x41, 0x42],
  [0xc3, 0xa9],
  [0xf0, 0x9f, 0x98, 0x80],
  [0x7f],
];
const invalidUtf8 = [
  [0x80],
  [0xc0, 0x80],       // overlong
  [0xc1, 0xbf],       // overlong
  [0xe0, 0x80, 0x80], // overlong
  [0xed, 0xa0, 0x80], // surrogate
  [0xed, 0xbf, 0xbf], // surrogate
  [0xf0, 0x80, 0x80, 0x80], // overlong
  [0xf4, 0x90, 0x80, 0x80], // above U+10FFFF
  [0xf0, 0x9f, 0x98],       // truncated
  [0xc3],                    // truncated
  [0xfe],
  [0xff],
];
// Node 22 has no `Buffer.isUtf8`, so the oracle is a fatal TextDecoder, which
// validates with the same rules (WHATWG UTF-8 decode rejects overlong forms,
// surrogates and truncated sequences). `isAscii` is the documented
// "every byte < 0x80" and `isLatin1` the documented "every code unit <= 0xFF".
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });
for (const bytes of [...validUtf8, ...invalidUtf8]) {
  const label = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  const buffer = Buffer.from(bytes);
  let utf8;
  try {
    strictUtf8.decode(buffer);
    utf8 = true;
  } catch {
    utf8 = false;
  }
  record(`isUtf8:${label || 'empty'}`, String(utf8));
  record(`isAscii:${label || 'empty'}`, String(bytes.every((b) => b < 0x80)));
}

// --- isLatin1 ---------------------------------------------------------------

for (const text of ['', 'abc', 'é', '\u0100', '😀']) {
  record(
    `isLatin1:${JSON.stringify(text)}`,
    String(
      Array.from(text).every((character) => character.codePointAt(0) <= 0xff)
        && Array.from({ length: text.length }, (_, index) => text.charCodeAt(index))
          .every((unit) => unit <= 0xff),
    ),
  );
}

// --- atob / btoa ------------------------------------------------------------

for (const text of ['', 'aGVsbG8=', 'aGVsbG8', 'aGVs bG8=', '/w==', 'YQ', 'Y', '====', 'aGVsbG8=a', 'a-_h']) {
  record(`atob:${JSON.stringify(text)}`, JSON.stringify(attempt(() => atob(text))));
}
for (const text of ['', 'hello', 'é', '\u0100', '😀']) {
  record(`btoa:${JSON.stringify(text)}`, JSON.stringify(attempt(() => btoa(text))));
}

// --- mask (RFC 6455, section 5.3) -------------------------------------------

function maskReference(source, mask) {
  const output = Buffer.alloc(source.length);
  for (let index = 0; index < source.length; index += 1) {
    output[index] = source[index] ^ mask[index % 4];
  }
  return output;
}

for (const [label, payload, mask] of [
  ['empty', [], [0x37, 0xfa, 0x21, 0x3d]],
  ['one', [0x48], [0x37, 0xfa, 0x21, 0x3d]],
  ['hello', [0x48, 0x65, 0x6c, 0x6c, 0x6f], [0x37, 0xfa, 0x21, 0x3d]],
  ['long', Array.from({ length: 37 }, (_, index) => index), [0xde, 0xad, 0xbe, 0xef]],
]) {
  record(`mask:${label}`, maskReference(Buffer.from(payload), mask).toString('hex'));
}

// --- arrayBufferAlignedOffset ----------------------------------------------

// Not exposed on the public API, so only its contract is recorded: the offset
// must bring the data pointer up to a multiple of the alignment.
record('alignedOffset:contract', 'offset is a multiple of alignment such that data + offset is aligned');

process.stdout.write(`${JSON.stringify(Object.fromEntries(cases.map((c) => [c.name, c.value])), null, 2)}\n`);
