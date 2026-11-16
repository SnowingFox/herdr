'use strict';
// Differential probe for `toASCII` / `toUnicode` and the two `url` members that
// are the only consumers of the same conversion.
//
// One line per case: the label, then `url.domainToASCII`, `url.domainToUnicode`,
// `encoding_binding.toASCII` and `encoding_binding.toUnicode`. Four columns
// because the two surfaces are different functions in Node — `url`'s pair goes
// through `set_hostname` on a `ws://x` seed and truncates at a delimiter, the
// binding's pair is a bare `ada::idna` call — and a fix that made one match by
// breaking the other would be invisible with two columns.
//
// Deterministic: no timings, no ids. Runs on `node`, on the built `rustnode`,
// and inside the in-process isolate in `tests/idna.rs` when the binding is
// installed directly. `--expose-internals` is required for the binding columns
// only, so the caller supplies it; the isolate run skips the binding half
// instead, which is why `hasBinding` is probed rather than assumed.

const url = require('url');

let binding = null;
try {
  binding = require('internal/test/binding').internalBinding('encoding_binding');
} catch {
  binding = null;
}

function quote(value) {
  let out = '"';
  for (const character of value) {
    const point = character.codePointAt(0);
    if (character === '"') out += '\\"';
    else if (character === '\\') out += '\\\\';
    else if (point < 0x20 || point > 0x7e) out += '\\u' + point.toString(16).padStart(4, '0');
    else out += character;
  }
  return out + '"';
}

function call(fn, input) {
  if (fn === null) return 'MISSING';
  try {
    return quote(fn(input));
  } catch (error) {
    return 'THROW:' + (error.code || error.name);
  }
}

const repeat = (text, count) => text.repeat(count);

const cases = [
  ['zero-width-space', 'a\u200Bb.com'],
  ['zero-width-joiner', 'a\u200Db.com'],
  ['soft-hyphen', 'a\u00ADb.com'],
  ['ideographic-full-stop', 'a\u3002b'],
  ['fullwidth-full-stop', 'a\uFF0Eb'],
  ['halfwidth-ideographic-stop', 'a\uFF61b'],
  ['all-separators-mixed', 'a\u3002b\uFF0Ec\uFF61d'],
  ['halfwidth-katakana', '\uFF71\uFF72\uFF73.example'],
  ['halfwidth-katakana-single', '\uFF71.example'],
  ['uppercase-ascii', 'EXAMPLE.COM'],
  ['uppercase-mixed', 'ExAmPlE.CoM'],
  ['label-63-bytes', repeat('a', 63) + '.com'],
  ['label-64-bytes', repeat('a', 64) + '.com'],
  ['label-128-bytes', repeat('a', 128) + '.com'],
  ['total-255-bytes', repeat('a', 63) + '.' + repeat('b', 63) + '.' + repeat('c', 63) + '.' + repeat('d', 61)],
  ['total-256-bytes', repeat('a', 63) + '.' + repeat('b', 63) + '.' + repeat('c', 63) + '.' + repeat('d', 62)],
  ['total-4-labels', repeat('a', 63) + '.' + repeat('b', 63) + '.' + repeat('c', 63) + '.' + repeat('d', 63)],
  ['already-punycode', 'xn--mnchen-3ya.de'],
  ['already-punycode-upper', 'XN--MNCHEN-3YA.de'],
  ['already-punycode-invalid', 'xn--a'],
  ['already-punycode-invalid-zz', 'xn--zz'],
  ['already-punycode-bare', 'xn--'],
  ['empty-label-middle', 'a..b'],
  ['empty-label-leading', '.a'],
  ['empty-label-trailing', 'a.'],
  ['trailing-dot', 'example.com.'],
  ['trailing-two-dots', 'a..'],
  ['only-dots', '...'],
  ['empty', ''],
  ['lone-surrogate', 'a\uD800b.com'],
  ['lone-low-surrogate', 'a\uDC00b.com'],
  ['umlaut-mixed-case', 'M\u00FCnchen.DE'],
  ['umlaut-mixed-label', 'a.M\u00FCnchenB'],
  ['umlaut-lower', 'm\u00FCnchen.de'],
  ['sharp-s-upper', '\u1E9E.com'],
  ['fullwidth-ascii', '\uFF21\uFF22\uFF23.com'],
  ['combining-mark', 'e\u0301.com'],
  ['nfc', '\u00E9.com'],
  ['cjk', '\u4F8B\u3048.\u30C6\u30B9\u30C8'],
  ['path-delimiter', 'a/b'],
  ['port-suffix', 'example.com:80'],
  ['ipv6-literal', '[::1]'],
  ['ipv4-shorthand', '0x7f.1'],
  ['percent-escape', '%41.com'],
  ['space-in-label', 'a b.com'],
];

for (const [name, input] of cases) {
  console.log([
    name.padEnd(28),
    call(url.domainToASCII, input),
    call(url.domainToUnicode, input),
    call(binding && binding.toASCII, input),
    call(binding && binding.toUnicode, input),
  ].join(' '));
}
