'use strict';
// Differential probe for `decodeUTF8` and the `Blob` text path.
//
// One line per case, so two runtimes can be diffed byte for byte. Every line is
// deterministic: no timings, no object ids, no addresses. The same file runs on
// `node`, on the built `rustnode`, and (for the binding cases) inside the
// in-process isolate in `tests/decoder.rs`.
//
// `decodeUTF8` is `internalBinding('encoding_binding').decodeUTF8(list,
// ignoreBom, fatal)` and is reached here only through `TextDecoder`, `Blob` and
// `Response`, because that is the surface the reference has too.

const { Blob } = require('buffer');

const out = [];
const TIMEOUT = Symbol('timeout');

function describe(error) {
  if (!(error instanceof Error)) return `nonerror=${typeof error}`;
  return (
    `name=${error.name} code=${String(error.code)}` +
    ` isTypeError=${error instanceof TypeError}` +
    ` msg=${JSON.stringify(error.message)}`
  );
}

function sync(label, fn) {
  try {
    out.push(`${label}: OK ${JSON.stringify(fn())}`);
  } catch (error) {
    out.push(`${label}: THROW ${describe(error)}`);
  }
}

// One at a time, in source order, so the output cannot depend on scheduling.
// The timeout exists only so a hung read reports `TIMEOUT` instead of making
// the whole file hang: it is not a latency budget.
async function async_(label, fn) {
  try {
    const value = await Promise.race([
      Promise.resolve().then(fn),
      new Promise((resolve) => setTimeout(() => resolve(TIMEOUT), 1000)),
    ]);
    out.push(
      value === TIMEOUT
        ? `${label}: TIMEOUT`
        : `${label}: OK ${JSON.stringify(value)}`,
    );
  } catch (error) {
    out.push(`${label}: THROW ${describe(error)}`);
  }
}

const BOM = [0xef, 0xbb, 0xbf];
const A = 0x41;
const BAD = 0xff;

async function main() {
  // --- ignoreBom --------------------------------------------------------
  sync('bom/default', () => new TextDecoder().decode(Buffer.from([...BOM, A])));
  sync('bom/ignoreBOM-true', () =>
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(Buffer.from([...BOM, A])));
  sync('bom/ignoreBOM-false', () =>
    new TextDecoder('utf-8', { ignoreBOM: false }).decode(Buffer.from([...BOM, A])));
  sync('bom/only', () => new TextDecoder().decode(Buffer.from(BOM)));
  sync('bom/only-ignore', () =>
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(Buffer.from(BOM)));
  sync('bom/fatal-valid', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from([...BOM, A])));
  sync('bom/fatal-invalid', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from([...BOM, BAD])));
  sync('bom/ignoreBOM-bad-bytes', () =>
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(Buffer.from([BAD])));
  sync('bom/both-flags-bad', () =>
    new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }).decode(Buffer.from([BAD])));

  // --- fatal ------------------------------------------------------------
  sync('fatal/default-bad', () => new TextDecoder().decode(Buffer.from([BAD])));
  sync('fatal/true-bad', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from([BAD])));
  sync('fatal/false-bad', () =>
    new TextDecoder('utf-8', { fatal: false }).decode(Buffer.from([BAD])));
  sync('fatal/true-ascii', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from('hello', 'latin1')));
  sync('fatal/true-valid-multibyte', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from('\u00e9\u20ac\ud83d\ude00')));
  sync('fatal/true-truncated', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from([0xe2, 0x82])));
  sync('fatal/true-surrogate-bytes', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from([0xed, 0xa0, 0x80])));
  sync('fatal/true-overlong', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from([0xc0, 0xaf])));
  sync('fatal/true-empty', () =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.alloc(0)));

  // The replacement count for every malformed 2-byte and 3-byte prefix. A
  // lossy decoder that replaces a differently-sized span shows up here even
  // when each individual case "looks right".
  sync('lossy/sweep-2byte', () => {
    const lengths = [];
    for (let a = 0x80; a <= 0xf4; a++) {
      for (let b = 0x00; b <= 0xff; b++) {
        lengths.push(new TextDecoder().decode(Uint8Array.of(a, b)).length);
      }
    }
    return lengths.join(',');
  });
  sync('lossy/sweep-3byte', () => {
    let hash = 0;
    for (let a = 0x80; a <= 0xff; a++) {
      for (let b = 0x00; b <= 0xff; b += 17) {
        for (let c = 0x00; c <= 0xff; c += 31) {
          const text = new TextDecoder().decode(Uint8Array.of(a, b, c));
          for (let i = 0; i < text.length; i++) {
            hash = (hash * 31 + text.charCodeAt(i)) >>> 0;
          }
          hash = (hash * 31 + text.length) >>> 0;
        }
      }
    }
    return hash;
  });
  sync('lossy/exact-codepoints', () =>
    [
      [0xe0, 0x80],
      [0xed, 0xa0, 0x80],
      [0xf0, 0x80, 0x80],
      [0xf4, 0x90, 0x80, 0x80],
      [0xc0, 0xaf],
      [0xe2, 0x82],
      [0xf0, 0x9f, 0x98],
    ].map((bytes) =>
      Array.from(new TextDecoder().decode(Uint8Array.from(bytes)))
        .map((ch) => ch.codePointAt(0).toString(16))
        .join('+'),
    ));

  // --- input shapes -----------------------------------------------------
  sync('input/plain-arraybuffer', () => {
    const buffer = new ArrayBuffer(2);
    new Uint8Array(buffer).set([0x61, 0x62]);
    return new TextDecoder().decode(buffer);
  });
  sync('input/typedarray-u8', () => new TextDecoder().decode(new Uint8Array([0x61, 0x62])));
  sync('input/typedarray-u8-offset', () => {
    const whole = new Uint8Array([0xef, 0xbb, 0xbf, 0x62, 0x63]);
    return new TextDecoder().decode(whole.subarray(3));
  });
  sync('input/typedarray-u16', () => new TextDecoder().decode(new Uint16Array([0x6261])));
  sync('input/dataview', () =>
    new TextDecoder().decode(new DataView(new Uint8Array([0x61, 0x62, 0x63]).buffer, 1)));
  sync('input/dataview-empty', () =>
    new TextDecoder().decode(new DataView(new ArrayBuffer(4), 2, 0)));
  sync('input/arraybuffer-empty', () => new TextDecoder().decode(new ArrayBuffer(0)));
  sync('input/buffer-subarray', () =>
    new TextDecoder().decode(Buffer.from([0x00, 0x61, 0x62]).subarray(1)));
  sync('input/string', () => new TextDecoder().decode('abc'));
  sync('input/number', () => new TextDecoder().decode(5));
  sync('input/undefined', () => new TextDecoder().decode(undefined));
  sync('input/detached-arraybuffer', () => {
    const buffer = new ArrayBuffer(4);
    new Uint8Array(buffer).set([0x61, 0x62, 0x63, 0x64]);
    structuredClone(buffer, { transfer: [buffer] });
    return new TextDecoder().decode(buffer);
  });
  sync('input/detached-view', () => {
    const view = new Uint8Array([0x61, 0x62, 0x63, 0x64]);
    structuredClone(view.buffer, { transfer: [view.buffer] });
    return new TextDecoder().decode(view);
  });

  // --- streaming BOM state, which lives in JavaScript -------------------
  sync('stream/two-chunks-both-bom', () => {
    const decoder = new TextDecoder();
    const first = decoder.decode(Buffer.from([...BOM, 0x41]), { stream: true });
    const second = decoder.decode(Buffer.from([...BOM, 0x42]), { stream: true });
    return [first, second, decoder.decode()];
  });
  sync('stream/split-bom', () => {
    const decoder = new TextDecoder();
    const first = decoder.decode(Buffer.from([0xef, 0xbb]), { stream: true });
    const second = decoder.decode(Buffer.from([0xbf, 0x41]), { stream: true });
    return [first, second, decoder.decode()];
  });
  sync('stream/reuse-after-end', () => {
    const decoder = new TextDecoder();
    return [
      decoder.decode(Buffer.from([...BOM, 0x41])),
      decoder.decode(Buffer.from([...BOM, 0x42])),
    ];
  });

  // --- Blob, whose `text()` decodes an ArrayBuffer ----------------------
  await async_('blob/text', () => new Blob(['hi']).text());
  await async_('blob/text-utf8', () => new Blob(['h\u00e9\u20ac\ud83d\ude00']).text());
  await async_('blob/text-1-byte', () => new Blob(['x']).text());
  await async_('blob/text-2-bytes', () => new Blob(['xy']).text());
  await async_('blob/text-3-bytes', () => new Blob(['xyz']).text());
  await async_('blob/arrayBuffer', async () =>
    Buffer.from(await new Blob(['hi']).arrayBuffer()).toString('hex'));
  await async_('blob/bytes', async () =>
    Array.from(await new Blob(['hi']).bytes()).join(','));
  await async_('blob/text-bom', () => new Blob([new Uint8Array([...BOM, 0x41])]).text());
  await async_('blob/text-roundtrip', async () => {
    const blob = new Blob(['snowman \u2603']);
    const again = new Blob([await blob.arrayBuffer()]);
    return [await blob.text(), await again.text()];
  });
  await async_('blob/stream', async () => {
    const reader = new Blob(['\u00e9x']).stream().getReader();
    const decoder = new TextDecoder();
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  });

  // --- Response over a Blob body, which is the other broken consumer ----
  await async_('response/blob-text', () => new Response(new Blob(['hi'])).text());
  await async_('response/blob-text-2-bytes', () => new Response(new Blob(['ab'])).text());
  await async_('response/blob-text-multibyte', () =>
    new Response(new Blob(['\u00e9\u20ac\ud83d\ude00'])).text());
  await async_('response/blob-arrayBuffer', async () =>
    Buffer.from(await new Response(new Blob(['hi'])).arrayBuffer()).toString('hex'));
  await async_('response/blob-bytes', async () =>
    Array.from(await new Response(new Blob(['hi'])).bytes()).join(','));
  await async_('response/string-text', () => new Response('hi').text());
  await async_('response/u8-body-text', () =>
    new Response(new Uint8Array([0x68, 0x69])).text());

  for (const line of out) console.log(line);
}

main();
