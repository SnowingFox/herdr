// Generates `tests/data/streams-oracle.json`: what Bun 1.4.4 does for the seven
// `readableStreamTo*` helpers and `Bun.ArrayBufferSink`.
//
//     bun tests/record-streams-oracle.js > tests/data/streams-oracle.json
//
// Every case carries either a resolved value or the *shape* of the rejection, so
// a test can compare failure modes and not only successes. The cases that
// matter are the ones a plausible implementation gets wrong: per-chunk
// boundaries in `ToArray`, the stream error passing through unchanged, an
// already-consumed stream, and validation that throws synchronously rather than
// rejecting.

'use strict';

const B = globalThis.Bun;

function streamOf(chunks) {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk);
      }
      controller.close();
    },
  });
}

function errored() {
  return new ReadableStream({
    start(controller) {
      controller.error(new Error('boom'));
    },
  });
}

function describe(value) {
  if (typeof value === 'string') return { kind: 'string', value };
  if (value instanceof Uint8Array) {
    return { kind: 'bytes', ctor: value.constructor.name, hex: hex(value) };
  }
  if (value instanceof ArrayBuffer) {
    return { kind: 'arraybuffer', ctor: value.constructor.name, hex: hex(new Uint8Array(value)) };
  }
  if (Array.isArray(value)) {
    return {
      kind: 'array',
      chunks: value.map((chunk) => ({
        ctor: chunk.constructor.name,
        hex: hex(chunk),
      })),
    };
  }
  if (typeof Blob !== 'undefined' && value instanceof Blob) {
    return {
      kind: 'blob',
      ctor: value.constructor.name,
      size: value.size,
      type: value.type,
      isBlob: value instanceof Blob,
    };
  }
  if (typeof FormData !== 'undefined' && value instanceof FormData) {
    return {
      kind: 'formdata',
      ctor: value.constructor.name,
      entries: [...value.entries()].map(([key, entry]) => [key, typeof entry === 'string' ? entry : '<file>']),
    };
  }
  return { kind: 'json', value };
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function failure(error) {
  return {
    threw: true,
    ctor: error.constructor.name,
    // `undefined` is recorded as null so the JSON stays valid.
    code: error.code === undefined ? null : error.code,
    message: error.message,
  };
}

const out = { streams: [], sink: [], validations: [], errors: [] };

const cases = [
  ['readableStreamToText', ['he', 'llo']],
  ['readableStreamToText', []],
  ['readableStreamToBytes', ['ab', 'cd']],
  ['readableStreamToBytes', []],
  ['readableStreamToArrayBuffer', ['ab', 'cd']],
  ['readableStreamToArray', ['ab', 'cd']],
  ['readableStreamToArray', []],
  ['readableStreamToBlob', ['ab', 'cd']],
  ['readableStreamToJSON', ['{"a":', '1}']],
];

async function main() {
  for (const [member, chunks] of cases) {
    try {
      const value = await B[member](streamOf(chunks));
      out.streams.push([member, chunks, { ok: true, value: describe(value) }]);
    } catch (error) {
      out.streams.push([member, chunks, failure(error)]);
    }
  }

  // `readableStreamToJSON` on invalid JSON, whose message is Bun's own rather
  // than the engine's.
  try {
    await B.readableStreamToJSON(streamOf(['notjson']));
    out.streams.push(['readableStreamToJSON', ['notjson'], { ok: true }]);
  } catch (error) {
    out.streams.push(['readableStreamToJSON', ['notjson'], failure(error)]);
  }

  // An errored stream rejects with the stream's own error, unchanged.
  for (const member of [
    'readableStreamToText',
    'readableStreamToBytes',
    'readableStreamToArray',
    'readableStreamToArrayBuffer',
    'readableStreamToBlob',
    'readableStreamToFormData',
    'readableStreamToJSON',
  ]) {
    try {
      await B[member](errored());
      out.errors.push([member, { ok: true }]);
    } catch (error) {
      out.errors.push([member, failure(error)]);
    }
  }

  // An already-consumed stream.
  {
    const stream = streamOf(['x']);
    const first = await B.readableStreamToText(stream);
    try {
      await B.readableStreamToText(stream);
      out.streams.push(['readableStreamToText', 'consumed-twice', { ok: true, first }]);
    } catch (error) {
      out.streams.push(['readableStreamToText', 'consumed-twice', failure(error)]);
    }
  }

  // Validation throws synchronously, so it is caught without `await`.
  for (const member of [
    'readableStreamToText',
    'readableStreamToArray',
    'readableStreamToArrayBuffer',
    'readableStreamToBlob',
    'readableStreamToBytes',
    'readableStreamToFormData',
    'readableStreamToJSON',
  ]) {
    for (const [tag, argument] of [
      ['undefined', undefined],
      ['string', 'notastream'],
      ['uint8array', new Uint8Array(1)],
      ['array', [1, 2]],
      ['object', {}],
    ]) {
      try {
        B[member](argument);
        out.validations.push([member, tag, { ok: true }]);
      } catch (error) {
        out.validations.push([member, tag, failure(error)]);
      }
    }
  }

  // FormData: multipart with an explicit boundary, and a plain body.
  try {
    const boundary = '----x';
    const body =
      '--' + boundary + '\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--' + boundary + '--\r\n';
    const form = await B.readableStreamToFormData(streamOf([body]), boundary);
    out.streams.push(['readableStreamToFormData', 'multipart', { ok: true, value: describe(form) }]);
  } catch (error) {
    out.streams.push(['readableStreamToFormData', 'multipart', failure(error)]);
  }
  try {
    const form = await B.readableStreamToFormData(streamOf(['x']));
    out.streams.push(['readableStreamToFormData', 'plain', { ok: true, value: describe(form) }]);
  } catch (error) {
    out.streams.push(['readableStreamToFormData', 'plain', failure(error)]);
  }

  await recordSink();
  process.stdout.write(JSON.stringify(out, null, 1) + '\n');
}

// `Bun.ArrayBufferSink`, whose shape is the point: the constructor has no
// `prototype` property while its instances carry nine methods.
async function recordSink() {
  const Sink = B.ArrayBufferSink;
  out.sinkShape = {
    typeof: typeof Sink,
    length: Sink.length,
    name: Sink.name,
    prototypeType: typeof Sink.prototype,
  };

  const instance = new Sink();
  out.sinkShape.methods = Object.getOwnPropertyNames(Object.getPrototypeOf(instance)).sort();
  out.sinkShape.ownProps = Object.getOwnPropertyNames(instance);
  out.sinkShape.constructorMatches = Object.getPrototypeOf(instance).constructor === Sink;
  out.sinkShape.sinkId = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(instance),
    'sinkId'
  ).value;

  // The behaviours that are easy to get wrong.
  const s1 = new Sink();
  const writes = [s1.write('he'), s1.write('llo')];
  const ended = s1.end();
  out.sink.push(['write-returns-per-call', writes]);
  out.sink.push(['end', { ctor: ended.constructor.name, hex: hex(new Uint8Array(ended)) }]);

  const s2 = new Sink();
  s2.write('hello');
  const withDest = s2.end(new Uint8Array(10));
  out.sink.push(['end-ignores-dest', { ctor: withDest.constructor.name, byteLength: withDest.byteLength }]);

  const s3 = new Sink();
  s3.write('x');
  const first = s3.end();
  const second = s3.end();
  out.sink.push(['end-twice', [first.byteLength, second.byteLength]]);

  const s4 = new Sink({ stream: true });
  s4.write('ab');
  s4.write('cd');
  const streamed = s4.end();
  out.sink.push(['stream-end', { ctor: streamed.constructor.name, hex: hex(new Uint8Array(streamed)) }]);

  const s5 = new Sink();
  out.sink.push(['write-uint8array', s5.write(new Uint8Array([1, 2, 3]))]);
  out.sink.push(['write-empty-string', s5.write('')]);

  const s6 = new Sink();
  s6.write('ab');
  out.sink.push(['flush', s6.flush()]);

  const s7 = new Sink({ stream: true });
  s7.write('ab');
  out.sink.push(['flush-stream', s7.flush()]);

  try {
    new Sink().write(42);
    out.sink.push(['write-number', { ok: true }]);
  } catch (error) {
    out.sink.push(['write-number', failure(error)]);
  }

  const s8 = new Sink();
  out.sink.push(['end-empty', s8.end().byteLength]);
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack) + '\n');
  process.exit(1);
});
