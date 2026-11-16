'use strict';

// The `readableStreamTo*` family, in JavaScript.
//
// Consuming a `ReadableStream` in Rust would mean driving the reader protocol by
// hand and then keeping the promise chain alive across native frames, which is
// the sort of code that leaks a lock or swallows a rejection. These helpers are
// one `for await` loop each, and the measured behaviour is that simple:
//
//   * consumption is by async iteration, so `stream.locked` is also false right
//     after the call returns and only becomes true once the loop starts;
//   * validation is SYNCHRONOUS, not a rejected promise: the argument check runs
//     before the promise is created, so `try { readableStreamToText({}) }` throws
//     `ERR_INVALID_ARG_TYPE` at the call site;
//   * `readableStreamToArray` preserves chunk boundaries, while `ToBytes`,
//     `ToArrayBuffer` and `ToText` concatenate;
//   * an errored stream rejects with the stream's own error, unchanged.
//
// Everything below is measured against Bun 1.4.4; `tests/data/streams-oracle.json`
// and `tests/streams_parity.rs` hold the recordings.

(function installStreamHelpers() {
  'use strict';

  // The exact message shape Node's `ERR_INVALID_ARG_TYPE` produces, which Bun
  // copies for every one of the seven helpers.
  function invalidStream(value) {
    const type = typeof value;
    let received;
    if (value === undefined) {
      received = 'undefined';
    } else if (value === null) {
      received = 'null';
    } else if (type === 'string') {
      received = "type string ('" + value + "')";
    } else if (type === 'number') {
      received = 'type number (' + value + ')';
    } else if (type === 'boolean') {
      received = 'type boolean (' + value + ')';
    } else if (type === 'symbol') {
      received = 'type symbol';
    } else if (type === 'bigint') {
      received = 'type bigint (' + value + 'n)';
    } else if (type === 'function') {
      received = 'function ' + (value.name || '(anonymous)');
    } else if (value instanceof ArrayBuffer) {
      received = 'an instance of ArrayBuffer';
    } else if (ArrayBuffer.isView(value)) {
      received = 'an instance of ' + (value.constructor && value.constructor.name || 'ArrayBufferView');
    } else if (Array.isArray(value)) {
      received = 'an instance of Array';
    } else {
      const name = value && value.constructor && value.constructor.name;
      received = name ? 'an instance of ' + name : 'an instance of Object';
    }
    const error = new TypeError(
      'The "stream" argument must be of type ReadableStream. Received ' + received
    );
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }

  // A `ReadableStream` is accepted including subclasses; anything else is the
  // synchronous throw above.
  function requireStream(value) {
    if (!(value instanceof ReadableStream)) throw invalidStream(value);
    return value;
  }

  // Collects the chunks as `Uint8Array`s, preserving boundaries.
  async function collectChunks(stream) {
    const chunks = [];
    for await (const chunk of stream) {
      if (typeof chunk === 'string') {
        // A stream may yield strings; they are encoded so every consumer sees
        // bytes, and `readableStreamToArray` still reports one chunk.
        chunks.push(new TextEncoder().encode(chunk));
      } else if (chunk instanceof Uint8Array) {
        chunks.push(chunk);
      } else if (chunk instanceof ArrayBuffer) {
        chunks.push(new Uint8Array(chunk));
      } else if (ArrayBuffer.isView(chunk)) {
        chunks.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
      } else {
        // Any other chunk type is coerced the way a `Blob` part would be.
        chunks.push(new TextEncoder().encode(String(chunk)));
      }
    }
    return chunks;
  }

  function concatLength(chunks) {
    let total = 0;
    for (let i = 0; i < chunks.length; i++) total += chunks[i].length;
    return total;
  }

  function concat(chunks) {
    const out = new Uint8Array(concatLength(chunks));
    let offset = 0;
    for (let i = 0; i < chunks.length; i++) {
      out.set(chunks[i], offset);
      offset += chunks[i].length;
    }
    return out;
  }

  // Every helper validates its argument **before** creating a promise, and is
  // therefore not itself `async`: an `async` function turns a `throw` into a
  // rejected promise, which would make the argument check asynchronous. Bun
  // throws at the call site, and so does this.
  function readableStreamToArray(stream) {
    requireStream(stream);
    return collectChunks(stream);
  }

  function readableStreamToBytes(stream) {
    requireStream(stream);
    return (async () => concat(await collectChunks(stream)))();
  }

  function readableStreamToArrayBuffer(stream) {
    requireStream(stream);
    return (async () => {
      const bytes = concat(await collectChunks(stream));
      // A fresh `ArrayBuffer` rather than the view's own, so the result's
      // `byteLength` is exactly the data and owns nothing extra.
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    })();
  }

  function readableStreamToText(stream) {
    requireStream(stream);
    return (async () => new TextDecoder().decode(concat(await collectChunks(stream))))();
  }

  function readableStreamToBlob(stream) {
    requireStream(stream);
    return (async () => new Blob(await collectChunks(stream)))();
  }

  function readableStreamToJSON(stream) {
    requireStream(stream);
    return (async () => {
      const text = new TextDecoder().decode(concat(await collectChunks(stream)));
      try {
        return JSON.parse(text);
      } catch {
        // Bun's message quotes the whole input rather than the engine's own
        // token, which is what makes it useful on a truncated body.
        throw new SyntaxError('JSON Parse error: Unexpected identifier "' + text + '"');
      }
    })();
  }

  // Multipart only: a non-multipart body fails with `missing final boundary`,
  // and a plain `"x"` body parses as one field named `x` with an empty value.
  function readableStreamToFormData(stream, boundary) {
    requireStream(stream);
    return formDataFrom(stream, boundary);
  }

  async function formDataFrom(stream, boundary) {
    const bytes = concat(await collectChunks(stream));
    if (typeof boundary === 'string' && boundary.length > 0) {
      return parseMultipart(bytes, boundary);
    }
    if (boundary !== undefined && boundary !== null) {
      throw new TypeError('boundary must be a string or ArrayBufferView');
    }
    const text = new TextDecoder().decode(bytes);
    const match = /boundary=(?:"([^"]+)"|([^;\s]+))/.exec(text);
    if (match) {
      return parseMultipart(bytes, match[1] || match[2]);
    }
    // No boundary anywhere: Bun still produces a FormData, treating the body as
    // a single nameless field. `readableStreamToFormData(mk(["x"]))` resolves to
    // a FormData whose only key is `"x"` with an empty value.
    const form = new FormData();
    form.append(text, '');
    return form;
  }

  function parseMultipart(bytes, boundary) {
    const text = new TextDecoder().decode(bytes);
    const delimiter = '--' + boundary;
    if (text.indexOf(delimiter) === -1) {
      throw new Error('missing final boundary while parsing FormData');
    }
    const form = new FormData();
    const parts = text.split(delimiter);
    for (let i = 1; i < parts.length; i++) {
      let part = parts[i];
      if (part.startsWith('--')) break;
      if (part.startsWith('\r\n')) part = part.slice(2);
      else if (part.startsWith('\n')) part = part.slice(1);
      const separator = part.indexOf('\r\n\r\n');
      const loneSeparator = separator === -1 ? part.indexOf('\n\n') : -1;
      const splitAt = separator !== -1 ? separator : loneSeparator;
      if (splitAt === -1) continue;
      const skip = separator !== -1 ? 4 : 2;
      const headers = part.slice(0, splitAt);
      let value = part.slice(splitAt + skip);
      if (value.endsWith('\r\n')) value = value.slice(0, -2);
      else if (value.endsWith('\n')) value = value.slice(0, -1);
      const nameMatch = /name="([^"]*)"/.exec(headers);
      if (!nameMatch) continue;
      form.append(nameMatch[1], value);
    }
    return form;
  }

  return {
    readableStreamToArray,
    readableStreamToArrayBuffer,
    readableStreamToBlob,
    readableStreamToBytes,
    readableStreamToFormData,
    readableStreamToJSON,
    readableStreamToText,
  };
});
