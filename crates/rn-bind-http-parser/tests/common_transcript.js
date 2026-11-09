// The transcript shared by the Rust and Node sides of `node_parity.rs`.
//
// It is one file rather than two strings so the two sides cannot drift: if the
// comparison is going to mean anything, both have to run the same script.
//
// The parser reports header names and values as one-byte strings and the body as
// a Buffer; both sides normalise to a latin1 string, so the transcript is
// comparable without transporting bytes.

function toText(value) {
  if (typeof value === 'string') return value;
  if (value === undefined) return '<undefined>';
  if (value === null) return '<null>';
  let out = '';
  for (const byte of value) out += String.fromCharCode(byte);
  return out;
}

// A latin1 byte view of a string. `Buffer` is not available in a bare V8
// isolate, and the inputs are ASCII, so a manual copy keeps both sides
// identical rather than relying on an engine global one of them lacks.
function toBytes(text) {
  const out = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) {
    out[index] = text.charCodeAt(index) & 0xff;
  }
  return out;
}

function runCase(binding, testCase) {
  const H = binding.HTTPParser;
  const parser = new H();
  const log = [];

  parser[H.kOnMessageBegin] = function() { log.push('begin'); };
  parser[H.kOnHeaders] = function(headers, url) {
    log.push('headers(' + headers.map(toText).join(',') + '|' + toText(url) + ')');
  };
  parser[H.kOnHeadersComplete] = function(
    versionMajor, versionMinor, headers, method, url, statusCode, statusMessage,
    upgrade, shouldKeepAlive,
  ) {
    log.push('headersComplete(' + [
      versionMajor,
      versionMinor,
      headers === undefined ? '<undefined>' : headers.map(toText).join(','),
      method === undefined ? '<undefined>' : method,
      url === undefined ? '<undefined>' : toText(url),
      statusCode === undefined ? '<undefined>' : statusCode,
      statusMessage === undefined ? '<undefined>' : toText(statusMessage),
      upgrade,
      shouldKeepAlive,
    ].join('|') + ')');
    return 0;
  };
  parser[H.kOnBody] = function(chunk) {
    log.push('body(' + toText(chunk) + ')');
  };
  parser[H.kOnMessageComplete] = function() {
    log.push('complete');
  };

  parser.initialize(
    testCase.kind === 'request' ? H.REQUEST : H.RESPONSE,
    {},
    testCase.maxHeaderSize,
    0,
    undefined,
    testCase.maxHeaderPairs,
  );

  const data = toBytes(testCase.input);
  const step = testCase.step === 0 ? data.length : testCase.step;
  const results = [];
  for (let offset = 0; offset < data.length; offset += step) {
    const slice = data.subarray(offset, Math.min(offset + step, data.length));
    results.push(describe(parser.execute(slice)));
  }
  if (testCase.finish) {
    results.push('finish:' + describe(parser.finish()));
  }
  return { name: testCase.name, results, log };
}

function describe(value) {
  if (value instanceof Error) {
    return 'error(' + [
      value.code,
      value.reason === undefined ? '<undefined>' : value.reason,
      value.message,
      value.bytesParsed === undefined ? '<undefined>' : value.bytesParsed,
    ].join('|') + ')';
  }
  return String(value);
}

function runCases(binding, cases) {
  return JSON.stringify(cases.map((testCase) => runCase(binding, testCase)));
}
