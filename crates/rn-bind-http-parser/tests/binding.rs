//! End-to-end checks that drive the binding through a real V8 isolate.
//!
//! `lib/internal/http/common.js` is unchanged Node code, so the only honest way
//! to prove this crate speaks the right protocol is to make the same calls it
//! makes: construct a parser, assign the four callbacks by index, `initialize`,
//! and feed it bytes. The cases below are therefore written as JavaScript
//! against the installed namespace rather than against Rust APIs.
//!
//! The expectations are literal strings recorded from a real `node` binary's
//! `internalBinding('http_parser')`, and `node_parity.rs` re-derives them from
//! that binary so they cannot drift silently.

use rn_bind_http_parser::HttpParser;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// A driver that reproduces how `lib/internal/http/common.js` uses the parser.
///
/// It exists so each case is a few lines of "what to feed in" rather than a
/// re-statement of the callback wiring. The callback constants are read off
/// `HTTPParser` exactly as `common.js` reads them.
const DRIVER: &str = r#"
globalThis.bytes = function bytes(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
};

// `Buffer` does not exist in a bare isolate, so these tests stand in the two
// things `lib/**` needs from it: a byte view for headers and body, and the
// `Uint8Array`-with-`Buffer.prototype` shape the binding returns.
// `kOnHeaders` and `kOnHeadersComplete` are handed byte views, and `kOnBody` a
// byte view as well; the body is the only one that would be a `Buffer` in Node.
// Everything else (the URL, the status message) is already a string.
globalThis.text = function text(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return value;
  let out = '';
  for (const byte of value) out += String.fromCharCode(byte);
  return out;
};

// Builds a parser that records every callback in `log`, with the argument
// shapes `parserOnHeaders` and `parserOnHeadersComplete` destructure.
globalThis.makeParser = function makeParser(kind, options) {
  options = options || {};
  const H = globalThis.__httpParserBinding.HTTPParser;
  const parser = new H();
  const log = [];
  globalThis.lastLog = log;

  parser[H.kOnMessageBegin] = function() {
    log.push(['begin']);
  };
  parser[H.kOnHeaders] = function(headers, url) {
    log.push(['headers', headers.map((value) => text(value)), text(url)]);
  };
  parser[H.kOnHeadersComplete] = function(
    versionMajor, versionMinor, headers, method, url, statusCode, statusMessage,
    upgrade, shouldKeepAlive,
  ) {
    log.push([
      'headersComplete',
      versionMajor,
      versionMinor,
      headers === undefined ? null : headers.map((value) => text(value)),
      method === undefined ? null : method,
      url === undefined ? null : text(url),
      statusCode === undefined ? null : statusCode,
      statusMessage === undefined ? null : text(statusMessage),
      upgrade,
      shouldKeepAlive,
    ]);
    return options.headersCompleteReturn || 0;
  };
  parser[H.kOnBody] = function(chunk) {
    log.push(['body', text(chunk), chunk.constructor.name]);
  };
  parser[H.kOnMessageComplete] = function() {
    log.push(['complete']);
  };

  parser.initialize(
    kind === 'request' ? H.REQUEST : H.RESPONSE,
    {},
    options.maxHeaderSize || 0,
    options.lenientFlags || 0,
    options.connections,
    options.maxHeaderPairs || 0,
  );
  return parser;
};

// Feeds `source` in `step`-byte slices and reports every `execute` result, which
// is what proves the parse is incremental rather than all-at-once.
globalThis.feed = function feed(parser, source, step) {
  const data = bytes(source);
  const results = [];
  for (let offset = 0; offset < data.length; offset += step) {
    const slice = data.subarray(offset, Math.min(offset + step, data.length));
    const result = parser.execute(slice);
    results.push(result instanceof Error ? 'error:' + result.code : result);
  }
  return results;
};

globalThis.summary = function summary(parser, source, step) {
  const results = feed(parser, source, step || source.length);
  return JSON.stringify({ results, log: globalThis.lastLog });
};
"#;

/// Runs `source` after the driver, in one fresh isolate, and returns the value
/// of the last expression.
///
/// V8's platform is process-wide, so every case in a test shares one process.
/// Each test still gets its own isolate, which is what keeps one case's pending
/// exception from affecting another's.
fn eval(source: &str) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = HttpParser
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("the http_parser binding installs");

    let global = context.global(scope);
    let key = v8::String::new(scope, "__httpParserBinding").expect("key");
    global.set(scope, key.into(), binding.into());

    let mut last = String::new();
    for prelude in std::iter::once(DRIVER).chain(std::iter::once(source)) {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let code = v8::String::new(scope, prelude).expect("source");
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
            last = value.to_rust_string_lossy(scope);
        }
    }
    last
}

/// Runs a case that is expected to throw, returning the exception message.
fn eval_expecting_throw(source: &str) -> String {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = HttpParser
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("the http_parser binding installs");
    let global = context.global(scope);
    let key = v8::String::new(scope, "__httpParserBinding").expect("key");
    global.set(scope, key.into(), binding.into());

    for prelude in std::iter::once(DRIVER).chain(std::iter::once(source)) {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let code = v8::String::new(scope, prelude).expect("source");
        let script = v8::Script::compile(scope, code, None).expect("compiles");
        let run = script.run(scope);
        if scope.has_caught() {
            return scope
                .exception()
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "unknown exception".to_string());
        }
        if run.is_none() {
            return "no value".to_string();
        }
    }
    "did not throw".to_string()
}

/// The namespace shape, which `lib/**` reads at module scope.
fn the_namespace_has_exactly_the_four_contract_members() {
    let shape = eval(
        r#"
const binding = globalThis.__httpParserBinding;
JSON.stringify({
  keys: Object.keys(binding).sort(),
  methods: binding.methods.length,
  allMethods: binding.allMethods.length,
  methodsFirst: binding.methods[0],
  methodsLast: binding.methods[binding.methods.length - 1],
  allLast: binding.allMethods[binding.allMethods.length - 1],
  hasMsearch: binding.methods.includes('M-SEARCH'),
  parserIsFunction: typeof binding.HTTPParser === 'function',
  parserLength: binding.HTTPParser.length,
  listIsFunction: typeof binding.ConnectionsList === 'function',
  listLength: binding.ConnectionsList.length,
});
"#,
    );
    assert_eq!(
        shape,
        concat!(
            r#"{"keys":["ConnectionsList","HTTPParser","allMethods","methods"],"#,
            r#""methods":35,"allMethods":47,"methodsFirst":"DELETE","#,
            r#""methodsLast":"QUERY","allLast":"QUERY","hasMsearch":true,"#,
            r#""parserIsFunction":true,"parserLength":0,"#,
            r#""listIsFunction":true,"listLength":0}"#
        ),
        "the namespace must expose exactly the four contract members with \
         llhttp's method tables; both constructors report length 0, as they do \
         in Node"
    );
}

/// The `kOn*` and `kLenient*` constants `common.js` reads at module scope.
///
/// These are load-bearing numbers: `common.js` writes its callbacks to
/// `parser[HTTPParser.kOnHeaders]`, so a shifted index silently sends the wrong
/// callback.
fn the_parser_constants_match_node() {
    let constants = eval(
        r#"
const H = globalThis.__httpParserBinding.HTTPParser;
JSON.stringify({
  REQUEST: H.REQUEST,
  RESPONSE: H.RESPONSE,
  kOnMessageBegin: H.kOnMessageBegin,
  kOnHeaders: H.kOnHeaders,
  kOnHeadersComplete: H.kOnHeadersComplete,
  kOnBody: H.kOnBody,
  kOnMessageComplete: H.kOnMessageComplete,
  kOnExecute: H.kOnExecute,
  kOnTimeout: H.kOnTimeout,
  kLenientNone: H.kLenientNone,
  kLenientHeaders: H.kLenientHeaders,
  kLenientChunkedLength: H.kLenientChunkedLength,
  kLenientKeepAlive: H.kLenientKeepAlive,
  kLenientTransferEncoding: H.kLenientTransferEncoding,
  kLenientVersion: H.kLenientVersion,
  kLenientDataAfterClose: H.kLenientDataAfterClose,
  kLenientOptionalLFAfterCR: H.kLenientOptionalLFAfterCR,
  kLenientOptionalCRLFAfterChunk: H.kLenientOptionalCRLFAfterChunk,
  kLenientOptionalCRBeforeLF: H.kLenientOptionalCRBeforeLF,
  kLenientSpacesAfterChunkSize: H.kLenientSpacesAfterChunkSize,
  kLenientHeaderValueRelaxed: H.kLenientHeaderValueRelaxed,
  kLenientAll: H.kLenientAll,
});
"#,
    );
    assert_eq!(
        constants,
        concat!(
            r#"{"REQUEST":1,"RESPONSE":2,"#,
            r#""kOnMessageBegin":0,"kOnHeaders":1,"kOnHeadersComplete":2,"#,
            r#""kOnBody":3,"kOnMessageComplete":4,"kOnExecute":5,"kOnTimeout":6,"#,
            r#""kLenientNone":0,"kLenientHeaders":1,"kLenientChunkedLength":2,"#,
            r#""kLenientKeepAlive":4,"kLenientTransferEncoding":8,"#,
            r#""kLenientVersion":16,"kLenientDataAfterClose":32,"#,
            r#""kLenientOptionalLFAfterCR":64,"kLenientOptionalCRLFAfterChunk":128,"#,
            r#""kLenientOptionalCRBeforeLF":256,"kLenientSpacesAfterChunkSize":512,"#,
            r#""kLenientHeaderValueRelaxed":1024,"kLenientAll":1023}"#
        ),
        "every constant is read by lib/** at module scope, so the values are \
         part of the contract"
    );
}

/// A whole request in one `execute`, which is the common path.
fn a_request_in_one_chunk_reports_begin_headers_complete_and_complete() {
    let result = eval(r#"summary(makeParser('request'), 'GET /x HTTP/1.1\r\nHost: a\r\n\r\n')"#);
    assert_eq!(
        result,
        concat!(
            r#"{"results":[28],"log":[["begin"],"#,
            r#"["headersComplete",1,1,["Host","a"],1,"/x","#,
            r#"null,null,false,true],["complete"]]}"#
        )
    );
}

/// The same request delivered one byte at a time, which is what proves the parse
/// is genuinely incremental: llhttp retains its state between `execute` calls and
/// every `execute` reports it consumed the one byte it was given.
fn a_request_delivered_one_byte_at_a_time_parses_identically() {
    let result = eval(r#"summary(makeParser('request'), 'GET /x HTTP/1.1\r\nHost: a\r\n\r\n', 1)"#);
    assert_eq!(
        result,
        concat!(
            r#"{"results":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"#,
            r#""log":[["begin"],"#,
            r#"["headersComplete",1,1,["Host","a"],1,"/x",null,null,false,true],"#,
            r#"["complete"]]}"#
        ),
        "'GET /x HTTP/1.1\\r\\nHost: a\\r\\n\\r\\n' is 28 bytes, so 28 one-byte \
         executes each reporting one byte consumed"
    );
}

/// A body split from its headers, which is the case `parserOnBody` sees as
/// several pushes.
///
/// The split is *not* merged: a body is delivered once per `execute` that
/// produced one, so a 4-byte step yields `'h'` and `'ello'`. That is Node's
/// behaviour, recorded from a real binary — `KOnBody` fires at the end of every
/// `llhttp_execute`, and `parserOnBody` pushes each chunk into the stream
/// separately.
fn a_body_is_reported_through_the_body_callback() {
    let result = eval(
        r#"summary(makeParser('request'),
                   'POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello', 4)"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"results":[4,4,4,4,4,4,4,4,4,4,4],"#,
            r#""log":[["begin"],"#,
            r#"["headersComplete",1,1,["Content-Length","5"],3,"/x","#,
            r#"null,null,false,true],["body","h","Uint8Array"],"#,
            r#"["body","ello","Uint8Array"],["complete"]]}"#
        )
    );
}

/// The same body one byte at a time yields one `kOnBody` per byte, which is the
/// extreme case of the above and the one that proves nothing is coalesced.
fn a_body_delivered_one_byte_at_a_time_reports_each_byte() {
    let result = eval(
        r#"summary(makeParser('request'),
                   'POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello', 1)"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"results":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"#,
            r#""log":[["begin"],"#,
            r#"["headersComplete",1,1,["Content-Length","5"],3,"/x","#,
            r#"null,null,false,true],["body","h","Uint8Array"],"#,
            r#"["body","e","Uint8Array"],["body","l","Uint8Array"],"#,
            r#"["body","l","Uint8Array"],["body","o","Uint8Array"],"#,
            r#"["complete"]]}"#
        )
    );
}

/// A chunked request: llhttp strips the framing and only the payload reaches
/// `kOnBody`.
///
/// The two chunks arrive as one buffer because the pinned Node 28 source
/// accumulates every body span an `execute` produces and delivers it once, when
/// `llhttp_execute` returns. Node 22 would report them separately — it calls
/// `kOnBody` straight from `on_body` — but the JavaScript layer in
/// `vendor/libnode-js` is Node 28's, so Node 28 is the specification. Either
/// way a stream consumer sees the same bytes.
fn a_chunked_body_is_reassembled_without_its_framing() {
    let result = eval(
        r#"summary(makeParser('request'),
          'POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n')"#,
    );
    assert!(
        result.contains(r#""body","helloabc","Uint8Array""#),
        "both chunks reach kOnBody, joined within the one execute: {result}"
    );
    assert!(
        !result.contains("5\r\n") && !result.contains("0\r\n"),
        "the chunk framing must not reach kOnBody: {result}"
    );
}

/// A response parser reports a status line instead of a method and URL.
fn a_response_reports_the_status_line() {
    let result = eval(
        r#"summary(makeParser('response'), 'HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nhi')"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"results":[47],"log":[["begin"],"#,
            r#"["headersComplete",1,1,["Content-Length","2"],null,null,404,"Not Found","#,
            r#"false,true],["body","hi","Uint8Array"],["complete"]]}"#
        )
    );
}

/// Two messages in one buffer, which is how pipelining reaches the parser.
fn two_pipelined_requests_each_report_a_full_message() {
    let result = eval(
        r#"summary(makeParser('request'),
          'GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n')"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"results":[56],"log":[["begin"],"#,
            r#"["headersComplete",1,1,["Host","x"],1,"/a",null,null,false,true],"#,
            r#"["complete"],["begin"],"#,
            r#"["headersComplete",1,1,["Host","y"],1,"/b",null,null,false,true],"#,
            r#"["complete"]]}"#
        )
    );
}

/// A header pair split across two `execute` calls, which is where the
/// accumulator's span joining matters.
fn a_header_split_across_chunks_is_rejoined() {
    let result = eval(
        r#"
const parser = makeParser('request');
const results = [];
results.push(parser.execute(bytes('GET /x HTTP/1.1\r\nLong-Na')));
results.push(parser.execute(bytes('me: val')));
results.push(parser.execute(bytes('ue\r\n\r\n')));
JSON.stringify({ results, log: globalThis.lastLog });
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"results":[24,7,6],"log":[["begin"],"#,
            r#"["headersComplete",1,1,["Long-Name","value"],1,"/x","#,
            r#"null,null,false,true],["complete"]]}"#
        )
    );
}

/// Past 32 headers the batch is handed to `kOnHeaders` in pieces, and
/// `kOnHeadersComplete` then has no headers argument. This is the boundary that
/// `MAX_HEADER_FIELDS` exists for.
fn more_than_thirty_two_headers_are_flushed_through_on_headers() {
    let result = eval(
        r#"
let headerBlock = '';
for (let i = 0; i < 40; i++) headerBlock += 'H' + i + ': v\r\n';
const parser = makeParser('request');
const ret = parser.execute(bytes('GET /x HTTP/1.1\r\n' + headerBlock + '\r\n'));
const log = globalThis.lastLog;
JSON.stringify({
  ret,
  pairs: log.filter((entry) => entry[0] === 'headers').map((entry) => (entry[1].length / 2)),
  headersCompleteHeaders: log.find((entry) => entry[0] === 'headersComplete')[3],
  completed: log.filter((entry) => entry[0] === 'complete').length,
});
"#,
    );
    assert_eq!(
        result, r#"{"ret":329,"pairs":[31,9],"headersCompleteHeaders":null,"completed":1}"#,
        "40 headers flush as 31 then 9, and kOnHeadersComplete gets no headers"
    );
}

/// `maxHeaderSize` is enforced across the request line and headers, and reports
/// `HPE_HEADER_OVERFLOW` in the `code:reason` shape `prepareError` splits.
fn an_oversized_header_block_reports_hpe_header_overflow() {
    let result = eval(
        r#"
const parser = makeParser('request', { maxHeaderSize: 64 });
const buffer = bytes('GET /x HTTP/1.1\r\nLong: ' + 'v'.repeat(200) + '\r\n\r\n');
const ret = parser.execute(buffer);
JSON.stringify({
  isError: ret instanceof Error,
  message: ret.message,
  code: ret.code,
  reason: ret.reason,
  bytesParsed: ret.bytesParsed,
});
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"isError":true,"message":"Parse Error","#,
            r#""code":"HPE_HEADER_OVERFLOW","reason":"Header overflow","bytesParsed":224}"#
        )
    );
}

/// A malformed header line reports llhttp's own error, which is where the
/// `HPE_*` name comes from.
fn an_invalid_header_token_reports_hpe_invalid_header_token() {
    let result = eval(
        r#"
const parser = makeParser('request');
const buffer = bytes('GET /x HTTP/1.1\r\nBad Header\r\n\r\n');
const ret = parser.execute(buffer);
JSON.stringify({
  code: ret.code,
  message: ret.message,
  reason: ret.reason,
  bytesParsed: ret.bytesParsed,
  prefix: text(buffer.subarray(0, ret.bytesParsed)),
});
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"code":"HPE_INVALID_HEADER_TOKEN","message":"Parse Error","#,
            r#""reason":"Invalid header token","bytesParsed":20,"#,
            r#""prefix":"GET /x HTTP/1.1\r\nBad"}"#
        )
    );
}

/// `finish()` on an incomplete message reports `HPE_INVALID_EOF_STATE` and
/// returns no value on success.
fn finish_reports_an_incomplete_message_and_returns_nothing_on_success() {
    let result = eval(
        r#"
const incomplete = makeParser('request');
incomplete.execute(bytes('POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhe'));
const failed = incomplete.finish();

const complete = makeParser('request');
complete.execute(bytes('GET /x HTTP/1.1\r\nHost: a\r\n\r\n'));
const ok = complete.finish();

JSON.stringify({
  failedCode: failed instanceof Error ? failed.code : null,
  failedReason: failed instanceof Error ? failed.reason : null,
  ok,
  okType: typeof ok,
});
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"failedCode":"HPE_INVALID_EOF_STATE","failedReason":"Invalid EOF state","#,
            r#""okType":"undefined"}"#
        )
    );
}

/// `pause()` from inside a callback lets the run in progress finish, so the
/// message-complete callback still fires; the *next* `execute` reports
/// `HPE_PAUSED`, and `resume()` clears it.
fn pause_from_a_callback_still_completes_the_message() {
    let result = eval(
        r#"
const H = globalThis.__httpParserBinding.HTTPParser;
const parser = makeParser('request');
let paused = false;
parser[H.kOnHeadersComplete] = function() {
  if (!paused) { paused = true; parser.pause(); }
  return 0;
};
const first = parser.execute(bytes('GET /a HTTP/1.1\r\nHost: x\r\n\r\n'));
const logAfterFirst = globalThis.lastLog.length;
const whilePaused = parser.execute(bytes('GET /b HTTP/1.1\r\nHost: y\r\n\r\n'));
parser.resume();
const afterResume = parser.execute(bytes(''));
// The replacement callback does not append to the log, so only the driver's
// own begin/complete entries appear. The second request is re-fed after the
// resume, because a paused `execute` consumed nothing.
const afterResumeFeed = parser.execute(bytes('GET /b HTTP/1.1\r\nHost: y\r\n\r\n'));
JSON.stringify({
  first,
  logAfterFirst,
  pausedCode: whilePaused instanceof Error ? whilePaused.code : null,
  afterResume,
  afterResumeFeed,
  messages: globalThis.lastLog.filter((entry) => entry[0] === 'complete').length,
  fullLog: globalThis.lastLog.map((e) => e[0]),
});
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"first":28,"logAfterFirst":2,"pausedCode":"HPE_PAUSED","#,
            r#""afterResume":0,"afterResumeFeed":28,"messages":2,"#,
            r#""fullLog":["begin","complete","begin","complete"]}"#
        ),
        "the message in flight completes before the pause is visible, the next \
         execute reports HPE_PAUSED without consuming anything, and after \
         resume() a re-fed request parses normally"
    );
}

/// An upgrade stops the parser at the boundary and reports success with the
/// pre-upgrade byte count, leaving the rest of the buffer unconsumed.
fn an_upgrade_stops_at_the_boundary_and_leaves_the_rest() {
    let result = eval(
        r#"
const parser = makeParser('request');
const ret = parser.execute(bytes(
  'GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nrawdata'));
const log = globalThis.lastLog;
JSON.stringify({
  ret,
  upgrade: log.find((entry) => entry[0] === 'headersComplete')[8],
  completed: log.some((entry) => entry[0] === 'complete'),
});
"#,
    );
    assert_eq!(result, r#"{"ret":70,"upgrade":true,"completed":true}"#);
}

/// A `headersComplete` callback returning 1 tells llhttp the message has no
/// body; returning 2 does the same and stops at the upgrade boundary.
fn a_headers_complete_return_value_controls_the_body() {
    let result = eval(
        r#"
const skip = makeParser('request', { headersCompleteReturn: 1 });
const skipRet = skip.execute(bytes(
  'POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /y HTTP/1.1\r\nHost: z\r\n\r\n'));
const upgrade = makeParser('request', { headersCompleteReturn: 2 });
const upgradeRet = upgrade.execute(bytes(
  'POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloTAIL'));
JSON.stringify({
  skipIsError: skipRet instanceof Error,
  skipCode: skipRet instanceof Error ? skipRet.code : null,
  upgradeRet,
});
"#,
    );
    assert_eq!(
        result, r#"{"skipIsError":true,"skipCode":"HPE_INVALID_METHOD","upgradeRet":39}"#,
        "1 skips the body and the following bytes are parsed as a new message, \
         which fails; 2 stops at the boundary"
    );
}

/// An exception thrown by a callback propagates out of `execute`, and the parser
/// then refuses further input with `HPE_JS_EXCEPTION`.
fn an_exception_from_a_callback_propagates_and_poisons_the_parser() {
    let result = eval(
        r#"
const parser = makeParser('request');
let thrown = null;
parser[globalThis.__httpParserBinding.HTTPParser.kOnHeadersComplete] = function() {
  throw new Error('boom');
};
try {
  parser.execute(bytes('GET /a HTTP/1.1\r\n\r\n'));
} catch (error) {
  thrown = error.message;
}
const after = parser.execute(bytes(''));
JSON.stringify({ thrown, afterCode: after instanceof Error ? after.code : null });
"#,
    );
    assert_eq!(
        result,
        r#"{"thrown":"boom","afterCode":"HPE_CB_HEADERS_COMPLETE"}"#
    );
}

/// `getCurrentBuffer` returns the buffer being parsed while a callback runs.
fn get_current_buffer_returns_the_buffer_being_parsed() {
    let result = eval(
        r#"
const H = globalThis.__httpParserBinding.HTTPParser;
const parser = makeParser('request');
let seen = null;
parser[H.kOnHeadersComplete] = function() {
  const current = parser.getCurrentBuffer();
  seen = { length: current.length, matches: text(current) === 'GET /a HTTP/1.1\r\n\r\n' };
  return 0;
};
const source = 'GET /a HTTP/1.1\r\n\r\n';
parser.execute(bytes(source));
JSON.stringify(seen);
"#,
    );
    assert_eq!(result, r#"{"length":19,"matches":true}"#);
}

/// `close()` makes the wrapper inert without invalidating the object, which is
/// what `lib/**` relies on when it frees a parser and later touches it.
fn close_leaves_the_object_alive_but_inert() {
    let result = eval(
        r#"
const parser = makeParser('request');
const before = parser.execute(bytes('GET /a HTTP/1.1\r\n\r\n'));
parser.close();
const afterExecute = parser.execute(bytes('GET /b HTTP/1.1\r\n\r\n'));
const afterFinish = parser.finish();
const canInitialize = typeof parser.initialize === 'function';
JSON.stringify({
  before,
  afterExecute,
  afterFinishType: typeof afterFinish,
  canInitialize,
  stillAnObject: typeof parser === 'object',
});
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"before":19,"afterExecute":0,"afterFinishType":"undefined","#,
            r#""canInitialize":true,"stillAnObject":true}"#
        )
    );
}

/// `ConnectionsList` tracks parsers through their whole lifecycle, which is what
/// `server.closeIdleConnections()` and the expiry interval read.
fn the_connections_list_tracks_parsers_through_their_lifecycle() {
    let result = eval(
        r#"
const binding = globalThis.__httpParserBinding;
const list = new binding.ConnectionsList();
const empty = {
  all: list.all().length,
  idle: list.idle().length,
  active: list.active().length,
  expired: list.expired(0, 0).length,
};

const parser = makeParser('request', { connections: list });
const afterInitialize = {
  all: list.all().length,
  idle: list.idle().length,
  active: list.active().length,
  identity: list.all()[0] === parser,
};

parser.execute(bytes('GET /a HTTP/1.1\r\nHost: x\r\n\r\n'));
const afterMessage = {
  all: list.all().length,
  idle: list.idle().length,
  active: list.active().length,
};

parser.remove();
const afterRemove = list.all().length;

JSON.stringify({ empty, afterInitialize, afterMessage, afterRemove });
"#,
    );
    assert_eq!(
        result,
        concat!(
            r#"{"empty":{"all":0,"idle":0,"active":0,"expired":0},"#,
            // Node 28's `Idle` tests `last_message_start_ == 0 || !received_data_`
            // and `Initialize` clears `received_data_`, so a parser that has not
            // received a byte is idle as well as active.
            r#""afterInitialize":{"all":1,"idle":1,"active":1,"identity":true},"#,
            r#""afterMessage":{"all":1,"idle":1,"active":0},"#,
            r#""afterRemove":0}"#
        ),
        "initialize registers the parser in both lists, message completion \
         unlinks it from the active one, and remove() unlinks it from both"
    );
}

/// `expired()` unlinks the parser from the active list as it reports it.
fn expired_reports_and_unlinks_a_stale_connection() {
    let result = eval(
        r#"
const list = new globalThis.__httpParserBinding.ConnectionsList();
const parser = makeParser('request', { connections: list });
parser.execute(bytes('GET /a HTTP/1.1\r\nHost: x\r\n'));  // headers incomplete
const expired = list.expired(1, 0);
JSON.stringify({ expired: expired.length, active: list.active().length, all: list.all().length });
"#,
    );
    assert_eq!(result, r#"{"expired":0,"active":1,"all":1}"#);
}

/// `initialize` rejects a non-request/response type instead of silently building
/// a parser that parses nothing.
fn initialize_rejects_an_unknown_parser_type() {
    let message = eval_expecting_throw(
        r#"
const H = globalThis.__httpParserBinding.HTTPParser;
const parser = new H();
parser.initialize(7, {}, 0, 0, undefined, 0);
"#,
    );
    assert!(
        message.contains("REQUEST") && message.contains("RESPONSE"),
        "the error names the two valid types: {message}"
    );
}

/// `execute` requires a view, which Node enforces by asserting.
fn execute_rejects_a_non_view() {
    let message = eval_expecting_throw(
        r#"
const parser = makeParser('request');
parser.execute('not a buffer');
"#,
    );
    assert!(
        message.contains("Buffer") || message.contains("TypedArray"),
        "the error names what is accepted: {message}"
    );
}

/// `consume` resolves its argument to a `StreamBase` handle, which is what Node
/// `CHECK`s. A plain object has no stream attached under the pairing symbol, so
/// the closest honest equivalent is a throw that names the requirement.
///
/// The message is deliberately about the *argument*, not about the runtime:
/// `tcp_wrap` and `pipe_wrap` publish real stream handles, and the pairing is
/// what `StreamBase::FromObject` unwraps in Node. A caller passing `{}` is a
/// caller bug in both runtimes.
fn consume_rejects_a_non_stream_handle() {
    let message = eval_expecting_throw(
        r#"
const parser = makeParser('request');
parser.consume({});
"#,
    );
    assert!(
        message.contains("stream handle"),
        "the message names what consume needs: {message}"
    );
}

/// `unconsume` on a parser that was never consuming is a silent no-op.
///
/// This is `Parser::Unconsume`'s early return for `stream_ == nullptr`, and
/// `lib/internal/http/common.js`'s `freeParser` depends on it: it calls
/// `unconsume` whenever `parser._consumed` is set, including for sockets whose
/// handle it never had.
fn unconsume_without_consume_is_a_no_op() {
    let value = eval(
        r#"
const parser = makeParser('request');
parser.unconsume();
parser.unconsume();
'no-op';
"#,
    );
    assert_eq!(value.trim(), "no-op", "unconsume must not throw");
}

/// Every case above, in one test.
///
/// V8's platform and global state are process-wide and `V8::initialize` is
/// guarded by a non-reentrant lock, so separate `#[test]` functions would race
/// each other. Each case still gets its own isolate, which is what keeps one
/// case's pending exception from leaking into the next.
#[test]
fn http_parser_binding_end_to_end() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    the_namespace_has_exactly_the_four_contract_members();
    the_parser_constants_match_node();
    a_request_in_one_chunk_reports_begin_headers_complete_and_complete();
    a_request_delivered_one_byte_at_a_time_parses_identically();
    a_body_is_reported_through_the_body_callback();
    a_body_delivered_one_byte_at_a_time_reports_each_byte();
    a_chunked_body_is_reassembled_without_its_framing();
    a_response_reports_the_status_line();
    two_pipelined_requests_each_report_a_full_message();
    a_header_split_across_chunks_is_rejoined();
    more_than_thirty_two_headers_are_flushed_through_on_headers();
    an_oversized_header_block_reports_hpe_header_overflow();
    an_invalid_header_token_reports_hpe_invalid_header_token();
    finish_reports_an_incomplete_message_and_returns_nothing_on_success();
    pause_from_a_callback_still_completes_the_message();
    an_upgrade_stops_at_the_boundary_and_leaves_the_rest();
    a_headers_complete_return_value_controls_the_body();
    an_exception_from_a_callback_propagates_and_poisons_the_parser();
    get_current_buffer_returns_the_buffer_being_parsed();
    close_leaves_the_object_alive_but_inert();
    the_connections_list_tracks_parsers_through_their_lifecycle();
    expired_reports_and_unlinks_a_stale_connection();
    initialize_rejects_an_unknown_parser_type();
    execute_rejects_a_non_view();
    consume_rejects_a_non_stream_handle();
    unconsume_without_consume_is_a_no_op();
}
