//! Drives the binding through the real `rustnode` binary, the way `lib/**` will.
//!
//! `binding.rs` calls the namespace from a bare isolate, which proves the
//! protocol but not the wiring: a crate can be registered and still be
//! unreachable through `internalBinding`, and the `Buffer` a body callback
//! receives only exists once the bootstrap has installed `Buffer` as a global.
//!
//! This test spawns `target/debug/rustnode`, asks it for
//! `internalBinding('http_parser')` exactly as `lib/internal/http/common.js`
//! does, and checks the result. It skips when the binary is absent, since a
//! `cargo test -p rn-bind-http-parser` does not build `rn-cli`; `tools/check.sh`
//! builds it first, so the gate always exercises this.
//!
//! Everything here was derived by running the same script through a real
//! `node`, which is why the expectations are the transcripts Node produces.

use std::path::PathBuf;
use std::process::Command;

/// The `rustnode` binary, if it has been built.
fn rustnode() -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("rustnode");
    path.exists().then_some(path)
}

/// Runs `source` through `rustnode` and returns its last stdout line.
///
/// The script reaches the namespace the way `lib/**` does — through
/// `internal/bootstrap/realm`'s `internalBinding` — because there is no
/// `internalBinding` global.
fn run(source: &str) -> String {
    let Some(binary) = rustnode() else {
        eprintln!("skipping: target/debug/rustnode is not built");
        return String::new();
    };
    let output = Command::new(&binary)
        .arg("-e")
        .arg(source)
        .output()
        .expect("rustnode runs");
    assert!(
        output.status.success(),
        "rustnode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .last()
        .unwrap_or_default()
        .to_string()
}

/// The namespace is reachable and its method tables are llhttp's.
#[test]
fn the_binding_is_reachable_through_the_cli() {
    let result = run(r#"
const binding = require('internal/bootstrap/realm').internalBinding('http_parser');
console.log(JSON.stringify({
  keys: Object.keys(binding).sort(),
  methods: binding.methods.length,
  allMethods: binding.allMethods.length,
  firstMethod: binding.methods[0],
  lastMethod: binding.methods[binding.methods.length - 1],
  lastAll: binding.allMethods[binding.allMethods.length - 1],
  parserArities: [binding.HTTPParser.length, binding.ConnectionsList.length],
}));
"#);
    if result.is_empty() {
        return;
    }
    assert_eq!(
        result,
        concat!(
            r#"{"keys":["ConnectionsList","HTTPParser","allMethods","methods"],"#,
            r#""methods":35,"allMethods":47,"firstMethod":"DELETE","#,
            r#""lastMethod":"QUERY","lastAll":"QUERY","parserArities":[0,0]}"#
        ),
        "the namespace is reachable and matches the contract"
    );
}

/// A request parsed byte by byte through the CLI, with every `execute`
/// reporting one byte consumed — the transcript a real `node` produces.
#[test]
fn a_byte_wise_request_parses_the_same_through_the_cli() {
    let result = run(r#"
const binding = require('internal/bootstrap/realm').internalBinding('http_parser');
const H = binding.HTTPParser;
const parser = new H();
const log = [];
parser[H.kOnMessageBegin] = () => log.push('begin');
parser[H.kOnHeadersComplete] = (vMajor, vMinor, headers, method, url, statusCode,
                                statusMessage, upgrade, keepAlive) => {
  log.push(['complete', vMajor, vMinor,
            headers.map((value) => Buffer.from(value).toString()),
            method, url, statusCode, statusMessage, upgrade, keepAlive]);
  return 0;
};
parser[H.kOnBody] = (chunk) => {
  // A `Buffer` here is what makes `parserOnBody`'s `stream.push(chunk)` work.
  log.push(['body', Buffer.from(chunk).toString(), Buffer.isBuffer(chunk)]);
};
parser[H.kOnMessageComplete] = () => log.push('done');
parser.initialize(H.REQUEST, {}, 0, 0, undefined, 0);

const data = Buffer.from('POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello');
const results = [];
for (let index = 0; index < data.length; index++) {
  const ret = parser.execute(data.subarray(index, index + 1));
  results.push(ret instanceof Error ? 'error:' + ret.code : ret);
}
console.log(JSON.stringify({ results, log }));
"#);
    if result.is_empty() {
        return;
    }
    // 44 bytes, so 44 ones; then the body arrives one byte at a time because
    // each `execute` flushes its own spans.
    let mut expected_results = String::from("[");
    for index in 0..44u32 {
        if index > 0 {
            expected_results.push(',');
        }
        expected_results.push('1');
    }
    expected_results.push(']');
    assert_eq!(
        result,
        format!(
            concat!(
                r#"{{"results":{},"log":["begin","#,
                r#"["complete",1,1,["Content-Length","5"],3,"/x",null,null,false,true],"#,
                r#"["body","h",true],["body","e",true],["body","l",true],"#,
                r#"["body","l",true],["body","o",true],"done"]}}"#
            ),
            expected_results
        ),
        "byte-wise parsing and Buffer identity match Node"
    );
}

/// A parse error carries the fields `prepareError` reads.
#[test]
fn a_parse_error_carries_code_reason_and_bytes_parsed() {
    let result = run(r#"
const binding = require('internal/bootstrap/realm').internalBinding('http_parser');
const H = binding.HTTPParser;
const parser = new H();
parser[H.kOnHeadersComplete] = () => 0;
parser.initialize(H.REQUEST, {}, 0, 0, undefined, 0);
const ret = parser.execute(Buffer.from('GET /x HTTP/1.1\r\nBad Header\r\n\r\n'));
console.log(JSON.stringify({
  isError: ret instanceof Error,
  code: ret.code,
  reason: ret.reason,
  message: ret.message,
  bytesParsed: ret.bytesParsed,
}));
"#);
    if result.is_empty() {
        return;
    }
    assert_eq!(
        result,
        concat!(
            r#"{"isError":true,"code":"HPE_INVALID_HEADER_TOKEN","#,
            r#""reason":"Invalid header token","message":"Parse Error","#,
            r#""bytesParsed":20}"#
        )
    );
}

/// `ConnectionsList` works through the CLI, which is what `server.js` needs.
#[test]
fn the_connections_list_works_through_the_cli() {
    let result = run(r#"
const binding = require('internal/bootstrap/realm').internalBinding('http_parser');
const H = binding.HTTPParser;
const list = new binding.ConnectionsList();
const parser = new H();
parser[H.kOnHeadersComplete] = () => 0;
parser[H.kOnMessageComplete] = () => {};
parser.initialize(H.REQUEST, {}, 0, 0, list, 0);
const afterInitialize = [list.all().length, list.idle().length, list.active().length,
                         list.all()[0] === parser];
parser.execute(Buffer.from('GET /a HTTP/1.1\r\nHost: x\r\n\r\n'));
const afterMessage = [list.all().length, list.idle().length, list.active().length];
parser.remove();
console.log(JSON.stringify({
  afterInitialize,
  afterMessage,
  afterRemove: list.all().length,
  expiredNoTimeouts: list.expired(0, 0).length,
}));
"#);
    if result.is_empty() {
        return;
    }
    assert_eq!(
        result,
        concat!(
            r#"{"afterInitialize":[1,1,1,true],"afterMessage":[1,1,0],"#,
            r#""afterRemove":0,"expiredNoTimeouts":0}"#
        )
    );
}

/// The real consumer: `lib/internal/http/common.js` loads and parses.
///
/// Everything else in this file drives the binding directly. This one requires
/// the actual Node module, which is the consumer the namespace exists for, and
/// checks the pieces `common.js` derives at module scope: the `methods` array, the
/// `kOn*` indices it writes its callbacks to, and `calculateLenientFlags`, which
/// maps `--http-validation` onto the `kLenient*` bits.
///
/// It does not require `http` itself: that module also needs `stream_wrap`, which
/// this runtime does not have yet, so it fails for a reason unrelated to this
/// binding.
#[test]
fn the_real_common_js_module_loads_and_parses() {
    let result = run(r#"
const common = require('internal/http/common');
const H = common.HTTPParser;
const parser = new H();
const log = [];
parser[H.kOnHeadersComplete] = (vMajor, vMinor, headers, method, url) => {
  log.push(['headersComplete', vMajor, vMinor,
            headers.map((value) => Buffer.from(value).toString()), method, url]);
  return 0;
};
parser[H.kOnBody] = (chunk) => log.push(['body', Buffer.from(chunk).toString()]);
parser[H.kOnMessageComplete] = () => log.push('complete');
parser.initialize(H.REQUEST, {}, 0, 0, undefined, 0);
const ret = parser.execute(
  Buffer.from('POST /p?q=1 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'));
console.log(JSON.stringify({
  ret,
  log,
  methods: common.methods.length,
  firstMethod: common.methods[0],
  strict: common.calculateLenientFlags('strict', undefined),
  relaxed: common.calculateLenientFlags('relaxed', undefined),
  insecure: common.calculateLenientFlags('insecure', undefined),
}));
"#);
    if result.is_empty() {
        return;
    }
    assert_eq!(
        result,
        concat!(
            r#"{"ret":46,"log":["#,
            r#"["headersComplete",1,1,["Content-Length","3"],3,"/p?q=1"],"#,
            r#"["body","abc"],"complete"],"#,
            // `common.js` re-exports `methods` but keeps `allMethods` private;
            // it uses the latter to turn the numeric method from
            // `kOnHeadersComplete` back into a name.
            r#""methods":35,"firstMethod":"DELETE","#,
            r#""strict":0,"relaxed":1024,"insecure":1023}"#
        ),
        "the real consumer loads, and its derived values are the recorded ones"
    );
}
