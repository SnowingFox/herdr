//! Cross-checks the binding against a real `node --expose-internals`.
//!
//! Every expectation in `binding.rs` is a literal string. That is right for a
//! regression test but only as good as whoever recorded it. This test removes
//! that trust: it runs the same sequences through real Node's
//! `internalBinding('http_parser')` and through this crate's, and compares the
//! callback logs, the `execute` return values and the error fields.
//!
//! The cases skip themselves when no `node` is on `PATH`, because the crate's
//! gate must not depend on an external binary. When one is present, every case
//! runs.
//!
//! # Why the comparison is a transcript
//!
//! The interesting thing about an incremental parser is the *sequence* of
//! callbacks and byte counts, not any single value: a parser that reports the
//! right headers but in the wrong order, or that consumes the wrong number of
//! bytes on one chunk, is broken in a way an equality check on the final state
//! cannot see. So each side prints one JSON line per case and the lines must be
//! identical.

use rn_bind_http_parser::HttpParser;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_node_oracle::Oracle;
use rn_v8_sys::v8;

/// One case: a parser type, an optional configuration, the input, and how many
/// bytes to feed per `execute`.
///
/// `step == 0` means "all at once".
struct Case {
    name: &'static str,
    /// `'request'` or `'response'`.
    kind: &'static str,
    /// Passed as `maxHeaderSize`; `0` keeps the default.
    max_header_size: u32,
    /// Passed as `maxHeaderPairs`; `0` means no limit.
    max_header_pairs: u32,
    input: &'static str,
    step: usize,
    /// Call `finish()` after the input.
    finish: bool,
}

const CASES: &[Case] = &[
    Case {
        name: "get-request-one-shot",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "get-request-byte-wise",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
        step: 1,
        finish: false,
    },
    Case {
        name: "post-with-body",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
        step: 0,
        finish: false,
    },
    Case {
        name: "post-with-body-chunked-input",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
        step: 3,
        finish: false,
    },
    Case {
        name: "chunked-request",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "chunked-request-byte-wise",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        step: 1,
        finish: false,
    },
    Case {
        name: "response",
        kind: "response",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nhi",
        step: 0,
        finish: false,
    },
    Case {
        name: "response-chunked-input",
        kind: "response",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
        step: 5,
        finish: false,
    },
    Case {
        name: "pipelined-requests",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "header-split-across-executes",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nLong-Name: value\r\n\r\n",
        step: 9,
        finish: false,
    },
    Case {
        name: "more-than-32-headers",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nH0: v\r\nH1: v\r\nH2: v\r\nH3: v\r\nH4: v\r\nH5: v\r\nH6: v\r\nH7: v\r\nH8: v\r\nH9: v\r\nH10: v\r\nH11: v\r\nH12: v\r\nH13: v\r\nH14: v\r\nH15: v\r\nH16: v\r\nH17: v\r\nH18: v\r\nH19: v\r\nH20: v\r\nH21: v\r\nH22: v\r\nH23: v\r\nH24: v\r\nH25: v\r\nH26: v\r\nH27: v\r\nH28: v\r\nH29: v\r\nH30: v\r\nH31: v\r\nH32: v\r\nH33: v\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "empty-header-value",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nEmpty:\r\nSpaces:   v  \r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "upgrade-request",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nrest",
        step: 0,
        finish: false,
    },
    Case {
        name: "invalid-header-token",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nBad Header\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "header-overflow",
        kind: "request",
        max_header_size: 64,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nLong: vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "max-header-pairs",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 2,
        input: "GET /x HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "finish-incomplete-body",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhe",
        step: 0,
        finish: true,
    },
    Case {
        name: "finish-complete",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
        step: 0,
        finish: true,
    },
    Case {
        name: "connect-request",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "m-search",
        kind: "request",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "M-SEARCH * HTTP/1.1\r\nHost: x\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "status-without-reason",
        kind: "response",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "HTTP/1.1 204\r\n\r\n",
        step: 0,
        finish: false,
    },
    Case {
        name: "head-response-has-no-body",
        kind: "response",
        max_header_size: 0,
        max_header_pairs: 0,
        input: "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
        step: 0,
        finish: false,
    },
];

/// Runs every case through a fresh isolate and returns the transcript.
fn rust_transcript() -> String {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

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

    // The cases are emitted as an array literal, so both sides read the same
    // description and neither has to parse a string it produced itself.
    let combined = format!(
        "{}\nglobalThis.__httpParserResult = runCases(globalThis.__httpParserBinding, {});",
        include_str!("common_transcript.js"),
        cases_json()
    );
    let code = v8::String::new(scope, &combined).expect("source");
    let script = v8::Script::compile(scope, code, None).expect("compiles");
    script.run(scope).expect("runs");

    let key = v8::String::new(scope, "__httpParserResult").expect("result key");
    let result = global.get(scope, key.into()).expect("result");
    result.to_rust_string_lossy(scope)
}

/// The cases as JSON, so both sides read one description.
fn cases_json() -> String {
    let mut out = String::from("[");
    for (index, case) in CASES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            r#"{{"name":{},"kind":{},"maxHeaderSize":{},"maxHeaderPairs":{},"input":{},"step":{},"finish":{}}}"#,
            json_string(case.name),
            json_string(case.kind),
            case.max_header_size,
            case.max_header_pairs,
            json_string(case.input),
            case.step,
            case.finish,
        ));
    }
    out.push(']');
    out
}

/// Escapes a string for JSON. The inputs are ASCII HTTP messages, so only the
/// control characters need escaping.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Runs every case through the pinned oracle with `--expose-internals`.
fn node_transcript(oracle: &Oracle) -> String {
    let script = format!(
        r#"
const {{ internalBinding }} = require('internal/test/binding');
{shared}
const binding = internalBinding('http_parser');
process.stdout.write(runCases(binding, {cases}));
"#,
        shared = include_str!("common_transcript.js"),
        cases = cases_json(),
    );

    let output = oracle
        .command()
        .args(["--expose-internals", "--no-warnings", "-e", &script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", oracle.describe()));
    if !output.status.success() {
        panic!(
            "{} failed: {}\n{}",
            oracle.describe(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The comparison.
///
/// The transcript must equal the pinned oracle's exactly. There is no allowance
/// list: the earlier version reconciled a *locally installed* Node against the
/// pinned source, which was necessary only because the two were different
/// engines. Now that the oracle is the pinned build itself (see
/// [`rn_node_oracle`]) any difference is a real disagreement, and an allowance
/// list would have hidden exactly the kind of divergence this test exists to
/// catch.
///
/// With no oracle the test skips loudly; with a wrong-version Node it fails.
#[test]
fn the_transcript_matches_the_pinned_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("rn-bind-http-parser node parity") else {
        return;
    };
    let node = node_transcript(&oracle);
    let ours = rust_transcript();

    if node == ours {
        return;
    }

    // Fall back to a per-case comparison so one differing case does not hide the
    // other twenty-one in the diff.
    let node_cases: Vec<serde_json::Value> = serde_json::from_str(&node).expect("node transcript");
    let our_cases: Vec<serde_json::Value> =
        serde_json::from_str(&ours).expect("rustnode transcript");
    assert_eq!(
        node_cases.len(),
        our_cases.len(),
        "the two sides ran different numbers of cases"
    );

    let mut differences = Vec::new();
    for (expected, actual) in node_cases.iter().zip(our_cases.iter()) {
        if expected == actual {
            continue;
        }
        let name = expected["name"].as_str().unwrap_or("<unnamed>");
        differences.push(format!(
            "{name}\n  node:     {expected}\n  rustnode: {actual}"
        ));
    }

    assert!(
        differences.is_empty(),
        "the callback transcripts differ from {}\n\n{}",
        oracle.describe(),
        differences.join("\n\n")
    );
}
