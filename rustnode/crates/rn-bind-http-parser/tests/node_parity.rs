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

use std::process::Command;

use rn_bind_http_parser::HttpParser;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
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

/// Runs every case through a real `node --expose-internals`.
fn node_transcript() -> Option<String> {
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

    let output = Command::new("node")
        .args(["--expose-internals", "--no-warnings", "-e", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        panic!(
            "node failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Cases where the installed Node binary and the pinned Node source disagree.
///
/// `tools/node-pin.toml` pins the JavaScript layer to Node 28, and that revision
/// is the specification here, so where a locally installed Node (any released
/// version) behaves differently the pinned source wins. Each entry records both
/// sides and why, so a divergence is reviewed rather than tolerated: a case not
/// listed here still fails the comparison.
struct KnownDifference {
    case: &'static str,
    /// The fields the installed binary produces, by JSON key.
    installed: &'static [(&'static str, &'static str)],
    /// The fields this crate produces, following the pinned source.
    pinned: &'static [(&'static str, &'static str)],
    reason: &'static str,
}

impl KnownDifference {
    fn installed_summary(&self) -> String {
        self.installed
            .iter()
            .map(|(field, value)| format!("{field}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn pinned_summary(&self) -> String {
        self.pinned
            .iter()
            .map(|(field, value)| format!("{field}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

const KNOWN_DIFFERENCES: &[KnownDifference] = &[
    KnownDifference {
        case: "chunked-request",
        installed: &[(
            "log",
            r#"["begin","headersComplete(1|1|Transfer-Encoding,chunked|3|/x|<undefined>|<undefined>|false|true)","body(hello)","body(abc)","complete"]"#,
        )],
        pinned: &[(
            "log",
            r#"["begin","headersComplete(1|1|Transfer-Encoding,chunked|3|/x|<undefined>|<undefined>|false|true)","body(helloabc)","complete"]"#,
        )],
        reason: "the installed Node calls kOnBody per llhttp span, while the pinned \
                 Node 28 buffers every span an execute produces and calls it once \
                 when llhttp_execute returns. A stream consumer sees the same \
                 bytes either way.",
    },
    KnownDifference {
        case: "max-header-pairs",
        installed: &[
            ("results", r#"["37"]"#),
            (
                "log",
                r#"["begin","headersComplete(1|1|A,1,B,2,C,3|1|/x|<undefined>|<undefined>|false|true)","complete"]"#,
            ),
        ],
        pinned: &[
            (
                "results",
                r#"["error(HPE_HEADER_OVERFLOW|Header overflow|Parse Error|25)"]"#,
            ),
            ("log", r#"["begin"]"#),
        ],
        reason: "the installed Node's initialize() takes five arguments, so a \
                 maxHeaderPairs is never applied; the pinned Node 28 added the \
                 sixth and enforces it through TrackHeaderPair.",
    },
];

/// Whether a transcript field equals a recorded JSON fragment.
///
/// The recorded side is a JSON literal, so it is parsed and compared as values
/// rather than as text: key order and whitespace then cannot make an equal
/// transcript look different.
fn matches_json(value: &serde_json::Value, expected: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(expected) {
        Ok(expected) => *value == expected,
        Err(_) => false,
    }
}

/// The comparison.
///
/// Skips when `node` is absent or too old to expose `internal/test/binding`,
/// because the crate's gate must not depend on an external binary.
#[test]
fn the_transcript_matches_a_real_node_binary() {
    let Some(node) = node_transcript() else {
        eprintln!("skipping: no usable `node` on PATH");
        return;
    };
    let ours = rust_transcript();

    if node == ours {
        return;
    }

    // Fall back to a per-case comparison so a single known difference does not
    // mask the other twenty-one cases.
    let node_cases: Vec<serde_json::Value> = serde_json::from_str(&node).expect("node transcript");
    let our_cases: Vec<serde_json::Value> =
        serde_json::from_str(&ours).expect("rustnode transcript");
    assert_eq!(
        node_cases.len(),
        our_cases.len(),
        "the two sides ran different numbers of cases"
    );

    let mut unexpected = Vec::new();
    for (installed, actual) in node_cases.iter().zip(our_cases.iter()) {
        if installed == actual {
            continue;
        }
        let name = installed["name"].as_str().unwrap_or("<unnamed>");
        let Some(known) = KNOWN_DIFFERENCES.iter().find(|known| known.case == name) else {
            unexpected.push(format!(
                "{name}\n  node:     {installed}\n  rustnode: {actual}"
            ));
            continue;
        };
        // Both sides are compared field by field rather than by substring, so a
        // change to any part of the recorded behaviour is caught: the installed
        // binary must still produce today's behaviour, and this crate must still
        // produce the pinned source's.
        let installed_matches = known
            .installed
            .iter()
            .all(|(field, expected)| matches_json(&installed[*field], expected));
        let pinned_matches = known
            .pinned
            .iter()
            .all(|(field, expected)| matches_json(&actual[*field], expected));
        if !installed_matches {
            unexpected.push(format!(
                "{name}: the installed node no longer produces the recorded behaviour, so the \
                 review note is stale\n  recorded: {}\n  actual:   {installed}",
                known.installed_summary()
            ));
        } else if !pinned_matches {
            unexpected.push(format!(
                "{name}: rustnode no longer matches the pinned source\n  recorded: {}\n  actual:   {actual}",
                known.pinned_summary()
            ));
        } else {
            eprintln!(
                "{name}: differs from the installed node and matches the pinned source; {}",
                known.reason
            );
        }
    }

    assert!(
        unexpected.is_empty(),
        "the callback transcripts differ\n\n{}",
        unexpected.join("\n\n")
    );
}
