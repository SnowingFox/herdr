//! Cross-checks the binding against a real `node` binary.
//!
//! The expectations in `tests/binding.rs` are literal strings, which is right
//! for a regression test but only as good as the person who recorded them. This
//! test removes that trust: it runs the same input sequences through real Node's
//! `require('string_decoder')` and through this binding's `decode`/`flush`, then
//! compares the UTF-16 code units of every result.
//!
//! The cases skip themselves when no `node` is on `PATH`, because this crate's
//! gate must not depend on an external binary being installed. When `node` is
//! present, every case runs.
//!
//! Comparing code units rather than the strings themselves matters: it is what
//! catches a lone surrogate being normalised, a U+FFFD appearing where a
//! retained byte should have been, or `ascii` masking 0xFF to U+007F instead of
//! leaving it.

use std::process::Command;

use rn_bind_string_decoder::StringDecoder;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// One decoder session: the encoding, and the chunks written in order.
struct Case {
    encoding: &'static str,
    chunks: &'static [&'static [u8]],
    /// Whether to call `end()` and include its result.
    flush: bool,
}

/// The sequences compared against Node. They are chosen so every branch of
/// `DecodeData` and `FlushData` is reached at least once:
///
/// * UTF-8: a whole character, a character split at every interior boundary,
///   the pending character completed exactly, a non-continuation byte arriving
///   where one was expected, and invalid bytes that V8 must replace.
/// * UTF-16LE: a surrogate pair split in both halves, and a lone byte.
/// * Base64: every input length modulo three, and a group completed across
///   three writes.
/// * Hex, latin1 and ascii: inputs that need no retention, including a high
///   byte, which is where ascii and latin1 diverge.
const CASES: &[Case] = &[
    Case {
        encoding: "utf8",
        chunks: &[b"hello"],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0xF0, 0x9F], &[0x98, 0x80]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0xF0], &[0x9F, 0x98], &[0x80]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0xF0, 0x9F, 0x98], &[0x80]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0x61, 0xE2]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0xE2, 0x82], &[0xAC]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0x61, 0xF0, 0x9F], &[0x41]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0x61, 0xFF, 0x62]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0x80, 0x80, 0x80, 0x80, 0x80]],
        flush: true,
    },
    Case {
        encoding: "utf8",
        chunks: &[&[0x61], &[0xF0], &[], &[0x9F], &[0x98], &[0x80], &[0x62]],
        flush: true,
    },
    Case {
        encoding: "utf16le",
        chunks: &[&[0x3D, 0xD8], &[0x00, 0xDE]],
        flush: true,
    },
    Case {
        encoding: "utf16le",
        chunks: &[&[0x41]],
        flush: true,
    },
    Case {
        encoding: "utf16le",
        chunks: &[&[0x41, 0x00, 0x42]],
        flush: true,
    },
    Case {
        encoding: "utf16le",
        chunks: &[&[0x41, 0x00], &[0x3D, 0xD8], &[0x00, 0xDE]],
        flush: true,
    },
    Case {
        encoding: "base64",
        chunks: &[&[0x41]],
        flush: true,
    },
    Case {
        encoding: "base64",
        chunks: &[&[0x41, 0x42]],
        flush: true,
    },
    Case {
        encoding: "base64",
        chunks: &[&[0x41, 0x42, 0x43]],
        flush: true,
    },
    Case {
        encoding: "base64",
        chunks: &[&[0x41], &[0x42, 0x43], &[0x44, 0x45, 0x46, 0x47]],
        flush: true,
    },
    Case {
        encoding: "base64url",
        chunks: &[&[0x41], &[0xFB, 0xFF, 0xFF]],
        flush: true,
    },
    Case {
        encoding: "base64url",
        chunks: &[&[0xFB, 0xFF, 0xFF]],
        flush: true,
    },
    Case {
        encoding: "hex",
        chunks: &[&[0xDE, 0xAD, 0xBE, 0xEF]],
        flush: true,
    },
    Case {
        encoding: "hex",
        chunks: &[&[0x01], &[0x23]],
        flush: true,
    },
    Case {
        encoding: "latin1",
        chunks: &[&[0x41, 0xFF, 0x42, 0x80]],
        flush: true,
    },
    Case {
        encoding: "ascii",
        chunks: &[&[0x41, 0xFF, 0x42, 0x80]],
        flush: true,
    },
    // No `end()`: the decoder must still have produced the right writes.
    Case {
        encoding: "utf8",
        chunks: &[&[0x61, 0xF0, 0x9F, 0x98, 0x80, 0x62]],
        flush: false,
    },
];

/// Builds the JavaScript that runs `CASES` through real Node.
///
/// Results are the UTF-16 code units of each write, plus `end()` when the case
/// asks for it, as a flat JSON array of numbers.
fn node_script() -> String {
    let mut cases = String::new();
    for case in CASES {
        cases.push_str("  { encoding: ");
        cases.push_str(&format!("{:?}", case.encoding));
        cases.push_str(", chunks: [");
        for chunk in case.chunks {
            cases.push('[');
            let bytes: Vec<String> = chunk.iter().map(|byte| byte.to_string()).collect();
            cases.push_str(&bytes.join(","));
            cases.push_str("],");
        }
        cases.push_str("], flush: ");
        cases.push_str(if case.flush { "true" } else { "false" });
        cases.push_str(" },\n");
    }
    format!(
        r#"
const {{ StringDecoder }} = require('string_decoder');
const cases = [
{cases}];
const out = [];
for (const testCase of cases) {{
  const decoder = new StringDecoder(testCase.encoding);
  const parts = [];
  for (const chunk of testCase.chunks) {{
    parts.push(decoder.write(Buffer.from(chunk)));
  }}
  if (testCase.flush) parts.push(decoder.end());
  const units = [];
  for (const part of parts) {{
    for (let i = 0; i < part.length; i++) units.push(part.charCodeAt(i));
  }}
  out.push(units);
}}
process.stdout.write(JSON.stringify(out));
"#
    )
}

/// Runs the same cases through the binding and returns the code units.
fn binding_results() -> Vec<Vec<u16>> {
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = StringDecoder
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("string_decoder binding installs");
    let global = context.global(scope);
    let key = v8::String::new(scope, "__binding").expect("key");
    global.set(scope, key.into(), binding.into());

    // The same driver as `tests/binding.rs`, minus the assertions: this test is
    // only interested in the text, not the intermediate state.
    let harness = v8::String::new(
        scope,
        r#"
        const binding = globalThis.__binding;
        const encodingsMap = { __proto__: null };
        for (let i = 0; i < binding.encodings.length; ++i) {
          encodingsMap[binding.encodings[i]] = i;
        }
        globalThis.runCase = function runCase(encoding, chunks, flush) {
          const state = new Uint8Array(binding.kSize);
          state[binding.kEncodingField] = encodingsMap[encoding];
          const parts = [];
          for (const chunk of chunks) {
            parts.push(binding.decode(state, new Uint8Array(chunk)));
          }
          if (flush && state[binding.kBufferedBytes] > 0) {
            parts.push(binding.flush(state));
          }
          const units = [];
          for (const part of parts) {
            for (let i = 0; i < part.length; i++) units.push(part.charCodeAt(i));
          }
          return units;
        };
        "#,
    )
    .expect("source");
    let script = v8::Script::compile(scope, harness, None).expect("compiles");
    script.run(scope).expect("runs");

    let run_case = {
        let key = v8::String::new(scope, "runCase").expect("key");
        global.get(scope, key.into()).expect("runCase")
    };
    let run_case = v8::Local::<v8::Function>::try_from(run_case).expect("runCase is a function");

    let mut results = Vec::with_capacity(CASES.len());
    for case in CASES {
        let encoding = v8::String::new(scope, case.encoding).expect("encoding");
        let mut chunks = Vec::with_capacity(case.chunks.len());
        for chunk in case.chunks {
            let mut values = Vec::with_capacity(chunk.len());
            for byte in *chunk {
                values.push(v8::Integer::new(scope, i32::from(*byte)).into());
            }
            chunks.push(v8::Array::new_with_elements(scope, &values).into());
        }
        let chunks = v8::Array::new_with_elements(scope, &chunks);
        let flush = v8::Boolean::new(scope, case.flush).into();

        let returned = run_case
            .call(
                scope,
                global.into(),
                &[encoding.into(), chunks.into(), flush],
            )
            .expect("runCase returns");
        let array = v8::Local::<v8::Array>::try_from(returned).expect("array");
        let length = array.length();
        let mut units = Vec::with_capacity(length as usize);
        for index in 0..length {
            let value = array.get_index(scope, index).expect("index in range");
            let unit = value.uint32_value(scope).unwrap_or(u32::MAX);
            units.push(u16::try_from(unit).expect("a UTF-16 code unit"));
        }
        results.push(units);
    }
    results
}

/// Parses Node's flat JSON array of arrays of numbers.
fn parse_node_output(raw: &str) -> Vec<Vec<u16>> {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("[[")
        .and_then(|rest| rest.strip_suffix("]]"))
        .unwrap_or_else(|| panic!("unexpected node output: {trimmed}"));
    if body.is_empty() {
        return Vec::new();
    }
    body.split("],[")
        .map(|group| {
            group
                .split(',')
                .filter(|part| !part.is_empty())
                .map(|part| {
                    part.parse::<u16>()
                        .unwrap_or_else(|_| panic!("not a code unit: {part}"))
                })
                .collect()
        })
        .collect()
}

fn node_available() -> bool {
    Command::new("node")
        .arg("-e")
        .arg("0")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[test]
fn decoded_output_matches_node_code_unit_for_code_unit() {
    if !node_available() {
        eprintln!("skipping: no node on PATH");
        return;
    }

    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let output = Command::new("node")
        .arg("-e")
        .arg(node_script())
        .output()
        .expect("node runs");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = parse_node_output(&String::from_utf8_lossy(&output.stdout));
    let actual = binding_results();

    assert_eq!(
        actual.len(),
        expected.len(),
        "one result per case, got {} vs {}",
        actual.len(),
        expected.len()
    );

    for (index, case) in CASES.iter().enumerate() {
        assert_eq!(
            actual[index],
            expected[index],
            "case {index} ({}, {} chunk(s), flush={}) differs from node",
            case.encoding,
            case.chunks.len(),
            case.flush
        );
    }
}
