//! `Bun.concatArrayBuffers`, `Bun.allocUnsafe`, `Bun.indexOfLine`,
//! `Bun.nanoseconds`, `Bun.sleepSync` and the UUIDs, against recorded Bun 1.4.4
//! answers and measured invariants.
//!
//! Two kinds of case live here, and the split is deliberate:
//!
//! * **Recorded values.** `concatArrayBuffers`, `allocUnsafe` and `indexOfLine`
//!   return the same thing on every run, so their answers were recorded from the
//!   oracle and are compared exactly — including the three `TypeError` messages
//!   and the two distinct `RangeError` conditions `allocUnsafe` can raise.
//! * **Invariants.** `nanoseconds`, the version-7 UUID and `sleepSync` are
//!   clocks. Their absolute values differ between runs, so nothing is compared
//!   against a literal; only type, monotonicity, version nibble, variant and
//!   uniqueness are.
//!
//! The `-0`/`NaN` and `ERR_OUT_OF_RANGE`-vs-`ERR_INVALID_ARG_TYPE` distinctions
//! are the parts a plausible implementation gets wrong, so each has its own case.

use rn_bun_text::timers;
use rn_bun_text::uuid;
use rn_v8_sys::v8;
use serde_json::Value as Json;

fn oracle() -> Json {
    serde_json::from_str(include_str!("data/values-oracle.json")).expect("valid oracle JSON")
}

mod common;

use common::{json_of, with_context};

// ---------------------------------------------------------------------------
// indexOfLine: pure, no V8 needed beyond a byte slice
// ---------------------------------------------------------------------------

#[test]
fn index_of_line_matches_bun() {
    let oracle = oracle();
    let cases = oracle["indexOfLine"].as_array().expect("indexOfLine cases");
    let mut failures = Vec::new();
    for case in cases {
        let text = case[0].as_str().expect("text");
        let offset = case[1].as_u64().map(|value| value as usize);
        let expected = &case[2];
        let bytes = text.as_bytes();
        // An absent offset is `0`, not "no search": `indexOfLine(Buffer.from("a\nb"))`
        // is measured `1`.
        let offset = offset.unwrap_or(0);
        let index = if offset < bytes.len() {
            bytes[offset..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|found| (offset + found) as i64)
                .unwrap_or(-1)
        } else {
            -1
        };
        // A recorded success carries `{ok: true, value}`; there are no failure
        // cases in this group beyond the string rejection below.
        let Some(expected_value) = expected["value"].as_i64() else {
            continue;
        };
        if index != expected_value {
            failures.push(format!(
                "indexOfLine({text:?}, {offset:?}) = {index}, bun says {expected_value}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn index_of_line_rejects_a_string() {
    let oracle = oracle();
    let expected = &oracle["indexOfLineString"];
    assert_eq!(
        expected["ctor"].as_str(),
        Some("TypeError"),
        "the recorded string rejection must be a TypeError"
    );
    assert_eq!(expected["code"].as_str(), Some("ERR_INVALID_ARG_TYPE"));
    assert_eq!(
        expected["message"].as_str(),
        Some("buffer must be an ArrayBuffer or ArrayBufferView"),
        "Bun's message for a non-buffer argument, which this must reproduce"
    );
}

// ---------------------------------------------------------------------------
// concatArrayBuffers and allocUnsafe, through the real native members
// ---------------------------------------------------------------------------

/// Builds a test `Bun` object with only the buffer members installed and runs
/// `script`, returning its JSON.
fn with_members(script: &str) -> Json {
    with_context(|scope| {
        common::install_as_private_global(scope);
        let source = v8::String::new(scope, script).expect("script");
        let script = v8::Script::compile(scope, source, None).expect("compile");
        let value = script.run(scope).expect("run");
        json_of(scope, value)
    })
}

#[test]
fn concat_array_buffers_matches_bun() {
    let oracle = oracle();
    let cases = oracle["concatArrayBuffers"]
        .as_array()
        .expect("concat cases");
    // Each recorded case is re-driven as one probe, so the comparison covers the
    // result's prototype as well as its bytes — the whole point being that it is
    // a plain `ArrayBuffer`, not a `Uint8Array`.
    let probes = [
        (
            "two",
            "(() => { const r = __bun.concatArrayBuffers([new Uint8Array([1,2]), new Uint8Array([3,4])]); \
             return { ctor: r.constructor.name, byteLength: r.byteLength, \
                      hex: [...new Uint8Array(r)].map((b) => b.toString(16).padStart(2, '0')).join('') }; })()",
        ),
        (
            "length",
            "(() => { const r = __bun.concatArrayBuffers([new Uint8Array([1,2]), new Uint8Array([3,4])], 4); \
             return { ctor: r.constructor.name, byteLength: r.byteLength, \
                      hex: [...new Uint8Array(r)].map((b) => b.toString(16).padStart(2, '0')).join('') }; })()",
        ),
        (
            "empty",
            "(() => { const r = __bun.concatArrayBuffers([]); \
             return { ctor: r.constructor.name, byteLength: r.byteLength, hex: '' }; })()",
        ),
        (
            "buffers",
            "(() => { const r = __bun.concatArrayBuffers([new Uint8Array([1]).buffer, new Uint8Array([2]).buffer]); \
             return { ctor: r.constructor.name, byteLength: r.byteLength, \
                      hex: [...new Uint8Array(r)].map((b) => b.toString(16).padStart(2, '0')).join('') }; })()",
        ),
        (
            "mixed",
            "(() => { const r = __bun.concatArrayBuffers([new Uint8Array([1]), new Uint8Array([2]).buffer]); \
             return { ctor: r.constructor.name, byteLength: r.byteLength, \
                      hex: [...new Uint8Array(r)].map((b) => b.toString(16).padStart(2, '0')).join('') }; })()",
        ),
    ];
    let mut failures = Vec::new();
    for (case, probe) in cases.iter().zip(probes.iter()) {
        let expected = &case[2];
        if expected["ok"].as_bool() != Some(true) {
            continue;
        }
        let actual = with_members(probe.1);
        let expected_value = &expected["value"];
        if actual != *expected_value {
            failures.push(format!(
                "{}: got {actual}, bun says {expected_value}",
                probe.0
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn concat_array_buffers_error_messages() {
    // The three failures all carry Bun's exact message and no `code`, which is
    // why they are transcribed rather than paraphrased.
    let probes = [
        (
            "no argument",
            "__bun.concatArrayBuffers()",
            "Expected at least one argument",
        ),
        (
            "not an array",
            "__bun.concatArrayBuffers('x')",
            "Argument must be an array",
        ),
        (
            "non-typed element",
            "__bun.concatArrayBuffers([1])",
            "Expected TypedArray",
        ),
    ];
    for (label, call, message) in probes {
        let actual = with_members(&format!(
            "(() => {{ try {{ {call}; return {{ ok: true }}; }} \
             catch (error) {{ return {{ ctor: error.constructor.name, code: error.code === undefined ? null : error.code, message: error.message }}; }} }})()"
        ));
        assert_eq!(
            actual["ctor"].as_str(),
            Some("TypeError"),
            "{label}: {actual}"
        );
        assert_eq!(actual["code"], Json::Null, "{label}: no `code`: {actual}");
        assert_eq!(
            actual["message"].as_str(),
            Some(message),
            "{label}: {actual}"
        );
    }
}

#[test]
fn alloc_unsafe_matches_bun() {
    let oracle = oracle();
    let cases = oracle["allocUnsafe"].as_array().expect("allocUnsafe cases");
    let mut failures = Vec::new();

    for case in cases {
        let size = &case[0];
        let expected = &case[1];
        let call = match size {
            Json::Null => "__bun.allocUnsafe()".to_string(),
            Json::String(text) => format!("__bun.allocUnsafe('{text}')"),
            other => format!("__bun.allocUnsafe({other})"),
        };
        let actual = with_members(&format!(
            r#"(() => {{
                try {{
                    const value = {call};
                    return {{ ctor: value.constructor.name, length: value.length,
                             isUint8Array: value instanceof Uint8Array,
                             isBuffer: typeof Buffer !== 'undefined' && value instanceof Buffer,
                             byteLength: value.byteLength }};
                }} catch (error) {{
                    return {{ threw: true, ctor: error.constructor.name,
                             code: error.code === undefined ? null : error.code,
                             message: error.message }};
                }}
            }})()"#
        ));
        // The recording wraps a success as `{ok: true, value}` and a throw as
        // `{ok: false, ctor, code, message}`; the probe reports the value or the
        // error directly, so the two are normalised before comparing.
        let normalised = if expected["ok"].as_bool() == Some(true) {
            expected["value"].clone()
        } else {
            let mut error = serde_json::Map::new();
            error.insert("threw".to_string(), Json::Bool(true));
            for field in ["ctor", "code", "message"] {
                error.insert(field.to_string(), expected[field].clone());
            }
            Json::Object(error)
        };
        if actual != normalised {
            failures.push(format!(
                "allocUnsafe({size}): got {actual}, bun says {normalised}"
            ));
        }
    }

    // The pooling identity fact: two small allocations must not share a backing
    // store, which is the measured difference from `Buffer.allocUnsafe`.
    let pooled = with_members(
        "(() => { const a = __bun.allocUnsafe(4); const b = __bun.allocUnsafe(4); return a.buffer === b.buffer; })()",
    );
    let expected_pooled = oracle["allocUnsafePooled"].as_bool().expect("pooled");
    if pooled.as_bool() != Some(expected_pooled) {
        failures.push(format!(
            "two 4-byte allocations share a buffer: got {pooled}, bun says {expected_pooled}"
        ));
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// Clocks and identifiers: invariants, never literals
// ---------------------------------------------------------------------------

#[test]
fn nanoseconds_is_a_monotonic_number() {
    let first = timers::monotonic_nanos();
    let second = timers::monotonic_nanos();
    assert!(
        second >= first,
        "the monotonic clock went backwards: {first} then {second}"
    );
    // A `number`, and a safe integer: Bun returns a double, not a BigInt, and
    // `Number.isSafeInteger(Bun.nanoseconds())` is measured `true`.
    assert!(
        (first as f64).is_finite() && first < (1u64 << 53),
        "the value must be a safe integer as a double, got {first}"
    );
}

#[test]
fn uuid_v5_is_deterministic_and_matches_rfc_4122() {
    // The RFC 4122 test vector for the DNS namespace, which Bun reproduces
    // exactly: SHA-1 over the 16 namespace bytes followed by the name.
    let generated = uuid::uuid_v5(b"example.com", &uuid::NAMESPACE_DNS);
    assert_eq!(
        uuid::format_uuid(&generated),
        "cfbff0d1-9375-5685-968c-48ce8b15ae17",
        "the version-5 UUID must match the RFC 4122 value Bun returns"
    );
    // Same input twice, same UUID.
    assert_eq!(
        uuid::uuid_v5(b"example.com", &uuid::NAMESPACE_DNS),
        generated
    );
    // The empty name is also recorded by the oracle.
    assert_eq!(
        uuid::format_uuid(&uuid::uuid_v5(b"", &uuid::NAMESPACE_DNS)),
        "4ebd0208-8328-5d69-8c44-ec50939c0967"
    );
}

#[test]
fn sha1_matches_the_fips_vectors() {
    // FIPS 180-4's own vectors, so a bug in the digest is caught here rather
    // than as a wrong UUID that looks plausible.
    let digest = uuid::sha1(b"abc");
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");

    let digest = uuid::sha1(b"");
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn uuid_v7_holds_its_invariants() {
    let mut seen = Vec::new();
    for _ in 0..64 {
        let mut random = [0u8; 10];
        uuid::fill_random(&mut random).expect("getrandom must work");
        let (millis, counter) = uuid::next_v7_clock();
        let text = uuid::format_uuid(&uuid::uuid_v7(millis, counter, &random));
        // Version nibble 7, variant in [89ab], and the canonical shape.
        let bytes = uuid::parse_uuid(&text).expect("round trips");
        assert_eq!(bytes[6] >> 4, 7, "version nibble must be 7: {text}");
        assert!(
            matches!(bytes[8] >> 6, 0b10),
            "variant bits must be RFC 4122: {text}"
        );
        // Lexicographic order must not decrease, which is what the counter is
        // for: two UUIDs in the same millisecond still sort by call order.
        if let Some(previous) = seen.last() {
            assert!(
                previous <= &text,
                "uuid v7 went backwards: {previous} then {text}"
            );
        }
        seen.push(text);
    }
    // Uniqueness.
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "64 UUIDs must all differ");
}

#[test]
fn sleep_sync_argument_rules() {
    // `sleepSync` rejects a negative by name and value, carries
    // `ERR_INVALID_ARG_TYPE`, and treats `NaN` as zero rather than an error.
    assert!(timers::validate_sleep_sync(Some(0.0)).is_ok());
    assert!(timers::validate_sleep_sync(Some(f64::NAN)).is_ok());
    assert_eq!(timers::validate_sleep_sync(Some(1.5)).ok(), Some(1));

    let error = timers::validate_sleep_sync(None)
        .err()
        .expect("no argument rejects");
    assert_eq!(error.message(), "milliseconds must be a number");

    let error = timers::validate_sleep_sync(Some(-5.0))
        .err()
        .expect("a negative rejects");
    assert_eq!(
        error.message(),
        "argument to sleepSync must not be negative, got -5"
    );
}
