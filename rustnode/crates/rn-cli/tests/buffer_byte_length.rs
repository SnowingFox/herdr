//! `Buffer.byteLength` agrees with `Buffer.from(s).length`, for every string.
//!
//! # What this pins
//!
//! `byteLength` counts UTF-8 bytes without producing them; `Buffer.from`
//! produces them. They are separate code paths — one walks the string and adds
//! up per-scalar widths, the other encodes — so nothing structural keeps them
//! in agreement, and a counter can be wrong in ways an encoder is not:
//!
//! * counting an unpaired surrogate as 3 but a *pair* as 6 rather than 4,
//! * counting a pair as two replacements and then also as one scalar,
//! * treating the two-byte range boundary as inclusive on the wrong side.
//!
//! # This is a regression guard, not a bug report
//!
//! Before the counter was introduced, `byteLength` was implemented by encoding
//! the string and taking the length, so it could not disagree with
//! `Buffer.from`. That implementation was correct and merely slow, and this
//! test would have passed against it. It exists to hold the rewrite to the
//! behaviour it replaced, not to demonstrate a defect that was there.
//!
//! The lone-surrogate rows are the interesting ones. Node counts an unpaired
//! surrogate as one U+FFFD, so three bytes; it does **not** use WTF-8 (which
//! would be three bytes for a different reason: `ED A0 80`) and it does not
//! drop the character. `Buffer.from` writes `EF BF BD` for the same string, so
//! agreeing here means agreeing about which of those three rules applies.

use std::process::Command;

/// The strings the two APIs must agree on.
///
/// Every entry is written as a JavaScript expression so the table can be
/// embedded in a script verbatim. The escapes matter: `'\uD800'` in a Rust
/// string literal would be a lone surrogate in a `&str`, which Rust rejects, so
/// these are JavaScript source rather than Rust values.
const CASES: &[&str] = &[
    "''",
    "'a'",
    "'é'",
    "'€'",
    "'😀'",
    "'a😀b'",
    "'\\uD800'",
    "'\\uDC00'",
    "'a\\uD800b'",
    // Not in the required table, but each one distinguishes two rules that the
    // required rows alone would not: a reversed pair, and a repeated lead.
    "'\\uDC00\\uD800'",
    "'\\uD800\\uD800'",
    // A trail surrogate that *follows* a lead but is not its pair, followed by
    // a real one. Combining greedily from the left is what makes this 7.
    "'\\uD800\\uD800\\uDC00'",
    // Range boundaries for the two- and three-byte widths.
    "'\\u007F\\u0080\\u07FF\\u0800\\uFFFF'",
    // A long ASCII string exercises the fast path the rewrite added.
    "'x'.repeat(5000)",
    // Mixed, so the fast path is entered and then rejected.
    "'x'.repeat(4999) + '€'",
    // V8 can hold a Latin-1 code point in a *two-byte* string, so the ASCII
    // fast path in `utf8_length` must test `< 0x80` rather than `< 0x100`:
    // a lone `é` is 2 bytes, not 1. This slice of a two-byte string is exactly
    // that representation, and it is why the unit table above pins `0xE9 -> 2`.
    "('\\u20ac' + '\\u00e9').slice(1)",
    // The same value in a plain one-byte string, which takes the
    // `utf8_length_from_latin1` path instead. Both must say 2.
    "'\\u00e9'",
];

/// Runs `script` under `binary` and returns its stdout.
fn run(binary: &str, script: &str) -> String {
    let output = Command::new(binary)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    assert!(
        output.status.success(),
        "{binary} failed on {script:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

/// One line of `byteLength` and `Buffer.from(...).length` per case.
fn comparison_script() -> String {
    let mut script = String::from("const cases = [\n");
    for case in CASES {
        script.push_str("  ");
        script.push_str(case);
        script.push_str(",\n");
    }
    script.push_str(
        "];\n\
         for (const text of cases) {\n\
           const counted = Buffer.byteLength(text);\n\
           const encoded = Buffer.from(text).length;\n\
           console.log(counted + ' ' + encoded + ' ' + JSON.stringify(text));\n\
         }\n",
    );
    script
}

#[test]
fn byte_length_agrees_with_from_for_every_case() {
    let output = run(env!("CARGO_BIN_EXE_rustnode"), &comparison_script());
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), CASES.len(), "one line per case: {output}");

    let mut disagreements = Vec::new();
    for (line, case) in lines.iter().zip(CASES) {
        let mut fields = line.splitn(3, ' ');
        let counted = fields.next().expect("counted length");
        let encoded = fields.next().expect("encoded length");
        if counted != encoded {
            disagreements.push(format!(
                "byteLength={counted} Buffer.from={encoded} for {case}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "Buffer.byteLength disagreed with Buffer.from(s).length:\n{}",
        disagreements.join("\n")
    );
}

/// The same table against the reference `node`, so the agreement above is
/// agreement with Node and not two implementations sharing one mistake.
#[test]
fn byte_length_matches_node() {
    let script = comparison_script();
    let expected = run("node", &script);
    let actual = run(env!("CARGO_BIN_EXE_rustnode"), &script);
    assert_eq!(actual, expected, "byte length table differs from node");
}
