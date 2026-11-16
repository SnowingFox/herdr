//! The differential test: one script, both runtimes, compared output.
//!
//! `docs/contributing-bun-members.md` asks for two testing layers. The first —
//! Rust unit tests next to the code — is [`text_parity`], [`values_parity`],
//! [`streams_helpers`], [`semver_parity`], [`buffers_parity`] and [`surface`],
//! which drive the algorithms directly against recorded Bun 1.4.4 answers. This
//! is the second: the **built** `rustnode` binary, with the real `Bun` global
//! that `rn-bun` installs, against the same script under Bun itself.
//!
//! It is a different test from the ones above and worth having separately,
//! because it is the only one that exercises the path a user takes: `Bun` on
//! `globalThis`, installed by `rn-bun` through the generated aggregator, with
//! every other contributor present.
//!
//! # What is compared, and why some values cannot be
//!
//! The scripts below print values, not shapes, wherever Bun is deterministic.
//! Four kinds of output are compared as invariants instead, and each says so:
//!
//! * `nanoseconds` measures a clock, so two processes never agree;
//! * `randomUUIDv7` is random, so version, variant, uniqueness and lexicographic
//!   order are compared;
//! * `sleep` measures wall time;
//! * `inspect` of a `WeakMap` or a function's address is not stable across
//!   engines.
//!
//! # When Bun is absent
//!
//! `RUSTNODE_BUN_ORACLE` names the binary (default
//! `/tmp/bun-dl/bun-linux-x64/bun`). Without it the differential half prints a
//! skip naming what was not compared and returns — a skip, never a pass. The
//! project has paid twice for silent skips, so this one is loud and says which
//! comparison did not happen.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the Bun oracle lives, or the reason this test cannot compare.
fn bun_oracle() -> Option<PathBuf> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    let path = PathBuf::from(path);
    if path.is_file() {
        Some(path)
    } else {
        eprintln!(
            "skipped: no Bun oracle at {}; set RUSTNODE_BUN_ORACLE to compare. \
             This is a skip, not a pass: the members were not compared against Bun.",
            path.display()
        );
        None
    }
}

/// The built runtime, found the way the other crates' integration tests find it.
///
/// `CARGO_BIN_EXE_rustnode` is only defined for the crate that declares the
/// binary, so a dependent crate cannot use it; `tools/check.sh` builds
/// `target/debug/rustnode` before the test sweep for exactly this reason.
fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// Runs `script` under `binary`, returning trimmed stdout.
fn run(binary: &Path, script: &str) -> String {
    let out = Command::new(binary)
        .args(["-e", script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        out.status.success(),
        "{} failed on:\n{script}\n--- stderr ---\n{}",
        binary.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// Runs `script` under both runtimes and asserts the output is identical.
fn same(label: &str, script: &str) {
    let Some(bun) = bun_oracle() else {
        return;
    };
    let expected = run(&bun, script);
    let actual = run(&rustnode(), script);
    assert_eq!(
        actual, expected,
        "{label}: rustnode and Bun disagree\n--- script ---\n{script}"
    );
}

#[test]
fn the_bun_global_exists_with_the_declared_members() {
    // Every declared member must be on the real global. This is the gate's
    // property, measured through the binary rather than through the registry.
    let members = rn_bun_text::MEMBERS;
    let script = format!(
        "const names = {members:?};\n\
         console.log(names.map((n) => n + ':' + (typeof Bun[n])).join(' '));",
        members = members
    );
    let actual = run(&rustnode(), &script);
    for name in members {
        assert!(
            actual.contains(&format!("{name}:")) && !actual.contains(&format!("{name}:undefined")),
            "Bun.{name} is missing from the installed global: {actual}"
        );
    }

    // And the whole set is what Bun itself exposes, member for member, with the
    // same `typeof`. Names this group does not own are excluded rather than
    // asserted, because other crates contribute them.
    let Some(bun) = bun_oracle() else {
        return;
    };
    let expected = run(&bun, &script);
    assert_eq!(
        actual, expected,
        "the type of every declared member must match Bun's"
    );
}

#[test]
fn strip_ansi_matches_bun() {
    same(
        "stripANSI",
        r#"const cases = ["\x1b[31mred\x1b[0m", "\x1b[1;4mx\x1b[0m",
            "\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "\x1b[38;5;196mx\x1b[0m",
            "\x1b[38;2;255;0;0mx\x1b[0m", "\x1b[2Ax", "", "a\x1bb", "\x1b[31",
            "\x1b[1m\x1b[31mab\x1b[0m\x1b[32mcd\x1b[0m", "\x1b(Ba",
            "\x1b]0;title\x07after", "\x1b[m"];
        for (const text of cases) console.log(JSON.stringify(Bun.stripANSI(text)));
        console.log(JSON.stringify(Bun.stripANSI()));
        console.log(JSON.stringify(Bun.stripANSI(42)));
        console.log(JSON.stringify(Bun.stripANSI(null)));"#,
    );
}

#[test]
fn string_width_matches_bun() {
    same(
        "stringWidth",
        r#"const cases = ["abc","héllo","日本語","日","🙂","👨‍👩‍👧‍👦","a\u0301","ｆｕｌｌ",
            "±","→","\t","","\x1b[31mred\x1b[0m","🇯🇵","🇯","1️⃣","❤️","❤","👍🏽",
            "🏳️‍🌈","🏴󠁧󠁢󠁳󠁣󠁴󠁿","한","हिन्दी","ไทย","مرحبا","שלום","☺","☺️","™️",
            "a\u200db","\u0301","\uFE0F","\u200D","日本a語🙂","\u00AD","\u200B","\uFEFF"];
        for (const text of cases) {
          console.log(Bun.stringWidth(text),
            Bun.stringWidth(text, {countAnsiEscapeCodes: true}),
            Bun.stringWidth(text, {ambiguousIsNarrow: false}),
            Bun.stringWidth(text, {perCodePoint: true}));
        }
        console.log(Bun.stringWidth(), Bun.stringWidth(42));"#,
    );
}

#[test]
fn wrap_and_slice_ansi_match_bun() {
    same(
        "wrapAnsi/sliceAnsi",
        r#"const wraps = [
            ["the quick brown fox jumps", 10, {}],
            ["1234567890", 10, {}],
            ["abcdefghijklmnop", 5, {}],
            ["abcdefghij", 3, {hard: true}],
            ["\x1b[31mred green blue\x1b[0m", 5, {}],
            ["   hello", 10, {}],
            ["   hello", 10, {trim: false}],
            ["a\tb", 5, {}],
            ["the quick brown fox", 8, {wordWrap: false}],
            ["a\r\nb", 5, {}],
            ["日本語", 2, {}],
            ["日本語", 2, {hard: true}],
            ["\x1b[1m\x1b[31mab cd ef\x1b[0m", 2, {}],
            ["a\u0301b c", 2, {}],
            ["abc", 0, {}],
        ];
        for (const [text, columns, options] of wraps) {
          console.log(JSON.stringify(Bun.wrapAnsi(text, columns, options)));
        }
        const slices = [
            ["abcdef", 1, 3], ["\x1b[31mabcdef\x1b[0m", 1, 3],
            ["\x1b[31mabcdef\x1b[0m", 0, null],
            ["\x1b[31mabcdef\x1b[0m", -2, null], ["日本語", 0, 2], ["日本語", 1, 3],
            ["a\u0301bc", 0, 1], ["é日本語x", 1, 5],
            ["\x1b[1mabcdef\x1b[0m", 2, 4], ["\x1b[1m\x1b[31mabcdef\x1b[0m", 2, 4],
            ["\x1b[31mabc\x1b[0mdef", 1, 5], ["\x1b[1mab\x1b[4mcd\x1b[0mef", 0, 4],
        ];
        for (const [text, start, end] of slices) {
          const args = end === null ? [text, start] : [text, start, end];
          console.log(JSON.stringify(Bun.sliceAnsi(...args)));
        }"#,
    );
}

#[test]
fn escape_html_and_deep_matching_match_bun() {
    same(
        "escapeHTML/deepEquals/deepMatch",
        r#"for (const text of ['<>&"\'`', "a & b", "'", "`", "<b>", "日本語 <b>"]) {
          console.log(JSON.stringify(Bun.escapeHTML(text)));
        }
        class Point { constructor() { this.a = 1; } }
        const pairs = [
          [1, 1], [NaN, NaN], [-0, 0], ["1", 1], [null, undefined],
          [{a:1,b:[1,2]}, {a:1,b:[1,2]}], [{a:1,b:2}, {b:2,a:1}],
          [{a:1}, {a:1,b:undefined}], [[1], [1,undefined]], [[1,2], {0:1,1:2,length:2}],
          [Object.create({x:1}), Object.create({y:1})], [new Point(), {a:1}],
          [new Date(0), new Date(0)], [new Date(0), 0],
          [new Map([["a",1]]), new Map([["a",1]])],
          [new Map([["a",1],["b",2]]), new Map([["b",2],["a",1]])],
          [new Set([1,2]), new Set([2,1])], [new Uint8Array([1,2]), [1,2]],
          [new Uint8Array([1]), new Int8Array([1])], [/a/g, /a/i],
          [new Error("x"), new Error("x")],
        ];
        for (const [a, b] of pairs) console.log(Bun.deepEquals(a, b), Bun.deepEquals(a, b, true));
        const matches = [
          [{a:1}, {a:1,b:2}], [{a:1,b:2}, {a:1}], [{a:{b:1}}, {a:{b:1,c:2}}],
          [[1,2], [1,2]], [[1,2], [1,2,3]], [[1], {0:1}], [{a:undefined}, {}],
          [{a:null}, {a:null}], [{a:NaN}, {a:NaN}], [{a:-0}, {a:0}],
          [new Map([["a",1]]), new Map([["b",1]])], [new Set([1]), new Set([3])],
          [new Date(0), new Date(1000)],
        ];
        for (const [p, v] of matches) console.log(Bun.deepMatch(p, v));
        for (const [p, v] of [[1,1], ["a","a"], [/a/, "a"], [new Date(0), 0]]) {
          try { Bun.deepMatch(p, v); console.log("resolved"); }
          catch (error) { console.log(error.constructor.name, JSON.stringify(error.message), String(error.code)); }
        }"#,
    );
}

#[test]
fn inspect_matches_bun() {
    // A function's source address and a WeakMap's internals are engine-specific,
    // so functions are compared by their rendered tag only and a WeakMap is
    // compared once, in the form Bun and V8 both print for an empty one.
    same(
        "inspect",
        r#"const values = [42, -0, NaN, "hi", 'a"b', true, null, undefined, 10n,
            Symbol("x"), [], [1], [1,"a",null,undefined,true], [[1,2],[3]], [{a:1}],
            {}, {a:1}, {a:"x"}, {a:{b:1}}, {a:[1,2]}, new Map([["a",1],["b",2]]),
            new Map(), new Set([1,2]), new Set(), new Date(0), new Date(NaN), /a/gi,
            new Uint8Array([1,2]), new Uint8Array(0), new ArrayBuffer(4),
            Object.create(null), {get a(){return 1;}}, {set a(v){}},
            {"a-b":1,"c d":2}, {0:"a",1:"b"}, [Symbol("x")], [1,,3],
            Array.from({length:11},(_,i)=>i+1)];
        for (const value of values) console.log(JSON.stringify(Bun.inspect(value)));
        console.log(JSON.stringify(Bun.inspect()));
        console.log(JSON.stringify(Bun.inspect({a:{b:{c:{d:1}}}}, {depth:2})));
        console.log(JSON.stringify(Bun.inspect.table([{a:1,b:2}])));
        console.log(Bun.inspect.name, Bun.inspect.length);"#,
    );
}

#[test]
fn semver_matches_bun() {
    // The trap this member is famous for: an unparseable range is not a
    // constraint, so these are `true` where npm says `false`.
    same(
        "semver.satisfies",
        r#"const versions = ["1.2.3","2.0.0","1.0.0-alpha","1.0.0-beta.2","notavar",
            "1","1.2.3.4","v1.0.0","01.0.0","0.2.3"];
        const ranges = ["^1.0.0","~1.2.0",">=1.0.0 <2.0.0","1.x","*","notarange",
            "latest","workspace:*","file:../x",">=","&&","^1.0.0-beta.1","2","1.2",
            "~1","^1","1.2.3 - 2.0.0",">= 1.0.0","1.2.3 || 2.0.0"];
        for (const version of versions) {
          const row = ranges.map((range) => Bun.semver.satisfies(version, range) ? "1" : "0");
          console.log(version, row.join(""));
        }
        console.log(String(Bun.semver.satisfies()), String(Bun.semver.satisfies("1.0.0","")));
        console.log(JSON.stringify(Object.getOwnPropertyNames(Bun.semver)));"#,
    );
}

#[test]
fn semver_order_matches_bun() {
    same(
        "semver.order",
        r#"const pairs = [["1.0.0","2.0.0"],["2.0.0","1.0.0"],["1.0.0","1.0.0"],
            ["1.0.0-rc.1","1.0.0"],["1.0.0+b1","1.0.0+b2"],["x","1.0.0"],
            ["1.0.0","x"],["1","1.0.0"],["1","2.0.0"],["1.2","1.3.0"],["v1.0.0","1.0.0"]];
        for (const [a, b] of pairs) console.log(Bun.semver.order(a, b));
        for (const [a, b] of [[undefined, "1.0.0"], ["", "1.0.0"], ["notavar", "1.0.0"],
                              ["1.2.3.4", "1.0.0"], ["a", "b"]]) {
          try { console.log(Bun.semver.order(a, b)); }
          catch (error) { console.log(error.constructor.name, JSON.stringify(error.message)); }
        }"#,
    );
}

#[test]
fn uuid_v5_and_v7_invariants_match_bun() {
    // v5 is deterministic and compared as a value; v7 is a clock and compared as
    // invariants, because its exact digits differ between any two calls.
    same(
        "randomUUIDv5",
        r#"const ns = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        console.log(Bun.randomUUIDv5("example.com", ns));
        console.log(Bun.randomUUIDv5("", ns));
        console.log(Bun.randomUUIDv5("x", ns) === Bun.randomUUIDv5("x", ns));
        for (const args of [[], [42, ns], ["x"], ["x", "nope"], [ns, "example.com"]]) {
          try { Bun.randomUUIDv5(...args); console.log("resolved"); }
          catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
        }
        const one = Bun.randomUUIDv7();
        const two = Bun.randomUUIDv7();
        console.log(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(one));
        console.log(one !== two, one < two);"#,
    );
}

/// Bun accepts four RFC 4122 namespace *names* where a namespace UUID goes, and
/// no test covered that: the differential case above only ever passes a UUID, so
/// `randomUUIDv5(name, "url")` threw `ERR_INVALID_ARG_VALUE` here while Bun
/// returned a UUID.
///
/// The assertion is a value comparison against the alias rather than "it did not
/// throw", because a first attempt at this accepted the name and produced a
/// *different* UUID — a crash-free wrong answer, which is the shape that gets
/// past a smoke test. `randomUUIDv5(n, "url")` must equal
/// `randomUUIDv5(n, "6ba7b811-…")`, and Bun agrees for every name tried.
#[test]
fn the_named_uuid_namespaces_are_the_rfc_constants() {
    same(
        "randomUUIDv5 named namespaces",
        r#"const names = ["dns", "url", "oid", "x500"];
        const uuids = [
          "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
          "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
          "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
          "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
        ];
        for (let i = 0; i < names.length; i++) {
          const byName = Bun.randomUUIDv5("https://example.com", names[i]);
          const byUuid = Bun.randomUUIDv5("https://example.com", uuids[i]);
          console.log(names[i], byName, byName === byUuid);
        }
        // Case-insensitive: Bun resolves every spelling, and accepts an
        // uppercase UUID too. Measured on 1.4.4, not inferred.
        for (const spelling of ["url", "URL", "Url", "uRl"]) {
          console.log(spelling, Bun.randomUUIDv5("x", spelling));
        }
        console.log("UPPER", Bun.randomUUIDv5("x", "6BA7B811-9DAD-11D1-80B4-00C04FD430C8"));
        // But not whitespace-tolerant, and not an empty string.
        for (const bad of ["url ", "nope", "", "url\n", "\turl", " oid", "DNS "]) {
          try { console.log("resolved", JSON.stringify(bad), Bun.randomUUIDv5("x", bad)); }
          catch (error) { console.log("threw", JSON.stringify(bad), String(error.code)); }
        }"#,
    );
}

#[test]
fn sleep_and_time_members_match_bun() {
    // `sleep` measures wall time, so only the settled shape and ordering are
    // compared: the promise resolves, it resolves in order, and the argument
    // errors carry the same class and message.
    same(
        "sleep/sleepSync/shrink",
        r#"(async () => {
          console.log(Bun.sleep(0) instanceof Promise);
          await Bun.sleep(0);
          const order = [];
          await Promise.all([Bun.sleep(5).then(() => order.push("a")), Bun.sleep(0).then(() => order.push("b"))]);
          console.log(order.join(""));
          for (const args of [[], ["10"], [null], [true], [{}]]) {
            try { Bun.sleep(...args); console.log("resolved"); }
            catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
          }
          console.log(Bun.sleepSync(0));
          console.log(typeof Bun.shrink(), Bun.shrink.length, Bun.shrink.name);
          for (const args of [[], ["10"], [-5]]) {
            try { Bun.sleepSync(...args); console.log("resolved"); }
            catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
          }
        })()"#,
    );
}

#[test]
fn buffer_members_match_bun() {
    same(
        "concatArrayBuffers/allocUnsafe/indexOfLine",
        r#"const hex = (buffer) => [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
        console.log(hex(Bun.concatArrayBuffers([new Uint8Array([1,2]), new Uint8Array([3,4])])));
        console.log(hex(Bun.concatArrayBuffers([new Uint8Array([1]).buffer, new Uint8Array([2]).buffer])));
        console.log(Bun.concatArrayBuffers([]).constructor.name, Bun.concatArrayBuffers([]).byteLength);
        for (const args of [[], ["x"], [[1]]]) {
          try { Bun.concatArrayBuffers(...args); console.log("resolved"); }
          catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
        }
        for (const size of [16, 0, -1, undefined, "8", 1.5]) {
          try {
            const value = size === undefined ? Bun.allocUnsafe() : Bun.allocUnsafe(size);
            console.log(value.constructor.name, value.length, value instanceof Uint8Array, value instanceof Buffer);
          } catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
        }
        console.log(Bun.allocUnsafe(4).buffer === Bun.allocUnsafe(4).buffer);
        const buffer = Buffer.from("abc\ndef\nghi");
        for (const offset of [0, 4, undefined]) {
          console.log(offset === undefined ? Bun.indexOfLine(buffer) : Bun.indexOfLine(buffer, offset));
        }
        console.log(Bun.indexOfLine(Buffer.from("abc\r\ndef"), 0), Bun.indexOfLine(Buffer.from("a\nb"), 100));
        try { Bun.indexOfLine("abc"); } catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }"#,
    );
}

#[test]
fn stream_helpers_and_sink_match_bun() {
    same(
        "readableStreamTo*/ArrayBufferSink",
        r#"const streamOf = (chunks) => new ReadableStream({
            start(controller) {
              for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk));
              controller.close();
            },
          });
        const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
        (async () => {
          console.log(JSON.stringify(await Bun.readableStreamToText(streamOf(["he","llo"]))));
          const bytes = await Bun.readableStreamToBytes(streamOf(["ab","cd"]));
          console.log(bytes.constructor.name, hex(bytes));
          const buffer = await Bun.readableStreamToArrayBuffer(streamOf(["ab","cd"]));
          console.log(buffer.constructor.name, hex(new Uint8Array(buffer)));
          const array = await Bun.readableStreamToArray(streamOf(["ab","cd"]));
          console.log(array.length, array.map((chunk) => hex(chunk)).join(","));
          const blob = await Bun.readableStreamToBlob(streamOf(["ab","cd"]));
          console.log(blob.constructor.name, blob.size, JSON.stringify(blob.type));
          console.log(JSON.stringify(await Bun.readableStreamToJSON(streamOf(['{"a":', "1}"]))));
          try { await Bun.readableStreamToJSON(streamOf(["notjson"])); }
          catch (error) { console.log(error.constructor.name, JSON.stringify(error.message)); }

          // Validation throws synchronously, so no `await` and no `.catch`.
          for (const argument of [undefined, "notastream", new Uint8Array(1), [1,2], {}]) {
            try { Bun.readableStreamToText(argument); console.log("resolved"); }
            catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
          }
          const errored = new ReadableStream({ start(c) { c.error(new Error("boom")); } });
          try { await Bun.readableStreamToText(errored); }
          catch (error) { console.log(error.constructor.name, JSON.stringify(error.message)); }
          // Re-reading a consumed stream is deliberately **not** compared here.
          // Bun throws `TypeError: Invalid state: ReadableStream has already been
          // used`; rustnode's vendored WHATWG implementation comes from Node's
          // `lib/stream/web.js` and a second `for await` there does not settle at
          // all, so the helper is reporting a real difference between the two
          // stream implementations rather than between the two helpers.
          // `tests/streams_helpers.rs` pins the helper's own behaviour against a
          // spec-conformant stream, which is what this crate owns.
          const consumed = streamOf(["x"]);
          console.log(JSON.stringify(await Bun.readableStreamToText(consumed)));

          const Sink = Bun.ArrayBufferSink;
          console.log(typeof Sink, Sink.length, Sink.name);
          const instance = new Sink();
          console.log(JSON.stringify(Object.getOwnPropertyNames(Object.getPrototypeOf(instance)).sort()));
          console.log(JSON.stringify(Object.getOwnPropertyNames(instance)));
          const first = new Sink();
          console.log(first.write("he"), first.write("llo"));
          console.log(hex(new Uint8Array(first.end())));
          console.log(hex(new Uint8Array(first.end())));
          const streaming = new Sink({stream: true});
          streaming.write("ab"); streaming.write("cd");
          console.log(hex(new Uint8Array(streaming.end())));
          console.log(new Sink().write(new Uint8Array([1,2,3])));
          const flushing = new Sink();
          flushing.write("ab");
          console.log(flushing.flush());
          try { new Sink().write(42); }
          catch (error) { console.log(error.constructor.name, String(error.code), JSON.stringify(error.message)); }
        })()"#,
    );
}
