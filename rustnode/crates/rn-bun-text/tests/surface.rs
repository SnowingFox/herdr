//! The installed `Bun` surface: which members exist, what they report for
//! `name` and `length`, and the few property attributes that are observable.
//!
//! This is the gate the compat plan asks for in miniature. It exists because a
//! member can be present and still be wrong in a way a value test cannot see:
//! `Bun.stripANSI.length` is `1` and `Bun.wrapAnsi.length` is `3`, `Bun.semver`
//! is a read-only plain object with exactly two own keys, and
//! `Bun.inspect.custom` is `Symbol.for("nodejs.util.inspect.custom")` rather than
//! a fresh symbol. Each of those is compared against Bun 1.4.4.
//!
//! It also pins the two argument rules that disagree with each other on purpose:
//! `stripANSI()` with no argument is `"undefined"` because it stringifies, and
//! `stringWidth()` with no argument is `0` because it treats the argument as
//! absent.

use rn_bun_text::MEMBERS;
use rn_v8_sys::v8;
use serde_json::Value as Json;

mod common;

use common::{install_as_global, json_of, with_context};

/// Installs the members on a fresh object and returns a script evaluating `body`
/// with that object bound to `Bun`.
fn probe(body: &str) -> Json {
    with_context(|scope| {
        install_as_global(scope);
        let source = v8::String::new(scope, body).expect("script");
        let script = v8::Script::compile(scope, source, None).expect("compile");
        let value = script.run(scope).expect("run");
        json_of(scope, value)
    })
}

#[test]
fn every_declared_member_is_installed_with_buns_shape() {
    // The expected `(name, length)` pairs are Bun 1.4.4's, read off
    // `Object.getOwnPropertyDescriptor(Bun, name).value.length` and `.name`.
    let expected: &[(&str, i32)] = &[
        ("ArrayBufferSink", 0),
        ("allocUnsafe", 1),
        ("concatArrayBuffers", 3),
        ("deepEquals", 2),
        ("deepMatch", 2),
        ("escapeHTML", 2),
        ("indexOfLine", 1),
        ("inspect", 2),
        ("randomUUIDv5", 3),
        ("randomUUIDv7", 2),
        ("readableStreamToArray", 1),
        ("readableStreamToArrayBuffer", 1),
        ("readableStreamToBlob", 1),
        ("readableStreamToBytes", 1),
        ("readableStreamToFormData", 1),
        ("readableStreamToJSON", 1),
        ("readableStreamToText", 1),
        // `Bun.nanoseconds` is deliberately absent: `rn-bun-time` owns it, and the
        // registry rejects two crates claiming one member.
        //
        // `semver` is an object, not a function, so it has no `length`.
        ("semver", -1),
        ("shrink", 0),
        ("sleep", 1),
        ("sleepSync", 1),
        ("sliceAnsi", 5),
        ("stringWidth", 2),
        ("stripANSI", 1),
        ("wrapAnsi", 3),
    ];

    // The declared list and the expected list have to agree, so adding a member
    // to one without the other fails here rather than at the gate.
    let mut declared: Vec<&str> = MEMBERS.to_vec();
    let mut described: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
    declared.sort_unstable();
    described.sort_unstable();
    assert_eq!(declared, described, "MEMBERS and this test's list disagree");

    for (name, length) in expected {
        let actual = probe(&format!(
            "(() => {{ const d = Object.getOwnPropertyDescriptor(Bun, {name:?}); \
             if (!d) return {{ missing: true }}; \
             return {{ type: typeof d.value, name: d.value && d.value.name, \
                       length: (typeof d.value === 'function' ? d.value.length : -1) }}; }})()"
        ));
        assert_ne!(
            actual["missing"],
            Json::Bool(true),
            "{name} is declared in MEMBERS but not installed"
        );
        let expected_type = if *length < 0 { "object" } else { "function" };
        assert_eq!(actual["type"].as_str(), Some(expected_type), "{name}");
        if *length >= 0 {
            assert_eq!(
                actual["name"].as_str(),
                Some(*name),
                "{name} must be named after its property"
            );
            assert_eq!(
                actual["length"].as_i64(),
                Some(i64::from(*length)),
                "{name}.length"
            );
        }
    }
}

#[test]
fn no_member_is_missing() {
    // A direct form of the check above, so a failure names the missing member
    // instead of being buried in a shape comparison.
    let present =
        probe("(() => { const names = Object.getOwnPropertyNames(Bun).sort(); return names; })()");
    let installed: Vec<&str> = present
        .as_array()
        .expect("names array")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();
    for name in MEMBERS {
        assert!(
            installed.contains(name),
            "{name} is declared in MEMBERS but Bun has no such property; installed: {installed:?}"
        );
    }
}

#[test]
fn semver_is_a_read_only_two_key_object() {
    let actual = probe(
        r#"(() => {
            const descriptor = Object.getOwnPropertyDescriptor(Bun, 'semver');
            return {
                keys: Object.keys(Bun.semver),
                ownNames: Object.getOwnPropertyNames(Bun.semver),
                writable: descriptor.writable,
                configurable: descriptor.configurable,
                enumerable: descriptor.enumerable,
                satisfiesLength: Bun.semver.satisfies.length,
                orderLength: Bun.semver.order.length,
                satisfiesName: Bun.semver.satisfies.name,
                orderName: Bun.semver.order.name,
                plainProto: Object.getPrototypeOf(Bun.semver) === Object.prototype,
            };
        })()"#,
    );
    assert_eq!(
        actual["ownNames"],
        serde_json::json!(["satisfies", "order"])
    );
    assert_eq!(
        actual["writable"],
        Json::Bool(false),
        "Bun.semver is read-only"
    );
    assert_eq!(
        actual["configurable"],
        Json::Bool(false),
        "Bun.semver is non-configurable"
    );
    assert_eq!(actual["enumerable"], Json::Bool(true));
    assert_eq!(actual["satisfiesLength"].as_i64(), Some(2));
    assert_eq!(actual["orderLength"].as_i64(), Some(2));
    assert_eq!(actual["satisfiesName"].as_str(), Some("satisfies"));
    assert_eq!(actual["orderName"].as_str(), Some("order"));
    assert_eq!(actual["plainProto"], Json::Bool(true));
}

#[test]
fn the_two_missing_argument_rules_disagree() {
    // The measured disagreement: `stripANSI()` stringifies `undefined`, while
    // `stringWidth()` treats the argument as absent and returns `0`. These are
    // the two members a shared "coerce the first argument" helper would break.
    let actual = probe(
        "({ stripped: Bun.stripANSI(), width: Bun.stringWidth(), html: Bun.escapeHTML(), wrapped: Bun.wrapAnsi(), sliced: Bun.sliceAnsi() })",
    );
    assert_eq!(actual["stripped"].as_str(), Some("undefined"));
    assert_eq!(actual["width"].as_i64(), Some(0));
    assert_eq!(actual["html"].as_str(), Some("undefined"));
    assert_eq!(actual["wrapped"].as_str(), Some("undefined"));
    assert_eq!(actual["sliced"].as_str(), Some("undefined"));
}

#[test]
fn inspect_carries_node_symbol_and_a_table() {
    let actual = probe(
        r#"(() => ({
            customIsNodeSymbol: Bun.inspect.custom === Symbol.for('nodejs.util.inspect.custom'),
            customType: typeof Bun.inspect.custom,
            tableType: typeof Bun.inspect.table,
            tableName: Bun.inspect.table.name,
            inspectName: Bun.inspect.name,
            inspectLength: Bun.inspect.length,
            noArgument: Bun.inspect(),
        }))()"#,
    );
    assert_eq!(actual["customIsNodeSymbol"], Json::Bool(true));
    assert_eq!(actual["customType"].as_str(), Some("symbol"));
    assert_eq!(actual["tableType"].as_str(), Some("function"));
    assert_eq!(actual["tableName"].as_str(), Some("table"));
    assert_eq!(actual["inspectName"].as_str(), Some("inspect"));
    assert_eq!(actual["inspectLength"].as_i64(), Some(2));
    assert_eq!(
        actual["noArgument"].as_str(),
        Some(""),
        "inspect() with no argument is the empty string, not `\"undefined\"`"
    );
}

#[test]
fn a_member_is_an_ordinary_writable_property() {
    // Bun publishes these as plain writable, non-configurable properties. That
    // matters because `test/common` style audits read the attributes, and a
    // read-only member would be a different object shape from Bun's.
    let actual = probe(
        r#"(() => {
            const descriptor = Object.getOwnPropertyDescriptor(Bun, 'stringWidth');
            return { writable: descriptor.writable, configurable: descriptor.configurable, enumerable: descriptor.enumerable };
        })()"#,
    );
    assert_eq!(actual["writable"], Json::Bool(true));
    assert_eq!(actual["configurable"], Json::Bool(false));
    assert_eq!(actual["enumerable"], Json::Bool(true));
}
