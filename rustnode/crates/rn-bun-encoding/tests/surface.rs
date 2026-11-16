//! The namespace shapes, from the built runtime, compared against the recording.
//!
//! `differential.rs` covers behaviour; this covers the surface a caller inspects
//! before calling anything. Each assertion is here because getting it wrong is
//! observable and no behavioural test would notice:
//!
//! * `Bun.JSONC` has **no** `stringify`, so a member added there is a divergence in
//!   the same way a missing one is;
//! * `Bun.JSONL`'s members are non-configurable and its namespace carries
//!   `Symbol.toStringTag`, which none of its six siblings do;
//! * every member is a function with Bun's own `length` and `name`, that is not a
//!   constructor;
//! * each namespace's prototype is `Object.prototype`.
//!
//! The whole surface is also diffed against `tools/bun-surface.json`, which is the
//! recording of Bun 1.4.4's own `Object.getOwnPropertyNames(Bun)`.

use std::process::Command;

/// The built runtime.
fn rustnode() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

/// Runs `script` and returns its trimmed stdout.
///
/// The script's last expression is wrapped in `console.log(String(...))` so a
/// probe that evaluates to a value prints it: `rustnode -e` evaluates without
/// printing, unlike `node -p`. Every caller passes an expression, which is what
/// makes that wrapping safe — a statement would need its own `console.log`.
fn run(script: &str) -> String {
    let script = format!("console.log(String({script}))");
    run_raw(&script)
}

/// Runs `script` verbatim.
fn run_raw(script: &str) -> String {
    let binary = rustnode();
    let output = Command::new(&binary)
        .args(["-e", script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && !stderr.contains("Uncaught"),
        "the script failed: {stderr}"
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Each namespace's own members, in `Object.getOwnPropertyNames` order.
///
/// The order is part of the assertion because Bun's objects are built by
/// assigning in a fixed sequence, and a reordering would be visible to anything
/// that enumerates them.
#[test]
fn namespaces_have_exactly_buns_members() {
    let expected: &[(&str, &[&str])] = &[
        ("YAML", &["parse", "stringify"]),
        ("TOML", &["parse", "stringify"]),
        ("JSON5", &["parse", "stringify"]),
        ("JSONC", &["parse"]),
        ("JSONL", &["parse", "parseChunk"]),
        ("XML", &["parse", "stringify"]),
        ("markdown", &["html", "ansi", "render", "react"]),
    ];
    for (namespace, members) in expected {
        let script =
            format!("console.log(JSON.stringify(Object.getOwnPropertyNames(Bun.{namespace})))");
        let actual = run_raw(&script);
        let actual: Vec<String> = serde_json::from_str(&actual).expect("the probe emits JSON");
        assert_eq!(
            actual,
            members
                .iter()
                .map(|member| member.to_string())
                .collect::<Vec<_>>(),
            "Bun.{namespace}'s member list differs from Bun 1.4.4"
        );
    }
}

/// `Bun.JSONC.stringify` must not exist.
///
/// This is the trap the specification calls out: an implementation that adds a
/// `stringify` "for symmetry" invents surface Bun does not have, and a test that
/// merely checks the members it knows about would not see it. `typeof` is the
/// assertion rather than a member count, because a count passes whether the extra
/// member is there or the expected one is missing.
#[test]
fn jsonc_has_no_stringify() {
    assert_eq!(
        run("String(typeof Bun.JSONC.stringify)"),
        "undefined",
        "Bun.JSONC.stringify does not exist on Bun 1.4.4, so it must not exist here"
    );
    assert_eq!(
        run("String(Object.getOwnPropertyNames(Bun.JSONC).length)"),
        "1",
        "Bun.JSONC has exactly one own member"
    );
}

/// `Bun.JSONL` carries `Symbol.toStringTag` and non-configurable members.
///
/// Both are unique to this namespace in the group and both are what
/// `Object.getOwnPropertyDescriptor` reports, so they are pinned rather than left
/// to the differential, which compares values rather than descriptors.
#[test]
fn jsonl_has_its_own_namespace_shape() {
    assert_eq!(
        run("String(Object.getOwnPropertyDescriptor(Bun.JSONL, Symbol.toStringTag).value)"),
        "JSONL"
    );
    assert_eq!(
        run_raw(
            r#"console.log(JSON.stringify(Object.getOwnPropertyDescriptor(Bun.JSONL, "parse"), ["writable", "enumerable", "configurable"]))"#
        ),
        r#"{"writable":true,"enumerable":true,"configurable":false}"#,
        "Bun.JSONL's members are non-configurable, unlike its siblings'"
    );
    assert_eq!(
        run_raw(
            r#"console.log(JSON.stringify(Object.getOwnPropertyDescriptor(Bun.YAML, "parse"), ["writable", "enumerable", "configurable"]))"#
        ),
        r#"{"writable":true,"enumerable":true,"configurable":true}"#,
        "a sibling's members are configurable, which is what makes JSONL notable"
    );
}

/// Every member is a plain function with Bun's `length` and `name`, and no
/// `[[Construct]]`.
///
/// `length` and `name` are read off Bun 1.4.4 and are not cosmetic: `length` is
/// what `util.inspect` prints and `name` reaches stack traces. `new` on a member
/// throws, which is what makes these functions rather than classes.
#[test]
fn members_are_plain_named_functions() {
    let expected: &[(&str, i64)] = &[
        ("Bun.YAML.parse", 1),
        ("Bun.YAML.stringify", 3),
        ("Bun.TOML.parse", 1),
        ("Bun.TOML.stringify", 3),
        ("Bun.JSON5.parse", 1),
        ("Bun.JSON5.stringify", 3),
        ("Bun.JSONC.parse", 1),
        ("Bun.JSONL.parse", 1),
        ("Bun.JSONL.parseChunk", 1),
        ("Bun.XML.parse", 2),
        ("Bun.XML.stringify", 3),
        ("Bun.markdown.html", 1),
        ("Bun.markdown.ansi", 2),
        ("Bun.markdown.render", 3),
        ("Bun.markdown.react", 3),
    ];
    for (path, length) in expected {
        // `XML.parse` has length 2 because Bun's second argument exists and is
        // ignored; every other parse is 1.
        let script =
            format!("console.log(JSON.stringify([typeof {path}, {path}.length, {path}.name]))");
        let actual = run_raw(&script);
        let actual: Vec<serde_json::Value> =
            serde_json::from_str(&actual).expect("the probe emits JSON");
        assert_eq!(actual[0], "function", "{path} is not a function");
        assert_eq!(actual[1], *length, "{path}.length");
        assert_eq!(
            actual[2],
            path.rsplit('.').next().unwrap_or_default(),
            "{path}.name"
        );
        let constructible = run(&format!(
            "(function(){{try{{new {path}();return 'constructible'}}catch(e){{return e.constructor.name}}}})()"
        ));
        assert_eq!(
            constructible, "TypeError",
            "{path} must be a TypeError under `new`, as Bun's is"
        );
    }
}

/// Each namespace is a plain object.
#[test]
fn namespaces_are_plain_objects() {
    for namespace in ["YAML", "TOML", "JSON5", "JSONC", "JSONL", "XML", "markdown"] {
        assert_eq!(
            run(&format!(
                "String(Object.getPrototypeOf(Bun.{namespace}) === Object.prototype)"
            )),
            "true",
            "Bun.{namespace} must be a plain object"
        );
    }
}

/// Every declared member is a name Bun 1.4.4 actually has.
///
/// The registry and the gate check this too, but the check is repeated here
/// against the recorded surface so a reader can see the declaration next to the
/// evidence without opening the Python guard.
#[test]
fn declared_members_are_in_buns_recorded_surface() {
    let surface: serde_json::Value =
        serde_json::from_str(include_str!("../../../tools/bun-surface.json"))
            .expect("the surface recording is valid JSON");
    let members = surface["members"]
        .as_object()
        .expect("the recording has a members object");
    for member in rn_bun_encoding::MEMBERS {
        assert!(
            members.contains_key(*member),
            "Bun.{member} is declared by rn-bun-encoding but absent from Bun 1.4.4's \
             recorded surface"
        );
        assert_eq!(
            members[*member]["tier"], 1,
            "Bun.{member} is a Tier 1 member"
        );
        assert_eq!(
            members[*member]["kind"], "object",
            "Bun.{member} is an object on Bun 1.4.4"
        );
    }
}
