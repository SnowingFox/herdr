//! Unit tests for the lexer glue.
//!
//! Two layers are tested here and they check different things.
//!
//! [`merve`] runs the linked lexer directly through [`crate::ffi`], with no V8
//! involved. That is where a vendoring mistake shows up: a wrong object file, a
//! build that dropped a define, a struct layout that no longer matches the C
//! header.
//!
//! [`binding`] installs the namespace into a real isolate and calls `parse` as
//! JavaScript, so it covers the part this crate actually owns: the `[Set, Array]`
//! shape, the argument handling, and the fact that the `Set` is a real `Set`.
//!
//! The recorded expectations live in `tests/node_expected.json`, produced by
//! `tests/record.cjs` under a real `node --expose-internals`. Read the module
//! docs on [`crate::ffi`] before changing a case: several of merve's answers are
//! the opposite of the obvious rule, and `object_named`, `define_property_getter`
//! and `es_module_marker` exist specifically to pin those.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::ffi;
use crate::CjsLexer;

/// The cases in `tests/node_expected.json`, in the same order.
///
/// Kept as an array rather than read from the JSON so a case name that the
/// fixture has and this list does not is a test failure instead of a silently
/// unchecked recording. `parity.rs` compares the two sets.
pub(crate) const CASES: &[(&str, &str)] = &[
    ("empty", ""),
    ("whitespace", "\n\n  \n"),
    ("plain_script", "const a = 1;\nfunction f() { return 2; }\n"),
    ("object_shorthand", "module.exports = {a, b};"),
    ("object_named", "module.exports = { a: 1 };"),
    (
        "object_mixed",
        "const a = 1;\nmodule.exports = { a, b: 2, c };\n",
    ),
    ("exports_dot", "exports.x = 1;"),
    (
        "exports_dedup",
        "exports.a = 1;\nexports.b = 2;\nexports.a = 3;",
    ),
    ("module_exports_dot", "module.exports.z = 42;"),
    (
        "bracket_quoted",
        "exports['quoted'] = 1;\nexports[\"double\"] = 2;",
    ),
    (
        "define_property_value",
        "Object.defineProperty(exports, 'd1', { value: 1 });",
    ),
    (
        "define_property_getter",
        "Object.defineProperty(exports, 'd3', { get() { return 1; } });",
    ),
    (
        "es_module_marker",
        "Object.defineProperty(exports, \"__esModule\", { value: true });\nexports.real = 1;",
    ),
    ("nested_member", "exports.a.b = 1;"),
    ("shadowed_exports", "var exports = {}; exports.nope = 1;"),
    ("reexport_direct", "module.exports = require('./other');"),
    (
        "reexport_spread",
        "module.exports = { ...require('./spread'), own: 1 };",
    ),
    (
        "reexport_babel",
        "var __export = 0;\n__export(require('./z'));",
    ),
    (
        "reexport_object_keys",
        "Object.keys(require('./keys')).forEach(function (k) { exports[k] = 1; });",
    ),
    (
        "esm_import",
        "import foo from \"bar\";\nexport default foo;\n",
    ),
    ("esm_export", "export const q = 1;\n"),
    ("unterminated_string", "var s = 'unterminated"),
    ("unbalanced_brace", "function f() {"),
    ("unicode_escape", "exports['\\u0061b'] = 1;"),
    ("multiline", "exports.one = 1;\n\nexports.two = 2;\n"),
    ("template_literal", "exports.t = `a${1}b`;"),
];

// ---------------------------------------------------------------------------
// The lexer itself
// ---------------------------------------------------------------------------

mod merve {
    use super::*;

    #[test]
    fn linked_library_is_the_vendored_one() {
        assert_eq!(ffi::version(), crate::MERVE_VERSION);
    }

    #[test]
    fn empty_source_parses_into_no_exports() {
        // Not a failure: merve answers "nothing here" and Node reports that as
        // an empty pair rather than as an error.
        let parsed = ffi::parse_commonjs("").expect("empty source parses");
        assert!(parsed.exports.is_empty());
        assert!(parsed.reexports.is_empty());
    }

    #[test]
    fn esm_syntax_is_a_failed_analysis() {
        // `None`, not `Some(empty)`: the distinction is what tells the test
        // below that Node's empty result comes from the glue, not the lexer.
        assert!(ffi::parse_commonjs("export const q = 1;\n").is_none());
        assert!(ffi::parse_commonjs("import a from 'b';\n").is_none());
    }

    #[test]
    fn unterminated_literals_are_a_failed_analysis() {
        assert!(ffi::parse_commonjs("var s = 'oops").is_none());
        assert!(ffi::parse_commonjs("var t = `oops").is_none());
    }

    #[test]
    fn object_shorthand_exports_only_bare_names() {
        // The named form is not an export; this is the rule a hand-written
        // lexer most often gets backwards, so it is asserted directly as well
        // as through the recording.
        let parsed =
            ffi::parse_commonjs("module.exports = { a, b: 2, c };").expect("source parses");
        assert_eq!(parsed.exports, ["a"]);
    }

    #[test]
    fn reexports_are_specifiers_not_names() {
        let parsed =
            ffi::parse_commonjs("module.exports = require('./other');").expect("source parses");
        assert!(parsed.exports.is_empty());
        assert_eq!(parsed.reexports, ["./other"]);
    }

    #[test]
    fn escaped_export_names_are_unescaped() {
        // `\u0061b` is `ab`, which merve materialises into its own buffer; that
        // is the path that proves the borrow in `Analysis` is load-bearing.
        let parsed = ffi::parse_commonjs("exports['\\u0061b'] = 1;").expect("source parses");
        assert_eq!(parsed.exports, ["ab"]);
    }

    #[test]
    fn the_source_buffer_is_not_retained() {
        // A source that is dropped immediately must still produce correct
        // names: if merve retained the pointer rather than the glue copying
        // while the borrow is live, this would read freed memory under a
        // sanitizer and is a use-after-free regardless.
        let parsed = {
            let owned = String::from("exports.kept = 1;");
            ffi::parse_commonjs(&owned).expect("source parses")
        };
        assert_eq!(parsed.exports, ["kept"]);
    }
}

// ---------------------------------------------------------------------------
// The namespace, through V8
// ---------------------------------------------------------------------------

mod binding {
    use super::*;

    fn initialize_once() {
        static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INIT.get_or_init(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });
    }

    /// Installs the namespace, runs `source` in a fresh context, and returns the
    /// script's result as JSON.
    ///
    /// `source` is expected to assign to a `result` variable; returning a value
    /// from a classic script is not possible, and the JSON round-trip keeps the
    /// assertion on the Rust side independent of V8 handle lifetimes.
    fn run(source: &str) -> String {
        initialize_once();
        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let mut context_scope = std::pin::pin!(v8::ContextScope::new(scope, context));
        let scope = &mut context_scope;

        let mut async_ids = rn_core::AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let namespace = CjsLexer
            .install(scope, &mut ctx)
            .expect("install cjs_lexer");
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "binding").expect("allocate key");
        global.set(scope, key.into(), namespace.into());

        let source = v8::String::new(scope, source).expect("allocate source");
        let script = v8::Script::compile(scope, source, None).expect("compile");
        script.run(scope).expect("run");

        let json = v8::String::new(scope, "JSON.stringify(result)").expect("allocate json");
        let script = v8::Script::compile(scope, json, None).expect("compile json");
        let value = script.run(scope).expect("run json");
        value
            .to_string(scope)
            .expect("result is a string")
            .to_rust_string_lossy(scope)
    }

    /// `run` for one recorded case, answering `{"exports": [...], "reexports": [...]}`.
    fn parse_case(source: &str) -> serde_json::Value {
        let script = format!(
            "const [set, arr] = binding.parse({});\n\
             const result = {{ exports: Array.from(set), reexports: Array.from(arr) }};",
            js_string(source)
        );
        serde_json::from_str(&run(&script)).expect("result is JSON")
    }

    /// A JS string literal for `text`.
    ///
    /// `serde_json`'s escaping is valid JS, so the two sides cannot drift on a
    /// literal the way a hand-rolled escaper would.
    fn js_string(text: &str) -> String {
        serde_json::to_string(text).expect("string serializes")
    }

    #[test]
    fn installs_exactly_one_member() {
        assert_eq!(CjsLexer.namespace(), "cjs_lexer");
        assert_eq!(CjsLexer.members(), ["parse"]);
        // The contract is one member, and nothing is deferred; a deferral here
        // would be invisible to `rn-compat` because the namespace would cover
        // its contract either way.
        assert!(CjsLexer.deferred().is_empty());
    }

    #[test]
    fn plain_script_and_empty_input_have_no_exports() {
        for source in ["", "const a = 1;\n"] {
            let value = parse_case(source);
            assert_eq!(value["exports"], serde_json::json!([]));
            assert_eq!(value["reexports"], serde_json::json!([]));
        }
    }

    #[test]
    fn missing_null_and_undefined_return_an_empty_pair() {
        // Node treats all three the same, and the shape is a real `[Set, Array]`
        // rather than an empty array, so a caller destructuring it works.
        let result = run(
            "const shapes = [binding.parse(), binding.parse(null), binding.parse(undefined)];\n\
             const result = shapes.map(([set, arr]) => [\
               set instanceof Set, set.size, Array.isArray(arr), arr.length\
             ]);",
        );
        assert_eq!(result, "[[true,0,true,0],[true,0,true,0],[true,0,true,0]]");
    }

    #[test]
    fn returns_a_set_and_an_array() {
        let result = run("const pair = binding.parse('exports.x = 1;');\n\
             const result = [\
               Array.isArray(pair), pair.length,\
               pair[0] instanceof Set, pair[1] instanceof Array,\
               typeof pair[0].add,\
             ];");
        assert_eq!(result, "[true,2,true,true,\"function\"]");
    }

    #[test]
    fn export_names_are_internalized() {
        // Node creates them with `kInternalized`, and these names are compared
        // against property keys, so the same content must be the same string.
        let result = run("const [set] = binding.parse('exports.shared = 1;');\n\
             const [name] = Array.from(set);\n\
             const internalized = 'shared';\n\
             const result = [name === internalized, name === ('sha' + 'red')];");
        assert_eq!(result, "[true,true]");
    }

    #[test]
    fn a_non_string_argument_throws_instead_of_aborting() {
        // Node `CHECK`s here and aborts the process. Throwing keeps the caller's
        // mistake visible without a crash.
        let result = run("let thrown = 'none';\n\
             try { binding.parse(123); } catch (error) { thrown = error.name; }\n\
             const result = thrown;");
        assert_eq!(result, "\"TypeError\"");
    }

    #[test]
    fn every_recorded_case_matches_node() {
        let recorded: serde_json::Value =
            serde_json::from_str(rn_bind_cjs_lexer_fixture()).expect("fixture is JSON");
        let recorded = recorded.as_object().expect("fixture is an object");

        // The case list and the recording must describe the same cases; a name
        // on one side only would otherwise go unchecked.
        let mut expected_names: Vec<&str> = recorded.keys().map(String::as_str).collect();
        let mut listed: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
        expected_names.sort_unstable();
        listed.sort_unstable();
        assert_eq!(expected_names, listed);

        for (name, source) in CASES {
            let expected = &recorded[*name];
            let actual = parse_case(source);
            assert_eq!(
                actual["exports"], expected["exports"],
                "case {name}: export names differ from the node recording"
            );
            assert_eq!(
                actual["reexports"], expected["reexports"],
                "case {name}: reexport specifiers differ from the node recording"
            );
        }
    }
}

/// The recording, included so the test binary carries it.
pub(crate) fn rn_bind_cjs_lexer_fixture() -> &'static str {
    include_str!("../tests/node_expected.json")
}
