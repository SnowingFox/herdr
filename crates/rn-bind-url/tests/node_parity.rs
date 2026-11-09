//! Cross-checks the binding against a real `node` binary.
//!
//! Every expectation here is produced by running Node, not by reading its
//! source, so a mistake in reading `node_url.cc` shows up as a test failure
//! instead of as a silently different runtime. The tables cover the cases the
//! definitions of done call out: credentials, default ports, IPv6 hosts, `file:`
//! URLs, percent-encoded paths, relative resolution against a base, and invalid
//! input.
//!
//! The tests skip when no `node` is on `PATH`, so the crate's gate does not
//! depend on an external binary; when `node` is present every assertion runs.
//!
//! # How the comparison works
//!
//! Node's `url` binding answers with a serialized href and writes nine numbers
//! into `urlComponents`. That is exactly the pair this crate produces, so the
//! comparison is component for component: for each input, run
//! `binding.parse(input, base, false)` here and `bindingUrl.parse(...)` there,
//! then compare the href and all nine offsets. `canParse` is checked on the same
//! table against `parse`, which is the agreement the two are required to have.

use std::process::Command;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_url::Url;

fn node_available() -> bool {
    Command::new("node")
        .arg("-e")
        .arg("0")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// The two lines every Node-side snippet needs: the internal binding, aliased
/// to the same name the V8-side snippets use.
const NODE_PRELUDES: &str =
    "const { internalBinding } = require('internal/test/binding');\nconst urlBinding = internalBinding('url');\n";

/// Runs a Node script and returns its stdout.
fn node_script(source: &str) -> String {
    let out = Command::new("node")
        .arg("--expose-internals")
        .arg("-e")
        .arg(source)
        .output()
        .expect("node runs");
    assert!(
        out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn initialize_once() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// One input's result from the binding: the href and the nine components.
#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    /// `None` when the input did not parse.
    href: Option<String>,
    /// Nine offsets, or empty when `href` is `None`.
    components: Vec<u32>,
}

/// Evaluates `source` with the namespace installed and returns `String(__out)`.
fn eval(source: &str) -> String {
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
    let namespace = Url.install(scope, &mut ctx).expect("install");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "urlBinding").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set");

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    script.run(scope).expect("runs");

    let out_key = v8::String::new(scope, "__out").expect("key");
    let out = global.get(scope, out_key.into()).expect("__out");
    out.to_rust_string_lossy(scope)
}

/// Parses one input with the binding, reading back the components buffer.
fn parse_here(input: &str, base: Option<&str>) -> Parsed {
    let source = format!(
        r#"
        const base = {base};
        const href = urlBinding.parse({input}, base, false);
        globalThis.__out = JSON.stringify({{
          href: href === undefined ? null : href,
          components: href === undefined ? [] : Array.from(urlBinding.urlComponents),
        }});
        "#,
        input = js_string(input),
        base = base.map_or("undefined".to_string(), js_string),
    );
    let raw = eval(&source);
    parse_result(&raw)
}

/// Parses one input with a real Node binding.
fn parse_there(input: &str, base: Option<&str>) -> Parsed {
    let source = format!(
        r#"
        const {{ internalBinding }} = require('internal/test/binding');
        const b = internalBinding('url');
        const base = {base};
        const href = b.parse({input}, base, false);
        console.log(JSON.stringify({{
          href: href === undefined ? null : href,
          components: href === undefined ? [] : Array.from(b.urlComponents),
        }}));
        "#,
        input = js_string(input),
        base = base.map_or("undefined".to_string(), js_string),
    );
    parse_result(&node_script(&source))
}

/// Reads `{"href": .., "components": [..]}` without pulling in a JSON library.
///
/// The shape is fixed and produced by code above, so a hand-rolled reader is
/// enough; `serde_json` in dev-dependencies covers the cases where the input
/// could contain something awkward.
fn parse_result(raw: &str) -> Parsed {
    let value: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    let href = match value.get("href") {
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        _ => None,
    };
    let components = value
        .get("components")
        .and_then(|list| list.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|item| item.as_u64().map(|number| number as u32))
                .collect()
        })
        .unwrap_or_default();
    Parsed { href, components }
}

/// Renders a Rust string as a JavaScript string literal.
fn js_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Escaping every non-ASCII character keeps the literal safe to embed
            // in a `-e` argument regardless of the caller's locale.
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Runs `parse` here and in Node for every case, asserting they agree.
fn assert_parse_parity(cases: &[(&str, Option<&str>)]) {
    assert_parse_parity_expecting(cases, true)
}

/// `assert_parse_parity`, with the anti-vacuity guard made optional so a table
/// that is deliberately all-failures can still be checked.
fn assert_parse_parity_expecting(cases: &[(&str, Option<&str>)], expect_mostly_valid: bool) {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let mut failures = Vec::new();
    let mut parsed_ok = 0usize;
    for (input, base) in cases {
        let here = parse_here(input, *base);
        let there = parse_there(input, *base);
        if here.href.is_some() {
            parsed_ok += 1;
            assert_eq!(here.components.len(), 9, "components for {input:?}");
        }
        if here != there {
            failures.push(format!(
                "input {input:?} base {base:?}\n  rust: {here:?}\n  node: {there:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases disagree:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
    // Guard against a vacuous pass: if the harness silently produced nothing,
    // every comparison above would have "agreed" on nothing at all.
    if expect_mostly_valid {
        assert!(
            parsed_ok > cases.len() / 2,
            "only {parsed_ok} of {} cases parsed; the harness is not reading results",
            cases.len()
        );
    }
}

/// The URLs the definitions of done require, plus the shape edges around them.
const PARSE_CASES: &[&str] = &[
    // Credentials and authorities.
    "https://user:pw@example.com:8080/a/b?q=1#f",
    "http://user@example.com/",
    "http://user:@example.com/",
    "http://:@example.com/",
    "http://@example.com/",
    "http://:p@h/",
    "https://user:pa@ex.com/",
    // Default ports.
    "http://example.com:80/",
    "https://example.com:443/x",
    "ftp://example.com:21/x",
    "ws://example.com:80/x",
    "wss://example.com:443/x",
    "http://example.com:0/",
    "http://example.com:/",
    // IPv6 hosts.
    "http://[::1]/",
    "http://[::1]:8080/x?q#h",
    "http://[2001:db8::1]/p",
    "http://[::ffff:1.2.3.4]/",
    // file URLs.
    "file:///tmp/x",
    "file:///tmp/a b.txt",
    "file://localhost/etc/passwd",
    "file://host/share/x",
    "file:/tmp/x",
    "file:///tmp/x?q#h",
    // Percent-encoded paths and other components.
    "http://example.com/a%20b/c",
    "http://example.com/a%2Fb",
    "http://example.com/%zz",
    "http://example.com/a b",
    "http://example.com/ü",
    "http://example.com/?q=a b",
    "http://example.com/?q=a+b",
    "http://example.com/#a b",
    "http://ex%41mple.com/",
    // Empty and bare components.
    "http://example.com",
    "http://example.com/",
    "http://example.com/?",
    "http://example.com/#f",
    "http://example.com/?#",
    "http://example.com/?#f",
    // Non-special schemes and opaque paths.
    "foo://bar/baz?x#y",
    "foo://bar",
    "foo://bar/",
    "foo:/bar",
    "foo:bar",
    "foo:/bar?q#h",
    "mailto:a@b.c",
    "data:text/plain,hi",
    "about:blank",
    "javascript:alert(1)",
    "urn:isbn:0451450523",
    "sc://ñ.test/",
    // Path normalisation.
    "http://example.com/a/../b",
    "http://example.com/a/./b",
    "http://example.com/../",
    "http://example.com/a/b/../../",
    "http://example.com/%2e%2e/x",
    "http://example.com/foo//bar",
    "http:/example.com",
    "http:example.com",
    "HTTP://EXAMPLE.COM/",
    "http://EXAMPLE.com/Path",
    "http://example.com\\a\\b",
    // IPv4 shorthand, which is host parsing rather than a lookup.
    "http://0x7f.1/",
    "http://127.1/",
    // IDN.
    "http://例え.テスト/",
    "http://xn--r8jz45g.xn--zckzah/",
    "http://faß.de/",
    "http://☃.net/",
    // Characters that differ per component's encode set.
    "http://example.com/~",
    "http://example.com/!",
    "http://example.com/'()",
    "http://example.com/[]{}|",
    "http://example.com/^`\"",
    "http://example.com/<>",
    // Invalid input.
    "://bad",
    "",
    "//example.com",
    "http://",
    "http://exa mple.com/",
    "http://example.com:65536/",
    "http://example.com:999999/",
    "https://exam_ple.com/x",
    "https://example..com/x",
];

/// Relative resolutions against each kind of base.
const RESOLUTION_CASES: &[(&str, Option<&str>)] = &[
    ("c", Some("http://example.com/a/b?q#f")),
    ("../c", Some("http://example.com/a/b?q#f")),
    ("../../c", Some("http://example.com/a/b?q#f")),
    ("/c", Some("http://example.com/a/b?q#f")),
    ("?x", Some("http://example.com/a/b?q#f")),
    ("#h", Some("http://example.com/a/b?q#f")),
    ("", Some("http://example.com/a/b?q#f")),
    ("./", Some("http://example.com/a/b?q#f")),
    ("..", Some("http://example.com/a/b?q#f")),
    (".", Some("http://example.com/a/b?q#f")),
    ("//other/z", Some("http://example.com/a/b?q#f")),
    ("%41", Some("http://example.com/a/b?q#f")),
    ("a b", Some("http://example.com/a/b?q#f")),
    ("c?d#e", Some("http://example.com/a/b?q#f")),
    ("/c/../d", Some("http://example.com/a/b?q#f")),
    ("?", Some("http://example.com/a/b?q#f")),
    ("#", Some("http://example.com/a/b?q#f")),
    ("c", Some("http://example.com/a/b/")),
    ("../c", Some("http://example.com/a/b/")),
    ("c", Some("file:///tmp/x/y")),
    ("../c", Some("file:///tmp/x/y")),
    ("/c", Some("file:///tmp/x/y")),
    ("c", Some("foo://bar/baz/qux")),
    ("c", Some("foo:/a/b")),
    ("c", Some("https://u:p@h:9/x/y")),
    // A URL that cannot be a base refuses relative input.
    ("c", Some("mailto:a@b.c")),
    ("#h", Some("mailto:a@b.c")),
    // A base that does not parse makes the whole thing fail.
    ("c", Some("bad base")),
    ("https://ok.test/x", Some("bad base")),
    // An absolute input ignores the base entirely.
    ("https://other.test/z", Some("http://example.com/a")),
];

#[test]
fn parse_matches_node_for_the_required_url_shapes() {
    let cases: Vec<(&str, Option<&str>)> = PARSE_CASES.iter().map(|input| (*input, None)).collect();
    assert_parse_parity(&cases);
}

#[test]
fn parse_matches_node_when_resolving_against_a_base() {
    assert_parse_parity(RESOLUTION_CASES);
}

#[test]
fn parse_matches_node_for_every_failure_case() {
    // The failures are already inside the tables above; this names them so a
    // failure reports which class regressed rather than only which string.
    let cases: Vec<(&str, Option<&str>)> = [
        "://bad",
        "",
        "//example.com",
        "http://",
        "http://exa mple.com/",
    ]
    .iter()
    .map(|input| (*input, None))
    .collect();
    assert_parse_parity_expecting(&cases, false);
}

#[test]
fn can_parse_agrees_with_parse_on_every_case() {
    // `ada::can_parse` is defined to agree with `ada::parse`; this asserts the
    // same of the Rust pair, on both the absolute and the relative tables.
    let mut cases: Vec<(&str, Option<&str>)> =
        PARSE_CASES.iter().map(|input| (*input, None)).collect();
    cases.extend_from_slice(RESOLUTION_CASES);

    let mut source = String::from("const cases = [\n");
    for (input, base) in &cases {
        source.push_str(&format!(
            "[{}, {}],\n",
            js_string(input),
            base.map_or("undefined".to_string(), js_string)
        ));
    }
    source.push_str(
        r#"];
        const out = [];
        for (const [input, base] of cases) {
          const canParse = base === undefined
            ? urlBinding.canParse(input)
            : urlBinding.canParse(input, base);
          const parsed = base === undefined
            ? urlBinding.parse(input, undefined, false)
            : urlBinding.parse(input, base, false);
          out.push([canParse, parsed !== undefined]);
        }
        globalThis.__out = JSON.stringify(out);
        "#,
    );
    let raw = eval(&source);
    let results: Vec<(bool, bool)> = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(results.len(), cases.len(), "one result per case");

    let disagreements: Vec<String> = results
        .iter()
        .enumerate()
        .filter(|(_, (can_parse, parses))| can_parse != parses)
        .map(|(index, (can_parse, parses))| {
            let (input, base) = cases[index];
            format!("{input:?} base {base:?}: canParse={can_parse} parse={parses}")
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "canParse and parse disagree:\n{}",
        disagreements.join("\n")
    );
}

#[test]
fn can_parse_matches_node_on_every_case() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let mut cases: Vec<(&str, Option<&str>)> =
        PARSE_CASES.iter().map(|input| (*input, None)).collect();
    cases.extend_from_slice(RESOLUTION_CASES);

    let mut here_source = String::from("const cases = [\n");
    let mut there_source = String::from(
        "const { internalBinding } = require('internal/test/binding');\nconst b = internalBinding('url');\nconst cases = [\n",
    );
    for (input, base) in &cases {
        let entry = format!(
            "[{}, {}],\n",
            js_string(input),
            base.map_or("undefined".to_string(), js_string)
        );
        here_source.push_str(&entry);
        there_source.push_str(&entry);
    }
    here_source.push_str(
        r#"];
        globalThis.__out = JSON.stringify(cases.map(([input, base]) =>
          base === undefined ? urlBinding.canParse(input) : urlBinding.canParse(input, base)));
        "#,
    );
    there_source.push_str(
        r#"];
        console.log(JSON.stringify(cases.map(([input, base]) =>
          base === undefined ? b.canParse(input) : b.canParse(input, base))));
        "#,
    );

    let here: Vec<bool> = serde_json::from_str(&eval(&here_source)).expect("valid JSON");
    let there: Vec<bool> = serde_json::from_str(&node_script(&there_source)).expect("valid JSON");
    assert_eq!(here, there, "canParse disagrees with node");
}

#[test]
fn update_matches_node_on_every_action_and_value() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let actions = [
        "kProtocol",
        "kHost",
        "kHostname",
        "kPort",
        "kUsername",
        "kPassword",
        "kPathname",
        "kSearch",
        "kHash",
        "kHref",
    ];
    let bases = [
        "https://user:pw@example.com:8080/a/b?q=1#f",
        "http://example.com/",
        "file:///tmp/x",
        "foo://bar/baz",
        "foo:/bar",
        "mailto:a@b.c",
        "http://[::1]:8080/x",
        "https://ex.com:443/x",
    ];
    let values = [
        "",
        "x",
        "/p q",
        "http",
        "https",
        "ftp",
        "file",
        "foo",
        "a b",
        "%41",
        "\u{e9}",
        "99999",
        "0",
        "8080",
        "#h",
        "?q=2",
        "example.org",
        "[::2]",
        "bad host",
        ":",
        "//x",
        "a@b",
        "a:80",
        "a:",
        "80a",
        "65535",
        "OTHER.test",
        "/a/../b",
    ];

    let mut cases = String::new();
    for base in bases {
        for action in actions {
            for value in values {
                cases.push_str(&format!(
                    "[{}, {}, {}],\n",
                    js_string(base),
                    js_string(action),
                    js_string(value)
                ));
            }
        }
    }
    let body = format!(
        r#"const cases = [{cases}];
        const A = {{kProtocol:0,kHost:1,kHostname:2,kPort:3,kUsername:4,kPassword:5,kPathname:6,kSearch:7,kHash:8,kHref:9}};
        const out = cases.map(([base, action, value]) => {{
          const result = urlBinding.update(base, A[action], value);
          return result === false ? false : result;
        }});"#
    );
    let here = eval(&format!("{body}\nglobalThis.__out = JSON.stringify(out);"));
    let there = node_script(&format!(
        "{}{body}\nconsole.log(JSON.stringify(out));",
        NODE_PRELUDES
    ));

    let here: Vec<serde_json::Value> = serde_json::from_str(&here).expect("valid JSON");
    let there: Vec<serde_json::Value> = serde_json::from_str(&there).expect("valid JSON");
    assert_eq!(here.len(), there.len());
    let mut disagreements = Vec::new();
    let mut known = Vec::new();
    for (index, (mine, theirs)) in here.iter().zip(there.iter()).enumerate() {
        if mine == theirs {
            continue;
        }
        let base = bases[index / (actions.len() * values.len())];
        let rest = index % (actions.len() * values.len());
        let action = actions[rest / values.len()];
        let value = values[rest % values.len()];
        let report = format!("base {base:?} {action}({value:?})\n  rust: {mine}\n  node: {theirs}");
        // The one documented divergence: the url crate cannot represent a
        // `file:` URL whose path begins `//`, so `set_pathname("//x")` on a
        // `file:` URL yields the folded path. See the crate docs.
        if is_known_path_divergence(base, action, value) {
            known.push(report);
        } else {
            disagreements.push(report);
        }
    }
    assert!(
        known.len() <= 1,
        "the known file://// divergence grew to {} cases:\n{}",
        known.len(),
        known.join("\n")
    );
    assert!(
        disagreements.is_empty(),
        "{} of {} update cases disagree:\n{}",
        disagreements.len(),
        there.len(),
        disagreements
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Whether a mismatch is the documented `file:` double-slash divergence rather
/// than a bug. Kept as an explicit predicate so a *new* mismatch in the same
/// place still fails, and so the reason lives next to the assertion.
fn is_known_path_divergence(base: &str, action: &str, value: &str) -> bool {
    base.starts_with("file:") && action == "kPathname" && value.starts_with("//")
}

#[test]
fn format_matches_node_for_every_flag_combination() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let hrefs = [
        "https://user:pw@example.com:8080/a/b?q=1#f",
        "http://example.com/",
        "http://example.com/?",
        "http://example.com/#",
        "http://example.com/?#",
        "file:///tmp/x",
        "foo://bar/baz?x#y",
        "mailto:a@b.c",
        "http://xn--9ca.com:8080/x?q#h",
        "http://[::1]:8080/x?q#h",
        "http://example.com/\u{fc}?q=\u{fc}#\u{fc}",
        "https://example.com/x",
    ];
    let mut cases = String::new();
    for href in hrefs {
        for fragment in [true, false] {
            for unicode in [true, false] {
                for search in [true, false] {
                    for auth in [true, false] {
                        cases.push_str(&format!(
                            "[{}, {}, {}, {}, {}],\n",
                            js_string(href),
                            fragment,
                            unicode,
                            search,
                            auth
                        ));
                    }
                }
            }
        }
    }
    let body = format!(
        r#"const cases = [{cases}];
        const out = cases.map(([href, fragment, unicode, search, auth]) =>
          urlBinding.format(href, fragment, unicode, search, auth));"#
    );
    let here = eval(&format!("{body}\nglobalThis.__out = JSON.stringify(out);"));
    let there = node_script(&format!(
        "{}{body}\nconsole.log(JSON.stringify(out));",
        NODE_PRELUDES
    ));
    let here: Vec<String> = serde_json::from_str(&here).expect("valid JSON");
    let there: Vec<String> = serde_json::from_str(&there).expect("valid JSON");
    assert_eq!(here.len(), there.len());
    let disagreements: Vec<String> = here
        .iter()
        .zip(there.iter())
        .enumerate()
        .filter(|(_, (mine, theirs))| mine != theirs)
        .map(|(index, (mine, theirs))| {
            let rest = index % 16;
            let href_index = index / 16;
            format!(
                "href {hrefs:?}[{href_index}] flags fragment={} unicode={} search={} auth={}\n  rust: {mine:?}\n  node: {theirs:?}",
                rest & 1 == 0,
                (rest >> 1) & 1 == 0,
                (rest >> 2) & 1 == 0,
                (rest >> 3) & 1 == 0
            )
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} format cases disagree:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}

#[test]
fn get_origin_matches_node() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let hrefs = [
        "https://user:pw@example.com:8080/a?q#f",
        "http://example.com",
        "file:///x",
        "file://host/x",
        "foo://bar/x",
        "mailto:a@b.c",
        "blob:https://example.com/u",
        "blob:http://x:8080/u",
        "blob:file:///x",
        "blob:null/x",
        "about:blank",
        "data:,x",
        "http://[::1]:8080/",
        "ws://x:80/",
        "ftp://x:21/",
        "https://example.com:443/",
        "http://u@x:1/",
    ];
    let mut cases = String::new();
    for href in hrefs {
        cases.push_str(&format!("{},\n", js_string(href)));
    }
    let body = format!(
        r#"const cases = [{cases}];
        const out = cases.map((href) => {{
          try {{ return urlBinding.getOrigin(href); }}
          catch (error) {{ return ['threw', error.code]; }}
        }});"#
    );
    let here = eval(&format!("{body}\nglobalThis.__out = JSON.stringify(out);"));
    let there = node_script(&format!(
        "{}{body}\nconsole.log(JSON.stringify(out));",
        NODE_PRELUDES
    ));
    assert_eq!(here, there, "getOrigin disagrees with node");
}

#[test]
fn get_origin_throws_the_same_error_as_node() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let body = r#"const out = (() => {
          try { urlBinding.getOrigin('bad url'); return ['no throw']; }
          catch (error) { return [error.name, error.code, error.message, error.input]; }
        })();"#;
    let here = eval(&format!("{body}\nglobalThis.__out = JSON.stringify(out);"));
    let there = node_script(&format!(
        "{NODE_PRELUDES}{body}\nconsole.log(JSON.stringify(out));"
    ));
    assert_eq!(here, there, "the ERR_INVALID_URL shape disagrees");
}

#[test]
fn path_to_file_url_matches_node() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let paths = [
        "/tmp/x",
        "/tmp/a b",
        "/tmp/a%20b",
        "/tmp/a%b",
        "/tmp/~user",
        "/tmp/a#b",
        "/tmp/a?b",
        "/tmp/a[b]",
        "/tmp/a^b",
        "/tmp/a|b",
        "/tmp/a\"b",
        "/tmp/\u{e9}",
        "/tmp/a\tb",
        "/tmp/a\nb",
        "/tmp/a\rb",
        "/",
        "/tmp/a:b",
        "/tmp/a@b",
        "/tmp/a\\b",
        "/tmp/a-b_c.d!e",
        "/tmp/a&b=c+d",
        "/tmp/a;b",
        "/tmp/a*b",
        "/tmp/a$b",
        "/tmp/a'b",
        "/tmp/a(b)",
        "/tmp/a,b",
        "/tmp/a<b>",
        "/tmp/a{b}",
        "/tmp/a`b",
    ];
    let mut cases = String::new();
    for path in paths {
        cases.push_str(&format!("{},\n", js_string(path)));
    }
    let body = format!(
        r#"const cases = [{cases}];
        const out = cases.map((path) => urlBinding.pathToFileURL(path, false));"#
    );
    let here = eval(&format!("{body}\nglobalThis.__out = JSON.stringify(out);"));
    let there = node_script(&format!(
        "{}{body}\nconsole.log(JSON.stringify(out));",
        NODE_PRELUDES
    ));
    let here: Vec<String> = serde_json::from_str(&here).expect("valid JSON");
    let there: Vec<String> = serde_json::from_str(&there).expect("valid JSON");
    let disagreements: Vec<String> = here
        .iter()
        .zip(there.iter())
        .enumerate()
        .filter(|(_, (mine, theirs))| mine != theirs)
        .map(|(index, (mine, theirs))| {
            format!(
                "path {:?}\n  rust: {mine:?}\n  node: {theirs:?}",
                paths[index]
            )
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} of {} pathToFileURL cases disagree:\n{}",
        disagreements.len(),
        there.len(),
        disagreements.join("\n")
    );
}

#[test]
fn domain_members_match_node() {
    if !node_available() {
        eprintln!("node is not installed; skipping the parity check");
        return;
    }
    let domains = [
        "example.com",
        "EXAMPLE.COM",
        "xn--nxasmq6b.xn--j6w193g",
        "\u{4f8b}\u{3048}.\u{30c6}\u{30b9}\u{30c8}",
        "fa\u{df}.de",
        "stra\u{df}e.de",
        "\u{21d2}.com",
        "\u{2603}.net",
        "xn--n3h.net",
        "xn--",
        "xn--a",
        "a..b",
        ".a",
        "a.",
        "a b.com",
        "a_b.com",
        "\u{ad}.com",
        "xn--nxasmq6b",
        "\u{130}.com",
        "\u{3c2}.gr",
        "\u{3a3}.gr",
        "\u{fffd}.com",
        "xn--ls8h.la",
        "1.2.3.4",
        "[::1]",
        "0x7f.1",
        "%41.com",
        "a%2eb.com",
        "\u{ff21}\u{ff22}\u{ff23}.com",
        "xn--fiqs8s",
        "xn--fiqz9s",
        "a/b",
        "a?b",
        "a\\b",
        "a@b",
        "example.com:80",
        "",
    ];
    let mut cases = String::new();
    for domain in domains {
        cases.push_str(&format!("{},\n", js_string(domain)));
    }
    let body = format!(
        r#"const cases = [{cases}];
        const out = cases.map((domain) => [
          urlBinding.domainToASCII(domain),
          urlBinding.domainToUnicode(domain),
        ]);"#
    );
    let here = eval(&format!("{body}\nglobalThis.__out = JSON.stringify(out);"));
    let there = node_script(&format!(
        "{}{body}\nconsole.log(JSON.stringify(out));",
        NODE_PRELUDES
    ));
    let here: Vec<(String, String)> = serde_json::from_str(&here).expect("valid JSON");
    let there: Vec<(String, String)> = serde_json::from_str(&there).expect("valid JSON");
    let disagreements: Vec<String> = here
        .iter()
        .zip(there.iter())
        .enumerate()
        .filter(|(_, (mine, theirs))| mine != theirs)
        .map(|(index, (mine, theirs))| {
            format!(
                "domain {:?}\n  rust: ascii={:?} unicode={:?}\n  node: ascii={:?} unicode={:?}",
                domains[index], mine.0, mine.1, theirs.0, theirs.1
            )
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} of {} domain cases disagree:\n{}",
        disagreements.len(),
        there.len(),
        disagreements.join("\n")
    );
}
