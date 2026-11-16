//! Cross-checks the binding against a real `node` binary.
//!
//! Every expectation here is produced by running Node, not by reading its
//! source, so a mistake in reading `node_url.cc` shows up as a test failure
//! instead of as a silently different runtime. The tables cover the cases the
//! definitions of done call out: credentials, default ports, IPv6 hosts, `file:`
//! URLs, percent-encoded paths, relative resolution against a base, invalid
//! input, and — for `update` — every one of the ten actions over a value table
//! built to hit each guard.
//!
//! # Which `node` this runs
//!
//! The oracle is the nightly rustnode tracks, resolved in this order:
//!
//! 1. `HERDR_URL_ORACLE`, an absolute path to a `node` binary.
//! 2. `$HOME/.cache/herdr-oracle/node`, the path the harness uses when it
//!    downloads the pinned build.
//! 3. `node` on `PATH`, with a warning.
//!
//! The `PATH` fallback is a known hazard and is deliberately loud: this image's
//! default is v22, which answers differently from the v28 nightly in this
//! crate's area (`^` in paths, the `update` guards, malformed punycode), so a
//! v22 run reports disagreements that are not defects and would pass over ones
//! that are. A test that cannot find the pinned oracle still runs — the tables
//! are cheap — but prints which binary it compared against.
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

/// The Node build this crate's expectations are pinned to.
const PINNED_ORACLE_VERSION: &str = "v28.0.0-nightly20261111e8c1160d20";

/// Absolute paths to try before falling back to `PATH`.
///
/// The pinned nightly is what the project's own instructions name; the cache
/// path is where a harness that downloads it would put it.
fn oracle_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(explicit) = std::env::var("HERDR_URL_ORACLE") {
        if !explicit.is_empty() {
            candidates.push(explicit);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!("{home}/.cache/herdr-oracle/node"));
        candidates.push(format!(
            "{home}/.cache/herdr-oracle/node-{PINNED_ORACLE_VERSION}-linux-x64/bin/node"
        ));
    }
    candidates.push(format!(
        "/tmp/oracle-dl/node-{PINNED_ORACLE_VERSION}-linux-x64/bin/node"
    ));
    candidates
}

/// The oracle binary, or `None` when none of the candidates exists.
fn oracle() -> Option<String> {
    for candidate in oracle_candidates() {
        let runs = Command::new(&candidate)
            .arg("-e")
            .arg("0")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if runs {
            return Some(candidate);
        }
    }
    Command::new("node")
        .arg("-e")
        .arg("0")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|_| "node".to_string())
}

/// The oracle, with a warning when it is not the pinned build.
fn node_binary() -> Option<String> {
    let binary = oracle()?;
    if binary == "node" {
        eprintln!(
            "warning: no pinned node oracle found; comparing against `node` on PATH \
             (expected {PINNED_ORACLE_VERSION}). Set HERDR_URL_ORACLE to override."
        );
    }
    Some(binary)
}

/// The two lines every Node-side snippet needs: the internal binding, aliased
/// to the same name the V8-side snippets use.
const NODE_PRELUDES: &str =
    "const { internalBinding } = require('internal/test/binding');\nconst urlBinding = internalBinding('url');\n";

/// Runs a Node script and returns its stdout.
///
/// The script is passed on stdin rather than as `-e`, because the sweeps here
/// build case tables far past `ARG_MAX` and `execve` fails with
/// `ArgumentListTooLong` long before the script itself is unreasonable.
fn node_script(source: &str) -> String {
    use std::io::Write;
    use std::process::Stdio;

    let binary = node_binary().expect("the caller checked the oracle exists");
    let mut child = Command::new(&binary)
        .arg("--expose-internals")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node starts");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(source.as_bytes())
        .expect("the script fits on stdin");
    let out = child.wait_with_output().expect("node runs");
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
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
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
    // file URLs, including the double-slash paths an aggregator must hold.
    "file:///tmp/x",
    "file:///tmp/a b.txt",
    "file://localhost/etc/passwd",
    "file://host/share/x",
    "file:/tmp/x",
    "file:///tmp/x?q#h",
    "file:////a",
    "file:////",
    "file:////a/b",
    "file://///a",
    "file:/.//a",
    "file:/.//",
    "file://host//x",
    "file://host///x",
    "file://h/.//x",
    "file:////a/./b",
    "file:////a?q#h",
    "file:////../a",
    "file:.//x",
    "file:/..//x",
    "file:///c|/x",
    "file:///c|",
    "file://h/c|/x",
    "file:///c|?q",
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
    // The path percent-encode set, which is where `^` lives.
    "http://a/x^y",
    "http://a/^",
    "http://example.com/^`\"",
    "http://a/x^y?q^#h^",
    "http://a/%2e%2e/^",
    "http://a/x^y/%2e%2e/",
    "file:///a^b",
    "file:///c:/x^",
    "foo:/p^",
    "foo://a/p^",
    "foo:/.//x^y",
    // Empty and bare components.
    "http://example.com",
    "http://example.com/",
    "http://example.com/?",
    "http://example.com/#f",
    "http://example.com/?#",
    "http://example.com/?#f",
    // An opaque path keeps a trailing space only when nothing follows it.
    "foo:a b",
    "foo:a ?q",
    "foo:a #h",
    "foo:a  ",
    "foo:^ ",
    "foo:%20",
    // Non-special schemes and opaque paths, including the `/.` guard.
    "foo://bar/baz?x#y",
    "foo://bar",
    "foo://bar/",
    "foo:/bar",
    "foo:bar",
    "foo:/bar?q#h",
    "foo:/.//x",
    "foo:/.//x?q#h",
    "foo:/.//",
    "foo:////a",
    "foo:////",
    "foo:////a?q",
    "foo://///a",
    "http:/.//x",
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
    // IDN, and the ASCII fast path that skips UTS #46 validation.
    "http://例え.テスト/",
    "http://xn--r8jz45g.xn--zckzah/",
    "http://faß.de/",
    "http://☃.net/",
    "http://xn--a/",
    "http://xn--zz/",
    "http://xn--/",
    "http://xn--a.com/",
    "http://XN--A/",
    "http://xn--a-/",
    "http://xn--a./",
    "http://xn--a..b/",
    "http://xn--0.com/",
    "http://a.xn--a/",
    "http://xn--a%41/",
    "http://xn--%41/",
    "http://ẞ.com/",
    "http://ＡＢＣ.com/",
    // Characters that differ per component's encode set.
    "http://example.com/~",
    "http://example.com/!",
    "http://example.com/'()",
    "http://example.com/[]{}|",
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
    "http://xn--a.1/",
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
    ("//x", Some("file:///a")),
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
        "http://xn--a.1/",
    ]
    .iter()
    .map(|input| (*input, None))
    .collect();
    assert_parse_parity_expecting(&cases, false);
}

#[test]
fn can_parse_agrees_with_parse_on_every_case() {
    // `ada::can_parse` is defined to agree with `ada::parse`; this asserts the
    // same of the binding pair, on both the absolute and the relative tables.
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
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
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

/// One `update` case: a base URL, an action name, and a value.
type UpdateCase = (&'static str, &'static str, &'static str);

/// The actions, in `updateActions` order.
const ACTIONS: &[&str] = &[
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

/// Base URLs chosen so that every guard has something to preserve.
///
/// Each entry is a shape a guard branches on: credentials present or not, a port
/// present or not, an authority present or not, a `file:` URL, an opaque path,
/// an explicit empty query or fragment, and the double-slash `file:` path that
/// the previous implementation could not represent at all.
const UPDATE_BASES: &[&str] = &[
    "https://user:pw@example.com:8080/a/b?q=1#f",
    "http://example.com/",
    "http://a/?",
    "http://a/#",
    "http://a/?#",
    "http://orig:81/x",
    "https://ex.com:443/x",
    "http://[::1]:8080/x",
    "http://a:9/x",
    "file:///tmp/x",
    "file://host/tmp/x",
    "file:////a",
    "file://host//x",
    "foo://bar/baz",
    "foo:/bar",
    "foo:bar",
    "foo:/.//x",
    "foo:////a",
    "mailto:a@b.c",
    "data:,x",
];

/// Values chosen to hit each guard, plus the characters whose encode sets
/// differ per component.
///
/// Grouped by the guard they exercise so a failure names the class:
///
/// * encoding: `^`, space, backslash, the sigils, `%`, non-ASCII;
/// * delimiter truncation: `/`, `?`, `\`, `:`, `#` inside a host value;
/// * port acceptance: leading digit vs not, out of range, empty;
/// * scheme refusal: special vs not, capitals, trailing text;
/// * path shape: `//`, dot segments, trailing space, drive letters;
/// * malformed punycode, which the ASCII fast path must accept.
const UPDATE_VALUES: &[&str] = &[
    // Nothing / clearing.
    "",
    "?",
    "#",
    "?#",
    "??",
    "##",
    // Host delimiters.
    "x",
    "x/y",
    "x\\y",
    "x?y",
    "x#y",
    "x:y",
    "x:",
    ":",
    ":80",
    "a:80",
    "a:99999",
    "a:x1",
    "a b",
    "a b:80",
    "[::1]",
    "[::1]:81",
    "[::1",
    "%2e",
    "..",
    "a..b",
    "localhost",
    "EXAMPLE.ORG",
    "example.org",
    // Ports.
    "0",
    "1",
    "1x",
    "x1",
    "x0y",
    "80a",
    "0009",
    "0080",
    "65535",
    "65536",
    "99999",
    "-1",
    "+80",
    " 80",
    "80 ",
    "\t",
    // Schemes.
    "http",
    "https",
    "ftp",
    "file",
    "FILE",
    "foo",
    "wss",
    "a:80",
    // Credentials.
    "a b",
    "a^b",
    "a\tb",
    // Paths.
    "/",
    "//",
    "//x",
    "///x",
    "/p q",
    "/x ",
    "/x  ",
    " ",
    "\t",
    "x/y",
    "x\\y",
    "\\z",
    "/x^y",
    "^",
    "/a/../b",
    "a/../../b",
    "/a/.",
    "/a/..",
    "..",
    ".",
    "/C:/x",
    "c:/x",
    "C|/x",
    "c|",
    "/%zz",
    "/%41",
    "/%2e%2e",
    "/a//b",
    "/x\t",
    // Search and hash payloads.
    "?q=2",
    "?a^b",
    "?a'b",
    "? ",
    "#h",
    "#a^b",
    "  a",
    " a",
    // Hosts the ASCII fast path must accept.
    "xn--a",
    "xn--zz",
    "xn--",
    "xn--a.com",
    "xn--a:1",
    "XN--A",
    "xn--a.",
    // Whole-URL replacement.
    "file:///y",
    "file:////y",
    "not a url",
    "http://b/x^y",
    "foo:/x^y",
    "\u{e9}",
    "\u{2603}.net",
];

/// The full cross product, built once per test that needs it.
fn update_cases() -> Vec<UpdateCase> {
    let mut cases = Vec::with_capacity(UPDATE_BASES.len() * ACTIONS.len() * UPDATE_VALUES.len());
    for base in UPDATE_BASES {
        for action in ACTIONS {
            for value in UPDATE_VALUES {
                cases.push((*base, *action, *value));
            }
        }
    }
    cases
}

/// Runs one batch of `update` cases through both runtimes and returns the
/// disagreements, paired with the case that produced them.
fn update_disagreements(cases: &[UpdateCase]) -> Vec<(UpdateCase, String, String)> {
    let source_cases = {
        let mut text = String::new();
        for (base, action, value) in cases {
            text.push_str(&format!(
                "[{}, {}, {}],\n",
                js_string(base),
                js_string(action),
                js_string(value)
            ));
        }
        text
    };
    let body = format!(
        r#"const cases = [{source_cases}];
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
    assert_eq!(here.len(), there.len(), "one result per case");
    assert_eq!(here.len(), cases.len(), "one result per case");

    here.iter()
        .zip(there.iter())
        .enumerate()
        .filter(|(_, (mine, theirs))| mine != theirs)
        .map(|(index, (mine, theirs))| (cases[index], mine.to_string(), theirs.to_string()))
        .collect()
}

#[test]
fn update_matches_node_on_every_action_and_value() {
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
        return;
    }
    let cases = update_cases();
    // Batched so one disagreement does not require running the whole cross
    // product again, and so a single script stays a sane size.
    let mut disagreements = Vec::new();
    for chunk in cases.chunks(2_000) {
        disagreements.extend(update_disagreements(chunk));
    }
    let report: Vec<String> = disagreements
        .iter()
        .take(20)
        .map(|((base, action, value), mine, theirs)| {
            format!("base {base:?} {action}({value:?})\n  rust: {mine}\n  node: {theirs}")
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} of {} update cases disagree:\n{}",
        disagreements.len(),
        cases.len(),
        report.join("\n")
    );
}

/// The 0x00–0xFF sweep: every byte, through parse and through every action.
///
/// This is the table that found the `^` divergence. It is kept as a sweep rather
/// than as a list of the characters that used to differ, so a change to a
/// percent-encode set on either side shows up as a named byte instead of as an
/// unnoticed new delta.
///
/// It drives `parse` and `update` rather than the JS `URL` class, for two
/// reasons: those are the two members through which every byte reaches ada, and
/// the binding is the same object in both runtimes, so one script body runs
/// unchanged in the bare isolate and under Node. `update` covers the setters the
/// class would have called, one action per row.
#[test]
fn every_byte_matches_node_in_every_component() {
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
        return;
    }

    // Rows are `[kind, payload, action]`; `kind` is "parse" or "update".
    let mut rows: Vec<(String, String, String, String)> = Vec::new();
    for byte in 0u32..0x100 {
        let c = char::from_u32(byte)
            .expect("a single code unit")
            .to_string();
        let label = format!("{byte:02x}");
        let mid = format!("a{c}b");

        // Parsing, per component. Each label names the encode set under test.
        for (component, href) in [
            ("parse.path", format!("http://a/p{c}q")),
            ("parse.pathfile", format!("file:///a{c}b")),
            ("parse.query", format!("http://a/?a{c}b")),
            ("parse.query.nonspecial", format!("foo://a/?a{c}b")),
            ("parse.fragment", format!("http://a/#a{c}b")),
            ("parse.userinfo.user", format!("http://u{c}s:p@a/")),
            ("parse.userinfo.pass", format!("http://u:p{c}s@a/")),
            ("parse.opaque", format!("foo:a{c}b")),
            ("parse.host", format!("http://a{c}b.example/")),
            ("parse.file.host", format!("file://h{c}i/x")),
            ("parse.href", "http://a/x?q#f".to_string()),
        ] {
            rows.push((
                format!("{component}:{label}"),
                href,
                "kHref".to_string(),
                "parse".to_string(),
            ));
        }

        // Every setter, as the `update` action the class calls for it. Two bases
        // where the special/non-special split matters.
        for (action, base, payload) in [
            ("kPathname", "http://a/x?q#f", mid.clone()),
            ("kPathname", "foo://a/x", format!("/a{c}b")),
            ("kPathname", "file:///a/b", mid.clone()),
            ("kSearch", "http://a/x?q#f", mid.clone()),
            ("kSearch", "foo://a/x?q", mid.clone()),
            ("kHash", "http://a/x?q#f", mid.clone()),
            ("kUsername", "http://a/x", mid.clone()),
            ("kPassword", "http://a:x@x/", mid.clone()),
            ("kHost", "http://a.example:9/x", mid.clone()),
            ("kHostname", "http://a.example:9/x", mid.clone()),
            ("kPort", "http://a:9/x", mid.clone()),
            ("kProtocol", "https://a/x", mid.clone()),
            ("kHref", "http://a/x", format!("http://b/{mid}")),
        ] {
            rows.push((
                format!("{action}:{label}"),
                base.to_string(),
                action.to_string(),
                payload,
            ));
        }
    }

    let mut body = String::from("const ACTIONS = {kProtocol:0,kHost:1,kHostname:2,kPort:3,kUsername:4,kPassword:5,kPathname:6,kSearch:7,kHash:8,kHref:9};\nconst out = [];\n");
    for (label, base, action, payload) in &rows {
        body.push_str(&format!(
            "{{\n  const base = {base};\n  const action = {action};\n  const payload = {payload};\n  let value;\n  if (action === 'parse') {{\n    value = urlBinding.parse(payload, undefined, false);\n    value = value === undefined ? ['PARSE-FAILED'] : [value, Array.from(urlBinding.urlComponents)];\n  }} else {{\n    const r = urlBinding.update(base, ACTIONS[action], payload);\n    value = r === false ? ['REFUSED'] : [r, Array.from(urlBinding.urlComponents)];\n  }}\n  out.push([{label}, value]);\n}}\n",
            base = js_string(base),
            action = js_string(action),
            payload = js_string(payload),
            label = js_string(label),
        ));
    }
    body.push_str("globalThis.__out = JSON.stringify(out);");

    // The payload mixes a string href with numeric component offsets, so it is
    // read as an opaque JSON value rather than a `(String, Vec<String>)`.
    let here: Vec<(String, serde_json::Value)> =
        serde_json::from_str(&eval(&body)).expect("valid JSON");
    let there: Vec<(String, serde_json::Value)> = serde_json::from_str(&node_script(&format!(
        "{NODE_PRELUDES}{body}\nconsole.log(JSON.stringify(out));"
    )))
    .expect("valid JSON");
    assert_eq!(here.len(), there.len(), "one result per case");
    assert_eq!(here.len(), rows.len(), "one result per case");
    let disagreements: Vec<String> = here
        .iter()
        .zip(there.iter())
        .filter(|(mine, theirs)| mine != theirs)
        .map(|(mine, theirs)| format!("{}\n  rust: {:?}\n  node: {:?}", mine.0, mine.1, theirs.1))
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} of {} byte cases disagree:\n{}",
        disagreements.len(),
        there.len(),
        disagreements
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn format_matches_node_for_every_flag_combination() {
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
        return;
    }
    let hrefs = [
        "https://user:pw@example.com:8080/a/b?q=1#f",
        "http://example.com/",
        "http://example.com/?",
        "http://example.com/#",
        "http://example.com/?#",
        "file:///tmp/x",
        "file:////a",
        "file://host//x",
        "foo://bar/baz?x#y",
        "foo:/.//x",
        "mailto:a@b.c",
        "http://xn--9ca.com:8080/x?q#h",
        "http://xn--a/x",
        "http://xn--n3h/x",
        "http://[::1]:8080/x?q#h",
        "http://example.com/\u{fc}?q=\u{fc}#\u{fc}",
        "http://a/x^y",
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
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
        return;
    }
    let hrefs = [
        "https://user:pw@example.com:8080/a?q#f",
        "http://example.com",
        "file:///x",
        "file://host/x",
        "file:////a",
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
        "http://xn--a:81/x",
        "http://xn--a/",
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
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
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
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
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
        "//x",
        "//x/y",
        "///x",
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
    if node_binary().is_none() {
        eprintln!("no node oracle available; skipping the parity check");
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
        "xn--zz",
        "xn--a.com",
        "xn--a-",
        "xn--0.com",
        "xn--a.xn--n3h",
        "XN--A",
        "XN--N3H",
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
