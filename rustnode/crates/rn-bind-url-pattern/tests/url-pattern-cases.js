//! `URLPattern` cases, printed as one JSON line each.
//!
//! Every case is a self-contained observation: the component accessors, the
//! prototype descriptor, `test`, `exec`, and the global binding. The output is
//! compared byte for byte against the same file run under `node`, so nothing
//! here may depend on anything but what the runtime reports.
//!
//! The two things this file exists to pin are the defects it was written for:
//!
//! * the eight component getters must be *accessors* on `URLPattern.prototype`,
//!   not data properties holding `undefined`. A descriptor read is the direct
//!   observation, and `p.pathname` reading a value is the indirect one.
//! * `URLPattern` must be a global, so a script that never calls
//!   `require('url')` can construct one.
//!
//! Everything else is there because `test`/`exec` are only meaningful if the
//! pattern underneath them is right, which means the grammar cases have to run
//! too.

const { URLPattern } = require("url");

const COMPONENTS = [
  "protocol", "username", "password", "hostname",
  "port", "pathname", "search", "hash",
];

const out = [];
const emit = (name, value) => out.push(JSON.stringify({ name, value }));

/// Describes a property the way a caller introspects it.
const describe = (object, key) => {
  const d = Object.getOwnPropertyDescriptor(object, key);
  if (d === undefined) return "missing";
  const parts = [];
  if ("get" in d) parts.push(`get:${typeof d.get}`);
  if ("set" in d) parts.push(`set:${typeof d.set}`);
  if ("value" in d) parts.push(`value:${typeof d.value}`);
  parts.push(`w:${d.writable === undefined ? "-" : d.writable}`);
  parts.push(`e:${d.enumerable}`);
  parts.push(`c:${d.configurable}`);
  return parts.join(" ");
};

const components = (pattern) => {
  const result = {};
  for (const name of COMPONENTS) result[name] = pattern[name];
  return result;
};

const attempt = (fn) => {
  try {
    const value = fn();
    return value === undefined ? "undefined" : value;
  } catch (error) {
    return `throw ${error.constructor.name} ${error.code} ${error.message}`;
  }
};

// --- The prototype surface: F3's direct observation ------------------------

for (const name of COMPONENTS.concat("hasRegExpGroups")) {
  emit(`descriptor-${name}`, describe(URLPattern.prototype, name));
}
emit("prototype-names", Object.getOwnPropertyNames(URLPattern.prototype));
emit("prototype-symbols",
     Object.getOwnPropertySymbols(URLPattern.prototype).map(String));
emit("prototype-toStringTag",
     describe(URLPattern.prototype, Symbol.toStringTag));
emit("method-exec", describe(URLPattern.prototype, "exec"));
emit("method-test", describe(URLPattern.prototype, "test"));
emit("constructor-length", URLPattern.prototype.test.length);
emit("constructor-name", URLPattern.name);
emit("constructor-length-prop", URLPattern.length);

// --- Accessor values ------------------------------------------------------

emit("component-object-form",
     components(new URLPattern({ pathname: "/books/:id" })));
emit("component-defaults", components(new URLPattern()));
emit("component-null-input", components(new URLPattern(null)));
emit("component-string-absolute",
     components(new URLPattern("https://user:pw@example.com:8080/a?q=1#h")));
emit("component-string-no-path", components(new URLPattern("https://example.com")));
emit("component-string-empty-search",
     components(new URLPattern("https://example.com/a?")));
emit("component-string-empty-hash",
     components(new URLPattern("https://example.com/a#")));
emit("component-string-uppercase", components(new URLPattern("HTTPS://E.COM/X")));
emit("component-string-dot-segments",
     components(new URLPattern("https://example.com/a/../b")));
emit("component-string-space-encodes",
     components(new URLPattern("https://example.com/a b")));
emit("component-string-default-port",
     components(new URLPattern("https://example.com:443/x")));
emit("component-empty-port", components(new URLPattern({ pathname: "/a", port: "" })));
emit("component-empty-search", components(new URLPattern({ search: "" })));
emit("component-empty-hash", components(new URLPattern({ hash: "" })));
emit("component-hostname-lowercased",
     components(new URLPattern({ hostname: "E.COM" })));
emit("component-brace-literal",
     components(new URLPattern({ pathname: "/b/{x,y}" })));
emit("component-base-merges-relative",
     components(new URLPattern("c", "https://example.com/a/b")));
emit("component-base-absolute-path",
     components(new URLPattern("/c", "https://example.com/a/b")));
emit("hasRegExpGroups-plain", new URLPattern({ pathname: "/a" }).hasRegExpGroups);
emit("hasRegExpGroups-regexp",
     new URLPattern({ pathname: "/a(\\d+)" }).hasRegExpGroups);
emit("hasRegExpGroups-group",
     new URLPattern({ pathname: "/a/:id" }).hasRegExpGroups);

// --- Receivers and writes -------------------------------------------------

emit("getter-borrowed-receiver",
     attempt(() => Object.getOwnPropertyDescriptor(URLPattern.prototype, "pathname")
       .get.call({})));
emit("getter-on-prototype",
     attempt(() => URLPattern.prototype.pathname));
emit("test-borrowed-receiver",
     attempt(() => URLPattern.prototype.test.call({}, "https://example.com/")));
emit("exec-borrowed-receiver",
     attempt(() => URLPattern.prototype.exec.call({}, "https://example.com/")));
emit("assign-in-strict", attempt(() => {
  "use strict"; // eslint-disable-line no-unused-expressions
  new URLPattern({ pathname: "/a" }).pathname = "x";
}));
emit("assign-sloppy", (() => {
  const pattern = new URLPattern({ pathname: "/a" });
  pattern.pathname = "x";
  return pattern.pathname;
})());
emit("call-without-new", attempt(() => URLPattern({})));
emit("instance-own-properties",
     Object.getOwnPropertyNames(new URLPattern({ pathname: "/a" })));
emit("instance-keys", Object.keys(new URLPattern({ pathname: "/a" })));

// --- test() and exec() ----------------------------------------------------

const cases = [
  ["literal-true", { protocol: "https", hostname: "example.com", pathname: "/a" },
   "https://example.com/a"],
  ["literal-false", { protocol: "https", hostname: "example.com", pathname: "/a" },
   "https://example.com/b"],
  ["wildcard-component", { pathname: "*" }, "https://example.com/a/b"],
  ["named-group", { pathname: "/b/:id" }, "https://example.com/b/42"],
  ["named-group-no-match", { pathname: "/b/:id" }, "https://example.com/b/42/x"],
  ["star-middle", { pathname: "/b/*" }, "https://example.com/b/x/y"],
  ["star-prefix", { pathname: "/b/x*" }, "https://example.com/b/xyz"],
  ["regexp-group", { pathname: "/b/(\\d+)" }, "https://example.com/b/42"],
  ["regexp-group-miss", { pathname: "/b/(\\d+)" }, "https://example.com/b/x"],
  ["hostname-wildcard", { hostname: "*.example.com" },
   "https://a.example.com/x"],
  ["port-empty", { pathname: "/a", port: "" }, "https://example.com/a"],
  ["port-empty-rejects", { pathname: "/a", port: "" },
   "https://example.com:8080/a"],
  ["search-literal", { search: "q=1", pathname: "/a" },
   "https://example.com/a?q=1"],
  ["empty-pathname", { pathname: "" }, "https://example.com/"],
  ["no-arguments", {}, undefined],
];

for (const [name, pattern, input] of cases) {
  const compiled = new URLPattern(pattern);
  emit(`test-${name}`, attempt(() => input === undefined
    ? compiled.test()
    : compiled.test(input)));
  const result = attempt(() => input === undefined
    ? compiled.exec()
    : compiled.exec(input));
  if (typeof result === "string") {
    emit(`exec-${name}`, result);
  } else if (result === null) {
    emit(`exec-${name}`, null);
  } else {
    // `exec` returns a null-prototype object, so it is flattened explicitly
    // rather than relying on a JSON round-trip preserving that.
    emit(`exec-${name}-result`, {
      prototype: Object.getPrototypeOf(result) === null ? "null" : "object",
      keys: Object.keys(result),
      components: COMPONENTS.reduce((into, component) => {
        into[component] = {
          input: result[component].input,
          groups: Object.keys(result[component].groups)
            .reduce((groups, key) => {
              groups[key] = result[component].groups[key];
              return groups;
            }, {}),
        };
        return into;
      }, {}),
      inputs: result.inputs,
    });
  }
}

// Group key *order* is observable and comes from Node's group container; a
// separate case pins it since `Object.keys` is the only way to see it.
for (const pattern of ["/:a/:b/:c", "/:a/:b/:c/:d", "/:x/:y/:z"]) {
  const input = "https://example.com/" +
    pattern.split("/").filter((part) => part.startsWith(":")).map(() => "1").join("/");
  const result = new URLPattern({ pathname: pattern }).exec(input);
  emit(`group-order${pattern}`, Object.keys(result.pathname.groups));
}
for (const pattern of ["/*/*/*", "/*/*"]) {
  const segments = pattern.split("/").length - 1;
  const input = "https://example.com/" + Array(segments).fill("1").join("/");
  const result = new URLPattern({ pathname: pattern }).exec(input);
  emit(`group-order${pattern}`, Object.keys(result.pathname.groups));
}

// An object input reports the object it was given, and a relative string input
// reports both the input and the base.
emit("exec-string-inputs", new URLPattern({ pathname: "/c" })
  .exec("/c", "https://example.com/a/b").inputs);
emit("exec-object-inputs", new URLPattern({ pathname: "/a" })
  .exec({ protocol: "https", hostname: "example.com", pathname: "/a" }).inputs);

// --- Errors ---------------------------------------------------------------

emit("error-numeric-input", attempt(() => new URLPattern(42)));
emit("error-relative-without-base", attempt(() => new URLPattern("/a?q=1")));
emit("error-bad-port", attempt(() => new URLPattern({ port: "70000" })));
emit("error-port-not-a-number", attempt(() => new URLPattern({ port: "x" })));
emit("error-object-with-base",
     attempt(() => new URLPattern({ pathname: "/a" }, "https://example.com")));
emit("error-test-numeric",
     attempt(() => new URLPattern({ pathname: "*" }).test(42)));
emit("error-test-base-number",
     attempt(() => new URLPattern({ pathname: "/a" }).test("/a", 5)));
emit("error-test-object-with-base",
     attempt(() => new URLPattern({ pathname: "/a" })
       .test({ pathname: "/a" }, "https://example.com")));
emit("error-exec-object-with-base",
     attempt(() => new URLPattern({ pathname: "/a" })
       .exec({ pathname: "/a" }, "https://example.com")));

// A relative input with no base is not an error: it resolves against an empty
// URL, so only the path is populated.
emit("relative-input-no-base",
     new URLPattern({ pathname: "*" }).exec("a/b").pathname.input);
emit("relative-input-no-base-components",
     components(new URLPattern({ pathname: "*" })).protocol);
emit("empty-input-path", new URLPattern({ pathname: "*" }).exec("").pathname.input);
emit("empty-input-test", new URLPattern({ pathname: "/" }).test(""));

// U+005E is in the path percent-encode set, so a pattern for `/x%5Ey` has to
// match the URL `https://example.com/x^y`, in both the special and the opaque
// pathname forms.
emit("caret-path-pattern", new URLPattern({ pathname: "/x^y" }).pathname);
emit("caret-path-match", new URLPattern({ pathname: "/x^y" }).test("https://example.com/x%5Ey"));
emit("caret-path-input",
     new URLPattern({ pathname: "*" }).exec("https://example.com/x^y").pathname.input);
emit("caret-opaque-input",
     new URLPattern({ pathname: "*" }).exec("data://example.com/x^y").pathname.input);
emit("caret-opaque-match",
     new URLPattern({ protocol: "data", pathname: "/x^y" })
       .test("data://example.com/x^y"));

// An IPv6 hostname in a pattern is rejected by both runtimes: ada's IPv6 path
// only runs for a `{`/`\[` prefixed hostname, and the `[`/`]` are pattern
// syntax rather than literal text.
emit("ipv6-hostname-rejected", attempt(() => new URLPattern({ hostname: "[::1]" })));
emit("ipv6-hostname-bare-rejected", attempt(() => new URLPattern({ hostname: "::1" })));
emit("ipv6-string-rejected", attempt(() => new URLPattern("https://[::1]/x")));

// A pattern may name a group with a non-ASCII identifier, which is
// `ID_Start`/`ID_Continue` rather than ASCII.
emit("unicode-group-name", new URLPattern({ pathname: "/:名前" }).pathname);
emit("unicode-group-name-test",
     new URLPattern({ pathname: "/:名前" }).test("https://example.com/x"));
emit("digit-group-name-rejected", attempt(() => new URLPattern({ pathname: "/:1" })));

// --- The global binding: F4's observation ---------------------------------

emit("global-typeof", typeof globalThis.URLPattern);
emit("global-descriptor", describe(globalThis, "URLPattern"));
emit("global-same-as-require", globalThis.URLPattern === URLPattern);
emit("global-constructs",
     new globalThis.URLPattern({ pathname: "/books/:id" }).pathname);
emit("global-test",
     new globalThis.URLPattern({ protocol: "https", hostname: "e.com",
                                 pathname: "/a" }).test("https://e.com/a"));

for (const line of out) console.log(line);
