// Records what a real `node --expose-internals` answers for every case in
// `src/tests.rs`, so the Rust binding's expectations are a recording rather than
// a reading of the C++ source.
//
//     node --expose-internals tests/record.cjs > tests/node_expected.json
//
// This is deliberately the same shape the Rust side consumes: the case list here
// and `CASES` in `src/tests.rs` must stay in step, and `parity.rs` fails when one
// gains a case the other does not have.
//
// `require('internal/test/binding')` is the only supported way to reach a
// namespace from outside the builtin layer; it exists only under
// `--expose-internals`. Recorded with v27.0.0-alpha.0.0.0, the version
// `tools/node-pin.toml` names as `recorder_version`, because Node 28 is not
// published as a binary yet.

const { internalBinding } = require('internal/test/binding');
const { parse } = internalBinding('cjs_lexer');

const cases = {
  empty: '',
  whitespace: '\n\n  \n',
  plain_script: 'const a = 1;\nfunction f() { return 2; }\n',
  object_shorthand: 'module.exports = {a, b};',
  object_named: 'module.exports = { a: 1 };',
  object_mixed: 'const a = 1;\nmodule.exports = { a, b: 2, c };\n',
  exports_dot: 'exports.x = 1;',
  exports_dedup: 'exports.a = 1;\nexports.b = 2;\nexports.a = 3;',
  module_exports_dot: 'module.exports.z = 42;',
  bracket_quoted: "exports['quoted'] = 1;\nexports[\"double\"] = 2;",
  define_property_value: "Object.defineProperty(exports, 'd1', { value: 1 });",
  define_property_getter: "Object.defineProperty(exports, 'd3', { get() { return 1; } });",
  es_module_marker:
    'Object.defineProperty(exports, "__esModule", { value: true });\nexports.real = 1;',
  nested_member: 'exports.a.b = 1;',
  shadowed_exports: 'var exports = {}; exports.nope = 1;',
  reexport_direct: "module.exports = require('./other');",
  reexport_spread: "module.exports = { ...require('./spread'), own: 1 };",
  reexport_babel: "var __export = 0;\n__export(require('./z'));",
  reexport_object_keys:
    "Object.keys(require('./keys')).forEach(function (k) { exports[k] = 1; });",
  esm_import: 'import foo from "bar";\nexport default foo;\n',
  esm_export: 'export const q = 1;\n',
  unterminated_string: "var s = 'unterminated",
  unbalanced_brace: 'function f() {',
  unicode_escape: "exports['\\u0061b'] = 1;",
  multiline: 'exports.one = 1;\n\nexports.two = 2;\n',
  template_literal: 'exports.t = `a${1}b`;',
};

const out = {};
for (const [name, source] of Object.entries(cases)) {
  const [exportsSet, reexportsArray] = parse(source);
  out[name] = {
    exports: Array.from(exportsSet),
    reexports: Array.from(reexportsArray),
  };
}

process.stdout.write(JSON.stringify(out, null, 2) + '\n');
