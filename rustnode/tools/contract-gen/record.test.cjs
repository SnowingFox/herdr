#!/usr/bin/env node
// Tests for the AST half of the recorder.
//
//   node tools/contract-gen/record.test.cjs
//
// Run with `--expose-internals` to use the acorn copy Node bundles; otherwise
// the test skips, because the recorder itself needs that parser too.
//
// These tests cover the extraction rules, not Node's own builtin JS: a
// regression here would silently record wrong members, and the contracts are
// what every binding crate is checked against.

'use strict';

const assert = require('assert');

function loadAcorn() {
  try {
    return require('internal/deps/acorn/acorn/dist/acorn');
  } catch {
    return null;
  }
}

const acorn = loadAcorn();
if (acorn === null) {
  process.stderr.write(
    'acorn unavailable; run with --expose-internals (as generate.sh does)\n',
  );
  process.exit(1);
}

const { analyzeFile } = require('./record.cjs');

function scan(source, relative = 'test.js') {
  const sink = { namespaces: new Map(), files: new Map() };
  analyzeFile(
    acorn.parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      allowReturnOutsideFunction: true,
    }),
    relative,
    sink,
  );
  return sink;
}

/** Member map for one namespace, with sets flattened for easy comparison. */
function members(sink, namespace) {
  const ns = sink.namespaces.get(namespace);
  if (!ns) return null;
  return Object.fromEntries(
    [...ns.entries()].map(([name, info]) => [
      name,
      {
        called: info.called,
        properties: [...info.properties].sort(),
        guards: [...info.guards].sort(),
      },
    ]),
  );
}

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

test('object destructuring records every member', () => {
  const sink = scan("const { open, close, read } = internalBinding('fs');");
  assert.deepStrictEqual(Object.keys(members(sink, 'fs')).sort(), ['close', 'open', 'read']);
});

test('renamed destructuring records the member, not the local name', () => {
  const sink = scan("const { open: openFile } = internalBinding('fs');");
  const got = members(sink, 'fs');
  assert.ok(got.open, 'member `open` recorded');
  assert.strictEqual(got.openFile, undefined, 'local alias must not become a member');
});

test('direct member call marks the member as a function', () => {
  const sink = scan("internalBinding('types').isDate(1);");
  assert.strictEqual(members(sink, 'types').isDate.called, true);
});

test('alias to the namespace resolves later member reads', () => {
  const sink = scan(
    "const binding = internalBinding('os');\nbinding.getHostname();\nbinding.uptime;",
  );
  const got = members(sink, 'os');
  assert.strictEqual(got.getHostname.called, true);
  assert.ok(got.uptime, 'property-only member recorded');
  assert.strictEqual(got.uptime.called, false);
});

test('member of a member contributes sub-properties', () => {
  const sink = scan(
    "const { os: osConstants } = internalBinding('constants');\nconst { signals } = osConstants;",
  );
  assert.deepStrictEqual(members(sink, 'constants').os.properties, ['signals']);
});

test('typeof guard infers the static kind', () => {
  const sink = scan("if (typeof internalBinding('config').hasIntl === 'boolean') {}");
  assert.deepStrictEqual(members(sink, 'config').hasIntl.guards, ['boolean']);
});

test('destructured member called by its local name is a function', () => {
  const sink = scan(
    "const { queryObjects: q } = internalBinding('internal_only_v8');\nq({});",
  );
  assert.strictEqual(members(sink, 'internal_only_v8').queryObjects.called, true);
});

test('a namespace with no member reads is still registered', () => {
  const sink = scan("internalBinding('locks');");
  assert.deepStrictEqual(Object.keys(members(sink, 'locks')), []);
  assert.ok(sink.files.get('locks').has('test.js'));
});

test('dynamic names are ignored rather than guessed', () => {
  const sink = scan("const name = 'fs';\ninternalBinding(name);");
  assert.strictEqual(sink.namespaces.size, 0);
});

test('multiple files accumulate into one namespace', () => {
  const sink = { namespaces: new Map(), files: new Map() };
  for (const [file, source] of [
    ['a.js', "const { open } = internalBinding('fs');"],
    ['b.js', "const { close } = internalBinding('fs');"],
  ]) {
    analyzeFile(acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'script' }), file, sink);
  }
  assert.deepStrictEqual(Object.keys(members(sink, 'fs')).sort(), ['close', 'open']);
  assert.deepStrictEqual([...sink.files.get('fs')].sort(), ['a.js', 'b.js']);
});

test('a member read on a non-binding alias is not recorded', () => {
  const sink = scan("const fs = require('node:fs');\nfs.readFileSync('x');");
  assert.strictEqual(
    sink.namespaces.size,
    0,
    'require() must not be mistaken for a binding',
  );
});

test('computed string member reads are recorded', () => {
  const sink = scan("const binding = internalBinding('fs');\nbinding['open']();");
  assert.strictEqual(members(sink, 'fs').open.called, true);
});

test('a file with a top-level return still parses and records', () => {
  // lib/internal/quic/* and dtls/* use this shape for build-flag exits.
  const sink = scan(
    "if (!config.hasQuic) return;\nconst { Endpoint } = internalBinding('quic');",
  );
  assert.deepStrictEqual(Object.keys(members(sink, 'quic')), ['Endpoint']);
});

let failures = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    process.stdout.write(`ok   ${name}\n`);
  } catch (error) {
    failures += 1;
    process.stdout.write(`FAIL ${name}\n     ${error.message}\n`);
  }
}
process.stdout.write(`\n${tests.length - failures}/${tests.length} passed\n`);
if (failures > 0) process.exit(1);
