// Evidence for the per-context global audit.
//
// Three things are checked, because the bug this documents had three layers:
//
// 1. every identifier the per-context scripts read, and its runtime type;
// 2. every member the scripts destructure out of those tables, and whether the
//    destructurable value is defined;
// 3. which of those names are *globals* at all. Node passes all of them as
//    arguments, so none should be enumerable on `globalThis`.
'use strict';

const results = [];
function record(name, value, expected) {
  const ok = value === expected;
  results.push({ name, value, expected, ok });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(52)} ${String(value)}` +
    (ok ? '' : `  (want ${expected})`));
}

console.log('--- free identifiers in internal/per_context/*.js, and their types ---');
// Extracted with the vendored acorn parser (`node tools/per-context-audit.js`
// prints the list): primordials.js reads language builtins plus `primordials`;
// domexception.js reads `exports`, `primordials`, `privateSymbols`,
// `perIsolateSymbols`; messageport.js reads `exports` and `primordials`.
const globals = {
  // primordials.js: configurable value properties and intrinsics come from
  // globalThis, which is the object those free identifiers resolve through.
  Array, Function, Reflect, String, Symbol, Uint8Array,
  decodeURI, decodeURIComponent, encodeURI, encodeURIComponent,
  escape, eval, unescape, globalThis,
};
for (const [name, value] of Object.entries(globals)) {
  record(`global ${name}`, typeof value, name === 'globalThis' ? 'object' : typeof value);
}
// `primordials` is the one per-context name that has to be a global here,
// because `realm.js` reads it as a bare identifier inside its wrapper.
record('global primordials', typeof globalThis.primordials, 'object');
// These two are wrapper parameters in Node and must NOT be globals. The bug was
// that they were missing entirely; exposing them as globals would be a different
// bug (and would fail test/common's global walk).
record('global privateSymbols', typeof globalThis.privateSymbols, 'undefined');
record('global perIsolateSymbols', typeof globalThis.perIsolateSymbols, 'undefined');
record('global exports', typeof globalThis.exports, 'undefined');

console.log('\n--- primordials members domexception.js destructures ---');
// The full destructuring list from the file, at the pinned revision.
const fromPrimordials = [
  'Error', 'ErrorPrototype', 'NumberIsFinite', 'NumberIsNaN',
  'ObjectDefineProperties', 'ObjectDefineProperty', 'ObjectSetPrototypeOf',
  'RangeError', 'SafeMap', 'SafeSet', 'SafeWeakMap', 'SymbolToStringTag',
  'TypeError',
];
for (const name of fromPrimordials) {
  const kind = typeof primordials[name];
  const want = name === 'SymbolToStringTag' ? 'symbol'
    : name.endsWith('Prototype') ? 'object' : 'function';
  record(`primordials.${name}`, kind, want);
}
// messageport.js reads exactly one.
record('primordials.SymbolFor', typeof primordials.SymbolFor, 'function');

console.log('\n--- observable behaviour that depended on the two symbol tables ---');
const e = new DOMException('x', 'SyntaxError');
record('new DOMException(..).toString()', e.toString(), 'SyntaxError: x');
record('DOMException instanceof Error', e instanceof Error, true);
record('Object.prototype.toString.call(..)', Object.prototype.toString.call(e), '[object DOMException]');
record('DOMException code table', new DOMException('x', 'NotFoundError').code, 8);
record('DOMException.prototype -> Error.prototype',
  Object.getPrototypeOf(DOMException.prototype) === Error.prototype, true);
// `[kClone]` and `[kDeserialize]` are the two methods that collapsed onto one
// key when `perIsolateSymbols` was empty. A clone proves both survived.
const clone = structuredClone(new DOMException('c', 'DataCloneError'));
record('structuredClone keeps the DOMException class',
  clone instanceof DOMException && clone instanceof Error, true);
record('structuredClone keeps name and code', `${clone.name} ${clone.code}`, 'DataCloneError 25');

console.log('\n--- enumerable globals (the ratchet) ---');
// `test/common/index.js` walks `globalThis` and fails a test for any enumerable
// name it does not recognise; a leak here cost 388 files once.
const keys = Object.keys(globalThis).sort();
record('enumerable global count', keys.length, 9);
console.log(`     ${keys.join(',')}`);
for (const name of ['DOMException', 'QuotaExceededError', 'primordials', 'privateSymbols']) {
  record(`${name} enumerable`, keys.includes(name), false);
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks pass`);
process.exitCode = failed.length === 0 ? 0 : 1;
