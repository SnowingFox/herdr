'use strict';
// Lists every own function member of each requested binding namespace with its
// `name`, `length` and `[[Construct]]`, so a differential can compare binding
// function identity against a real Node instead of by eye.
//
//   <runtime> --expose-internals tools/function-name-enumerate.js <namespaces.json>
//
// The namespace list comes from the Rust binding registry (see
// `tools/function-name-audit.py`), not from a hand-written list, so a namespace
// added by a new binding crate is measured without editing this file.
//
// Constructibility is decided by the engine via `Reflect.construct`, exactly as
// `tools/no-new-enumerate.js` does it: an own `prototype` property is the wrong
// probe in both directions.
//
// Nothing here calls a member, so nothing here can abort a process.
const { internalBinding } = require('internal/test/binding');

const namespaces = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));

const BASE = function FunctionNameAuditBase() {};

function isConstructor(fn) {
  try {
    Reflect.construct(BASE, [], fn);
    return true;
  } catch {
    return false;
  }
}

const report = {};
for (const namespace of namespaces) {
  let target;
  try {
    target = internalBinding(namespace);
  } catch (e) {
    report[namespace] = { error: e.message };
    continue;
  }
  const members = {};
  for (const key of Object.getOwnPropertyNames(target)) {
    let value;
    try {
      value = target[key];
    } catch (e) {
      members[key] = { kind: 'unreadable' };
      continue;
    }
    if (typeof value !== 'function') continue;
    let name;
    try {
      name = value.name;
    } catch (e) {
      name = '';
    }
    members[key] = {
      kind: isConstructor(value) ? 'constructor' : 'function',
      name: typeof name === 'string' ? name : '',
      length: value.length,
    };
  }
  report[namespace] = { members };
}
process.stdout.write(JSON.stringify(report));
