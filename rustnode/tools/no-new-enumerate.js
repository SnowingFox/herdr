'use strict';
// Lists every own function member of each requested binding namespace, and asks
// the engine whether each one is a constructor.
//
//   <runtime> --expose-internals tools/no-new-enumerate.js <namespaces.json>
//
// The namespace list comes from the Rust binding registry (see
// tools/no-new-audit.py), not from a hand-written list, so a namespace added by
// a new binding crate is audited without editing this file.
//
// Constructibility is decided by the engine, not by a list written here.
// `Reflect.construct(Object, [], fn)` succeeds exactly when `fn` has
// `[[Construct]]`, which is the property that decides whether `new fn()` is
// legal. Testing for an own `prototype` property instead would be wrong in
// both directions: rustnode gives every binding function a prototype, while
// Node's `FunctionTemplate` callbacks have none, so that test would classify
// every rustnode member as a class and no Node one as a class.
//
// Nothing here *calls* a member, so nothing here can abort a process.
const { internalBinding } = require('internal/test/binding');

const namespaces = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));

// A throwaway base whose instances are never exposed: only `[[Construct]]` on
// `fn` is under test. The base is a function so `Reflect.construct` has a valid
// target even when `fn` turns out not to be constructible.
const BASE = function NoNewAuditBase() {};

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
      members[key] = 'unreadable';
      continue;
    }
    if (typeof value !== 'function') continue;
    members[key] = isConstructor(value) ? 'constructor' : 'function';
  }
  report[namespace] = { members };
}
process.stdout.write(JSON.stringify(report));
