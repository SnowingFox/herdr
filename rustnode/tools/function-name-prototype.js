'use strict';
// Lists every method on each requested class's prototype with its `name`, so
// prototype-method naming can be compared to a real Node the same way namespace
// members are.
//
//   <runtime> --expose-internals tools/function-name-prototype.js <namespace> <Class>...
//
// A missing class is reported as an error entry rather than a silent absence:
// "compared nothing" must never read as a pass.
const { internalBinding } = require('internal/test/binding');

const [namespace, ...classes] = process.argv.slice(2);

const report = {};
let binding;
try {
  binding = internalBinding(namespace);
} catch (e) {
  process.stdout.write(JSON.stringify({ error: e.message }));
  process.exit(0);
}

for (const className of classes) {
  const ctor = binding[className];
  if (typeof ctor !== 'function') {
    report[className] = { error: 'not a function' };
    continue;
  }
  const prototype = ctor.prototype;
  if (prototype == null || (typeof prototype !== 'object' && typeof prototype !== 'function')) {
    report[className] = { error: 'no prototype' };
    continue;
  }
  const members = {};
  for (const key of Object.getOwnPropertyNames(prototype)) {
    if (key === 'constructor') continue;
    const descriptor = Object.getOwnPropertyDescriptor(prototype, key);
    const value = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    if (typeof value !== 'function') continue;
    members[key] = { name: value.name, length: value.length };
  }
  report[className] = { members };
}

process.stdout.write(JSON.stringify(report));
