'use strict';
// Runs exactly one "call the constructor without `new`" case and reports the
// outcome as one machine-readable line.
//
//   <runtime> --expose-internals tools/no-new-case.js <namespace> <member>
//
// One case per process is not a stylistic choice. Several constructors in this
// tree do not throw when the construct check fails - Node's
// `CHECK(args.IsConstructCall())` aborts the process - so an in-process runner
// would die on the first such case and silently never measure the rest.
//
// The outcome line is `#CASE#` followed by JSON, on its own line, so a parent
// that also sees V8's stack trace can still find the result.
const { internalBinding } = require('internal/test/binding');

const namespace = process.argv[2];
const member = process.argv[3];

function emit(outcome) {
  process.stdout.write(`\n#CASE#${JSON.stringify({ namespace, member, ...outcome })}\n`);
}

let target;
try {
  target = internalBinding(namespace);
} catch (e) {
  emit({ kind: 'binding-missing', message: e.message });
  process.exit(0);
}
let fn;
try {
  fn = target[member];
} catch (e) {
  emit({ kind: 'member-missing', message: e.message });
  process.exit(0);
}
if (typeof fn !== 'function') {
  emit({ kind: 'not-a-function', detail: typeof fn });
  process.exit(0);
}

// The engine's own classification, reported alongside the outcome so the audit
// can tell "this is not really a class" from "this class accepts a plain call".
const descriptor = Object.getOwnPropertyDescriptor(fn, 'prototype');
const constructible = descriptor !== undefined && descriptor.value !== null &&
  typeof descriptor.value === 'object';

try {
  const value = fn();
  emit({ kind: 'return', constructible, returned: typeof value });
} catch (e) {
  emit({
    kind: 'throw',
    constructible,
    errorName: e.name,
    message: e.message,
    code: typeof e.code === 'string' ? e.code : null,
  });
}
