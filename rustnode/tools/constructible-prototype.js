'use strict';
// Reports, for one class reached through `internalBinding()`, which of its
// prototype's methods are constructible.
//
//   <runtime> --expose-internals tools/constructible-prototype.js <ns> <Class>...
//
// The namespace-member half of the contract is in no-new-enumerate.js, which
// walks whole namespace objects. This walks one level deeper, into the
// prototype of a class that is itself a namespace member, because Node installs
// those with `SetProtoMethod` — also `ConstructorBehavior::kThrow`
// (`src/util.cc:570`) — so `new binding.TCP.prototype.connect()` is a TypeError
// even though `new binding.TCP()` is not.
//
// Only own data properties whose value is a function are reported; accessors and
// `constructor` itself are skipped, the latter because it is the class the caller
// already named.
const { internalBinding } = require('internal/test/binding');

const [namespace, ...classes] = process.argv.slice(2);

function isConstructor(fn) {
  try {
    Reflect.construct(function Noop() {}, [], fn);
    return true;
  } catch {
    return false;
  }
}

const target = internalBinding(namespace);
const report = {};
for (const name of classes) {
  const value = target[name];
  if (typeof value !== 'function' || !value.prototype) {
    report[name] = { error: 'not a constructor with a prototype' };
    continue;
  }
  const members = {};
  for (const key of Object.getOwnPropertyNames(value.prototype)) {
    if (key === 'constructor') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value.prototype, key);
    if (!descriptor || typeof descriptor.value !== 'function') continue;
    members[key] = isConstructor(descriptor.value) ? 'constructor' : 'function';
  }
  report[name] = { members };
}
process.stdout.write(JSON.stringify(report));
