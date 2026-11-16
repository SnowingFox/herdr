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
// The whole *prototype chain* is walked, in lookup order, and not just the
// prototype object the class names itself. A method's constructibility does not
// depend on the depth it sits at, and the layout is an internal detail of how
// the reference happens to assemble its templates: Node's `TTY` has
// `getWindowSize`/`setRawMode` on its own prototype and `close`/`ref`/
// `unref`/`hasRef` two links up on `HandleWrap`'s, while rustnode installs all
// eight on the object the class names. Walking only own properties made six of
// those eight invisible to the comparison, because a name that is not an own
// property of Node's prototype was never looked for at all — a check that
// reported clean while measuring a subset of what the comment above promised.
//
// A name is classified from the occurrence JavaScript would actually resolve:
// the shallowest one. A shadowed deeper method is not reachable through an
// instance, so its constructibility is not observable and is not reported.
//
// Only data properties whose value is a function are reported; accessors and
// `constructor` itself are skipped, the latter because it is the class the caller
// already named.
const { internalBinding } = require('internal/test/binding');

const [namespace, ...classes] = process.argv.slice(2);

// A prototype chain cannot be this deep, so the bound is a cycle guard rather
// than a limit anything real reaches.
const MAX_DEPTH = 16;

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
  // Every name met so far, at any depth. A shallower property — data or
  // accessor — wins over a deeper one with the same name.
  const seen = new Set(['constructor']);
  let proto = value.prototype;
  let depth = 0;
  while (proto && proto !== Object.prototype && proto !== Function.prototype &&
         depth < MAX_DEPTH) {
    for (const key of Object.getOwnPropertyNames(proto)) {
      if (seen.has(key)) continue;
      seen.add(key);
      const descriptor = Object.getOwnPropertyDescriptor(proto, key);
      if (!descriptor || typeof descriptor.value !== 'function') continue;
      members[key] = isConstructor(descriptor.value) ? 'constructor' : 'function';
    }
    proto = Object.getPrototypeOf(proto);
    depth += 1;
  }
  report[name] = { members };
}
process.stdout.write(JSON.stringify(report));
