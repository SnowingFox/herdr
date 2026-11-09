// Records which internalBinding namespaces and members the Node JS layer reads.
// Run with: node --require ./preload.cjs --import ./preload.mjs <script>
'use strict';

const fs = require('fs');
const path = require('path');

const output = process.env.RUSTNODE_CONTRACT_OUT;
if (output) {
  const seen = new Map();
  const nodeModule = require('node:module');

  const original = nodeModule.internalBinding;
  const record = (namespace) => {
    let entry = seen.get(namespace);
    if (!entry) {
      entry = { namespace, members: {} };
      seen.set(namespace, entry);
    }
    return entry;
  };

  nodeModule.internalBinding = function internalBinding(namespace) {
    const result = original.call(this, namespace);
    const entry = record(namespace);
    if (result && (typeof result === 'object' || typeof result === 'function')) {
      for (const key of Object.getOwnPropertyNames(result)) {
        const value = result[key];
        const kind = typeof value;
        const member = entry.members[key] || (entry.members[key] = { kind });
        if (kind === 'function') member.arity = value.length;
        if (value && kind === 'object') {
          for (const inner of Object.getOwnPropertyNames(value)) member.properties.push(inner);
        }
      }
    }
    return result;
  };

  const flush = () => {
    const json = {};
    for (const [namespace, entry] of seen) json[namespace] = entry;
    fs.writeFileSync(output, JSON.stringify(json, null, 2));
  };
  process.on('exit', flush);
  process.on('SIGTERM', () => { flush(); process.exit(0); });
}
