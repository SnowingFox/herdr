// Runtime half of the binding contract recorder.
//
// `require('module').internalBinding` is not reachable from user code, so a
// preload cannot wrap the function the builtin layer actually calls. The
// supported route is to start Node with `--expose-internals` and take the real
// `internalBinding` from `internal/test/binding`; it resolves the same cached
// namespace objects the JS layer receives.
//
// This module is both:
//   - a preload: `node --expose-internals --require ./preload.cjs <script>`
//     records every namespace named in RUSTNODE_CONTRACT_NAMESPACES (comma
//     separated) to RUSTNODE_CONTRACT_OUT on exit, and
//   - a library: `require('./preload.cjs').captureRuntime(namespaces)` returns
//     the same snapshot without touching process state, which is what
//     `record.cjs` uses.
//
// It only ever observes. Nothing here mutates a namespace object.

'use strict';

const fs = require('fs');

/**
 * @typedef {{ kind: string, arity?: number, properties: string[] }} MemberShape
 * @typedef {{ namespace: string, reachable: true, members: Record<string, MemberShape> }} ReachedNamespace
 * @typedef {{ namespace: string, reachable: false, error: string }} UnreachedNamespace
 */

function loadInternalBinding() {
  // `internal/test/binding` is the only supported bridge to `internalBinding`
  // from user code. It exists under `--expose-internals` only.
  const bridge = require('internal/test/binding');
  if (typeof bridge.internalBinding !== 'function') {
    throw new Error('internal/test/binding did not expose internalBinding');
  }
  return bridge.internalBinding;
}

/**
 * Describe one namespace object. Only own enumerable+non-enumerable string
 * properties are recorded, matching what `Object.getOwnPropertyNames` reports:
 * that is the set the JS layer destructures.
 *
 * @param {string} namespace
 * @param {unknown} value
 * @returns {ReachedNamespace}
 */
function describeNamespace(namespace, value) {
  const members = Object.create(null);
  const object = value !== null && (typeof value === 'object' || typeof value === 'function')
    ? value
    : null;
  if (object !== null) {
    for (const key of Object.getOwnPropertyNames(object)) {
      /** @type {{ kind: string, arity?: number, properties: string[] }} */
      const member = { kind: typeof object[key], properties: [] };
      if (member.kind === 'function') {
        member.arity = object[key].length;
      } else if (member.kind === 'object' && object[key] !== null) {
        for (const inner of Object.getOwnPropertyNames(object[key])) {
          if (!member.properties.includes(inner)) member.properties.push(inner);
        }
      }
      members[key] = member;
    }
  }
  return { namespace, reachable: true, members };
}

/**
 * Capture the runtime shape of every requested namespace.
 *
 * A namespace that is compiled out of the running binary (`node_use_quic=0`,
 * `--no-expose-*`, ...) fails with "No such binding"; that is recorded as an
 * explicit miss instead of aborting the run, because the static scan in
 * `record.cjs` still covers those members.
 *
 * @param {string[]} namespaces
 * @returns {(ReachedNamespace | UnreachedNamespace)[]}
 */
function captureRuntime(namespaces) {
  const internalBinding = loadInternalBinding();
  /** @type {(ReachedNamespace | UnreachedNamespace)[]} */
  const out = [];
  for (const namespace of namespaces) {
    try {
      out.push(describeNamespace(namespace, internalBinding(namespace)));
    } catch (error) {
      out.push({
        namespace,
        reachable: false,
        error: String(error && error.message ? error.message : error),
      });
    }
  }
  return out;
}

module.exports = { captureRuntime, describeNamespace };

const preloadOutput = process.env.RUSTNODE_CONTRACT_OUT;
const preloadNamespaces = process.env.RUSTNODE_CONTRACT_NAMESPACES;
if (preloadNamespaces && preloadOutput) {
  const requested = preloadNamespaces.split(',').map((n) => n.trim()).filter(Boolean);
  let written = false;
  const flush = () => {
    if (written) return;
    written = true;
    try {
      fs.writeFileSync(preloadOutput, JSON.stringify(captureRuntime(requested), null, 2));
    } catch (error) {
      process.emitWarning(`contract preload could not write ${preloadOutput}: ${error}`);
    }
  };
  process.on('exit', flush);
  process.on('SIGTERM', () => {
    flush();
    process.exit(0);
  });
}
