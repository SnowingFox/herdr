#!/usr/bin/env node
// Binding contract recorder: the raw half of `contract-gen`.
//
// Regenerate the contracts with:
//
//   ./tools/contract-gen/generate.sh
//
// or, equivalently, by hand:
//
//   node --expose-internals tools/contract-gen/record.cjs \
//        --lib vendor/libnode-js/lib --out /tmp/recorded.json
//   cargo run -p contract-gen -- /tmp/recorded.json --out contracts
//
// Why `--expose-internals`: `require('module').internalBinding` is not visible
// to user code, so a preload cannot wrap it. The only supported bridge is
// `require('internal/test/binding')`, which exists under `--expose-internals`
// and returns the same cached namespace object the builtin JS layer sees.
//
// Two sources are merged:
//
//   1. runtime   - every namespace object the running binary can hand out.
//                  Authoritative for `kind`, `arity` and `properties`.
//   2. static    - an acorn AST pass over `vendor/libnode-js/lib/**` that
//                  resolves `internalBinding('ns')` call sites and the member
//                  accesses on them. Authoritative for the member *set*: it
//                  sees members that only run on other platforms, behind
//                  disabled build flags, or after an early return.
//
// A namespace the running binary was compiled without (QUIC, DTLS,
// `internal_only_v8`) is recorded as `reachable: false` with the reason, and
// its members come from the static pass alone.

'use strict';

const fs = require('fs');
const path = require('path');

const { captureRuntime } = require('./preload.cjs');

const MEMBER_KINDS = new Set([
  'function',
  'number',
  'string',
  'object',
  'symbol',
  'bigint',
  'boolean',
  'undefined',
  'unknown',
]);

function parseArgs(argv) {
  const options = {
    lib: path.join(__dirname, '../../vendor/libnode-js/lib'),
    out: null,
    pin: path.join(__dirname, '../node-pin.toml'),
    indent: 2,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--lib':
        options.lib = argv[++i];
        break;
      case '--out':
        options.out = argv[++i];
        break;
      case '--pin':
        options.pin = argv[++i];
        break;
      case '--help':
        process.stdout.write(
          'usage: record.cjs [--lib <lib-dir>] [--out <recorded.json>] [--pin <node-pin.toml>]\n',
        );
        process.exit(0);
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!options.out) throw new Error('missing --out <recorded.json>');
  return options;
}

/** Every `.js` file under `dir`, sorted for deterministic output. */
function listJsFiles(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && entry.name.endsWith('.js')) out.push(full);
    }
  }
  return out.sort();
}

/**
 * Generic pre-order AST walk. `visit(node, ancestors)` receives the ancestor
 * chain with the nearest parent last, so classification never needs a second
 * pass or mutation of the tree.
 */
function walk(node, ancestors, visit) {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, ancestors, visit);
    return;
  }
  if (typeof node.type !== 'string') return;
  visit(node, ancestors);
  const next = [...ancestors, node];
  for (const childKey of Object.keys(node)) {
    if (childKey === 'type' || childKey === 'loc' || childKey === 'start' || childKey === 'end') {
      continue;
    }
    walk(node[childKey], next, visit);
  }
}

/** Static property name of a member expression, or null when dynamic. */
function propertyName(member) {
  if (!member.computed && member.property && member.property.type === 'Identifier') {
    return member.property.name;
  }
  if (
    member.computed &&
    member.property &&
    (member.property.type === 'Literal' || member.property.type === 'StringLiteral') &&
    typeof member.property.value === 'string'
  ) {
    return member.property.value;
  }
  return null;
}

/**
 * Names bound by an ObjectPattern, skipping rest elements.
 *
 * Returns both the member name and the local binding so `{ a: b }` can be
 * followed later: `a` is the namespace member, `b` is the local alias.
 */
function patternBindings(pattern) {
  const bindings = [];
  for (const property of pattern.properties) {
    if (property.type === 'RestElement') continue;
    let member = null;
    if (property.key && property.key.type === 'Identifier') member = property.key.name;
    else if (property.key && typeof property.key.value === 'string') member = property.key.value;
    if (member === null) continue;

    let local = member;
    if (property.value && property.value.type === 'Identifier') local = property.value.name;
    else if (property.value && property.value.type === 'AssignmentPattern' && property.value.left.type === 'Identifier') {
      local = property.value.left.name;
    }
    bindings.push({ member, local });
  }
  return bindings;
}

function isInternalBindingCall(node) {
  return (
    node.type === 'CallExpression' &&
    node.callee &&
    node.callee.type === 'Identifier' &&
    node.callee.name === 'internalBinding' &&
    node.arguments.length > 0 &&
    node.arguments[0].type === 'Literal' &&
    typeof node.arguments[0].value === 'string'
  );
}

/**
 * Scan one parsed file and fold its findings into `sink`.
 *
 * `sink.namespaces`: Map<namespace, Map<member, {properties, called, guards}>>
 * `sink.files`: Map<namespace, Set<relative path>>
 *
 * Recognised shapes, which is every form `lib/**` actually uses:
 *
 *   const { a, b } = internalBinding('ns');          // members a, b
 *   const b = internalBinding('ns');                 // alias, then b.x
 *   internalBinding('ns').member();                  // member, function
 *   const { c } = internalBinding('ns').member;      // member, sub-property c
 *   const m = internalBinding('ns').member;          // alias, then m.x
 */
function analyzeFile(ast, relative, sink) {
  /**
   * Local identifier -> the namespace member it refers to.
   * `at: null` means the identifier is the namespace object itself.
   * @type {Map<string, {namespace: string, at: string|null}>}
   */
  const aliases = new Map();

  const namespaceOf = (namespace) => {
    let ns = sink.namespaces.get(namespace);
    if (!ns) {
      ns = new Map();
      sink.namespaces.set(namespace, ns);
    }
    let files = sink.files.get(namespace);
    if (!files) {
      files = new Set();
      sink.files.set(namespace, files);
    }
    files.add(relative);
    return ns;
  };

  const memberOf = (namespace, member) => {
    const ns = namespaceOf(namespace);
    let entry = ns.get(member);
    if (!entry) {
      entry = { properties: new Set(), called: false, guards: new Set() };
      ns.set(member, entry);
    }
    return entry;
  };

  walk(ast, [], (node, ancestors) => {
    const parent = ancestors.length > 0 ? ancestors[ancestors.length - 1] : null;

    /**
     * Resolve `expr` to the namespace member it reads, following one level of
     * binding alias. Returns `{ namespace, member }` where `member` is null
     * when `expr` is the bare namespace object.
     */
    const resolveMember = (expr) => {
      if (!expr) return null;
      if (isInternalBindingCall(expr)) return { namespace: expr.arguments[0].value, member: null };
      if (expr.type === 'Identifier') {
        const alias = aliases.get(expr.name);
        if (!alias) return null;
        return { namespace: alias.namespace, member: alias.at };
      }
      if (expr.type === 'MemberExpression') {
        const outer = resolveMember(expr.object);
        if (!outer || outer.member !== null) return null;
        const name = propertyName(expr);
        if (name === null) return null;
        return { namespace: outer.namespace, member: name };
      }
      return null;
    };

    if (isInternalBindingCall(node)) {
      // Registers the namespace and the file even when no member is read.
      namespaceOf(node.arguments[0].value);
    }

    // Declarations are the only place bindings are introduced: handle them
    // once here rather than re-deriving the shape at every nested node.
    if (node.type === 'VariableDeclarator') {
      const resolved = resolveMember(node.init);
      if (!resolved) return;
      if (resolved.member === null) {
        if (node.id.type === 'ObjectPattern') {
          for (const { member, local } of patternBindings(node.id)) {
            memberOf(resolved.namespace, member);
            aliases.set(local, { namespace: resolved.namespace, at: member });
          }
        } else if (node.id.type === 'Identifier') {
          aliases.set(node.id.name, { namespace: resolved.namespace, at: null });
        }
        return;
      }
      const entry = memberOf(resolved.namespace, resolved.member);
      if (node.id.type === 'ObjectPattern') {
        // `const { signals } = ns.member` names sub-properties.
        for (const inner of patternBindings(node.id)) {
          entry.properties.add(inner.member);
          aliases.set(inner.local, { namespace: resolved.namespace, at: resolved.member });
        }
      } else if (node.id.type === 'Identifier') {
        aliases.set(node.id.name, { namespace: resolved.namespace, at: resolved.member });
      }
      return;
    }

    if (node.type === 'MemberExpression') {
      const resolved = resolveMember(node);
      if (!resolved || resolved.member === null) return;
      const entry = memberOf(resolved.namespace, resolved.member);

      // `internalBinding('ns').member(...)` and `<alias>.member(...)`
      if (parent && parent.type === 'CallExpression' && parent.callee === node) {
        entry.called = true;
      }

      // `typeof ns.member === 'number'` proves the static kind when the
      // running binary cannot hand the namespace out. `typeof` wraps the
      // member, so the comparison is the grandparent in that shape.
      const isTypeofWrap =
        parent && parent.type === 'UnaryExpression' && parent.operator === 'typeof';
      const compare = isTypeofWrap
        ? ancestors.length > 1
          ? ancestors[ancestors.length - 2]
          : null
        : parent;
      if (compare && compare.type === 'BinaryExpression' && compare.operator === '===') {
        const subject = isTypeofWrap ? parent : node;
        const other = compare.left === subject ? compare.right : compare.left;
        if (other && other.type === 'Literal' && typeof other.value === 'string') {
          entry.guards.add(other.value);
        }
      }
      return;
    }

    if (node.type === 'CallExpression' && node.callee && node.callee.type === 'Identifier') {
      // A destructured member called by its local name proves function:
      // `const { queryObjects: q } = internalBinding('internal_only_v8'); q()`
      const alias = aliases.get(node.callee.name);
      if (alias && alias.at !== null) {
        memberOf(alias.namespace, alias.at).called = true;
      }
    }
  });
}

/** Parse a TOML pin file just enough to read `[node] version`. */
function readPinVersion(pinPath) {
  try {
    const text = fs.readFileSync(pinPath, 'utf8');
    const match = /^\s*version\s*=\s*"([^"]+)"/m.exec(text);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const acorn = require('internal/deps/acorn/acorn/dist/acorn');

  const files = listJsFiles(options.lib);
  if (files.length === 0) throw new Error(`no .js files under ${options.lib}`);

  const sink = { namespaces: new Map(), files: new Map() };
  const parseErrors = [];
  for (const file of files) {
    const relative = path.relative(options.lib, file).split(path.sep).join('/');
    const source = fs.readFileSync(file, 'utf8');
    let ast;
    try {
      ast = acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        allowHashBang: true,
        allowAwaitOutsideFunction: true,
        // Node compiles builtins inside a CommonJS wrapper, so a top-level
        // `return` is legal there (lib/internal/quic/*, dtls/* use it for
        // early build-flag exits) even though a bare script forbids it.
        allowReturnOutsideFunction: true,
      });
    } catch (error) {
      parseErrors.push({ file: relative, error: String(error.message) });
      continue;
    }
    analyzeFile(ast, relative, sink);
  }

  const staticNamespaces = [...sink.namespaces.keys()].sort();
  const runtime = captureRuntime(staticNamespaces);
  const runtimeByName = new Map(runtime.map((entry) => [entry.namespace, entry]));

  /** @type {Record<string, unknown>} */
  const namespaces = {};
  let unreachable = 0;
  for (const namespace of staticNamespaces) {
    const observed = runtimeByName.get(namespace);
    const staticMembers = sink.namespaces.get(namespace) || new Map();
    /** @type {Record<string, {kind: string, arity?: number, properties: string[], origin: string}>} */
    const members = {};

    if (observed && observed.reachable) {
      for (const [name, shape] of Object.entries(observed.members)) {
        members[name] = {
          kind: shape.kind,
          ...(shape.arity !== undefined ? { arity: shape.arity } : {}),
          ...(shape.properties.length > 0 ? { properties: shape.properties.slice().sort() } : {}),
          origin: 'runtime',
        };
      }
    }

    for (const [name, info] of staticMembers) {
      const existing = members[name];
      const properties = [...info.properties].sort();
      // A runtime kind always wins. Without one, a call site proves function,
      // and a `typeof x === 'string'` guard proves the guarded type.
      const guarded = [...info.guards].find((kind) => kind !== 'function' && kind !== 'undefined');
      const staticKind = info.called ? 'function' : guarded && MEMBER_KINDS.has(guarded) ? guarded : 'unknown';
      if (existing) {
        if (existing.origin === 'runtime') existing.origin = 'both';
        if (existing.kind === 'unknown' && staticKind !== 'unknown') existing.kind = staticKind;
        if (properties.length > 0) {
          const merged = new Set([...(existing.properties || []), ...properties]);
          existing.properties = [...merged].sort();
        }
      } else {
        members[name] = {
          kind: staticKind,
          ...(properties.length > 0 ? { properties } : {}),
          origin: 'static',
        };
      }
    }

    const reachable = Boolean(observed && observed.reachable);
    if (!reachable) unreachable += 1;
    namespaces[namespace] = {
      namespace,
      reachable,
      ...(reachable ? {} : { unreachable_reason: observed ? observed.error : 'not captured' }),
      members,
      files: [...(sink.files.get(namespace) || new Set())].sort(),
    };
  }

  for (const member of Object.values(namespaces)) {
    for (const shape of Object.values(member.members)) {
      if (!MEMBER_KINDS.has(shape.kind)) shape.kind = 'unknown';
    }
  }

  const pinVersion = readPinVersion(options.pin);
  const recorded = {
    meta: {
      schema_version: 1,
      generator: 'tools/contract-gen/record.cjs',
      lib_dir: path.relative(path.join(__dirname, '../..'), options.lib).split(path.sep).join('/'),
      builtin_files: files.length,
      parse_errors: parseErrors,
      node: {
        version: process.version,
        v8: process.versions.v8,
        executable: process.execPath,
        pin_version: pinVersion,
        pin_match: pinVersion !== null && process.version.replace(/^v/, '') === pinVersion,
        expose_internals: typeof require('internal/test/binding').internalBinding === 'function',
      },
      namespaces: staticNamespaces.length,
      members: Object.values(namespaces).reduce(
        (total, ns) => total + Object.keys(ns.members).length,
        0,
      ),
      unreachable,
    },
    namespaces,
  };

  fs.mkdirSync(path.dirname(path.resolve(options.out)), { recursive: true });
  fs.writeFileSync(options.out, `${JSON.stringify(recorded, null, options.indent)}\n`);

  const memberTotal = recorded.meta.members;
  process.stderr.write(
    `recorded ${staticNamespaces.length} namespaces / ${memberTotal} members ` +
      `from ${files.length} files (node ${process.version}, pin ${pinVersion ?? 'unknown'})\n`,
  );
  if (unreachable > 0) {
    const names = Object.values(namespaces)
      .filter((ns) => !ns.reachable)
      .map((ns) => ns.namespace)
      .join(', ');
    process.stderr.write(`runtime-unreachable (${unreachable}): ${names}\n`);
  }
  if (parseErrors.length > 0) {
    process.stderr.write(`parse errors: ${parseErrors.length} (see meta.parse_errors)\n`);
  }
}

// Exported for record.test.cjs. Requiring this file does not run the recorder.
module.exports = { analyzeFile, walk, propertyName, patternBindings, listJsFiles, main };

if (require.main === module) {
  main();
}
