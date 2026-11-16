'use strict';

// The value-shape half of the text/misc group, in JavaScript.
//
// `deepEquals`, `deepMatch` and `inspect` all walk arbitrary object graphs: they
// meet Maps, Sets, getters, cycles, and cross-realm values. Doing that through
// V8's Rust API means re-implementing `Map.prototype.entries`, prototype
// identity and the iteration protocol by hand, and each of those is a place to
// be subtly wrong. Written here they are ordinary property reads.
//
// This file is evaluated once by `install` and the functions it returns are
// published on the `Bun` object. `stringWidth` is passed in rather than
// reimplemented, so column measurement stays in Rust where the generated
// Unicode table is.
//
// Every rule below was measured against Bun 1.4.4; `tests/data/values-oracle.json`
// and `tests/values_parity.rs` hold the oracle's own answers.

(function installValueMembers(stringWidth) {
  'use strict';

  const SAME = Object.is;

  // --- deepEquals -----------------------------------------------------------

  // Bun's `deepEquals` is not `util.isDeepStrictEqual`, and the differences are
  // measured rather than inferred:
  //
  //   * `Object.is` decides scalars, so NaN equals NaN and -0 differs from 0;
  //   * prototypes are not compared in the default mode, so a class instance
  //     with the same own keys as a plain object is equal to it;
  //   * `strict` adds exactly one rule — **constructor names must match** — plus
  //     array lengths (which fall out of the same comparison);
  //   * without `strict`, an array's missing element equals an `undefined`
  //     element, so `[1]` equals `[1, undefined]`, and an object key that is
  //     `undefined` on both sides is skipped.
  //
  // The constructor *name* is what `strict` compares, not the constructor's
  // identity: two different classes both named `Dup` compare equal, and a class
  // literally named `Object` compares equal to `{}`.
  function deepEquals(a, b, strict) {
    return !!strict ? strictEqual(a, b, [], 0) : looseEqual(a, b, [], 0);
  }

  function looseEqual(a, b, stack, depth) {
    if (SAME(a, b)) return true;
    if (depth > 512) return false;
    if (a === null || a === undefined || b === null || b === undefined) return false;
    if (typeof a !== 'object' || typeof b !== 'object') return false;

    if (cycleSeen(a, b, stack)) return true;
    // An array is never an array-like object, whatever its keys say: `[1,2]` is
    // not `{0:1, 1:2, length:2}` even without `strict`.
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    stack.push(a, b);
    try {
      return compareObjects(a, b, false, stack, depth);
    } finally {
      stack.pop();
      stack.pop();
    }
  }

  function strictEqual(a, b, stack, depth) {
    if (SAME(a, b)) return true;
    if (depth > 512) return false;
    if (a === null || a === undefined || b === null || b === undefined) return false;
    if (typeof a !== 'object' || typeof b !== 'object') return false;

    if (cycleSeen(a, b, stack)) return true;
    stack.push(a, b);
    try {
      // The one rule `strict` adds beyond lengths: the constructors must be
      // named the same. A null prototype and a plain object both name `Object`.
      if (constructorName(a) !== constructorName(b)) return false;
      if (Array.isArray(a) !== Array.isArray(b)) return false;
      if (Array.isArray(a) && a.length !== b.length) return false;
      return compareObjects(a, b, true, stack, depth);
    } finally {
      stack.pop();
      stack.pop();
    }
  }

  function constructorName(value) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype === null) return 'Object';
    const constructor = prototype.constructor;
    if (constructor === undefined) return 'Object';
    return typeof constructor.name === 'string' && constructor.name !== ''
      ? constructor.name
      : 'Object';
  }

  function cycleSeen(a, b, stack) {
    for (let i = 0; i < stack.length; i += 2) {
      if (stack[i] === a && stack[i + 1] === b) return true;
    }
    return false;
  }

  // The shared body once the scalar, cycle, array-vs-object and (for `strict`)
  // constructor checks have passed.
  function compareObjects(a, b, strict, stack, depth) {
    const aMap = a instanceof Map;
    const bMap = b instanceof Map;
    if (aMap !== bMap) return false;
    const aSet = a instanceof Set;
    const bSet = b instanceof Set;
    if (aSet !== bSet) return false;

    // Typed arrays and ArrayBuffers compare by constructor and by bytes, before
    // own keys, because their indices are own keys.
    const aTyped = typedName(a);
    const bTyped = typedName(b);
    if (aTyped !== null || bTyped !== null) {
      if (aTyped !== bTyped) return false;
      return sameBytes(a, b);
    }

    const aDate = a instanceof Date;
    const bDate = b instanceof Date;
    if (aDate !== bDate) return false;
    if (aDate) {
      const x = Date.prototype.getTime.call(a);
      const y = Date.prototype.getTime.call(b);
      return x === y || (x !== x && y !== y);
    }

    const aRegExp = a instanceof RegExp;
    const bRegExp = b instanceof RegExp;
    if (aRegExp !== bRegExp) return false;
    if (aRegExp) return a.source === b.source && a.flags === b.flags;

    const aError = a instanceof Error;
    const bError = b instanceof Error;
    if (aError !== bError) return false;
    if (aError) return a.name === b.name && a.message === b.message;

    if (aMap) return mapsEqual(a, b, strict, stack, depth);
    if (aSet) return setsEqual(a, b, strict, stack, depth);

    if (Array.isArray(a)) return arraysEqual(a, b, strict, stack, depth);
    return objectsEqual(a, b, strict, stack, depth);
  }

  // Arrays are compared element by element over the longer length. Without
  // `strict`, a missing element and an `undefined` element are the same thing,
  // which is why `[1]` equals `[1, undefined]` and `[1, , 3]` does not equal
  // `[1, 3]` (index 1 there is `undefined` against a real `3`).
  function arraysEqual(a, b, strict, stack, depth) {
    const length = Math.max(a.length, b.length);
    for (let i = 0; i < length; i++) {
      const av = a[i];
      const bv = b[i];
      if (!strict && av === undefined && bv === undefined) continue;
      if (!(strict ? strictEqual(av, bv, stack, depth + 1) : looseEqual(av, bv, stack, depth + 1))) {
        return false;
      }
    }
    return true;
  }

  function objectsEqual(a, b, strict, stack, depth) {
    const aKeys = ownKeys(a);
    const bKeys = ownKeys(b);
    if (strict && aKeys.length !== bKeys.length) return false;

    for (let i = 0; i < aKeys.length; i++) {
      const key = aKeys[i];
      const av = read(a, key);
      const bv = read(b, key);
      // The non-strict skip: a key that is `undefined` on both sides does not
      // count, which is how `{a:1}` equals `{a:1, b:undefined}`.
      if (!strict && av === undefined && bv === undefined) continue;
      if (!(strict ? strictEqual(av, bv, stack, depth + 1) : looseEqual(av, bv, stack, depth + 1))) {
        return false;
      }
    }

    if (strict) return true;

    for (let i = 0; i < bKeys.length; i++) {
      const key = bKeys[i];
      if (aKeys.indexOf(key) !== -1) continue;
      if (read(b, key) === undefined) continue;
      return false;
    }
    return true;
  }

  function mapsEqual(a, b, strict, stack, depth) {
    // Key order is irrelevant, so each of `a`'s entries is looked up in `b`.
    if (a.size !== b.size) return false;
    for (const [key, value] of a) {
      if (!b.has(key)) return false;
      const equal = strict
        ? strictEqual(value, b.get(key), stack, depth + 1)
        : looseEqual(value, b.get(key), stack, depth + 1);
      if (!equal) return false;
    }
    return true;
  }

  function setsEqual(a, b, strict, stack, depth) {
    // Membership, not order: equal sizes plus a one-to-one structural match is a
    // partition, so `new Set([1,2])` equals `new Set([2,1])`.
    if (a.size !== b.size) return false;
    const remaining = [...b];
    for (const member of a) {
      let found = -1;
      for (let i = 0; i < remaining.length; i++) {
        const equal = strict
          ? strictEqual(member, remaining[i], [], 0)
          : looseEqual(member, remaining[i], [], 0);
        if (equal) {
          found = i;
          break;
        }
      }
      if (found === -1) return false;
      remaining.splice(found, 1);
    }
    return true;
  }

  // --- deepMatch ------------------------------------------------------------

  // The pattern is the FIRST argument, and the match is partial: the value may
  // carry more keys. **Arrays are the only special case** — an array pattern
  // requires an array value of the same length, and elements are compared
  // recursively.
  //
  // Everything else goes through the same own-enumerable-key walk, which is why
  // these are all measured `true`: a `Map` pattern against a `Set` value (a Map
  // has no own enumerable keys), a `Date` against a number-free object, and a
  // `RegExp` against `{}`. There is no container-kind or class check at all.
  function deepMatch(pattern, value) {
    // Both operands must be objects, and this is checked before any comparison:
    // `deepMatch(1, 1)` and `deepMatch(new Date(0), 0)` both throw rather than
    // returning `false`. The message is Bun's, and the error carries no `code`.
    if (!isObjectLike(pattern) || !isObjectLike(value)) {
      throw new TypeError('Expected 2 objects to match');
    }
    return matches(pattern, value, 0);
  }

  // `typeof value === 'object' && value !== null`: a Date, Map, RegExp and array
  // all qualify, and a function does not, which is what Bun's `isObject()` says.
  function isObjectLike(value) {
    return value !== null && typeof value === 'object';
  }

  function matches(pattern, value, depth) {
    if (SAME(pattern, value)) return true;
    if (depth > 512) return false;
    // A nested `null` or `undefined` matches only itself, which `SAME` already
    // ruled out. The primitive case is the same: only an identical primitive.
    if (pattern === null || pattern === undefined) return false;
    if (value === null || value === undefined) return false;
    if (typeof pattern !== 'object' || typeof value !== 'object') return false;

    if (Array.isArray(pattern)) {
      if (!Array.isArray(value)) return false;
      if (pattern.length !== value.length) return false;
      for (let i = 0; i < pattern.length; i++) {
        if (!matches(pattern[i], value[i], depth + 1)) return false;
      }
      return true;
    }

    // Typed arrays are indices plus a length, so a `Uint8Array` pattern matches
    // an array value when the value is at least as long — measured: a
    // `Uint8Array([1,2])` pattern matches `[1,2,3]` and fails `[1,2]`.
    const keys = ownKeys(pattern);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      // The key has to *exist*, even when its value is `undefined`:
      // `deepMatch({a:undefined}, {})` is measured `false`.
      if (!hasOwn(value, key)) return false;
      if (!matches(pattern[key], value[key], depth + 1)) return false;
    }
    return true;
  }

  // --- helpers --------------------------------------------------------------

  // The constructor name of a typed array, DataView or ArrayBuffer, or `null`.
  function typedName(value) {
    if (value instanceof ArrayBuffer) return 'ArrayBuffer';
    if (ArrayBuffer.isView(value)) {
      const name = value.constructor && value.constructor.name;
      return name || 'TypedArray';
    }
    return null;
  }

  function sameBytes(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    if (a instanceof ArrayBuffer) {
      const x = new Uint8Array(a);
      const y = new Uint8Array(b);
      for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
      return true;
    }
    const x = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    const y = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
    return true;
  }

  // Own keys: enumerable string keys first, then own symbols. Prototypes are
  // never walked, which is the rule that makes `new A()` equal `{a:1}`.
  function ownKeys(value) {
    const names = Object.keys(value);
    const symbols = Object.getOwnPropertySymbols(value).filter((symbol) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, symbol);
      return descriptor && descriptor.enumerable;
    });
    return symbols.length === 0 ? names : names.concat(symbols);
  }

  function hasOwn(value, key) {
    return Object.prototype.hasOwnProperty.call(value, key);
  }

  // Reads one key, reporting an accessor by its kind rather than invoking it.
  // Bun does not call getters, so a getter never makes two objects differ by
  // value: both sides report `[Getter]` and compare equal.
  const GETTER = Object.freeze({ toString: () => '[Getter]' });
  const SETTER = Object.freeze({ toString: () => '[Setter]' });
  const GETTER_SETTER = Object.freeze({ toString: () => '[Getter/Setter]' });

  function read(value, key) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return undefined;
    if (descriptor.get || descriptor.set) {
      if (descriptor.get && descriptor.set) return GETTER_SETTER;
      return descriptor.get ? GETTER : SETTER;
    }
    return descriptor.value;
  }

  // --- inspect --------------------------------------------------------------

  // Bun's format, which is not Node's:
  //   * multiline by default, with a trailing comma after the last property;
  //   * double-quoted strings;
  //   * `[ 1, 2 ]` for an array of at most ten primitives, `[\n  …\n]` otherwise;
  //   * `[Object ...]` where Node prints `[Object]`;
  //   * `inspect()` with no argument returns `""`, not `"undefined"`.

  function inspect(value, options) {
    if (arguments.length === 0) return '';
    let depth = Infinity;
    if (options && typeof options === 'object' && options.depth !== undefined && options.depth !== null) {
      depth = Number(options.depth);
    }
    return render(value, Number.isFinite(depth) ? depth : Infinity, 0, []);
  }

  function render(value, depth, indent, seen) {
    const type = typeof value;
    if (value === null) return 'null';
    if (type === 'undefined') return 'undefined';
    if (type === 'string') return quote(value);
    if (type === 'number') return renderNumber(value);
    if (type === 'bigint') return value.toString() + 'n';
    if (type === 'boolean') return value ? 'true' : 'false';
    if (type === 'symbol') return value.toString();
    if (type === 'function') return renderFunction(value);

    if (value === GETTER) return '[Getter]';
    if (value === SETTER) return '[Setter]';
    if (value === GETTER_SETTER) return '[Getter/Setter]';

    for (let i = 0; i < seen.length; i++) {
      if (seen[i] === value) return '[Circular]';
    }

    if (value instanceof Date) {
      const time = Date.prototype.getTime.call(value);
      return time === time ? new Date(time).toISOString() : 'Invalid Date';
    }
    if (value instanceof RegExp) return String(value);
    if (value instanceof Error) return renderError(value, depth, indent);
    if (value instanceof WeakMap) return 'WeakMap {}';
    if (value instanceof WeakSet) return 'WeakSet {}';
    if (value instanceof Promise) return 'Promise { <resolved> }';
    if (value instanceof ArrayBuffer) {
      const bytes = [...new Uint8Array(value)];
      return 'ArrayBuffer(' + bytes.length + ') ' + renderArray(bytes, depth, indent, seen);
    }
    const typed = typedName(value);
    if (typed !== null) {
      const items = [...value];
      return typed + '(' + items.length + ') ' + renderArray(items, depth, indent, seen);
    }
    if (value instanceof Number) return '[Number: ' + Number(value) + ']';
    if (value instanceof Boolean) return '[Boolean: ' + (value.valueOf() ? 'true' : 'false') + ']';
    if (value instanceof String) return quote(String(value));

    if (depth < 0) return '[Object ...]';

    if (value instanceof Map) return renderMap(value, depth, indent, seen);
    if (value instanceof Set) return renderSet(value, depth, indent, seen);
    if (Array.isArray(value)) {
      if (depth === 0 && value.length > 0) return '[Array ...]';
      return renderArray(value, depth, indent, seen);
    }
    return renderObject(value, depth, indent, seen);
  }

  // An array is inline when it has at most ten elements and every element is a
  // primitive. That is the measured rule: eleven one-character strings, or a
  // single object element, both go multiline while twenty wide strings inline.
  // An array element renders its own text, and a hole — an index that was never
  // assigned — prints `empty item` rather than `undefined`. Extra non-index own
  // properties are appended after the elements as `key: value`.
  function arrayParts(items, depth, indent, seen) {
    const parts = [];
    for (let i = 0; i < items.length; i++) {
      parts.push(i in items ? render(items[i], depth - 1, indent + 1, seen) : 'empty item');
    }
    for (const key of Object.getOwnPropertyNames(items)) {
      if (key === 'length' || /^(0|[1-9][0-9]*)$/.test(key)) continue;
      parts.push(key + ': ' + render(items[key], depth - 1, indent + 1, seen));
    }
    return parts;
  }

  function renderArray(items, depth, indent, seen) {
    if (items.length === 0) return '[]';
    let inline = items.length <= 10;
    if (inline) {
      for (let i = 0; i < items.length; i++) {
        if (!isPrimitive(items[i])) {
          inline = false;
          break;
        }
      }
      if (inline) {
        for (const key of Object.getOwnPropertyNames(items)) {
          if (key === 'length' || /^(0|[1-9][0-9]*)$/.test(key)) continue;
          inline = false;
          break;
        }
      }
    }
    if (inline) {
      return '[ ' + arrayParts(items, depth, indent, seen).join(', ') + ' ]';
    }
    seen.push(items);
    try {
      const inner = pad(indent + 1);
      return '[\n' + inner + arrayParts(items, depth, indent, seen).join(', ') + '\n' + pad(indent) + ']';
    } finally {
      seen.pop();
    }
  }

  // `inspect` lists **every** own property, enumerable or not, string and symbol
  // alike — unlike `deepEquals`, which only sees enumerable keys. That is why a
  // getter defined with `enumerable: false` still prints as `[Getter]`.
  function inspectKeys(value) {
    return Object.getOwnPropertyNames(value).concat(Object.getOwnPropertySymbols(value));
  }

  function renderObject(value, depth, indent, seen) {
    const keys = inspectKeys(value);
    const prefix = prefixOf(value);
    if (keys.length === 0) return prefix + '{}';
    if (depth === 0) {
      // At the depth limit the object still lists its own keys; it is each
      // *value* that truncates to `[Object ...]`. Measured:
      // `inspect({a:{b:{c:{d:1}}}}, {depth:2})` prints `c: [Object ...]`, not a
      // bare `[Object ...]` for the whole object.
      const inner = pad(indent + 1);
      const lines = [];
      for (const key of keys) {
        const label = typeof key === 'symbol' ? '[' + key.toString() + ']' : formatKey(key);
        lines.push(inner + label + ': [Object ...],');
      }
      return prefix + '{\n' + lines.join('\n') + '\n' + pad(indent) + '}';
    }
    seen.push(value);
    try {
      const inner = pad(indent + 1);
      const lines = [];
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const label = typeof key === 'symbol' ? '[' + key.toString() + ']' : formatKey(key);
        const rendered = render(read(value, key), depth - 1, indent + 1, seen);
        lines.push(inner + label + ': ' + rendered + ',');
      }
      return prefix + '{\n' + lines.join('\n') + '\n' + pad(indent) + '}';
    } finally {
      seen.pop();
    }
  }

  function renderMap(value, depth, indent, seen) {
    if (value.size === 0) return 'Map {}';
    seen.push(value);
    try {
      const inner = pad(indent + 1);
      const lines = [];
      for (const [key, entry] of value) {
        lines.push(
          inner +
            render(key, depth - 1, indent + 1, seen) +
            ': ' +
            render(entry, depth - 1, indent + 1, seen) +
            ','
        );
      }
      return 'Map(' + value.size + ') {\n' + lines.join('\n') + '\n' + pad(indent) + '}';
    } finally {
      seen.pop();
    }
  }

  function renderSet(value, depth, indent, seen) {
    if (value.size === 0) return 'Set {}';
    seen.push(value);
    try {
      const inner = pad(indent + 1);
      const lines = [];
      for (const member of value) {
        lines.push(inner + render(member, depth - 1, indent + 1, seen) + ',');
      }
      return 'Set(' + value.size + ') {\n' + lines.join('\n') + '\n' + pad(indent) + '}';
    } finally {
      seen.pop();
    }
  }

  function renderError(error, depth, indent) {
    // Bun prints the error's own header and then any extra own properties.
    const header = String(error).split('\n')[0];
    const extras = [];
    for (const key of Object.keys(error)) {
      extras.push(' ' + key + ': ' + render(error[key], depth - 1, indent + 1, []));
    }
    return header + '\n' + extras.join('\n') + (extras.length ? '\n' : '');
  }

  function renderFunction(value) {
    const tag = Object.prototype.toString.call(value).slice(8, -1);
    const name = value.name;
    if (tag === 'GeneratorFunction') return name ? '[GeneratorFunction: ' + name + ']' : '[GeneratorFunction]';
    if (tag === 'AsyncFunction') return name ? '[AsyncFunction: ' + name + ']' : '[AsyncFunction]';
    if (isClass(value)) return '[class ' + (name || '(anonymous)') + ']';
    return name ? '[Function: ' + name + ']' : '[Function]';
  }

  // `class X {}` has no `[[Construct]]`-only marker to read, so the source's
  // leading keyword is what distinguishes it from a function declaration.
  function isClass(value) {
    return Function.prototype.toString.call(value).startsWith('class');
  }

  function prefixOf(value) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype === null) return '[Object: null prototype] ';
    const constructor = prototype.constructor;
    if (typeof constructor === 'function' && constructor.name && constructor.name !== 'Object') {
      return constructor.name + ' ';
    }
    return '';
  }

  function isPrimitive(value) {
    const type = typeof value;
    return value === null || (type !== 'object' && type !== 'function');
  }

  function pad(level) {
    return '  '.repeat(level);
  }

  function formatKey(key) {
    // A key that is not a valid identifier is double-quoted, matching how string
    // values print. Bun never uses single quotes.
    return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : quote(String(key));
  }

  function renderNumber(value) {
    if (value !== value) return 'NaN';
    if (value === Infinity) return 'Infinity';
    if (value === -Infinity) return '-Infinity';
    if (value === 0 && 1 / value === -Infinity) return '-0';
    return String(value);
  }

  function quote(text) {
    // Double quotes, with `"` and `\` escaped and the control characters as
    // `\uXXXX`; everything else, wide and combining characters included, prints
    // as itself.
    let out = '"';
    for (const character of text) {
      const code = character.codePointAt(0);
      if (character === '"') out += '\\"';
      else if (character === '\\') out += '\\\\';
      else if (code === 0x0a) out += '\\n';
      else if (code === 0x0d) out += '\\r';
      else if (code === 0x09) out += '\\t';
      else if (code < 0x20 || code === 0x7f) out += '\\u' + code.toString(16).padStart(4, '0');
      else out += character;
    }
    return out + '"';
  }

  // --- inspect.table --------------------------------------------------------

  // A box table whose column widths come from `stringWidth`, so wide characters
  // line up. Column order follows the first row's keys.
  function inspectTable(rows, columnsOrOptions) {
    const options = Array.isArray(columnsOrOptions) ? { columns: columnsOrOptions } : columnsOrOptions || {};
    const normalised = normaliseRows(rows);
    if (normalised === null) return '';

    let columns;
    if (Array.isArray(options.columns)) {
      columns = options.columns.map(String);
    } else {
      columns = [];
      for (const entry of normalised) {
        for (const key of Object.keys(entry.value)) {
          if (columns.indexOf(key) === -1) columns.push(key);
        }
      }
      if (columns.length === 0) columns.push('Values');
    }

    const header = ['', ...columns];
    const body = normalised.map((entry) => [
      entry.label,
      ...columns.map((column) => cellText(entry.value[column])),
    ]);

    const widths = header.map((_, index) => {
      let widest = stringWidth(String(header[index]));
      for (const row of body) {
        widest = Math.max(widest, stringWidth(String(row[index])));
      }
      return widest;
    });

    const rule = (left, middle, right) =>
      left + widths.map((width) => '─'.repeat(width + 2)).join(middle) + right + '\n';
    const renderRow = (cells) => {
      let out = '│';
      for (let i = 0; i < cells.length; i++) {
        const text = String(cells[i]);
        out += ' ' + text + ' '.repeat(widths[i] - stringWidth(text)) + ' │';
      }
      return out + '\n';
    };

    let out = rule('┌', '┬', '┐');
    out += renderRow(header);
    out += rule('├', '┼', '┤');
    for (const row of body) out += renderRow(row);
    out += rule('└', '┴', '┘');
    return out;
  }

  // A table cell cannot hold a newline, so a nested object prints inline.
  function cellText(value) {
    if (value === undefined) return 'undefined';
    if (value === null) return 'null';
    if (Array.isArray(value)) return '[ ' + value.map(cellText).join(', ') + ' ]';
    if (typeof value === 'object') {
      const keys = Object.keys(value);
      if (keys.length === 0) return '{}';
      return '{ ' + keys.map((key) => key + ': ' + cellText(value[key])).join(', ') + ' }';
    }
    return render(value, Infinity, 0, []);
  }

  // `inspect.table` accepts an array of objects, an array of arrays, an object of
  // scalars, or an array of scalars; anything else renders as `""`.
  function normaliseRows(rows) {
    if (Array.isArray(rows)) {
      return rows.map((row, index) => {
        const label = String(index);
        if (Array.isArray(row)) {
          const object = {};
          for (let i = 0; i < row.length; i++) object[String(i)] = row[i];
          return { label, value: object };
        }
        if (row !== null && typeof row === 'object') return { label, value: row };
        return { label, value: { Values: row } };
      });
    }
    if (rows !== null && typeof rows === 'object') {
      // An object of scalars becomes a two-column `key | Values` table.
      return Object.keys(rows).map((key) => ({ label: key, value: { Values: rows[key] } }));
    }
    return null;
  }

  return { deepEquals, deepMatch, inspect, inspectTable };
});
