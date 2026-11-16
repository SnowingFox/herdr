// Generates `tests/data/values-oracle.json`: the answers a real Bun gives for
// `deepEquals`, `deepMatch`, `inspect`, `escapeHTML`, `concatArrayBuffers`,
// `allocUnsafe`, `indexOfLine` and the deterministic `semver` cases.
//
//     bun tests/record-values-oracle.js > tests/data/values-oracle.json
//
// Only deterministic results are recorded. `nanoseconds`, `sleep`, the UUIDs and
// anything measuring wall time are compared as invariants in the Rust tests
// instead, because their absolute values differ between two runs of the same
// binary and a recorded literal would pin nothing.

'use strict';

const B = globalThis.Bun;

function attempt(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return {
      ok: false,
      ctor: error.constructor.name,
      code: error.code,
      message: error.message,
    };
  }
}

class Point {
  constructor() {
    this.a = 1;
  }
}

const deepEqualsCases = [
  // Scalars and the -0/NaN trap.
  [1, 1], [1, 2], ['1', 1], [NaN, NaN], [-0, 0], [0, -0], [null, undefined],
  [null, null], [undefined, undefined], [Infinity, Infinity], [1n, 1n], [1n, 1],
  [Symbol.for('a'), Symbol.for('a')], [Symbol.for('a'), Symbol.for('b')],
  // Objects and key order.
  [{ a: 1, b: [1, 2] }, { a: 1, b: [1, 2] }],
  [{ a: 1, b: 2 }, { b: 2, a: 1 }],
  [{ a: 1 }, { a: 1, b: undefined }],
  // Arrays: the non-strict undefined tolerance.
  [[1, 2], { 0: 1, 1: 2, length: 2 }],
  [[1], [1, undefined]],
  [[1, 2], [1, 2, 3]],
  // Prototypes are not compared.
  [Object.create({ x: 1 }), Object.create({ y: 1 })],
  [{ a: 1 }, Object.create({ a: 1 })],
  [new Point(), { a: 1 }],
  [new Point(), new Point()],
  // Built-ins.
  [new Date(0), new Date(0)],
  [new Date(0), 0],
  [new Date(0), new Date(1000)],
  [new Map([['a', 1]]), new Map([['a', 1]])],
  [new Map([['a', 1]]), new Map([['a', 2]])],
  [new Map([['a', 1], ['b', 2]]), new Map([['b', 2], ['a', 1]])],
  [new Set([1, 2]), new Set([1, 2])],
  [new Set([1, 2]), new Set([2, 1])],
  [new Set([1]), new Set([1, 2])],
  [new Uint8Array([1, 2]), [1, 2]],
  [new Uint8Array([1, 2]), new Uint8Array([1, 2])],
  [new Uint8Array([1]), new Int8Array([1])],
  [new Uint8Array([1]).buffer, new Uint8Array([1]).buffer],
  [/a/g, /a/g],
  [/a/g, /a/i],
  [new Error('x'), new Error('x')],
  [new Error('x'), new Error('y')],
  [new TypeError('x'), new Error('x')],
  [new Number(1), new Number(1)],
  [new String('a'), 'a'],
  [function () {}, function () {}],
];

const deepMatchCases = [
  [{ a: 1 }, { a: 1, b: 2 }],
  [{ a: 1, b: 2 }, { a: 1 }],
  [{ a: { b: 1 } }, { a: { b: 1, c: 2 } }],
  [{ a: { b: 1 } }, { a: {} }],
  [[1, 2], [1, 2]],
  [[1, 2], [1, 2, 3]],
  [[1, 2, 3], [1, 2]],
  [[1], { 0: 1 }],
  [{ a: 1 }, [1]],
  [{ a: undefined }, { a: undefined }],
  [{ a: undefined }, {}],
  [{ a: null }, { a: null }],
  [{ a: null }, { a: undefined }],
  [{ a: NaN }, { a: NaN }],
  [{ a: -0 }, { a: 0 }],
  [{ a: '1' }, { a: 1 }],
  [{ a: /x/ }, { a: /x/ }],
  [new Map([['a', 1]]), new Map([['a', 2]])],
  [new Map([['a', 1]]), new Map([['a', 1], ['b', 2]])],
  [new Map([['a', 1]]), new Map([['b', 1]])],
  [new Set([1]), new Set([1, 2])],
  [new Set([1]), new Set([3])],
  [new Date(0), new Date(1000)],
  [new Date(0), 0],
  [new Uint8Array([1]), new Uint8Array([1])],
  [new Uint8Array([1]), new Uint8Array([1, 2])],
  [new Uint8Array([1]), new Uint8Array([2])],
  [new Uint8Array([1]), [1]],
  [[1], new Uint8Array([1])],
  [{ a: [{ b: 1 }] }, { a: [{ b: 1, c: 2 }] }],
  [{ a: [{ b: 1 }] }, { a: [{ b: 2 }] }],
  [{}, {}],
  [{}, { a: 1 }],
];

const inspectCases = [
  42, -1, 1.5, -0, Infinity, NaN, 'hi', 'a"b', "it's", '', true, null, undefined,
  10n, Symbol('x'), Symbol.for('s'), Symbol(), [], [1], [1, 'a', null, undefined, true],
  [[1, 2], [3]], [{ a: 1 }], {}, { a: 1 }, { a: 'x' }, { a: { b: 1 } },
  { a: 1, b: 2, c: 3 }, { a: [1, 2] }, new Map([['a', 1], ['b', 2]]),
  new Map([['a', { x: 1 }]]), new Map(), new Set([1, 2]), new Set([{ x: 1 }]),
  new Set(), new Date(0), new Date(NaN), /a/gi, function foo() {}, function () {},
  () => {}, class X {}, new Uint8Array([1, 2]), new Uint8Array(0),
  new Float64Array([1.5]), new ArrayBuffer(4), new WeakMap(), new WeakSet(),
  Object.create(null), { get a() { return 1; } }, { set a(v) {} },
  { get a() { return 1; }, set a(v) {} }, { a: 1, get b() { return 2; } },
  { 'a-b': 1, 'c d': 2 }, { 0: 'a', 1: 'b' }, [Symbol('x')], { f() {} },
  { f: function g() {} }, { C: class Y {} }, [], {}, [[[[1]]]],
  Array.from({ length: 10 }, (_, i) => i + 1),
  Array.from({ length: 11 }, (_, i) => i + 1),
  Array.from({ length: 20 }, (_, i) => i + 1),
  'a\tb\r\nc', 'a\u0001b', '日本語', 'x'.repeat(200), { a: undefined },
  [undefined], [1, , 3],
];

const inspectTableCases = [
  [[{ a: 1, b: 2 }]],
  [[{ a: 1 }, { a: 2 }]],
  [[{ a: 1, b: 22 }, { a: 333, b: 4 }]],
  [[]],
  [['ab']],
  [[[1, 2]]],
  [5],
  [{ x: 1, y: 2 }],
  [[{ a: { b: 1 } }]],
  [[{ 'x y': 1 }]],
  [[{ a: 1, b: undefined }]],
];

const concatCases = [
  [[[1, 2], [3, 4]]],
  [[[1, 2], [3, 4]], 4],
  [[]],
  ['buffers'],
  ['mixed'],
];

const out = {
  deepEquals: [],
  deepMatch: [],
  inspect: [],
  inspectTable: [],
  concatArrayBuffers: [],
  allocUnsafe: [],
  indexOfLine: [],
};

// `deepEquals` with the third argument recorded as null when absent, so the
// Rust can tell `deepEquals(a, b)` from `deepEquals(a, b, false)`.
for (const [a, b] of deepEqualsCases) {
  for (const strict of [null, true]) {
    const result = strict === null ? B.deepEquals(a, b) : B.deepEquals(a, b, strict);
    out.deepEquals.push([label(a), label(b), strict, result]);
  }
}

for (const [pattern, value] of deepMatchCases) {
  const result = attempt(() => B.deepMatch(pattern, value));
  out.deepMatch.push([label(pattern), label(value), result]);
}

for (const value of inspectCases) {
  out.inspect.push([label(value), attempt(() => B.inspect(value))]);
}

for (const [rows] of inspectTableCases) {
  out.inspectTable.push([label(rows), attempt(() => B.inspectTable(rows))]);
}

// `concatArrayBuffers` needs its inputs rebuilt from a description, because the
// JSON cannot carry a typed array.
for (const [chunks, total] of concatCases.map((entry) => [entry[0], entry[1]])) {
  const result = attempt(() => {
    let buffers;
    if (chunks === 'buffers') {
      buffers = [new Uint8Array([1]).buffer, new Uint8Array([2]).buffer];
    } else if (chunks === 'mixed') {
      buffers = [new Uint8Array([1]), new Uint8Array([2]).buffer];
    } else {
      buffers = chunks.map((bytes) => new Uint8Array(bytes));
    }
    const value = total === undefined ? B.concatArrayBuffers(buffers) : B.concatArrayBuffers(buffers, total);
    return {
      ctor: value.constructor.name,
      byteLength: value.byteLength,
      hex: [...new Uint8Array(value)].map((b) => b.toString(16).padStart(2, '0')).join(''),
    };
  });
  out.concatArrayBuffers.push([label(chunks), total === undefined ? null : total, result]);
}

for (const size of [-1, null, '8', 1.5, 0, 16]) {
  const result = attempt(() => {
    const value = size === null ? B.allocUnsafe() : B.allocUnsafe(size);
    return {
      ctor: value.constructor.name,
      length: value.length,
      isUint8Array: value instanceof Uint8Array,
      isBuffer: typeof Buffer !== 'undefined' && value instanceof Buffer,
      byteLength: value.byteLength,
    };
  });
  out.allocUnsafe.push([size, result]);
}

// `allocUnsafe` pooling is an identity fact, so it is its own probe.
out.allocUnsafePooled = (() => {
  const a = B.allocUnsafe(4);
  const b = B.allocUnsafe(4);
  return a.buffer === b.buffer;
})();

const indexCases = [
  ['abc\ndef\nghi', 0],
  ['abc\ndef\nghi', 4],
  ['abcdef', 0],
  ['', 0],
  ['a\nb', null],
  ['abc\r\ndef', 0],
  ['a\nb', 100],
];

for (const [text, offset] of indexCases) {
  const bytes = Buffer.from(text);
  const result = attempt(() => (offset === null ? B.indexOfLine(bytes) : B.indexOfLine(bytes, offset)));
  out.indexOfLine.push([text, offset, result]);
}

out.indexOfLineView = attempt(() => B.indexOfLine(new Uint8Array([97, 10, 98]), 0));
out.indexOfLineString = attempt(() => B.indexOfLine('abc'));

// Describes a value well enough that the Rust test can rebuild it. Only the
// shapes these probes use are covered; anything else round-trips as a marker.
function label(value) {
  if (value === undefined) return { k: 'undefined' };
  if (value === null) return { k: 'null' };
  if (typeof value === 'number') {
    if (value !== value) return { k: 'number', v: 'NaN' };
    if (value === Infinity) return { k: 'number', v: 'Infinity' };
    if (value === -Infinity) return { k: 'number', v: '-Infinity' };
    if (value === 0 && 1 / value === -Infinity) return { k: 'number', v: '-0' };
    return { k: 'number', v: value };
  }
  if (typeof value === 'string') return { k: 'string', v: value };
  if (typeof value === 'boolean') return { k: 'boolean', v: value };
  if (typeof value === 'bigint') return { k: 'bigint', v: value.toString() };
  if (typeof value === 'symbol') return { k: 'symbol', v: value.description, global: !!Symbol.keyFor(value) };
  if (typeof value === 'function') {
    return { k: 'function', v: value.name, isClass: /^class\b/.test(Function.prototype.toString.call(value)) };
  }
  if (value instanceof Date) {
    const time = value.getTime();
    return { k: 'date', v: time !== time ? 'NaN' : time };
  }
  if (value instanceof RegExp) return { k: 'regexp', v: value.source, flags: value.flags };
  if (value instanceof Error) return { k: 'error', name: value.name, v: value.message };
  if (value instanceof Map) return { k: 'map', v: [...value].map(([key, entry]) => [label(key), label(entry)]) };
  if (value instanceof Set) return { k: 'set', v: [...value].map(label) };
  if (value instanceof ArrayBuffer) return { k: 'arraybuffer', v: [...new Uint8Array(value)] };
  if (ArrayBuffer.isView(value)) return { k: 'typedarray', ctor: value.constructor.name, v: [...value] };
  if (value instanceof WeakMap) return { k: 'weakmap' };
  if (value instanceof WeakSet) return { k: 'weakset' };
  if (Array.isArray(value)) {
    const items = [];
    for (let i = 0; i < value.length; i++) {
      items.push(i in value ? label(value[i]) : { k: 'hole' });
    }
    return { k: 'array', v: items };
  }
  if (value instanceof Point) return { k: 'point' };
  if (value.constructor && value.constructor.name === 'Number') return { k: 'boxednumber', v: Number(value) };
  if (value.constructor && value.constructor.name === 'String') return { k: 'boxedstring', v: String(value) };
  if (Object.getPrototypeOf(value) === null) {
    return { k: 'object', v: Object.keys(value).map((key) => [key, label(value[key])]), nullProto: true };
  }
  // Describe accessors by kind rather than by invoking them: reading a getter
  // here would freeze its return value into the oracle and make the recorded
  // answer depend on when the recording ran.
  const entries = Object.keys(value).map((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && descriptor.get && descriptor.set) return [key, { k: 'gettersetter' }];
    if (descriptor && descriptor.get) return [key, { k: 'getter' }];
    if (descriptor && descriptor.set) return [key, { k: 'setter' }];
    return [key, label(value[key])];
  });
  return {
    k: 'object',
    v: entries,
    proto: value.constructor && value.constructor.name !== 'Object' ? value.constructor.name : null,
  };
}

process.stdout.write(JSON.stringify(out, null, 1) + '\n');
