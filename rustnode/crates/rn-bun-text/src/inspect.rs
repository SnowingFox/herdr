//! `Bun.ArrayBufferSink`.
//!
//! The measured shape is strange enough to be worth stating before anything
//! about the buffering:
//!
//! ```text
//! typeof Bun.ArrayBufferSink                  "function"
//! Bun.ArrayBufferSink.length                  0
//! typeof Bun.ArrayBufferSink.prototype        "undefined"     <-- note
//! Object.getPrototypeOf(new Bun.ArrayBufferSink()) has
//!     close flush end start write ref unref _getFd sinkId
//! Object.getOwnPropertyNames(instance)        []
//! ```
//!
//! So the class has **no `prototype` property** while its instances still have
//! methods. Reading `Ctor.prototype` reports `undefined` and would make a gate
//! conclude the class has no surface at all; the methods live on the object you
//! reach through `Object.getPrototypeOf(instance)`, and that is what the tests
//! read.
//!
//! # Behaviour
//!
//! * `write` returns the byte count of **that call**, not a running total.
//! * `end()` returns a new `ArrayBuffer` and **ignores a destination argument**.
//! * A second `end()` returns an empty buffer rather than throwing.
//! * `flush()` returns `0`; the buffered bytes stay buffered.
//! * `write(number)` throws `ERR_INVALID_ARG_TYPE` with Bun's message.
//!
//! The implementation here is the JavaScript prototype object, because every one
//! of those behaviours is about the *shape* of the instances and keeping the
//! methods in one place makes the shape obvious.

/// The prototype object's JavaScript, evaluated once by
/// [`install`](crate::bindings::install).
///
/// It returns a constructor that creates its instances with an ordinary object
/// literal as the prototype, which is how the class ends up without a
/// `prototype` property while its instances still carry every method.
/// The sink's methods and per-instance state, as a factory.
///
/// It returns `{ proto, create }`: `create` makes an instance whose prototype is
/// `proto`, and Rust wraps the whole thing in a real constructor. The constructor
/// has to be built natively because deleting a function's `prototype` property is
/// a `TypeError` in JavaScript — it is non-configurable on a function — while
/// V8's `FunctionTemplate::remove_prototype` does exactly that.
pub const SINK_JS: &str = r#"
(function installArrayBufferSink() {
  'use strict';

  // The shared prototype. `Object.getPrototypeOf(instance)` reaches it; the
  // constructor does not expose it, which is why `Bun.ArrayBufferSink.prototype`
  // is `undefined` while the instance still has nine methods.
  const proto = {};

  // Per-instance state lives in a WeakMap rather than on the instance, which is
  // why `Object.getOwnPropertyNames(instance)` is `[]`.
  const state = new WeakMap();

  // The name the encoder uses for a string. Inlined rather than reaching for a
  // global so the sink works in a context that has no `TextEncoder`.
  function utf8(text) {
    const out = [];
    for (let index = 0; index < text.length; index++) {
      let code = text.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
        const trail = text.charCodeAt(index + 1);
        if (trail >= 0xdc00 && trail <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (trail - 0xdc00);
          index++;
        }
      }
      if (code < 0x80) out.push(code);
      else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      else if (code < 0x10000)
        out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      else
        out.push(
          0xf0 | (code >> 18),
          0x80 | ((code >> 12) & 0x3f),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f)
        );
    }
    return Uint8Array.from(out);
  }

  function write(value) {
    const current = state.get(this);
    if (current === undefined) return 0;
    let bytes;
    if (typeof value === 'string') {
      bytes = utf8(value);
    } else if (value instanceof ArrayBuffer) {
      bytes = new Uint8Array(value);
    } else if (ArrayBuffer.isView(value)) {
      bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    } else {
      const error = new TypeError('write() expects a string, ArrayBufferView, or ArrayBuffer');
      error.code = 'ERR_INVALID_ARG_TYPE';
      throw error;
    }
    if (current.closed) return 0;
    for (let index = 0; index < bytes.length; index++) current.chunks.push(bytes[index]);
    return bytes.length;
  }

  function flush() {
    // Measured `0`: flushing does not hand back the buffered bytes, so they
    // survive until `end()`.
    return 0;
  }

  function end() {
    const current = state.get(this);
    const bytes =
      current === undefined || current.closed ? new Uint8Array(0) : Uint8Array.from(current.chunks);
    if (current !== undefined) {
      current.chunks = [];
      current.closed = true;
    }
    // A fresh `ArrayBuffer` every time, and an empty one after the first call.
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  function start(options) {
    const current = state.get(this);
    if (current === undefined) return undefined;
    current.chunks = [];
    current.closed = false;
    if (options && typeof options === 'object' && options.stream === true) current.stream = true;
    return undefined;
  }

  function close() {
    const current = state.get(this);
    if (current !== undefined) current.closed = true;
  }

  function ref() { return this; }
  function unref() { return this; }
  function getFd() { return -1; }

  Object.defineProperty(proto, 'sinkId', {
    value: 0,
    writable: false,
    enumerable: false,
    configurable: true,
  });
  proto.close = close;
  proto.flush = flush;
  proto.end = end;
  proto.start = start;
  proto.write = write;
  proto.ref = ref;
  proto.unref = unref;
  proto._getFd = getFd;

  // Creating an instance is the one thing the constructor body needs, and `new`
  // and a plain call both work because the Rust side always returns an object.
  function create(options) {
    const instance = Object.create(proto);
    state.set(instance, {
      chunks: [],
      closed: false,
      stream: !!(options && typeof options === 'object' && options.stream),
    });
    return instance;
  }

  return { proto, create };
});
"#;
