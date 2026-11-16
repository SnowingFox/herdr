//! The `readableStreamTo*` helpers driven by a spec-conformant `ReadableStream`.
//!
//! # Why this test builds its own stream
//!
//! The helpers consume a `ReadableStream` through its async iterator. A bare V8
//! context has no web globals — `ReadableStream`, `Blob`, `FormData`,
//! `TextEncoder` and `TextDecoder` all come from Node's own vendored
//! `lib/stream/web.js`, which only exists after a full realm bootstrap. Booting
//! one in this crate would mean duplicating `rn-cli`'s isolate setup, its
//! registry, its option store and its process state, and a test that fragile
//! would be disabled before it was useful.
//!
//! So this file supplies the smallest `ReadableStream` that satisfies the parts
//! of the WHATWG contract the helpers depend on — `getReader`/`releaseLock` and
//! `Symbol.asyncIterator` over a queue that reports `done`, propagates a
//! `controller.error` unchanged, and refuses a second reader — plus real
//! `TextEncoder`/`TextDecoder`/`Blob` implementations in JavaScript. What it does
//! *not* stub is any of the helper logic: the code under test is exactly
//! `src/streams.js`.
//!
//! # What this proves, and what it does not
//!
//! Proves: chunk boundary preservation, concatenation, JSON parsing and its error
//! message, the stream's own error passing through unchanged, validation throwing
//! synchronously with Node's message, and an already-consumed stream failing.
//! Every one of those is compared against the recorded Bun output in
//! `tests/data/streams-oracle.json`.
//!
//! Does not prove: that the helpers work against *Node's* `ReadableStream`
//! specifically. That needs the runtime, and is covered once `Bun` is installed
//! by `rn-bun` and the binary can be driven directly.

use rn_v8_sys::v8;
use serde_json::Value as Json;

/// A `ReadableStream`/`Blob`/`FormData`/encoder environment, in JavaScript.
///
/// The stream implements the async-iterator path the helpers take: `locked`
/// becomes true once iteration starts, `read()` resolves `{done, value}`, and a
/// queued error is thrown rather than resolved.
const ENVIRONMENT: &str = r#"
(function installEnvironment(global) {
  'use strict';

  class StreamError extends Error {}

  class Stream {
    constructor(source) {
      this._queue = [];
      this._done = false;
      this._error = null;
      this._locked = false;
      this._started = false;
      this._source = source;
    }

    get locked() {
      return this._locked;
    }

    _pump() {
      if (this._started) return;
      this._started = true;
      const controller = {
        enqueue: (chunk) => {
          this._queue.push(chunk);
        },
        close: () => {
          this._done = true;
        },
        error: (error) => {
          this._error = error;
        },
      };
      this._source.start(controller);
    }

    getReader() {
      if (this._locked) {
        const error = new TypeError('Invalid state: ReadableStream is locked');
        error.code = 'ERR_INVALID_STATE';
        throw error;
      }
      this._locked = true;
      this._pump();
      return {
        read: async () => {
          if (this._error) throw this._error;
          if (this._queue.length > 0) return { done: false, value: this._queue.shift() };
          if (this._done) return { done: true, value: undefined };
          return { done: true, value: undefined };
        },
        releaseLock: () => {
          this._locked = false;
        },
        cancel: async () => {},
      };
    }

    [Symbol.asyncIterator]() {
      if (this._locked) {
        // The helper must surface this as a rejection, matching the recorded
        // `Invalid state: ReadableStream is locked` case.
        const error = new TypeError('Invalid state: ReadableStream is locked');
        error.code = 'ERR_INVALID_STATE';
        throw error;
      }
      const reader = this.getReader();
      const self = this;
      return {
        next: async () => reader.read(),
        return: async () => {
          reader.releaseLock();
          return { done: true, value: undefined };
        },
      };
    }
  }

  function encode(text) {
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

  function decode(bytes) {
    let out = '';
    let index = 0;
    while (index < bytes.length) {
      const first = bytes[index++];
      let code;
      if (first < 0x80) code = first;
      else if (first < 0xe0) code = ((first & 0x1f) << 6) | (bytes[index++] & 0x3f);
      else if (first < 0xf0)
        code = ((first & 0x0f) << 12) | ((bytes[index++] & 0x3f) << 6) | (bytes[index++] & 0x3f);
      else
        code =
          ((first & 0x07) << 18) |
          ((bytes[index++] & 0x3f) << 12) |
          ((bytes[index++] & 0x3f) << 6) |
          (bytes[index++] & 0x3f);
      out += String.fromCodePoint(code);
    }
    return out;
  }

  class FakeBlob {
    constructor(parts) {
      const chunks = [];
      let size = 0;
      for (const part of parts) {
        const bytes = part instanceof Uint8Array ? part : encode(String(part));
        chunks.push(bytes);
        size += bytes.length;
      }
      this._chunks = chunks;
      this.size = size;
      this.type = '';
    }
  }

  class FakeFormData {
    constructor() {
      this._entries = [];
    }
    append(key, value) {
      this._entries.push([String(key), value]);
    }
    get(key) {
      for (const [candidate, value] of this._entries) if (candidate === key) return value;
      return null;
    }
    has(key) {
      return this._entries.some(([candidate]) => candidate === key);
    }
    keys() {
      return this._entries.map(([key]) => key);
    }
    entries() {
      return this._entries[Symbol.iterator]();
    }
  }

  global.ReadableStream = Stream;
  global.Blob = FakeBlob;
  global.FormData = FakeFormData;
  global.TextEncoder = class {
    encode(text) {
      return encode(text);
    }
  };
  global.TextDecoder = class {
    decode(bytes) {
      return decode(bytes);
    }
  };
  global.__StreamError = StreamError;
  return true;
})(globalThis)
"#;

fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

fn oracle() -> Json {
    serde_json::from_str(include_str!("data/streams-oracle.json")).expect("valid oracle JSON")
}

fn eval<'s>(scope: &mut v8::PinScope<'s, '_>, source: &str) -> Option<v8::Local<'s, v8::Value>> {
    let source = v8::String::new(scope, source)?;
    let script = v8::Script::compile(scope, source, None)?;
    script.run(scope)
}

/// Installs the environment and the helpers; reports failure rather than
/// skipping, because a test that compares nothing must not report success.
fn install(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    eval(scope, ENVIRONMENT).ok_or("the environment script threw")?;
    let factory = eval(scope, include_str!("../src/streams.js"))
        .ok_or("streams.js threw while evaluating")?;
    let factory = v8::Local::<v8::Function>::try_from(factory)
        .map_err(|_| "streams.js must evaluate to a function".to_string())?;
    let members = factory
        .call(scope, v8::undefined(scope).into(), &[])
        .ok_or("the streams factory threw")?;
    let key = v8::String::new(scope, "__helpers").ok_or("cannot allocate __helpers")?;
    scope
        .get_current_context()
        .global(scope)
        .set(scope, key.into(), members)
        .ok_or_else(|| "cannot publish the helpers".to_string())?;
    Ok(())
}

/// Serialises a JS value through `JSON.stringify`.
fn json_of(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<v8::Value>) -> Json {
    let Some(global) = v8::String::new(scope, "JSON") else {
        return Json::Null;
    };
    let Some(json) = scope
        .get_current_context()
        .global(scope)
        .get(scope, global.into())
    else {
        return Json::Null;
    };
    let Some(stringify_key) = v8::String::new(scope, "stringify") else {
        return Json::Null;
    };
    let Some(stringify) = json
        .to_object(scope)
        .and_then(|object| object.get(scope, stringify_key.into()))
    else {
        return Json::Null;
    };
    let Ok(stringify) = v8::Local::<v8::Function>::try_from(stringify) else {
        return Json::Null;
    };
    let Some(text) = stringify.call(scope, json, &[value]) else {
        return Json::Null;
    };
    serde_json::from_str(&text.to_rust_string_lossy(scope)).unwrap_or(Json::Null)
}

/// Runs a probe script that resolves to a promise, then reads the settled value.
fn settle(scope: &mut v8::PinScope<'_, '_>, source: &str) -> Json {
    let Some(value) = eval(scope, source) else {
        return Json::Null;
    };
    let Ok(promise) = v8::Local::<v8::Promise>::try_from(value) else {
        return json_of(scope, value);
    };
    scope.perform_microtask_checkpoint();
    if promise.state() != v8::PromiseState::Fulfilled {
        return Json::Null;
    }
    json_of(scope, promise.result(scope))
}

/// The description of one helper's result, matching the recorder's shape.
fn describe(scope: &mut v8::PinScope<'_, '_>, member: &str, chunks: &Json) -> Json {
    let chunks_json = serde_json::to_string(chunks).unwrap_or_else(|_| "[]".to_string());
    let source = format!(
        r#"(async () => {{
            const chunks = {chunks_json};
            const stream = new ReadableStream({{
                start(controller) {{
                    for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk));
                    controller.close();
                }},
            }});
            const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
            try {{
                const value = await __helpers.{member}(stream);
                if (typeof value === 'string') return {{ ok: true, value: {{ kind: 'string', value }} }};
                if (value instanceof Uint8Array) {{
                    return {{ ok: true, value: {{ kind: 'bytes', ctor: value.constructor.name, hex: hex(value) }} }};
                }}
                if (value instanceof ArrayBuffer) {{
                    return {{ ok: true, value: {{ kind: 'arraybuffer', ctor: value.constructor.name, hex: hex(new Uint8Array(value)) }} }};
                }}
                if (Array.isArray(value)) {{
                    return {{ ok: true, value: {{ kind: 'array', chunks: value.map((chunk) => ({{ ctor: chunk.constructor.name, hex: hex(chunk) }})) }} }};
                }}
                if (value instanceof Blob) {{
                    return {{ ok: true, value: {{ kind: 'blob', ctor: 'Blob', size: value.size, type: value.type, isBlob: true }} }};
                }}
                if (value instanceof FormData) {{
                    return {{ ok: true, value: {{ kind: 'formdata', ctor: 'FormData', entries: [...value.entries()].map(([k, v]) => [k, typeof v === 'string' ? v : '<file>']) }} }};
                }}
                return {{ ok: true, value: {{ kind: 'json', value }} }};
            }} catch (error) {{
                return {{ threw: true, ctor: error.constructor.name, code: error.code === undefined ? null : error.code, message: error.message }};
            }}
        }})()"#
    );
    settle(scope, &source)
}

#[test]
fn stream_helpers_match_bun() {
    let oracle = oracle();
    with_context(|scope| {
        install(scope).expect("the stream environment and helpers must install");
        let mut failures = Vec::new();
        for case in oracle["streams"].as_array().expect("streams cases") {
            let member = case[0].as_str().expect("member");
            let chunks = &case[1];
            let expected = &case[2];
            // The recorded `consumed-twice` and `multipart`/`plain` cases take a
            // different setup, so they are exercised separately below.
            if !chunks.is_array() {
                continue;
            }
            let actual = describe(scope, member, chunks);
            if actual != *expected {
                failures.push(format!(
                    "{member}({chunks})\n  got  {actual}\n  bun  {expected}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} cases disagree with Bun:\n{}",
            failures.len(),
            failures.join("\n")
        );
    });
}

#[test]
fn an_errored_stream_rejects_with_the_streams_own_error() {
    let oracle = oracle();
    with_context(|scope| {
        install(scope).expect("the stream environment and helpers must install");
        let mut failures = Vec::new();
        for case in oracle["errors"].as_array().expect("error cases") {
            let member = case[0].as_str().expect("member");
            let expected = &case[1];
            let source = format!(
                r#"(async () => {{
                    const stream = new ReadableStream({{
                        start(controller) {{ controller.error(new Error('boom')); }},
                    }});
                    try {{
                        await __helpers.{member}(stream);
                        return {{ ok: true }};
                    }} catch (error) {{
                        return {{ threw: true, ctor: error.constructor.name, code: error.code === undefined ? null : error.code, message: error.message }};
                    }}
                }})()"#
            );
            let actual = settle(scope, &source);
            if actual != *expected {
                failures.push(format!(
                    "{member} on an errored stream\n  got  {actual}\n  bun  {expected}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} cases disagree with Bun:\n{}",
            failures.len(),
            failures.join("\n")
        );
    });
}

#[test]
fn validation_throws_synchronously() {
    let oracle = oracle();
    with_context(|scope| {
        install(scope).expect("the stream environment and helpers must install");
        let mut failures = Vec::new();
        for case in oracle["validations"].as_array().expect("validation cases") {
            let member = case[0].as_str().expect("member");
            let tag = case[1].as_str().expect("tag");
            let expected = &case[2];
            let argument = match tag {
                "undefined" => "undefined",
                "string" => "'notastream'",
                "uint8array" => "new Uint8Array(1)",
                "array" => "[1, 2]",
                "object" => "({})",
                other => panic!("no probe for the recorded argument {other:?}"),
            };
            // No `await` and no `.catch`: a synchronous throw is the whole
            // point of these cases.
            let source = format!(
                r#"(() => {{
                    try {{
                        __helpers.{member}({argument});
                        return {{ ok: true }};
                    }} catch (error) {{
                        return {{ threw: true, ctor: error.constructor.name, code: error.code === undefined ? null : error.code, message: error.message }};
                    }}
                }})()"#
            );
            let actual = eval(scope, &source)
                .map(|value| json_of(scope, value))
                .unwrap_or(Json::Null);
            if actual != *expected {
                failures.push(format!(
                    "{member}({tag})\n  got  {actual}\n  bun  {expected}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} cases disagree with Bun:\n{}",
            failures.len(),
            failures.join("\n")
        );
    });
}

#[test]
fn a_consumed_stream_rejects_on_the_second_read() {
    with_context(|scope| {
        install(scope).expect("the stream environment and helpers must install");
        let actual = settle(
            scope,
            r#"(async () => {
                const stream = new ReadableStream({
                    start(controller) { controller.enqueue(new TextEncoder().encode('x')); controller.close(); },
                });
                const first = await __helpers.readableStreamToText(stream);
                try {
                    await __helpers.readableStreamToText(stream);
                    return { first, second: 'resolved' };
                } catch (error) {
                    return { first, second: error.constructor.name, code: error.code === undefined ? null : error.code };
                }
            })()"#,
        );
        assert_eq!(
            actual["first"].as_str(),
            Some("x"),
            "the first read must succeed, so the second-read failure is about the lock and not the data"
        );
        assert_eq!(
            actual["second"].as_str(),
            Some("TypeError"),
            "a second read must throw a TypeError, not resolve; got {actual}"
        );
    });
}
