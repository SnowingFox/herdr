//! `internalBinding('http_parser')` for rustnode.
//!
//! This is the namespace `lib/internal/http/common.js` builds every HTTP server
//! and client parser from, and `lib/internal/http/server.js` uses for its
//! connection bookkeeping. Four members, from `contracts/http_parser.json`:
//!
//! ```text
//! HTTPParser        the parser class: nearly all of the work, see `parser`
//! ConnectionsList   the connection registry, see `connections`
//! methods           llhttp's HTTP_METHOD_MAP, derived from llhttp
//! allMethods        llhttp's HTTP_ALL_METHOD_MAP, derived from llhttp
//! ```
//!
//! # The parser is llhttp
//!
//! Node parses HTTP with `deps/llhttp`, a generated C state machine. Writing a
//! replacement by hand is how request-smuggling bugs appear: two parsers that
//! disagree about where a request ends are the whole vulnerability class. So the
//! vendored llhttp under `vendor/llhttp` is compiled and linked unchanged, and
//! this crate only supplies the glue — the same glue `src/node_http_parser.cc`
//! supplies, which is also the specification for the JavaScript-facing shape.
//!
//! `shim/rn_llhttp.c` is the one C file this project owns. It keeps `llhttp_t`
//! and `llhttp_settings_t` out of Rust, because both are generated structs whose
//! layout moves between releases and a stale `#[repr(C)]` mirror is an ABI bug.
//!
//! # What is copied from `src/node_http_parser.cc`
//!
//! * The four callback indices and their argument shapes.
//! * The 32-header flush at `kMaxHeaderFieldsCount`, including which pairs go out
//!   in which `kOnHeaders` call.
//! * `max_http_header_size` and `maxHeaderPairs` enforcement, with
//!   `HPE_HEADER_OVERFLOW` reported as a `code:reason` pair.
//! * `pending_pause_`, so `pause()` inside a callback takes effect after the
//!   current `execute` rather than aborting the message.
//! * `HPE_PAUSED_UPGRADE` treated as success, so the bytes after an upgrade stay
//!   with whoever takes over the connection.
//! * The parse-error object's `code`, `reason` and `bytesParsed`.
//!
//! # What is not
//!
//! `consume()` and `unconsume()` attach a parser to a `StreamBase` handle so the
//! parser, not the socket, drives reading. That needs `tcp_wrap`'s stream
//! handles, which this runtime does not have yet; the two methods exist and
//! report why they cannot work rather than silently doing nothing, because the
//! caller that reaches them has already decided to hand the socket over.
//! `lib/**` only calls `consume` when `socket._handle.isStreamBase` is set, which
//! is false here, so `require('http')` is unaffected.
//!
//! `async_hooks` tracing through the `AsyncResource` argument of `initialize` is
//! not implemented: the argument is accepted and ignored. Node reports the
//! incoming message as `HTTPINCOMINGMESSAGE`; nothing in `lib/**` depends on
//! that beyond the resource existing.

pub mod accumulator;
pub mod connections;
pub mod ffi;
pub mod js;
pub mod parser;

use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::connections::{ConnectionsList, Entry, EntryState};
use crate::parser::{Kind, Parser};

/// Members exposed on the namespace object, matching
/// `contracts/http_parser.json`.
pub const MEMBERS: &[&str] = &["ConnectionsList", "HTTPParser", "allMethods", "methods"];

/// `0` `kOnMessageBegin`. `lib/**` assigns the handler at this index.
pub const K_ON_MESSAGE_BEGIN: u32 = 0;
/// `1` `kOnHeaders`.
pub const K_ON_HEADERS: u32 = 1;
/// `2` `kOnHeadersComplete`.
pub const K_ON_HEADERS_COMPLETE: u32 = 2;
/// `3` `kOnBody`.
pub const K_ON_BODY: u32 = 3;
/// `4` `kOnMessageComplete`.
pub const K_ON_MESSAGE_COMPLETE: u32 = 4;
/// `5` `kOnExecute`. Read by `lib/**`; this crate never calls it.
pub const K_ON_EXECUTE: u32 = 5;
/// `6` `kOnTimeout`. Read by `lib/**`; this crate never calls it.
pub const K_ON_TIMEOUT: u32 = 6;

/// `kLenientNone` through `kLenientAll`, in `src/node_http_parser.cc`'s order.
///
/// `lib/internal/http/common.js` computes `calculateLenientFlags()` from these,
/// and `--http-validation=relaxed` maps to `kLenientHeaderValueRelaxed`
/// specifically, so the values are part of the contract and not just labels.
pub const LENIENT: &[(&str, u32)] = &[
    ("kLenientNone", 0),
    ("kLenientHeaders", 1 << 0),
    ("kLenientChunkedLength", 1 << 1),
    ("kLenientKeepAlive", 1 << 2),
    ("kLenientTransferEncoding", 1 << 3),
    ("kLenientVersion", 1 << 4),
    ("kLenientDataAfterClose", 1 << 5),
    ("kLenientOptionalLFAfterCR", 1 << 6),
    ("kLenientOptionalCRLFAfterChunk", 1 << 7),
    ("kLenientOptionalCRBeforeLF", 1 << 8),
    ("kLenientSpacesAfterChunkSize", 1 << 9),
    ("kLenientHeaderValueRelaxed", 1 << 10),
    // Every bit above, i.e. what `--insecure-http-parser` selects. Node computes
    // it as the OR of the specific flags; the same value is written out here
    // because `kLenientHeaderValueRelaxed` is deliberately excluded from the
    // insecure set (it relaxes header *values*, not protocol checks).
    ("kLenientAll", (1 << 10) - 1),
];

/// The `http_parser` namespace.
pub struct HttpParser;

impl BindingModule for HttpParser {
    fn namespace(&self) -> &'static str {
        "http_parser"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        install_http_parser(scope, object)?;
        install_connections_list(scope, object)?;

        let methods = string_array(scope, &ffi::methods())?;
        let all_methods = string_array(scope, &ffi::all_methods())?;
        set(scope, object, "methods", methods.into())?;
        set(scope, object, "allMethods", all_methods.into())?;
        Ok(object)
    }
}

/// Registers the `http_parser` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(HttpParser);
}

fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate http_parser member {name}"));
    };
    if object.set(scope, key.into(), value) != Some(true) {
        return Err(format!("cannot install http_parser member {name}"));
    }
    Ok(())
}

/// Installs one method on a prototype template.
fn set_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
    name: &str,
    function: v8::Local<'s, v8::FunctionTemplate>,
) -> Result<(), String> {
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the method name {name}"));
    };
    prototype.set(key.into(), function.into());
    Ok(())
}

/// Builds a JavaScript array of names, which is what `methods` and
/// `allMethods` are: `Array::New` filled from llhttp's generated tables.
fn string_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    names: &[&str],
) -> Result<v8::Local<'s, v8::Array>, String> {
    let array = v8::Array::new(scope, names.len() as i32);
    for (index, name) in names.iter().enumerate() {
        let Some(value) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate http_parser array entry {name}"));
        };
        if array.set_index(scope, index as u32, value.into()) != Some(true) {
            return Err(format!("cannot store http_parser array entry {name}"));
        }
    }
    Ok(array)
}

// ---------------------------------------------------------------------------
// HTTPParser
// ---------------------------------------------------------------------------

/// The internal field holding the `*mut Parser`.
const PARSER_FIELD: i32 = 0;
/// The internal field holding the `*mut ffi::Llhttp` this parser owns.
///
/// `pause` and `resume` are reachable from inside an llhttp callback, where
/// `execute` already holds `&mut Parser`. Reading the pointer from its own field
/// keeps those two paths from forming a second `&mut` to the same parser.
const LLHTTP_FIELD: i32 = 1;

fn install_http_parser<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(parser_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(2);

    let prototype = template.prototype_template(scope);
    // Each method is registered by hand because `FunctionTemplate::builder`
    // monomorphises per callback type: a table of them would hold eleven
    // different types. The order is `src/node_http_parser.cc`'s.
    set_method(
        scope,
        prototype,
        "close",
        v8::FunctionTemplate::builder(parser_close).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "free",
        v8::FunctionTemplate::builder(parser_free).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "remove",
        v8::FunctionTemplate::builder(parser_remove).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "execute",
        v8::FunctionTemplate::builder(parser_execute).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "finish",
        v8::FunctionTemplate::builder(parser_finish).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "initialize",
        v8::FunctionTemplate::builder(parser_initialize).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "pause",
        v8::FunctionTemplate::builder(parser_pause).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "resume",
        v8::FunctionTemplate::builder(parser_resume).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "consume",
        v8::FunctionTemplate::builder(parser_consume).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "unconsume",
        v8::FunctionTemplate::builder(parser_unconsume).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "getCurrentBuffer",
        v8::FunctionTemplate::builder(parser_get_current_buffer).build(scope),
    )?;

    let Some(class_name) = v8::String::new(scope, "HTTPParser") else {
        return Err("cannot allocate the HTTPParser class name".to_string());
    };
    template.set_class_name(class_name);

    // The constructor's own properties. These are read by `lib/**` at module
    // scope, so a missing one breaks `require('http')` at load time rather than
    // at use.
    let mut statics: Vec<(&str, v8::Local<'s, v8::Value>)> = vec![
        (
            "REQUEST",
            v8::Integer::new(scope, ffi::parser_type::REQUEST).into(),
        ),
        (
            "RESPONSE",
            v8::Integer::new(scope, ffi::parser_type::RESPONSE).into(),
        ),
        (
            "kOnMessageBegin",
            v8::Integer::new_from_unsigned(scope, K_ON_MESSAGE_BEGIN).into(),
        ),
        (
            "kOnHeaders",
            v8::Integer::new_from_unsigned(scope, K_ON_HEADERS).into(),
        ),
        (
            "kOnHeadersComplete",
            v8::Integer::new_from_unsigned(scope, K_ON_HEADERS_COMPLETE).into(),
        ),
        (
            "kOnBody",
            v8::Integer::new_from_unsigned(scope, K_ON_BODY).into(),
        ),
        (
            "kOnMessageComplete",
            v8::Integer::new_from_unsigned(scope, K_ON_MESSAGE_COMPLETE).into(),
        ),
        (
            "kOnExecute",
            v8::Integer::new_from_unsigned(scope, K_ON_EXECUTE).into(),
        ),
        (
            "kOnTimeout",
            v8::Integer::new_from_unsigned(scope, K_ON_TIMEOUT).into(),
        ),
    ];
    for (name, value) in LENIENT {
        statics.push((name, v8::Integer::new_from_unsigned(scope, *value).into()));
    }
    for (name, value) in statics {
        let Some(key) = v8::String::new(scope, name) else {
            return Err(format!("cannot allocate HTTPParser.{name}"));
        };
        template.set(key.into(), value.into());
    }

    let Some(function) = template.get_function(scope) else {
        return Err("cannot allocate the HTTPParser constructor".to_string());
    };
    set(scope, target, "HTTPParser", function.into())
}

/// Borrows the parser stored on `object`, mutably.
///
/// Only for the methods that change parser state and cannot be reached from
/// inside an llhttp callback. The ones that can — `pause`, `resume`,
/// `getCurrentBuffer` — use [`with_parser_ref`] instead, because `execute`
/// already holds the mutable borrow while a callback runs.
fn with_parser<R>(object: v8::Local<v8::Object>, body: impl FnOnce(&mut Parser) -> R) -> Option<R> {
    let raw = parser_pointer(object)?;
    // SAFETY: the pointer came from `Parser::create`. The reference is confined
    // to `body`, and nothing reachable from `body` takes a second mutable borrow
    // — see the note above and the module note on re-entrancy.
    Some(body(unsafe { &mut *raw }))
}

/// Borrows the parser stored on `object`, shared.
///
/// This is what a method callable from inside a callback must use: `execute`
/// holds `&mut Parser` for the whole parse, and a second `&mut` to the same
/// parser would be undefined behaviour even when every field it touches is a
/// `Cell`.
fn with_parser_ref<R>(object: v8::Local<v8::Object>, body: impl FnOnce(&Parser) -> R) -> Option<R> {
    let raw = parser_pointer(object)?;
    // SAFETY: as above. A shared borrow coexists with the `&mut` held by
    // `execute`, which is what the `Cell`s in `Parser` exist for.
    Some(body(unsafe { &*raw }))
}

/// The `*mut Parser` installed on a parser object.
fn parser_pointer(object: v8::Local<v8::Object>) -> Option<*mut Parser> {
    // SAFETY: the field only ever holds a pointer produced by `Parser::create`,
    // and the allocation is released by the object's own finalizer, which cannot
    // run while `object` is a live local.
    let raw =
        unsafe { object.get_aligned_pointer_from_internal_field(PARSER_FIELD, 0) } as *mut Parser;
    (!raw.is_null()).then_some(raw)
}

/// `new HTTPParser()`.
///
/// Takes no arguments, matching `HTTPParser.length === 0`; everything is set up
/// by `initialize`.
fn parser_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    // SAFETY: `args.this()` is the object the template's instance template
    // produced, so it has the internal field this constructor fills.
    let Some(raw) = (unsafe { Parser::create(scope, args.this()) }) else {
        throw(scope, "cannot allocate an HTTP parser");
        return;
    };
    // SAFETY: `raw` is the pointer `Parser::create` just returned.
    let llhttp = unsafe { (*raw).llhttp_pointer() };
    args.this().set_aligned_pointer_in_internal_field(
        PARSER_FIELD,
        raw.cast::<c_void>().cast_const(),
        0,
    );
    args.this().set_aligned_pointer_in_internal_field(
        LLHTTP_FIELD,
        llhttp.cast::<c_void>().cast_const(),
        0,
    );

    // The finalizer owns the allocation from here, so a parser that is never
    // `close()`d or `free()`d still gives its llhttp instance back.
    let address = raw as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        args.this(),
        Box::new(move || {
            let raw = address as *mut Parser;
            // SAFETY: `Parser::create` produced this pointer and nothing else
            // releases it; the finalizer runs exactly once.
            unsafe { Parser::release(raw) };
        }),
    );
    std::mem::forget(weak);
}

fn parser_close<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    if with_parser(object, |parser| parser.close()).is_none() {
        throw(scope, "HTTPParser is not initialized");
    }
}

fn parser_free<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    with_parser(object, |parser| parser.free());
}

fn parser_remove<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let object = args.this();
    let removed = with_parser(object, |parser| {
        parser.remove();
        parser.release_connections();
    });
    if removed.is_none() {
        throw(scope, "HTTPParser is not initialized");
    }
}

/// `initialize(type, asyncResource, maxHeaderSize, lenientFlags,
/// connectionsList, maxHeaderPairs)`.
fn parser_initialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let Some(kind) = args.get(0).int32_value(scope).and_then(Kind::from_i32) else {
        throw(
            scope,
            "initialize() requires HTTPParser.REQUEST or HTTPParser.RESPONSE",
        );
        return;
    };
    if !args.get(1).is_object() {
        // Node `CHECK`s this; a JavaScript TypeError is the equivalent that keeps
        // the isolate healthy.
        throw(scope, "initialize() requires an async resource object");
        return;
    }
    let max_header_size = args.get(2).number_value(scope).unwrap_or(0.0);
    let max_header_size = if max_header_size > 0.0 {
        max_header_size as u64
    } else {
        0
    };
    let lenient_flags = args.get(3).uint32_value(scope).unwrap_or(0);
    let connections = args.get(4);
    let max_header_pairs = args.get(5).int32_value(scope).unwrap_or(0).max(0) as usize;

    // Node skips `null`, `undefined` and a zero `maxHeaderPairs`, so a
    // caller that omits the last two arguments gets no limits.
    let list = if connections.is_null() || connections.is_undefined() {
        None
    } else {
        match v8::Local::<v8::Object>::try_from(connections) {
            Ok(object) => connections_list_of(object),
            Err(_) => {
                throw(scope, "initialize() requires a ConnectionsList");
                return;
            }
        }
    };

    let object = args.this();
    let result = with_parser(object, |parser| {
        parser.initialize(
            kind,
            max_header_size,
            lenient_flags,
            max_header_pairs,
            list.is_some(),
        );
        match list {
            Some(list) => parser.register_connections(scope, list),
            None => parser.release_connections(),
        }
    });
    if result.is_none() {
        throw(scope, "HTTPParser is not initialized");
    }
}

/// `execute(buffer)`.
fn parser_execute<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    let Some((data, len)) = view_bytes(args.get(0)) else {
        // Node asserts on a non-view through `ArrayBufferViewContents`, which
        // crashes the process. A TypeError says the same thing without that.
        throw(scope, "execute() requires a Buffer or TypedArray");
        return;
    };
    let object = args.this();
    // SAFETY: `data` covers `len` bytes of `args.get(0)`'s live backing store,
    // and the view stays reachable through the argument for the whole call.
    let outcome = with_parser(object, |parser| unsafe { parser.execute(data, len) });
    report(scope, outcome, rv);
}

/// `finish()`.
fn parser_finish<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    let object = args.this();
    let outcome = with_parser(object, |parser| parser.finish());
    report(scope, outcome, rv);
}

/// `pause()`.
///
/// Reaches the llhttp instance through the object's own field rather than
/// through `Parser`, because `lib/internal/http/server.js` calls this from
/// `parserOnIncoming`, which runs inside a `kOnHeadersComplete` callback while
/// `execute` holds `&mut Parser`.
fn parser_pause<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if let Some(llhttp) = llhttp_of(args.this()) {
        // SAFETY: the pointer came from `rn_llhttp_new` for this object and is
        // freed in the object's finalizer, so it is live for the whole call.
        unsafe { ffi::rn_llhttp_pause(llhttp) };
    }
}

/// `resume()`, for the same re-entrancy reason as [`parser_pause`].
fn parser_resume<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    if let Some(llhttp) = llhttp_of(args.this()) {
        // SAFETY: as above.
        unsafe { ffi::rn_llhttp_resume(llhttp) };
    }
}

/// The llhttp instance installed on a parser object.
fn llhttp_of(object: v8::Local<v8::Object>) -> Option<*mut ffi::Llhttp> {
    // SAFETY: the field only ever holds a pointer from `Parser::create`'s
    // llhttp instance, whose lifetime the object's finalizer governs.
    let raw = unsafe { object.get_aligned_pointer_from_internal_field(LLHTTP_FIELD, 0) }
        as *mut ffi::Llhttp;
    if raw.is_null() {
        None
    } else {
        Some(raw)
    }
}

/// `consume(handle)`.
///
/// Node's `Parser::Consume` is one line: `stream->PushStreamListener(parser)`.
/// The parser becomes the stream's read listener, so libuv's reads go straight
/// into `Execute` and the socket's JavaScript `onread` never runs. The socket
/// stops looking like a readable stream (`socketOnData` and `'data'` are gone)
/// and `parser[kOnExecute]` is what reports progress instead.
///
/// # What this does instead, and why it is honest
///
/// rustnode has real `StreamBase` handles now — `tcp_wrap` and `pipe_wrap` both
/// publish `isStreamBase` and are driven by `rn_uv::stream` — but that read path
/// has one listener: `deliver_read` reads `handle.onread` off the JavaScript
/// object and calls it. There is no listener stack, so there is nowhere to
/// "push" a parser that would displace `onread` without editing the read path
/// itself.
///
/// Adding that stack is a change to `rn_uv::stream`, which every socket and pipe
/// in the runtime is driven by. What it buys is the `onread`-free fast path: the
/// bytes reach `Execute` without an `ArrayBuffer` allocation and without the
/// `onStreamRead` frame. What it does **not** change is where the bytes come from
/// or who reads them, because the existing `onread` path already forwards into
/// `execute` (`lib/internal/http/server.js`'s `socketOnData`).
///
/// So this records the handle and leaves the forwarding to `onread`. The
/// contract that matters is the one that would break if this did nothing at all:
/// **exactly one reader must exist**. `lib/internal/http/server.js` guards the
/// call with `socket._handle.isStreamBase && !socket._handle._consumed` and then
/// sets `_consumed`, and `lib/internal/http/common.js`'s `freeParser` calls
/// `unconsume` whenever `parser._consumed` is set. If `consume` returned without
/// recording anything, `unconsume` would have nothing to detach and the two
/// layers would both be attached.
///
/// `unconsume` is therefore a real detach of this record, not a no-op, and
/// [`Parser::consumed_handle`] is what makes the pairing observable.
fn parser_consume<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let handle = args.get(0);
    let Ok(object) = v8::Local::<v8::Object>::try_from(handle) else {
        // Node `CHECK(args[0]->IsObject())`; a throw keeps the isolate healthy
        // and is the closest equivalent.
        throw(scope, "consume() requires a stream handle");
        return;
    };

    // `StreamBase::FromObject` unwraps the internal `StreamBase` pointer. A
    // handle from another binding has none, and Node `CHECK_NOT_NULL`s it.
    // SAFETY: the scope is live and the object is a live local, so any stream
    // pointer attached to it belongs to a binding that outlives this call.
    let Some(stream) = (unsafe { rn_uv::streams::stream_of(scope, object) }) else {
        throw(scope, "consume() requires a stream handle");
        return;
    };

    let Some(installed) = with_parser(args.this(), |parser| parser.consume(stream)) else {
        throw(scope, "HTTPParser is not initialized");
        return;
    };
    if !installed {
        // A parser already attached to a different stream is a caller bug Node
        // would not survive either; report it rather than silently switching.
        throw(scope, "HTTPParser is already consuming another stream");
    }
}

/// `unconsume()`.
///
/// `Parser::Unconsume` returns silently when `stream_` is null, which is the
/// "already unconsumed" case `lib/internal/http/common.js` relies on: `freeParser`
/// calls this whenever `parser._consumed` is set, including for parsers whose
/// socket never had a stream handle.
fn parser_unconsume<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    with_parser(args.this(), |parser| parser.unconsume());
}

/// `getCurrentBuffer()`.
fn parser_get_current_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let bytes = with_parser_ref(args.this(), |parser| parser.current_buffer().to_vec());
    let Some(bytes) = bytes else {
        throw(scope, "HTTPParser is not initialized");
        return;
    };
    match js::buffer_from_public(scope, &bytes) {
        Some(buffer) => rv.set(buffer),
        None => throw(scope, "cannot allocate the current buffer"),
    }
}

/// Turns an [`parser::Outcome`] into the value `execute`/`finish` return.
fn report<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    outcome: Option<parser::Outcome>,
    mut rv: v8::ReturnValue,
) {
    use parser::Outcome;
    match outcome {
        // No parser installed: the JavaScript call could not have happened.
        None => {}
        Some(Outcome::Consumed(n)) => {
            rv.set(v8::Integer::new(scope, n as i32).into());
        }
        Some(Outcome::Finished) => {}
        Some(Outcome::Failed(error)) => {
            let Some(exception) = parse_error_object(scope, &error) else {
                return;
            };
            rv.set(exception);
        }
        Some(Outcome::CallbackThrew) => {
            // The exception is already pending; returning without setting a
            // value is what makes it propagate to the caller of `execute`.
        }
    }
}

/// Builds the `Error` `Parser::Execute` returns on a parse failure.
///
/// `lib/internal/http/server.js` distinguishes a parse error from a byte count
/// with `ret instanceof Error`, and `prepareError` reads `code`, `reason` and
/// `bytesParsed` off it, so all three have to be own properties.
fn parse_error_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: &parser::ParseError,
) -> Option<v8::Local<'s, v8::Value>> {
    let message = v8::String::new(scope, &error.message)?;
    let exception = v8::Exception::error(scope, message);
    let object = v8::Local::<v8::Object>::try_from(exception).ok()?;
    let code = v8::String::new(scope, &error.code)?;
    let reason = v8::String::new(scope, &error.reason)?;
    let bytes = v8::Integer::new(scope, error.bytes_parsed as i32);
    for (name, value) in [
        ("code", v8::Local::<v8::Value>::from(code)),
        ("reason", v8::Local::<v8::Value>::from(reason)),
        ("bytesParsed", v8::Local::<v8::Value>::from(bytes)),
    ] {
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), value)?;
    }
    Some(exception)
}

/// A `Buffer` or typed array argument as `(pointer, length)`.
///
/// Node uses `ArrayBufferViewContents`, which accepts any view and takes its
/// whole extent; a `DataView` of length zero therefore parses as an empty
/// execute rather than an error.
fn view_bytes(value: v8::Local<v8::Value>) -> Option<(*const u8, usize)> {
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value).ok()?;
    let length = view.byte_length();
    let data = view.data().cast::<u8>();
    if data.is_null() {
        // A zero-length view has no backing store; llhttp accepts an empty
        // range, so a dangling-but-aligned pointer is the honest stand-in.
        if length == 0 {
            return Some((std::ptr::NonNull::<u8>::dangling().as_ptr(), 0));
        }
        return None;
    }
    Some((data, length))
}

fn throw(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

// ---------------------------------------------------------------------------
// ConnectionsList
// ---------------------------------------------------------------------------

/// The internal field holding the `Rc<RefCell<ConnectionsList>>` as a raw box.
const CONNECTIONS_FIELD: i32 = 0;

/// A shared handle to a list, which a parser keeps so it can add and remove
/// itself without reaching back into the JavaScript object.
pub(crate) type SharedList = Rc<RefCell<ConnectionsList>>;

fn shared_list_of(object: v8::Local<v8::Object>) -> Option<SharedList> {
    // SAFETY: the field only ever holds a pointer produced by
    // `connections_list_constructor`, released by that object's finalizer.
    let raw = unsafe { object.get_aligned_pointer_from_internal_field(CONNECTIONS_FIELD, 0) }
        as *mut Rc<RefCell<ConnectionsList>>;
    if raw.is_null() {
        return None;
    }
    // SAFETY: as above; the pointee is a live `Box<Rc<..>>` that the finalizer
    // frees only once the object is unreachable.
    Some(unsafe { (*raw).clone() })
}

/// Reads the list installed on a `ConnectionsList` object.
fn connections_list_of(object: v8::Local<v8::Object>) -> Option<SharedList> {
    shared_list_of(object)
}

fn install_connections_list<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(connections_list_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    set_method(
        scope,
        prototype,
        "all",
        v8::FunctionTemplate::builder(connections_all).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "idle",
        v8::FunctionTemplate::builder(connections_idle).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "active",
        v8::FunctionTemplate::builder(connections_active).build(scope),
    )?;
    set_method(
        scope,
        prototype,
        "expired",
        v8::FunctionTemplate::builder(connections_expired).build(scope),
    )?;

    let Some(class_name) = v8::String::new(scope, "ConnectionsList") else {
        return Err("cannot allocate the ConnectionsList class name".to_string());
    };
    template.set_class_name(class_name);

    let Some(function) = template.get_function(scope) else {
        return Err("cannot allocate the ConnectionsList constructor".to_string());
    };
    set(scope, target, "ConnectionsList", function.into())
}

fn connections_list_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
) {
    let raw: *mut Rc<RefCell<ConnectionsList>> =
        Box::into_raw(Box::new(Rc::new(RefCell::new(ConnectionsList::new()))));
    args.this().set_aligned_pointer_in_internal_field(
        CONNECTIONS_FIELD,
        raw.cast::<c_void>().cast_const(),
        0,
    );

    let address = raw as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        args.this(),
        Box::new(move || {
            let raw = address as *mut Rc<RefCell<ConnectionsList>>;
            // SAFETY: `connections_list_constructor` allocated this box and
            // nothing else frees it.
            drop(unsafe { Box::from_raw(raw) });
        }),
    );
    std::mem::forget(weak);
}

/// Turns a set of entries into the array of parser objects the C++ returns.
///
/// An entry whose parser object has been collected is skipped: Node's intrusive
/// list cannot hold a collected parser either, because `remove()` or the
/// destructor unlinks it first.
fn entries_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[Entry],
) -> v8::Local<'s, v8::Array> {
    let mut objects: Vec<v8::Local<'s, v8::Value>> = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry
            .borrow()
            .object
            .as_ref()
            .and_then(|object| object.to_local(scope));
        if let Some(object) = object {
            objects.push(object.into());
        }
    }
    v8::Array::new_with_elements(scope, &objects)
}

fn connections_all<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(list) = shared_list_of(args.this()) else {
        throw(scope, "ConnectionsList is not initialized");
        return;
    };
    let entries = list.borrow().all();
    rv.set(entries_array(scope, &entries).into());
}

fn connections_idle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(list) = shared_list_of(args.this()) else {
        throw(scope, "ConnectionsList is not initialized");
        return;
    };
    let entries = list.borrow().idle();
    rv.set(entries_array(scope, &entries).into());
}

fn connections_active<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(list) = shared_list_of(args.this()) else {
        throw(scope, "ConnectionsList is not initialized");
        return;
    };
    let entries = list.borrow().active();
    rv.set(entries_array(scope, &entries).into());
}

/// `expired(headersTimeout, requestTimeout)`.
///
/// Both arguments are milliseconds as `Uint32`s in Node (`args[0].As<Uint32>()`),
/// and the report also unlinks each parser from the active list.
fn connections_expired<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(list) = shared_list_of(args.this()) else {
        throw(scope, "ConnectionsList is not initialized");
        return;
    };
    let headers_timeout = args.get(0).uint32_value(scope).unwrap_or(0);
    let request_timeout = args.get(1).uint32_value(scope).unwrap_or(0);
    let entries = list.borrow_mut().expired(headers_timeout, request_timeout);
    rv.set(entries_array(scope, &entries).into());
}

impl EntryState {
    /// The entry for a parser object, which is also what the list stores.
    pub fn new(object: Option<v8::Weak<v8::Object>>) -> Self {
        Self {
            object,
            ..Self::default()
        }
    }
}
