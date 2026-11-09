//! Calling the JavaScript callbacks from inside an llhttp callback.
//!
//! # The scope problem
//!
//! `execute(buffer)` is a JavaScript call, so V8's isolate is entered and a
//! context is on the stack. llhttp then calls back into C, and from there into
//! JavaScript, which needs `Local` handles — and a `Local` can only be made in a
//! handle scope. The scope the caller of `execute` made is not reachable from
//! here: V8 never hands it to us.
//!
//! So every callback opens a *nested* handle scope from the isolate pointer this
//! parser kept. That is legal because the preconditions are exactly the ones a
//! callback runs under: the isolate is entered and a context is current. Node
//! does the equivalent from the other direction, opening an
//! `EscapableHandleScope` around the whole `llhttp_execute` call in
//! `Parser::Execute`.
//!
//! # Why the callbacks are read back off the object
//!
//! `lib/**` assigns them as ordinary properties, and `cleanParser` sets them to
//! `null` between messages, so they are read lazily and cached the way Node's
//! internal fields do. A non-function is skipped rather than reported, because
//! assigning `null` is how the JavaScript layer stops receiving a callback.
//!
//! # Arrays and buffers
//!
//! Headers go out as a flat `[name, value, name, value, ...]` array, which is
//! what `parserOnHeaders` spreads and `parserOnHeadersComplete` counts with
//! `.length`. Body goes out as a `Buffer`.

use std::os::raw::{c_char, c_int};

use rn_v8_sys::v8;

use crate::parser::Parser;

/// Which callback a [`Parser`] slot holds, in the order
/// `src/node_http_parser.cc` numbers them.
///
/// `kOnExecute` (5) and `kOnTimeout` (6) are deliberately absent: `lib/**` owns
/// both, and this crate neither stores nor calls them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    MessageBegin = 0,
    Headers = 1,
    HeadersComplete = 2,
    Body = 3,
    MessageComplete = 4,
}

impl Slot {
    pub fn index(self) -> usize {
        self as usize
    }

    /// The property `lib/**` assigns, i.e. the `kOn*` constant's numeric value.
    fn property(self) -> &'static str {
        match self {
            Self::MessageBegin => "0",
            Self::Headers => "1",
            Self::HeadersComplete => "2",
            Self::Body => "3",
            Self::MessageComplete => "4",
        }
    }
}

/// The nine arguments `kOnHeadersComplete` receives, in Node's order.
pub struct HeadersCompleteArgs<'a> {
    pub version_major: c_int,
    pub version_minor: c_int,
    /// `None` when `kOnHeaders` already delivered them.
    pub headers: Option<&'a [(Vec<u8>, Vec<u8>)]>,
    /// The numeric method, request parsers only.
    pub method: Option<c_int>,
    /// The URL, request parsers on the fast path only.
    pub url: Option<&'a [u8]>,
    /// The status code, response parsers only.
    pub status_code: Option<c_int>,
    /// The status message, response parsers only.
    pub status_message: Option<&'a [u8]>,
    pub upgrade: bool,
    pub keep_alive: bool,
}

/// Reads a NUL-terminated string the shim handed back.
///
/// # Safety
///
/// `pointer` must be NULL or a valid NUL-terminated string that outlives the
/// borrow.
pub unsafe fn c_str<'a>(pointer: *const c_char) -> Option<&'a str> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: delegated to the caller; every pointer here is a static string.
    unsafe { std::ffi::CStr::from_ptr(pointer) }.to_str().ok()
}

/// Opens a handle scope on `parser`'s isolate and runs `body` inside it.
///
/// Returns `None` when there is no isolate to open a scope on, which only
/// happens after teardown.
fn with_scope<R>(
    parser: &mut Parser,
    body: impl FnOnce(&mut Parser, &v8::PinScope<'_, '_>) -> R,
) -> Option<R> {
    // The wrapper is a `Copy` address, so a local holds it; the reference taken
    // from it lives exactly as long as this call, which is what makes it sound
    // to derive a `&mut Isolate` per callback rather than storing one.
    let mut isolate_ptr = parser.isolate_ptr();
    if isolate_ptr.is_null() || parser.context().is_none() {
        return None;
    }
    // SAFETY: the address came from a live scope in `Parser::create`, and every
    // caller runs while that isolate is entered — the precondition
    // `CallbackScope::new` documents. Reinterpreting the wrapper neither enters
    // the isolate nor takes ownership of it, so nothing is disposed on the way
    // out.
    let isolate = unsafe { v8::Isolate::ref_from_raw_isolate_ptr_mut(&mut isolate_ptr) };

    // `CallbackScope` is the type V8 provides for exactly this situation: code
    // called back from C while a JavaScript frame is still on the stack. It
    // opens a handle scope, and `ContextScope` then puts the parser's context on
    // the stack so the callbacks resolve their own globals.
    // SAFETY: as above; the isolate is entered and a context is on the stack.
    let callback_storage = unsafe { v8::CallbackScope::new(&mut *isolate) };
    let callback_storage = std::pin::pin!(callback_storage);
    let mut callback_scope = callback_storage.init();

    // SAFETY: the handle was created from a live scope of this isolate in
    // `Parser::create` and is rooted as a `Global`, so it is valid here.
    let context = v8::Local::new(&callback_scope, parser.context()?);
    let context_storage = std::pin::pin!(v8::ContextScope::new(&mut callback_scope, context));
    // `ContextScope` derefs to `PinScope<'_, '_>`, which is the shape every V8
    // helper below takes. The storage outlives the body, so the deref is valid
    // throughout.
    let scope: &v8::PinScope<'_, '_> = &context_storage;
    Some(body(parser, scope))
}

/// Reads the callback for `slot`, caching it the way Node's internal fields do.
fn callback<'s>(
    scope: &v8::PinScope<'s, '_>,
    parser: &mut Parser,
    slot: Slot,
) -> Option<v8::Local<'s, v8::Function>> {
    if let Some(cached) = parser.cached_callback(slot) {
        return Some(v8::Local::new(scope, cached));
    }
    let object = parser.object()?.to_local(scope)?;
    let key = v8::String::new(scope, slot.property())?;
    let value = object.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(value).ok()?;
    parser.cache_callback(slot, v8::Global::new(scope, function));
    Some(function)
}

/// The object to use as `this`.
fn receiver<'s>(
    scope: &v8::PinScope<'s, '_>,
    parser: &Parser,
) -> Option<v8::Local<'s, v8::Object>> {
    parser.object()?.to_local(scope)
}

/// Calls a zero-argument callback (`kOnMessageBegin`, `kOnMessageComplete`).
///
/// A missing callback is not an error: `lib/**` clears them between messages.
pub fn call_no_args(parser: &mut Parser, slot: Slot) {
    let outcome = with_scope(parser, |parser, scope| {
        let Some(callback) = callback(scope, parser, slot) else {
            return true;
        };
        let Some(receiver) = receiver(scope, parser) else {
            return true;
        };
        callback.call(scope, receiver.into(), &[]).is_some()
    });
    if outcome == Some(false) {
        parser.note_exception();
    }
}

/// Calls `kOnHeaders(headers, url)`.
///
/// Returns whether the call succeeded; on failure the exception is pending and
/// the caller stops.
pub fn call_headers(parser: &mut Parser, pairs: &[(Vec<u8>, Vec<u8>)], url: Option<&[u8]>) -> bool {
    let outcome = with_scope(parser, |parser, scope| {
        let Some(callback) = callback(scope, parser, Slot::Headers) else {
            return true;
        };
        let Some(receiver) = receiver(scope, parser) else {
            return true;
        };
        let Some(array) = headers_array(scope, pairs) else {
            return true;
        };
        // Node always passes a URL string here, empty when there is none.
        let url = url
            .and_then(|bytes| one_byte_string(scope, bytes))
            .unwrap_or_else(|| v8::String::empty(scope));
        let args = [array.into(), url.into()];
        callback.call(scope, receiver.into(), &args).is_some()
    });
    match outcome {
        // No callback installed, or no object: `lib/**` cleared it.
        None | Some(true) => true,
        Some(false) => {
            parser.note_exception();
            false
        }
    }
}

/// Calls `kOnBody(buffer)`. Returns whether the call succeeded.
pub fn call_body(parser: &mut Parser, bytes: &[u8]) -> bool {
    let outcome = with_scope(parser, |parser, scope| {
        let Some(callback) = callback(scope, parser, Slot::Body) else {
            return true;
        };
        let Some(receiver) = receiver(scope, parser) else {
            return true;
        };
        let Some(buffer) = buffer_from(scope, bytes) else {
            return true;
        };
        let args = [buffer];
        callback.call(scope, receiver.into(), &args).is_some()
    });
    match outcome {
        None | Some(true) => true,
        Some(false) => {
            parser.note_exception();
            false
        }
    }
}

/// What `kOnHeadersComplete` decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadersComplete {
    /// No function is installed: llhttp carries on with its default behaviour.
    /// `lib/**` sets the property to `null` between messages, so this is normal,
    /// not an error.
    NoCallback,
    /// The instruction llhttp should follow: 0 to continue, 1 for "no body", 2
    /// for "no body and stop at the upgrade boundary".
    Instruction(c_int),
    /// The callback threw, so the exception is pending and `execute` must return
    /// no value.
    Failed,
}

/// Calls `kOnHeadersComplete` and reports what it decided.
pub fn call_headers_complete(
    parser: &mut Parser,
    args: HeadersCompleteArgs<'_>,
) -> HeadersComplete {
    let outcome = with_scope(parser, |parser, scope| {
        let Some(callback) = callback(scope, parser, Slot::HeadersComplete) else {
            return HeadersComplete::NoCallback;
        };
        let Some(receiver) = receiver(scope, parser) else {
            return HeadersComplete::NoCallback;
        };

        let undefined: v8::Local<v8::Value> = v8::undefined(scope).into();
        let headers = match args.headers {
            Some(pairs) => headers_array(scope, pairs)
                .map(v8::Local::into)
                .unwrap_or(undefined),
            None => undefined,
        };
        let method = match args.method {
            Some(method) => v8::Integer::new_from_unsigned(scope, method as u32).into(),
            None => undefined,
        };
        let url = args
            .url
            .and_then(|bytes| one_byte_string(scope, bytes))
            .map(v8::Local::into)
            .unwrap_or(undefined);
        // A status code is a signed int in Node (`Integer::New`), and only a
        // response parser sets it.
        let status_code = match args.status_code {
            Some(code) => v8::Integer::new(scope, code).into(),
            None => undefined,
        };
        let status_message = args
            .status_message
            .and_then(|bytes| one_byte_string(scope, bytes))
            .map(v8::Local::into)
            .unwrap_or(undefined);

        // Order and arity are `parserOnHeadersComplete`'s signature:
        // (versionMajor, versionMinor, headers, method, url, statusCode,
        //  statusMessage, upgrade, shouldKeepAlive)
        let call_args = [
            v8::Integer::new(scope, args.version_major).into(),
            v8::Integer::new(scope, args.version_minor).into(),
            headers,
            method,
            url,
            status_code,
            status_message,
            v8::Boolean::new(scope, args.upgrade).into(),
            v8::Boolean::new(scope, args.keep_alive).into(),
        ];

        let Some(result) = callback.call(scope, receiver.into(), &call_args) else {
            return HeadersComplete::Failed;
        };
        // Node reads the result with `IntegerValue`, which maps `undefined` and
        // `null` to 0 and truncates a number; only an integer is a valid
        // instruction, and anything else stops the parse.
        match result.integer_value(scope) {
            Some(value) => match c_int::try_from(value) {
                Ok(instruction) => HeadersComplete::Instruction(instruction),
                Err(_) => HeadersComplete::Failed,
            },
            None => HeadersComplete::Failed,
        }
    });

    match outcome {
        Some(decision) => decision,
        // No isolate to call into, which only happens after teardown.
        None => HeadersComplete::NoCallback,
    }
}

/// Builds the flat `[name, value, ...]` array Node hands to JavaScript.
///
/// Copies, as `Buffer::Copy` does: the accumulator's bytes are cleared as soon
/// as the call returns, so a view over them would dangle.
fn headers_array<'s>(
    scope: &v8::PinScope<'s, '_>,
    pairs: &[(Vec<u8>, Vec<u8>)],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, (pairs.len() * 2) as i32);
    for (index, (name, value)) in pairs.iter().enumerate() {
        let name = one_byte_string(scope, name)?;
        let value = one_byte_string(scope, value)?;
        array.set_index(scope, (index * 2) as u32, name.into())?;
        array.set_index(scope, (index * 2 + 1) as u32, value.into())?;
    }
    Some(array)
}

/// A one-byte string, which is what Node builds for header bytes.
///
/// HTTP field names and values are byte sequences, so one-byte strings are both
/// the cheapest encoding and an exact round trip: `OneByteString` in Node does
/// the same, and decoding as UTF-8 first would corrupt anything outside ASCII.
fn one_byte_string<'s>(
    scope: &v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_one_byte(scope, bytes, v8::NewStringType::Normal)
}

/// A `Buffer` holding `bytes`, for callers outside this module.
pub fn buffer_from_public<'s>(
    scope: &v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    buffer_from(scope, bytes)
}

/// A `Buffer` holding `bytes`.
///
/// Node's `Buffer::Copy` allocates a `Uint8Array` and gives it Buffer's
/// prototype, which is what makes `Buffer.isBuffer` true and what
/// `parserOnBody`'s `stream.push(b)` requires. rustnode's `Buffer` *is* the
/// `Uint8Array` carrying that prototype, so the same two steps apply.
fn buffer_from<'s>(scope: &v8::PinScope<'s, '_>, bytes: &[u8]) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, array_buffer, 0, bytes.len())?;
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    Some(view.into())
}

/// The prototype `lib/buffer.js` installed on the global `Buffer`.
///
/// This crate does not depend on `rn-bind-buffer`: a binding reaching into
/// another binding's state would be a layering violation, and `setBufferPrototype`
/// keeps its copy in that crate's own thread-local. Reading `Buffer.prototype`
/// off the global reaches the same object, because `lib/buffer.js` both assigns
/// `Buffer.prototype` and hands it to the binding.
fn buffer_prototype<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}
