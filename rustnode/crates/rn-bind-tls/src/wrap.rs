//! The `tls_wrap` namespace: `wrap`, the `TLSWrap` class, and the two testing
//! hooks.
//!
//! `TLSWrap::Initialize` (`crypto_tls.cc:2363`) installs three namespace
//! functions, one constant, and a `TLSWrap` constructor carrying 33 prototype
//! methods plus `writeQueueSize` and the whole `StreamBase::AddMethods` surface.
//! `contracts/tls_wrap.json` records three members because that is all
//! `rn-compat` could observe without an OpenSSL-backed `SecureContext`; the
//! source is the spec and this module implements its list.
//!
//! # What increment 1 does and does not do
//!
//! This lands the namespace, the class, and [`wrap`] — a `TLSWrap` constructed
//! from a real `SecureContext`, holding a real `SSL` with real BIOs, with the
//! full prototype surface present and every method that needs the state machine
//! **throwing with the increment that will implement it named**. No handshake
//! runs yet: `start()` reports that it is not implemented rather than silently
//! doing nothing, because a silent no-op would turn "TLS does not work yet" into
//! "the handshake hangs", which is far harder to attribute.
//!
//! That is the acceptance the plan sets for this increment: `require('tls')`
//! loads, `tls.createSecureContext()` works, and `new tls.TLSSocket()` reaches a
//! legible failure rather than a missing-binding error.
//!
//! # R2, and why nothing here calls V8 while holding the state
//!
//! Every method below follows the same three steps: [`state::with_state`] to take
//! what it needs, end the borrow, then act. The prototype methods that have to
//! throw do their work inside the closure and return the message, which is why
//! they cannot accidentally hold a borrow across a `throw_exception`.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::ssl::{Kind, Ssl};
use crate::state::{self, WrapState};

/// Members this crate installs on the `tls_wrap` namespace.
///
/// The three functions and the constant are `Initialize`'s namespace members.
/// `TLSWrap` is the constructor. `HAVE_SSL_TRACE` is a number, and it is `0`
/// because the vendored OpenSSL is not built with `enable-ssl-trace`; the member
/// exists either way, because `lib/internal/tls/wrap.js` reads it to decide
/// whether to offer `enableTrace`.
pub const MEMBERS: &[&str] = &[
    "TLSWrap",
    "wrap",
    "injectOpenSSLErrorForTesting",
    "hasOpenSSLErrorForTesting",
    "HAVE_SSL_TRACE",
];

/// The prototype methods `Initialize` installs, in its order.
///
/// `crypto_tls.cc:2397-2460`. The list is here as data so a test can assert the
/// installed prototype matches it, rather than the two drifting apart when a
/// method is added to one and not the other.
///
/// `setMaxSendFragment` is unconditional here even though Node guards it on
/// `#ifdef SSL_set_max_send_fragment`: the guard is about the *header* exposing
/// the macro, and this crate calls `SSL_ctrl` with the same control directly, so
/// the feature is present on every build OpenSSL 3.6 supports.
pub const PROTO_METHODS: &[&str] = &[
    // The state-machine half, in `Initialize`'s order.
    "certCbDone",
    "clientHelloDone",
    "destroySSL",
    "enableCertCb",
    "enableALPNCb",
    "enableKeylogCallback",
    "enableSessionCallbacks",
    "enableTrace",
    "getServername",
    "loadSession",
    "newSessionDone",
    "receive",
    "renegotiate",
    "requestOCSP",
    "setALPNProtocols",
    "setKeyCert",
    "setOCSPResponse",
    "setServername",
    "setSession",
    "setVerifyMode",
    "start",
    "writesIssuedByPrevListenerDone",
    // The `SetProtoMethodNoSideEffect` group.
    "exportKeyingMaterial",
    "isSessionReused",
    "getALPNNegotiatedProtocol",
    "getCertificate",
    "getX509Certificate",
    "getCipher",
    "getEphemeralKeyInfo",
    "getFinished",
    "getPeerCertificate",
    "getPeerX509Certificate",
    "hasPeerCertificate",
    "getPeerFinished",
    "getProtocol",
    "getSession",
    "getSharedSigalgs",
    "getTLSTicket",
    "verifyError",
    // Guarded ones, present on this build.
    "setMaxSendFragment",
    "enablePskCallback",
    "setPskIdentityHint",
];

/// The `StreamBase::AddMethods` surface, which `TLSWrap` inherits.
///
/// Without these a `TLSSocket` cannot read or write at all: `lib/net.js` calls
/// `writeBuffer`/`shutdown`/`readStart` on `this._handle`, and
/// `lib/internal/stream_base_commons.js` reads `onread` and the byte counters.
/// They are installed here rather than inherited from a template because
/// rustnode has no shared `LibuvStreamWrap` base; `crate::stream` documents how
/// each one delegates to the wrapped stream.
pub const STREAM_METHODS: &[&str] = &[
    "readStart",
    "readStop",
    "shutdown",
    "useUserBuffer",
    "writev",
    "writeBuffer",
    "writeAsciiString",
    "writeUtf8String",
    "writeUcs2String",
    "writeLatin1String",
];

/// The `StreamBase` accessors, which `AddMethods` installs first.
pub const STREAM_ACCESSORS: &[&str] = &["fd", "_externalStream", "bytesRead", "bytesWritten"];

/// Installs the namespace object.
///
/// `install` rather than a `register*` helper: `tools/regen-bindings.sh` treats a
/// `register` *declaration* as the crate's discovery entry point, and this crate
/// provides a namespace through [`crate::register`] only.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _ctx: &mut rn_core::InstallCtx<'_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);

    let wrap_template = v8::FunctionTemplate::builder(wrap)
        .length(4)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let wrap_fn = wrap_template
        .get_function(scope)
        .ok_or("cannot allocate the wrap function")?;
    set(scope, object, "wrap", wrap_fn.into())?;

    let inject_template = v8::FunctionTemplate::builder(inject_error)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let inject = inject_template
        .get_function(scope)
        .ok_or("cannot allocate injectOpenSSLErrorForTesting")?;
    set(scope, object, "injectOpenSSLErrorForTesting", inject.into())?;

    let has_error_template = v8::FunctionTemplate::builder(has_error)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let has_error_fn = has_error_template
        .get_function(scope)
        .ok_or("cannot allocate hasOpenSSLErrorForTesting")?;
    set(
        scope,
        object,
        "hasOpenSSLErrorForTesting",
        has_error_fn.into(),
    )?;

    // `NODE_DEFINE_CONSTANT(target, HAVE_SSL_TRACE)`. `NODE_OPENSSL_HAS_SSL_TRACE`
    // is defined only for a build with `enable-ssl-trace`, which the vendored one
    // is not; `wrap.js` therefore never calls `enableTrace`.
    let have_trace = v8::Integer::new(scope, 0);
    set(scope, object, "HAVE_SSL_TRACE", have_trace.into())?;

    let constructor = constructor(scope)?;
    set(scope, object, "TLSWrap", constructor)?;

    // The constructor is also stashed so [`wrap`] can build an instance without a
    // second template — `env->tls_wrap_constructor_function()` in Node, which
    // `Wrap` uses for exactly that reason: two templates would make `instanceof`
    // disagree between a wrapped handle and a directly constructed one.
    store_constructor(scope, constructor)?;

    Ok(object)
}

thread_local! {
    /// `Environment::tls_wrap_constructor_function`.
    ///
    /// A `Global` because it has to survive between the namespace install and the
    /// first `tls_wrap.wrap()` call, which happens in a later task. Rooted for
    /// the process' life, which is what Node does with the same function.
    static CONSTRUCTOR: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
}

/// Records the constructor for [`wrap`] to instantiate.
fn store_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    constructor: v8::Local<v8::Value>,
) -> Result<(), String> {
    let function = v8::Local::<v8::Function>::try_from(constructor)
        .map_err(|_| "TLSWrap is not a function".to_string())?;
    let global = v8::Global::new(scope.as_ref(), function);
    CONSTRUCTOR.with(|slot| *slot.borrow_mut() = Some(global));
    Ok(())
}

/// The recorded constructor, materialised into `scope`.
fn constructor_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    CONSTRUCTOR.with(|slot| {
        let borrow = slot.borrow();
        let global = borrow.as_ref()?;
        Some(v8::Local::new(scope, global))
    })
}

/// `tls_wrap.wrap(handle, context, isServer, wrapHasActiveWriteFromPrevOwner)`.
///
/// `crypto_tls.cc:600`. The four arguments are `CHECK`ed for type there; here a
/// wrong one is a `TypeError`, for the reason `AGENTS.md` gives: a binding that
/// coerces hides the caller's bug.
///
/// # What it does
///
/// 1. resolves the `SSL_CTX` from the `SecureContext` object — never creating a
///    second context, which is the one-owner rule;
/// 2. creates the `SSL` with its BIO pair ([`Ssl::new`]), which is also where
///    `SSL_set_bio` transfers ownership (R1);
/// 3. builds a `TLSWrap` object from the recorded constructor;
/// 4. installs the state, roots the context, and pushes the stream listener.
///
/// Step 4 is where a real `TLSWrap` differs from a `JSStream`: the listener is
/// how the wrapped stream's reads reach this object. Increment 1 installs it, so
/// the plumbing exists and a later increment only has to fill in `on_stream_read`.
fn wrap(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if args.length() < 4 {
        throw_type_error(
            scope,
            "tls_wrap.wrap expects (handle, context, isServer, hasActiveWrite)",
        );
        return;
    }
    let handle = args.get(0);
    if !handle.is_object() {
        throw_type_error(scope, "handle must be a StreamBase object");
        return;
    }
    let context = args.get(1);
    if !context.is_object() {
        throw_type_error(scope, "context must be a SecureContext object");
        return;
    }
    // `CHECK(args[2]->IsBoolean())` — a non-boolean is a caller bug, not
    // something to coerce.
    let is_server = if args.get(2).is_true() {
        true
    } else if args.get(2).is_false() {
        false
    } else {
        throw_type_error(scope, "isServer must be a boolean");
        return;
    };

    let kind = if is_server {
        Kind::Server
    } else {
        Kind::Client
    };

    let handle_object = match v8::Local::<v8::Object>::try_from(handle) {
        Ok(object) => object,
        Err(_) => {
            throw_type_error(scope, "handle must be an object");
            return;
        }
    };
    let context_object = match v8::Local::<v8::Object>::try_from(context) {
        Ok(object) => object,
        Err(_) => {
            throw_type_error(scope, "context must be a SecureContext object");
            return;
        }
    };

    // The `SSL_CTX` comes from the `SecureContext` and is owned by it. A closed
    // context — `wrap.js:769` closes a single-use one while the wrapper is still
    // reachable — has none, which a real `node` reports as
    // `ERR_TLS_INVALID_CONTEXT`.
    let Some(ctx) = rn_bind_secure_context::ssl_ctx_of(context_object) else {
        throw_coded(
            scope,
            "context is not a SecureContext, or it has been closed",
            "ERR_TLS_INVALID_CONTEXT",
        );
        return;
    };

    // SAFETY: `ctx` is owned by the `SecureContext` object, which this function
    // roots in the new wrap's state before returning. `Ssl::new` takes its own
    // reference on the `SSL_CTX`, so the `SSL` does not depend on that root
    // staying alive — but the BIO callbacks installed in a later increment do
    // reach back through the wrap, so the root is what keeps the two lifetimes
    // agreeing.
    let ssl = match unsafe { Ssl::new(ctx, kind) } {
        Ok(ssl) => ssl,
        Err(error) => {
            throw_coded(
                scope,
                &format!("cannot create an SSL: {error}"),
                "ERR_CRYPTO_CUSTOM_ENGINE_NOT_SUPPORTED",
            );
            return;
        }
    };

    let Some(constructor) = constructor_function(scope) else {
        throw_error(scope, "the TLSWrap constructor was not installed");
        return;
    };
    let object = match constructor.new_instance(scope, &[]) {
        Some(object) => object,
        None => {
            // `new_instance` leaves an exception pending when it fails; reporting
            // a second one would replace the useful message.
            return;
        }
    };

    let Some(cell) = state::state_cell(object) else {
        throw_error(scope, "the TLSWrap instance has no state");
        return;
    };

    // SAFETY: `cell` was just created by the constructor for this object, and
    // this is its only borrow.
    let state_ref = unsafe { &*cell };
    let Ok(mut state) = state_ref.try_borrow_mut() else {
        throw_error(scope, "the TLSWrap state is already borrowed");
        return;
    };
    state.kind = kind;
    let ssl_ptr = ssl.as_ptr();
    state.ssl = Some(ssl);
    state.secure_context = Some(v8::Global::new(scope.as_ref(), context_object));
    state.object = Some(v8::Global::new(scope.as_ref(), object));
    // The wrap's own `StreamBase` delivers cleartext to `handle.onread`, which
    // `lib/net.js` assigns on *this* object rather than on the socket beneath it.
    state.reader.owner_object = Some(v8::Global::new(scope.as_ref(), object));
    state.flags.has_active_write_issued_by_prev_listener = args.get(3).is_true();
    // `InitSSL`'s callback installation, which needs the state address to exist
    // first. This is what makes `onhandshakestart`/`onhandshakedone` fire and
    // what sets `flags.established`.
    //
    // The mirrors the info callback reads. Registered before `install` so the
    // very first handshake message can notify JavaScript.
    let handles = crate::callback::register(cell, v8::Global::new(scope.as_ref(), object));
    state.callback = Some(handles);
    // SAFETY: `cell` is the state allocated for this object, and it outlives the
    // `SSL` because teardown frees the `SSL` from that same state.
    unsafe { crate::callback::install(ssl_ptr, cell) };
    drop(state);

    // The stream the listener attaches to, if the handle published one. A handle
    // with none is not a `StreamBase`, which `wrap.js` already checked with
    // `assert(handle.isStreamBase)`; reporting it here keeps the failure legible
    // for a caller that bypassed that check.
    // `stream_of` answers the `uv_stream_t` the handle published; the listener
    // layer needs the `StreamState` that owns it, which libuv carries in the
    // stream's `data` field.
    //
    // SAFETY: `handle_object` is a live local, `stream_of` only reads the symbol
    // property a stream binding attached, and a non-null stream it returns is
    // live until that binding's close callback runs.
    let underlying = unsafe {
        rn_uv::streams::stream_of(scope, handle_object)
            .and_then(|stream| rn_uv::handle::owner(stream))
    };
    let listener = match underlying {
        // SAFETY: `stream` is live (resolved from the handle's attached
        // pointer), and `cell` is the state this function just installed on
        // `object`, which outlives the listener because `destroySSL` removes it.
        Some(stream) => unsafe { crate::listener::attach(object, stream, cell) },
        None => None,
    };
    if listener.is_some() {
        let _ = state::with_state(object, |state| {
            state.underlying = underlying;
            state.listener = listener;
        });
    }

    rv.set(object.into());
}

/// `injectOpenSSLErrorForTesting()`.
///
/// `crypto_tls.cc`'s member of the same name pushes one synthetic error so a test
/// can prove the queue-reporting path runs without provoking a real failure.
fn inject_error(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    crate::error::inject();
}

/// `hasOpenSSLErrorForTesting()`.
///
/// `SetMethodNoSideEffect` in Node, and it genuinely has none: it peeks at the
/// queue rather than draining it, so a test can assert twice.
fn has_error(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Boolean::new(_scope, crate::error::has_error()).into());
}

/// Builds the `TLSWrap` constructor and its prototype.
fn constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(construct_tls_wrap).build(scope);
    let name = v8::String::new(scope, "TLSWrap").ok_or("cannot allocate the TLSWrap class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(state::INTERNAL_FIELD_COUNT);

    let prototype = template.prototype_template(scope);

    // `writeQueueSize`, an accessor with `ReadOnly | DontDelete`. Node installs it
    // before the prototype methods, which is why it comes first here.
    let queue_size = v8::FunctionTemplate::builder(crate::methods::get_write_queue_size)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set_accessor_property(
        key(scope, "writeQueueSize")?.into(),
        Some(queue_size),
        None,
        v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
    );

    // Each prototype method's implementation. The ones increment 1 does not
    // implement map to [`crate::methods::pending`], which throws the increment
    // that will land it — see this module's docs.
    for name in PROTO_METHODS {
        crate::methods::install_into(scope, &prototype, name)?;
    }

    // `StreamBase::AddMethods`. The four accessors come first, with the
    // `Signature` guard Node attaches; `READ_ONLY | DONT_DELETE | DONT_ENUM` is
    // the attribute set `AddMethods` uses.
    for name in STREAM_ACCESSORS {
        crate::stream::install_accessor(scope, &prototype, name)?;
    }

    for name in STREAM_METHODS {
        crate::stream::install_method(scope, &prototype, name)?;
    }
    // `t->PrototypeTemplate()->Set("isStreamBase", True(isolate))`, which
    // `wrap.js:831` asserts on.
    prototype.set(
        key(scope, "isStreamBase")?.into(),
        v8::Boolean::new(scope, true).into(),
    );

    // `onread`, the accessor `AddMethods` installs last. `lib/net.js` assigns it
    // (`Socket.prototype._handle.onread = onStreamRead`) and the read path calls
    // it, so it has to be a real property that round-trips.
    let onread_getter = v8::FunctionTemplate::builder(crate::stream::get_onread)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let onread_setter = v8::FunctionTemplate::builder(crate::stream::set_onread)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set_accessor_property(
        key(scope, "onread")?.into(),
        Some(onread_getter),
        Some(onread_setter),
        v8::PropertyAttribute::DONT_DELETE | v8::PropertyAttribute::DONT_ENUM,
    );

    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the TLSWrap constructor")?;
    function.set_name(name);
    Ok(function.into())
}

/// `new TLSWrap()`, which only [`wrap`] reaches.
///
/// Node's `TLSWrap` is built from a template that is never exposed as directly
/// constructible in practice: `wrapjs` always goes through `tls_wrap.wrap`, which
/// fills the state in immediately. A script *can* reach the constructor (it is on
/// the namespace), so the `new` check and the state allocation are both here; a
/// direct `new TLSWrap()` produces an object with empty state, and every method
/// on it reports that rather than crashing.
fn construct_tls_wrap<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "TLSWrap cannot be invoked without 'new'");
        return;
    }
    let object = args.this();
    let cell = Box::into_raw(Box::new(RefCell::new(WrapState::new(Kind::Client))));
    object.set_aligned_pointer_in_internal_field(
        state::STATE_FIELD,
        cell.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = cell as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this finalizer
            // runs exactly once. `WrapState`'s `Drop` runs here, which is what
            // frees the `SSL` on the finalizer path (R1).
            drop(unsafe { Box::from_raw(address as *mut RefCell<WrapState>) });
        }),
    );
    // The registration is kept alive by V8; dropping the handle would cancel it.
    std::mem::forget(weak);
    rv.set(object.into());
}

/// A `v8::String` for `name`, with the failure spelled out.
pub(crate) fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the {name} property name"))
}

/// Sets an own property on `object`.
fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let name_key = key(scope, name)?;
    object.set(scope, name_key.into(), value);
    Ok(())
}

/// Throws a `TypeError`.
pub(crate) fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws a plain `Error`.
pub(crate) fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws an `Error` carrying Node's `code` property.
///
/// `lib/**` dispatches on `err.code` throughout (`ERR_TLS_INVALID_CONTEXT`,
/// `ERR_SSL_*`), so a thrown error without one takes the wrong branch in a
/// caller rather than failing legibly.
pub(crate) fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let error = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(error) {
        if let Ok(code_text) = key(scope, "code") {
            if let Some(code_value) = v8::String::new(scope, code) {
                let _ = object.set(scope, code_text.into(), code_value.into());
            }
        }
    }
    scope.throw_exception(error);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The member list is the contract's, plus the constant and the two testing
    /// hooks the contract cannot see. `tests/prototype.rs` checks the installed
    /// prototype against `PROTO_METHODS`; this checks the lists themselves.
    #[test]
    fn the_member_list_covers_the_namespace() {
        assert_eq!(
            MEMBERS,
            &[
                "TLSWrap",
                "wrap",
                "injectOpenSSLErrorForTesting",
                "hasOpenSSLErrorForTesting",
                "HAVE_SSL_TRACE",
            ]
        );
    }

    /// Every contract member is installed, and the contract's three are a subset.
    ///
    /// The contract records three members because `rn-compat` cannot observe the
    /// rest without a working `SecureContext`; this asserts the direction that
    /// matters — nothing the contract names is missing — rather than the equality
    /// a complete contract would justify.
    #[test]
    fn every_contract_member_is_installed() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/tls_wrap.json"))
                .expect("the tls_wrap contract parses");
        let recorded = contract["members"]
            .as_object()
            .expect("the contract has a members object");
        for member in recorded.keys() {
            assert!(
                MEMBERS.contains(&member.as_str()),
                "{member} is in the contract but not installed"
            );
        }
    }

    /// `Initialize`'s prototype list is 42 entries: 39 unguarded plus the three
    /// guarded ones this build also has.
    ///
    /// The count is pinned because the plan's correction was that the contract's
    /// 3 is a floor and the source's list is the spec; a silent drop of one is
    /// what this catches.
    #[test]
    fn the_prototype_list_is_complete() {
        assert_eq!(PROTO_METHODS.len(), 42);
        let mut sorted = PROTO_METHODS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), before, "a prototype method is listed twice");
    }

    /// The `StreamBase` surface is ten methods and four accessors, which is what
    /// `AddMethods` installs.
    #[test]
    fn the_stream_surface_is_installed() {
        assert_eq!(STREAM_METHODS.len(), 10);
        assert_eq!(STREAM_ACCESSORS.len(), 4);
        assert!(STREAM_METHODS.contains(&"writeBuffer"));
        assert!(STREAM_ACCESSORS.contains(&"bytesRead"));
    }
}
