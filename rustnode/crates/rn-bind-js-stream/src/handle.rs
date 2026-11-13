//! The `JSStream` constructor and its prototype.
//!
//! `src/js_stream.cc`'s `Initialize` builds one `FunctionTemplate`:
//!
//! ```c
//! Local<FunctionTemplate> t = NewFunctionTemplate(isolate, New);
//! t->InstanceTemplate()->SetInternalFieldCount(JSStream::kInternalFieldCount);
//! t->Inherit(AsyncWrap::GetConstructorTemplate(env));
//! SetProtoMethod(isolate, t, "finishWrite", Finish<WriteWrap>);
//! SetProtoMethod(isolate, t, "finishShutdown", Finish<ShutdownWrap>);
//! SetProtoMethod(isolate, t, "readBuffer", ReadBuffer);
//! SetProtoMethod(isolate, t, "emitEOF", EmitEOF);
//! StreamBase::AddMethods(env, t);
//! ```
//!
//! and the resulting prototype order is observable, so the methods are installed
//! in that order: the four `JSStream` ones, then the `AddMethods` accessors and
//! methods, then `isStreamBase`.
//!
//! # The state behind the object
//!
//! Node's `JSStream` is an `AsyncWrap` plus a `StreamBase`, so it has an async id
//! and no libuv handle. What the JavaScript side actually needs is the byte
//! counters and a place for the request objects in flight; the counters are
//! `bytesRead`/`bytesWritten`, and `lib/internal/js_stream_socket.js` keeps the
//! requests itself (`kCurrentWriteRequest` and friends). So the slot holds the
//! counters, the rooted object, and a flag for whether a read is in progress.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::ptr;

use rn_v8_sys::v8;

use rn_uv::handle::StreamState;

use crate::methods;

/// Internal field holding the `*mut StreamSlot`.
pub(crate) const SLOT_FIELD: i32 = 0;

/// The state one `JSStream` object owns.
///
/// `Cell` rather than `&mut` because the accessors take `&self`: a getter has to
/// read a counter from a borrowed slot, and several `StreamBase` methods update
/// one without needing to own the whole slot.
pub struct StreamSlot {
    /// The `StreamResource` half: the byte counters and the listener chain.
    ///
    /// Node's `JSStream` is an `AsyncWrap + StreamBase`, so it is a
    /// `StreamResource` with no libuv handle — and its `stream` field is null
    /// because there is nothing underneath it. That is exactly the shape
    /// [`rn_uv::listener`] supports, and it is why `readBuffer` can go through
    /// `EmitRead` rather than calling `onread` itself: a listener pushed onto a
    /// `JSStream` sees the bytes, as `js_stream.cc:176-197` does.
    ///
    /// `UnsafeCell` is not needed and `Option` is not used: the state is
    /// constructed once with the slot and dropped with it, and every method that
    /// touches it takes `&mut` from [`with_state`], which is scoped to one
    /// callback — the same borrow discipline [`rn_uv::listener::emit_read`]
    /// requires.
    pub state: RefCell<StreamState>,

    /// Whether `readStart` has been called and `readStop` has not, which is
    /// `StreamBase`'s `reading_` notion and what `readStart` twice must not
    /// double-count.
    pub reading: Cell<bool>,
    /// `onread`, which `StreamBase::AddMethods` stores in an internal field.
    ///
    /// `lib/internal/js_stream_socket.js` never assigns it; `lib/net.js` does,
    /// through `Socket.prototype._handle.onread = onStreamRead`, and that is what
    /// `readBuffer` and `emitEOF` reach through the default listener. A
    /// `RefCell` because the accessor pair replaces it while a read is being
    /// delivered.
    pub onread: RefCell<Option<v8::Global<v8::Function>>>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    pub weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

impl StreamSlot {
    /// A slot for a fresh `JSStream`.
    pub fn new() -> Self {
        let mut state = StreamState::new(ptr::null_mut());
        // `StreamBase`'s constructor pushes `default_listener_`; here absence is
        // the default, so the owner object is what `deliver_read` reaches. It is
        // installed by `new` below once the object exists.
        state.owner_object = None;
        Self {
            state: RefCell::new(state),
            reading: Cell::new(false),
            onread: RefCell::new(None),
            weak: RefCell::new(None),
        }
    }

    /// `StreamBase::bytesRead`.
    pub fn bytes_read(&self) -> u64 {
        self.state.borrow().bytes_read
    }

    /// `StreamBase::bytesWritten`.
    pub fn bytes_written(&self) -> u64 {
        self.state.borrow().bytes_written
    }
}

impl Default for StreamSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs `body` with the slot behind a `JSStream` object.
pub(crate) fn with_slot<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&StreamSlot) -> R,
) -> Option<R> {
    // SAFETY: the field only ever holds a pointer installed by `new`, and the
    // object is a live local so its finalizer has not run.
    let address = unsafe { object.get_aligned_pointer_from_internal_field(SLOT_FIELD, 0) } as usize;
    if address == 0 {
        return None;
    }
    // SAFETY: as above — the address is the live slot this object owns.
    Some(body(unsafe { &*(address as *const StreamSlot) }))
}

/// Runs `body` with a scoped `&mut StreamState` for the slot's stream.
///
/// This is the same shape [`rn_uv::listener::emit_read`] documents: the borrow
/// ends before the callback, so a listener that re-enters — removing itself,
/// writing, or reading a counter — cannot alias it.
pub(crate) fn with_state<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut StreamState) -> R,
) -> Option<R> {
    with_slot(object, |slot| body(&mut slot.state.borrow_mut()))
}

/// The listener chain for a `JSStream`, as the address the listener layer takes.
///
/// Returns `None` for a receiver that is not a `JSStream`.
///
/// The state is a `RefCell` because the accessors take `&self`, but the listener
/// layer takes a raw pointer precisely so no borrow is held across a callback —
/// see [`rn_uv::listener`]. `RefCell::as_ptr` gives that address without creating
/// a reference, which is why it is used here rather than `borrow_mut`.
pub(crate) fn state_pointer(object: v8::Local<v8::Object>) -> Option<*mut StreamState> {
    // SAFETY: the field only ever holds a pointer installed by `new`, and the
    // object is a live local.
    let address = unsafe { object.get_aligned_pointer_from_internal_field(SLOT_FIELD, 0) } as usize;
    if address == 0 {
        return None;
    }
    // SAFETY: as above — the slot is live for as long as the object is, which is
    // at least as long as the callback using this pointer.
    let slot = unsafe { &*(address as *const StreamSlot) };
    Some(slot.state.as_ptr())
}

/// Builds the `JSStream` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `JSStream.length` is 0: `NewFunctionTemplate`'s default.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name =
        v8::String::new(scope, "JSStream").ok_or("cannot allocate the JSStream class name")?;
    template.set_class_name(name);

    // `JSStream::kInternalFieldCount` is the larger of `AsyncWrap`'s and
    // `StreamBase`'s, which is 3 in Node. One field is enough here: the async id
    // and the stream pointer are the slot's own business, and
    // `lib/internal/js_stream_socket.js` reads neither.
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);

    // The four methods `JSStream::Initialize` installs, in its order.
    macro_rules! install_method {
        ($($method_name:literal => $method:expr => $length:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .length($length)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                prototype.set(crate::key(scope, $method_name)?.into(), method_template.into());
            )*
        };
    }
    install_method! {
        "finishWrite" => methods::finish_write => 2,
        "finishShutdown" => methods::finish_shutdown => 2,
        "readBuffer" => methods::read_buffer => 1,
        "emitEOF" => methods::emit_eof => 0,
    }

    // `StreamBase::AddMethods`, in its order. `AddMethod` installs the four
    // accessors first with `Signature::New(isolate, t)`, which is why they come
    // before the methods here too.
    for (name, getter) in [
        ("fd", methods::get_fd as Accessor),
        ("_externalStream", methods::get_external),
        ("bytesRead", methods::get_bytes_read),
        ("bytesWritten", methods::get_bytes_written),
    ] {
        let _ = getter;
        let template = match name {
            "fd" => v8::FunctionTemplate::builder(methods::get_fd),
            "_externalStream" => v8::FunctionTemplate::builder(methods::get_external),
            "bytesRead" => v8::FunctionTemplate::builder(methods::get_bytes_read),
            _ => v8::FunctionTemplate::builder(methods::get_bytes_written),
        };
        let template = template
            .length(0)
            .constructor_behavior(v8::ConstructorBehavior::Throw)
            .build(scope);
        prototype.set_accessor_property(
            crate::key(scope, name)?.into(),
            Some(template),
            None,
            v8::PropertyAttribute::DONT_DELETE,
        );
    }

    install_method! {
        "readStart" => methods::read_start => 0,
        "readStop" => methods::read_stop => 0,
        "shutdown" => methods::shutdown => 1,
        "useUserBuffer" => methods::use_user_buffer => 1,
        "writev" => methods::writev => 3,
        "writeBuffer" => methods::write_buffer => 2,
        "writeAsciiString" => methods::write_ascii => 2,
        "writeUtf8String" => methods::write_utf8 => 2,
        "writeUcs2String" => methods::write_ucs2 => 2,
        "writeLatin1String" => methods::write_latin1 => 2,
    }

    // `t->PrototypeTemplate()->Set("isStreamBase", True(isolate))`.
    let is_stream_base = v8::Boolean::new(scope, true);
    prototype.set(
        crate::key(scope, "isStreamBase")?.into(),
        is_stream_base.into(),
    );

    // `AddAccessor(..., BaseObject::InternalFieldGet<kOnReadFunctionField>, ...)`.
    // Node stores `onread` in an internal field, so a value assigned from
    // JavaScript is readable by native code that has no property lookup handy.
    // The observable contract is only that assigning and reading agree, which a
    // plain property keeps.
    let onread = v8::FunctionTemplate::builder(methods::get_onread)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let onread_setter = v8::FunctionTemplate::builder(methods::set_onread)
        .length(1)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    prototype.set_accessor_property(
        crate::key(scope, "onread")?.into(),
        Some(onread),
        Some(onread_setter),
        v8::PropertyAttribute::DONT_DELETE,
    );

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the JSStream constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// The accessors and the methods use these two shapes.
type Accessor =
    fn(&mut v8::PinScope<'_, '_>, v8::FunctionCallbackArguments<'_>, v8::ReturnValue<'_>);

/// `new JSStream()`.
///
/// `src/js_stream.cc`'s `New` is `CHECK(args.IsConstructCall())` and then
/// constructs. A script can never reach this constructor — it is not on any
/// global — so the check is about the shape of the API rather than a user error,
/// and a `TypeError` is what a `CHECK` amounts to without the abort.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "JSStream cannot be invoked without 'new'");
        return;
    }
    let object = args.this();
    let slot = Box::into_raw(Box::new(StreamSlot::new()));
    object.set_aligned_pointer_in_internal_field(SLOT_FIELD, slot.cast::<c_void>(), 0);

    // The default listener reaches JavaScript through `owner_object`, so the
    // object a `JSStream` delivers to is its own wrapper — Node's
    // `StreamBase::GetObject()`.
    // SAFETY: `slot` was just created and is not aliased yet.
    unsafe {
        (*slot).state.borrow_mut().owner_object = Some(v8::Global::new(scope.as_ref(), object))
    };

    // `StreamBase::FromObject` is how anything that consumes a stream finds its
    // state, and `rn_uv::streams::attach_state` is the cross-crate spelling of it.
    // Every other stream binding publishes a `uv_stream_t`, but a `JSStream` has
    // none — its `StreamState::stream` is null — so it publishes the *state*
    // instead. Without this, `Http2Session.consume` could not find the stream
    // behind one and `http2.connect` over a `Duplex` threw "requires a stream
    // handle", which is the largest single `Uncaught` signature in the
    // measurement.
    // SAFETY: `slot` is live, and the stream it names is the slot's own
    // `StreamState`, which outlives the object through the finalizer above.
    unsafe {
        rn_uv::streams::attach_state(scope, object, (*slot).state.as_ptr());
    }

    let address = slot as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this
            // finalizer runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut StreamSlot) });
        }),
    );
    // SAFETY: `slot` is live and this is its only borrow.
    *unsafe { &(*slot).weak }.borrow_mut() = Some(weak);
    rv.set(object.into());
}

/// Throws a `TypeError`, which is what a failed `CHECK` amounts to here.
pub(crate) fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}
