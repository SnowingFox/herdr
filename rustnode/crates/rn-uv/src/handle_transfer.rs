//! Passing a libuv handle over an IPC pipe: `uv_write2` and the receiving half.
//!
//! Node's `child.send(message, handle)` and `cluster`'s internal
//! `{ act: 'newconn' }` both put a *descriptor* on the IPC channel. The channel is
//! a `uv_pipe_t` created with `ipc = 1`, and every write on it goes through
//! `StreamBase::Write` with a non-null `send_handle`, which
//! `LibuvStreamWrap::DoWrite` dispatches as `uv_write2` (`src/stream_wrap.cc`):
//!
//! ```c
//! return w->Dispatch(uv_write2, stream(), bufs, count, send_handle, AfterUvWrite);
//! ```
//!
//! On the far side the descriptor arrives attached to the next read, and
//! `LibuvStreamWrap::OnUvRead` turns it into a JavaScript object before it hands
//! the bytes to `handle.onread`:
//!
//! ```c
//! if (is_named_pipe_ipc() &&
//!     uv_pipe_pending_count(reinterpret_cast<uv_pipe_t*>(stream())) > 0) {
//!   type = uv_pipe_pending_type(reinterpret_cast<uv_pipe_t*>(stream()));
//! }
//! ...
//! if (type == UV_TCP) pending_obj = AcceptHandle<TCPWrap>(env(), this);
//! else if (type == UV_NAMED_PIPE) pending_obj = AcceptHandle<PipeWrap>(env(), this);
//! else if (type == UV_UDP) pending_obj = AcceptHandle<UDPWrap>(env(), this);
//! ...
//! object()->Set(env()->context(), env()->pending_handle_string(), local_pending_obj);
//! ```
//!
//! `lib/internal/child_process.js` then reads `channel.pendingHandle` off the same
//! object it read the bytes from.
//!
//! # Why this is a registration slot rather than a generic implementation
//!
//! `uv_accept` needs a *destination* handle of the same type as the pending one,
//! and the destination is a `TCP`, `Pipe` or `UDP` object — each owned by its own
//! binding crate, and each reachable from JavaScript only through that binding's
//! constructor. `rn-uv` cannot depend on those crates without inverting the
//! dependency direction (they depend on it), so the bindings register how to make
//! one and how to give one back for sending, and this module owns only the parts
//! they share: the `uv_write2` dispatch and the pending-handle bookkeeping.
//!
//! That mirrors Node, where the same split exists for the same reason:
//! `stream_wrap.cc` owns `OnUvRead`'s shape and `tcp_wrap.cc` owns
//! `TCPWrap::Instantiate`.
//!
//! # The two halves, and which one was missing
//!
//! Both were absent before this module: `rn-bind-pipe-wrap`'s `writeBuffer` read
//! only `(req, buffer)` and dropped the handle argument, `uv_write` was called
//! unconditionally, and no binding published `pendingHandle`. A process could
//! therefore send a message *about* a handle and never the handle itself, which
//! is what made every `cluster` server test hang: the primary `uv_accept`ed the
//! connection, tried to transfer it, and the transfer silently became a plain
//! message, leaving the accepted `uv_tcp_t` referenced on the primary's loop
//! forever with nothing that would ever close it.
//!
//! # Why a resolver is keyed on the object's own class
//!
//! Every handle binding stores its native pointer in internal field 0, so a
//! resolver that merely reads that field cannot tell a `TCP` from a `Pipe` — it
//! would cast one binding's allocation to the other's type and hand
//! `uv_write2` a garbage descriptor. Node has the same problem and answers it with
//! `WrapType::Instantiate`'s `instanceof` check (`handleConversion[type].send`),
//! so each registration carries the constructor it belongs to and
//! [`resolve`] asks `[[HasInstance]]` before touching a field.

use std::cell::RefCell;
use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

/// A handle that can be sent over an IPC pipe.
///
/// Implemented by the binding crates for the object they wrap. The two methods
/// are `HandleWrap::GetHandle` and `HandleWrap::IsAlive`, which is all
/// `StreamBase::WriteBuffer` reads off the argument it is given.
pub trait Transferable {
    /// The `uv_handle_t` to hand to `uv_write2`.
    fn transfer_handle(&self) -> *mut uv::uv_handle_t;
    /// Whether the handle is still usable, i.e. not closing or closed.
    fn transfer_is_alive(&self) -> bool;
}

/// Reads a binding's handle out of an object it has already accepted as its own.
///
/// Called only after the registration's constructor has matched, so the internal
/// field is known to hold this binding's type.
pub type HandleLookup = for<'s> fn(
    &mut v8::PinScope<'s, '_>,
    v8::Local<'s, v8::Object>,
) -> Option<Box<dyn Transferable>>;

/// One binding's answer to "is this value mine, and if so what handle is it".
struct ResolverRegistration {
    /// The constructor whose instances this binding wraps.
    constructor: v8::Global<v8::Function>,
    lookup: HandleLookup,
}

/// Creates the JavaScript object for a descriptor that arrived on an IPC pipe.
///
/// This is `AcceptHandle<T>` (`src/stream_wrap.cc:254`): make an empty handle of
/// the same kind, `uv_accept` the parent's pending descriptor into it, and wrap it
/// in a freshly constructed JavaScript object. The object is returned rather than
/// assigned here because `pendingHandle` belongs on the *reading* pipe's object,
/// which this function does not have.
pub type AcceptHandler = for<'s> unsafe fn(
    scope: &mut v8::PinScope<'s, '_>,
    parent: *mut uv::uv_stream_t,
    kind: uv::uv_handle_type,
) -> Option<v8::Local<'s, v8::Object>>;

thread_local! {
    /// The bindings' handle resolvers, in registration order.
    static RESOLVERS: RefCell<Vec<ResolverRegistration>> = const { RefCell::new(Vec::new()) };
    /// The bindings' accept handlers, keyed by the libuv handle type they build.
    ///
    /// Keyed rather than ordered because `OnUvRead` asks for exactly one type and
    /// a wrong-but-present handler would `uv_accept` into a mismatched handle,
    /// which libuv rejects with `EINVAL` after the descriptor on the parent is
    /// already pending — an error the receiver could not recover from.
    static ACCEPTORS: RefCell<Vec<(uv::uv_handle_type, AcceptHandler)>> =
        const { RefCell::new(Vec::new()) };
    /// The address of every IPC pipe the bindings created.
    ///
    /// Addresses rather than pointers so the set stays comparable and cannot be
    /// dereferenced by mistake. An address may be reused after the pipe is freed,
    /// which is why [`forget_ipc_pipe`] has to be called from the close path.
    static IPC_PIPES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Registers a binding's constructor and how to read a handle out of its
/// instances.
///
/// Called from each binding's `install`, so a build that omits a binding simply
/// cannot send that kind of handle — which is the same failure Node has for an
/// object that is not a `HandleWrap`.
pub fn register_resolver(
    scope: &mut v8::PinScope<'_, '_>,
    constructor: v8::Local<v8::Function>,
    lookup: HandleLookup,
) {
    let constructor = v8::Global::new(scope.as_ref(), constructor);
    RESOLVERS.with(|slot| {
        let mut slot = slot.borrow_mut();
        // A realm may install a namespace more than once; keeping one entry per
        // lookup stops the list growing and changing which one answers.
        push_unique(
            &mut slot,
            // `fn_addr_eq`, not `==`: a `fn` pointer's address is not guaranteed
            // unique or stable across codegen units, so a plain comparison is
            // allowed to be wrong in both directions.
            |existing: &ResolverRegistration| std::ptr::fn_addr_eq(existing.lookup, lookup),
            ResolverRegistration {
                constructor,
                lookup,
            },
        );
    });
}

/// Adds a lookup to a list unless one is already there.
///
/// Split out from [`register_resolver`] so the idempotence rule is testable
/// without an isolate to build a constructor in.
fn push_unique<T>(entries: &mut Vec<T>, duplicate: impl Fn(&T) -> bool, entry: T) {
    if entries.iter().any(duplicate) {
        return;
    }
    entries.push(entry);
}

/// Registers a binding's way of building the object for a received descriptor.
pub fn register_acceptor(kind: uv::uv_handle_type, acceptor: AcceptHandler) {
    ACCEPTORS.with(|slot| {
        let mut slot = slot.borrow_mut();
        if !slot.iter().any(|(existing, _)| *existing == kind) {
            slot.push((kind, acceptor));
        }
    });
}

/// Resolves `value` to a handle one of the bindings own.
///
/// Returns `None` when no installed binding claims the value, which
/// `StreamBase::WriteBuffer` reports as `UV_EINVAL` through
/// `ASSIGN_OR_RETURN_UNWRAP`.
pub fn resolve<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<Box<dyn Transferable>> {
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return None;
    };
    // The constructors are cloned out before the loop because `instance_of` can
    // run JavaScript (`Symbol.hasInstance`), which must not happen while the
    // registration list is borrowed.
    let candidates: Vec<(v8::Global<v8::Function>, HandleLookup)> = RESOLVERS.with(|slot| {
        slot.borrow()
            .iter()
            .map(|registration| (registration.constructor.clone(), registration.lookup))
            .collect()
    });
    for (constructor, lookup) in candidates {
        let constructor: v8::Local<v8::Function> = v8::Local::new(scope, &constructor);
        // A `Function` is always an `Object`, so this cannot fail; the cast
        // exists only because `instance_of` takes the constructor as one.
        let constructor = v8::Local::<v8::Object>::from(constructor);
        // `[[HasInstance]]` is what `instanceof` runs; a throw here is a pending
        // exception, and this is not the place to report it.
        match object.instance_of(scope, constructor) {
            Some(true) => return lookup(scope, object),
            Some(false) => continue,
            None => return None,
        }
    }
    None
}

/// Builds the object for a received descriptor of `kind`.
fn acceptor(kind: uv::uv_handle_type) -> Option<AcceptHandler> {
    ACCEPTORS.with(|slot| {
        slot.borrow()
            .iter()
            .find(|(existing, _)| *existing == kind)
            .map(|(_, acceptor)| *acceptor)
    })
}

/// Whether `stream` is an IPC pipe, i.e. one that can carry descriptors.
///
/// `StreamBase::WriteBuffer` gates the whole send path on `IsIPCPipe()`, and
/// `LibuvStreamWrap::OnUvRead` gates the receive path on `is_named_pipe_ipc()`.
/// Both are the `ipc` bit passed to `uv_pipe_init`, which libuv does not expose a
/// getter for, so the binding that created the pipe records it in
/// [`set_ipc_pipe`] and this answers from that set.
pub fn is_ipc_pipe(handle: *mut uv::uv_handle_t) -> bool {
    if handle.is_null() {
        return false;
    }
    IPC_PIPES.with(|slot| slot.borrow().contains(&(handle as usize)))
}

/// Records that `handle` is an IPC pipe.
pub fn set_ipc_pipe(handle: *mut uv::uv_handle_t) {
    IPC_PIPES.with(|slot| {
        let mut slot = slot.borrow_mut();
        let address = handle as usize;
        if !slot.contains(&address) {
            slot.push(address);
        }
    });
}

/// Forgets an IPC pipe, once it is closed.
pub fn forget_ipc_pipe(handle: *mut uv::uv_handle_t) {
    IPC_PIPES.with(|slot| slot.borrow_mut().retain(|&a| a != handle as usize));
}

/// A handle to send along with a write, resolved from the `writeBuffer` argument.
pub struct SendHandle {
    /// The descriptor `uv_write2` transfers.
    pub handle: *mut uv::uv_handle_t,
    /// The JavaScript object, rooted so it outlives the completion.
    ///
    /// `StreamBase::WriteBuffer` does the same thing with `req_wrap_obj->Set(...,
    /// env->handle_string(), send_handle_obj)`: without a strong reference the
    /// sender's wrapper may be collected while the descriptor is in flight, and
    /// the finalizer would `uv_close` a handle libuv is still transferring.
    pub object: v8::Global<v8::Object>,
}

impl SendHandle {
    /// Resolves `value` as a handle to send.
    ///
    /// Returns `None` when the value is not one of the installed bindings' handles,
    /// which the caller reports as `UV_EINVAL` — the code
    /// `ASSIGN_OR_RETURN_UNWRAP` uses.
    pub fn from_value<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        value: v8::Local<'s, v8::Value>,
    ) -> Option<Self> {
        let handle = resolve(scope, value)?;
        if !handle.transfer_is_alive() {
            return None;
        }
        let object = v8::Local::<v8::Object>::try_from(value).ok()?;
        Some(Self {
            handle: handle.transfer_handle(),
            object: v8::Global::new(scope.as_ref(), object),
        })
    }
}

/// The pending descriptor on an IPC pipe, if there is one.
///
/// This is the pair of calls at the top of `LibuvStreamWrap::OnUvRead`. It returns
/// `UV_UNKNOWN_HANDLE` when nothing is pending, which is the value Node's `type`
/// starts at and compares against.
///
/// # Safety
///
/// `stream` must be a live `uv_pipe_t`. Reading the pending count on a stream that
/// is not a pipe is undefined, so callers check [`is_ipc_pipe`] first.
pub unsafe fn pending_type(stream: *mut uv::uv_stream_t) -> uv::uv_handle_type {
    if stream.is_null() {
        return uv::uv_handle_type_UV_UNKNOWN_HANDLE;
    }
    let pipe = stream.cast::<uv::uv_pipe_t>();
    // SAFETY: the caller guarantees `stream` is a live pipe.
    let count = unsafe { uv::uv_pipe_pending_count(pipe) };
    if count <= 0 {
        return uv::uv_handle_type_UV_UNKNOWN_HANDLE;
    }
    // SAFETY: as above, and `count > 0` means libuv has a type to report.
    unsafe { uv::uv_pipe_pending_type(pipe) }
}

/// Accepts the descriptor pending on `parent` into a new JavaScript object.
///
/// This is `AcceptHandle<T>` (`src/stream_wrap.cc:254`), which is the whole
/// receive path: make the handle, `uv_accept` the descriptor into it, wrap it.
///
/// Returns `None` when no binding can build `kind` — a build without that binding
/// — or when `uv_accept` fails. Node `ABORT()`s on a failed accept because the
/// alternative is a descriptor nothing owns; the caller here closes the orphan,
/// which is the same outcome without taking the process down.
///
/// # Safety
///
/// `parent` must be a live IPC pipe with a descriptor pending on it.
pub unsafe fn accept<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    parent: *mut uv::uv_stream_t,
    kind: uv::uv_handle_type,
) -> Option<v8::Local<'s, v8::Object>> {
    let build = acceptor(kind)?;
    // SAFETY: the caller guarantees `parent` is a live IPC pipe with a descriptor
    // pending on it, which is this function's whole contract.
    unsafe { build(scope, parent, kind) }
}

/// Closes a handle nothing adopted, so its descriptor cannot leak.
///
/// # Safety
///
/// `handle` must be a live handle this thread owns and that nothing else holds.
pub unsafe fn close_orphan(handle: *mut uv::uv_handle_t) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller guarantees the handle is live and unowned. No close
    // callback is installed because nothing needs to observe the completion.
    unsafe { uv::uv_close(handle, None) };
}

/// A `uv_handle_t*` from a `*mut c_void`, for a binding's trait implementation.
///
/// Kept here so a binding implementing [`Transferable`] does not have to import
/// `libuv-sys2` just to cast.
pub fn handle_from_ptr(pointer: *mut c_void) -> *mut uv::uv_handle_t {
    pointer.cast()
}

/// The descriptor behind a live handle, `uv_fileno`.
///
/// Node's `TCPWrap::TransferForMessaging` asks for this before it duplicates the
/// socket. `None` means libuv has no descriptor to report, which is the ordinary
/// answer for a handle that has not been opened yet.
pub fn fileno(handle: *mut uv::uv_handle_t) -> Option<uv::uv_os_fd_t> {
    if handle.is_null() {
        return None;
    }
    let mut descriptor: uv::uv_os_fd_t = -1;
    // SAFETY: the caller passed a live handle, and `uv_fileno` only reads it.
    let status = unsafe { uv::uv_fileno(handle, &mut descriptor) };
    (status == 0 && descriptor >= 0).then_some(descriptor)
}

/// Duplicates a descriptor so two event loops can each own a reference.
///
/// Node's `TCPWrap::TransferForMessaging` calls `dup()` for exactly this: the
/// sending loop closes its handle, and the duplicate keeps the underlying socket
/// alive until the receiving loop adopts it — or until the transfer payload is
/// dropped, which closes it.
///
/// Returns `None` when `dup` fails, which is the caller's signal that the handle
/// cannot be moved.
pub fn duplicate_descriptor(descriptor: uv::uv_os_fd_t) -> Option<uv::uv_os_fd_t> {
    // SAFETY: `dup` takes an open descriptor and only borrows it for the call.
    let duplicate = unsafe { libc::dup(descriptor) };
    (duplicate >= 0).then_some(duplicate)
}

/// Closes a descriptor this process owns and nothing else will close.
///
/// Used for the two ends of a transfer that never reaches an event loop: a
/// payload dropped before it is rebuilt, and a duplicate `uv_tcp_open` rejected.
/// Both are the same obligation — the descriptor was taken out of the transfer
/// state and has no owner left.
pub fn close_descriptor(descriptor: uv::uv_os_fd_t) {
    if descriptor < 0 {
        return;
    }
    // SAFETY: the caller guarantees the descriptor is owned here and no other
    // handle refers to it. `close` only reads the number.
    unsafe {
        libc::close(descriptor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registrations are idempotent, so a realm that re-installs a binding does
    /// not grow the list and change which resolver answers first.
    #[test]
    fn registering_the_same_lookup_twice_keeps_one_entry() {
        // `push_unique` is the rule `register_resolver` applies, factored out so
        // it can be exercised without an isolate to build a constructor in.
        let mut entries: Vec<u32> = Vec::new();
        push_unique(&mut entries, |existing| *existing == 7, 7);
        push_unique(&mut entries, |existing| *existing == 7, 7);
        push_unique(&mut entries, |existing| *existing == 9, 9);
        assert_eq!(entries, vec![7, 9], "a re-install must not duplicate");
    }

    /// The IPC-pipe set answers only for handles it was told about, and forgets
    /// them on close. Without the forget, a reused address would make an ordinary
    /// pipe look like an IPC channel and the send path would call `uv_write2` on
    /// it.
    #[test]
    fn ipc_pipe_membership_is_recorded_and_forgotten() {
        let mut storage = std::mem::MaybeUninit::<uv::uv_pipe_t>::zeroed();
        let handle = storage.as_mut_ptr().cast::<uv::uv_handle_t>();
        assert!(!is_ipc_pipe(handle));
        set_ipc_pipe(handle);
        assert!(is_ipc_pipe(handle));
        forget_ipc_pipe(handle);
        assert!(!is_ipc_pipe(handle));
    }

    /// A null handle is never an IPC pipe: every caller reaches this from a
    /// `uv_stream_t` that may be null, and dereferencing it would be worse than a
    /// wrong answer.
    #[test]
    fn a_null_handle_is_not_an_ipc_pipe() {
        assert!(!is_ipc_pipe(std::ptr::null_mut()));
    }

    /// An empty pending type is what `OnUvRead` compares against, so a null stream
    /// has to answer with it rather than dereference.
    #[test]
    fn a_null_stream_has_no_pending_handle() {
        // SAFETY: the function returns before touching a null stream.
        let kind = unsafe { pending_type(std::ptr::null_mut()) };
        assert_eq!(kind, uv::uv_handle_type_UV_UNKNOWN_HANDLE);
    }
}
