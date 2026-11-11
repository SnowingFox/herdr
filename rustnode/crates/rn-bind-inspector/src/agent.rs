//! The inspector agent: one `V8Inspector`, its context group, and its sessions.
//!
//! Node's counterpart is `src/inspector_agent.cc`'s `Agent`. The shape is the
//! same and the reason is the same: V8's inspector is one object per isolate that
//! must be told which context it inspects, and every frontend — the
//! `inspector.Session` JavaScript object, a CDP client on a WebSocket — is a
//! *session* against that one inspector rather than a second inspector.
//!
//! # Why the isolate is recorded rather than passed
//!
//! `V8Inspector::create` needs `&mut Isolate`, which a `FunctionCallback` cannot
//! obtain soundly: the `v8` crate documents `FunctionCallbackArguments::get_isolate`
//! as unsound while a callback scope is open, and one always is inside a binding.
//! So the CLI records the isolate at startup through [`set_isolate`], exactly as
//! `rn-bind-heap-utils` does for heap snapshots, and this reconstructs a borrowing
//! `Isolate` from that pointer for the duration of one call.
//!
//! A reconstructed `Isolate` is a `NonNull<RealIsolate>` newtype with no `Drop`
//! impl, so it borrows rather than owns. It is only used on the thread that
//! recorded it, while that isolate is alive.
//!
//! # Lifetime of the inspector
//!
//! `V8Inspector` is stored in a thread-local and deliberately never dropped. V8
//! owns the context and every session, and a session can outlive the JavaScript
//! `Session` object that created it (`lib/inspector.js`'s `disconnect` drops its
//! own reference, but a CDP client's session is owned by the server). Dropping the
//! inspector at a moment V8 did not choose is what aborts the process, so the
//! process exit is the only teardown — which is also what Node does.

use std::cell::{Cell, RefCell};

use rn_v8_sys::v8;

/// The one context group every session attaches to.
///
/// A group is what ties a set of contexts to a set of sessions, so all sessions
/// here agree on it; a frontend attached to a different (empty) group would have
/// every `Runtime.evaluate` answered with "Cannot find context with specified id".
/// Node's `Agent` uses a single group id per environment for the same reason.
pub const CONTEXT_GROUP_ID: i32 = 1;

thread_local! {
    /// The isolate the bindings were installed into, as the raw V8 pointer.
    static ISOLATE: Cell<Option<v8::UnsafeRawIsolatePtr>> = const { Cell::new(None) };
    static STATE: RefCell<AgentState> = const { RefCell::new(AgentState::new()) };
}

struct AgentState {
    /// The isolate the inspector was created for.
    ///
    /// One inspector belongs to one isolate, so recording which isolate it was made
    /// for is what lets a second isolate — a test's, or a hypothetical worker's —
    /// get its own instead of silently evaluating against a dead one. The symptom of
    /// getting this wrong is `Runtime.evaluate` answering "Cannot find default
    /// execution context" while everything else looks correct.
    isolate: Option<usize>,
    /// The inspector itself, leaked on purpose.
    ///
    /// V8 tears down its inspector objects as part of isolate disposal, so dropping
    /// this afterwards dereferences freed memory — and the drop would happen from a
    /// thread-local destructor, which runs *after* `main` has already dropped the
    /// isolate. Leaking it is what Node does too: `Agent` lives for the process's
    /// life and its `V8Inspector` is never explicitly destroyed.
    inspector: Option<&'static v8::inspector::V8Inspector>,
    /// Whether `contextCreated` has run for the context being inspected.
    context_created: bool,
    /// The inspected context, rooted.
    ///
    /// V8 asks the client for "the default context in this group" on every protocol
    /// message that does not name one, so the handle has to outlive the call that
    /// created it.
    default_context: Option<v8::Global<v8::Context>>,
}

impl AgentState {
    const fn new() -> Self {
        Self {
            isolate: None,
            inspector: None,
            context_created: false,
            default_context: None,
        }
    }
}

/// Records the isolate the inspector is created against.
///
/// Called by the CLI once, immediately after the isolate is created. Repeated
/// calls are harmless and record the same pointer.
pub fn set_isolate(isolate: &mut v8::Isolate) {
    // SAFETY: producing the pointer is safe; re-entering it requires the
    // guarantee documented on this module, which the CLI satisfies by calling this
    // once for an isolate that outlives every binding call.
    let pointer = unsafe { isolate.as_raw_isolate_ptr() };
    ISOLATE.with(|slot| slot.set(Some(pointer)));
}

/// The address an isolate pointer refers to, for identity comparison.
///
/// `UnsafeRawIsolatePtr` has no `PartialEq` — comparing V8 pointers is not something
/// the crate wants to encourage — but identifying "the inspector for this isolate" is
/// a plain address comparison.
fn pointer_address(pointer: v8::UnsafeRawIsolatePtr) -> usize {
    // SAFETY: reading the address out is not a dereference; the value is only compared.
    unsafe { std::mem::transmute::<v8::UnsafeRawIsolatePtr, usize>(pointer) }
}

/// Runs `body` against the recorded isolate.
///
/// Returns `None` before [`set_isolate`] has run, which is the honest answer: an
/// inspector cannot be created without an isolate to inspect.
pub fn with_isolate<R>(body: impl FnOnce(&mut v8::Isolate) -> R) -> Option<R> {
    let pointer = ISOLATE.with(|slot| slot.get())?;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: `pointer` came from `set_isolate` on this thread for an isolate that
    // outlives every binding call, as documented on the module.
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(pointer) };
    Some(body(&mut isolate))
}

/// The inspector client V8 calls back into.
///
/// Two methods are load-bearing:
///
/// * `ensure_default_context_in_group` must return the inspected context. Without it
///   every `Runtime.evaluate` answers `Cannot find default execution context`, because
///   V8 has no way to pick a context when the protocol message names none — which is
///   exactly the case for `Runtime.evaluate`, `Runtime.getProperties` and every
///   `Profiler.*` call. The default trait implementation returns `None`, so leaving it
///   out produces a namespace that looks complete and evaluates nothing.
/// * `run_message_loop_on_pause` is what makes a breakpoint *stop* JavaScript. V8 calls
///   it from inside `Debugger.pause` and from a breakpoint hit, and it must not return
///   until the frontend says resume; returning immediately is the shape that made this
///   crate's first slice acknowledge a pause and keep running. See `pause` for what it
///   blocks on and why it is a condition variable rather than a nested event loop.
struct Client;

impl v8::inspector::V8InspectorClientImpl for Client {
    fn run_message_loop_on_pause(&self, _context_group_id: i32) {
        // `waiting_for_resume_ = true; runMessageLoop();` in Node's
        // `runMessageLoopOnPause` (`inspector_agent.cc:538`). The loop dispatches
        // frontend messages — including the `Debugger.resume` that ends it — and the
        // isolate sits still until then.
        crate::pause::set_resumed(false);
        // `NodeRuntime.waitingForDebugger` is what `test-inspector-debug-brk-flag.js`
        // and `test-inspector.js` wait for after sending `NodeRuntime.enable`. It is
        // emitted here, at the moment the pause really starts, because that is the
        // event's meaning: the runtime is stopped and the frontend may now drive it.
        if let Some(message) = crate::domains::waiting_for_debugger_notification() {
            crate::deliver_to_frontends(&message);
        }
        crate::pause::run_pause_loop();
    }

    fn quit_message_loop_on_pause(&self) {
        // Node: `waiting_for_resume_ = false` (`:590`). V8 calls this from inside
        // `Debugger.resume`, on the paused thread, so it only has to flip the flag the
        // wait condition reads.
        crate::pause::resume();
    }
    fn ensure_default_context_in_group(
        &self,
        context_group_id: i32,
    ) -> Option<v8::Local<'_, v8::Context>> {
        if context_group_id != CONTEXT_GROUP_ID {
            return None;
        }
        let pointer = ISOLATE.with(|slot| slot.get())?;
        let context = STATE.with(|state| state.borrow().default_context.clone())?;
        // A handle scope is needed to turn the `Global` back into a `Local`, and there
        // is none: V8 calls this from inside protocol dispatch, not from a binding.
        // Re-entering the isolate for one handle is what `rn-bind-heap-utils` does for
        // heap snapshots, for the same reason.
        //
        // SAFETY: `pointer` is the isolate this thread recorded, still alive because
        // V8 is inside a call on it.
        let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(pointer) };
        let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = storage.init();
        let local = v8::Local::new(&scope, &context);
        // SAFETY: the returned `Local` is a `NonNull<Context>` and nothing else — its
        // lifetime is a phantom marker. The handle scope above only owns the slot V8
        // would have used for it, which this type does not allocate from, so the
        // pointer stays valid. The context itself is rooted in `default_context` for as
        // long as the inspector exists, and V8 consumes the value during this callback.
        Some(unsafe { leak_local(local) })
    }
}

/// Erases a `Local`'s lifetime.
///
/// # Safety
///
/// The returned handle must only be used while the V8 heap object behind it is alive
/// and must not be stored past the V8 call that asked for it. The caller is
/// responsible for both, which is why the only use is the client callback above.
unsafe fn leak_local<'s, T>(local: v8::Local<'_, T>) -> v8::Local<'s, T> {
    // SAFETY: `Local<T>` is a `NonNull<T>` with a phantom lifetime, so the two types
    // have identical layout and the same validity requirement.
    unsafe { std::mem::transmute(local) }
}

/// Creates the inspector and registers the current context with it, once.
///
/// `contextCreated` is what makes V8 build the `InspectedContext` a session
/// evaluates against, and it is also what installs V8's own `console` on the
/// per-context extras object that `lib/internal/util/inspector.js`'s `wrapConsole`
/// reads. So this must run before the global console is wrapped, which is why the
/// CLI calls it during bootstrap rather than on the first `open()`.
///
/// Returns false when there is no isolate to inspect, which `open()` turns into
/// `ERR_INSPECTOR_NOT_AVAILABLE`.
pub fn ensure_inspector(scope: &mut v8::PinScope<'_, '_>) -> bool {
    let current = ISOLATE.with(|slot| slot.get().map(pointer_address));

    let already = STATE.with(|state| {
        let state = state.borrow();
        state.inspector.is_some() && state.context_created && state.isolate == current
    });
    if already {
        return true;
    }

    let created = STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.inspector.is_some() && state.isolate == current {
            return true;
        }
        // A different isolate: this inspector inspects one that no longer exists, so
        // it cannot be reused. It is leaked rather than dropped, for the reason on
        // `AgentState::inspector`.
        state.inspector = None;
        state.context_created = false;
        state.default_context = None;
        state.isolate = current;
        let Some(inspector) = with_isolate(|isolate| {
            // SAFETY-adjacent note: the leak is deliberate, see `AgentState::inspector`.
            Box::leak(Box::new(v8::inspector::V8Inspector::create(
                isolate,
                v8::inspector::V8InspectorClient::new(Box::new(Client)),
            ))) as &'static v8::inspector::V8Inspector
        }) else {
            return false;
        };
        state.inspector = Some(inspector);
        true
    });
    if !created {
        return false;
    }

    // V8 calls the channel's `send_response` from inside `dispatch`, with no V8 scope
    // of its own open. `rn-uv`'s `callback::with_context` is how every other binding in
    // this tree re-enters JavaScript from a callback, and it needs the isolate and
    // context recorded first — which is exactly here, where both are in hand.
    rn_uv::callback::remember_context(scope);

    let context = scope.get_current_context();
    // Node passes an empty human-readable name for the main context and
    // `{"isDefault":true}` as aux data, which is what makes DevTools treat it as
    // the page's default execution context instead of a worker.
    let name = String::new();
    let aux_data = String::from(r#"{"isDefault":true}"#);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.context_created {
            return;
        }
        if let Some(inspector) = state.inspector.as_ref() {
            inspector.context_created(
                context,
                CONTEXT_GROUP_ID,
                v8::inspector::StringView::from(name.as_bytes()),
                v8::inspector::StringView::from(aux_data.as_bytes()),
            );
            state.context_created = true;
            state.default_context = Some(v8::Global::new(scope.as_ref(), context));
        }
    });
    true
}

/// Opens one session against the inspector.
///
/// `state` is the value V8 hands back to a frontend that reconnects; it is empty
/// for a fresh session. `FullyTrusted` is what Node passes — the default untrusted
/// level disables the debugger domains entirely.
pub fn connect(
    channel: v8::inspector::Channel,
) -> Option<&'static v8::inspector::V8InspectorSession> {
    STATE.with(|state| {
        let state = state.borrow();
        let inspector = state.inspector.as_ref()?;
        let session = inspector.connect(
            CONTEXT_GROUP_ID,
            channel,
            v8::inspector::StringView::empty(),
            v8::inspector::V8InspectorClientTrustLevel::FullyTrusted,
        );
        // Leaked for the same reason the inspector is: V8 owns the session's storage
        // until the isolate goes away, and a session outlives the JavaScript object
        // that opened it (`disconnect` drops only the caller's reference).
        Some(&*Box::leak(Box::new(session)))
    })
}

/// Notifies the inspector that an async task was scheduled.
///
/// `task` is the pointer Node's `inspector_js_api.cc`'s `GetAsyncTask` derives
/// from the async id (`id << 1`), which the inspector stores as an opaque key.
///
/// # Safety
///
/// `task` must be the same pointer passed to the matching started/finished calls.
pub unsafe fn async_task_scheduled(
    task_name: &str,
    task: *const std::ffi::c_void,
    recurring: bool,
) {
    let view = v8::inspector::StringView::from(task_name.as_bytes());
    STATE.with(|state| {
        let state = state.borrow();
        if let Some(inspector) = state.inspector.as_ref() {
            // SAFETY: the caller upholds the pointer contract documented above.
            unsafe { inspector.async_task_scheduled(view, task, recurring) };
        }
    });
}

/// Notifies the inspector that a scheduled async task was cancelled.
///
/// # Safety
///
/// As [`async_task_scheduled`].
pub unsafe fn async_task_canceled(task: *const std::ffi::c_void) {
    STATE.with(|state| {
        let state = state.borrow();
        if let Some(inspector) = state.inspector.as_ref() {
            // SAFETY: the caller upholds the pointer contract.
            unsafe { inspector.async_task_canceled(task) };
        }
    });
}

/// Notifies the inspector that an async task started running.
///
/// # Safety
///
/// As [`async_task_scheduled`].
pub unsafe fn async_task_started(task: *const std::ffi::c_void) {
    STATE.with(|state| {
        let state = state.borrow();
        if let Some(inspector) = state.inspector.as_ref() {
            // SAFETY: the caller upholds the pointer contract.
            unsafe { inspector.async_task_started(task) };
        }
    });
}

/// Notifies the inspector that an async task finished running.
///
/// # Safety
///
/// As [`async_task_scheduled`].
pub unsafe fn async_task_finished(task: *const std::ffi::c_void) {
    STATE.with(|state| {
        let state = state.borrow();
        if let Some(inspector) = state.inspector.as_ref() {
            // SAFETY: the caller upholds the pointer contract.
            unsafe { inspector.async_task_finished(task) };
        }
    });
}

/// Asks a session to pause before the next statement executes.
///
/// This is what `--inspect-brk` and `callAndPauseOnStart` need: the request is
/// recorded on the session, and V8 suspends at the next statement it compiles
/// into that session's context.
pub fn schedule_pause_on_next_statement(
    session: &'static v8::inspector::V8InspectorSession,
    reason: &str,
) {
    let buffer = reason.as_bytes();
    let view = v8::inspector::StringView::from(buffer);
    session.schedule_pause_on_next_statement(view, view);
}
