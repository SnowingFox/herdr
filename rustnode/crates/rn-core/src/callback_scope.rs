//! The scope a native callback runs JavaScript inside.
//!
//! `src/api/callback.cc`'s `InternalCallbackScope` is not a convenience wrapper
//! around `Function::Call`. It is the thing that makes a callback belong to a
//! resource, and four separate Node behaviours live in it:
//!
//! 1. **`push_async_context` / `pop_async_context`** (`src/env.cc:133`) — the
//!    execution and trigger ids for the duration of the call, so
//!    `executionAsyncId()` inside the callback is the resource's.
//! 2. **`EmitBefore` / `EmitAfter`** — the `async_hooks` `before`/`after`
//!    hooks for that id.
//! 3. **`async_context_frame::exchange`** (`src/async_context_frame.cc:41`) —
//!    the continuation-preserved embedder data the resource captured when it
//!    was created. This is the store `AsyncLocalStorage.getStore()` reads.
//! 4. **A `v8::TryCatch` around the call**, with a caught exception routed to
//!    `TriggerUncaughtException` so `process.on('uncaughtException')` runs and
//!    an unhandled one exits non-zero.
//!
//! Item 3 is the easy one to miss, because it is invisible until something
//! reads it: without the exchange, a socket callback runs with whatever frame
//! the *last* callback in the process happened to leave behind, which outside
//! a `run()` is `undefined`.
//!
//! # Why the scope is driven from here and not from the binding
//!
//! The callbacks that need a scope are in `rn-uv` (stream reads and write
//! completions), but every operation above needs something only
//! `rn-bind-async-wrap` can reach: the shared id arrays, the hook functions,
//! the frame binding. `rn-uv` cannot depend on a binding, and a binding cannot
//! be depended on by the crate that owns libuv.
//!
//! So this module holds the seam, the same way [`crate::native_immediates`]
//! does: `rn-core` defines the interface, `rn-bind-async-wrap` registers the
//! implementation at install time, and `rn-uv` asks for a scope without knowing
//! who answers. Before the registration the answer is "no scope", which is the
//! honest state during bootstrap when there is no `async_wrap` to talk to.
//!
//! # Ordering, which is not the intuitive one
//!
//! `InternalMakeCallback` sets `MarkAsFailed()` when the callback throws, and
//! `InternalCallbackScope::Close` then returns at `if (failed_) return;` — so
//! the `PerformCheckpoint` that would drain microtasks never runs. The uncaught
//! trigger therefore happens **before** any microtask the throwing callback
//! queued. `crates/rn-napi/tests/addon_e2e.rs` pins the same order for
//! thread-safe functions (`callback,listener,microtask`).
//!
//! This module gets that order for free rather than by checking for it: the
//! report happens inside [`with_scope`], which runs inside the libuv callback,
//! and the microtask checkpoint is the loop's drain *between* iterations
//! (`rn_io::Loop::tick`). A future change that drained microtasks here instead
//! would have to move the report after it to keep this order, and the ordering
//! test is what would notice.
//!
//! # Why the frame is passed in rather than looked up
//!
//! `AsyncWrap` stores the frame on its own state, and the wrapper that owns a
//! stream handle is the only thing that can hand it over. Passing it in keeps
//! this module free of a handle lookup and keeps the one place that knows where
//! the frame lives (`rn-bind-async-wrap`) the only place that reads it.

use std::cell::RefCell;
use std::rc::Rc;

use rn_v8_sys::v8;

/// The async identity of the resource a callback belongs to.
///
/// Mirrors `async_context` in `src/async_wrap.h`: two ids, both `-1` when the
/// resource has none. `InternalCallbackScope` checks `async_id != 0` before it
/// emits hooks or pushes anything, so `-1` and `0` both mean "no resource".
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AsyncContext {
    /// `AsyncWrap::async_id_`.
    pub async_id: f64,
    /// `AsyncWrap::trigger_async_id_`.
    pub trigger_async_id: f64,
}

impl AsyncContext {
    /// The context of a callback that belongs to no resource.
    pub const NONE: Self = Self {
        async_id: -1.0,
        trigger_async_id: -1.0,
    };

    /// Whether hooks fire and a context is pushed.
    ///
    /// `InternalCallbackScope`'s test is `async_id != 0 && !skip_hooks_`, and a
    /// negative id means the handle was never reset, so nothing was ever
    /// emitted for it.
    pub fn is_resource(&self) -> bool {
        self.async_id > 0.0
    }
}

impl From<crate::AsyncWrapState> for AsyncContext {
    /// The context a callback for this wrap runs under.
    ///
    /// `AsyncWrap::MakeCallback` builds its context as
    /// `{get_async_id(), get_trigger_async_id()}` (`src/async_wrap.cc:681`), so
    /// this is that pair and nothing else.
    fn from(state: crate::AsyncWrapState) -> Self {
        Self {
            async_id: state.async_id,
            trigger_async_id: state.trigger_async_id,
        }
    }
}

/// Everything a scope needs to know about the callback it wraps.
pub struct ScopeArgs {
    /// The resource's async identity.
    pub context: AsyncContext,
    /// The JS object the resource is visible as, for `executionAsyncResource`.
    pub resource: Option<v8::Global<v8::Object>>,
    /// The frame the resource captured when it was created.
    ///
    /// `None` is Node's empty internal field, which `async_context_frame`
    /// represents with `empty_context_frame_sentinel_symbol`. A missing frame and
    /// an explicit `undefined` are the same thing to `AsyncLocalStorage`.
    pub frame: Option<v8::Global<v8::Value>>,
}

/// What a registered implementation has to do.
///
/// A trait rather than three function pointers because the pieces share state
/// (`rn-bind-async-wrap` keeps the hook functions and the id arrays in
/// thread-locals) and this keeps that state private to the crate that owns it.
pub trait CallbackScopeHooks {
    /// Opens the scope, before the call.
    ///
    /// This is `InternalCallbackScope`'s constructor: push the async context,
    /// exchange the frame, then emit `before`. Returns the prior frame, rooted,
    /// because it is a JS value that has to survive the call.
    fn open(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        args: &ScopeArgs,
    ) -> Option<v8::Global<v8::Value>>;

    /// Closes the scope, after the call.
    ///
    /// This is `InternalCallbackScope::Close`: emit `after` unless the call
    /// threw, pop the async context, then restore the frame. The restore runs
    /// even on a throw — Node's destructor runs either way, and a callback that
    /// throws must not leave the id stack one frame deeper for the rest of the
    /// process.
    ///
    /// Restoring the frame *last* is deliberate: an `after` hook that reads
    /// `getStore()` still sees the callback's own frame.
    fn close(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
        args: &ScopeArgs,
        prior_frame: Option<v8::Global<v8::Value>>,
        threw: bool,
    );

    /// Hands a caught exception to the runtime's uncaught-exception path.
    ///
    /// Implemented by `rn-bind-async-wrap` as
    /// `rn_errors::report_uncaught_exception`, which is `TriggerUncaughtException`
    /// in order: `process._fatalException` first, and only a `false` answer
    /// reaches the print-and-exit path. There is deliberately no second
    /// implementation anywhere — two paths that disagree about ordering is the
    /// same class of defect as two finalizer registries.
    fn report_uncaught(&self, scope: &mut v8::PinScope<'_, '_>, error: v8::Local<v8::Value>);
}

thread_local! {
    /// The registered implementation, if a binding has installed one.
    ///
    /// An `Rc` rather than a `Box` because a callback can reach another scoped
    /// callback: taking a `Box` out for the duration would leave the nested call
    /// with no implementation and it would silently run unscoped.
    static HOOKS: RefCell<Option<Rc<dyn CallbackScopeHooks>>> = const { RefCell::new(None) };
}

/// Registers the implementation that gives native callbacks a scope.
///
/// Called once, by `rn-bind-async-wrap`'s install. A second call replaces the
/// first rather than accumulating, because there is one `async_wrap` namespace
/// per isolate and two implementations would mean two context pushes per
/// callback.
pub fn set_hooks(hooks: Rc<dyn CallbackScopeHooks>) {
    HOOKS.with(|slot| *slot.borrow_mut() = Some(hooks));
}

/// Whether a scope can be opened.
///
/// False during bootstrap: `async_wrap` installs before anything can call back
/// from libuv, so a caller that sees `false` is running earlier than it should.
pub fn is_installed() -> bool {
    HOOKS.with(|slot| slot.borrow().is_some())
}

/// Runs `body` with the scope for `args` open around it.
///
/// Returns `Some(body's value)` when the callback returned, `None` when it
/// threw. A throw is reported to `process._fatalException` before this returns,
/// which is the ordering [`crate::callback_scope`]'s module docs explain.
///
/// The exception is not left pending: the `TryCatch` here consumes it, because
/// the only thing above a libuv callback is `uv_run`, where a pending exception
/// would reach V8's default reporter instead of Node's.
pub fn with_scope<R>(
    scope: &mut v8::PinScope<'_, '_>,
    args: ScopeArgs,
    body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> R,
) -> Option<R> {
    // No implementation means no `async_wrap`, i.e. something is calling back
    // before the bindings installed. Running the body unscoped is the only
    // option, and it is what every call site did before this existed.
    let Some(hooks) = HOOKS.with(|slot| slot.borrow().clone()) else {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scoped = &mut try_catch.init();
        let result = body(scoped);
        return (!scoped.has_caught()).then_some(result);
    };

    let prior = hooks.open(scope, &args);
    let (returned, result) = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scoped = &mut try_catch.init();
        let result = body(scoped);
        match scoped.exception() {
            // Reported while the exception is still a local: `report_uncaught`
            // runs JavaScript, and it must not run after the `TryCatch` above
            // has closed and dropped the only handle to the value.
            Some(error) => {
                hooks.report_uncaught(scoped, error);
                (false, result)
            }
            None => (true, result),
        }
    };
    hooks.close(scope, &args, prior, !returned);
    returned.then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_implementation_runs_the_body_unscoped() {
        // The bootstrap state: the body still runs, so a callback that arrives
        // before `async_wrap` installs is not silently dropped.
        HOOKS.with(|slot| *slot.borrow_mut() = None);
        assert!(!is_installed());
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
        let mut isolate = v8::Isolate::new(Default::default());
        let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut storage.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        let args = ScopeArgs {
            context: AsyncContext::NONE,
            resource: None,
            frame: None,
        };
        let mut ran = false;
        let result = with_scope(scope, args, |_| {
            ran = true;
            7
        });
        assert_eq!(result, Some(7));
        assert!(ran, "the body must run even with no implementation");
    }

    #[test]
    fn a_context_with_no_resource_asks_for_no_hooks() {
        // `InternalCallbackScope` checks `async_id != 0 && !skip_hooks_`, and a
        // negative id is the "never reset" handle no hooks were ever emitted for.
        assert!(!AsyncContext::NONE.is_resource());
        assert!(!AsyncContext {
            async_id: 0.0,
            trigger_async_id: 0.0
        }
        .is_resource());
        assert!(AsyncContext {
            async_id: 1.0,
            trigger_async_id: 0.0
        }
        .is_resource());
    }
}
