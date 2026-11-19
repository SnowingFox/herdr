//! `--trace-promises`: the isolate promise hook `Environment::TracePromises` installs.
//!
//! `Environment::InitializeDiagnostics` (`src/node.cc:247`) is the whole of
//! Node's setup:
//!
//! ```text
//! if (options_->trace_promises) {
//!   isolate_->SetPromiseHook(TracePromises);
//! }
//! ```
//!
//! and `Environment::TracePromises` (`src/env.cc:2300`) is the whole of the
//! output. It ignores `kBefore` and `kAfter` — only creation and resolution are
//! reported — gives every promise an environment-wide sequence number kept in a
//! V8 *private* property, prints `[--trace-promises] created promise #N` or
//! `[--trace-promises] resolved promise #N` with `promise #P ` inserted after the
//! prefix when the promise has a parent, and follows each line with
//! `PrintCurrentStackTrace`.
//!
//! # Why an isolate hook rather than `lib/internal/promise_hooks.js`
//!
//! That module is a different mechanism: it drives async hooks' consumers, and
//! Node's flag does not install it. The isolate hook sees every promise V8
//! creates, including the ones the loader makes before any `lib/` module has
//! run, which is exactly why the first ids in the trace belong to bootstrap
//! internals.
//!
//! # The callback's shape
//!
//! `v8::PromiseHook` is a bare `extern "C" fn(PromiseHookType, Local<Promise>,
//! Local<Value>)`: handles, no isolate, no context. Node opens nothing because
//! its callback machinery already has a scope on the stack and reads the context
//! from the entered isolate. Neither is available through the `v8` crate here —
//! it binds no `Isolate::GetCurrent`/`GetCurrentContext` — so the two facts the
//! hook needs are recorded when the realm is built:
//!
//! * the isolate pointer, from `install`, which is where Node calls
//!   `SetPromiseHook`;
//! * the principal realm's context, from [`record_context`], which runs once the
//!   CLI has created it.
//!
//! With both, the hook opens its own `HandleScope` — a nested scope is what V8
//! expects a callback that allocates handles to open — re-enters the recorded
//! context, and does the work there. A process without the flag installs no
//! callback, so nothing below runs.
//!
//! # Cost when the flag is off
//!
//! Nothing: no hook, no private property, no counter.

use rn_v8_sys::v8;

thread_local! {
    /// The next id to hand out, `Environment::trace_promise_id_counter_`.
    ///
    /// Per thread rather than per process: an isolate is entered on one thread at
    /// a time and this is only read and written from inside the hook on that
    /// thread, which is the same scope Node's per-environment counter has.
    static NEXT_ID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };

    /// The isolate the hook was installed on.
    ///
    /// `None` until [`install`] runs on a process that asked for the flag, so a
    /// hook that somehow fired without it returns instead of dereferencing null.
    static ISOLATE: std::cell::Cell<Option<v8::UnsafeRawIsolatePtr>> =
        const { std::cell::Cell::new(None) };

    /// The principal realm's context, and the `Private` the trace ids live under.
    ///
    /// Both are `Global` handles so they survive across callbacks, and both are
    /// created once: a fresh `Private` per callback would never match the one an
    /// earlier callback stored.
    static STATE: std::cell::RefCell<Option<TraceState>> = const { std::cell::RefCell::new(None) };
}

/// The two handles the hook needs and cannot construct without a scope of the
/// caller's kind.
struct TraceState {
    context: v8::Global<v8::Context>,
    key: v8::Global<v8::Private>,
}

/// Arms the hook when `--trace-promises` asked for it.
///
/// This is `InitializeDiagnostics`'s `SetPromiseHook(TracePromises)`.
/// `enabled` comes from the CLI's own parser because this runs before the option
/// store is installed; the store and `EnvironmentOptions` are filled from the
/// same argv, so the two cannot disagree.
///
/// Only the main isolate is armed. `Environment::InitializeDiagnostics` runs per
/// environment in Node, so a worker gets its own hook and its own counter; this
/// build's worker isolate is created in `rn-bind-worker`, which arms nothing.
/// Worker-scoped `--trace-promises` is therefore a stated gap rather than an
/// approximation: borrowing the main thread's counter inside a worker would print
/// ids that match nothing.
pub fn arm(enabled: bool, isolate: &mut v8::Isolate) {
    if !enabled {
        return;
    }
    // SAFETY: `as_raw_isolate_ptr` is the crate's own escape hatch for holding an
    // isolate across a callback that receives none. The pointer is only read back
    // from inside `hook`, which V8 invokes with this isolate entered.
    let raw = unsafe { isolate.as_raw_isolate_ptr() };
    ISOLATE.with(|slot| slot.set(Some(raw)));
    isolate.set_promise_hook(hook);
}

/// Records the realm the hook reports against.
///
/// Called once the principal realm's context exists, which is the earliest point
/// a `Local<Context>` can be turned into the `Global` the hook needs. `enabled` is
/// the CLI's own record rather than a store lookup, because this runs before the
/// option store is installed.
///
/// The `Private` key is created here rather than inside the hook because a
/// `Private` needs a scope, and a lazily created one would have to prove the
/// first callback always has a usable scope. One key per process matches
/// `Environment::promise_trace_id()`, which is one per environment.
pub fn record_context(
    enabled: bool,
    scope: &v8::PinScope<'_, '_, ()>,
    context: v8::Local<'_, v8::Context>,
) {
    if !enabled {
        return;
    }
    let Some(name) = v8::String::new(scope, "node:promise_trace_id") else {
        return;
    };
    let key = v8::Private::new(scope, Some(name));
    STATE.with(|slot| {
        *slot.borrow_mut() = Some(TraceState {
            context: v8::Global::new(scope, context),
            key: v8::Global::new(scope, key),
        });
    });
}

/// The id `TracePromises` stored on `promise`, if it has one.
///
/// `GetPromiseId`: a promise without the private property, or whose value is not
/// a `Uint32`, has no id. Node drops a `kResolve` for such a promise too.
fn promise_id(
    scope: &v8::PinScope<'_, '_>,
    promise: v8::Local<'_, v8::Promise>,
    key: v8::Local<'_, v8::Private>,
) -> Option<u32> {
    let object: v8::Local<'_, v8::Object> = promise.into();
    let stored = object.get_private(scope, key)?;
    stored.uint32_value(scope)
}

/// `Environment::TracePromises`.
unsafe extern "C" fn hook(
    hook_type: v8::PromiseHookType,
    promise: v8::Local<v8::Promise>,
    parent: v8::Local<v8::Value>,
) {
    // `if (type == kBefore || type == kAfter) return;`
    if matches!(
        hook_type,
        v8::PromiseHookType::Before | v8::PromiseHookType::After
    ) {
        return;
    }
    let Some(isolate_ptr) = ISOLATE.with(std::cell::Cell::get) else {
        return;
    };
    // SAFETY: V8 calls the hook with this isolate entered on the thread that
    // recorded it. `Isolate` is a `NonNull` wrapper with no `Drop` of its own —
    // only `OwnedIsolate` has one — so this borrow neither owns nor destroys the
    // engine's isolate. The same construction `rn-bind-http-parser` uses for its
    // own callbacks.
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(isolate_ptr) };
    // A handle scope nested inside whatever scope V8 called the hook from, which
    // is exactly a callback's situation: the handles below live until this
    // function returns.
    let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let storage = &mut storage.init();
    let Some((context, key)) = STATE.with(|slot| {
        slot.borrow().as_ref().map(|state| {
            (
                v8::Local::new(&*storage, &state.context),
                v8::Local::new(&*storage, &state.key),
            )
        })
    }) else {
        return;
    };
    let mut context_storage = std::pin::pin!(v8::ContextScope::new(storage, context));
    let scope: &mut v8::PinScope<'_, '_> = &mut context_storage;

    record(scope, hook_type, promise, parent, key);
}

/// The reporting half of the hook, in the callback's scope.
fn record(
    scope: &mut v8::PinScope<'_, '_>,
    hook_type: v8::PromiseHookType,
    promise: v8::Local<'_, v8::Promise>,
    parent: v8::Local<'_, v8::Value>,
    key: v8::Local<'_, v8::Private>,
) {
    // `if (!parent.IsEmpty() && parent->IsPromise()) parent_id = GetPromiseId(...)`
    let parent_id = if parent.is_promise() {
        v8::Local::<v8::Promise>::try_from(parent)
            .ok()
            .and_then(|parent| promise_id(scope, parent, key))
    } else {
        None
    };

    let (id, action) = match hook_type {
        v8::PromiseHookType::Init => {
            let id = NEXT_ID.with(|next| {
                let id = next.get();
                next.set(id.wrapping_add(1));
                id
            });
            let object: v8::Local<'_, v8::Object> = promise.into();
            let stored = v8::Integer::new_from_unsigned(scope, id);
            let _ = object.set_private(scope, key, stored.into());
            (id, "created")
        }
        v8::PromiseHookType::Resolve => {
            let Some(id) = promise_id(scope, promise, key) else {
                return;
            };
            (id, "resolved")
        }
        // `Before` and `After` returned at the top; V8 has no other variant.
        v8::PromiseHookType::Before | v8::PromiseHookType::After => return,
    };

    // `FPrintF(stderr, "[--trace-promises] ")`, then `"promise #%d "` when there
    // is a parent, then `"%s promise #%d\n"`. The parent prefix comes *before*
    // the action, which is why one string is built here.
    let mut text = match parent_id {
        Some(parent) => format!("[--trace-promises] promise #{parent} {action} promise #{id}\n"),
        None => format!("[--trace-promises] {action} promise #{id}\n"),
    };
    // The message and the stack are one write: stderr is line buffered and the
    // oracle's output has no interleaving between them.
    if let Some(trace) = v8::StackTrace::current_stack_trace(scope, stack_trace_limit()) {
        text.push_str(&rn_errors::format_stack_trace(scope, &trace));
        text.push('\n');
    }
    rn_core::hook_slot::write_stderr(&text);
}

/// The frame limit `PrintCurrentStackTrace` uses: `--stack-trace-limit`.
///
/// `PrintStackTrace` runs with the environment's own limit, which is the value
/// `Error.stackTraceLimit` reports. Zero means no frames, which is why the
/// negative case is handled explicitly rather than cast.
fn stack_trace_limit() -> usize {
    let limit = rn_core::hook_slot::stack_trace_limit();
    usize::try_from(limit).unwrap_or(0)
}
