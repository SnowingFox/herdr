//! `AsyncWrap::RegisterDestroyHook`: the `destroy` hook for a resource that dies
//! by garbage collection.
//!
//! `src/async_wrap.cc:252` ties a `destroy` hook to a *JavaScript object's*
//! collection rather than to a C++ `AsyncWrap`. `lib/async_hooks.js:216` calls it
//! from the `AsyncResource` constructor when `destroy` hooks are enabled and the
//! caller did not ask for a manual destroy, and
//! `lib/internal/async_hooks.js:333` calls it for every promise when destroy
//! tracking is on. Without it, a userland `AsyncResource` that is dropped and
//! collected never reports `destroy`, which is what
//! `test/parallel/test-async-hooks-destroy-on-gc.js` asserts and what every
//! `AsyncLocalStorage` leak test depends on for its `onGC` listener.
//!
//! # The three places this can run, and what each may touch
//!
//! * **Registration** (`register`, from the constructor) runs with a scope on
//!   the isolate thread.
//! * **Collection** (the weak callback) runs on whichever thread triggered the
//!   collection, which in this runtime is *measured* not to be the isolate's —
//!   `rn_core::finalizer`'s module docs record the measurement. That callback
//!   therefore touches no V8 state and no thread-local: it hands the async id to
//!   [`rn_core::finalizer::enqueue_for`], which is a mutex and a wake.
//! * **Emission** (the deferred body, then the native immediate) runs with a
//!   scope on the isolate thread, which is the only place the `destroyed`
//!   property bag can be read and the hook called.
//!
//! # Why the `v8::Weak` lives in a side table
//!
//! **Dropping a `v8::Weak` deregisters its finalizer** (`impl Drop for Weak` in
//! `handle.rs`). Node keeps the registration alive in a heap-allocated
//! `DestroyParam` that the weak callback itself frees (`async_wrap.cc:231`); the
//! nearest equivalent here is a table entry that the deferred body removes. That
//! removal is what drops the handle, and it happens on the isolate thread, which
//! `Weak` requires: it is neither `Send` nor `Sync`, and its `Drop` reaches the
//! isolate's finalizer map.

use std::cell::RefCell;
use std::thread::ThreadId;

use rn_v8_sys::v8;

/// The property the bag carries, `Environment::destroyed_string()`.
const DESTROYED: &str = "destroyed";

struct Registration {
    async_id: f64,
    /// The handle that makes the object weak.
    ///
    /// Never read: holding it is the whole contract. Dropping a `v8::Weak`
    /// removes its finalizer (`impl Drop for Weak` calls `remove_finalizer`), so
    /// a `let _ =` registration would install the callback and remove it in the
    /// same expression. The same defect this crate has already had once, recorded
    /// on `rn_napi::wrap::Wrap::weak`.
    #[allow(dead_code)]
    weak: v8::Weak<v8::Object>,
}

/// One collected registration waiting to be reported.
pub(crate) struct Collected {
    pub(crate) async_id: f64,
    /// The `destroyed` bag `lib/async_hooks.js` allocated, when it passed one.
    ///
    /// Promises are registered with two arguments and have none, which is why
    /// the field is optional: `AsyncWrap::WeakCallback` treats an absent bag as
    /// "not destroyed yet" and emits (`async_wrap.cc:247`).
    bag: Option<v8::Global<v8::Object>>,
}

thread_local! {
    /// Live registrations on this thread's isolate.
    ///
    /// Bounded by the number of resources that are registered but not yet
    /// collected, which is exactly Node's `DestroyParam` population.
    static REGISTRATIONS: RefCell<Vec<Registration>> = const { RefCell::new(Vec::new()) };
    /// Registrations whose object was collected, waiting for the check phase.
    static COLLECTED: RefCell<Vec<Collected>> = const { RefCell::new(Vec::new()) };
}

/// `AsyncWrap::RegisterDestroyHook`.
///
/// `bag` is the `{ destroyed: false }` object `lib/async_hooks.js` allocates so
/// that `AsyncResource.emitDestroy()` can suppress the collection-time hook. It
/// is rooted here because it has to be readable at collection time, and it is
/// dropped with the registration, which is the only thing that reads it.
pub(crate) fn register(
    scope: &mut v8::PinScope<'_, '_>,
    target: v8::Local<v8::Object>,
    async_id: f64,
    bag: Option<v8::Local<v8::Object>>,
) {
    let owner = std::thread::current().id();
    let bag = bag.map(|bag| v8::Global::new(scope.as_ref(), bag));
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        target,
        Box::new(move || collected(owner, async_id, bag)),
    );
    REGISTRATIONS.with(|registrations| {
        registrations
            .borrow_mut()
            .push(Registration { async_id, weak });
    });
}

/// The weak callback: the object is gone, so its `destroy` is now due.
///
/// Runs on whichever thread triggered the collection, so the only thing it may
/// do is hand the ids to the deferred queue. The bag travels with them because
/// reading it needs a scope on the isolate thread.
fn collected(owner: ThreadId, async_id: f64, bag: Option<v8::Global<v8::Object>>) {
    // `enqueue_for` is documented safe from any thread — it takes a mutex and
    // wakes the loop, touching no V8 state — and it files the body under
    // `owner`, which is the thread whose isolate has the hook functions and the
    // shared arrays.
    let _ = rn_core::finalizer::enqueue_for(Some(owner), move || {
        on_owner_thread(async_id, bag);
    });
}

/// Forgets the registration and queues the id for the `destroy` hook.
///
/// Called from a deferred finalizer, i.e. with a scope open on the isolate
/// thread: `REGISTRATIONS` and `COLLECTED` are thread-locals, and dropping the
/// `v8::Weak` here reaches the isolate's finalizer map.
fn on_owner_thread(async_id: f64, bag: Option<v8::Global<v8::Object>>) {
    REGISTRATIONS.with(|registrations| {
        let mut registrations = registrations.borrow_mut();
        if let Some(index) = registrations
            .iter()
            .position(|registration| registration.async_id == async_id)
        {
            // Dropping the entry drops the weak handle. The finalizer already
            // ran, so `Weak::drop` finds no finalizer to remove and no pointer
            // to reset; the handle's own allocation is what is released.
            registrations.remove(index);
        }
    });
    COLLECTED.with(|collected| {
        collected.borrow_mut().push(Collected { async_id, bag });
    });
    // `AsyncWrap::EmitDestroy` defers through the native immediate queue, so the
    // hook still runs from the check phase rather than inline in the finalizer.
    crate::schedule_destroy_drain();
}

/// Takes every collected registration waiting on this thread.
pub(crate) fn take_collected() -> Vec<Collected> {
    COLLECTED.with(|collected| std::mem::take(&mut *collected.borrow_mut()))
}

/// Drops the registrations of every realm this thread has hosted.
///
/// A worker's realm ends on a thread that may host another realm later, and a
/// registration that outlives its isolate would leave the next realm's finalizer
/// map carrying an entry pointing at an object from a disposed heap. Registered
/// as a teardown hook by [`crate::AsyncWrap::install`].
pub(crate) fn clear_registrations() {
    REGISTRATIONS.with(|registrations| registrations.borrow_mut().clear());
    COLLECTED.with(|collected| collected.borrow_mut().clear());
}

impl Collected {
    /// The id this registration reported when it was created.
    pub(crate) fn async_id(&self) -> f64 {
        self.async_id
    }

    /// Whether `AsyncResource.emitDestroy()` already reported this id.
    ///
    /// `AsyncWrap::WeakCallback` (`src/async_wrap.cc:238-248`) emits unless the
    /// bag exists *and* its `destroyed` property is not exactly `false`. A bag
    /// whose read threw takes the same early return Node's does, because the
    /// alternative is emitting a destroy for a resource that is still being
    /// reported by its own `emitDestroy`.
    pub(crate) fn suppressed(&self, scope: &mut v8::PinScope<'_, '_>) -> bool {
        let Some(bag) = self.bag.as_ref() else {
            return false;
        };
        // A throwing getter is a real possibility: the bag is a user-visible
        // object only in the sense that the constructor made it, and a
        // `destroyed` accessor can be installed on it. Node's `ToLocal(&val)`
        // returning false takes the early return, and the `TryCatchScope` in
        // `WeakCallback` swallows the exception. A `TryCatch` here does the same
        // and is required rather than tidy: this body runs outside any
        // callback's own catch, so a pending exception would reach V8's default
        // reporter and print a stack from a hook nobody called.
        let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
        let scope = &mut try_catch.init();
        let Some(key) = v8::String::new(scope, DESTROYED) else {
            return true;
        };
        let bag = v8::Local::new(scope, bag);
        match bag.get(scope, key.into()) {
            Some(value) => !value.is_false(),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_v8() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        static PLATFORM: std::sync::OnceLock<v8::SharedRef<v8::Platform>> =
            std::sync::OnceLock::new();
        INIT.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            // Kept for the process: `initialize_platform` stores a raw pointer to
            // it, so dropping the last reference would leave V8 dereferencing
            // freed memory.
            let _ = PLATFORM.set(platform.clone());
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });
    }

    #[test]
    fn a_collected_registration_without_a_bag_is_not_suppressed() {
        // Promises register with two arguments, so their destroy has to be
        // reported from the collection alone.
        let suppressed = with_scope(|scope| {
            let collected = Collected {
                async_id: 7.0,
                bag: None,
            };
            collected.suppressed(scope)
        });
        assert!(!suppressed);
    }

    /// A scope with a context entered, which is what the property read needs.
    fn with_scope<R>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> R) -> R {
        init_v8();
        let mut isolate = v8::Isolate::new(Default::default());
        let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut storage.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        body(scope)
    }

    fn bag_with(value: bool) -> impl FnOnce(&mut v8::PinScope<'_, '_>) -> Collected {
        move |scope| {
            let bag = v8::Object::new(scope);
            let key = v8::String::new(scope, DESTROYED).expect("a property name");
            let flag: v8::Local<v8::Value> = v8::Boolean::new(scope, value).into();
            bag.set(scope, key.into(), flag);
            Collected {
                async_id: 7.0,
                bag: Some(v8::Global::new(scope.as_ref(), bag)),
            }
        }
    }

    #[test]
    fn a_bag_whose_destroyed_flag_is_set_suppresses_the_hook() {
        // `AsyncResource.emitDestroy()` writes `bag.destroyed = true`, which is
        // what stops the collection path from reporting the id a second time.
        let suppressed = with_scope(|scope| {
            let collected = bag_with(true)(scope);
            collected.suppressed(scope)
        });
        assert!(suppressed);
    }

    #[test]
    fn a_bag_that_is_still_alive_does_not_suppress_the_hook() {
        // The `{ destroyed: false }` the constructor allocates is the ordinary
        // case, and it must emit: this is the bug the whole module exists for.
        let suppressed = with_scope(|scope| {
            let collected = bag_with(false)(scope);
            collected.suppressed(scope)
        });
        assert!(!suppressed);
    }

    #[test]
    fn the_registry_is_empty_before_anything_registers() {
        // The table is a thread-local, so a test that leaves an entry behind
        // would make a later registration's `position` find the wrong one.
        clear_registrations();
        assert!(take_collected().is_empty());
    }
}
