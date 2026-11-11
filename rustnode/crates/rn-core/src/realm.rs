//! The binding registry a realm is bootstrapped against.
//!
//! # Why this is not a parameter
//!
//! `internalBinding(name)` is installed by `realm.js` as a plain function that
//! `lib/**` closes over, and every V8 callback behind it has a fixed argument
//! shape. A V8 `FunctionCallback` cannot capture a value: its data slot holds a
//! raw pointer and nothing else. Node solves this with `Environment`, reached
//! from the isolate; rustnode reaches the registry the same way, through a
//! thread-local, because one thread hosts exactly one realm at a time.
//!
//! # Why per thread and not one leaked registry for the process
//!
//! A `BindingRegistry` caches the object each namespace produced
//! (`BindingRegistry::install`), and those objects are V8 handles belonging to
//! one isolate. Sharing a registry across two isolates would hand the second
//! one handles from the first, which is undefined behaviour rather than a
//! wrong answer. Each realm therefore gets its own registry, and this module is
//! how the callbacks inside that realm find the right one.
//!
//! # Lifetime
//!
//! [`install`] takes ownership and returns a guard. The registry lives exactly
//! as long as the guard, which is the realm's scope, so nothing has to be
//! leaked for a callback to stay valid — which matters because a worker thread
//! is created and destroyed once per `new Worker()`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::binding::BindingRegistry;

thread_local! {
    /// The registry for the realm on this thread, while one is installed.
    ///
    /// `Rc` rather than `Box` so the guard can put back whatever was there
    /// before. A worker thread installs one at the start of its realm and drops
    /// it at the end; the main thread does the same.
    static REGISTRY: RefCell<Option<Rc<BindingRegistry>>> = const { RefCell::new(None) };
}

/// Registers how to build a new binding registry.
///
/// A worker thread runs in a second isolate and needs its own registry, because
/// the object each namespace produces is a V8 handle belonging to one isolate.
/// `rn-bindings` is the crate that knows how to assemble one, and it depends on
/// every binding crate — including this one — so a worker crate cannot call it
/// without a cycle. The CLI installs the factory here at startup instead, which
/// is the same arrangement `native_immediates` uses for its wake-up.
///
/// This is process-global and not thread-local on purpose: it is a *function
/// pointer* with no per-thread state, and the whole point is that a thread that
/// did not install it — a worker — can still call it.
pub fn set_registry_factory(factory: fn() -> BindingRegistry) {
    let _ = FACTORY.set(factory);
}

/// Builds a registry for a new realm, if a factory was installed.
///
/// Returns `Err` rather than `None` so the caller can say *why* a worker could
/// not start, which is more useful than a silent failure at the first binding.
pub fn build_registry() -> Result<BindingRegistry, String> {
    let factory = FACTORY.get().ok_or(
        "no binding-registry factory is installed; a worker cannot bootstrap its own realm",
    )?;
    Ok(factory())
}

/// The factory, set once at startup.
///
/// `OnceLock` rather than a `Mutex<Option<_>>`: it is written exactly once before
/// any worker exists, so there is nothing to lock and a second write is a bug
/// worth ignoring rather than a state to manage.
static FACTORY: std::sync::OnceLock<fn() -> BindingRegistry> = std::sync::OnceLock::new();

/// Makes `registry` the one `internalBinding` resolves against on this thread.
///
/// The returned guard keeps it installed and restores the previous value when
/// dropped, so a nested scope cannot leave a stale registry behind for the next
/// realm on the same thread.
pub fn install(registry: BindingRegistry) -> RegistryGuard {
    let previous = REGISTRY.with(|slot| slot.borrow_mut().replace(Rc::new(registry)));
    RegistryGuard { previous }
}
/// The registry installed on this thread, if a realm is running.
pub fn installed() -> Option<Rc<BindingRegistry>> {
    REGISTRY.with(|slot| slot.borrow().clone())
}

/// Restores the previous registry when the realm ends.
pub struct RegistryGuard {
    previous: Option<Rc<BindingRegistry>>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        REGISTRY.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installing_makes_a_registry_visible_and_dropping_restores_the_previous_one() {
        assert!(installed().is_none(), "a fresh thread has no realm");

        let outer = install(BindingRegistry::new());
        let first = installed().expect("the outer registry is installed");
        assert!(first.names().next().is_none(), "it is empty");

        {
            let mut registry = BindingRegistry::new();
            registry.register(crate::Namespace::empty("probe"));
            let _inner = install(registry);
            let inner = installed().expect("the inner registry is installed");
            assert_eq!(inner.names().collect::<Vec<_>>(), vec!["probe"]);
        }

        let after = installed().expect("the outer registry came back");
        assert!(
            Rc::ptr_eq(&first, &after),
            "dropping the guard must restore the identical registry, not a copy"
        );
        drop(outer);
        assert!(
            installed().is_none(),
            "the last guard leaves nothing behind"
        );
    }
}
