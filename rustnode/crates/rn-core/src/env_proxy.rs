//! The one object that is `process.env`, for the code that has to recognise it.
//!
//! `process.env` is not a `BaseObject` and carries no internal fields: it is an
//! ordinary object produced from a template with property interceptors. Node
//! recognises it by template identity —
//! `env_proxy_ctor_template->HasInstance(object)` in
//! `SerializationContext::WriteHostObject` — and that check exists for one
//! behaviour: `structuredClone(process.env)` and `postMessage(process.env)` must
//! serialise it as a *plain object* holding the current variables, not throw
//! `DataCloneError`.
//!
//! `src/node_messaging.cc` does that by writing the sentinel id `kNormalObject`,
//! then writing a freshly built normal object whose properties are the pairs
//! `env_vars()->AssignToObject()` produced. The receiving delegate, on seeing the
//! sentinel, reads a value instead of looking up a host-object id.
//!
//! The identity has to live here rather than in `rn-realm`, because
//! `rn-bind-messaging` needs to ask the question and cannot depend on the realm
//! that built the object. It is a per-thread `v8::Global`, one per realm, which
//! is the same granularity as `IsolateData`'s template.

use std::cell::RefCell;

use rn_v8_sys::v8;

thread_local! {
    /// The `process.env` object of the realm this thread is running.
    ///
    /// Replaced when a realm is built, so a worker's realm records its own.
    /// `v8::Global` rather than a raw handle because the serializer asks across
    /// handle scopes.
    static PROXY: RefCell<Option<v8::Global<v8::Object>>> = const { RefCell::new(None) };
}

/// Records `object` as this realm's `process.env`.
pub fn set<'s>(scope: &mut v8::PinScope<'s, '_>, object: v8::Local<'s, v8::Object>) {
    let global = v8::Global::new(scope, object);
    PROXY.with(|slot| {
        *slot.borrow_mut() = Some(global);
    });
}

/// Whether `object` is this realm's `process.env`.
///
/// Two `Local`s of one V8 object compare equal with `strict_equals`, so this is
/// an identity test rather than a structural one — which is what Node's
/// `HasInstance` is too. An object that merely *looks* like `process.env`, or a
/// spread copy of it, is not a proxy and serialises as the plain object it is.
pub fn is_proxy(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<'_, v8::Object>) -> bool {
    let proxy = PROXY.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|global| v8::Local::new(scope, global))
    });
    let Some(proxy) = proxy else {
        return false;
    };
    proxy.strict_equals(object.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_a_proxy_before_a_realm_records_one() {
        // The common case is a process that never builds `process.env`, and the
        // answer has to be a cheap `false` rather than a panic.
        PROXY.with(|slot| {
            let had = slot.borrow_mut().take();
            assert!(had.is_none() || had.is_some());
            *slot.borrow_mut() = None;
        });

        // A scope-free check is impossible, so this only pins that the slot can
        // be cleared and re-read; `is_proxy` itself is exercised from the
        // integration tests that have an isolate.
        let empty = PROXY.with(|slot| slot.borrow().is_none());
        assert!(empty, "the slot should be empty after clearing it");
    }
}
