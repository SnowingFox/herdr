//! `internalBinding('signal_wrap')` for rustnode.
//!
//! One member, `Signal`, which `lib/internal/process/signal.js` constructs the
//! first time a JavaScript listener is added for a real signal. Node's
//! `src/signal_wrap.cc` is a `HandleWrap` around a `uv_signal_t`.
//!
//! # Why the whole module needs this
//!
//! `lib/internal/process/signal.js` is loaded from `pre_execution`, and
//! `process.on('SIGINT')`-style listeners are how Node's own tests install
//! cleanup handlers. The binding is reached lazily, so a process that never
//! adds a signal listener never touches it — which is why `require('http')`
//! could work while `test-async-hooks-http-parser-destroy.js` threw
//! `internalBinding('signal_wrap'): the namespace has no Rust implementation
//! yet` from inside a test helper.
//!
//! # Contract
//!
//! `lib/internal/process/signal.js` requires exactly this much:
//!
//! * `new Signal()` — constructible with no arguments.
//! * `wrap.unref()` — inherited from `HandleWrap`. A signal watcher must not
//!   keep the loop alive on its own, which is why the JS layer calls this
//!   immediately after construction.
//! * `wrap.onsignal = fn` — the callback libuv invokes with the signal number.
//! * `wrap.start(signum)` — returns `0` or a negative libuv error the caller
//!   turns into an `ErrnoException` naming `uv_signal_start`.
//! * `wrap.close()` — inherited from `HandleWrap`.
//!
//! # `handled_signals`, and why it is not here
//!
//! Node keeps a process-wide count of the signals that have a JavaScript
//! handler, because `Node::Kill` and the inspector both ask whether one exists.
//! rustnode has no caller for that question, so a count nobody reads would be
//! dead state that looks like a guarantee. The count is declared as deferred
//! rather than silently omitted, and `tools/deferred-reach.py` keeps that
//! honest: nothing in `lib/**` calls it.

mod handle;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/signal_wrap.json`.
pub const MEMBERS: &[&str] = &["Signal"];

/// Members this namespace needs but cannot install yet.
///
/// Empty: the single recorded member is installed. The process-wide handler
/// count is state no `lib/**` caller reads, so it is not a member at all rather
/// than an absent one.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('signal_wrap')`.
pub struct SignalWrap;

impl BindingModule for SignalWrap {
    fn namespace(&self) -> &'static str {
        "signal_wrap"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        // Signal delivery runs from inside `uv_run`, which needs a way back
        // into V8.
        rn_uv::callback::remember_context(scope);

        let object = v8::Object::new(scope);
        let constructor = handle::constructor(scope)?;
        set(scope, object, "Signal", constructor)?;
        Ok(object)
    }
}

/// Registers the `signal_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(SignalWrap);
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use rn_core::BindingModule;

    use super::*;

    #[test]
    fn the_member_list_is_the_contract() {
        assert_eq!(MEMBERS, &["Signal"]);
        assert_eq!(SignalWrap.members(), MEMBERS);
        assert!(SignalWrap.deferred().is_empty());
    }

    #[test]
    fn every_contract_member_is_installed() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/signal_wrap.json"))
                .expect("the signal_wrap contract parses");
        let recorded = contract["members"]
            .as_object()
            .expect("the contract has a members object");
        assert_eq!(recorded.len(), MEMBERS.len());
        for member in recorded.keys() {
            assert!(
                MEMBERS.contains(&member.as_str()),
                "{member} is in the contract but not installed"
            );
        }
    }
}
