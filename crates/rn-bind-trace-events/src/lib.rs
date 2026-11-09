//! `internalBinding('trace_events')` for rustnode.
//!
//! `lib/internal/trace_events.js` is loaded by `internal/errors`, which is
//! loaded by the realm bootstrap, so this namespace is on the critical path for
//! `require('util')` and `require('assert')` even though tracing is off by
//! default.
//!
//! # Tracing off is the honest answer, not a stub
//!
//! Node exposes one byte per trace category saying whether that category is
//! enabled, and the JavaScript layer reads it on every `trace()` call to skip
//! building the message. rustnode has no tracing controller, so every category
//! is disabled: `getCategoryEnabledBuffer` returns a real one-byte
//! `Uint8Array` holding `0`, and `isTraceCategoryEnabled` returns `false`. Both
//! are true statements about this process, which is why they are implemented
//! rather than deferred.
//!
//! What is deferred is `CategorySet`, which asks a tracing agent to enable or
//! disable categories. There is no agent to ask.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/trace_events.json`.
///
/// `CategorySet` is not here: it is deferred, and a member that is both
/// installed and declared deferred would be reported as a mismatch.
pub const MEMBERS: &[&str] = &[
    "getCategoryEnabledBuffer",
    "getEnabledCategories",
    "hasAgent",
    "isTraceCategoryEnabled",
    "setTraceCategoryStateUpdateHandler",
    "trace",
    "usePerfetto",
];

/// Members this build does not install yet.
pub const DEFERRED: &[(&str, &str)] = &[(
    "CategorySet",
    "asks a tracing agent to enable or disable categories; there is no agent",
)];

thread_local! {
    /// One flag byte per category, shared with the JavaScript layer.
    ///
    /// Node's buffer points straight at the tracing controller's own flag, so
    /// both sides see one byte. There is no controller here, so the map holds
    /// buffers this binding allocated and they stay zero.
    static CATEGORY_BUFFERS: RefCell<BTreeMap<String, v8::Global<v8::Uint8Array>>> =
        const { RefCell::new(BTreeMap::new()) };
    /// The state-update handler installed by `internal/trace_events.js`.
    static STATE_UPDATE_HANDLER: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };
}

pub struct TraceEvents;

impl BindingModule for TraceEvents {
    fn namespace(&self) -> &'static str {
        "trace_events"
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
        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 7] = [
            ("hasAgent", function(scope, "hasAgent", has_agent)?),
            (
                "getEnabledCategories",
                function(scope, "getEnabledCategories", get_enabled_categories)?,
            ),
            (
                "getCategoryEnabledBuffer",
                function(
                    scope,
                    "getCategoryEnabledBuffer",
                    get_category_enabled_buffer,
                )?,
            ),
            (
                "isTraceCategoryEnabled",
                function(scope, "isTraceCategoryEnabled", is_trace_category_enabled)?,
            ),
            ("trace", function(scope, "trace", trace)?),
            (
                "setTraceCategoryStateUpdateHandler",
                function(
                    scope,
                    "setTraceCategoryStateUpdateHandler",
                    set_trace_category_state_update_handler,
                )?,
            ),
            // rustnode does not link Perfetto, which is what Node's
            // `V8_USE_PERFETTO` build reports here.
            ("usePerfetto", v8::Boolean::new(scope, false).into()),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(TraceEvents);
}

fn has_agent(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // No tracing agent is attached, so there is nothing that could enable a
    // category at runtime.
    rv.set(v8::Boolean::new(scope, false).into());
}

fn get_enabled_categories(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // A comma-separated list of enabled category names, empty when tracing is
    // off, which is always here.
    match v8::String::new(scope, "") {
        Some(text) => rv.set(text.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn get_category_enabled_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(name) = args.get(0).to_string(scope) else {
        return;
    };
    let name = name.to_rust_string_lossy(scope);

    // One buffer per category, so repeated calls for the same category return
    // the same array. The JavaScript layer caches the result, but a test may
    // call twice and expect identity.
    let existing = CATEGORY_BUFFERS.with(|buffers| {
        buffers
            .borrow()
            .get(&name)
            .map(|buffer| v8::Local::new(scope, buffer))
    });
    if let Some(existing) = existing {
        rv.set(existing.into());
        return;
    }

    let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(vec![0u8].into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let Some(array) = v8::Uint8Array::new(scope, buffer, 0, 1) else {
        return;
    };
    CATEGORY_BUFFERS.with(|buffers| {
        buffers
            .borrow_mut()
            .insert(name, v8::Global::new(scope, array));
    });
    rv.set(array.into());
}

fn is_trace_category_enabled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `isTraceCategoryEnabled(category, flagBuffer?)`. The flag buffer, when
    // given, is the authority; it is always zero here. Reading it rather than
    // hardcoding false keeps the two members consistent.
    let flag = match v8::Local::<v8::Uint8Array>::try_from(args.get(1)) {
        Ok(buffer) => buffer
            .get_index(scope, 0)
            .and_then(|value| value.uint32_value(scope))
            .is_some_and(|value| value != 0),
        Err(_) => false,
    };
    rv.set(v8::Boolean::new(scope, flag).into());
}

fn trace(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // The synchronous trace intrinsic. With no tracing controller there is
    // nowhere for the event to go, and the JavaScript layer already skipped
    // building the message by reading the zero flag first.
    let _ = scope;
}

fn set_trace_category_state_update_handler(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let handler = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|handler| v8::Global::new(scope, handler));
    STATE_UPDATE_HANDLER.with(|slot| *slot.borrow_mut() = handler);
}

/// The category state-update handler, if one was installed.
pub fn state_update_handler<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    STATE_UPDATE_HANDLER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|handler| v8::Local::new(scope, handler))
    })
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope,
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
    use super::*;

    #[test]
    fn the_member_and_deferral_lists_do_not_overlap() {
        // A member in both lists would be installed and reported missing at the
        // same time, which the contract check would then call a mismatch.
        for (deferred, _) in DEFERRED {
            assert!(
                !MEMBERS.contains(deferred),
                "{deferred} cannot be both installed and deferred"
            );
        }
    }

    #[test]
    fn every_contract_member_is_accounted_for() {
        // 8 recorded members: 7 installed plus CategorySet deferred.
        assert_eq!(MEMBERS.len() + DEFERRED.len(), 8);
        assert!(MEMBERS.contains(&"trace"));
        assert!(MEMBERS.contains(&"usePerfetto"));
    }
}
