//! `internalBinding('diagnostics_channel')` for rustnode.
//!
//! `lib/diagnostics_channel.js` owns the channel objects, the message
//! publishing and the weak-reference bookkeeping. This namespace is the native
//! side of one thing: a per-channel subscriber count that native code can read
//! cheaply, so a hot path can skip building a message nobody will hear.
//!
//! The count lives in `subscribers`, a `Uint32Array` the JavaScript side
//! indexes by channel index. Node grows it by doubling and re-exposing it; so
//! does this, because the JavaScript layer caches the property and would
//! otherwise keep writing into a detached array.
//!
//! `notifyChannelActive` and `notifyChannelInactive` reach a native observer the
//! embedder registers. rustnode registers none yet, so they are accepted and
//! ignored, which is what Node does with an empty observer table.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/diagnostics_channel.json`.
pub const MEMBERS: &[&str] = &[
    "linkNativeChannel",
    "notifyChannelActive",
    "notifyChannelInactive",
    "subscribers",
];

/// `BindingData::kInitialChannelCapacity` in `node_diagnostics_channel.cc`.
pub const INITIAL_CHANNEL_CAPACITY: usize = 32;

thread_local! {
    /// The channel index allocator and the counts behind `subscribers`.
    static CHANNELS: RefCell<Channels> = const { RefCell::new(Channels {
        subscribers: None,
        counts: Vec::new(),
        indices: BTreeMap::new(),
        next_index: 0,
    }) };
    /// The callback `linkNativeChannel` was given.
    static LINK_CALLBACK: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };
    /// Status observers registered by a native embedder, keyed by channel index.
    static STATUS_CALLBACKS: RefCell<BTreeMap<u32, v8::Global<v8::Function>>> =
        const { RefCell::new(BTreeMap::new()) };
}

#[derive(Default)]
struct Channels {
    /// The `Uint32Array` the JavaScript layer holds.
    subscribers: Option<v8::Global<v8::Uint32Array>>,
    /// Subscriber count per channel index.
    counts: Vec<u32>,
    /// Channel name to index, so a name maps to one slot.
    indices: BTreeMap<String, u32>,
    /// The next index to hand out.
    next_index: u32,
}

pub struct DiagnosticsChannel;

impl BindingModule for DiagnosticsChannel {
    fn namespace(&self) -> &'static str {
        "diagnostics_channel"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let array = create_subscribers(scope, INITIAL_CHANNEL_CAPACITY)?;
        CHANNELS.with(|channels| {
            let mut channels = channels.borrow_mut();
            channels.counts = vec![0; INITIAL_CHANNEL_CAPACITY];
            channels.subscribers = Some(v8::Global::new(scope, array));
        });

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 4] = [
            ("subscribers", array.into()),
            (
                "linkNativeChannel",
                function(scope, "linkNativeChannel", link_native_channel)?,
            ),
            (
                "notifyChannelActive",
                function(scope, "notifyChannelActive", notify_channel_active)?,
            ),
            (
                "notifyChannelInactive",
                function(scope, "notifyChannelInactive", notify_channel_inactive)?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(DiagnosticsChannel);
}

fn create_subscribers<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    length: usize,
) -> Result<v8::Local<'s, v8::Uint32Array>, String> {
    let buffer = v8::ArrayBuffer::new(scope, length * 4);
    v8::Uint32Array::new(scope, buffer, 0, length)
        .ok_or_else(|| "cannot allocate the diagnostics_channel subscribers array".to_string())
}

fn link_native_channel(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        throw(scope, "linkNativeChannel expects a function");
        return;
    };
    let callback = v8::Global::new(scope, callback);
    LINK_CALLBACK.with(|slot| *slot.borrow_mut() = Some(callback));
}

fn notify_channel_active(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    notify_status(scope, args, true);
}

fn notify_channel_inactive(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    notify_status(scope, args, false);
}

fn notify_status(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    active: bool,
) {
    let Some(index) = args.get(0).uint32_value(scope) else {
        return;
    };
    // A native observer is optional: with none registered, the notification is
    // a no-op rather than an error.
    let callback = STATUS_CALLBACKS.with(|callbacks| {
        callbacks
            .borrow()
            .get(&index)
            .map(|callback| v8::Local::new(scope, callback))
    });
    if let Some(callback) = callback {
        let value = v8::Boolean::new(scope, active);
        let _ = callback.call(scope, v8::undefined(scope).into(), &[value.into()]);
    }
}

/// Registers a native observer for one channel's active state.
///
/// Node exposes this only to embedders; rustnode keeps it public so a later
/// native subsystem can subscribe without reworking the binding.
pub fn observe_channel(scope: &mut v8::PinScope, index: u32, callback: v8::Global<v8::Function>) {
    let _ = scope;
    STATUS_CALLBACKS.with(|callbacks| {
        callbacks.borrow_mut().insert(index, callback);
    });
}

/// The subscriber count for a channel index, as the shared array holds it.
pub fn subscriber_count(index: usize) -> u32 {
    CHANNELS.with(|channels| channels.borrow().counts.get(index).copied().unwrap_or(0))
}

/// The index for a channel name, allocating one when the name is new.
///
/// This is the native mirror of what `linkNativeChannel` drives from the
/// JavaScript side; the two share one allocator so an index never collides.
pub fn channel_index(name: &str) -> u32 {
    CHANNELS.with(|channels| {
        let mut channels = channels.borrow_mut();
        if let Some(index) = channels.indices.get(name) {
            return *index;
        }
        let index = channels.next_index;
        channels.next_index += 1;
        channels.indices.insert(name.to_string(), index);
        if channels.counts.len() <= index as usize {
            channels.counts.resize(index as usize + 1, 0);
        }
        index
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

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_keeps_one_index() {
        CHANNELS.with(|channels| *channels.borrow_mut() = Channels::default());
        let first = channel_index("alpha");
        let second = channel_index("alpha");
        assert_eq!(first, second);
        assert_eq!(channel_index("beta"), first + 1);
    }

    #[test]
    fn an_unknown_index_reports_zero_subscribers() {
        CHANNELS.with(|channels| *channels.borrow_mut() = Channels::default());
        assert_eq!(subscriber_count(999), 0);
    }
}
