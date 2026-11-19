//! The `AsyncWrap` identity of a `MessagePort`.
//!
//! `MessagePort(env, context, wrap)` is a `HandleWrap` over
//! `AsyncWrap(env, wrap, PROVIDER_MESSAGEPORT)` (`src/node_messaging.cc:667-673`),
//! and `OnMessage` dispatches each delivered message through
//! `MakeCallback(emitMessage_string, ...)` (`:1053`). So a port is an async
//! resource from construction, every delivered message is one `before`/`after`
//! pair on it, and `close` queues its `destroy`.
//!
//! # Why the ids are not on the object
//!
//! `MessagePort`'s one internal field already holds the `PortSlot` pointer, and
//! `PortInner` is shared by the delivery queue, the sibling group and the
//! transfer path — none of which need the ids. They are per *object*, so they
//! live in the slot beside the port.

use rn_v8_sys::v8;

/// The pair `AsyncWrap` keeps: the resource's id and the id that triggered it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AsyncIds {
    /// `AsyncWrap::async_id_`.
    pub async_id: f64,
    /// `AsyncWrap::trigger_async_id_`.
    pub trigger_async_id: f64,
}

impl AsyncIds {
    /// The `AsyncWrap` context `MakeCallback` pushes.
    pub fn context(self) -> rn_core::callback_scope::AsyncContext {
        rn_core::callback_scope::AsyncContext {
            async_id: self.async_id,
            trigger_async_id: self.trigger_async_id,
        }
    }
}

/// `MessagePort(env, context, wrap) : AsyncWrap(..., PROVIDER_MESSAGEPORT)`.
///
/// Emits `init` once, at construction, which is what Node does before
/// `uv_async_init` even runs. Returns `None` in the bootstrap state where no
/// `async_wrap` binding has installed.
pub fn begin(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    _inner: &crate::port::PortInner,
) -> Option<AsyncIds> {
    let (async_id, trigger_async_id) = rn_bind_async_wrap::emit_init_for_new_resource(
        scope,
        object,
        rn_core::async_wrap::PROVIDER_MESSAGEPORT,
    )?;
    Some(AsyncIds {
        async_id,
        trigger_async_id,
    })
}
