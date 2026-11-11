//! The `AsyncWrap` state a wrapped handle owns.
//!
//! Node builds every handle on `AsyncWrap`, which owns three things: the id of
//! the resource, the id that triggered it, and the provider kind that names it.
//! `AsyncReset` is what re-issues all three, and it is the method
//! `lib/internal/http/agent.js::asyncResetHandle` calls on a pooled socket.
//!
//! # Why the state is here and the behaviour is not
//!
//! The state is plain data, so `rn-uv` can put it in a `StreamState` without
//! depending on a binding crate. The behaviour needs V8 (it emits `init`), so it
//! lives in `rn-bind-async-wrap` and `rn-bind-tcp-wrap` calls it. Keeping the
//! split at "data in the kernel, hooks in the binding" is the same rule the rest
//! of the kernel follows.

/// `AsyncWrap::kInvalidAsyncId`.
pub const INVALID_ASYNC_ID: f64 = -1.0;

/// `PROVIDER_NONE` in `src/async_wrap.h`, which `GetProviderType` reports before
/// it unwraps.
pub const PROVIDER_NONE: u32 = 0;

/// `PROVIDER_TCPSERVERWRAP`: a listening socket.
pub const PROVIDER_TCPSERVERWRAP: u32 = 41;
/// `PROVIDER_TCPWRAP`: a connected socket.
pub const PROVIDER_TCPWRAP: u32 = 42;
/// `PROVIDER_TTYWRAP`: a terminal.
pub const PROVIDER_TTYWRAP: u32 = 43;
/// `PROVIDER_PIPECONNECTWRAP`: a pipe connect request.
pub const PROVIDER_PIPECONNECTWRAP: u32 = 25;
/// `PROVIDER_PIPESERVERWRAP`: a listening pipe.
pub const PROVIDER_PIPESERVERWRAP: u32 = 26;
/// `PROVIDER_PIPEWRAP`: a connected pipe or an IPC channel.
pub const PROVIDER_PIPEWRAP: u32 = 27;

/// The `AsyncWrap` fields of a wrapped handle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AsyncWrapState {
    /// `AsyncWrap::async_id_`, which starts invalid.
    pub async_id: f64,
    /// `AsyncWrap::trigger_async_id_`.
    pub trigger_async_id: f64,
    /// `AsyncWrap::provider_type_`.
    pub provider: u32,
}

impl AsyncWrapState {
    /// An instance that has not been reset yet, matching the
    /// `AsyncWrap(env, object)` constructor `src/async_wrap.h` describes as
    /// "user is responsible to call set_provider_type() and AsyncReset()".
    pub const fn uninitialised(provider: u32) -> Self {
        Self {
            async_id: INVALID_ASYNC_ID,
            trigger_async_id: INVALID_ASYNC_ID,
            provider,
        }
    }

    /// The id `getAsyncId()` reports.
    pub const fn async_id(&self) -> f64 {
        self.async_id
    }

    /// The provider `getProviderType()` reports.
    pub const fn provider(&self) -> u32 {
        self.provider
    }
}

/// Async id space mirroring Node's `AsyncWrap` so `async_hooks` ordering is
/// preserved bit for bit.
#[derive(Default)]
pub struct AsyncIds {
    next: u64,
}

impl AsyncIds {
    pub fn new() -> Self {
        Self { next: 1 }
    }
    pub fn next_id(&mut self) -> u64 {
        let id = self.next;
        self.next += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_instance_is_invalid_and_keeps_its_provider() {
        // `AsyncWrap(env, object, provider)` assigns the provider *before* the
        // reset, so `getProviderType()` is answerable on an id-less handle. That
        // is what `asyncResetHandle` reads to build its `ReusedHandle`.
        let state = AsyncWrapState::uninitialised(PROVIDER_TCPWRAP);
        assert_eq!(state.async_id(), INVALID_ASYNC_ID);
        assert_eq!(state.trigger_async_id, INVALID_ASYNC_ID);
        assert_eq!(state.provider(), PROVIDER_TCPWRAP);
        assert_eq!(
            AsyncWrapState::uninitialised(PROVIDER_TCPSERVERWRAP).provider(),
            PROVIDER_TCPSERVERWRAP
        );
    }

    #[test]
    fn the_provider_ids_match_the_async_wrap_table() {
        // These two are the only providers this crate names, and they are the
        // ones `src/tcp_wrap.cc` selects between. A drift here would label every
        // socket with the wrong kind while still looking like a working id.
        assert_eq!(PROVIDER_TCPSERVERWRAP, 41);
        assert_eq!(PROVIDER_TCPWRAP, 42);
        assert_eq!(PROVIDER_NONE, 0);
    }
}
