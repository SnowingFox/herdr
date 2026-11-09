//! `internalBinding('cares_wrap')` for rustnode.
//!
//! `lib/dns.js`, `lib/net.js`, `lib/tls.js` and `lib/internal/dns/**` are
//! unchanged Node code, so this namespace's contract is the one
//! `src/cares_wrap.cc` defines.
//!
//! # The backend decision
//!
//! Node's implementation is c-ares. This crate is not: forward and reverse
//! lookups go through `uv_getaddrinfo`/`uv_getnameinfo`'s *semantics* — which are
//! `getaddrinfo(3)` and `getnameinfo(3)` on the libuv threadpool — and the
//! `ChannelWrap` query methods speak DNS over UDP directly. The trade is stated
//! in the README and summarised here:
//!
//! * `getaddrinfo`/`getnameinfo` are `libc` calls, so the answers are the
//!   system resolver's answers. That is what `dns.lookup()` promises, and it is
//!   why `localhost` resolves identically to Node on the same machine.
//! * The `query*` methods need the DNS wire protocol, which c-ares provides.
//!   Linking it would mean shipping a second C library on every platform for a
//!   protocol this crate implements in `channel.rs`; the record shapes and error
//!   codes are the part that must match, and those are pinned by tests.
//!
//! # Asynchrony
//!
//! Node runs both families of call on the threadpool, so the JavaScript that
//! started a lookup always runs to completion first. rustnode resolves inline
//! and defers the *completion* onto a microtask (`deliver.rs`), which preserves
//! the ordering `lib/dns.js` depends on without an event loop. The cost is that a
//! slow resolver blocks instead of running in the background.

mod channel;
mod deliver;
mod errors;
mod install;
mod ip;
mod sys;

#[cfg(test)]
mod testsupport;

pub use install::{CaresWrap, MEMBERS};

/// Registers the `cares_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(CaresWrap);
}
