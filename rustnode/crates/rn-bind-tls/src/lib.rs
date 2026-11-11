//! `internalBinding('tls_wrap')` for rustnode.
//!
//! `src/crypto/crypto_tls.cc` (2529 lines) and `crypto_tls_certificates.cc` are
//! the translation units this mirrors. At the pinned revision
//! (`f344e7f552e3656bd37517151c5dc87d22b33771`) `src/tls_wrap.cc` does not exist:
//! Node 28 moved the whole TLS layer under `src/crypto/`. The *binding name* is
//! unchanged — `NODE_BINDING_CONTEXT_AWARE_INTERNAL(tls_wrap, ...)` is at
//! `crypto_tls.cc:2527` — so `internalBinding('tls_wrap')` still finds this.
//!
//! # What the JavaScript does with this namespace
//!
//! `lib/internal/tls/wrap.js` is the only consumer with a load-bearing use:
//!
//! ```js
//! const tls_wrap = internalBinding('tls_wrap');            // :61
//! tls_wrap.TLSWrap.prototype.close = function close(cb) {...}; // :773
//! const res = tls_wrap.wrap(handle, context.context,      // :836
//!                           !!options.isServer, wrapHasActiveWriteFromPrevOwner);
//! ```
//!
//! `tls_wrap.TLSWrap` is read at *module scope*, so the class has to exist for
//! `require('tls')` to complete at all. That is the negative control this crate
//! replaces: before it existed, `require('tls')` threw
//! `internalBinding('tls_wrap'): the namespace has no Rust implementation yet`.
//!
//! # What this landing covers
//!
//! The namespace, the `TLSWrap` class with its full 42-method prototype plus the
//! `StreamBase` surface, and `wrap()` — which produces a real `SSL`, with a real
//! BIO pair, created from a real `SecureContext`. Every method that needs the
//! handshake state machine throws `ERR_TLS_NOT_IMPLEMENTED` naming the increment
//! that adds it, rather than returning a plausible value.
//!
//! # The four teardown rules
//!
//! These are the plan's §4 R1–R4, and each has one place that upholds it:
//!
//! * **R1 — the `SSL` owns both `BIO`s.** [`ssl::Ssl`] is the only type that
//!   frees the `SSL`, and `SSL_free` releases both BIOs. There is no `BIO_free`
//!   in production code. [`bio::Pair`] is consumed by `attach`, so there is no
//!   state in which this crate holds a BIO it believes it owns.
//! * **R2 — no V8 call while holding a `&mut` to the wrap state.** Every entry
//!   point uses [`state::with_state`], which scopes the borrow to a closure, and
//!   takes `try_borrow_mut` so a re-entrant call is reported rather than
//!   aborting. Teardown returns what it could not do ([`state::Destroyed`]) for
//!   the caller to complete after the borrow ends.
//! * **R3 — a pending write must be completed, not dropped.** [`state::WrapState::destroy`]
//!   hands the queued write and shutdown back, and `destroySSL` completes both
//!   with `UV_ECANCELED` through `rn_bind_stream_wrap::report_completion`.
//! * **R4 — the loop must never be left busy.** The wrap holds no libuv handle of
//!   its own and no `uv_ref`; the listener is removed on teardown so the wrapped
//!   stream stops calling into it. Deferred work goes through
//!   `rn_core::native_immediates`, which is `Environment::SetImmediate`.
//!
//! # The `SSL_CTX` is borrowed, never owned
//!
//! [`wrap::install`]'s `wrap()` resolves the `SSL_CTX` from the `SecureContext`
//! object through `rn_bind_secure_context::ssl_ctx_of` and roots that object in
//! the wrap's state. `SSL_new` takes its own reference on the `SSL_CTX` and
//! `SSL_free` releases it, so the free path stays `SecureContext::close()` and
//! that crate's finalizer — one owner, one lifetime.
//!
//! # Deferred, and why
//!
//! Nothing is deferred at the namespace level: all five members are installed.
//! The *prototype* methods that need the state machine throw rather than being
//! absent, and [`methods::pending`] is the list with the increment for each. See
//! that module for why throwing beats a stub that returns `undefined`.

pub mod bio;
pub mod callback;
pub mod cycle;
pub mod error;
pub mod ffi_extra;
pub mod listener;
pub mod methods;
pub mod peer_cert;
pub mod ssl;
pub mod state;
pub mod stream;
pub mod wrap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// `internalBinding('tls_wrap')`.
pub struct TlsWrap;

impl BindingModule for TlsWrap {
    fn namespace(&self) -> &'static str {
        "tls_wrap"
    }

    fn members(&self) -> &'static [&'static str] {
        wrap::MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        wrap::install(scope, ctx)
    }
}

/// Members this namespace needs but does not install.
///
/// Empty: `TLSWrap::Initialize` installs five members and all five are here. The
/// gaps that remain are prototype *methods*, and those exist and throw — which is
/// a different thing from a deferral, and is documented in [`methods::pending`]
/// rather than here. A deferred method would be absent and a caller would get
/// `TypeError: not a function`; a throwing one names the increment.
pub const DEFERRED: &[(&str, &str)] = &[];

/// Registers the `tls_wrap` namespace with the runtime.
///
/// The name is `register` because `tools/regen-bindings.sh` discovers a namespace
/// provider by that declaration. Every helper in this crate is named something
/// else, per `AGENTS.md`'s warning about the matcher.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(TlsWrap);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The namespace name is the binding id Node uses, not a UI-surface name.
    #[test]
    fn the_namespace_is_node_s_binding_id() {
        assert_eq!(TlsWrap.namespace(), "tls_wrap");
    }

    /// Nothing is deferred at the namespace level, which is what makes the
    /// remaining gaps a *throwing* surface rather than a missing one.
    #[test]
    fn nothing_is_deferred() {
        assert!(TlsWrap.deferred().is_empty());
        assert_eq!(DEFERRED.len(), 0);
    }

    /// The five members `TLSWrap::Initialize` installs are all present.
    #[test]
    fn the_namespace_installs_the_five_members() {
        let members = TlsWrap.members();
        assert_eq!(members.len(), 5);
        for expected in [
            "TLSWrap",
            "wrap",
            "injectOpenSSLErrorForTesting",
            "hasOpenSSLErrorForTesting",
            "HAVE_SSL_TRACE",
        ] {
            assert!(members.contains(&expected), "{expected} is missing");
        }
    }
}
