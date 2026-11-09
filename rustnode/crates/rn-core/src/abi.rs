//! The ABI every binding crate implements.
//!
//! Node's JavaScript layer calls `internalBinding(name)` and uses the returned
//! object. rustnode reproduces that by having each binding crate install the
//! same members into a plain JavaScript object. Keeping one trait here is what
//! lets many crates be developed in parallel without inventing mutually
//! incompatible interfaces.

use rn_v8_sys::v8;

use crate::AsyncIds;

/// Per-isolate state a binding may read or update while installing.
pub struct InstallCtx<'a> {
    pub async_ids: &'a mut AsyncIds,
}

/// One `internalBinding()` namespace implemented in Rust.
///
/// Implementations describe their members statically so `rn-compat` can check
/// them against the contract recorded from a real Node binary, and build the
/// object inside a V8 scope.
pub trait BindingModule {
    /// Namespace name, exactly as `lib/**` passes it to `internalBinding`.
    fn namespace(&self) -> &'static str;

    /// Members this crate exposes.
    fn members(&self) -> &'static [&'static str];

    /// Members the namespace needs but this crate does not install yet, each
    /// with the reason. Defaults to none.
    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Builds the object `internalBinding(namespace)` returns.
    ///
    /// Must not throw a JavaScript exception; return `Err` instead and let the
    /// runtime surface it as a startup failure.
    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String>;
}
