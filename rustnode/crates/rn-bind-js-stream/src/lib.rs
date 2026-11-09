//! `internalBinding('js_stream')` for rustnode.
//!
//! `lib/internal/js_stream_socket.js` is the only consumer. It builds a
//! `JSStreamSocket extends net.Socket` whose handle is a `JSStream`, which is how
//! TLS and HTTP/2 wrap a *JavaScript* stream — `new net.Socket()` over a
//! `Duplex`, rather than over a file descriptor. The comment at the top of that
//! file says exactly this:
//!
//! > to maintain composability, we need a way to create "fake" net.Socket
//! > instances that call back into a "real" JavaScript stream.
//!
//! # What a `JSStream` is
//!
//! `src/js_stream.cc` is a `StreamBase` with no libuv handle at all. Every
//! operation `StreamBase` would perform on a socket becomes a method call on the
//! JavaScript object, which `JSStreamSocket` assigns:
//!
//! | native hook | JavaScript method | when |
//! | --- | --- | --- |
//! | `IsClosing` | `isClosing()` | `_writeGeneric`, before a write |
//! | `ReadStart` | `onreadstart()` | `socket.resume()` |
//! | `ReadStop` | `onreadstop()` | `socket.pause()` |
//! | `DoShutdown` | `onshutdown(req)` | `socket.end()` |
//! | `DoWrite` | `onwrite(req, bufs)` | `socket.write()` |
//!
//! and two methods go the *other* way, from JavaScript into this object:
//! `readBuffer(chunk)` feeds data to the reading side, and `emitEOF()` reports
//! end of stream. `finishWrite`/`finishShutdown` complete a request the
//! JavaScript side has finished with.
//!
//! # Why the `StreamBase` surface is installed here
//!
//! Node calls `StreamBase::AddMethods(env, t)` on the `JSStream` template, so its
//! prototype carries the whole stream surface — `readStart`, `writeBuffer`,
//! `writeUtf8String`, `fd`, `bytesRead`, `onread` and the rest. rustnode's
//! `tcp_wrap`/`pipe_wrap` install theirs from [`rn_uv::stream_base`], which is
//! written against a libuv handle. A `JSStream` has none, so the same surface is
//! built here over a plain counter pair instead. The methods a caller can reach
//! are the same; only what they do differs, exactly as in Node.
//!
//! # Deferred
//!
//! `useUserBuffer` is installed (it is part of `StreamBase::AddMethods` and
//! `lib/internal/js_stream_socket.js` tolerates it being a no-op because it never
//! calls it), and nothing else is missing, so [`DEFERRED`] is empty.

mod handle;
mod methods;
use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/js_stream.json`.
pub const MEMBERS: &[&str] = &["JSStream"];

/// Members this build does not install yet.
///
/// Empty: the single recorded member is installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('js_stream')`.
pub struct JsStream;

impl BindingModule for JsStream {
    fn namespace(&self) -> &'static str {
        "js_stream"
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
        let constructor = handle::constructor(scope)?;
        set(scope, object, "JSStream", constructor)?;
        Ok(object)
    }
}

/// Registers the `js_stream` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(JsStream);
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

/// A `v8::String` for `name`, with the failure spelled out.
pub(crate) fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))
}

#[cfg(test)]
mod tests {
    use rn_core::BindingModule;

    use super::*;

    #[test]
    fn the_member_list_is_the_contract() {
        assert_eq!(MEMBERS, &["JSStream"]);
        assert_eq!(JsStream.members(), MEMBERS);
        assert!(JsStream.deferred().is_empty());
    }

    #[test]
    fn every_contract_member_is_installed() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/js_stream.json"))
                .expect("the js_stream contract parses");
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
