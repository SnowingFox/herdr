//! `internalBinding('wasm_web_api')` for rustnode.
//!
//! This namespace exists for one reason: `WebAssembly.compileStreaming` is
//! specified to fetch and compile incrementally, and V8 leaves the fetching half
//! to the embedder. Node implements that half in JavaScript
//! (`lib/internal/wasm_web_api.js`, over `undici`) and keeps only the V8 bridge
//! in C++ (`src/node_wasm_web_api.cc`).
//!
//! The namespace surface is therefore a single setter,
//! `setImplementation(fn)`. Node calls it once during bootstrap from
//! `internal/bootstrap/web/exposed-window-or-worker.js`; `is_main_thread.js` only
//! needs the binding to *exist*, which it does with a bare
//! `internalBinding('wasm_web_api')` at module scope.
//!
//! # What is implemented and what is not
//!
//! `setImplementation` records the callback. The callback is *not* wired to V8's
//! `set_wasm_streaming_callback`, because the one thing that hook needs from the
//! native side is a `v8::WasmStreaming` object handed to JavaScript, and the
//! `v8` crate's `WasmStreaming` is a Rust-owned handle with no path back into
//! JavaScript. Bridging it would mean wrapping it in an object with
//! `onBytesReceived`/`finish`/`abort` methods, which is a real piece of work for
//! a feature nothing in the current test suite exercises.
//!
//! So this is declared honestly rather than faked: the binding exists, the setter
//! stores what it is given, and `WebAssembly.compileStreaming` reports V8's own
//! "streaming compilation is not available" instead of silently compiling
//! everything in one shot (which would change observable timing) or throwing from
//! an obscure place.

use std::cell::RefCell;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/wasm_web_api.json`.
pub const MEMBERS: &[&str] = &["setImplementation"];

thread_local! {
    /// The implementation `lib/internal/wasm_web_api.js` installed.
    ///
    /// Held so the callback cannot be collected and so a later reader can find
    /// it once the streaming bridge exists; nothing calls it yet.
    static IMPLEMENTATION: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };
}

pub struct WasmWebApi;

impl BindingModule for WasmWebApi {
    fn namespace(&self) -> &'static str {
        "wasm_web_api"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let key = v8::String::new(scope, "setImplementation")
            .ok_or("cannot allocate setImplementation")?;
        let template = v8::FunctionTemplate::builder(set_implementation).build(scope);
        let function = template
            .get_function(scope)
            .ok_or("cannot allocate setImplementation")?;
        object.set(scope, key.into(), function.into());
        Ok(object)
    }
}

fn set_implementation(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        if let Some(message) = v8::String::new(scope, "setImplementation requires a function") {
            let exception = v8::Exception::type_error(scope, message);
            scope.throw_exception(exception);
        }
        return;
    };
    let callback = v8::Global::new(scope, callback);
    IMPLEMENTATION.with(|slot| {
        *slot.borrow_mut() = Some(callback);
    });
}

/// Registers the `wasm_web_api` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(WasmWebApi);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_cover_the_recorded_contract() {
        assert_eq!(MEMBERS, ["setImplementation"]);
    }
}
