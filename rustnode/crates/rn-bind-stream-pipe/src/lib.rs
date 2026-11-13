//! `internalBinding('stream_pipe')` for rustnode.
//!
//! `StreamPipe` connects one stream's reads to another stream's writes in native
//! code, with no JavaScript hop per chunk. Its only caller in `lib/**` is
//! `lib/internal/http2/core.js`, in the `sendFile` path:
//!
//! ```js
//! const pipe = new StreamPipe(handle, self[kHandle]);
//! pipe.onunpipe = onFileUnpipe;
//! pipe.start();
//! ```
//!
//! # Why this namespace has to exist for `node:http2` to load
//!
//! `core.js:196` destructures `StreamPipe` at module scope. A namespace that
//! cannot install throws there, so `stream_pipe` was the last module-scope
//! blocker standing between this runtime and `require('node:http2')` resolving
//! at all — independent of whether `sendFile` is ever called.
//!
//! # The shape, and where it is observable
//!
//! `src/stream_pipe.cc` makes `StreamPipe` an `AsyncWrap` that pushes a readable
//! listener onto the source and a writable listener onto the sink:
//!
//! * the readable listener forwards each source read as a write on the sink, and
//!   when the source ends or errors it waits for the writes in flight, shuts the
//!   sink down and unpipes;
//! * the writable listener counts those writes down and, when the source has
//!   ended and the count reaches zero, emits `onunpipe`.
//!
//! `Unpipe` stops the source read, detaches both listeners, and then emits
//! `onunpipe` and nulls the four object links the constructor established:
//!
//! ```text
//! pipe.source = source      source.pipeTarget  = pipe
//! pipe.sink   = sink        sink.pipeSource    = pipe
//! ```
//!
//! Those links are a cycle on purpose: an `Http2Stream` keeps its handle weakly,
//! so without the links the pipe could be collected mid-transfer. They are also
//! why `Unpipe` clears all four.
//!
//! # Where the reads come from
//!
//! `ReadableListener::OnStreamAlloc` asks for `min(suggested, wanted_data_)`
//! bytes, `wanted_data_` being the sink's last `OnStreamWantsWrite` hint. This
//! crate asks for the default allocation and copies into the sink's write buffer
//! instead, because the default allocation is owned only for the duration of the
//! read callback and a queued `uv_write` needs its buffer to outlive that. One
//! memcpy per chunk, and the only place this differs from Node's shape.
//!
//! # Reachability today, honestly
//!
//! Nothing in the current build can *construct* one: `sendFile` is the only
//! caller, and it needs `internalBinding('fs')`'s `FileHandle` (deferred in
//! `rn-bind-fs`) as the source and `Http2Stream` as the sink. So this crate
//! installs a real constructor and real methods over the `rn_uv` listener layer —
//! the wiring is not a stub — while the JS path that reaches it waits on those
//! two other increments.

mod handle;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/stream_pipe.json`.
pub const MEMBERS: &[&str] = &["StreamPipe"];

/// Members this build does not install yet.
///
/// Empty: the single recorded member is installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('stream_pipe')`.
pub struct StreamPipe;

impl BindingModule for StreamPipe {
    fn namespace(&self) -> &'static str {
        "stream_pipe"
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
        set(scope, object, "StreamPipe", constructor)?;
        Ok(object)
    }
}

/// Registers the `stream_pipe` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(StreamPipe);
}

thread_local! {
    /// Pipes whose `onunpipe` is due on the next check phase, as raw addresses.
    ///
    /// `Unpipe` can run from a stream's destructor, so it must not call into
    /// JavaScript directly: Node defers the JS-facing half through
    /// `Environment::SetImmediate`, which is this same native queue. A plain
    /// address rather than a boxed closure keeps the deferring path free of
    /// allocation, and the queue drains before the queue can outlive its entry
    /// because the pipe's own object is rooted in its state until the finalizer
    /// runs.
    static PENDING_UNPIPE: std::cell::RefCell<Vec<usize>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Queues a pipe's `onunpipe` notification for the next check phase.
pub(crate) fn defer_unpipe(address: usize) {
    PENDING_UNPIPE.with(|pending| pending.borrow_mut().push(address));
    rn_core::native_immediates::set_immediate(deliver_unpipe);
}

/// Runs every queued `onunpipe`, clearing the four object links.
///
/// The address is turned back into a reference only here, and only for the
/// duration of one notification.
fn deliver_unpipe(scope: &mut v8::PinScope<'_, '_>) {
    let pipes: Vec<usize> =
        PENDING_UNPIPE.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    for address in pipes {
        if address == 0 {
            continue;
        }
        // SAFETY: the address was queued by `defer_unpipe` for a pipe whose state
        // the `StreamPipe` object owns, and the object is rooted in that state, so
        // it cannot have been finalised between the queue and this drain.
        let state = unsafe { &*(address as *const handle::PipeState) };
        // SAFETY: as above; the pipe is live for this call.
        unsafe {
            handle::notify_unpiped(scope, state);
        }
    }
}

/// Sets a normal property.
fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: v8::Local<'_, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    if object.set(scope, key.into(), value).is_none() {
        return Err(format!("cannot define {name}"));
    }
    Ok(())
}

/// Throws a `TypeError`, which is what a failed `CHECK` amounts to here.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let error = v8::Exception::type_error(scope, text);
    scope.throw_exception(error);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_matches_the_contract() {
        // `rn-compat` checks this too, but only when it runs. A bare
        // `cargo test` should also notice a rename, because the name is what
        // `core.js` destructures at module scope.
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/stream_pipe.json"
        ))
        .expect("contracts/stream_pipe.json is readable");
        let contract: serde_json::Value = serde_json::from_str(&raw).expect("the contract parses");
        let recorded: Vec<&String> = contract["members"]
            .as_object()
            .expect("the contract has a members object")
            .keys()
            .collect();
        assert_eq!(recorded, vec!["StreamPipe"]);
        assert_eq!(MEMBERS, ["StreamPipe"]);
        assert!(DEFERRED.is_empty(), "nothing is deferred");
    }
}
