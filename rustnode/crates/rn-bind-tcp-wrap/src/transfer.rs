//! Moving a live `TCP` handle between event loops, `TCPWrap::TransferForMessaging`.
//!
//! `lib/net.js` marks a `Socket`, a `Server` and a `BoundSocket` transferable and
//! gives each a `[kTransfer]` that returns its `TCP` handle as `data`; the handle
//! itself is what crosses. Node does that in `src/tcp_wrap.cc` by duplicating the
//! descriptor, closing the source handle, and constructing a fresh `TCPWrap` in
//! the receiving environment around `uv_tcp_open`.
//!
//! # Why a duplicate rather than the descriptor itself
//!
//! Threads share one descriptor table, so `dup()` names the same socket from the
//! receiving loop while the sending loop's handle is closed. Handing the original
//! number over would let the sender's `uv_close` tear down a descriptor the
//! receiver had already adopted, and would leave the two loops racing over one
//! `uv_tcp_t` — which libuv requires not to move once `uv_tcp_init` has run.
//!
//! # Why this is a *transfer* kind and not a clone kind
//!
//! A socket cannot be copied: two `uv_tcp_t`s over one connection would split the
//! byte stream. [`rn_core::host_object::register_transfer_kind`] says exactly
//! that, which is what makes `postMessage(socket)` without a transfer list report
//! `Object that needs transfer was found in message but not listed in
//! transferList` instead of silently cloning the handle.

use std::sync::{Arc, Mutex};

use libuv_sys2 as uv;
use rn_core::host_object::TransferData;
use rn_v8_sys::v8;

use crate::handle::{self, TcpHandle};

/// The `host_object` kind for a `TCP` handle.
pub const TCP_KIND: &str = "TCPWrap";

/// `TCPWrap::GetTransferMode`, as the transfer hook sees it.
///
/// A handle that is not live has no descriptor to duplicate, so it answers "not
/// transferable" and a list naming it is refused with the invalid-value message.
fn transferable(object: v8::Local<'_, v8::Object>) -> bool {
    // `StreamState::is_alive` plus libuv's own closing bit: a `uv_close` that is
    // in flight leaves the state alive until its callback runs, and duplicating a
    // descriptor out from under it would hand the receiver a socket the sender is
    // about to tear down.
    handle::with_handle(object, |handle| {
        handle.state.is_alive() && !handle.state.is_closing()
    })
    .unwrap_or(false)
}

/// [`TCP_KIND`]'s transfer hook, for
/// [`rn_core::host_object::register_transfer_kind`].
///
/// Gives up the sending handle: the descriptor is duplicated for the receiver and
/// the source's `uv_close` runs, so further use of the sending `net.Socket` fails
/// cleanly rather than splitting the stream between two loops.
pub fn transfer_for_messaging<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<Arc<dyn TransferData>> {
    if !transferable(object) {
        return None;
    }
    let prepared = handle::with_handle(object, |handle| {
        let stream = rn_uv::handle::as_handle(handle.stream());
        // SAFETY: `handle.stream()` is the live stream this wrapper owns, and the
        // wrapper has not been closed here.
        let descriptor = unsafe { rn_uv::handle_transfer::fileno(stream) }?;
        let duplicate = rn_uv::handle_transfer::duplicate_descriptor(descriptor)?;
        // `uv_read_stop` before the sender lets go. `lib/net.js` starts reading on
        // every accepted socket, so the source almost always has a read in flight;
        // that completion still lands on the source handle after the transfer, and
        // it then reports through `onStreamRead` against a socket whose stream was
        // destroyed — `ERR_OUT_OF_RANGE` from `getSystemErrorName`. Node never sees
        // this because `TCPWrap::TransferForMessaging` calls `Close()` on the
        // source, which stops the read as part of closing the handle. Stopping the
        // read is the part of that teardown this side is responsible for; the
        // wrapper's own finalizer does the rest.
        // SAFETY: the stream is live and not closing.
        unsafe {
            rn_uv::stream::read_stop(handle.stream());
        }
        Some((duplicate, handle.kind))
    })??;

    // `Close()` on the source, which is the second half of
    // `TCPWrap::TransferForMessaging`. The duplicate keeps the underlying socket
    // alive until the receiver adopts it, and closing the original is what hands
    // the accept queue over: a listening connection accepted into the original's
    // backlog before the receiver's `uv_listen` runs is otherwise never dequeued,
    // which is why an immediate `net.connect` after a server transfer hung while a
    // delayed one worked.
    //
    // The finalizer skips a handle libuv has already begun closing, so this and
    // the wrapper's own teardown cannot both `uv_close` it.
    // SAFETY: the handle is live — `transferable` just confirmed it — and nothing
    // else may adopt it: the receiver gets the duplicate, not this one.
    if let Some(stream) = handle::with_handle(object, |handle| handle.stream()) {
        unsafe { rn_uv::handle_transfer::close_orphan(rn_uv::handle::as_handle(stream)) };
    }

    Some(Arc::new(TcpTransfer {
        socket: Mutex::new(prepared.0),
        kind: prepared.1,
    }))
}

/// The state one transferred `TCP` carries to the receiving end.
///
/// Node's `TCPWrap::TransferData`: the duplicated descriptor and the socket type.
/// Dropping it without ever rebuilding closes the duplicate, which is what makes
/// a message that is never delivered release its descriptor instead of leaking it
/// — `test-worker-message-port-transfer-filehandle-fd0.js` is the same obligation
/// for a file rather than a socket.
struct TcpTransfer {
    /// The duplicate `dup()` produced, or `-1` once it has been adopted.
    socket: Mutex<i32>,
    /// [`crate::SOCKET`] or [`crate::SERVER`], so the receiver reports the same
    /// provider the sender did.
    kind: i32,
}

impl TcpTransfer {
    /// Takes the descriptor, leaving `-1` so `Drop` will not close it.
    fn take(&self) -> i32 {
        match self.socket.lock() {
            Ok(mut socket) => std::mem::replace(&mut *socket, -1),
            Err(poisoned) => std::mem::replace(&mut poisoned.into_inner(), -1),
        }
    }
}

impl Drop for TcpTransfer {
    fn drop(&mut self) {
        // Node's `TCPWrap::TransferData::~TransferData` does the same: a message
        // that is never deserialized still owns the duplicate, and dropping it has
        // to close the descriptor or the socket stays open for the process' life.
        rn_uv::handle_transfer::close_descriptor(self.take());
    }
}

impl TransferData for TcpTransfer {
    fn rebuild<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _target: v8::Local<'s, v8::Context>,
    ) -> Option<v8::Local<'s, v8::Object>> {
        // `TCPWrap::TransferData::Deserialize`: construct a fresh `TCP` in the
        // receiving environment and adopt the descriptor with `uv_tcp_open`.
        //
        // The handle is built with `TcpHandle::adopt` rather than through the
        // constructor's `park_accept` path, because that path takes a
        // `Box<TcpHandle>` whose `uv_tcp_t` the constructor then initialises: here
        // the `uv_tcp_t` has to be initialised first so `uv_tcp_open` has
        // somewhere to put the socket.
        let descriptor = self.take();
        if descriptor < 0 {
            return None;
        }

        let mut tcp = TcpHandle::new(self.kind)?;
        // SAFETY: `tcp.tcp` is a live `uv_tcp_t` initialised on this thread's
        // loop, and `descriptor` is a socket no other handle owns.
        let status = unsafe { uv::uv_tcp_open(tcp.tcp.as_mut(), descriptor as uv::uv_os_sock_t) };
        if status != 0 {
            // The descriptor is still ours; closing it is the only way it gets
            // released, since no handle adopted it.
            rn_uv::handle_transfer::close_descriptor(descriptor);
            return None;
        }
        tcp.kind = self.kind;
        handle::park_accept(tcp);
        // The socket type decides the async provider, and a `net.Server` adopts
        // this handle by calling `listen` on it: a listening socket rebuilt as a
        // plain `SOCKET` would report `PROVIDER_TCPWRAP` and never accept.
        handle::instantiate_kind(scope, self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_payload_hands_its_descriptor_back_exactly_once() {
        // Two `take`s must not both report the descriptor: a second one would ask
        // `Drop` to close a number the process may since have reused.
        let payload = TcpTransfer {
            socket: Mutex::new(7),
            kind: crate::SOCKET,
        };
        assert_eq!(payload.take(), 7);
        assert_eq!(payload.take(), -1);
    }

    #[test]
    fn the_kind_name_is_the_one_the_marking_uses() {
        // `mark` and `register_transfer_kind` have to agree on the string, or a
        // marked handle resolves to no hook and every transfer fails as
        // "unsupported type".
        assert_eq!(TCP_KIND, "TCPWrap");
    }
}
