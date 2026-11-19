//! Moving a native `FileHandle` between event loops, `FileHandle::TransferForMessaging`.
//!
//! `lib/internal/fs/promises.js` marks a `FileHandle` transferable and gives it a
//! `[kTransferList]` returning `[this[kHandle]]` — the *native* handle this crate
//! builds. That handle is what crosses, and Node's `src/node_file.cc` moves it by
//! taking the descriptor out of the source handle and constructing a fresh
//! `FileHandle` around it on the receiving side.
//!
//! # Why the descriptor moves rather than being duplicated
//!
//! A descriptor is not a socket: the receiving thread must own it outright, or two
//! handles would close the same number. Node's `FileHandle::TransferForMessaging`
//! sets `closed_ = true` on the source and constructs the receiving handle from
//! `fd_`, so exactly one owner exists at each step. The source is left with `-1`,
//! which is what makes `fh.fd === -1` after a transfer and `readFile()` on it fail
//! with `EBADF`.
//!
//! # The descriptor is closed if the message is never delivered
//!
//! Node's `FileHandle::TransferData::~TransferData` closes a descriptor that is
//! still held when the payload dies. `test-worker-message-port-transfer-filehandle-
//! fd0.js` asserts exactly that, descriptor 0 included: a message discarded because
//! its target port lives in another context must not leak the file.

use std::sync::{Arc, Mutex};

use rn_core::host_object::TransferData;
use rn_v8_sys::v8;

use crate::filehandle;

/// The `host_object` kind for a native `FileHandle`.
pub const FILE_HANDLE_KIND: &str = "FileHandle";

/// Whether the handle can move, `FileHandle::GetTransferMode`.
///
/// Node answers `DisallowCloneAndTransfer` while a read is in progress, while a
/// close is in progress, and once closed. `lib/internal/fs/promises.js` enforces
/// that itself in `[kTransfer]` — it throws
/// `Cannot transfer FileHandle while in use` before reaching the native layer —
/// so this is the native guard that keeps the two agreeing rather than the
/// user-visible message.
fn transferable(object: v8::Local<'_, v8::Object>) -> bool {
    filehandle::raw_handle_state(object).is_some_and(|pointer| {
        // SAFETY: `raw_handle_state` proved the pointer is live and this borrow
        // ends before anything else can run.
        !unsafe { &*pointer }.is_busy()
    })
}

/// [`FILE_HANDLE_KIND`]'s transfer hook, for
/// [`rn_core::host_object::register_transfer_kind`].
pub fn transfer_for_messaging<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<Arc<dyn TransferData>> {
    if !transferable(object) {
        return None;
    }
    // `FileHandle::TransferForMessaging` takes the descriptor and marks the source
    // closed. `release` is that step here: it clears both the outer descriptor and
    // the stream half's copy, which is what makes `handle.fd` answer `-1`.
    let descriptor = filehandle::raw_handle_state(object)
        .map(|pointer| {
            // SAFETY: as above; `release` is the same transition `close` uses.
            unsafe { &*pointer }.release()
        })
        .filter(|descriptor| *descriptor >= 0)?;

    Some(Arc::new(FileHandleTransfer {
        descriptor: Mutex::new(descriptor),
    }))
}

/// One moved descriptor, Node's `FileHandle::TransferData`.
struct FileHandleTransfer {
    /// The descriptor, or `-1` once it has been adopted.
    descriptor: Mutex<i32>,
}

impl FileHandleTransfer {
    /// Takes the descriptor, leaving `-1` so `Drop` will not close it.
    fn take(&self) -> i32 {
        match self.descriptor.lock() {
            Ok(mut descriptor) => std::mem::replace(&mut *descriptor, -1),
            Err(poisoned) => std::mem::replace(&mut poisoned.into_inner(), -1),
        }
    }
}

impl Drop for FileHandleTransfer {
    fn drop(&mut self) {
        // `FileHandle::TransferData::~TransferData`: a message that is never
        // deserialized still owns the descriptor, and dropping it has to close it
        // or the file stays open for the process' life. `test-worker-message-port-
        // transfer-filehandle-fd0.js` is the test for this, descriptor 0 included.
        let descriptor = self.take();
        if descriptor >= 0 {
            // SAFETY: the descriptor was moved out of the source handle and no
            // other owner exists.
            unsafe {
                libc::close(descriptor);
            }
        }
    }
}

impl TransferData for FileHandleTransfer {
    fn rebuild<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Context>,
    ) -> Option<v8::Local<'s, v8::Object>> {
        // `FileHandle::TransferData::Deserialize` builds a fresh native handle
        // around the descriptor in the receiving environment. A `FileHandle` is a
        // host object whose state is a descriptor, so it may only be rebuilt into
        // the environment's own context — the same rule `JSTransferable` uses, and
        // the reason a message discarded for a `vm` realm closes the descriptor
        // instead of handing it over.
        if !rn_bind_messaging::context_is_environment(scope, target) {
            return None;
        }
        filehandle::new_native_handle(scope, self.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_payload_hands_its_descriptor_back_exactly_once() {
        // Two `take`s must not both report the descriptor: the second would ask
        // `Drop` to close a number the process may since have reused.
        let payload = FileHandleTransfer {
            descriptor: Mutex::new(9),
        };
        assert_eq!(payload.take(), 9);
        assert_eq!(payload.take(), -1);
    }
}
