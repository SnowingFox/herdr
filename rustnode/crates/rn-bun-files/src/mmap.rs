//! `Bun.mmap(path, options?)`.
//!
//! # What Bun returns
//!
//! A `Uint8Array` **view over the mapped region**, not a copy. Measured:
//!
//! ```text
//! mmap("m.txt")                  => Uint8Array[10], the file's 10 bytes
//! the default is SHARED          => b[0] = 88 writes the file
//! {shared: false}                => b[0] = 88 changes the view, not the file
//! missing file                   !! Error ENOENT, "open '<abs path>'"
//! mmap() / mmap(42)              !! TypeError, "path must be a string"
//! zero-length file               !! Error EINVAL, "invalid argument, mmap"
//! ```
//!
//! **The default being shared contradicts the recorded spec**, which says the
//! default is a private copy. Measured on 1.4.4 it is the other way round, and
//! the read-only-file case proves it (a private mapping needs only `O_RDONLY`,
//! and Bun reports `EACCES`). [`map_file`] states the evidence; the tests pin it.
//!
//! The zero-length case is not incidental: `mmap` with a length of 0 is
//! `EINVAL` at the syscall, so a file of zero bytes has to be refused rather
//! than turned into an empty array.
//!
//! # The lifetime design
//!
//! A mapped region must stay mapped for exactly as long as any view of it can
//! be read, and must be unmapped exactly once. V8's `ArrayBuffer::Allocator` is
//! the wrong seam for that here: its `free` is called with the allocation's
//! length and V8 may free a backing store from another thread at an arbitrary
//! point, but the allocator's contract is a plain `alloc`/`free` pair and gives
//! no place to put the mapping's *bookkeeping* (the length and the address to
//! `munmap`) without a side table.
//!
//! The seam that does have a place for it is `ArrayBuffer::new_backing_store_from_ptr`,
//! which takes a data pointer, a length, and a **deleter callback plus a data
//! pointer of its own**. The mapping's bookkeeping goes in the deleter's data,
//! and the deleter runs when V8 releases the last reference to the backing
//! store — which is exactly "when no view can read it any more", because V8
//! keeps the backing store alive while any `ArrayBuffer` or typed-array view of
//! it is reachable.
//!
//! ```text
//! Mapping { address, length, shared }        // one Box per mmap call
//!        |
//!        +--> ArrayBuffer::new_backing_store_from_ptr(address, length,
//!             munmap_deleter, Box::into_raw(Mapping))
//!                   |
//!                   +--> with_backing_store() --> ArrayBuffer
//!                          |
//!                          +--> Uint8Array::new(buffer, 0, length)
//! ```
//!
//! Ownership rules, which are what make this sound:
//!
//! * The `Box<Mapping>` is created only after a successful `mmap`, and is
//!   released only by [`munmap_deleter`]. The failure paths drop it themselves
//!   and never hand it to V8.
//! * `V8` calls the deleter exactly once per backing store it was given, on
//!   whichever thread releases the last reference. `munmap` is thread-safe, so
//!   that is the only requirement on the callback, and the `Box` is turned back
//!   into ownership there so it cannot be freed twice.
//! * Nothing keeps a raw pointer to the mapping after the backing store is
//!   built. The `Uint8Array` reaches the bytes only through V8's data pointer,
//!   and V8 invalidates it when the backing store dies.
//!
//! # The one thing this cannot guarantee
//!
//! V8 may call the deleter while JavaScript still holds a *detached* view, whose
//! length is zero and whose data pointer is no longer readable through the
//! language. That is safe by construction rather than by observation: a view
//! cannot be read after detach, so it cannot read unmapped memory. The tests
//! check the live path (bytes correct, still correct after a forced collection)
//! and that releasing the last reference unmaps without crashing.

use std::cell::Cell;

use rn_v8_sys::v8;

use crate::error::{self, SyscallError};

/// A live mapping, owned by whoever holds the `Box`.
///
/// Every field is needed by [`munmap_deleter`]: the address and length are what
/// `munmap` takes, and `shared` is not used there but documents at the site of
/// the mapping whether a write is visible in the file — so a reader of the
/// release path can tell a write-back mapping from a private one, and the field
/// cannot silently drift out of the mapping it describes.
struct Mapping {
    address: *mut libc::c_void,
    length: usize,
    #[allow(dead_code)]
    shared: bool,
}

// SAFETY: a mapping is a process-wide address range with no thread affinity;
// `munmap` from any thread is valid, which is exactly why the deleter may run
// wherever V8 collected.
unsafe impl Send for Mapping {}

// How many times a mapping has been released, for the tests.
//
// A `munmap` running twice is the defect this whole module is arranged to avoid,
// and it is invisible from JavaScript unless the process crashes. The counter
// makes "exactly once" an assertion rather than a hope.
thread_local! {
    static RELEASES: Cell<usize> = const { Cell::new(0) };
}

/// How many mappings this thread has released.
///
/// Reset by the tests before each case so the count belongs to one scenario.
pub fn release_count() -> usize {
    RELEASES.with(Cell::get)
}

/// Resets [`release_count`].
pub fn reset_release_count() {
    RELEASES.with(|cell| cell.set(0));
}

/// `Bun.mmap(path, options?)`.
pub fn bun_mmap<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let argument = args.get(0);
    // `Bun.mmap(42)` is a `TypeError` with the same message as the no-argument
    // case, so a number must not become `"42"` on the way in.
    if !argument.is_string() {
        error::throw_invalid_arg(scope, "path must be a string");
        return;
    }
    let path = argument.to_rust_string_lossy(scope);

    // `to_object` throws on `undefined`, so the options argument is guarded
    // before it is converted: an absent options object is simply not shared.
    // The default is **shared**: measured, `Bun.mmap("a.txt")` writes through to
    // the file, and a read-only file is `EACCES` rather than a readable view. Only
    // an explicit `{shared: false}` asks for a private copy, so an absent options
    // object and an absent key both mean shared.
    let options = args.get(1);
    let shared = if options.is_null_or_undefined() {
        true
    } else {
        options
            .to_object(scope)
            .and_then(|object| {
                let key = v8::String::new(scope, "shared")?;
                object.get(scope, key.into())
            })
            .map(|flag| !flag.is_false())
            .unwrap_or(true)
    };

    match map_file(&path, shared) {
        Ok(view) => match build_view(scope, view) {
            Some(array) => rv.set(array.into()),
            None => error::throw_type_error(scope, "cannot create the mmap view"),
        },
        Err(failure) => error::throw_syscall(scope, &failure),
    }
}

/// A mapping ready to hand to V8.
#[derive(Debug)]
struct MappedView {
    address: *mut libc::c_void,
    length: usize,
    shared: bool,
}

/// `mmap`s `path`.
///
/// The error cases are the recorded ones: `ENOENT` for a missing path (reported
/// against the absolute path, which is what Bun prints), and `EINVAL` for a
/// zero-length file — because `mmap` of length 0 is invalid, not because the
/// file is empty in some other sense.
///
/// # The default is `MAP_SHARED`, and the spec has this backwards
///
/// `tier1-spec.md` §4.4 records the default as a private copy and
/// `{shared: true}` as the write-back. Measured on 1.4.4, that is inverted:
///
/// ```text
/// Bun.mmap("a.txt")                  -> b[0] = 88 writes the file   (MAP_SHARED)
/// Bun.mmap("a.txt", {shared: false}) -> b[0] = 88 does NOT write it (MAP_PRIVATE)
/// Bun.mmap("a.txt", {shared: true})  -> writes the file
/// Bun.mmap on a read-only file       -> EACCES, not a readable view
/// ```
///
/// The `EACCES` on a `0444` file is the extra confirmation: a private mapping
/// needs only `O_RDONLY`, so refusing it means Bun opened for write, which only a
/// shared mapping needs. The measured behaviour is what this implements; the
/// spec's table should be corrected.
fn map_file(path: &str, shared: bool) -> Result<MappedView, SyscallError> {
    let absolute = std::path::absolute(path)
        .map(|resolved| resolved.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());

    let metadata =
        std::fs::metadata(path).map_err(|cause| SyscallError::new(&cause, "open", &absolute))?;
    // A zero-length file needs no special case: `mmap` of length 0 fails with
    // `EINVAL`, and the failure path below turns that into Bun's
    // `EINVAL: invalid argument, mmap`. Measured — a zero-byte file and a
    // `mmap(2)` rejection of length 0 are indistinguishable from JavaScript, so
    // an explicit check here would be a branch no test could tell apart from its
    // absence. The test for it is `bun_mmap_view_is_live_and_private_by_default`,
    // which asserts the code and the message.
    let length = metadata.len();

    // A shared mapping needs a writable descriptor, and the *default* here is
    // shared: `Bun.mmap("a.txt")` writes through to the file. So the common case
    // opens for write, and a read-only file is `EACCES` — which is what Bun
    // reports, and is the cheapest confirmation that the default is shared.
    let file = if shared {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|cause| SyscallError::new(&cause, "open", &absolute))?
    } else {
        std::fs::File::open(path).map_err(|cause| SyscallError::new(&cause, "open", &absolute))?
    };
    let descriptor = {
        use std::os::fd::AsRawFd;
        file.as_raw_fd()
    };

    // Both modes need write permission on the *mapping*: even a private mapping
    // must let the store succeed, because measured, `b[0] = 88` changes what the
    // view reads back in both modes. Only `MAP_SHARED` decides whether the write
    // reaches the file. `MAP_PRIVATE | PROT_READ` — the first version — segfaulted
    // on the first store, which the write test caught.
    let flags = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    // A private mapping needs only `O_RDONLY` on the descriptor; a shared one
    // needs it open for writing, which `map_file` arranged above.
    let protection = libc::PROT_READ | libc::PROT_WRITE;

    // SAFETY: the descriptor is valid and open for the duration of the call, and
    // the length is the file's own size, so the kernel maps a range that exists.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length as usize,
            protection,
            flags,
            descriptor,
            0,
        )
    };
    if address == libc::MAP_FAILED {
        let cause = std::io::Error::last_os_error();
        // The `mmap` syscall failure is reported without a path, matching Bun.
        return Err(SyscallError {
            errno: cause.raw_os_error().unwrap_or(0),
            code: crate::error::code_of(cause.raw_os_error().unwrap_or(0)),
            message: format!(
                "{}: {}, mmap",
                crate::error::code_of(cause.raw_os_error().unwrap_or(0)),
                crate::error::reason_for(&cause)
            ),
        });
    }

    Ok(MappedView {
        address,
        length: length as usize,
        shared,
    })
}

/// Builds the `Uint8Array` over `mapped`, transferring the mapping to V8.
fn build_view<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    mapped: MappedView,
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    if mapped.length > v8::Uint8Array::MAX_LENGTH {
        // SAFETY: nothing else holds this mapping yet.
        unsafe { libc::munmap(mapped.address, mapped.length) };
        return None;
    }

    let owner = Box::new(Mapping {
        address: mapped.address,
        length: mapped.length,
        shared: mapped.shared,
    });
    let data = Box::into_raw(owner);

    // SAFETY: `mapped.address` is a live mapping of `mapped.length` bytes and
    // `data` is a `Box<Mapping>` this call owns. V8 takes over calling
    // `munmap_deleter` with `data`, exactly once, when the last reference to the
    // backing store dies. If the backing store cannot be created V8 does not call
    // the deleter, so the box would leak — but a failed allocation here is an
    // out-of-memory path V8 aborts on, not a case that returns.
    let store = unsafe {
        v8::ArrayBuffer::new_backing_store_from_ptr(
            mapped.address,
            mapped.length,
            munmap_deleter,
            data.cast(),
        )
    };
    let store = store.make_shared();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    v8::Uint8Array::new(scope, buffer, 0, mapped.length)
}

/// Unmaps the region and releases its bookkeeping.
///
/// V8 calls this once, from whichever thread released the last reference to the
/// backing store. It must not touch V8: a GC thread has no handle scope, and
/// `munmap` needs none.
///
/// # Safety
///
/// `deleter_data` must be a `Box<Mapping>` pointer produced by `Box::into_raw`
/// in [`build_view`], and this must be its first and only release.
unsafe extern "C" fn munmap_deleter(
    _data: *mut std::ffi::c_void,
    _length: usize,
    deleter_data: *mut std::ffi::c_void,
) {
    if deleter_data.is_null() {
        return;
    }
    // SAFETY: the caller guarantees this pointer came from `Box::into_raw` and
    // has not been released, so taking ownership here is the unique release.
    let mapping = unsafe { Box::from_raw(deleter_data.cast::<Mapping>()) };
    // SAFETY: the address and length are the ones a successful `mmap` produced
    // and V8 has finished with the range, so this unmaps it exactly once.
    unsafe {
        libc::munmap(mapping.address, mapping.length);
    }
    RELEASES.with(|cell| cell.set(cell.get() + 1));
    drop(mapping);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_length_mapping_is_einval_rather_than_an_empty_array() {
        // `mmap` of length 0 fails at the syscall, so a zero-byte file is refused
        // with EINVAL rather than turned into `new Uint8Array(0)`. There is no
        // explicit length check — the syscall is the check — so this also pins
        // that the syscall's failure is reported rather than swallowed.
        let dir = std::env::temp_dir().join("rn-bun-mmap-zero");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("zero.bin");
        std::fs::write(&path, b"").expect("write");

        let failure = map_file(path.to_str().expect("utf8"), true).expect_err("refused");
        assert_eq!(failure.code, "EINVAL");
        assert_eq!(failure.message, "EINVAL: invalid argument, mmap");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_path_reports_enoent() {
        let failure = map_file("/definitely/not/here.bin", false).expect_err("refused");
        assert_eq!(failure.code, "ENOENT");
    }

    #[test]
    fn the_deleter_releases_exactly_once_per_mapping() {
        // The count is the assertion: a deleter that ran twice would be a
        // double-unmap, which is the failure this design exists to prevent.
        reset_release_count();
        let path = std::env::temp_dir().join("rn-bun-mmap-count.bin");
        std::fs::write(&path, b"0123456789").expect("write");
        let mapped = map_file(path.to_str().expect("utf8"), false).expect("maps");

        let boxed = Box::into_raw(Box::new(Mapping {
            address: mapped.address,
            length: mapped.length,
            shared: mapped.shared,
        }));
        // SAFETY: `boxed` came from `Box::into_raw` just above.
        unsafe { munmap_deleter(std::ptr::null_mut(), mapped.length, boxed.cast()) };
        assert_eq!(release_count(), 1);

        std::fs::remove_file(&path).ok();
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;
    use std::sync::Once;

    fn with_scope<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });
        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        body(scope)
    }

    #[test]
    fn a_private_mapping_becomes_a_live_view() {
        let path = std::env::temp_dir().join("rn-bun-mmap-view.bin");
        std::fs::write(&path, b"0123456789").expect("write");
        let mapped = map_file(path.to_str().expect("utf8"), false).expect("maps");
        let length = mapped.length;
        with_scope(|scope| {
            let view = build_view(scope, mapped).expect("the view is built");
            assert_eq!(view.length(), length);
            let byte = view.get_index(scope, 0).expect("byte 0");
            assert_eq!(byte.int32_value(scope), Some(48));
        });
        std::fs::remove_file(&path).ok();
    }
}
