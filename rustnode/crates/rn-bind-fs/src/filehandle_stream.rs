//! The `StreamBase` half of `fs.FileHandle`.
//!
//! `src/node_file.cc` makes `FileHandle` an `AsyncWrap` **and** a `StreamBase`:
//!
//! ```cpp
//! class FileHandle final : public AsyncWrap, public StreamBase {
//! ```
//!
//! and `StreamBase::AddMethods` gives it `readStart`, `readStop`, `shutdown`, the
//! four `write*` forms, `isStreamBase` and an `onread` accessor. That is what makes
//! it usable as either end of a `StreamPipe`, which `lib/internal/http2/core.js`
//! relies on in `startFilePipe`:
//!
//! ```js
//! const handle = new FileHandle(fd, offset, length);
//! handle.onread = onPipedFileHandleRead;
//! const pipe = new StreamPipe(handle, self[kHandle]);
//! pipe.start();
//! ```
//!
//! # What is real here, and what Node does not have either
//!
//! * `readStart` is a real asynchronous `uv_fs_read` on libuv's threadpool. The
//!   bytes land in a listener's read buffer and travel through the listener chain
//!   exactly as a socket's do. It re-arms itself after each completion until
//!   `readStop`, `read_length_` runs out, or the file ends.
//! * `readStop` clears the reading flag, which is what stops that re-arm.
//! * `shutdown` closes the descriptor and reports a *synchronous* completion
//!   (`return 1`), which is what `FileHandle::DoShutdown` does and what
//!   `StreamPipe::WritableListener::OnStreamAfterShutdown` expects.
//! * `write` is `UV_ENOSYS`.
//!
//! That last one is Node's own behaviour, not a gap here: `FileHandle::DoWrite`
//! is `return UV_ENOSYS;  // Not implemented (yet).` (`src/node_file.cc:304`). So
//! a `FileHandle` is a valid pipe **source** and a sink that accepts the
//! construction but moves no bytes, on Node and here alike. Making it write would
//! not be parity, it would be a divergence.
//!
//! # Offsets and length
//!
//! Node's constructor takes `(fd, offset, length)` and stores both. `readStart`
//! reads at `read_offset_`, advances it per read, and decrements `read_length_`,
//! emitting `UV_EOF` when it reaches zero. `core.js` uses that for
//! `respondWithFile(path, headers, { offset, length })`, so both are honoured here.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::ptr;

use rn_uv::handle::{Allocation, StreamState};
use rn_uv::listener::{self, ReadBuffer};
use rn_uv::stream_ops::{StreamOps, WriteOutcome};
use rn_v8_sys::v8;

use crate::fsops;

/// `UV_EOF` from `uv.h`.
pub const EOF: i32 = -4095;

/// How much a single `readStart` asks for, matching `FileHandle::ReadStart`'s
/// `recommended_read = 65536`.
const RECOMMENDED_READ: usize = 65_536;

/// The `StreamBase` state one `FileHandle` owns.
///
/// The descriptor is *not* here. `close()`/`closeSync()` on the JavaScript side
/// have to release it exactly once too, so the single owner stays
/// [`crate::filehandle::HandleState`] and this asks it.
pub struct FileHandleStream {
    /// The `StreamResource` half: the byte counters and the listener chain.
    ///
    /// `stream` is null throughout — a `FileHandle` has no `uv_stream_t` — which
    /// is why the ops below are the only way to read or write it.
    pub state: RefCell<StreamState>,
    /// `reading_`: set by `readStart`, cleared by `readStop`.
    pub reading: Cell<bool>,
    /// `read_offset_`, or -1 for "wherever the descriptor is".
    pub offset: Cell<i64>,
    /// `read_length_`, or -1 for "until EOF".
    pub length: Cell<i64>,
    /// `current_read_` is in flight.
    ///
    /// `ReadStart` checks this so a re-entrant start does not issue a second
    /// concurrent read on one descriptor.
    pub reading_in_flight: Cell<bool>,
    /// The descriptor, kept in step with the handle's own field.
    ///
    /// A read completion runs with no V8 scope and no object to unwrap, and
    /// issuing the *next* read from there would otherwise need one. The value is
    /// `-1` once the descriptor has been released, which is what stops the re-arm.
    pub descriptor: Cell<i32>,
    /// `handle.onread`, rooted.
    ///
    /// `StreamBase::AddMethods` keeps this in an internal field, and the default
    /// listener reads it off `owner_object()` when a read has to reach JavaScript.
    /// A slot here rather than a JavaScript property because `onread` *is* the
    /// accessor pair above, so a property read inside the getter would recurse.
    pub onread: RefCell<Option<v8::Global<v8::Function>>>,
}

impl FileHandleStream {
    /// A stream half for `descriptor` starting at `offset` for `length` bytes.
    pub fn new(descriptor: i32, offset: i64, length: i64) -> Self {
        let mut state = StreamState::new(ptr::null_mut());
        state.ops = &FILE_HANDLE_OPS;
        Self {
            state: RefCell::new(state),
            reading: Cell::new(false),
            offset: Cell::new(offset),
            length: Cell::new(length),
            reading_in_flight: Cell::new(false),
            descriptor: Cell::new(descriptor),
            onread: RefCell::new(None),
        }
    }

    /// The state address the listener layer takes.
    pub fn state_pointer(&self) -> *mut StreamState {
        self.state.as_ptr()
    }

    /// Records this allocation on the state, so the ops can find it again.
    ///
    /// Called once the `FileHandleStream` is in its final place — the box that the
    /// object owns — because a pointer taken before that would not survive the
    /// move.
    ///
    /// # Safety
    ///
    /// `self` must be at its final address and outlive the state.
    pub unsafe fn install_owner(&self) {
        // SAFETY: the caller guarantees the address is final and outlives the
        // state.
        let state = unsafe { &mut *self.state.as_ptr() };
        state.owner = (self as *const FileHandleStream)
            .cast_mut()
            .cast::<c_void>();
    }

    /// Marks the descriptor released, so a pending re-arm does not read a closed
    /// descriptor another part of the process may have reused.
    pub fn release(&self) {
        self.descriptor.set(-1);
        self.reading.set(false);
    }

    /// `FileHandle::AfterClose` — the state transition `releaseFD` and `close`
    /// share.
    ///
    /// ```cpp
    /// void FileHandle::AfterClose() {
    ///   closing_ = false;
    ///   closed_ = true;
    ///   fd_ = -1;
    ///   if (reading_ && !persistent().IsEmpty()) EmitRead(UV_EOF);
    /// }
    /// ```
    ///
    /// Two things matter beyond clearing the descriptor. `closed_` makes
    /// `ReadStart` return `UV_EOF` rather than reading, and a readable side that
    /// was flowing gets an EOF so whatever is reading stops instead of waiting for
    /// a stream that will never produce again. `releaseFD` is called from
    /// `onFileUnpipe` on the `!stream.ownsFd` path — the `respondWithFD` family —
    /// where the descriptor belongs to the caller and must *not* be closed.
    pub fn after_close(&self) {
        let was_reading = self.reading.get();
        self.release();
        if was_reading {
            self.emit_eof();
        }
    }

    /// Whether the descriptor has been released, i.e. `FileHandle::closed_`.
    ///
    /// `ReadStart` checks this so a released handle reports `UV_EOF` instead of
    /// issuing a read on `-1`.
    pub fn is_closed(&self) -> bool {
        self.descriptor.get() < 0
    }

    /// Issues one `uv_fs_read`, or reports EOF when there is nothing left.
    fn issue(&self) {
        if self.descriptor.get() < 0 {
            return;
        }
        // `read_length_ == 0` is immediate EOF, exactly as `ReadStart` writes it.
        if self.length.get() == 0 {
            self.emit_eof();
            return;
        }
        let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
            return;
        };

        let mut recommended = RECOMMENDED_READ;
        let length = self.length.get();
        if length >= 0 && (length as usize) <= recommended {
            recommended = length as usize;
        }
        let Some(allocation) = Allocation::new(recommended) else {
            return;
        };

        let request = Box::new(ReadRequest {
            allocation,
            handle: (self as *const FileHandleStream).cast_mut(),
        });
        let request = Box::into_raw(request);
        let storage = Box::into_raw(Box::new(
            std::mem::MaybeUninit::<rn_uv::sys::uv_fs_t>::zeroed(),
        ));
        // SAFETY: `storage` is a live, aligned, zeroed `uv_fs_t`.
        let raw = unsafe { (*storage).as_mut_ptr() };
        // SAFETY: `raw` is live; `data` is the slot the completion reads.
        unsafe {
            (*raw).data = request.cast();
        }
        let buffer = rn_uv::sys::uv_buf_t {
            // SAFETY: `request` is the live box just created and its allocation is
            // not aliased; the pointer is to that allocation's own memory.
            base: unsafe { (*request).allocation.base_const() }
                .cast_mut()
                .cast(),
            // SAFETY: as above.
            len: unsafe { (*request).allocation.length() },
        };
        // SAFETY: the allocation inside `request` is live until the completion
        // takes it back, and `buffer` points into exactly that allocation.
        let status = unsafe {
            rn_uv::sys::uv_fs_read(
                loop_pointer,
                raw,
                self.descriptor.get(),
                &buffer,
                1,
                self.offset.get(),
                Some(after_read),
            )
        };
        if status < 0 {
            // Nothing was queued, so libuv will never call back.
            // SAFETY: both boxes came from `Box::into_raw` above and libuv took
            // ownership of neither.
            unsafe {
                drop(Box::from_raw(storage));
                drop(Box::from_raw(request));
            }
            self.emit_eof();
            return;
        }
        self.reading_in_flight.set(true);
    }

    /// `EmitRead(UV_EOF)`.
    fn emit_eof(&self) {
        self.reading.set(false);
        let state = self.state_pointer();
        // SAFETY: the state is live (it lives in this allocation) and `emit_read`
        // holds no reference across the listener call.
        unsafe {
            listener::emit_read(
                state,
                EOF as isize,
                ReadBuffer::Listener(rn_uv::sys::uv_buf_t {
                    base: ptr::null_mut(),
                    len: 0,
                }),
            )
        };
    }
}

/// The ops a `FileHandle`'s `StreamState` carries.
pub struct FileHandleOps;

/// The one instance every `FileHandle` state points at.
pub static FILE_HANDLE_OPS: FileHandleOps = FileHandleOps;

impl StreamOps for FileHandleOps {
    unsafe fn read_start(&self, state: *mut StreamState) -> i32 {
        let Some(handle) = handle_of(state) else {
            return rn_uv::stream_base::EINVAL;
        };
        // SAFETY: `handle_of` returned the live allocation that owns this state.
        let handle = unsafe { &*handle };
        // `if (!IsAlive() || IsClosing()) return UV_EOF;` — a released descriptor
        // must not be read, and reporting EOF is what makes a reader stop rather
        // than wait. `releaseFD` can land here from `onFileUnpipe` while a pipe is
        // still attached.
        if handle.is_closed() {
            return EOF;
        }
        handle.reading.set(true);
        if handle.reading_in_flight.get() {
            // `ReadStart` returns 0 when a read is already outstanding: not an
            // error, there is simply nothing to do.
            return 0;
        }
        handle.issue();
        0
    }

    unsafe fn read_stop(&self, state: *mut StreamState) -> i32 {
        let Some(handle) = handle_of(state) else {
            return rn_uv::stream_base::EINVAL;
        };
        // SAFETY: as above.
        unsafe { &*handle }.reading.set(false);
        0
    }

    unsafe fn shutdown(&self, state: *mut StreamState) -> i32 {
        if let Some(handle) = handle_of(state) {
            // SAFETY: as above.
            let handle = unsafe { &*handle };
            let descriptor = handle.descriptor.get();
            // `FileHandle::DoShutdown` dispatches `uv_fs_close` and then
            // `AfterClose()` — the same state transition a `closeSync` makes, so
            // the stream half and the descriptor cannot disagree about whether the
            // handle is still readable.
            handle.after_close();
            if descriptor >= 0 {
                // A close failure here is reported by the JavaScript close path,
                // which owns the descriptor; the shutdown itself completed.
                let _ = fsops::close(descriptor);
            }
        }
        // `FileHandle::DoShutdown` returns 1 when it finished synchronously, and
        // `FileHandle::CreateShutdownWrap` returns null because it always does.
        1
    }

    unsafe fn write(
        &self,
        _state: *mut StreamState,
        _buffers: Vec<rn_uv::sys::uv_buf_t>,
        _total_bytes: usize,
        _owned: Vec<Box<[u8]>>,
    ) -> WriteOutcome {
        // `FileHandle::DoWrite` is `return UV_ENOSYS;  // Not implemented (yet).`
        // in Node. Reporting it as a synchronous failure is what makes a pipe with
        // a FileHandle sink unpipe immediately instead of hanging on a completion
        // that never arrives — which is exactly what Node does.
        WriteOutcome::Sync(rn_uv::sys::uv_errno_t_UV_ENOSYS)
    }

    fn has_wants_write(&self) -> bool {
        // `FileHandle` does not override `StreamBase::HasWantsWrite`, whose
        // default is `false`.
        false
    }

    fn has_libuv_stream(&self) -> bool {
        false
    }
}

/// The `FileHandleStream` behind a state, from the state's own owner pointer.
fn handle_of(state: *mut StreamState) -> Option<*mut FileHandleStream> {
    if state.is_null() {
        return None;
    }
    // SAFETY: the caller passes the live state it read the ops from.
    let owner = unsafe { (*state).owner };
    if owner.is_null() {
        None
    } else {
        Some(owner.cast::<FileHandleStream>())
    }
}

/// One read in flight.
struct ReadRequest {
    /// The allocation libuv fills. Taken by the completion.
    allocation: Allocation,
    /// The `FileHandleStream` this read belongs to, so the completion can re-arm
    /// it.
    handle: *mut FileHandleStream,
}

/// libuv's `uv_fs_read` completion.
///
/// # Safety
///
/// Called by libuv with the `uv_fs_t` [`FileHandleStream::issue`] allocated.
unsafe extern "C" fn after_read(request: *mut rn_uv::sys::uv_fs_t) {
    if request.is_null() {
        return;
    }
    // SAFETY: `issue` stored this pointer in `data` and libuv hands the same
    // request back exactly once.
    let parked = unsafe { (*request).data.cast::<ReadRequest>() };
    // `result` is the byte count, or a negative errno. Read before the request is
    // released.
    let result = unsafe { (*request).result };
    // SAFETY: the request came from `Box<MaybeUninit<uv_fs_t>>`.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<rn_uv::sys::uv_fs_t>>()) });
    if parked.is_null() {
        return;
    }
    // SAFETY: `parked` came from `Box::into_raw` in `issue` and is not aliased.
    let parked = unsafe { Box::from_raw(parked) };
    if parked.handle.is_null() {
        return;
    }
    // SAFETY: the handle owns the state that owns this read, so it outlives it.
    let handle = unsafe { &*parked.handle };
    handle.reading_in_flight.set(false);

    let length = parked.allocation.length();
    let allocation = parked.allocation;

    // `Reading 0 bytes from a file always means EOF, or that we reached the end of
    // the requested range.` (`src/node_file.cc`).
    let count = if result <= 0 { 0 } else { result as usize };
    let limit = match handle.length.get() {
        n if n < 0 => count,
        // `Read at most as many bytes as we originally planned to.`
        n => count.min(n as usize),
    };
    if result > 0 {
        if handle.length.get() >= 0 {
            handle.length.set(handle.length.get() - limit as i64);
        }
        if handle.offset.get() >= 0 {
            handle.offset.set(handle.offset.get() + limit as i64);
        }
    }

    let status = if result < 0 {
        result
    } else if count == 0 {
        EOF as isize
    } else {
        limit as isize
    };
    let still_reading = handle.reading.get();
    let state = handle.state_pointer();

    if status > 0 {
        // Hand over only the bytes that were read, and only as many as the
        // requested range allows. A right-sized copy keeps the whole 64 KiB
        // reservation from being pinned by the view the listener receives.
        let buffer = if limit < length {
            match copy_prefix(&allocation, limit) {
                Some(sized) => {
                    drop(allocation);
                    ReadBuffer::Allocated(sized)
                }
                None => {
                    drop(allocation);
                    ReadBuffer::Listener(rn_uv::sys::uv_buf_t {
                        base: ptr::null_mut(),
                        len: 0,
                    })
                }
            }
        } else {
            ReadBuffer::Allocated(allocation)
        };
        // SAFETY: `state` is live and `emit_read` holds no reference to it across
        // the listener call.
        unsafe { listener::emit_read(state, status, buffer) };
    } else {
        drop(allocation);
        // SAFETY: as above.
        unsafe {
            listener::emit_read(
                state,
                status,
                ReadBuffer::Listener(rn_uv::sys::uv_buf_t {
                    base: ptr::null_mut(),
                    len: 0,
                }),
            )
        };
    }

    // `Start over, if EmitRead() didn't tell us to stop.`
    if still_reading && status > 0 {
        // SAFETY: `handle` is live; it owns the state this completion belongs to.
        unsafe { (*parked.handle).issue() };
    }
}

/// Copies the first `count` bytes of an allocation into a right-sized one.
fn copy_prefix(allocation: &Allocation, count: usize) -> Option<Allocation> {
    if count == 0 || count > allocation.length() {
        return None;
    }
    let mut sized = Allocation::new(count)?;
    // SAFETY: both allocations are live and distinct, and `count` is within both.
    unsafe {
        ptr::copy_nonoverlapping(allocation.base_const(), sized.base(), count);
    }
    Some(sized)
}

/// Installs the `StreamBase` prototype surface on `FileHandle`.
///
/// This is `StreamBase::AddMethods(isolate, t)` (`src/stream_base.cc:582`). On
/// Node the full prototype is
///
/// ```text
/// close, closeSync, releaseFD, fd, _externalStream, bytesRead, bytesWritten,
/// readStart, readStop, shutdown, useUserBuffer, writev, writeBuffer,
/// writeAsciiString, writeUtf8String, writeUcs2String, writeLatin1String,
/// isStreamBase, onread
/// ```
///
/// `close`, `closeSync` and `releaseFD` are installed by
/// [`crate::filehandle::constructor`] because `FileHandle::Initialize` does them
/// itself; everything from `fd` onward is installed here.
///
/// `_externalStream` is deliberately absent. It exists only for
/// `node_wasm_web_api.cc`'s external-memory-backed stream, and nothing on the
/// `fs` or `http2` path reads it — so it is the one member of this surface that
/// this runtime genuinely does not need, and it is omitted rather than stubbed
/// with a value that would be wrong if anything ever did read it.
pub fn install_stream_base(
    scope: &mut v8::PinScope<'_, '_>,
    prototype: v8::Local<'_, v8::ObjectTemplate>,
) -> Result<(), String> {
    // The four accessors `AddMethods` installs first (`AddAccessor`), before any
    // method.
    for (name, getter) in [
        ("bytesRead", get_bytes_read as Accessor),
        ("bytesWritten", get_bytes_written as Accessor),
    ] {
        let _ = getter;
        let template = match name {
            "bytesRead" => rn_core::method(get_bytes_read),
            _ => rn_core::method(get_bytes_written),
        };
        prototype.set_accessor_property(
            key(scope, name)?.into(),
            Some(template.build(scope)),
            None,
            v8::PropertyAttribute::DONT_DELETE,
        );
    }

    // `fd` is already installed by `filehandle::constructor` with the accessor
    // that reports `-1` once the descriptor is released, which is stricter than
    // Node's plain data property and is what `promises.js` re-reads on the
    // deserialize path. `_externalStream` is not installed: it exists for
    // WebAssembly's external-memory stream, which this runtime does not have.

    macro_rules! install {
        ($($name:literal => $method:expr),* $(,)?) => {
            $(
                prototype.set(
                    key(scope, $name)?.into(),
                    rn_core::method($method).build(scope).into(),
                );
            )*
        };
    }
    install! {
        "readStart" => read_start,
        "readStop" => read_stop,
        "shutdown" => shutdown,
        "useUserBuffer" => use_user_buffer,
        "writev" => writev,
        "writeBuffer" => write_buffer,
        "writeAsciiString" => write_ascii,
        "writeUtf8String" => write_utf8,
        "writeUcs2String" => write_ucs2,
        "writeLatin1String" => write_latin1,
        // `FileHandle::Initialize` installs `releaseFD` alongside `close` and
        // `closeSync`, before `StreamBase::AddMethods` runs. `core.js`'s
        // `onFileUnpipe` calls it on the `!stream.ownsFd` path — the
        // `respondWithFD` family — where the descriptor belongs to the caller and
        // must not be closed. Without it those five files die with
        // `this.source.releaseFD is not a function` instead of exercising their
        // subject.
        "releaseFD" => release_fd,
    }

    // `t->PrototypeTemplate()->Set("isStreamBase", True(isolate))`. `lib/net.js`
    // and `lib/internal/http2/core.js` test it before treating a handle as a
    // stream.
    prototype.set(
        key(scope, "isStreamBase")?.into(),
        v8::Boolean::new(scope, true).into(),
    );

    // `AddAccessor(..., kOnReadFunctionField, ...)`: `onread` is an accessor over
    // an internal field in Node. A plain property keeps the observable contract
    // (assigning and reading agree) and is where `deliver_read` looks.
    let onread = rn_core::method(get_onread).build(scope);
    let onread_setter = rn_core::method(set_onread).build(scope);
    prototype.set_accessor_property(
        key(scope, "onread")?.into(),
        Some(onread),
        Some(onread_setter),
        v8::PropertyAttribute::DONT_DELETE,
    );
    Ok(())
}

/// `handle.releaseFD()` — hand the descriptor back without closing it.
///
/// This is `FileHandle::ReleaseFD` (`src/node_file.cc:557`), whose whole body is
/// `fd->Release()`:
///
/// ```cpp
/// int FileHandle::Release() {
///   int fd = GetFD();
///   // Just pretend that Close was called and we're all done.
///   AfterClose();
///   return fd;
/// }
/// ```
///
/// `core.js`'s `onFileUnpipe` calls it from the `!stream.ownsFd` branch: the
/// descriptor came from the caller (`respondWithFD`), so the pipe must release
/// its claim on it rather than close a file the caller still owns. Marking the
/// handle closed first is what stops an in-flight `uv_fs_read` completion from
/// re-arming on a descriptor number the process may reuse.
pub(crate) fn release_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `ASSIGN_OR_RETURN_UNWRAP(&fd, args.This())` returns `undefined` for a
    // receiver that is not a `FileHandle`, which is what `release()` on a missing
    // handle amounts to.
    let Some(state) = crate::filehandle::raw_handle_state(args.this()) else {
        rv.set_undefined();
        return;
    };
    // SAFETY: `raw_handle_state` returned the live allocation the object owns.
    // `HandleState::release` clears both views of the descriptor — the one
    // `handle.fd` reads and the one a read completion reads — so they cannot
    // disagree about whether the handle is still open.
    let descriptor = unsafe { (*state).release() };
    rv.set(v8::Integer::new(scope, descriptor).into());
}

/// A prototype key, or the message to fail construction with.
fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate the name {name}"))
}

/// The accessors and methods share this shape.
type Accessor =
    fn(&mut v8::PinScope<'_, '_>, v8::FunctionCallbackArguments<'_>, v8::ReturnValue<'_>);

/// The stream half behind a `FileHandle` object.
fn stream_of_object(object: v8::Local<'_, v8::Object>) -> Option<&'static FileHandleStream> {
    let pointer = crate::filehandle::raw_handle_state(object)?;
    // SAFETY: `raw_handle_state` proved the pointer is live, and the stream half
    // lives in the same allocation, so it is live for the same span.
    Some(unsafe { &*(*pointer).stream() })
}

/// The state pointer a `FileHandle` object's stream half owns.
fn state_of_object(object: v8::Local<'_, v8::Object>) -> Option<*mut StreamState> {
    stream_of_object(object).map(|stream| stream.state_pointer())
}

/// `handle.fd` — `StreamBase`'s accessor, over the same descriptor.
///
/// Not installed: `filehandle::constructor` already installs `fd` as an accessor
/// that reports `-1` once the descriptor is released, which is stricter than
/// Node's plain data property and is what `promises.js` re-reads on the
/// deserialize path. Kept as the reference for what `StreamBase::AddMethods`
/// would otherwise add.
#[allow(dead_code)]
fn get_fd(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let descriptor = stream_of_object(args.this())
        .map(|stream| stream.descriptor.get())
        .unwrap_or(-1);
    rv.set(v8::Integer::new(scope, descriptor).into());
}

/// `handle.bytesRead`.
fn get_bytes_read(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = state_of_object(args.this())
        // SAFETY: the state is live for as long as the object is, which is this
        // call.
        .map(|state| unsafe { (*state).bytes_read })
        .unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `handle.bytesWritten`.
fn get_bytes_written(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let bytes = state_of_object(args.this())
        // SAFETY: as above.
        .map(|state| unsafe { (*state).bytes_written })
        .unwrap_or(0);
    rv.set(v8::Number::new(scope, bytes as f64).into());
}

/// `handle.readStart()`.
fn read_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `streamBaseState` is created by whichever namespace got there first, and the
    // default listener writes a read's count into it.
    let _ = rn_uv::stream::state_array(scope);
    let status = match state_of_object(args.this()) {
        // SAFETY: the state is live for the duration of the call, and `read_start`
        // holds no reference to it across any listener call.
        Some(state) => unsafe { (*state).ops.read_start(state) },
        None => rn_uv::stream_base::EINVAL,
    };
    rv.set(v8::Integer::new(scope, status).into());
}

/// `handle.readStop()`.
fn read_stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = match state_of_object(args.this()) {
        // SAFETY: as above.
        Some(state) => unsafe { (*state).ops.read_stop(state) },
        None => rn_uv::stream_base::EINVAL,
    };
    rv.set(v8::Integer::new(scope, status).into());
}

/// `handle.shutdown(req)`.
fn shutdown(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = match state_of_object(args.this()) {
        // SAFETY: as above.
        Some(state) => unsafe { (*state).ops.shutdown(state) },
        None => rn_uv::stream_base::EINVAL,
    };
    // `FileHandle::DoShutdown` finishes synchronously, so `shutdownWritable`
    // reads `1` and runs `afterShutdown` itself; the completion below is what
    // `stream_base_commons` would otherwise wait for.
    if let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) {
        rn_uv::stream::report_completion(scope, request, 0, None, None);
    }
    rv.set(v8::Integer::new(scope, status).into());
}

/// `handle.useUserBuffer()`, which a file does not support.
fn use_user_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `StreamBase::UseUserBuffer` returns UV_ENOSYS for a stream with no
    // `WriteWrap` to hand a user buffer to.
    rv.set(v8::Integer::new(scope, rn_uv::sys::uv_errno_t_UV_ENOSYS).into());
}

/// Every write form: `FileHandle::DoWrite` is `UV_ENOSYS`.
///
/// A single implementation serves all of them because the answer does not depend
/// on the encoding or the buffer shape — the descriptor cannot be written to
/// through `StreamBase` at all. The request object's completion is reported so
/// `afterWriteDispatched` does not wait forever, exactly as Node's synchronous
/// error path does.
fn write_unsupported(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue<'_>,
) {
    let status = rn_uv::sys::uv_errno_t_UV_ENOSYS;
    if let Ok(request) = v8::Local::<v8::Object>::try_from(args.get(0)) {
        rn_uv::stream::report_completion(scope, request, status, None, Some("write EINVAL"));
    }
    rv.set(v8::Integer::new(scope, status).into());
}

/// `handle.writev(req, chunks, allBuffers)`.
fn writev(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_unsupported(scope, args, &mut rv);
}

/// `handle.writeBuffer(req, buffer)`.
fn write_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_unsupported(scope, args, &mut rv);
}

/// `handle.writeAsciiString(req, string)`.
fn write_ascii(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_unsupported(scope, args, &mut rv);
}

/// `handle.writeUtf8String(req, string)`.
fn write_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_unsupported(scope, args, &mut rv);
}

/// `handle.writeUcs2String(req, string)`.
fn write_ucs2(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_unsupported(scope, args, &mut rv);
}

/// `handle.writeLatin1String(req, string)`.
fn write_latin1(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    write_unsupported(scope, args, &mut rv);
}

/// `handle.onread`, read.
fn get_onread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // A backing slot, not a property read: `onread` *is* this accessor, so reading
    // the property from inside the getter recurses until the stack overflows.
    let value = stream_of_object(args.this())
        .and_then(|stream| stream.onread.borrow().clone())
        .map(|handler| v8::Local::new(scope, &handler));
    match value {
        Some(value) => rv.set(value.into()),
        None => rv.set_undefined(),
    }
}

/// `handle.onread`, assigned.
fn set_onread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if let Some(stream) = stream_of_object(args.this()) {
        let value = args.get(0);
        // `AddAccessor(..., &Value::IsFunction)` only accepts a function; anything
        // else clears the slot, which is how `lib/net.js` "pauses" a handle.
        let stored = v8::Local::<v8::Function>::try_from(value)
            .ok()
            .map(|function| v8::Global::new(scope.as_ref(), function));
        *stream.onread.borrow_mut() = stored;
    }
    rv.set_undefined();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_stream_half_is_not_reading() {
        let stream = FileHandleStream::new(7, 0, -1);
        assert!(!stream.reading.get());
        assert!(!stream.reading_in_flight.get());
        assert_eq!(stream.offset.get(), 0);
        assert_eq!(stream.length.get(), -1);
        assert_eq!(stream.descriptor.get(), 7);
        // A `FileHandle` has no libuv stream, which is the whole reason the ops
        // indirection exists.
        assert!(!stream.state.borrow().ops.has_libuv_stream());
    }

    #[test]
    fn the_write_half_reports_enosys_synchronously() {
        // `FileHandle::DoWrite` is `return UV_ENOSYS` in Node, and the sync form is
        // what makes a pipe unpipe immediately instead of waiting for a completion
        // that never comes.
        let stream = FileHandleStream::new(7, 0, -1);
        let state = stream.state_pointer();
        // SAFETY: `state` is the live state this ops value was read from.
        let outcome = unsafe {
            stream
                .state
                .borrow()
                .ops
                .write(state, Vec::new(), 0, Vec::new())
        };
        assert_eq!(
            outcome,
            WriteOutcome::Sync(rn_uv::sys::uv_errno_t_UV_ENOSYS)
        );
    }

    #[test]
    fn releasing_the_descriptor_stops_the_rearm() {
        // A read completion checks `descriptor < 0` before issuing the next one,
        // so a descriptor released mid-read cannot be read again — the hazard
        // being that the number may name something else by then.
        let stream = FileHandleStream::new(7, 0, -1);
        stream.reading.set(true);
        stream.release();
        assert_eq!(stream.descriptor.get(), -1);
        assert!(!stream.reading.get());
    }

    #[test]
    fn an_exhausted_length_is_immediate_eof() {
        // `read_length_ == 0` is the `EmitRead(UV_EOF)` branch of `ReadStart`.
        let stream = FileHandleStream::new(7, 0, 0);
        stream.reading.set(true);
        stream.emit_eof();
        assert!(!stream.reading.get());
    }

    #[test]
    fn the_owner_pointer_round_trips() {
        // The ops reach their implementation through it, so it has to name this
        // allocation exactly.
        let stream = Box::new(FileHandleStream::new(9, 4, 16));
        // SAFETY: the box will not move again for the rest of the test.
        unsafe { stream.install_owner() };
        let state = stream.state_pointer();
        // SAFETY: `state` is live.
        let found = handle_of(state).expect("the state names its own allocation");
        assert_eq!(
            found as usize,
            (&*stream as *const FileHandleStream) as usize
        );
        // SAFETY: the pointer came from the box above.
        assert_eq!(unsafe { (*found).descriptor.get() }, 9);
        assert_eq!(unsafe { (*found).offset.get() }, 4);
        assert_eq!(unsafe { (*found).length.get() }, 16);
    }
}
