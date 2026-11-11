//! `ReadFileJob` and `WriteFileJob`: one-shot file jobs on libuv's threadpool.
//!
//! `src/node_file.cc` defines both classes in full, and `lib/fs.js` and
//! `lib/internal/fs/promises.js` construct them unconditionally:
//!
//! ```text
//! const job = new ReadFileJob(path, flagsNumber, kReadFileBufferLength, true);
//! job.context = context;
//! job.ondone = readFileAfterOneShot;
//! const accessError = job.run(path);
//! ```
//!
//! There is no fallback on that path. `options.buffer === undefined` is the only
//! guard, and no ordinary `fs.readFile` call sets it. A namespace that lacks
//! these constructors therefore makes every `fs.readFile(path, cb)` and
//! `fs.promises.readFile(path)` throw `TypeError: ReadFileJob is not a
//! constructor`, and `fs.writeFile` the same for `WriteFileJob`. Both were
//! declared deferred here on the theory that `lib/fs.js` would fall back to
//! `open`/`fstat`/`read`/`close`; it does not.
//!
//! # Why the work is a real threadpool job
//!
//! Collapsing open+fstat+read+close into one round trip is the point of the
//! class, and doing the syscalls inline would block the loop for the length of
//! the read. Each job owns a `uv_work_t`, runs its syscalls on a pool thread and
//! delivers `ondone` from the loop — the shape
//! `crates/rn-bind-crypto-keys/src/gen.rs` established for `kCryptoJobAsync`.
//!
//! # What `run(path)` returns
//!
//! `undefined` when the work was queued, and an error value when it was not.
//! The only such error is the permission model refusing the open: `lib/fs.js`
//! tests `if (accessError !== undefined) callback(accessError)` precisely because
//! nothing is scheduled in that case.
//!
//! # The two completion shapes
//!
//! `ReadFileJob` calls `ondone(err, buffer, fd, size, closeErr)`:
//!
//! | outcome | err | buffer | fd | size | closeErr |
//! | --- | --- | --- | --- | --- | --- |
//! | open/fstat/read failed | the error | undefined | -1 | undefined | undefined |
//! | larger than the limit | null | undefined | fd | size | undefined |
//! | whole file | null | Buffer | -1 | undefined | close failure or undefined |
//!
//! The `fd >= 0` row is what `readFileAfterOneShot` looks for to take the
//! chunked path: it assigns `context.fd` and `context.size` and calls
//! `context.read()`, so a large file is read in bounded, abortable chunks rather
//! than one unbounded allocation. Reporting `-1` there would silently truncate
//! every file above `kReadFileBufferLength` (512 KiB) to its first chunk.
//!
//! `WriteFileJob` calls `ondone(err)` and nothing else, which is why one
//! `run(path)` wrapper serves both classes: `lib/fs.js` assigns a one-argument
//! `ondone` for the write and a five-argument one for the read.

use std::sync::Mutex;

use rn_v8_sys::v8;

use crate::error::FsError;
use crate::fsops::{self, PathBytes};
use crate::permission;
use crate::stats::{is_regular_file, StatFields};

/// The internal field each job instance keeps its parameters in.
///
/// `lib/fs.js` assigns `job.context` and `job.ondone` as plain properties and
/// never touches an internal field, so one field is all either class needs.
const JOB_FIELD: i32 = 0;

/// `kUnknownSizeChunk`: the first allocation for a file that reports size 0.
///
/// A size-0 regular file is either genuinely empty or a procfs-style file that
/// reports 0 and yields data anyway. Node reads those until EOF, growing the
/// buffer, starting from 64 KiB.
const UNKNOWN_SIZE_CHUNK: usize = 64 * 1024;

/// `kMaxReadChunk` and `kMaxWriteChunk`: the cap on a single `read`/`write`.
const MAX_CHUNK: usize = 256 * 1024 * 1024;

/// The result of a `ReadFileJob`'s threadpool half.
///
/// `Send` and free of V8 handles by construction: the pool thread writes one of
/// these and the loop thread turns it into JavaScript afterwards.
enum ReadOutcome {
    /// The whole file, and the close error if only `close` failed.
    Done {
        data: Vec<u8>,
        close_error: Option<FsError>,
    },
    /// Larger than the job's limit: the caller owns the descriptor now.
    ///
    /// `track_fd` is carried out because Node registers the descriptor as
    /// *unmanaged* at this point — in `AfterThreadPoolWork`, not in the work
    /// itself — so its leak diagnostic does not blame a descriptor `lib/fs.js`
    /// is about to close. There is no such registry in this runtime, so
    /// [`ReadFileJob::deliver`] records the flag rather than acting on it.
    TooLarge { fd: i32, size: u64, track_fd: bool },
    /// Open, fstat or read failed. Any descriptor opened here is already closed.
    Failed(FsError),
}

/// The result of a `WriteFileJob`'s threadpool half.
type WriteOutcome = Result<(), FsError>;

/// The parameters a `ReadFileJob` carries from its constructor to the pool.
struct ReadParams {
    path: Vec<u8>,
    flags: i32,
    limit: u64,
    /// Whether a handed-back descriptor is registered as unmanaged.
    ///
    /// Node keeps an environment-level registry so `process.report` and the
    /// "file descriptor leaked" diagnostic do not blame a descriptor that
    /// `lib/fs.js` is about to close through `fs.close()`. This runtime has no
    /// such registry, so the flag is reported by the hand-back path rather than
    /// acted on; a future registry should not have to re-derive what it means.
    track_fd: bool,
}

impl ReadParams {
    /// `ReadFileJob::DoThreadPoolWork`.
    fn run(&self) -> ReadOutcome {
        let fd = match fsops::open(&self.path, self.flags, 0o666) {
            Ok(fd) => fd,
            Err(error) => return ReadOutcome::Failed(error),
        };

        // A fstat failure closes the descriptor and then reports itself, matching
        // `Fail("fstat", rc); CloseQuietly(fd);` in that order.
        let fields = match StatFields::for_fd(fd) {
            Ok(fields) => fields,
            Err(error) => {
                let _ = fsops::close(fd);
                return ReadOutcome::Failed(error);
            }
        };
        // A non-regular file (a pipe, a character device) has no meaningful size,
        // so it is read until EOF rather than to an announced length.
        let regular = is_regular_file(fields.mode);
        let size = if regular { fields.size } else { 0 };

        if size > self.limit {
            // `readFileAfterOneShot` closes this through `fs.close()`, so the
            // descriptor must not be closed here.
            //
            // Node registers it as *unmanaged* first when `trackFd` is set, so
            // its leak diagnostic does not blame a descriptor the JavaScript
            // layer is about to close. There is no such registry here, so the
            // flag is carried into the outcome for the caller instead of being
            // acted on.
            return ReadOutcome::TooLarge {
                fd,
                size,
                track_fd: self.track_fd,
            };
        }

        // A known size is read exactly once into a buffer of that size. Unknown
        // (0) grows on demand, which is where `UNKNOWN_SIZE_CHUNK` is the
        // starting allocation rather than a limit.
        let mut capacity = match usize::try_from(size) {
            Ok(known) if known > 0 => known,
            _ => UNKNOWN_SIZE_CHUNK,
        };
        let mut data: Vec<u8> = Vec::with_capacity(capacity);
        let mut failure = None;
        loop {
            if data.len() == capacity {
                if size > 0 {
                    break;
                }
                let Some(grown) = capacity.checked_mul(2) else {
                    failure = Some(FsError::from_errno("read", libc::ENOMEM));
                    break;
                };
                data.reserve(capacity);
                capacity = grown;
            }
            let want = (capacity - data.len()).min(MAX_CHUNK);
            let start = data.len();
            // `resize` rather than an uninitialised spare: the read fills
            // initialised memory, and whatever the syscall does not write is
            // truncated away below. Reads of a sparse or procfs file routinely
            // return fewer bytes than asked for.
            data.resize(start + want, 0);
            match fsops::read(fd, &mut data[start..], -1) {
                Ok(0) => {
                    data.truncate(start);
                    break;
                }
                Ok(count) => data.truncate(start + count),
                Err(mut error) => {
                    data.truncate(start);
                    error.syscall = "read";
                    failure = Some(error);
                    break;
                }
            }
        }

        let close_error = fsops::close(fd).err();
        match failure {
            // Node keeps `close_error_` for the success path only; a read failure
            // is reported as itself and the buffer is dropped.
            Some(error) => ReadOutcome::Failed(error),
            None => ReadOutcome::Done { data, close_error },
        }
    }
}

/// `fsBinding.ReadFileJob`.
pub struct ReadFileJob {
    parameters: Mutex<Option<ReadParams>>,
}

impl ReadFileJob {
    /// `new ReadFileJob(path, flags, limit, trackFd)`.
    ///
    /// The limit arrives as a `double` (`args[2]->IsNumber()`), and `New` clamps
    /// a negative one to 0 — which makes every file "larger than the limit", so
    /// the descriptor comes back and the chunked reader runs.
    pub fn new(path: Vec<u8>, flags: i32, limit: f64, track_fd: bool) -> Self {
        let limit = if limit.is_finite() && limit >= 0.0 {
            limit as u64
        } else {
            0
        };
        Self {
            parameters: Mutex::new(Some(ReadParams {
                path,
                flags,
                limit,
                track_fd,
            })),
        }
    }

    fn take(&self) -> Option<ReadParams> {
        self.parameters.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// `fsBinding.WriteFileJob`.
pub struct WriteFileJob {
    parameters: Mutex<Option<WriteParams>>,
}

/// The parameters a `WriteFileJob` carries from its constructor to the pool.
struct WriteParams {
    path: Vec<u8>,
    flags: i32,
    mode: u32,
    data: Vec<u8>,
}

impl WriteParams {
    /// `WriteFileJob::DoThreadPoolWork`.
    fn run(&self) -> WriteOutcome {
        let fd = fsops::open(&self.path, self.flags, self.mode)?;
        let mut written = 0;
        let mut failure = None;
        while written < self.data.len() {
            let end = self.data.len().min(written.saturating_add(MAX_CHUNK));
            match fsops::write(fd, &self.data[written..end], -1) {
                // A zero-byte write for a non-empty slice would spin forever, so
                // it is reported rather than retried.
                Ok(0) => {
                    failure = Some(FsError::from_errno("write", libc::EIO));
                    break;
                }
                Ok(count) => written += count,
                Err(mut error) => {
                    error.syscall = "write";
                    failure = Some(error);
                    break;
                }
            }
        }

        let close_error = fsops::close(fd).err();
        match failure {
            // The descriptor opened here is always closed, and a close failure
            // only wins when the write itself succeeded.
            Some(error) => Err(error),
            None => match close_error {
                Some(error) => Err(FsError::new(error.errno, "close")),
                None => Ok(()),
            },
        }
    }
}

impl WriteFileJob {
    /// `new WriteFileJob(path, flags, mode, buffer)`.
    ///
    /// The bytes are copied out of the view here, on the main thread: a resizable
    /// backing store can be shrunk by JavaScript while the pool thread reads it,
    /// and the copy is what keeps the pool on memory that cannot move.
    pub fn new(path: Vec<u8>, flags: i32, mode: u32, data: Vec<u8>) -> Self {
        Self {
            parameters: Mutex::new(Some(WriteParams {
                path,
                flags,
                mode,
                data,
            })),
        }
    }

    fn take(&self) -> Option<WriteParams> {
        self.parameters.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// A job class this module can queue.
///
/// The two classes differ only in their parameters, their outcome and how that
/// outcome becomes the argument list `ondone` receives, so the queueing, the
/// rooting and the teardown are written once here.
trait FsJob: Send + 'static {
    type Outcome: Send + 'static;

    /// The flag word the job would open its path with, for the permission check
    /// `run()` performs before scheduling.
    fn flags(&self) -> i32;

    /// Runs the syscalls. Called on a pool thread, so it may not touch V8.
    fn perform(&self) -> Self::Outcome;

    /// Turns the outcome into `ondone`'s arguments, on the loop thread.
    fn deliver<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        outcome: Self::Outcome,
    ) -> Vec<v8::Local<'s, v8::Value>>;
}

impl FsJob for ReadFileJob {
    type Outcome = ReadOutcome;

    fn flags(&self) -> i32 {
        self.parameters
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().map(|parameters| parameters.flags))
            .unwrap_or(0)
    }

    fn perform(&self) -> Self::Outcome {
        match self.take() {
            Some(parameters) => parameters.run(),
            // `run()` takes the parameters, so a second call has nothing left.
            // Node's `CHECK(!job->scheduled_)` aborts the process; reporting an
            // error keeps a JavaScript caller alive to see it.
            None => ReadOutcome::Failed(FsError::from_errno("read", libc::EINVAL)),
        }
    }

    fn deliver<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        outcome: Self::Outcome,
    ) -> Vec<v8::Local<'s, v8::Value>> {
        let null: v8::Local<'s, v8::Value> = v8::null(scope).into();
        let undefined: v8::Local<'s, v8::Value> = v8::undefined(scope).into();
        let negative_one: v8::Local<'s, v8::Value> = v8::Integer::new(scope, -1).into();
        match outcome {
            ReadOutcome::Failed(error) => vec![
                error_value(scope, &error),
                undefined,
                negative_one,
                undefined,
                undefined,
            ],
            ReadOutcome::TooLarge { fd, size, track_fd } => {
                // Node calls `env->AddUnmanagedFd(fd)` here when `trackFd` was
                // set, so its "file descriptor leaked" diagnostic does not
                // blame a descriptor `lib/fs.js` is about to close through
                // `fs.close()`. This runtime has no such registry, so there is
                // nothing to register with; the flag is read so the hand-back
                // path stays the one place a future registry has to touch.
                let _ = track_fd;
                vec![
                    null,
                    undefined,
                    v8::Integer::new(scope, fd).into(),
                    v8::Number::new(scope, size as f64).into(),
                    undefined,
                ]
            }
            ReadOutcome::Done { data, close_error } => {
                let buffer = buffer_from(scope, &data).unwrap_or(undefined);
                let close = match close_error {
                    Some(error) => error_value(scope, &error),
                    None => undefined,
                };
                vec![null, buffer, negative_one, undefined, close]
            }
        }
    }
}

impl FsJob for WriteFileJob {
    type Outcome = WriteOutcome;

    fn flags(&self) -> i32 {
        self.parameters
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().map(|parameters| parameters.flags))
            .unwrap_or(0)
    }

    fn perform(&self) -> Self::Outcome {
        match self.take() {
            Some(parameters) => parameters.run(),
            None => Err(FsError::from_errno("write", libc::EINVAL)),
        }
    }

    fn deliver<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        outcome: Self::Outcome,
    ) -> Vec<v8::Local<'s, v8::Value>> {
        match outcome {
            Ok(()) => vec![v8::null(scope).into()],
            Err(error) => vec![error_value(scope, &error)],
        }
    }
}

/// Builds the error value a completion carries.
///
/// Distinct from `request::throw_error`, which throws: here the error is an
/// argument, and `lib/fs.js` decides what to do with it.
fn error_value<'s>(scope: &mut v8::PinScope<'s, '_>, error: &FsError) -> v8::Local<'s, v8::Value> {
    match crate::request::error_object(scope, error) {
        Some(value) => value,
        // A failed allocation leaves V8 with an exception pending, so the
        // argument list is short by one value; `undefined` at least keeps the
        // arity `readFileAfterOneShot` destructures.
        None => v8::undefined(scope).into(),
    }
}

/// The permission refusal `run()` returns instead of queueing.
///
/// Node's `ReadFileJob::OpenPermissionError` runs the same two checks
/// `AsyncCheckOpenPermissions` would for an `open` and returns the error object
/// rather than rejecting a request wrap, because `lib/fs.js` hands it straight
/// to the user callback.
pub fn open_denied(path: &PathBytes, flags: i32) -> Option<rn_permission::AccessDeniedError> {
    permission::deny_open(path, flags)
}

/// The state an in-flight job needs, owned by its `uv_work_t`.
///
/// Boxed rather than stored on the JavaScript object because the pool thread
/// writes the outcome and the loop thread reads it after the object may already
/// be unreachable.
struct Queued<J: FsJob> {
    /// Taken by the work callback and put back for `deliver`.
    job: Mutex<Option<J>>,
    /// Written by the work callback, taken by the loop callback.
    outcome: Mutex<Option<J::Outcome>>,
    /// The `ondone` property, rooted while the work is in flight.
    ondone: Mutex<Option<v8::Global<v8::Function>>>,
    /// The job object, which `ondone` is invoked on: `readFileAfterOneShot`
    /// reads `this.context`, which `lib/fs.js` assigned to that same object.
    receiver: Mutex<Option<v8::Global<v8::Object>>>,
    /// The continuation-preserved embedder data at the moment `run()` was
    /// called, rooted.
    ///
    /// Node's `AsyncWrap` makes each resource carry its creator's `AsyncContext`
    /// and `MakeCallback` restores it around the completion, which is what makes
    /// `process.domain` and `AsyncLocalStorage.getStore()` inside an `fs`
    /// callback answer with the scope that started the call. A `uv_queue_work`
    /// completion is *not* a promise continuation and *not* a timer, so V8
    /// restores nothing here on its own: without this, `fs.readFile` inside
    /// `domain.run` delivers with `process.domain === null`. `setTimeout`
    /// appears to work because libuv's timer callback is driven by the JS timer
    /// machinery that does preserve the frame.
    frame: Mutex<Option<v8::Global<v8::Value>>>,
}

thread_local! {
    /// `uv_work_t` addresses with work still in flight, so the number of live
    /// jobs is observable to the tests.
    ///
    /// A thread-local set keyed by the request address, because that address is
    /// the identity libuv hands back and every job is queued from this thread.
    static IN_FLIGHT: std::cell::RefCell<std::collections::HashSet<usize>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

/// How many file jobs are queued or running on this thread's loop.
pub fn in_flight() -> usize {
    IN_FLIGHT.with(|slot| slot.borrow().len())
}

/// Queues `job` on the process loop.
///
/// `Ok(())` means the completion will arrive through `ondone`. `Err(error)` means
/// nothing was scheduled and `run()` must return that value.
fn schedule<'s, J: FsJob>(
    scope: &mut v8::PinScope<'s, '_>,
    job: J,
    receiver: v8::Global<v8::Object>,
    ondone: v8::Global<v8::Function>,
) -> Result<(), String> {
    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        return Err("no event loop for the file job".to_string());
    };

    // Captured on the thread that called `run()`, before any work is queued: it
    // has to describe the caller's scope, not whatever runs later.
    let frame = v8::Global::new(
        scope.as_ref(),
        scope.get_continuation_preserved_embedder_data(),
    );

    let state = Box::into_raw(Box::new(Queued::<J> {
        job: Mutex::new(Some(job)),
        outcome: Mutex::new(None),
        ondone: Mutex::new(Some(ondone)),
        receiver: Mutex::new(Some(receiver)),
        frame: Mutex::new(Some(frame)),
    }));

    let mut request: Box<libuv_sys2::uv_work_t> = Box::new(unsafe { std::mem::zeroed() });
    request.data = state.cast();
    let request = Box::into_raw(request);
    IN_FLIGHT.with(|slot| {
        slot.borrow_mut().insert(request as usize);
    });
    // Also visible to the exit path, which cancels it if `process.exit()` runs
    // while this job is still queued.
    rn_uv::threadpool::register(request);

    // SAFETY: `loop_pointer` is the process loop, which outlives the request;
    // `request` is heap-allocated and stays valid until the after-work callback
    // frees it.
    let queued = unsafe {
        libuv_sys2::uv_queue_work(
            loop_pointer,
            request,
            Some(work_trampoline::<J>),
            Some(after_work_trampoline::<J>),
        )
    };
    if queued == 0 {
        return Ok(());
    }

    // The loop refused the work, so no completion will arrive. Both boxes are
    // freed here and the refusal is reported inline, which keeps `run()`'s
    // contract: either it returns an error or `ondone` is called exactly once.
    IN_FLIGHT.with(|slot| slot.borrow_mut().remove(&(request as usize)));
    rn_uv::threadpool::unregister(request);
    // SAFETY: neither box was handed on; libuv took no ownership on failure.
    unsafe {
        drop(Box::from_raw(state));
        drop(Box::from_raw(request));
    }
    Err("cannot queue the file job".to_string())
}

/// The threadpool half: performs the syscalls off the main thread.
///
/// # Safety
///
/// `request` must be the `uv_work_t` [`schedule`] allocated, whose `data` is the
/// `Queued<J>` box for this job.
unsafe extern "C" fn work_trampoline<J: FsJob>(request: *mut libuv_sys2::uv_work_t) {
    // SAFETY: per the contract above, `data` is the box `schedule` created.
    let state = unsafe { &*((*request).data as *mut Queued<J>) };
    let Some(job) = state.job.lock().ok().and_then(|mut slot| slot.take()) else {
        // Taken twice would be a libuv contract violation; there is nothing to
        // run and the loop callback will find no outcome.
        return;
    };
    let outcome = job.perform();
    if let Ok(mut slot) = state.outcome.lock() {
        *slot = Some(outcome);
    }
    if let Ok(mut slot) = state.job.lock() {
        *slot = Some(job);
    }
}

/// The loop half: turns the outcome into arguments and calls `ondone`.
///
/// # Safety
///
/// As [`work_trampoline`].
unsafe extern "C" fn after_work_trampoline<J: FsJob>(
    request: *mut libuv_sys2::uv_work_t,
    status: std::ffi::c_int,
) {
    // SAFETY: `state` and `request` were created by `schedule` and are freed
    // here, exactly once, now that no other callback will use them.
    let state = unsafe { Box::from_raw((*request).data as *mut Queued<J>) };
    IN_FLIGHT.with(|slot| slot.borrow_mut().remove(&(request as usize)));
    rn_uv::threadpool::unregister(request);
    unsafe { drop(Box::from_raw(request)) };

    // `UV_ECANCELED` means the loop shut down before the work ran. Node returns
    // without calling back there, and matching it keeps a cancelled job from
    // delivering into a runtime that is already tearing down.
    if status == libuv_sys2::uv_errno_t_UV_ECANCELED {
        return;
    }

    let outcome = state.outcome.lock().ok().and_then(|mut slot| slot.take());
    let ondone = state.ondone.lock().ok().and_then(|mut slot| slot.take());
    let receiver = state.receiver.lock().ok().and_then(|mut slot| slot.take());
    let job = state.job.lock().ok().and_then(|mut slot| slot.take());
    let frame = state.frame.lock().ok().and_then(|mut slot| slot.take());
    let (Some(outcome), Some(ondone), Some(receiver), Some(job), Some(frame)) =
        (outcome, ondone, receiver, job, frame)
    else {
        return;
    };

    // The completion runs inside `uv_run`, which has no V8 scope and no entered
    // context, so this goes through the primitive the socket bindings use.
    rn_uv::callback::with_context(|scope| {
        // Node's `AsyncWrap`/`MakeCallback` restore the creator's async context
        // around `ondone`, so `process.domain` and `AsyncLocalStorage` read the
        // scope that called `run()`. A threadpool completion restores nothing by
        // itself, so the frame captured at `run()` is installed here and the
        // previous one put back afterwards.
        let previous = scope.get_continuation_preserved_embedder_data();
        scope.set_continuation_preserved_embedder_data(v8::Local::new(scope, &frame));

        let arguments = job.deliver(scope, outcome);
        let callback: v8::Local<v8::Function> = v8::Local::new(scope, &ondone);
        let target: v8::Local<v8::Object> = v8::Local::new(scope, &receiver);
        let _ = callback.call(&*scope, target.into(), &arguments);

        scope.set_continuation_preserved_embedder_data(previous);
    });
}

/// Builds a real `Buffer` over `bytes`.
///
/// `Buffer.from(arrayBuffer, 0, length)` off the global `Buffer`, rather than a
/// bare `Uint8Array`: `lib/fs.js` calls `.toString(encoding)` on the result and
/// `Buffer.isBuffer` is asserted by callers of `fs.readFile`.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let buffer = buffer_constructor(scope)?;
    let from_key = v8::String::new(scope, "from")?;
    let from = buffer.get(scope, from_key.into())?;
    let from = v8::Local::<v8::Function>::try_from(from).ok()?;
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, i32::try_from(bytes.len()).ok()?);
    let called = from.call(
        scope,
        buffer.into(),
        &[array_buffer.into(), start.into(), length.into()],
    )?;
    called.is_object().then_some(called)
}

/// The global `Buffer` constructor object.
fn buffer_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Reads a function-valued property.
fn property_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Function>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    v8::Local::<v8::Function>::try_from(value).ok()
}

/// Installs a job constructor with `run()` on its prototype.
///
/// The internal field is reserved here because `set_aligned_pointer_in_internal_field`
/// in the constructor has nowhere to write without it, and `run()` reads that
/// same field back.
pub fn install_job_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    constructor: impl v8::MapFnTo<v8::FunctionCallback>,
    run: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(JOB_FIELD as usize + 1);
    let prototype = template.prototype_template(scope);
    let Some(key) = v8::String::new(scope, "run") else {
        return Err(format!("cannot allocate {name}.run"));
    };
    prototype.set(
        key.into(),
        v8::FunctionTemplate::builder(run).build(scope).into(),
    );
    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    let Some(key) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} property name"));
    };
    target.set(scope, key.into(), function.into());
    Ok(())
}

/// Stores a job on the instance it was constructed for.
///
/// `run()` only receives `this`, so the parameters live in an internal field
/// with a finalizer that frees them when the object becomes unreachable —
/// including when `run()` was never called, which is the case for a job the
/// JavaScript dropped on the floor.
fn install_job<J: 'static>(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    job: J,
) -> bool {
    let boxed = Box::new(Mutex::new(Some(job)));
    let pointer = Box::into_raw(boxed);
    object.set_aligned_pointer_in_internal_field(
        JOB_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut Mutex<Option<J>>;
            // SAFETY: allocated just above for this object alone, freed once by
            // the finalizer V8 guarantees to run.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    true
}

/// Takes the job out of `this`, leaving the instance spent.
///
/// # Safety
///
/// `this` must be an instance of the class whose constructor called
/// [`install_job`] with the same `J`.
unsafe fn take_job<J: 'static>(this: v8::Local<v8::Object>) -> Option<J> {
    // SAFETY: field 0 is the box `install_job` created for this object, and the
    // finalizer that frees it runs only once the object is unreachable, which it
    // is not while `this` is a live argument.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(JOB_FIELD, 0) }
        as *const Mutex<Option<J>>;
    if pointer.is_null() {
        return None;
    }
    let cell = unsafe { &*pointer };
    cell.lock().ok().and_then(|mut slot| slot.take())
}

/// `new ReadFileJob(path, flags, limit, trackFd)`.
pub fn read_file_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // `CHECK_GE(args.Length(), 3)`, `CHECK(args[1]->IsInt32())` and
    // `CHECK(args[2]->IsNumber())` in Node abort on a bad shape. The JS layer
    // always passes them, so a mismatch means a direct binding caller got it
    // wrong, and a `TypeError` is more useful there than a crash.
    let (Some(path), Some(flags), Some(limit)) = (
        crate::args::path_bytes(scope, args.get(0)),
        crate::args::int32(scope, args.get(1)),
        args.get(2).number_value(scope),
    ) else {
        throw_invalid_arguments(scope, &mut rv);
        return;
    };
    let track_fd = args.length() > 3 && args.get(3).is_true();
    let this: v8::Local<v8::Object> = args.this();
    install_job(scope, this, ReadFileJob::new(path, flags, limit, track_fd));
    rv.set(this.into());
}

/// `new WriteFileJob(path, flags, mode, buffer)`.
pub fn write_file_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let (Some(path), Some(flags), Some(mode)) = (
        crate::args::path_bytes(scope, args.get(0)),
        crate::args::int32(scope, args.get(1)),
        crate::args::uint32(scope, args.get(2)),
    ) else {
        throw_invalid_arguments(scope, &mut rv);
        return;
    };
    // `CHECK(args[3]->IsArrayBufferView())`: the buffer is required, because
    // `lib/fs.js` converts a string to a Buffer before constructing the job.
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(3)) else {
        throw_invalid_arguments(scope, &mut rv);
        return;
    };
    let mut data = vec![0u8; view.byte_length()];
    // `copy_contents` writes at most `data.len()` bytes and reports how many it
    // wrote, which is the view's byte length for a well-formed view.
    let copied = view.copy_contents(&mut data);
    data.truncate(copied);

    let this: v8::Local<v8::Object> = args.this();
    install_job(scope, this, WriteFileJob::new(path, flags, mode, data));
    rv.set(this.into());
}

/// Reports a constructor call whose arguments do not fit the class.
fn throw_invalid_arguments(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue) {
    if let Some(text) = v8::String::new(scope, "invalid arguments for the file job") {
        rv.set(v8::Exception::type_error(scope, text));
    }
}

/// `run(path)` for either job class.
///
/// Shared because the two differ only in [`FsJob`]: the permission check, the
/// queueing and the "scheduled means undefined" answer are identical, and
/// duplicating them is how the two paths drift apart.
fn run_job<'s, J: FsJob>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    rv: &mut v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    // SAFETY: `run` is on the prototype of the class whose constructor installed
    // the job, so `this` is an instance of it.
    let Some(job) = (unsafe { take_job::<J>(this) }) else {
        // `run()` only reaches here once; a second call finds no job, which is
        // Node's `CHECK(!job->scheduled_)` turned into a reportable error.
        if let Some(text) = v8::String::new(scope, "the job already ran") {
            rv.set(v8::Exception::type_error(scope, text));
        }
        return;
    };

    // Both `Run` methods re-read the path from *their own* argument rather than
    // the constructor's, so a caller that swapped the path between the two is
    // judged on the one it is scheduling.
    let Some(path) = crate::args::path_bytes(scope, args.get(0)) else {
        if let Some(text) = v8::String::new(scope, "the file job needs a path") {
            rv.set(v8::Exception::type_error(scope, text));
        }
        return;
    };

    if let Some(denied) = open_denied(&path, job.flags()) {
        // Nothing is scheduled; `lib/fs.js` passes this straight to the callback.
        rv.set(denied.to_value(scope));
        return;
    }

    let Some(ondone) = property_function(scope, this, "ondone") else {
        // Without `ondone` there is nowhere to deliver, so nothing is queued.
        if let Some(text) = v8::String::new(scope, "the file job has no ondone callback") {
            rv.set(v8::Exception::type_error(scope, text));
        }
        return;
    };

    let receiver = v8::Global::new(scope.as_ref(), this);
    let ondone = v8::Global::new(scope.as_ref(), ondone);
    match schedule(scope, job, receiver, ondone) {
        // Queued: `lib/fs.js` reads `undefined` as "nothing to report".
        Ok(()) => rv.set_undefined(),
        Err(message) => {
            if let Some(text) = v8::String::new(scope, &message) {
                rv.set(v8::Exception::error(scope, text));
            }
        }
    }
}

/// `ReadFileJob.prototype.run(path)`.
pub fn read_file_run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    run_job::<ReadFileJob>(scope, &args, &mut rv);
}

/// `WriteFileJob.prototype.run(path)`.
pub fn write_file_run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    run_job::<WriteFileJob>(scope, &args, &mut rv);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_negative_limit_clamps_to_zero_like_nodes_new() {
        // `limit < 0 ? 0 : static_cast<uint64_t>(limit)`: with a zero limit every
        // file is larger than it, so the descriptor comes back and the chunked
        // reader runs. Clamping to `u64::MAX` instead would read everything in a
        // single allocation.
        let job = ReadFileJob::new(b"/tmp/x".to_vec(), 0, -1.0, false);
        assert_eq!(job.take().expect("parameters").limit, 0);
    }

    #[test]
    fn the_limit_is_read_from_a_double() {
        // `args[2]->IsNumber()`: the JS passes `kReadFileBufferLength` (512 KiB)
        // as a double, and truncating it must not round up past the value the
        // chunked reader assumes.
        let job = ReadFileJob::new(b"/tmp/x".to_vec(), 0, 512.0 * 1024.0, true);
        let parameters = job.take().expect("parameters");
        assert_eq!(parameters.limit, 512 * 1024);
        assert!(parameters.track_fd);
    }

    #[test]
    fn a_job_yields_its_parameters_once() {
        // `run()` takes them; a second `run()` has nothing to schedule, which is
        // the Rust equivalent of Node's `CHECK(!job->scheduled_)`.
        let job = ReadFileJob::new(b"/tmp/x".to_vec(), 0, 0.0, false);
        assert!(job.take().is_some());
        assert!(job.take().is_none());
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rn-fs-job-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn bytes_of(path: &std::path::Path) -> Vec<u8> {
        std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).to_vec()
    }

    #[test]
    fn an_empty_file_reads_as_an_empty_buffer() {
        let dir = scratch_dir("empty");
        let path = dir.join("empty");
        std::fs::write(&path, b"").expect("write");

        let parameters = ReadParams {
            path: bytes_of(&path),
            flags: 0,
            limit: 512 * 1024,
            track_fd: false,
        };
        match parameters.run() {
            ReadOutcome::Done { data, close_error } => {
                assert!(data.is_empty(), "an empty file has no bytes");
                assert!(close_error.is_none(), "close must succeed");
            }
            _ => panic!("an empty regular file is read, not handed back"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_above_the_limit_hands_back_the_descriptor_and_its_size() {
        // This is the `fd >= 0` row of `readFileAfterOneShot`. Without it every
        // file above the limit is truncated to its first chunk.
        let dir = scratch_dir("large");
        let path = dir.join("large");
        std::fs::write(&path, vec![b'x'; 64]).expect("write");

        let parameters = ReadParams {
            path: bytes_of(&path),
            flags: 0,
            limit: 8,
            track_fd: true,
        };
        match parameters.run() {
            ReadOutcome::TooLarge { fd, size, track_fd } => {
                assert_eq!(size, 64, "the size is the file's, not the limit's");
                assert!(track_fd, "the constructor's trackFd reaches the outcome");
                assert!(fd >= 0, "the caller owns the descriptor");
                // The caller closes it, exactly as `context.close()` would.
                fsops::close(fd).expect("close the handed-back fd");
            }
            _ => panic!("a file above the limit must hand back its descriptor"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_whole_file_is_read_when_it_fits_under_the_limit() {
        let dir = scratch_dir("fit");
        let path = dir.join("content");
        let content = vec![b'a'; 200];
        std::fs::write(&path, &content).expect("write");

        let parameters = ReadParams {
            path: bytes_of(&path),
            flags: 0,
            limit: 512 * 1024,
            track_fd: false,
        };
        match parameters.run() {
            ReadOutcome::Done { data, .. } => assert_eq!(data, content),
            _ => panic!("a small file is read in one pass"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_multi_chunk_write_lands_whole_and_survives_a_read_back() {
        // The write loop has to keep going until every byte is out; a single
        // `write` call can return short.
        let dir = scratch_dir("write");
        let path = dir.join("out");
        let bytes = vec![b'z'; 4096];

        let job = WriteFileJob::new(
            bytes_of(&path),
            crate::flags::uv_flags::O_CREAT
                | crate::flags::uv_flags::O_TRUNC
                | crate::flags::uv_flags::O_WRONLY,
            0o666,
            bytes.clone(),
        );
        job.perform().expect("the write succeeds");
        assert_eq!(std::fs::read(&path).expect("read back"), bytes);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_path_fails_with_open_as_the_syscall() {
        let parameters = ReadParams {
            path: b"/definitely/not/here/rn-fs-job".to_vec(),
            flags: 0,
            limit: 512 * 1024,
            track_fd: false,
        };
        match parameters.run() {
            ReadOutcome::Failed(error) => {
                assert_eq!(error.syscall, "open");
                assert_eq!(error.code(), "ENOENT");
            }
            _ => panic!("a missing path must fail"),
        }
    }

    #[test]
    fn a_write_job_reports_the_syscall_that_failed() {
        let job = WriteFileJob::new(
            b"/definitely/not/here/out".to_vec(),
            crate::flags::uv_flags::O_CREAT | crate::flags::uv_flags::O_WRONLY,
            0o666,
            b"x".to_vec(),
        );
        let error = job.perform().expect_err("the open fails");
        assert_eq!(error.syscall, "open");
        assert_eq!(error.code(), "ENOENT");
    }
}
