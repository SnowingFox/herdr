//! `backup(sourceDb, path[, options])`: one database copied onto a file.
//!
//! `Backup` and `BackupJob` in `src/node_sqlite.cc` are the specification, and
//! the shape they prescribe is the whole point of the function:
//!
//! * It returns a **`Promise`**. Copying a large database takes real time, so
//!   the pages move on libuv's threadpool and the loop keeps serving timers,
//!   I/O and other JavaScript meanwhile. A synchronous implementation would
//!   answer every observable question differently: the return type, when the
//!   progress callback runs, and whether a locked source lets anything else run
//!   at all.
//! * It steps through the copy `rate` pages at a time with
//!   `sqlite3_backup_step` and re-queues itself after each step, so a
//!   `SQLITE_BUSY`/`SQLITE_LOCKED` source is retried rather than failed. That is
//!   what makes `backup()` wait for a write transaction to commit instead of
//!   rejecting, and re-queueing between attempts is what keeps it from
//!   deadlocking: control returns to the loop, so the code that will commit the
//!   transaction gets to run.
//! * It reports progress between steps and rejects with the callback's own
//!   exception when that callback throws.
//!
//! # Handle ownership
//!
//! SQLite requires `sqlite3_backup_finish` for every successful
//! `sqlite3_backup_init`, whatever the step result was, and the destination
//! connection must outlive the backup. Both are owned by [`BackupState`] and
//! released together in [`BackupState::finish`], which every exit path calls
//! before settling the promise, error paths included.
//!
//! # Why the source object is rooted
//!
//! The pool thread reads the source connection, so the `Database` that owns it
//! must not be collected mid-copy. Node holds a `BaseObjectPtr<Database>`; here
//! the source `Database` *object* is held in a `v8::Global`, which keeps its
//! finalizer from running and therefore keeps the boxed
//! [`crate::db::DatabaseState`] alive for the duration. That is the regression
//! `test-sqlite-backup.mjs` calls "source database is kept alive while a backup
//! is in flight".
//!
//! # Threads
//!
//! `sqlite3_backup_step` runs on a pool thread while the main thread may still
//! use the source connection, exactly as Node's does. That is safe because the
//! vendored amalgamation is built with `SQLITE_THREADSAFE=1` (`build.rs`), which
//! serialises access through the connection's own mutex.

use std::ffi::CString;
use std::os::raw::c_int;
use std::sync::Mutex;

use rn_v8_sys::v8;

use crate::db;
use crate::errors;
use crate::ffi;

/// `rate`'s default: how many pages one step copies.
const DEFAULT_RATE: i32 = 100;

/// The destination connection, owned by the backup until [`BackupState::finish`].
///
/// A newtype rather than a bare pointer so the two handles cannot be swapped at
/// a call site, and so it is obvious which one `sqlite3_close_v2` takes.
struct Destination(*mut ffi::sqlite3);

/// The `sqlite3_backup` handle, owned by the backup until [`BackupState::finish`].
struct BackupHandle(*mut ffi::sqlite3_backup);

/// Everything one in-flight backup owns, freed when its promise settles.
///
/// Boxed and reached by raw pointer rather than stored on a JavaScript object:
/// the pool thread writes [`Self::last_status`] and the loop thread reads it
/// after the object that started the backup may already be unreachable.
struct BackupState {
    /// The promise this backup settles, exactly once.
    resolver: v8::Global<v8::PromiseResolver>,
    /// `options.progress`, called between steps when it is present.
    progress: Option<v8::Global<v8::Function>>,
    /// The source `Database` object, rooted so the connection outlives the copy.
    ///
    /// Never read. Holding the handle is the point: it stops V8 from running the
    /// `Database`'s finalizer, which is what would free the boxed
    /// [`crate::db::DatabaseState`] the pool thread is reading.
    _source: v8::Global<v8::Object>,
    /// The destination connection this backup opened.
    destination: Destination,
    /// The handle `sqlite3_backup_step` advances.
    backup: BackupHandle,
    /// `options.rate`: pages copied per step.
    pages: c_int,
    /// The result of the last step, written on a pool thread.
    last_status: Mutex<c_int>,
}

impl BackupState {
    /// `BackupJob::Cleanup`: finish the backup, then close what it opened.
    ///
    /// The order is load-bearing. `sqlite3_close_v2` on a connection with an
    /// unfinished backup turns it into a zombie SQLite frees only once the
    /// backup is finished, so closing first would leave the backup handle
    /// pointing at a connection this code no longer owns.
    fn finish(&mut self) {
        if !self.backup.0.is_null() {
            // SAFETY: the handle came from a successful `sqlite3_backup_init`
            // and is finished exactly once, here.
            unsafe { ffi::sqlite3_backup_finish(self.backup.0) };
            self.backup.0 = std::ptr::null_mut();
        }
        if !self.destination.0.is_null() {
            // SAFETY: the connection came from `sqlite3_open_v2` in
            // [`schedule`] and is closed exactly once, here.
            unsafe { ffi::sqlite3_close_v2(self.destination.0) };
            self.destination.0 = std::ptr::null_mut();
        }
    }
}

/// A SQLite failure reduced to the three fields the error object carries.
///
/// Both constructors mirror a `CreateSQLiteError` overload: one takes the
/// connection the failure happened on, the other only a result code.
struct SqliteFailure {
    message: String,
    errstr: String,
    errcode: c_int,
}

impl SqliteFailure {
    /// `CreateSQLiteError(isolate, int errcode)`: both strings come from the code.
    fn from_code(code: c_int) -> Self {
        // SAFETY: `errstr` returns static text for any code.
        let errstr = unsafe { errors::c_string(ffi::sqlite3_errstr(code)) };
        Self {
            message: errstr.clone(),
            errstr,
            errcode: code,
        }
    }

    /// `CreateSQLiteError(isolate, sqlite3* db)`: everything comes from the
    /// connection, which must still be open when this is called.
    fn from_connection(db: *mut ffi::sqlite3) -> Self {
        if db.is_null() {
            return Self::from_code(ffi::SQLITE_ERROR);
        }
        // SAFETY: `db` is a live connection this backup opened and has not
        // closed yet; both accessors only read connection state.
        unsafe {
            let errcode = ffi::sqlite3_extended_errcode(db);
            Self {
                message: errors::c_string(ffi::sqlite3_errmsg(db)),
                errstr: errors::c_string(ffi::sqlite3_errstr(errcode)),
                errcode,
            }
        }
    }

    /// The `Error` this failure becomes.
    fn into_value<'s>(self, scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
        errors::sqlite_error(scope, &self.message, &self.errstr, self.errcode)
    }
}

/// `backup(sourceDb, path[, options])`.
///
/// Every check runs in `Backup`'s order, and the open state is checked twice:
/// reading the options bag can run a property getter, and that getter may close
/// the source database. The second check is what makes
/// `test-sqlite-options-getter-reentry.js`'s `backup()` case throw instead of
/// handing a closed connection to `sqlite3_backup_init`.
pub fn backup<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    // `!args[0]->IsObject() || !HasInstance(args[0])`. `is_database` answers the
    // template question Node's `HasInstance` asks, which rejects a `Statement`, a
    // `Session`, `Object.create(Database.prototype)` and a `Proxy` around a real
    // instance — and accepts a subclass, whose instances really are allocated
    // from this class's template.
    let Some(pointer) = db::is_database(args.get(0)) else {
        invalid_source(scope);
        return;
    };
    let Ok(source_object) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        invalid_source(scope);
        return;
    };
    // SAFETY: `is_database` returned a live pointer for this object, and the
    // borrow ends before any JavaScript can run below.
    if !errors::require(
        scope,
        unsafe { (*pointer).is_open() },
        "database is not open",
    ) {
        return;
    }

    let Some(destination_path) = db::path_argument(scope, args.get(1), "path") else {
        return;
    };

    let mut rate = DEFAULT_RATE;
    let mut source_db = "main".to_string();
    let mut target_db = "main".to_string();
    let mut progress = None;
    let options = args.get(2);
    if !options.is_undefined() {
        let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
            errors::throw_type(scope, "The \"options\" argument must be an object.");
            return;
        };
        // `Backup`'s order: `rate`, then `source`, then `target`, then
        // `progress`. A getter may close the database here, which the second
        // open check below catches.
        if !read_rate(scope, options, &mut rate)
            || !db::optional_string(scope, options, "source", &mut source_db)
            || !db::optional_string(scope, options, "target", &mut target_db)
            || !read_progress(scope, options, &mut progress)
        {
            return;
        }
    }

    // SAFETY: as above; re-read because the options getters above ran user code
    // that may have closed the database.
    let open = unsafe { (*pointer).is_open() };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    // SAFETY: as above. The handle is copied out rather than borrowed, because
    // the backup outlives this call; rooting the source object for the same span
    // is what keeps it valid.
    let source_handle = unsafe { (*pointer).raw() };
    if source_handle.is_null() {
        errors::throw_coded(scope, "ERR_INVALID_STATE", "database is not open");
        return;
    }

    let Ok(destination_c) = CString::new(destination_path) else {
        // The path argument already rejects null bytes, so reaching this means
        // the check and the use disagreed; reporting it beats opening a
        // different file than the caller named.
        errors::throw_type(
            scope,
            "The \"path\" argument must be a string, Uint8Array, or URL without null bytes.",
        );
        return;
    };
    let (Ok(source_c), Ok(target_c)) = (CString::new(source_db), CString::new(target_db)) else {
        errors::throw_type(scope, "The database name must not contain a null byte.");
        return;
    };

    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        return;
    };
    // The promise is returned before anything can fail: `Backup` sets
    // `GetReturnValue()` and then lets `ScheduleBackup` reject it, so the caller
    // always holds a promise rather than having to distinguish a throw from a
    // rejection.
    rv.set(resolver.get_promise(scope).into());

    schedule(
        scope,
        resolver,
        source_object,
        source_handle,
        &destination_c,
        &source_c,
        &target_c,
        rate,
        progress,
    );
}

/// `BackupJob::ScheduleBackup`: open the destination, initialise the handle, and
/// queue the first step.
///
/// Every failure from here on rejects the promise the caller already holds.
#[allow(
    clippy::too_many_arguments,
    reason = "the argument list is `Backup`'s own, kept in its order"
)]
fn schedule(
    scope: &mut v8::PinScope<'_, '_>,
    resolver: v8::Local<'_, v8::PromiseResolver>,
    source_object: v8::Local<'_, v8::Object>,
    source_handle: *mut ffi::sqlite3,
    destination_c: &CString,
    source_c: &CString,
    target_c: &CString,
    pages: i32,
    progress: Option<v8::Local<'_, v8::Function>>,
) {
    let mut raw_destination: *mut ffi::sqlite3 = std::ptr::null_mut();
    // SAFETY: `destination_c` outlives the call and `raw_destination` is an
    // out-parameter SQLite writes. On failure it still sets a handle, which is
    // what the error below reads its message from.
    let opened = unsafe {
        ffi::sqlite3_open_v2(
            destination_c.as_ptr(),
            &mut raw_destination,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_URI,
            std::ptr::null(),
        )
    };
    let mut state = BackupState {
        resolver: v8::Global::new(scope.as_ref(), resolver),
        progress: progress.map(|function| v8::Global::new(scope.as_ref(), function)),
        _source: v8::Global::new(scope.as_ref(), source_object),
        destination: Destination(raw_destination),
        backup: BackupHandle(std::ptr::null_mut()),
        pages,
        last_status: Mutex::new(ffi::SQLITE_OK),
    };
    if opened != ffi::SQLITE_OK {
        let value = SqliteFailure::from_connection(state.destination.0).into_value(scope);
        // `state` lives on this stack frame, so it is settled in place rather
        // than through `reject_and_free`, which would `Box::from_raw` a borrow.
        reject_in_place(scope, &mut state, value);
        return;
    }

    // SAFETY: both connections are live, the name pointers outlive the call and
    // the handle out-parameter is written by SQLite. A null result means the
    // init failed and there is nothing to finish.
    let handle = unsafe {
        ffi::sqlite3_backup_init(
            state.destination.0,
            target_c.as_ptr(),
            source_handle,
            source_c.as_ptr(),
        )
    };
    if handle.is_null() {
        let value = SqliteFailure::from_connection(state.destination.0).into_value(scope);
        reject_in_place(scope, &mut state, value);
        return;
    }
    state.backup = BackupHandle(handle);

    let state = Box::into_raw(Box::new(state));
    if !queue_step(state) {
        // SAFETY: `queue_step` refused, so nothing else owns the box.
        let state = unsafe { &mut *state };
        let value = plain_error(scope, "Cannot queue the backup job");
        reject_and_free(scope, state, value);
    }
}

/// Queues one `sqlite3_backup_step` on the process loop.
///
/// A fresh `uv_work_t` per step rather than a reused one: libuv allows reusing a
/// request only after its after-work callback has returned, and a fresh
/// allocation is easier to reason about than a recycling rule the exit path
/// would also have to know.
fn queue_step(state: *mut BackupState) -> bool {
    let Some(loop_pointer) = rn_uv::uv_loop::loop_ptr() else {
        return false;
    };
    let mut request: Box<rn_uv::sys::uv_work_t> = Box::new(unsafe { std::mem::zeroed() });
    request.data = state.cast();
    let request = Box::into_raw(request);
    // Also visible to the exit path, which cancels it if `process.exit()` runs
    // while this step is still queued.
    rn_uv::threadpool::register(request);

    // SAFETY: `loop_pointer` is the process loop, which outlives the request;
    // `request` is heap-allocated and stays valid until the after-work callback
    // frees it.
    let queued = unsafe {
        rn_uv::sys::uv_queue_work(
            loop_pointer,
            request,
            Some(work_trampoline),
            Some(after_work_trampoline),
        )
    };
    if queued == 0 {
        return true;
    }
    rn_uv::threadpool::unregister(request);
    // SAFETY: libuv took no ownership on failure, so this box is still ours.
    unsafe { drop(Box::from_raw(request)) };
    false
}

/// The threadpool half: copies one batch of `rate` pages.
///
/// # Safety
///
/// `request` must be a request [`queue_step`] allocated, whose `data` is the
/// [`BackupState`] box for this backup.
unsafe extern "C" fn work_trampoline(request: *mut rn_uv::sys::uv_work_t) {
    // SAFETY: per the contract above, `data` is the state pointer `queue_step`
    // stored, and libuv calls the work callback exactly once per request.
    let state = unsafe { &*((*request).data as *const BackupState) };
    // SAFETY: the backup handle is live until `finish` runs on the loop thread,
    // which cannot happen while this step is executing.
    let status = unsafe { ffi::sqlite3_backup_step(state.backup.0, state.pages) };
    if let Ok(mut slot) = state.last_status.lock() {
        *slot = status;
    }
}

/// The loop half: reports progress, retries a busy source, or settles.
///
/// # Safety
///
/// As [`work_trampoline`].
unsafe extern "C" fn after_work_trampoline(request: *mut rn_uv::sys::uv_work_t, status: c_int) {
    // SAFETY: the state pointer was stored by `queue_step` for this request and
    // is still owned by this backup, so it is not freed here.
    let state = unsafe { (*request).data as *mut BackupState };
    rn_uv::threadpool::unregister(request);
    // SAFETY: `request` came from `Box::into_raw` in `queue_step`, and this
    // callback is its only owner now.
    unsafe { drop(Box::from_raw(request)) };

    // `UV_ECANCELED` means the loop shut down before the step ran. Node's job
    // simply disappears there, and the process is exiting, so the promise cannot
    // be observed; the state is released without touching V8.
    if status == rn_uv::sys::uv_errno_t_UV_ECANCELED {
        // SAFETY: nothing else references the state now.
        unsafe { drop(Box::from_raw(state)) };
        return;
    }

    let handled = rn_uv::callback::with_context(|scope| settle(scope, state));
    if handled.is_none() {
        // No isolate or context is reachable, so no completion can settle
        // anything. Freeing beats leaking; the process is on its way out.
        // SAFETY: nothing else references the state now.
        unsafe { drop(Box::from_raw(state)) };
    }
}

/// `BackupJob::AfterThreadPoolWork`, plus the single exit point behind it.
///
/// Takes ownership of `state`: every path either re-queues it or frees it.
fn settle(scope: &mut v8::PinScope<'_, '_>, state: *mut BackupState) {
    // SAFETY: the caller transferred ownership of the box.
    let state = unsafe { &mut *state };
    let step_status = match state.last_status.lock() {
        Ok(slot) => *slot,
        Err(poisoned) => *poisoned.into_inner(),
    };

    if is_transient(step_status) {
        // The source is locked by another writer. `Backup` re-queues instead of
        // failing, which is what makes `backup()` wait for a transaction to
        // commit. Going back through the loop between attempts is also what
        // keeps it from deadlocking: the code that will commit runs there.
        requeue_or_reject(scope, state);
        return;
    }

    if step_status != ffi::SQLITE_OK && step_status != ffi::SQLITE_DONE {
        // A hard failure. `CreateSQLiteError(isolate, backup_status_)` reports
        // the code's own description, which is what makes a backup onto a
        // read-only file say "attempt to write a readonly database".
        let value = SqliteFailure::from_code(step_status).into_value(scope);
        reject_and_free(scope, state, value);
        return;
    }

    // SAFETY: the handle is live and has not been finished yet.
    let (total_pages, remaining_pages) = unsafe {
        (
            ffi::sqlite3_backup_pagecount(state.backup.0),
            ffi::sqlite3_backup_remaining(state.backup.0),
        )
    };

    if remaining_pages != 0 {
        if let Some(progress) = state.progress.clone() {
            match report_progress(scope, &progress, total_pages, remaining_pages) {
                Ok(()) => {}
                Err(exception) => {
                    // The callback threw, so `Settle` rejects with its exception
                    // rather than a SQLite error: the caller sees its own error.
                    reject_and_free(scope, state, exception);
                    return;
                }
            }
        }
        // There is still work to do; the last call is not made because the
        // promise resolves on it.
        requeue_or_reject(scope, state);
        return;
    }

    if step_status != ffi::SQLITE_DONE {
        let value = SqliteFailure::from_connection(state.destination.0).into_value(scope);
        reject_and_free(scope, state, value);
        return;
    }

    // `Settle(resolver, {}, Integer::New(isolate, total_pages))`.
    state.finish();
    let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &state.resolver);
    resolver.resolve(scope, v8::Integer::new(scope, total_pages).into());
    free(state);
}

/// Queues the next step, or rejects when the loop refuses it.
fn requeue_or_reject(scope: &mut v8::PinScope<'_, '_>, state: &mut BackupState) {
    let pointer = state as *mut BackupState;
    if queue_step(pointer) {
        return;
    }
    let value = plain_error(scope, "Cannot queue the backup job");
    reject_and_free(scope, state, value);
}

/// Calls the progress callback with `{ totalPages, remainingPages }`.
///
/// `Err` carries the value the callback threw, rooted so it survives the
/// `TryCatch` that caught it: dropping a `TryCatch` resets the pending
/// exception, which is why the value has to be taken out before that happens.
fn report_progress<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    progress: &v8::Global<v8::Function>,
    total_pages: i32,
    remaining_pages: i32,
) -> Result<(), Option<v8::Local<'s, v8::Value>>> {
    let Some(info) = progress_info(scope, total_pages, remaining_pages) else {
        // `Settle(resolver, {}, {})` would leave the promise pending, which no
        // caller can recover from. Rejecting with a plain error keeps the
        // contract the rest of this module has: the promise always settles.
        return Err(plain_error(
            scope,
            "The backup progress object could not be built",
        ));
    };
    let function: v8::Local<v8::Function> = v8::Local::new(scope, progress);
    let (caught, thrown) = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let inner = &mut try_catch.init();
        let _ = function.call(inner, v8::undefined(inner).into(), &[info.into()]);
        (
            inner.has_caught(),
            inner.exception().map(|value| v8::Global::new(inner, value)),
        )
    };
    if !caught {
        return Ok(());
    }
    Err(thrown.map(|value| v8::Local::new(scope, &value)))
}

/// The `{ totalPages, remainingPages }` object the callback receives.
fn progress_info<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    total_pages: i32,
    remaining_pages: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    for (name, value) in [
        ("totalPages", total_pages),
        ("remainingPages", remaining_pages),
    ] {
        let key = v8::String::new(scope, name)?;
        object.set(scope, key.into(), v8::Integer::new(scope, value).into())?;
    }
    Some(object)
}

/// Rejects `state`'s promise with `value` and releases the handles, leaving the
/// box itself to its owner.
///
/// For the two failures in [`schedule`], where the state is still a local and
/// freeing it here would be a second free.
fn reject_in_place(
    scope: &mut v8::PinScope<'_, '_>,
    state: &mut BackupState,
    value: Option<v8::Local<'_, v8::Value>>,
) {
    state.finish();
    let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &state.resolver);
    if let Some(value) = value {
        resolver.reject(scope, value);
    }
}

/// Rejects `state`'s promise with `value`, releases the handles, and frees it.
fn reject_and_free(
    scope: &mut v8::PinScope<'_, '_>,
    state: &mut BackupState,
    value: Option<v8::Local<'_, v8::Value>>,
) {
    state.finish();
    let resolver: v8::Local<v8::PromiseResolver> = v8::Local::new(scope, &state.resolver);
    if let Some(value) = value {
        resolver.reject(scope, value);
    }
    free(state);
}

/// Drops the backup's state box.
///
/// This ends the `Global`s that root the source, the resolver and the progress
/// callback, and does nothing to the SQLite handles: every caller goes through
/// [`BackupState::finish`] first.
fn free(state: *mut BackupState) {
    // SAFETY: the caller held the last outstanding reference and will not use the
    // pointer afterwards.
    unsafe { drop(Box::from_raw(state)) };
}

/// The `TypeError` a bad `sourceDb` produces.
fn invalid_source(scope: &mut v8::PinScope<'_, '_>) {
    errors::throw_type(
        scope,
        "The \"sourceDb\" argument must be an instance of Database.",
    );
}

/// An `Error` carrying only a message, the shape `v8::Exception::error` produces.
fn plain_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    message: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let text = v8::String::new(scope, message)?;
    Some(v8::Exception::error(scope, text))
}

/// Reads `options.rate`, which must be a positive `int32`.
fn read_rate(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
    target: &mut i32,
) -> bool {
    let Some(key) = v8::String::new(scope, "rate") else {
        return false;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return false;
    };
    if value.is_undefined() {
        return true;
    }
    // `IsInt32()` rather than a numeric-range check: it is false for a
    // fractional number and for anything outside the 32-bit range, so `1.5` and
    // `2 ** 31` are type errors rather than truncations or clamps.
    let Ok(number) = v8::Local::<v8::Int32>::try_from(value) else {
        errors::throw_type(scope, "The \"options.rate\" argument must be an integer.");
        return false;
    };
    let rate = number.value();
    if rate <= 0 {
        errors::throw_range(
            scope,
            "The \"options.rate\" argument must be a positive integer.",
        );
        return false;
    }
    *target = rate;
    true
}

/// Reads `options.progress`, which must be a function when it is present.
fn read_progress<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Object>,
    target: &mut Option<v8::Local<'s, v8::Function>>,
) -> bool {
    let Some(key) = v8::String::new(scope, "progress") else {
        return false;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return false;
    };
    if value.is_undefined() {
        return true;
    }
    match v8::Local::<v8::Function>::try_from(value) {
        Ok(function) => {
            *target = Some(function);
            true
        }
        Err(_) => {
            errors::throw_type(
                scope,
                "The \"options.progress\" argument must be a function.",
            );
            false
        }
    }
}

/// Whether a step result is one `Backup` retries from.
///
/// `BackupJob::AfterThreadPoolWork` treats exactly these two as transient, so a
/// status added here that the step loop rejects would leave a locked source
/// failing where Node waits.
fn is_transient(status: c_int) -> bool {
    status == ffi::SQLITE_BUSY || status == ffi::SQLITE_LOCKED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transient set is exactly what `Backup`'s `AfterThreadPoolWork`
    /// retries, so a status added here that the step loop rejects would leave a
    /// locked source failing where Node waits.
    #[test]
    fn only_busy_and_locked_are_transient() {
        for status in [ffi::SQLITE_OK, ffi::SQLITE_DONE] {
            assert!(!is_transient(status), "{status} is a normal completion");
        }
        for status in [ffi::SQLITE_BUSY, ffi::SQLITE_LOCKED] {
            assert!(is_transient(status), "{status} must be retried");
        }
        for status in [
            ffi::SQLITE_ERROR,
            8,  /* SQLITE_READONLY */
            13, /* SQLITE_FULL */
        ] {
            assert!(!is_transient(status), "{status} is a hard failure");
        }
    }
}
