//! The `Session` object: SQLite's changeset extension.
//!
//! `Database::CreateSession` and `Session::Changeset` in `src/node_sqlite.cc` are
//! the specification. A session records every change made on a connection and
//! `changeset()` returns those changes as an opaque blob SQLite can replay
//! elsewhere; `applyChangeset` is the other half, and it is deferred here (see
//! the crate docs) because nothing in `lib/**` or the acceptance surface needs
//! it yet.
//!
//! # Why the session is deleted, not finalized
//!
//! `sqlite3session_delete` can invoke the preupdate hook of a statement in
//! flight, which reaches JavaScript, so `close()` refuses while a changeset is
//! being generated. `Session::Close` has the same three-way ordering, including
//! the comment that the `is_generating_changeset_` check must come after the
//! open checks because generating a changeset runs the authorizer and both
//! conditions hold at once.

use std::os::raw::{c_int, c_void};

use rn_v8_sys::v8;

use crate::db::DatabaseState;
use crate::errors;
use crate::ffi;

/// The internal field holding a `Session`'s boxed state.
pub const STATE_FIELD: i32 = 0;
/// How many internal fields a `Session` instance has.
pub const INTERNAL_FIELDS: usize = 1;

/// Everything one `Session` instance owns.
pub struct SessionState {
    /// The SQLite session, or null once closed.
    pub raw: *mut ffi::sqlite3_session,
    /// The database state. A session never outlives its connection: the
    /// statement-side rooting argument does not apply here, so the JS object
    /// roots its `Database` object exactly as a `Statement` does.
    pub database: *mut DatabaseState,
    /// The rooted `Database` object, keeping `database` valid.
    pub database_object: v8::Global<v8::Object>,
    /// Whether a changeset or patchset is being generated right now.
    pub generating: bool,
}

impl SessionState {
    /// Whether the session still owns a SQLite session handle.
    pub fn is_live(&self) -> bool {
        !self.raw.is_null()
    }

    /// Runs `body` with the database state.
    pub fn with_database<R>(&mut self, body: impl FnOnce(&mut DatabaseState) -> R) -> Option<R> {
        if self.database.is_null() {
            return None;
        }
        // SAFETY: `database_object` roots the `Database` object, so the boxed
        // state behind `database` outlives this session.
        Some(body(unsafe { &mut *self.database }))
    }

    /// `Session::Delete`: drop the SQLite session and leave the registry.
    pub fn delete(&mut self) {
        if self.raw.is_null() {
            return;
        }
        // SAFETY: `raw` is a live session this object owns; the pointer is
        // cleared immediately so this is its only deletion.
        unsafe { ffi::sqlite3session_delete(self.raw) };
        self.raw = std::ptr::null_mut();
        let this = self as *mut Self;
        self.with_database(|database| database.unregister_session(this));
    }

    /// `Session::Changeset`: the accumulated changes as a `Uint8Array`.
    ///
    /// `is_generating_changeset_` is set for the duration because generating a
    /// changeset runs the authorizer, which can reach back into the session.
    pub fn changeset<'s>(
        &mut self,
        scope: &mut v8::PinScope<'s, '_>,
        patchset: bool,
    ) -> Option<v8::Local<'s, v8::Uint8Array>> {
        if !self.is_live() {
            return None;
        }
        self.generating = true;
        let mut size: c_int = 0;
        let mut buffer: *mut c_void = std::ptr::null_mut();
        // SAFETY: `raw` is live and the two out-parameters are written by
        // SQLite; the buffer it returns must be freed with `sqlite3_free`.
        let code = unsafe {
            if patchset {
                ffi::sqlite3session_patchset(self.raw, &mut size, &mut buffer)
            } else {
                ffi::sqlite3session_changeset(self.raw, &mut size, &mut buffer)
            }
        };
        self.generating = false;
        if code != ffi::SQLITE_OK {
            let connection = self
                .with_database(|database| database.raw())
                .unwrap_or(std::ptr::null_mut());
            errors::throw_sqlite(scope, connection);
            return None;
        }
        let length = size.max(0) as usize;
        let bytes = if buffer.is_null() || length == 0 {
            &[][..]
        } else {
            // SAFETY: SQLite allocated `length` bytes at `buffer`.
            unsafe { std::slice::from_raw_parts(buffer as *const u8, length) }
        };
        let array = crate::value::uint8_array(scope, bytes);
        // SAFETY: `sqlite3session_changeset` hands ownership to the caller.
        if !buffer.is_null() {
            unsafe { ffi::sqlite3_free(buffer) };
        }
        array
    }
}

/// The `SessionState` behind `object`, or a thrown `ERR_INVALID_THIS`.
pub fn state_or_throw(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<*mut SessionState> {
    // SAFETY: the field is either absent, in which case V8 reports a null
    // pointer, or installed by `install_pointer` for this object's template.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut SessionState;
    if pointer.is_null() {
        errors::throw_coded(
            scope,
            "ERR_INVALID_THIS",
            "Value of \"this\" must be of type Session",
        );
        return None;
    }
    Some(pointer)
}

/// Boxes `state` onto `object` and registers the finalizer that frees it.
pub fn install_pointer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    pointer: *mut SessionState,
) {
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: the pointer came from `Box::into_raw` here, and this
            // finalizer runs exactly once, so it is the only owner.
            let mut state = unsafe { Box::from_raw(address as *mut SessionState) };
            if !state.raw.is_null() {
                // SAFETY: `raw` is a live session this object owns.
                unsafe { ffi::sqlite3session_delete(state.raw) };
                state.raw = std::ptr::null_mut();
            }
            let this: *mut SessionState = &mut *state;
            state.with_database(|database| database.unregister_session(this));
            drop(state);
        }),
    );
    // The registration has to outlive this scope; forgetting the `Weak` hands it
    // to V8 rather than cancelling it.
    std::mem::forget(weak);
}

/// Deletes a session on behalf of `Database::Close`.
///
/// # Safety
///
/// `pointer` must be a live session's state, already removed from the registry.
pub unsafe fn delete_from_database(pointer: *mut SessionState) {
    let state = &mut *pointer;
    if state.raw.is_null() {
        return;
    }
    ffi::sqlite3session_delete(state.raw);
    state.raw = std::ptr::null_mut();
}

/// Registers a freshly created session with its database.
pub fn track(database: &mut DatabaseState, session: *mut SessionState) {
    database.sessions.push(session);
}

/// `database.createSession([options])`.
pub fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    let Some(state) = crate::db::state_or_throw(scope, this) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`. The borrow ends
    // before the options bag is read, which can run user getters.
    let (open, authorizer) = unsafe { ((*state).is_open(), (*state).authorizer_depth) };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return;
    }

    let mut table = String::new();
    let mut db_name = "main".to_string();
    let options = args.get(0);
    if !options.is_undefined() {
        let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
            errors::throw_type(scope, "The \"options\" argument must be an object.");
            return;
        };
        if !crate::db::optional_string(scope, options, "table", &mut table) {
            return;
        }
        if !crate::db::optional_string(scope, options, "db", &mut db_name) {
            return;
        }
    }

    let (Ok(db_name), Ok(table)) = (
        std::ffi::CString::new(db_name),
        std::ffi::CString::new(table.clone()),
    ) else {
        errors::throw_type(scope, "The session options must not contain null bytes.");
        return;
    };

    // SAFETY: `state_of` returned a live pointer for `this`, and reading the
    // options above cannot have closed the connection. Re-checked below because
    // a getter could have.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let Some(raw) = crate::db::open_handle(scope, state) else {
        return;
    };
    let mut session: *mut ffi::sqlite3_session = std::ptr::null_mut();
    // SAFETY: `raw` is open and both strings outlive the call.
    let code = unsafe { ffi::sqlite3session_create(raw, db_name.as_ptr(), &mut session) };
    if code != ffi::SQLITE_OK {
        errors::throw_sqlite(scope, raw);
        return;
    }
    // An empty `table` means "attach every table", which SQLite spells as a
    // null name rather than `""`.
    let table_pointer = if table.as_bytes().is_empty() {
        std::ptr::null()
    } else {
        table.as_ptr()
    };
    // SAFETY: `session` is the handle just created and `table_pointer` is either
    // null or a valid C string.
    let code = unsafe { ffi::sqlite3session_attach(session, table_pointer) };
    if code != ffi::SQLITE_OK {
        // SAFETY: `session` is live and nothing else owns it yet.
        unsafe { ffi::sqlite3session_delete(session) };
        errors::throw_sqlite(scope, raw);
        return;
    }

    let Some(constructor) = constructor(scope) else {
        // SAFETY: `session` is live and nothing else owns it.
        unsafe { ffi::sqlite3session_delete(session) };
        return;
    };
    let Some(object) = constructor.new_instance(scope, &[]) else {
        // SAFETY: as above.
        unsafe { ffi::sqlite3session_delete(session) };
        return;
    };
    let state = SessionState {
        raw: session,
        database: state as *mut DatabaseState,
        database_object: v8::Global::new(scope, this),
        generating: false,
    };
    let pointer = Box::into_raw(Box::new(state));
    // SAFETY: the pointer is the allocation just made; nothing else owns it.
    track(state_of_database(pointer), pointer);
    install_pointer(scope, object, pointer);
    rv.set(object.into());
}

/// The database a freshly boxed session belongs to.
fn state_of_database(pointer: *mut SessionState) -> &'static mut DatabaseState {
    // SAFETY: the caller just built the state with a live database pointer that
    // its rooted object keeps alive, and this borrow ends before the next
    // statement.
    unsafe { &mut *(*pointer).database }
}

/// Builds the `Session` constructor. Only `create` produces instances.
pub fn constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Function>> {
    let template = v8::FunctionTemplate::builder(illegal_constructor)
        .length(0)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELDS);
    let prototype = template.prototype_template(scope);
    for (name, template) in [
        (
            "changeset",
            crate::database::method(scope, 0, changeset_method),
        ),
        (
            "patchset",
            crate::database::method(scope, 0, patchset_method),
        ),
        ("close", crate::database::method(scope, 0, close_method)),
    ] {
        let key = v8::String::new(scope, name)?;
        prototype.set(key.into(), template.into());
    }
    let dispose = crate::database::method(scope, 0, dispose_method);
    let dispose_key: v8::Local<'_, v8::Name> =
        match v8::Local::<v8::Symbol>::try_from(crate::database::well_known_dispose(scope)) {
            Ok(symbol) => symbol.into(),
            Err(_) => v8::String::new(scope, "@@dispose")
                .expect("literal allocates")
                .into(),
        };
    prototype.set(dispose_key, dispose.into());
    if let Some(name) = v8::String::new(scope, "Session") {
        template.set_class_name(name);
    }
    template.get_function(scope)
}

fn illegal_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    errors::throw_coded(scope, "ERR_ILLEGAL_CONSTRUCTOR", "Illegal constructor");
}

/// The session state behind `this`, or a thrown error.
fn this_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<*mut SessionState> {
    state_or_throw(scope, args.this())
}

/// Checks the two state conditions every session method opens with.
fn require_usable(
    scope: &mut v8::PinScope<'_, '_>,
    state: &mut SessionState,
    require_open: bool,
) -> bool {
    let database_open = state
        .with_database(|database| database.is_open())
        .unwrap_or(false);
    if !errors::require(scope, database_open, "database is not open") {
        return false;
    }
    if require_open {
        return errors::require(scope, state.is_live(), "session is not open");
    }
    true
}

/// `session.changeset()`.
fn changeset_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `this_state` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !require_usable(scope, state, true) {
        return;
    }
    if let Some(array) = state.changeset(scope, false) {
        rv.set(array.into());
    }
}

/// `session.patchset()`.
fn patchset_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: as above.
    let state = unsafe { &mut *pointer };
    if !require_usable(scope, state, true) {
        return;
    }
    if let Some(array) = state.changeset(scope, true) {
        rv.set(array.into());
    }
}

/// `session.close()`.
fn close_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: as above.
    let state = unsafe { &mut *pointer };
    if !require_usable(scope, state, true) {
        return;
    }
    // Checked after the open conditions, because generating a changeset also
    // holds the session and that more specific message has to win.
    if !errors::require(scope, !state.generating, "session is currently in use") {
        return;
    }
    state.delete();
}

/// `session[Symbol.dispose]()`.
fn dispose_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: as above.
    let state = unsafe { &mut *pointer };
    if !state.is_live() || state.generating {
        return;
    }
    state.delete();
}
