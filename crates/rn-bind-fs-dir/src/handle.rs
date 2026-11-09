//! `DirHandle`, and the two functions that open one.
//!
//! # Why the entries are read up front
//!
//! Node keeps a `uv_dir_t` alive and refills a caller-sized `dirents` array with
//! `uv_fs_readdir`, so one `dir.read()` can return a partial batch.
//! `lib/internal/fs/dir.js` loops until it gets `null`, so the observable
//! sequence is the directory's entries followed by `null` — which one listing
//! produces directly. Each `read()` therefore hands back the next slice and
//! `null` once the listing is exhausted.
//!
//! Reading up front also avoids holding a `uv_dir_t` (and its file descriptor)
//! open across arbitrary JavaScript turns, which is the one thing that would make
//! a leaked handle observable as a real descriptor leak.
//!
//! # The listing comes from `rn-bind-fs`
//!
//! [`rn_bind_fs::dirent::read_dir`] is the same scan `fs.readdirSync` uses, and it
//! already sorts ascending the way `uv_fs_scandir` does and classifies each entry
//! into a `uv_dirent_type_t`. Reusing it is what keeps `fs.opendir`'s order and
//! types identical to `fs.readdirSync`'s instead of drifting from them.
//!
//! # Delivery modes
//!
//! `opendir` and both `DirHandle` methods classify their trailing argument with
//! [`rn_bind_fs::request::classify`], the same rule every other `fs` member uses:
//! an object is a callback request, the `kUsePromises` symbol is a promise,
//! anything else (including `undefined`) is synchronous. Reusing it keeps
//! `fs.opendir`'s three call shapes identical to `fs.readdir`'s.

use std::cell::{Cell, RefCell};

use rn_v8_sys::v8;

use rn_bind_fs::complete::{deliver_to_callback, deliver_to_promise, Completion};
use rn_bind_fs::dirent::read_dir;
use rn_bind_fs::error::FsError;
use rn_bind_fs::request::{classify, throw_error, Delivery};

/// Internal field holding the `*mut DirSlot`.
const SLOT_FIELD: i32 = 0;

/// `nentries` Node gives a fresh `uv_dir_t`, and the default batch `Dir` uses.
const DEFAULT_BATCH: usize = 32;

/// One directory entry, as a `uv_dirent_t` reports it.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The file name, without its parent path.
    pub name: String,
    /// `uv_dirent_type_t`, which `getDirent` maps onto a `Dirent` class.
    pub kind: i32,
}

/// The state one `DirHandle` owns.
pub struct DirSlot {
    /// Every entry of the directory, in libuv's sorted order.
    entries: Vec<Entry>,
    /// How far into `entries` the previous `read()` got.
    position: Cell<usize>,
    /// Whether `close` ran, so a second one is a no-op rather than an error.
    closed: Cell<bool>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

// The constructor, so `opendir` can build a handle from native code.
thread_local! {
    static CONSTRUCTOR: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
}

/// Runs `body` with the slot behind a `DirHandle` object.
fn with_slot<R>(object: v8::Local<v8::Object>, body: impl FnOnce(&DirSlot) -> R) -> Option<R> {
    // SAFETY: the field only ever holds a pointer installed by `install_handle`,
    // and the object is a live local so its finalizer has not run.
    let address = unsafe { object.get_aligned_pointer_from_internal_field(SLOT_FIELD, 0) } as usize;
    if address == 0 {
        return None;
    }
    // SAFETY: as above — the address is the live slot this object owns.
    Some(body(unsafe { &*(address as *const DirSlot) }))
}

/// Builds a non-constructible method function, matching `SetMethod`.
pub fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let text = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    template.set_class_name(text);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    function.set_name(text);
    Ok(function.into())
}

/// Builds the `DirHandle` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name =
        v8::String::new(scope, "DirHandle").ok_or("cannot allocate the DirHandle class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    macro_rules! install_methods {
        ($($method_name:literal => $method:expr => $length:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .length($length)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $method_name)
                    .ok_or_else(|| format!("cannot allocate the name {}", $method_name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install_methods! {
        "read" => read => 2,
        "close" => close => 0,
    }

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the DirHandle constructor")?;
    constructor.set_name(name);
    CONSTRUCTOR.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope.as_ref(), constructor));
    });
    Ok(constructor.into())
}

/// `DirHandle::New`, which is `CHECK(args.IsConstructCall())` and nothing else.
///
/// `lib/internal/fs/dir.js` never calls it; `opendir` builds handles through the
/// constructor so the internal field and finalizer are installed in one place.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "DirHandle cannot be invoked without 'new'");
        return;
    }
    rv.set(args.this().into());
}

/// Instantiates a `DirHandle` around an already-read listing.
fn install_handle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: Vec<Entry>,
) -> Option<v8::Local<'s, v8::Object>> {
    let handle = CONSTRUCTOR.with(|slot| slot.borrow().clone())?;
    let handle: v8::Local<'s, v8::Function> = v8::Local::new(scope, &handle);
    let object = handle.new_instance(scope, &[])?;

    let slot = Box::into_raw(Box::new(DirSlot {
        entries,
        position: Cell::new(0),
        closed: Cell::new(false),
        weak: RefCell::new(None),
    }));
    object.set_aligned_pointer_in_internal_field(SLOT_FIELD, slot.cast(), 0);

    let address = slot as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `address` came from `Box::into_raw` above and this
            // finalizer runs exactly once. There is no descriptor to close:
            // the listing was read at open time.
            drop(unsafe { Box::from_raw(address as *mut DirSlot) });
        }),
    );
    // SAFETY: `slot` is live and this is its only borrow.
    *unsafe { &(*slot).weak }.borrow_mut() = Some(weak);
    Some(object)
}

/// Opens `path` and reads every entry.
///
/// `read_dir` already reports `scandir`-shaped errors with the path attached, so
/// the only thing left is the syscall name: `fs.opendir` reports `opendir`.
fn open(path: &[u8]) -> Result<Vec<Entry>, FsError> {
    let entries = read_dir(path, "opendir").map_err(|error| FsError {
        syscall: "opendir",
        ..error
    })?;
    Ok(entries
        .into_iter()
        .map(|entry| Entry {
            name: String::from_utf8_lossy(&entry.name).into_owned(),
            kind: entry.kind,
        })
        .collect())
}

/// `opendir(path, encoding[, req])`.
pub fn opendir<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(path) = path_argument(scope, &args, 0) else {
        return;
    };
    let tail = (args.length() > 2).then(|| args.get(2));
    let (mode, request) = classify(scope, tail);
    deliver_open(scope, &mut rv, mode, request, open(&path));
}

/// `opendirSync(path)`.
///
/// Node reads the path and nothing else here — unlike `opendir`, there is no
/// encoding argument to consume.
pub fn opendir_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(path) = path_argument(scope, &args, 0) else {
        return;
    };
    match open(&path) {
        Ok(entries) => {
            if let Some(object) = install_handle(scope, entries) {
                rv.set(object.into());
            }
        }
        Err(error) => throw_error(scope, &error),
    }
}

/// Delivers a `DirHandle` or an error in the mode the request slot selected.
fn deliver_open<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    rv: &mut v8::ReturnValue<'s>,
    mode: Delivery,
    request: Option<v8::Local<'s, v8::Object>>,
    result: Result<Vec<Entry>, FsError>,
) {
    match result {
        Ok(entries) => {
            let Some(object) = install_handle(scope, entries) else {
                return;
            };
            let value: v8::Local<'s, v8::Value> = object.into();
            match mode {
                Delivery::Sync => rv.set(value),
                Delivery::Callback => {
                    if let Some(request) = request {
                        deliver_to_callback(scope, request, Completion::value(value));
                    }
                }
                Delivery::Promise => {
                    if let Some(promise) = deliver_to_promise(scope, Completion::value(value)) {
                        rv.set(promise.into());
                    }
                }
            }
        }
        Err(error) => deliver_error(scope, rv, mode, request, error),
    }
}

/// Delivers `error` in the mode the request slot selected.
fn deliver_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    rv: &mut v8::ReturnValue<'s>,
    mode: Delivery,
    request: Option<v8::Local<'s, v8::Object>>,
    error: FsError,
) {
    match mode {
        Delivery::Sync => throw_error(scope, &error),
        Delivery::Callback => {
            if let Some(request) = request {
                deliver_to_callback(scope, request, Completion::failed(error));
            }
        }
        Delivery::Promise => {
            if let Some(promise) = deliver_to_promise(scope, Completion::failed(error)) {
                rv.set(promise.into());
            }
        }
    }
}

/// `DirHandle::Read`: `read(encoding, bufferSize[, req])`.
pub fn read<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    // `CHECK(args[1]->IsNumber())`. Node then compares it against its current
    // buffer length and resizes; the batch here is the number of entries to take.
    let batch = args
        .get(1)
        .number_value(scope)
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_BATCH);
    let tail = (args.length() > 2).then(|| args.get(2));
    let (mode, request) = classify(scope, tail);

    // `null` at the end of the listing, and also for a handle whose slot is
    // gone: `lib/internal/fs/dir.js` guards on `#closed`, so the exhausted
    // listing is the shape it expects rather than an error.
    let chunk = with_slot(object, |slot| {
        let start = slot.position.get();
        let end = start.saturating_add(batch).min(slot.entries.len());
        slot.position.set(end);
        if start >= end {
            return None;
        }
        Some(slot.entries[start..end].to_vec())
    })
    .flatten();

    let value: Option<v8::Local<'s, v8::Value>> =
        chunk.and_then(|entries| entries_array(scope, &entries).map(Into::into));
    let resolved = match value {
        Some(value) => value,
        // `req_wrap->Resolve(Null(isolate))`: the JS layer treats `null` as "no
        // more entries", which is what ends the loop in `#readSyncRecursive`.
        None => v8::null(scope).into(),
    };

    match mode {
        Delivery::Sync => rv.set(resolved),
        Delivery::Callback => {
            if let Some(request) = request {
                deliver_to_callback(scope, request, Completion::value(resolved));
            }
        }
        Delivery::Promise => {
            if let Some(promise) = deliver_to_promise(scope, Completion::value(resolved)) {
                rv.set(promise.into());
            }
        }
    }
}

/// `DirHandle::Close`: `close([req])`.
///
/// Closing twice is not an error: Node sets `closed_` on the first call and a
/// second `close()` returns without touching libuv.
pub fn close<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let object = args.this();
    let tail = (args.length() > 0).then(|| args.get(0));
    let (mode, request) = classify(scope, tail);

    with_slot(object, |slot| {
        slot.closed.set(true);
        // Drop the listing so a handle that is kept around cannot pin a whole
        // directory's names after it was closed.
        slot.position.set(slot.entries.len());
    });

    let resolved: v8::Local<'s, v8::Value> = v8::undefined(scope).into();
    match mode {
        Delivery::Sync => rv.set(resolved),
        Delivery::Callback => {
            if let Some(request) = request {
                deliver_to_callback(scope, request, Completion::unit());
            }
        }
        Delivery::Promise => {
            if let Some(promise) = deliver_to_promise(scope, Completion::unit()) {
                rv.set(promise.into());
            }
        }
    }
}

/// Builds the flat `[name, type, …]` array `#processReadResult` reads.
fn entries_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[Entry],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, (entries.len() * 2) as i32);
    for (index, entry) in entries.iter().enumerate() {
        let name = v8::String::new(scope, &entry.name)?;
        array.set_index(scope, (index * 2) as u32, name.into());
        let kind = v8::Integer::new(scope, entry.kind);
        array.set_index(scope, (index * 2 + 1) as u32, kind.into());
    }
    Some(array)
}

/// Reads argument `index` as a path, throwing `ERR_INVALID_ARG_TYPE` when it is
/// not a string.
fn path_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<Vec<u8>> {
    let value = args.get(index);
    if !value.is_string() {
        throw_invalid_arg_type(
            scope,
            "The \"path\" argument must be of type string or an instance of Buffer or URL",
        );
        return None;
    }
    value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope).into_bytes())
}

/// Throws a `TypeError` carrying `ERR_INVALID_ARG_TYPE`.
fn throw_invalid_arg_type(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    if let (Ok(object), Some(code)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "ERR_INVALID_ARG_TYPE"),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

/// Throws a `TypeError`.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, text);
        scope.throw_exception(exception);
    }
}
