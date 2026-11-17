//! `dlopen` for the `process_methods` namespace.
//!
//! Node reaches the addon loader through `process.dlopen`, which
//! `lib/internal/bootstrap/node.js` installs from `rawMethods.dlopen`, and
//! `lib/internal/modules/cjs/loader.js` calls from `Module._extensions['.node']`:
//!
//! ```js
//! Module._extensions['.node'] = function(module, filename) {
//!   return process.dlopen(module, path.toNamespacedPath(filename));
//! };
//! ```
//!
//! So the arguments are `(module, filename)`, the exports object is
//! `module.exports`, and the addon's `napi_register_module_v1` either mutates that
//! object or returns a different one to replace it.
//!
//! # Why the loaded libraries are kept in a thread-local table
//!
//! The addon hands JavaScript function pointers into its own `.text`, and those keep
//! working only while the shared object is mapped. Nothing in the language tells the
//! runtime when the last reference to an addon function goes away, so Node never
//! `dlclose`s an addon either — the handle lives for the life of the process. The
//! table is what holds those handles; dropping one would turn a later call into a
//! jump into unmapped memory.
//!
//! Thread-local because the V8 isolate is: an addon loaded on the main thread
//! created its `napi_value`s in that isolate's handle scopes, so its functions must
//! only be called from the same thread. A worker thread loading the same `.node`
//! gets its own `dlopen` (the dynamic loader refcounts the mapping) and its own
//! `napi_env`, which is what Node's per-worker load does too.

use std::cell::RefCell;
use std::path::Path;

use rn_napi::{LoadError, LoadResult, LoadedAddon};
use rn_v8_sys::v8;

thread_local! {
    /// Every addon this thread has loaded, in load order.
    static ADDONS: RefCell<Vec<LoadedAddon>> = const { RefCell::new(Vec::new()) };
}

/// Runs every loaded addon's teardown, in Node's order.
///
/// `Environment::RunCleanup` runs each environment's hooks when the environment
/// stops. This runtime has one process-lifetime environment per loaded addon, so
/// the equivalent moment is process exit, and this is what the CLI calls there —
/// **before** `rn_uv::threadpool::drain()`, because a cleanup hook must not run
/// after the pool that may still hold an addon's work has been torn down.
///
/// Not a `Drop` impl on [`LoadedAddon`]: `std::process::exit` does not run
/// destructors, and that is how every exit in this runtime ends. A destructor
/// here would be dead code on the only path that matters.
///
/// Visits newest-first, matching the reverse-registration principle Node applies
/// within one environment: the last addon loaded may depend on an earlier one, so
/// it is torn down first.
///
/// Idempotent per environment — each `Env` takes its hooks and instance-data slot
/// on the first call — so a second call is a cheap no-op rather than a double
/// free. That matters because this can be reached from both the normal exit path
/// and a `process.reallyExit`, and there is no ordering guarantee between them.
///
/// Returns how many environments reported that they ran something, so a test can
/// distinguish "no addons loaded" from "an addon with no hooks".
pub fn run_addon_teardowns() -> usize {
    // Taken out of the thread-local for the duration: a hook that loads another
    // addon re-enters `dlopen`, which pushes onto `ADDONS`, and holding the
    // borrow across the hooks would make that push a silent no-op.
    let addons: Vec<LoadedAddon> = ADDONS
        .with(|slot| {
            slot.try_borrow_mut()
                .map(|mut all| std::mem::take(&mut *all))
        })
        .unwrap_or_default();

    let mut ran = 0;
    for addon in addons.iter().rev() {
        // SAFETY: the environment was created by `rn_napi::load` and has not been
        // freed; `LoadedAddon` owns it for as long as this list does.
        if unsafe { rn_napi::env::run_env_teardown(addon.env()) } {
            ran += 1;
        }
    }

    // Returned to the list so the library handles are not dropped here — dropping
    // one would `dlclose` an addon whose hooks just ran and whose function
    // pointers JavaScript may still hold until the process actually exits.
    ADDONS.with(|slot| {
        if let Ok(mut all) = slot.try_borrow_mut() {
            all.extend(addons);
        }
    });

    ran
}

/// Whether this process may load native addons at all.
///
/// `Environment::no_native_addons()` is `!options_->allow_native_addons`, and
/// `Environment::InitializePermission` clears that option under a bare
/// `--permission` when `--allow-addons` was not given — deliberately not in
/// audit mode, where the denial has to come from the permission check instead so
/// it can be published.
///
/// rustnode models the same derivation here because the option the CLI publishes
/// is only the user's `--addons`/`--no-addons` flag. The second half of the rule
/// is this function's own: a permission model that enforces `addon` and did not
/// grant it means Node would have cleared `allow_native_addons`.
fn native_addons_allowed() -> bool {
    let Some(value) = rn_bind_options::parsed::value_of("--addons") else {
        // No option store installed: a test binary or a bare binding harness.
        // Node's default is `true`, and inventing `false` here would make every
        // embedder that never parsed a command line unable to load addons.
        return true;
    };
    let allowed = match value {
        rn_bind_options::parsed::ParsedValue::Bool(flag) => flag,
        // A non-boolean here means the table changed shape. Defaulting to the
        // permissive answer keeps an embedder working; the alternative would
        // silently disable every addon.
        _ => true,
    };
    if !allowed {
        return false;
    }
    // `InitializePermission` clears it when the model enforces `addon` and the
    // process is not in audit mode. Asking the model rather than re-reading
    // `--allow-addons` means a `process.permission.drop('addon')` revokes the
    // loader as well, which is what `test-permission-drop-addons.js` asserts.
    !rn_permission::runtime::enforces_addon_without_grant()
}

/// The `process.dlopen(module, filename[, flags])` binding.
///
/// Node's signature is `(module, filename)` with an optional integer `flags`. The
/// flags only ever select `RTLD_LAZY` versus `RTLD_NOW` on platforms that honour
/// them, and `libloading` opens with the loader's default, which is the same pair
/// Node's `DLib::kDefaultFlags` resolves to. A present non-integer `flags` is still
/// rejected, because Node rejects it and silently accepting one would hide a
/// caller's bug.
pub(crate) fn dlopen<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    open_addon(scope, &args, rv, None);
}

/// `process_methods.dlopenBinary(module, filename, flags, binary)`.
///
/// `src/node_binding.cc:959-961` is `DLOpenImpl(args, /*allow_binary=*/true)`, the
/// same function `process.dlopen` runs through with `allow_binary = false`. It
/// exists for `lib/internal/vfs/setup.js:1093`, which reads an addon's bytes out of
/// a virtual file system and hands them over because `dlopen(2)` has no inode to
/// open: a VFS path that no real file backs.
///
/// Three differences from `process.dlopen`:
///
/// * `args[3]` must be an `ArrayBufferView` (`ERR_INVALID_ARG_TYPE` otherwise);
/// * `args[2]` may be `undefined` and keeps the default, whereas `process.dlopen`
///   rejects a present non-integer;
/// * the bytes are materialized into a private image first, and the image — not
///   `filename` — is what the dynamic loader opens. `filename` is still the path
///   every error message names.
///
/// A `FileSystemWrite` permission check runs against the temporary directory
/// before the image is created, on every platform, "so that what a program must be
/// granted does not vary by platform" (`src/node_binding.cc:833-843`).
pub(crate) fn dlopen_binary<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    // The image is materialized before the shared body runs so an argument error
    // later still cleans up through `Drop`. When `args[3]` is absent the call
    // degrades to loading `filename` by path, which is what Node's
    // `allow_binary` branch does when the fourth argument is `undefined`.
    let mut image = match AddonImage::materialize(scope, &args) {
        Ok(image) => Some(image),
        Err(ImageError::Thrown) => return,
        Err(ImageError::NotProvided) => None,
    };
    open_addon(scope, &args, rv, image.as_mut());
    if let Some(image) = image.as_mut() {
        image.after_open();
    }
}

/// The shared body of `process.dlopen` and `dlopenBinary`.
///
/// `binary` is `Some` only on the internal path, and carries the materialized
/// image so its `Drop` can clean up after the load. Keeping the two entry points
/// as one function is Node's own shape (`DLOpenImpl`) and it is what makes the
/// argument checks, the `ERR_DLOPEN_DISABLED`-before-permission ordering, and the
/// `module.exports` replacement identical between them instead of two
/// near-copies that could drift.
fn open_addon<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue,
    binary: Option<&mut AddonImage>,
) {
    if args.length() < 2 {
        throw_code(
            scope,
            "ERR_MISSING_ARGS",
            "process.dlopen needs at least 2 arguments",
            true,
        );
        return;
    }

    if args.length() > 2 {
        let flags = args.get(2);
        // `undefined` keeps the default on the internal path, matching Node's
        // `allow_binary && args[2]->IsUndefined()` escape; anything else must be
        // an integer. `process.dlopen` has no such escape.
        let keeps_default = binary.is_some() && flags.is_undefined();
        if !keeps_default && !flags.is_int32() && !flags.is_uint32() {
            throw_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "The \"flags\" argument must be of type integer.",
                true,
            );
            return;
        }
    }

    // A module argument that is not an object is a caller bug. Node coerces with
    // `ToObject`; a coercion failure surfaces as the exception V8 already threw,
    // but an explicit rejection names the argument, which is more useful.
    let Ok(module) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"module\" argument must be of type object.",
            true,
        );
        return;
    };
    let Some(exports_key) = v8::String::new(scope, "exports") else {
        return;
    };
    let Some(exports_value) = module.get(scope, exports_key.into()) else {
        return;
    };
    let Ok(exports) = v8::Local::<v8::Object>::try_from(exports_value) else {
        throw_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"module.exports\" property must be of type object.",
            true,
        );
        return;
    };

    let Ok(filename) = v8::Local::<v8::String>::try_from(args.get(1)) else {
        throw_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"filename\" argument must be of type string.",
            true,
        );
        return;
    };
    let filename = filename.to_rust_string_lossy(scope);
    // The image's own path replaces `filename` only for the loader call; every
    // diagnostic still names the path the caller wrote.
    let path = Path::new(&filename);

    // `DLOpenImpl` throws `ERR_DLOPEN_DISABLED` when the environment has native
    // addons switched off and only then checks the permission scope, so the
    // order decides which error `test-permission-audit-addons-does-not-deny.js`
    // sees: a bare `--permission` turns addons off (`allow_native_addons =
    // false`), producing `ERR_DLOPEN_DISABLED`, while `--permission-audit`
    // deliberately leaves them on so the denial can be published instead.
    //
    // Both checks run before `rn_napi::load`, which is what makes "before any
    // `dlopen(3)`" true: nothing below this point maps the file.
    if !native_addons_allowed() {
        throw_code(
            scope,
            "ERR_DLOPEN_DISABLED",
            "Cannot load native addon because loading addons is disabled.",
            false,
        );
        return;
    }
    if let Some(denied) = rn_permission::runtime::check_addon(scope, "") {
        denied.throw(scope);
        return;
    }

    match binary {
        Some(image) => {
            let image_path = image.path.clone();
            load_into(scope, Path::new(&image_path), module, exports);
        }
        None => {
            load_into(scope, path, module, exports);
        }
    }
}

/// Loads `path` and publishes the addon's exports, then keeps the handle alive.
fn load_into<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    path: &Path,
    module: v8::Local<'s, v8::Object>,
    exports: v8::Local<'s, v8::Object>,
) {
    // SAFETY: `scope` is the callback scope V8 established for this call, and the
    // addon's exported values go straight into `module.exports`, which outlives the
    // scope because it is reachable from JavaScript.
    match unsafe { rn_napi::load::load(scope, path, exports) } {
        Ok(LoadResult {
            addon,
            returned_exports,
        }) => {
            // Node only replaces `module.exports` when the addon returned a
            // *different* object; returning the same one is the common case and must
            // not overwrite anything.
            if let Some(returned) = returned_exports {
                // SAFETY: the handle was created in this scope, which is alive.
                unsafe { rn_napi::apply_returned_exports(scope, module, exports.into(), returned) };
            }
            ADDONS.with(|addons| {
                // `try_borrow_mut` rather than `borrow_mut`: a re-entrant `dlopen`
                // from inside an addon's own registration is unsupported (Node's
                // single `thread_local_modpending` has the same limitation), and
                // dropping the handle there is better than panicking across FFI.
                // The load has already happened either way.
                if let Ok(mut addons) = addons.try_borrow_mut() {
                    addons.push(addon);
                }
            });
        }
        Err(error) => throw_load_error(scope, &error),
    }
}

/// Why an `AddonImage` could not be produced.
enum ImageError {
    /// An exception is already pending.
    Thrown,
    /// `args[3]` was absent or `undefined`, so there is nothing to materialize and
    /// the caller should load by path instead.
    NotProvided,
}

/// A private, self-cleaning image of an addon supplied as bytes.
///
/// The counterpart of `AddonImage` in `src/node_binding.h:193` and
/// `src/node_binding.cc:549-760`. On Linux the bytes go into an anonymous
/// `memfd_create(2)` file and the loader opens `/proc/self/fd/N`, so nothing
/// reaches the filesystem, there is no temporary file to secure or leak, and an
/// `noexec` mount cannot break the load. The fallback — `memfd_create` unavailable,
/// or the kernel older than 6.3 and rejecting `MFD_EXEC` — is a private `0700`
/// directory created with `mkdtemp` and a single `O_EXCL | O_NOFOLLOW` file in it.
///
/// `Drop` removes whatever is still there, which is the `~AddonImage` path: a
/// failure between materializing and loading must not leave an image behind. Once
/// the load succeeds the mapping keeps the inode alive, so unlinking immediately is
/// correct and leaves no on-disk trace.
struct AddonImage {
    fd: Option<std::os::fd::OwnedFd>,
    path: String,
    temp_dir: Option<std::path::PathBuf>,
    consumed: bool,
}

impl AddonImage {
    /// Materializes `args[3]`, or reports that there were no bytes to materialize.
    fn materialize<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        args: &v8::FunctionCallbackArguments<'s>,
    ) -> Result<Self, ImageError> {
        if args.length() <= 3 || args.get(3).is_undefined() {
            return Err(ImageError::NotProvided);
        }
        let Ok(binary) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(3)) else {
            throw_code(
                scope,
                "ERR_INVALID_ARG_TYPE",
                "binary must be a Buffer, TypedArray, or DataView",
                true,
            );
            return Err(ImageError::Thrown);
        };
        let bytes = view_bytes(scope, binary);

        // `THROW_IF_INSUFFICIENT_PERMISSIONS(…kFileSystemWrite, TempDir())` runs
        // before the image exists, and on every platform even where the image is
        // an anonymous memfd: the grant a program needs should not depend on which
        // one its platform happens to use.
        if let Some(denied) = rn_permission::runtime::deny_fs_write(temp_dir().as_bytes()) {
            denied.throw(scope);
            return Err(ImageError::Thrown);
        }
        Self::from_bytes(&bytes).ok_or(ImageError::Thrown)
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if let Some(image) = Self::from_memfd(bytes) {
            return Some(image);
        }
        Self::from_temp_file(bytes)
    }

    #[cfg(target_os = "linux")]
    fn from_memfd(bytes: &[u8]) -> Option<Self> {
        // `MFD_CLOEXEC` so a child process cannot inherit the image, and
        // `MFD_EXEC` because Linux 6.3+ refuses to `dlopen` a memfd without it;
        // an older kernel answers `EINVAL`, which is what triggers the retry.
        const MFD_CLOEXEC: libc::c_uint = 0x0001;
        const MFD_EXEC: libc::c_uint = 0x0010;
        // SAFETY: `memfd_create` takes a NUL-terminated name and a flag word.
        let mut raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"node-addon".as_ptr(),
                MFD_CLOEXEC | MFD_EXEC,
            )
        } as libc::c_int;
        if raw == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            // SAFETY: as above, without `MFD_EXEC`.
            raw = unsafe {
                libc::syscall(libc::SYS_memfd_create, c"node-addon".as_ptr(), MFD_CLOEXEC)
            } as libc::c_int;
        }
        if raw == -1 {
            return None;
        }
        // SAFETY: `raw` is a fresh descriptor this function owns.
        let fd = unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) };
        if !write_all(&fd, bytes) {
            return None;
        }
        // The loader remembers an object by the path it was opened with and hands
        // back the same object for the same path instead of opening it again. An
        // image loaded through `/proc/self/fd/N` closes its fd right after, so the
        // kernel can hand N to the next image while the first is still mapped —
        // ask the loader and step past a number it already knows.
        let mut fd = fd;
        loop {
            let path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&fd));
            if dlopen_noload(&path).is_none() {
                return Some(Self {
                    path,
                    fd: Some(fd),
                    temp_dir: None,
                    consumed: false,
                });
            }
            let moved = dup_above(&fd);
            fd = moved?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn from_memfd(_bytes: &[u8]) -> Option<Self> {
        None
    }

    fn from_temp_file(bytes: &[u8]) -> Option<Self> {
        use std::io::Write;
        let template = std::ffi::CString::new(format!("{}node-addon-XXXXXX", temp_dir())).ok()?;
        // SAFETY: `mkdtemp` mutates the buffer in place and returns it or null.
        let directory = unsafe { libc::mkdtemp(template.into_raw()) };
        if directory.is_null() {
            return None;
        }
        // SAFETY: `mkdtemp` returned a NUL-terminated path it just created.
        let directory = unsafe { std::ffi::CStr::from_ptr(directory) }
            .to_string_lossy()
            .into_owned();
        let directory = std::path::PathBuf::from(directory);
        let file = directory.join("addon.node");
        let path = file.to_string_lossy().into_owned();

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut handle = match options.open(&file) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = std::fs::remove_dir(&directory);
                return None;
            }
        };
        if handle.write_all(bytes).is_err() {
            let _ = std::fs::remove_file(&file);
            let _ = std::fs::remove_dir(&directory);
            return None;
        }
        // `dlopen` reopens by path, so the writing handle must be closed; the
        // mapping keeps the inode alive afterwards.
        drop(handle);
        Some(Self {
            fd: None,
            path,
            temp_dir: Some(directory),
            consumed: false,
        })
    }

    /// Records that the load was attempted, after which the mapping owns the
    /// image and `Drop` has nothing left to do.
    /// Releases the image once the load has been attempted.
    ///
    /// The cleanup is identical whether the load worked, which is why this takes
    /// no argument: on success the mapping keeps the inode (or the memfd) alive,
    /// and on failure nothing does, so unlinking and closing in both cases leaves
    /// the same result and no on-disk trace either way. Node's `AfterOpen` has the
    /// same property on this platform (`src/node_binding.cc:754-765`).
    fn after_open(&mut self) {
        self.consumed = true;
        self.fd = None;
        if let Some(directory) = self.temp_dir.take() {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&directory);
        }
    }
}

impl Drop for AddonImage {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        self.fd = None;
        if let Some(directory) = self.temp_dir.take() {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&directory);
        }
    }
}

fn temp_dir() -> String {
    let value = std::env::var_os("TMPDIR");
    let mut path = match value {
        Some(value) if !value.is_empty() => value.to_string_lossy().into_owned(),
        _ => "/tmp".to_string(),
    };
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

/// Reads an `ArrayBufferView`'s bytes without copying its backing buffer.
fn view_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    view: v8::Local<'_, v8::ArrayBufferView>,
) -> Vec<u8> {
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    let copied = view.copy_contents(&mut bytes);
    let _ = scope;
    bytes.truncate(copied);
    bytes
}

fn write_all(fd: &std::os::fd::OwnedFd, mut bytes: &[u8]) -> bool {
    use std::os::fd::AsRawFd;
    while !bytes.is_empty() {
        // SAFETY: `fd` is open for writing and `bytes` is valid for its length.
        let written = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
            )
        };
        if written < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        bytes = &bytes[written as usize..];
    }
    true
}

/// `dlopen(path, RTLD_LAZY | RTLD_NOLOAD)`: is this path already mapped?
fn dlopen_noload(path: &str) -> Option<*mut std::ffi::c_void> {
    const RTLD_LAZY: libc::c_int = 0x0001;
    #[cfg(target_os = "linux")]
    const RTLD_NOLOAD: libc::c_int = 0x0004;
    #[cfg(not(target_os = "linux"))]
    const RTLD_NOLOAD: libc::c_int = 0x0010;
    let path = std::ffi::CString::new(path).ok()?;
    // SAFETY: `path` is NUL-terminated and the flags are plain integers.
    let handle = unsafe { libc::dlopen(path.as_ptr(), RTLD_LAZY | RTLD_NOLOAD) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: `handle` came from `dlopen` a moment ago.
    unsafe { libc::dlclose(handle) };
    Some(handle)
}

/// `fcntl(fd, F_DUPFD_CLOEXEC, fd + 1)`, then closes the original.
fn dup_above(fd: &std::os::fd::OwnedFd) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw = fd.as_raw_fd();
    // SAFETY: `F_DUPFD_CLOEXEC` takes an integer minimum and returns a descriptor
    // this function then owns.
    let duplicated = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, raw + 1) };
    if duplicated == -1 {
        return None;
    }
    // SAFETY: `duplicated` is a fresh descriptor just returned by `fcntl`.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicated) })
}

/// Throws the `ERR_DLOPEN_FAILED` Node produces for a load failure.
fn throw_load_error(scope: &mut v8::PinScope<'_, '_>, error: &LoadError) {
    throw_code(scope, error.code(), &error.message(), false);
}

/// Throws an error carrying `code`, as Node's `ERR_*` classes do.
///
/// `err.code` is a plain data property rather than a getter: `assert.throws(fn,
/// { code })` reads it off the object, and a getter would make `Object.keys` and
/// `util.inspect` differ from Node's.
pub(crate) fn throw_code(
    scope: &mut v8::PinScope<'_, '_>,
    code: &str,
    message: &str,
    type_error: bool,
) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = if type_error {
        v8::Exception::type_error(scope, text)
    } else {
        v8::Exception::error(scope, text)
    };
    if let (Ok(object), Some(code_value)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, code),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

/// The number of addons loaded on this thread.
///
/// Exposed so a test can prove a load actually happened rather than inferring it
/// from an export appearing on the module object.
pub fn loaded_addon_count() -> usize {
    ADDONS.with(|addons| addons.borrow().len())
}

/// The environment of the most recently loaded addon.
pub fn last_env() -> Option<*mut rn_napi::NapiEnv> {
    ADDONS.with(|addons| addons.borrow().last().map(LoadedAddon::env))
}
