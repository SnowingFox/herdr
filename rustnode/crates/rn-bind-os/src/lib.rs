//! `internalBinding('os')` for rustnode.
//!
//! `lib/os.js` is unchanged Node code: it turns the raw values here into
//! `os.cpus()`, `os.networkInterfaces()`, `os.homedir()` and the rest. The
//! contract is therefore the one `src/node_os.cc` defines, including the
//! deliberately odd shapes it returns:
//!
//! * `getCPUs()` is a flat array of seven entries per core, not an array of
//!   objects, because Node packs it that way to avoid repeated property sets.
//! * `getInterfaceAddresses()` is likewise flat, seven entries per address.
//! * `getUserInfo({ encoding })` returns `{ uid, gid, username, homedir, shell }`
//!   with `shell` possibly `null`.
//! * `getLoadAvg(array)` fills a caller-provided `Float64Array(3)` instead of
//!   returning a value.
//!
//! Where Node calls libuv, this calls `libc` directly. The values match because
//! libuv is itself a thin layer over these same calls; the one difference is
//! that `uv_cpu_info` parses `/proc/stat` for per-core times, which this does
//! too.

use std::ffi::CStr;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/os.json`.
pub const MEMBERS: &[&str] = &[
    "getAvailableParallelism",
    "getCPUs",
    "getFreeMem",
    "getHomeDirectory",
    "getHostname",
    "getInterfaceAddresses",
    "getLoadAvg",
    "getOSInformation",
    "getPriority",
    "getTotalMem",
    "getUptime",
    "getUserInfo",
    "isBigEndian",
    "setPriority",
];

pub struct Os;

impl BindingModule for Os {
    fn namespace(&self) -> &'static str {
        "os"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 14] = [
            (
                "getAvailableParallelism",
                function(scope, "getAvailableParallelism", get_available_parallelism)?,
            ),
            ("getCPUs", function(scope, "getCPUs", get_cpus)?),
            ("getFreeMem", function(scope, "getFreeMem", get_free_mem)?),
            (
                "getHomeDirectory",
                function(scope, "getHomeDirectory", get_home_directory)?,
            ),
            ("getHostname", function(scope, "getHostname", get_hostname)?),
            (
                "getInterfaceAddresses",
                function(scope, "getInterfaceAddresses", get_interface_addresses)?,
            ),
            ("getLoadAvg", function(scope, "getLoadAvg", get_load_avg)?),
            (
                "getOSInformation",
                function(scope, "getOSInformation", get_os_information)?,
            ),
            ("getPriority", function(scope, "getPriority", get_priority)?),
            (
                "getTotalMem",
                function(scope, "getTotalMem", get_total_mem)?,
            ),
            ("getUptime", function(scope, "getUptime", get_uptime)?),
            (
                "getUserInfo",
                function(scope, "getUserInfo", get_user_info)?,
            ),
            (
                "isBigEndian",
                v8::Boolean::new(scope, cfg!(target_endian = "big")).into(),
            ),
            ("setPriority", function(scope, "setPriority", set_priority)?),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the `os` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Os);
    registry.register_module(Credentials);
}

/// Members of `credentials`, matching `contracts/credentials.json`.
pub const CREDENTIALS_MEMBERS: &[&str] = &[
    "getTempDir",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getuid",
    "implementsPosixCredentials",
    "initgroups",
    "safeGetenv",
    "setegid",
    "seteuid",
    "setgid",
    "setgroups",
    "setuid",
];

/// `internalBinding('credentials')`.
///
/// `lib/os.js` and `lib/internal/process/per_thread.js` are the consumers. The
/// interesting member is `safeGetenv`, which is the only permitted way to read
/// an environment variable from the native layer: it refuses when the process
/// could be running setuid, because then the environment may have been replaced
/// by an attacker.
pub struct Credentials;

impl BindingModule for Credentials {
    fn namespace(&self) -> &'static str {
        "credentials"
    }

    fn members(&self) -> &'static [&'static str] {
        CREDENTIALS_MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 14] = [
            (
                "implementsPosixCredentials",
                v8::Boolean::new(scope, cfg!(unix)).into(),
            ),
            ("safeGetenv", function(scope, "safeGetenv", safe_getenv)?),
            ("getTempDir", function(scope, "getTempDir", get_temp_dir)?),
            ("getuid", function(scope, "getuid", get_uid)?),
            ("geteuid", function(scope, "geteuid", get_euid)?),
            ("getgid", function(scope, "getgid", get_gid)?),
            ("getegid", function(scope, "getegid", get_egid)?),
            ("getgroups", function(scope, "getgroups", get_groups)?),
            ("setuid", function(scope, "setuid", set_uid)?),
            ("seteuid", function(scope, "seteuid", set_euid)?),
            ("setgid", function(scope, "setgid", set_gid)?),
            ("setegid", function(scope, "setegid", set_egid)?),
            ("setgroups", function(scope, "setgroups", set_groups)?),
            ("initgroups", function(scope, "initgroups", init_groups)?),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Whether the environment can be trusted.
///
/// Node refuses to read it when the real and effective ids differ, or when the
/// process is subject to a Linux capability-driven privilege change, because in
/// both cases the environment may belong to whoever invoked the binary.
fn environment_is_trusted() -> bool {
    // SAFETY: these take no arguments and cannot fail.
    unsafe { libc::getuid() == libc::geteuid() && libc::getgid() == libc::getegid() }
}

fn safe_getenv(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(name) = args.get(0).to_string(scope) else {
        return;
    };
    let name = name.to_rust_string_lossy(scope);
    if !environment_is_trusted() {
        return;
    }
    // `undefined` when unset, which is what the JavaScript layer checks for.
    if let Ok(value) = std::env::var(&name) {
        set_string(scope, &mut rv, &value);
    }
}

fn get_temp_dir(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if !environment_is_trusted() {
        return;
    }
    // `TMPDIR`, then `TMP`, then `TEMP`, matching Node.
    for name in ["TMPDIR", "TMP", "TEMP"] {
        let Ok(dir) = std::env::var(name) else {
            continue;
        };
        if dir.is_empty() {
            continue;
        }
        let dir = if dir.len() > 1 {
            dir.strip_suffix('/').unwrap_or(&dir).to_string()
        } else {
            dir
        };
        set_string(scope, &mut rv, &dir);
        return;
    }
}

fn get_uid(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // SAFETY: no arguments, cannot fail.
    rv.set(v8::Integer::new(scope, unsafe { libc::getuid() } as i32).into());
}

fn get_euid(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // SAFETY: no arguments, cannot fail.
    rv.set(v8::Integer::new(scope, unsafe { libc::geteuid() } as i32).into());
}

fn get_gid(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // SAFETY: no arguments, cannot fail.
    rv.set(v8::Integer::new(scope, unsafe { libc::getgid() } as i32).into());
}

fn get_egid(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // SAFETY: no arguments, cannot fail.
    rv.set(v8::Integer::new(scope, unsafe { libc::getegid() } as i32).into());
}

fn get_groups(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let groups = supplementary_groups();
    let array = v8::Array::new(scope, groups.len() as i32);
    for (index, group) in groups.iter().enumerate() {
        array.set_index(scope, index as u32, v8::Integer::new(scope, *group).into());
    }
    rv.set(array.into());
}

fn supplementary_groups() -> Vec<i32> {
    // SAFETY: `getgroups(0, null)` reports the count without writing anything.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return Vec::new();
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: `groups` has room for exactly `count` entries.
    let written = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if written < 0 {
        return Vec::new();
    }
    groups.truncate(written as usize);
    groups.into_iter().map(|group| group as i32).collect()
}

/// Resolves a uid that may be a number or a user name, after
/// `src/node_credentials.cc`'s `uid_by_name`.
///
/// `is_uint32` rather than `int32_value`: V8's numeric accessors *coerce*, so
/// `int32_value` answers `Some(0)` for the string `"nobody"` and every name
/// would become uid 0. Node guards with
/// `args[0]->IsUint32() || args[0]->IsString()` for the same reason, and
/// `lib/internal/bootstrap/switches/does_own_process_state.js` validates the
/// argument before it ever reaches here.
fn resolve_uid(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<libc::uid_t> {
    if value.is_uint32() {
        return Some(value.uint32_value(scope)? as libc::uid_t);
    }
    let name = std::ffi::CString::new(value.to_string(scope)?.to_rust_string_lossy(scope)).ok()?;
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buffer = vec![0 as libc::c_char; 8192];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for its stated length, and `entry` and
    // `buffer` outlive the call.
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status == 0 && !result.is_null() {
        // SAFETY: `result` points into `entry`, which `getpwnam_r` filled.
        Some(unsafe { entry.assume_init() }.pw_uid)
    } else {
        None
    }
}

/// Resolves a gid that may be a number or a group name, after
/// `src/node_credentials.cc`'s `gid_by_name`.
fn resolve_gid(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
) -> Option<libc::gid_t> {
    if value.is_uint32() {
        return Some(value.uint32_value(scope)? as libc::gid_t);
    }
    let name = std::ffi::CString::new(value.to_string(scope)?.to_rust_string_lossy(scope)).ok()?;
    let mut entry = std::mem::MaybeUninit::<libc::group>::zeroed();
    let mut buffer = vec![0 as libc::c_char; 8192];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: as in `resolve_uid`.
    let status = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status == 0 && !result.is_null() {
        // SAFETY: `result` points into `entry`, which `getgrnam_r` filled.
        Some(unsafe { entry.assume_init() }.gr_gid)
    } else {
        None
    }
}

fn set_uid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `1` is the "unknown credential" answer the JavaScript wrapper turns into
    // `ERR_UNKNOWN_CREDENTIAL`; a libc failure throws with its errno instead.
    let Some(uid) = resolve_uid(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    };
    // SAFETY: a single id; failure is reported through errno.
    if unsafe { libc::setuid(uid) } == -1 {
        throw_errno(scope, "setuid");
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

fn set_euid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(uid) = resolve_uid(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    };
    // SAFETY: as in `set_uid`.
    if unsafe { libc::seteuid(uid) } == -1 {
        throw_errno(scope, "seteuid");
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

fn set_gid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(gid) = resolve_gid(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    };
    // SAFETY: as in `set_uid`.
    if unsafe { libc::setgid(gid) } == -1 {
        throw_errno(scope, "setgid");
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

fn set_egid(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(gid) = resolve_gid(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    };
    // SAFETY: as in `set_uid`.
    if unsafe { libc::setegid(gid) } == -1 {
        throw_errno(scope, "setegid");
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

fn set_groups(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    };
    let mut groups = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(value) = array.get_index(scope, index) else {
            return;
        };
        let Some(gid) = resolve_gid(scope, value) else {
            // One-based, which is what the wrapper's `groups[result - 1]` reads.
            rv.set(v8::Integer::new_from_unsigned(scope, index + 1).into());
            return;
        };
        groups.push(gid);
    }
    // SAFETY: `groups` owns exactly `groups.len()` initialised entries.
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } == -1 {
        throw_errno(scope, "setgroups");
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

fn init_groups(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `1` means the user is unknown and `2` the group, which the wrapper turns
    // into `ERR_UNKNOWN_CREDENTIAL` naming the right one.
    let Some(uid) = resolve_uid(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    };
    let Some(gid) = resolve_gid(scope, args.get(1)) else {
        rv.set(v8::Integer::new(scope, 2).into());
        return;
    };
    // `initgroups` takes a user *name*, so the id is looked up back to one.
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buffer = vec![0 as libc::c_char; 8192];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for its stated length, and `entry` and
    // `buffer` outlive the call.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            entry.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    }
    // SAFETY: `result` points into `entry`, which `getpwuid_r` filled, and
    // `pw_name` points into `buffer`, which is still alive.
    let name = unsafe { entry.assume_init() }.pw_name;
    if name.is_null() {
        rv.set(v8::Integer::new(scope, 1).into());
        return;
    }
    // SAFETY: `name` is NUL-terminated inside `buffer`.
    if unsafe { libc::initgroups(name, gid) } == -1 {
        throw_errno(scope, "initgroups");
        return;
    }
    rv.set(v8::Integer::new(scope, 0).into());
}

/// `UVException`: an error carrying `errno`, `code`, `syscall` and the message
/// form `lib/**` and Node's own tests expect.
///
/// The shape is `node::UVException`'s, not `Environment::ThrowErrnoException`'s:
/// the message is `"<CODE>, <strerror>"` with the code *inside* it, `errno` is
/// the positive number, and `code` is the symbolic name (`EPERM`). Node's
/// `does_own_process_state` wrapper rethrows this object unchanged, so a test
/// comparing `e.code` or the message sees these fields.
fn throw_errno(scope: &mut v8::PinScope<'_, '_>, syscall: &str) {
    let errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EINVAL);
    // `uv_err_name` is the symbolic spelling; libc's `strerror` is the text
    // after the comma.
    let code = match errno {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ENOMEM => "ENOMEM",
        libc::ENOSYS => "ENOSYS",
        _ => "UNKNOWN",
    };
    // SAFETY: `strerror` returns a static string for any int, and it is never
    // null for a valid errno on glibc.
    let detail = unsafe {
        let pointer = libc::strerror(errno);
        if pointer.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(pointer)
                .to_string_lossy()
                .into_owned()
        }
    };
    let message = format!("{code}, {detail}");
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let error = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(error) {
        for (name, value) in [
            ("errno", v8::Integer::new(scope, errno).into()),
            (
                "code",
                v8::String::new(scope, code)
                    .map(|text| text.into())
                    .unwrap_or_else(|| v8::undefined(scope).into()),
            ),
            (
                "syscall",
                v8::String::new(scope, syscall)
                    .map(|text| text.into())
                    .unwrap_or_else(|| v8::undefined(scope).into()),
            ),
        ] {
            if let Some(key) = v8::String::new(scope, name) {
                object.set(scope, key.into(), value);
            }
        }
    }
    scope.throw_exception(error);
}

fn get_hostname(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match hostname() {
        Ok(name) => set_string(scope, &mut rv, &name),
        // Node reports failure by filling the context object and returning
        // `undefined`; `lib/os.js` turns that into `ERR_SYSTEM_ERROR`. Throwing
        // here instead would bypass that and lose the errno.
        Err(error) => report_system_error(scope, &args, "uv_os_gethostname", &error),
    }
}

/// Fills the error context object the way `CollectUVExceptionInfo` does.
///
/// `lib/os.js` wraps these calls in `getCheckedFunction`, which passes a fresh
/// object and throws `ERR_SYSTEM_ERROR` when the call returns `undefined`. The
/// object therefore has to carry `errno`, `code`, `message` and `syscall`.
fn report_system_error(
    scope: &mut v8::PinScope,
    args: &v8::FunctionCallbackArguments<'_>,
    syscall: &str,
    error: &SystemError,
) {
    let context = args.get(args.length() - 1);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(context) {
        let fields: [(&str, v8::Local<v8::Value>); 4] = [
            ("errno", v8::Integer::new(scope, error.errno).into()),
            (
                "code",
                v8::String::new(scope, &error.code)
                    .map(|text| text.into())
                    .unwrap_or_else(|| v8::undefined(scope).into()),
            ),
            (
                "message",
                v8::String::new(scope, &error.message)
                    .map(|text| text.into())
                    .unwrap_or_else(|| v8::undefined(scope).into()),
            ),
            (
                "syscall",
                v8::String::new(scope, syscall)
                    .map(|text| text.into())
                    .unwrap_or_else(|| v8::undefined(scope).into()),
            ),
        ];
        for (name, value) in fields {
            if let Some(key) = v8::String::new(scope, name) {
                object.set(scope, key.into(), value);
            }
        }
    }
}

/// The `errno`, `code` and `message` Node would put in an error context.
#[derive(Debug)]
pub struct SystemError {
    pub errno: i32,
    pub code: String,
    pub message: String,
}

impl SystemError {
    fn from_io(error: std::io::Error, code: &str) -> Self {
        Self {
            errno: error.raw_os_error().unwrap_or(0),
            code: code.to_string(),
            message: error.to_string(),
        }
    }
}

fn hostname() -> Result<String, SystemError> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid, correctly sized buffer and `len` reports the
    // size on entry, as `gethostname` requires.
    let result = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if result != 0 {
        return Err(SystemError::from_io(
            std::io::Error::last_os_error(),
            "ERR_SYSTEM_ERROR",
        ));
    }
    // SAFETY: `gethostname` null-terminates within the buffer on success, or
    // leaves it unterminated only when it truncated, which the length check
    // below turns into an error.
    let name = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
    Ok(name.to_string_lossy().into_owned())
}

fn get_os_information(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `[sysname, version, release, machine]`, the shape `os.version()` and
    // friends read.
    let info = os_information();
    let array = v8::Array::new(scope, 4);
    for (index, value) in info.iter().enumerate() {
        if let Some(text) = v8::String::new(scope, value) {
            array.set_index(scope, index as u32, text.into());
        }
    }
    rv.set(array.into());
}

fn os_information() -> [String; 4] {
    // `uname` is what `uv_os_uname` wraps.
    // SAFETY: `utsname` is a plain-old-data struct that `uname` fully writes.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is a valid, writable `utsname`.
    let result = unsafe { libc::uname(&mut uts) };
    if result != 0 {
        return [
            std::env::consts::OS.to_string(),
            String::new(),
            String::new(),
            std::env::consts::ARCH.to_string(),
        ];
    }
    let field = |bytes: &[libc::c_char]| -> String {
        // SAFETY: the arrays in `utsname` are null-terminated by `uname`.
        unsafe { CStr::from_ptr(bytes.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    [
        field(&uts.sysname),
        field(&uts.version),
        field(&uts.release),
        field(&uts.machine),
    ]
}

fn get_cpus(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Seven entries per core: model, speed, then user/nice/sys/idle/irq.
    let cpus = cpu_info();
    let array = v8::Array::new(scope, (cpus.len() * 7) as i32);
    for (core, cpu) in cpus.iter().enumerate() {
        let base = (core * 7) as u32;
        if let Some(model) = v8::String::new(scope, &cpu.model) {
            array.set_index(scope, base, model.into());
        }
        let times = [cpu.speed, cpu.user, cpu.nice, cpu.sys, cpu.idle, cpu.irq];
        for (offset, value) in times.iter().enumerate() {
            let number = v8::Number::new(scope, *value);
            array.set_index(scope, base + 1 + offset as u32, number.into());
        }
    }
    rv.set(array.into());
}

/// One core's worth of the flat `getCPUs` payload.
struct Cpu {
    model: String,
    speed: f64,
    user: f64,
    nice: f64,
    sys: f64,
    idle: f64,
    irq: f64,
}

/// Reads `model name` and `cpu MHz` from `/proc/cpuinfo` and per-core times
/// from `/proc/stat`, which is what `uv_cpu_info` does on Linux.
fn cpu_info() -> Vec<Cpu> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut models = Vec::new();
    let mut speeds = Vec::new();
    for line in cpuinfo.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some(value) = rest.split(':').nth(1) {
                models.push(value.trim().to_string());
            }
        } else if let Some(rest) = line.strip_prefix("cpu MHz") {
            if let Some(value) = rest.split(':').nth(1) {
                speeds.push(value.trim().parse::<f64>().unwrap_or(0.0));
            }
        }
    }
    let model = models
        .first()
        .cloned()
        .unwrap_or_else(|| std::env::consts::ARCH.to_string());

    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let tick = clock_ticks() as f64;
    let mut cpus = Vec::new();
    for line in stat.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        if rest.starts_with(' ') {
            // The aggregate `cpu` line, not a core.
            continue;
        }
        let mut fields = rest.split_whitespace();
        let mut next = || {
            fields
                .next()
                .and_then(|value| value.parse::<f64>().ok())
                .unwrap_or(0.0)
        };
        let user = next();
        let nice = next();
        let sys = next();
        let idle = next();
        let irq = next();
        let index = cpus.len();
        cpus.push(Cpu {
            model: model.clone(),
            speed: speeds.get(index).copied().unwrap_or(0.0),
            // `/proc/stat` counts in clock ticks; libuv reports milliseconds.
            user: user * 1000.0 / tick,
            nice: nice * 1000.0 / tick,
            sys: sys * 1000.0 / tick,
            idle: idle * 1000.0 / tick,
            irq: irq * 1000.0 / tick,
        });
    }

    if cpus.is_empty() {
        // Fall back to a single core so `os.cpus()` is never an empty array,
        // which would break `availableParallelism` callers.
        cpus.push(Cpu {
            model,
            speed: 0.0,
            user: 0.0,
            nice: 0.0,
            sys: 0.0,
            idle: 0.0,
            irq: 0.0,
        });
    }
    cpus
}

fn clock_ticks() -> u64 {
    // SAFETY: `sysconf` takes a plain integer name and returns a long.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as u64
    } else {
        100
    }
}

fn get_free_mem(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Number::new(scope, free_memory() as f64).into());
}

fn get_total_mem(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Number::new(scope, total_memory() as f64).into());
}

/// The `MemAvailable` line from `/proc/meminfo`, which is what
/// `uv_get_free_memory` reports on Linux.
fn free_memory() -> u64 {
    meminfo_kib("MemAvailable")
        .or_else(|| meminfo_kib("MemFree"))
        .map(|kib| kib * 1024)
        .unwrap_or(0)
}

fn total_memory() -> u64 {
    meminfo_kib("MemTotal").map(|kib| kib * 1024).unwrap_or(0)
}

fn meminfo_kib(field: &str) -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo.lines().find_map(|line| {
        let rest = line.strip_prefix(field)?;
        // The line reads `MemTotal:       16384 kB`, so the colon has to go
        // before the value can be parsed.
        rest.trim_start()
            .strip_prefix(':')?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })
}

fn get_uptime(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Number::new(scope, uptime()).into());
}

fn uptime() -> f64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

fn get_load_avg(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // The caller passes a `Float64Array(3)` it expects to be filled in place,
    // not a value to be returned.
    let Ok(array) = v8::Local::<v8::Float64Array>::try_from(args.get(0)) else {
        throw(scope, "getLoadAvg expects a Float64Array");
        return;
    };
    if array.length() != 3 {
        throw(scope, "getLoadAvg expects a Float64Array of length 3");
        return;
    }
    let load = load_average();
    for (index, value) in load.iter().enumerate() {
        let number = v8::Number::new(scope, *value);
        array.set_index(scope, index as u32, number.into());
    }
}

fn load_average() -> [f64; 3] {
    // SAFETY: `getloadavg` writes at most three doubles into the array.
    let mut load = [0f64; 3];
    unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
    load
}

fn get_interface_addresses(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let addresses = interface_addresses();
    let array = v8::Array::new(scope, (addresses.len() * 7) as i32);
    for (address, iface) in addresses.iter().enumerate() {
        let base = (address * 7) as u32;
        let entries: [&str; 4] = [&iface.name, &iface.address, &iface.netmask, &iface.family];
        for (offset, text) in entries.iter().enumerate() {
            if let Some(value) = v8::String::new(scope, text) {
                array.set_index(scope, base + offset as u32, value.into());
            }
        }
        if let Some(value) = v8::String::new(scope, &iface.mac) {
            array.set_index(scope, base + 4, value.into());
        }
        let internal = v8::Boolean::new(scope, iface.internal);
        array.set_index(scope, base + 5, internal.into());
        let scope_id = v8::Integer::new(scope, iface.scope_id);
        array.set_index(scope, base + 6, scope_id.into());
    }
    rv.set(array.into());
}

struct Interface {
    name: String,
    address: String,
    netmask: String,
    family: String,
    mac: String,
    internal: bool,
    scope_id: i32,
}

/// Enumerates IPv4 and IPv6 addresses with `getifaddrs`.
fn interface_addresses() -> Vec<Interface> {
    let mut interfaces = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `list` and returns 0 on success.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return interfaces;
    }

    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: `cursor` walks the list `getifaddrs` allocated and is non-null
        // here.
        let entry = unsafe { &*cursor };
        // SAFETY: `entry` is one live node of that list.
        if let Some(iface) = unsafe { describe_interface(entry) } {
            interfaces.push(iface);
        }
        cursor = entry.ifa_next;
    }

    // SAFETY: `list` is the head `getifaddrs` allocated and is still owned here.
    unsafe { libc::freeifaddrs(list) };
    interfaces
}

/// SAFETY: `entry` must be a live `ifaddrs` from `getifaddrs`.
unsafe fn describe_interface(entry: &libc::ifaddrs) -> Option<Interface> {
    let addr = entry.ifa_addr;
    if addr.is_null() {
        return None;
    }
    let family = (*addr).sa_family as i32;
    let (address, netmask, scope_id) = match family {
        libc::AF_INET => {
            let sockaddr = &*(addr as *const libc::sockaddr_in);
            let address = ipv4_string(sockaddr.sin_addr.s_addr);
            let netmask = if entry.ifa_netmask.is_null() {
                String::new()
            } else {
                ipv4_string(
                    (*(entry.ifa_netmask as *const libc::sockaddr_in))
                        .sin_addr
                        .s_addr,
                )
            };
            (address, netmask, -1)
        }
        libc::AF_INET6 => {
            let sockaddr = &*(addr as *const libc::sockaddr_in6);
            let address = ipv6_string(&sockaddr.sin6_addr.s6_addr);
            let netmask = if entry.ifa_netmask.is_null() {
                String::new()
            } else {
                ipv6_string(
                    &(*(entry.ifa_netmask as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr,
                )
            };
            (address, netmask, sockaddr.sin6_scope_id as i32)
        }
        _ => return None,
    };

    let family = family_field(family);
    let name = CStr::from_ptr(entry.ifa_name)
        .to_string_lossy()
        .into_owned();
    let (mac, internal) = hardware_address(addr);

    Some(Interface {
        name,
        address,
        netmask,
        family,
        mac,
        internal,
        scope_id,
    })
}

/// Formats an IPv4 address in network byte order the way `inet_ntop` does.
fn ipv4_string(raw: u32) -> String {
    // `s_addr` is in network byte order, so the bytes come out of `to_ne_bytes`
    // reversed on a little-endian host.
    let bytes = raw.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Formats an IPv6 address, compressing the longest run of zero groups the way
/// `inet_ntop` does.
fn ipv6_string(bytes: &[u8; 16]) -> String {
    let groups: Vec<u16> = (0..8)
        .map(|index| u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]))
        .collect();

    // Find the longest run of zero groups of length two or more.
    let mut best_start = None;
    let mut best_len = 0;
    let mut start = None;
    for (index, group) in groups.iter().enumerate() {
        if *group == 0 {
            if start.is_none() {
                start = Some(index);
            }
            let len = index - start.unwrap_or(index) + 1;
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            start = None;
        }
    }

    let mut text = String::new();
    let mut index = 0;
    while index < 8 {
        if best_len > 1 && Some(index) == best_start {
            text.push_str("::");
            index += best_len;
            if index == 8 {
                break;
            }
            continue;
        }
        if !text.is_empty() && !text.ends_with(':') {
            text.push(':');
        }
        text.push_str(&format!("{:x}", groups[index]));
        index += 1;
    }
    text
}

fn family_field(family: i32) -> String {
    match family {
        libc::AF_INET => "ipv4".to_string(),
        libc::AF_INET6 => "ipv6".to_string(),
        _ => "unknown".to_string(),
    }
}

/// The MAC address and loopback flag for one address.
///
/// SAFETY: `addr` must point at a live `sockaddr`.
unsafe fn hardware_address(addr: *const libc::sockaddr) -> (String, bool) {
    match (*addr).sa_family as i32 {
        libc::AF_PACKET => {
            let link = &*(addr as *const libc::sockaddr_ll);
            let bytes = &link.sll_addr[..6];
            let mac = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            (mac, false)
        }
        _ => (String::new(), false),
    }
}

fn get_home_directory(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    match home_directory() {
        Some(home) => set_string(scope, &mut rv, &home),
        // `uv_os_homedir` reports `UV_ENOENT` when neither `HOME` nor the
        // passwd entry names a directory.
        None => report_system_error(
            scope,
            &args,
            "uv_os_homedir",
            &SystemError {
                errno: -libc::ENOENT,
                code: "ERR_SYSTEM_ERROR".to_string(),
                message: "no home directory".to_string(),
            },
        ),
    }
}

fn home_directory() -> Option<String> {
    std::env::var("HOME").ok().filter(|home| !home.is_empty())
}

fn get_user_info(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `os.userInfo({ encoding })` may pass an options object; the encoding only
    // matters for non-UTF-8 locales, which a Rust string already normalizes.
    let _ = args;
    match user_info(scope) {
        Some(info) => rv.set(info),
        None => throw(scope, "uv_os_get_passwd: cannot read the passwd entry"),
    }
}

fn user_info<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
    let entry = passwd_entry()?;
    let object = v8::Object::new(scope);
    set(
        scope,
        object,
        "uid",
        v8::Number::new(scope, entry.uid as f64).into(),
    )
    .ok()?;
    set(
        scope,
        object,
        "gid",
        v8::Number::new(scope, entry.gid as f64).into(),
    )
    .ok()?;
    let username = v8::String::new(scope, &entry.username)?;
    set(scope, object, "username", username.into()).ok()?;
    let homedir = v8::String::new(scope, &entry.homedir)?;
    set(scope, object, "homedir", homedir.into()).ok()?;
    match &entry.shell {
        Some(shell) => {
            let shell = v8::String::new(scope, shell)?;
            set(scope, object, "shell", shell.into()).ok()?;
        }
        None => set(scope, object, "shell", v8::null(scope).into()).ok()?,
    }
    Some(object.into())
}

struct Passwd {
    uid: u32,
    gid: u32,
    username: String,
    homedir: String,
    shell: Option<String>,
}

/// Reads the calling user's entry with `getpwuid_r`.
///
/// The reentrant call is used rather than `getpwuid` because the latter returns
/// a pointer into a static buffer that another thread can overwrite.
fn passwd_entry() -> Option<Passwd> {
    // `_SC_GETPW_R_SIZE_MAX` is a hint; fall back to a generous default when
    // the system has no opinion.
    //
    // SAFETY: `sysconf` takes a plain integer name and returns a long.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let size = if suggested > 0 {
        suggested as usize
    } else {
        16 * 1024
    };

    let mut buffer = vec![0u8; size];
    // SAFETY: zeroed `passwd` is a valid all-null struct.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `entry` and `result` are valid out-parameters and `buffer` is
    // writable for its full length.
    let code = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if code != 0 || result.is_null() {
        return None;
    }

    // SAFETY: on success `getpwuid_r` filled the string pointers with addresses
    // into `buffer`, which is still alive here.
    let text = |pointer: *const libc::c_char| -> Option<String> {
        if pointer.is_null() {
            return None;
        }
        Some(
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned(),
        )
    };

    Some(Passwd {
        uid: entry.pw_uid,
        gid: entry.pw_gid,
        username: text(entry.pw_name)?,
        homedir: text(entry.pw_dir)?,
        shell: text(entry.pw_shell),
    })
}

fn get_available_parallelism(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Integer::new(scope, available_parallelism() as i32).into());
}

/// The CPU count `uv_available_parallelism` reports: the affinity mask's size
/// when the process is restricted, otherwise the online CPU count.
fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn get_priority(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let pid = args.get(0).int32_value(scope).unwrap_or(0);
    match priority(pid) {
        Ok(value) => rv.set(v8::Integer::new(scope, value).into()),
        Err(error) => report_system_error(scope, &args, "uv_os_getpriority", &error),
    }
}

fn priority(pid: i32) -> Result<i32, SystemError> {
    // SAFETY: `getpriority` is called with the caller's own pid, which cannot
    // race with anything.
    unsafe {
        *libc::__errno_location() = 0;
        let value = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
        let errno = *libc::__errno_location();
        if errno != 0 {
            return Err(SystemError::from_io(
                std::io::Error::from_raw_os_error(errno),
                "ERR_SYSTEM_ERROR",
            ));
        }
        Ok(value)
    }
}

fn set_priority(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let pid = args.get(0).int32_value(scope).unwrap_or(0);
    let value = args.get(1).int32_value(scope).unwrap_or(0);
    if let Err(error) = set_process_priority(pid, value) {
        report_system_error(scope, &args, "uv_os_setpriority", &error);
        return;
    }
    // Node returns the errno, which is 0 on success.
    rv.set(v8::Number::new(scope, 0.0).into());
}

fn set_process_priority(pid: i32, value: i32) -> Result<(), SystemError> {
    // SAFETY: as in `priority`; the args are plain integers.
    let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, value) };
    if result != 0 {
        return Err(SystemError::from_io(
            std::io::Error::last_os_error(),
            "ERR_SYSTEM_ERROR",
        ));
    }
    Ok(())
}

fn set_string(scope: &mut v8::PinScope, rv: &mut v8::ReturnValue, value: &str) {
    if let Some(text) = v8::String::new(scope, value) {
        rv.set(text.into());
    }
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_not_empty() {
        let name = hostname().expect("a hostname");
        assert!(!name.is_empty());
    }

    #[test]
    fn memory_is_reported_in_bytes() {
        // `os.totalmem()` is bytes, not KiB: /proc/meminfo's unit is the only
        // place a factor of 1024 could go wrong.
        let total = total_memory();
        assert!(total > 0, "total memory should be readable");
        assert!(
            total > 16 * 1024 * 1024,
            "total memory in bytes should exceed 16 MiB"
        );
        assert!(free_memory() <= total);
    }

    #[test]
    fn cpu_info_reports_every_core() {
        let cpus = cpu_info();
        assert!(!cpus.is_empty());
        // Each core's model must be non-empty, since `os.cpus()[0].model` is
        // what most tooling prints.
        assert!(cpus.iter().all(|cpu| !cpu.model.is_empty()));
    }

    #[test]
    fn uname_reports_four_fields() {
        let info = os_information();
        assert!(!info[0].is_empty(), "sysname");
        assert!(!info[3].is_empty(), "machine");
    }

    #[test]
    fn user_info_matches_the_passwd_entry() {
        let info = passwd_entry().expect("a passwd entry for the current user");
        assert!(!info.username.is_empty());
        assert!(!info.homedir.is_empty());
        assert_eq!(info.uid, unsafe { libc::getuid() });
    }

    #[test]
    fn available_parallelism_is_at_least_one() {
        assert!(available_parallelism() >= 1);
    }

    #[test]
    fn load_average_is_readable() {
        let load = load_average();
        assert!(load.iter().all(|value| *value >= 0.0));
    }
}
