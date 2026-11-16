//! `legacyMainResolve` and `getFormatOfExtensionlessFile`.
//!
//! Both members were declared deferred with the reason "owned by the CJS
//! loader" / "owned by the ESM loader". That reason was wrong in the way that
//! matters: neither is owned by a loader, they are `fs` members that
//! `lib/internal/modules/helpers.js` calls *directly* on
//! `internalFsBinding` (lines 81-83), and the ESM resolver reaches
//! `legacyMainResolve` on an ordinary dependency resolution through
//! `lib/internal/modules/esm/resolve.js:171`. Declaring them deferred made
//! `npm install` fail on its first package with
//! `internalFsBinding.legacyMainResolve is not a function`.
//!
//! # `legacyMainResolve` returns an index, not a path
//!
//! This is the detail that makes a plausible implementation wrong. The value
//! returned to JavaScript is an index into the suffix table the JavaScript side
//! also holds (`legacyMainResolveExtensions` in `helpers.js`), and the caller
//! reconstructs the path as `main || './'` plus that suffix. Returning the
//! resolved path instead would make `resolve()` concatenate the two and produce
//! a path that does not exist, and npm would misread the failure. The table here
//! and the one in `helpers.js` are the same ten strings in the same order:
//!
//! ```text
//! 0  ""            4  "/index.js"    8  ".json"
//! 1  ".js"         5  "/index.json"  9  ".node"
//! 2  ".json"       6  "/index.node"
//! 3  ".node"       7  ".js"
//! ```
//!
//! Suffixes 0-6 are tried against `<pkgPath>/<main>`; 7-9 are tried against
//! `<pkgPath>/index`. If nothing matches, the function throws
//! `ERR_MODULE_NOT_FOUND` naming the *candidate* it started from, which is why
//! the message differs between the "main was given" and "no main" shapes.
//!
//! # Paths are resolved the way `node::PathResolve` resolves them
//!
//! `PathResolve` is `path.resolve` in C++: it joins the arguments, walks in
//! reverse until it accumulates an absolute path, appends the working directory
//! if none did, and then normalises `.`/`..`/duplicate separators. Using
//! `std::path::Path::join` instead would keep `..` segments, so a `package.json`
//! `main` of `./dist/../lib/index.js` would be stat'ed as written rather than as
//! it resolves. [`normalize_string`] is a byte-for-byte port of the C++
//! `NormalizeString`, including its quirk of treating a trailing separator as one
//! more empty segment to flush.
//!
//! # `getFormatOfExtensionlessFile`
//!
//! Answers 0 (`EXTENSIONLESS_FORMAT_JAVASCRIPT`) or 1
//! (`EXTENSIONLESS_FORMAT_WASM`) by reading the first four bytes of the file and
//! comparing them against the Wasm magic. Every failure — unopenable, unreadable,
//! short — is answer 0, because the caller only distinguishes "wasm" from
//! "everything else".
//!
//! Node reads into an uninitialised `char buffer[4]`, so a file shorter than four
//! bytes compares its tail against whatever was on the stack. That is not
//! reproducible and not worth reproducing: the buffer here is zero-filled, which
//! makes every short file answer 0. A genuinely Wasm file always has all four
//! magic bytes, so nothing observable in the format decision changes.

use rn_v8_sys::v8;
use rn_v8_sys::v8::Local;

use crate::args;
use crate::stats::{is_directory, Follow, StatFields};
use rn_bind_url::file_url::{file_url_to_path, FileUrlToPathError};

/// The ten suffixes main resolution tries, in Node's order.
///
/// `lib/internal/modules/helpers.js` carries the identical list; the returned
/// value indexes into it on the JavaScript side.
pub const LEGACY_MAIN_EXTENSIONS: [&str; 10] = [
    "",
    ".js",
    ".json",
    ".node",
    "/index.js",
    "/index.json",
    "/index.node",
    ".js",
    ".json",
    ".node",
];

/// Where the `main` suffixes stop, from `legacy_main_extensions_with_main_end`.
const MAIN_END: usize = 7;

/// Where the `<pkgPath>/index` suffixes stop, from
/// `legacy_main_extensions_package_fallback_end`.
const FALLBACK_END: usize = 10;

/// `EXTENSIONLESS_FORMAT_JAVASCRIPT`, from `src/node_constants.h`.
pub const EXTENSIONLESS_FORMAT_JAVASCRIPT: i32 = 0;

/// `EXTENSIONLESS_FORMAT_WASM`, from `src/node_constants.h`.
pub const EXTENSIONLESS_FORMAT_WASM: i32 = 1;

/// The Wasm magic number: `\0asm`.
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];

/// What a candidate path turned out to be, including the denial case.
///
/// `FilePathIsFileReturnType` has three states for a reason: a permission
/// denial is neither "a file" nor "not a file", it ends the call with an
/// exception pending.
enum FileProbe {
    File,
    NotFile,
    Denied,
}

/// `legacyMainResolve(pkgPath, main, base)`.
pub fn legacy_main_resolve<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    call: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(package_path) = string_arg(scope, &call, 0) else {
        throw_type_error(scope, &call, 0);
        return;
    };

    // `args[1]->IsString()`: a non-string `main` is not an error, it simply
    // means the package has no usable `main` and resolution falls through to the
    // `index` suffixes. `null` and a number both land here.
    let main = if call.length() >= 2 && call.get(1).is_string() {
        string_arg(scope, &call, 1)
    } else {
        None
    };

    let mut package_initial_file: Vec<u8> = Vec::new();

    if let Some(main) = main {
        let initial = path_resolve(&package_path, &main);
        package_initial_file = initial.clone();
        for (index, extension) in LEGACY_MAIN_EXTENSIONS.iter().enumerate().take(MAIN_END) {
            match probe_file(scope, &join(&initial, extension)) {
                FileProbe::File => {
                    rv.set(v8::Number::new(scope, index as f64).into());
                    return;
                }
                FileProbe::NotFile => {}
                FileProbe::Denied => return,
            }
        }
    }

    // Always recomputed, even when the `main` loop above ran: the fallback
    // suffixes are tried against `<pkgPath>/index` regardless.
    let index_base = path_resolve(&package_path, b"./index");
    let fallback = LEGACY_MAIN_EXTENSIONS
        .iter()
        .enumerate()
        .skip(MAIN_END)
        .take(FALLBACK_END - MAIN_END);
    for (index, extension) in fallback {
        match probe_file(scope, &join(&index_base, extension)) {
            FileProbe::File => {
                rv.set(v8::Number::new(scope, index as f64).into());
                return;
            }
            FileProbe::NotFile => {}
            FileProbe::Denied => return,
        }
    }

    if package_initial_file.is_empty() {
        package_initial_file = join(&index_base, ".js");
    }

    // The base is only validated once resolution has failed, which is why a
    // package that resolves answers its index even with a nonsense base.
    let base = if call.length() >= 3 && call.get(2).is_string() {
        string_arg(scope, &call, 2)
    } else {
        None
    };
    let Some(base) = base else {
        throw_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"base\" argument must be of type string or an instance of URL.",
            true,
        );
        return;
    };

    let module_base = match file_url_to_path(&base) {
        Ok(path) => path,
        Err(error) => {
            throw_url_error(scope, error);
            return;
        }
    };

    let message = format!(
        "Cannot find package '{}' imported from {}",
        String::from_utf8_lossy(&package_initial_file),
        String::from_utf8_lossy(&module_base),
    );
    throw_with_code(scope, "ERR_MODULE_NOT_FOUND", &message, false);
}

/// `getFormatOfExtensionlessFile(filePath)`.
///
/// Returns [`EXTENSIONLESS_FORMAT_WASM`] when the file starts with the Wasm
/// magic number and [`EXTENSIONLESS_FORMAT_JAVASCRIPT`] in every other case,
/// including a path that cannot be opened or read.
pub fn get_format_of_extensionless_file<'a, 's, 'i>(
    scope: &'a mut v8::PinScope<'s, 'i>,
    call: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(path) = string_arg(scope, &call, 0) else {
        throw_type_error(scope, &call, 0);
        return;
    };

    // `THROW_IF_INSUFFICIENT_PERMISSIONS` runs before the open, so a gated path
    // is an error rather than a silent "javascript". Node leaves the return
    // value unset in that case and the pending exception is what the caller
    // sees.
    if let Some(denied) = crate::permission::deny_read(&path) {
        denied.throw(scope);
        return;
    }

    let format = match read_first_four(&path) {
        Some(buffer) if buffer == WASM_MAGIC => EXTENSIONLESS_FORMAT_WASM,
        _ => EXTENSIONLESS_FORMAT_JAVASCRIPT,
    };
    rv.set(v8::Number::new(scope, f64::from(format)).into());
}

/// `BindingData::FilePathIsFile`, which is "stat succeeded and it is not a
/// directory" — so a symlink to a file, a fifo and a device all count as files.
///
/// The stat goes through [`stat_fields_via_c_string`] so an embedded NUL
/// truncates the path, matching the `file_path.c_str()` the C++ passes to
/// `uv_fs_stat`. Without that, `main.js\0zzz` would fail to stat here and fall
/// through to the `index` suffixes, which is the opposite of Node's answer.
fn probe_file(scope: &mut v8::PinScope<'_, '_>, path: &[u8]) -> FileProbe {
    // `FilePathIsFile` passes `kThrowInsufficientPermissions`, so a denial ends
    // the whole call instead of continuing to the next candidate.
    if let Some(denied) = crate::permission::deny_read(path) {
        denied.throw(scope);
        return FileProbe::Denied;
    }
    match stat_fields_via_c_string(path) {
        Ok(fields) if !is_directory(fields.mode) => FileProbe::File,
        Ok(_) => FileProbe::NotFile,
        Err(_) => FileProbe::NotFile,
    }
}

/// `statx` on the C string `path` denotes, truncating at an embedded NUL.
///
/// `StatFields::for_path` rejects a path containing NUL because a `CString`
/// cannot hold one. The C++ has no such constraint: it builds a `std::string`
/// and passes `c_str()`, so everything from the first NUL onward is dropped and
/// the syscall sees the prefix. Reproducing that is not pedantry — it decides
/// which candidate `legacyMainResolve` reports, and its message shows the
/// untruncated path because `package_initial_file` is a `std::string`.
fn stat_fields_via_c_string(path: &[u8]) -> Result<StatFields, crate::error::FsError> {
    let truncated = truncate_at_nul(path);
    StatFields::for_path(truncated, Follow::Yes)
}

/// The prefix before the first NUL, which is what a `c_str()` receiver sees.
fn truncate_at_nul(path: &[u8]) -> &[u8] {
    match path.iter().position(|byte| *byte == 0) {
        Some(at) => &path[..at],
        None => path,
    }
}

/// Reads the first four bytes of `path`, or `None` when it cannot be opened or
/// read. Bytes past a short read stay zero, unlike Node's uninitialised buffer.
///
/// An embedded NUL truncates the path, because that is what the C++ does: it
/// hands `input.out()` — a NUL-terminated buffer — to `uv_fs_open`, so
/// `"<wasm file>\0junk"` opens the wasm file and `"wa\0sm"` opens nothing. A
/// Rust `CString::new` rejects such a path outright, which would answer
/// `JAVASCRIPT` for a file Node sniffs as Wasm.
fn read_first_four(path: &[u8]) -> Option<[u8; 4]> {
    let truncated = truncate_at_nul(path);
    let c_path = std::ffi::CString::new(truncated).ok()?;
    // SAFETY: `c_path` is NUL-terminated and the flags are plain integers. A
    // successful call returns a descriptor this function owns and closes.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let mut buffer = [0u8; 4];
    // SAFETY: `buffer` is four writable bytes and `read` writes at most that
    // many. The descriptor is valid until the `close` below.
    let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    // SAFETY: `fd` came from `open` above and is not used afterwards.
    unsafe { libc::close(fd) };
    if count < 0 {
        return None;
    }
    Some(buffer)
}

/// Concatenates a suffix onto a resolved path, as the C++ does with `+`.
fn join(base: &[u8], suffix: &str) -> Vec<u8> {
    let mut path = Vec::with_capacity(base.len() + suffix.len());
    path.extend_from_slice(base);
    path.extend_from_slice(suffix.as_bytes());
    path
}

/// `node::PathResolve(env, {base, relative})`.
///
/// The two-argument form is the only one either member needs. See the module
/// docs for why this is not `Path::join`.
fn path_resolve(base: &[u8], relative: &[u8]) -> Vec<u8> {
    let cwd = working_directory();
    let paths: [&[u8]; 2] = [base, relative];

    let mut resolved: Vec<u8> = Vec::new();
    let mut resolved_absolute = false;
    let mut index: i64 = paths.len() as i64 - 1;
    while index >= -1 && !resolved_absolute {
        let path: &[u8] = if index >= 0 {
            paths[index as usize]
        } else {
            &cwd
        };
        if !path.is_empty() {
            let mut next = Vec::with_capacity(path.len() + 1 + resolved.len());
            next.extend_from_slice(path);
            next.push(b'/');
            next.extend_from_slice(&resolved);
            resolved = next;
            if path[0] == b'/' {
                resolved_absolute = true;
                break;
            }
        }
        index -= 1;
    }

    let normalized = normalize_string(&resolved, !resolved_absolute);
    if resolved_absolute {
        let mut absolute = Vec::with_capacity(normalized.len() + 1);
        absolute.push(b'/');
        absolute.extend_from_slice(&normalized);
        absolute
    } else if normalized.is_empty() {
        b".".to_vec()
    } else {
        normalized
    }
}

/// The working directory `PathResolve` joins relative paths against.
///
/// `Environment::GetCwd` asks `uv_cwd` and falls back to the directory the
/// executable lives in when the working directory has been removed. The
/// executable path is the closest equivalent available here.
fn working_directory() -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(cwd) = std::env::current_dir() {
        return cwd.as_os_str().as_bytes().to_vec();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.as_os_str().as_bytes().to_vec();
        }
    }
    b".".to_vec()
}

/// `node::NormalizeString(path, allowAboveRoot, "/")`, ported directly.
///
/// The state machine is Node's: `last_slash` and `dots` track the current
/// segment, `last_segment_length` is what tells `..` apart from a segment that
/// merely ends in two dots, and `allow_above_root` decides whether a leading `..`
/// survives. Rewriting it with a `Vec<&str>` stack looks equivalent and is not —
/// `a/..` is `.` while `a/../..` is `..`, and the C++ distinguishes them by
/// those three variables rather than by what it has popped.
fn normalize_string(path: &[u8], allow_above_root: bool) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut last_segment_length: i64 = 0;
    let mut last_slash: i64 = -1;
    let mut dots: i64 = 0;
    let mut code: u8 = 0;

    for i in 0..=path.len() {
        if i < path.len() {
            code = path[i];
        } else if is_path_separator(code) {
            break;
        } else {
            code = b'/';
        }

        if is_path_separator(code) {
            if last_slash == i as i64 - 1 || dots == 1 {
                // An empty segment, or a single `.`: nothing to append.
            } else if dots == 2 {
                let length = result.len() as i64;
                let ends_in_dot_dot = length >= 2
                    && last_segment_length == 2
                    && result[length as usize - 1] == b'.'
                    && result[length as usize - 2] == b'.';
                if !ends_in_dot_dot {
                    if length > 2 {
                        match result.iter().rposition(|byte| *byte == b'/') {
                            None => {
                                result.clear();
                                last_segment_length = 0;
                            }
                            Some(separator) => {
                                result.truncate(separator);
                                let length = result.len() as i64;
                                last_segment_length = match result.iter().rposition(|b| *b == b'/')
                                {
                                    Some(index) => length - 1 - index as i64,
                                    // Mirrors `len - 1 - npos` in the C++, which
                                    // wraps to `len`: the whole result is one
                                    // segment.
                                    None => length,
                                };
                            }
                        }
                        last_slash = i as i64;
                        dots = 0;
                        continue;
                    } else if length != 0 {
                        result.clear();
                        last_segment_length = 0;
                        last_slash = i as i64;
                        dots = 0;
                        continue;
                    }
                }
                if allow_above_root {
                    if !result.is_empty() {
                        result.push(b'/');
                    }
                    result.extend_from_slice(b"..");
                    last_segment_length = 2;
                }
            } else {
                if !result.is_empty() {
                    result.push(b'/');
                }
                result.extend_from_slice(&path[(last_slash + 1) as usize..i]);
                last_segment_length = i as i64 - last_slash - 1;
            }
            last_slash = i as i64;
            dots = 0;
        } else if code == b'.' && dots != -1 {
            dots += 1;
        } else {
            dots = -1;
        }
    }

    result
}

/// `IsPathSeparator` on POSIX.
fn is_path_separator(byte: u8) -> bool {
    byte == b'/'
}

/// Why a `file:` URL could not become a path, as `node::url::FileURLToPath`
/// reports it. `rn-bind-url` owns the conversion and the parsing; this crate
/// only has to turn its failure into the right JS error.
///
/// Throws the error `THROW_ERR_*` produces for a `file:` URL failure.
fn throw_url_error(scope: &mut v8::PinScope<'_, '_>, error: FileUrlToPathError) {
    match error {
        FileUrlToPathError::Invalid => {
            throw_with_code(scope, "ERR_INVALID_URL", "Invalid URL", true);
        }
        FileUrlToPathError::Scheme => {
            throw_with_code(
                scope,
                "ERR_INVALID_URL_SCHEME",
                "The URL must be of scheme file:",
                true,
            );
        }
        // Node formats this one through `SPrintF` with a platform argument that
        // its own format string does not contain, so the real binary aborts on
        // the assertion rather than throwing. Aborting is not something a
        // runtime should copy; the intended message is produced instead.
        FileUrlToPathError::Host => {
            let message = format!(
                "File URL host must be \"localhost\" or empty on {}",
                std::env::consts::OS
            );
            throw_with_code(scope, "ERR_INVALID_FILE_URL_HOST", &message, true);
        }
        FileUrlToPathError::EncodedSlash => {
            throw_with_code(
                scope,
                "ERR_INVALID_FILE_URL_PATH",
                "File URL path must not include encoded / characters",
                true,
            );
        }
    }
}

/// Reads an argument that Node's C++ requires to be a string.
fn string_arg<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    call: &v8::FunctionCallbackArguments<'s>,
    index: i32,
) -> Option<Vec<u8>> {
    let value = call.get(index);
    if !value.is_string() {
        return None;
    }
    let string: Local<v8::String> = value.try_into().ok()?;
    Some(args::encode_utf8(scope, string))
}

/// Throws `TypeError` for an argument Node checks with `CHECK(...IsString())`.
///
/// Node aborts the process there. That is a programming error in the embedding
/// rather than a contract a caller can rely on, so the diagnosis is reported
/// instead, in the wording `lib/internal/errors.js` uses for the same mistake:
/// `ERR_INVALID_ARG_TYPE` naming the argument and what arrived.
fn throw_type_error<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    call: &v8::FunctionCallbackArguments<'s>,
    index: i32,
) {
    let received = if call.length() > index {
        describe_type(call.get(index))
    } else {
        "undefined".to_string()
    };
    let message = format!("The \"path\" argument must be of type string. Received {received}");
    throw_with_code(scope, "ERR_INVALID_ARG_TYPE", &message, true);
}

/// The `typeof`-plus-detail phrasing Node uses for a received argument.
fn describe_type(value: Local<v8::Value>) -> String {
    if value.is_null() {
        return "null".to_string();
    }
    if value.is_undefined() {
        return "undefined".to_string();
    }
    if value.is_number() {
        return "type number".to_string();
    }
    if value.is_boolean() {
        return "type boolean".to_string();
    }
    if value.is_function() {
        return "function".to_string();
    }
    if value.is_object() {
        return "an instance of Object".to_string();
    }
    "type string".to_string()
}

/// Throws an `Error`/`TypeError` carrying a `code`, like `ERR_*` in Node.
fn throw_with_code(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str, type_error: bool) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = if type_error {
        v8::Exception::type_error(scope, text)
    } else {
        v8::Exception::error(scope, text)
    };
    if let (Ok(object), Some(code_value)) = (
        Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, code),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn the_suffix_table_matches_the_javascript_side() {
        // `lib/internal/modules/helpers.js` holds the same ten strings; a change
        // here without a change there makes every returned index wrong.
        assert_eq!(
            LEGACY_MAIN_EXTENSIONS,
            [
                "",
                ".js",
                ".json",
                ".node",
                "/index.js",
                "/index.json",
                "/index.node",
                ".js",
                ".json",
                ".node"
            ]
        );
        assert_eq!(MAIN_END, 7);
        assert_eq!(FALLBACK_END, 10);
    }

    #[test]
    fn absolute_paths_are_joined_and_normalised() {
        assert_eq!(text(&path_resolve(b"/tmp/pkg", b"main")), "/tmp/pkg/main");
        assert_eq!(
            text(&path_resolve(b"/tmp/pkg", b"./index")),
            "/tmp/pkg/index"
        );
        assert_eq!(text(&path_resolve(b"/tmp/pkg/", b"main")), "/tmp/pkg/main");
        assert_eq!(text(&path_resolve(b"/tmp//pkg", b"main")), "/tmp/pkg/main");
    }

    #[test]
    fn dot_segments_are_collapsed_the_way_path_resolve_does() {
        assert_eq!(
            text(&path_resolve(b"/tmp/pkg", b"./dist/../lib/index.js")),
            "/tmp/pkg/lib/index.js"
        );
        assert_eq!(text(&path_resolve(b"/tmp/pkg/sub", b"../../x")), "/tmp/x");
        // Above the root the C++ drops the segment rather than keeping it,
        // because `allowAboveRoot` is false for an absolute result.
        assert_eq!(text(&path_resolve(b"/tmp", b"../../..")), "/");
    }

    #[test]
    fn a_relative_package_path_is_resolved_against_the_working_directory() {
        let cwd = std::env::current_dir().expect("cwd");
        let expected = format!("{}/pkg/main", cwd.to_string_lossy());
        assert_eq!(text(&path_resolve(b"pkg", b"main")), expected);
    }

    #[test]
    fn an_empty_main_leaves_the_package_path_alone() {
        assert_eq!(text(&path_resolve(b"/tmp/pkg", b"")), "/tmp/pkg");
    }

    #[test]
    fn a_missing_main_still_tries_the_index_suffixes() {
        // What the binding does after the `main` loop finds nothing: the
        // fallback base is always `<pkgPath>/index`.
        assert_eq!(
            text(&join(&path_resolve(b"/tmp/pkg", b"./index"), ".js")),
            "/tmp/pkg/index.js"
        );
        assert_eq!(
            text(&join(&path_resolve(b"/tmp/pkg", b"./index"), "/index.node")),
            "/tmp/pkg/index/index.node"
        );
    }

    #[test]
    fn normalize_keeps_a_leading_parent_only_when_allowed() {
        assert_eq!(text(&normalize_string(b"a/../../b", true)), "../b");
        assert_eq!(text(&normalize_string(b"a/../../b", false)), "b");
    }

    #[test]
    fn normalize_does_not_confuse_a_dot_dot_segment_with_a_dotted_name() {
        // `a..` ends in two dots but is not `..`, so it is a whole segment.
        assert_eq!(text(&normalize_string(b"x/a../b", false)), "x/a../b");
        assert_eq!(text(&normalize_string(b"x/../b", false)), "b");
    }

    #[test]
    fn a_wasm_header_is_recognised_and_anything_else_is_javascript() {
        let dir = std::env::temp_dir().join(format!("rn-legacy-main-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let wasm = dir.join("wasm");
        std::fs::write(&wasm, [0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00]).expect("write");
        let js = dir.join("js");
        std::fs::write(&js, b"console.log(1)").expect("write");
        let short = dir.join("short");
        std::fs::write(&short, [0x00u8, 0x61, 0x73]).expect("write");

        use std::os::unix::ffi::OsStrExt;
        let as_bytes = |path: &std::path::Path| path.as_os_str().as_bytes().to_vec();

        assert_eq!(read_first_four(&as_bytes(&wasm)), Some(WASM_MAGIC));
        assert_ne!(read_first_four(&as_bytes(&js)), Some(WASM_MAGIC));
        // A three-byte prefix zero-fills the fourth byte instead of reading
        // whatever was on the stack, so this is deterministically javascript.
        assert_eq!(
            read_first_four(&as_bytes(&short)),
            Some([0x00, 0x61, 0x73, 0x00])
        );
        assert_eq!(read_first_four(&as_bytes(&dir.join("absent"))), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An embedded NUL truncates the path, because the C++ passes `c_str()`.
    ///
    /// Both members are affected and in opposite-looking ways, which is why
    /// both are pinned: a path whose *prefix* names a Wasm file still sniffs as
    /// Wasm, and a `main` whose prefix names a real file still resolves to it
    /// while the message that would have named it shows the whole untruncated
    /// string. Rejecting the path instead is what a `CString::new` does by
    /// default, and it silently changes both answers.
    #[test]
    fn an_embedded_nul_truncates_the_path_the_way_c_str_does() {
        assert_eq!(truncate_at_nul(b"/tmp/ok\x00junk"), b"/tmp/ok");
        assert_eq!(truncate_at_nul(b"\x00junk"), b"");
        assert_eq!(truncate_at_nul(b"/tmp/ok"), b"/tmp/ok");

        let dir = std::env::temp_dir().join(format!("rn-legacy-nul-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let wasm = dir.join("wasm");
        std::fs::write(&wasm, [0x00u8, 0x61, 0x73, 0x6d, 0x01]).expect("write");

        use std::os::unix::ffi::OsStrExt;
        let mut suffixed = wasm.as_os_str().as_bytes().to_vec();
        suffixed.extend_from_slice(b"\x00JUNK");

        // The prefix is the wasm file, so this reads it, matching `input.out()`.
        assert_eq!(read_first_four(&suffixed), Some(WASM_MAGIC));
        // `wa\0sm` truncates to `.../wa`, which does not exist.
        let mut broken = dir.as_os_str().as_bytes().to_vec();
        broken.extend_from_slice(b"/wa\x00sm");
        assert_eq!(read_first_four(&broken), None);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
