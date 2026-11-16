//! Throwing the errors Bun throws, with Bun's classes, codes and messages.
//!
//! Three families, each measured rather than guessed:
//!
//! * **`TypeError` with `code: "ERR_INVALID_ARG_TYPE"`** for an argument of the
//!   wrong shape. Two of these use Node's argument-validator wording
//!   (`Bun.write`'s destination), the rest use Bun's own terse phrasing
//!   (`path must be a string`). The wording is per member and is pinned by the
//!   tests; there is no shared template that would be right for all of them.
//! * **`Error` with a `code`** for a syscall failure — `ENOENT`, `EISDIR`,
//!   `EINVAL`. The message is Bun's, which is *usually* Node's
//!   (`ENOENT: no such file or directory, open 'x'`) but is Bun's own for a
//!   directory read (`Directories cannot be read like files`, where Node says
//!   `EISDIR: illegal operation on a directory, read`).
//! * **`ResolveMessage`** for `Bun.resolve`'s failure, which is a custom class
//!   that is still `instanceof Error` and carries `code`.
//!
//! The `code` property is what callers branch on, and its *presence* is
//! observable: a `TypeError` from this module carries `ERR_INVALID_ARG_TYPE`
//! where a plain `TypeError` would not, and Bun's own errors all carry one.

use std::io;

use rn_v8_sys::v8;

/// `ERR_INVALID_ARG_TYPE`, the code Bun puts on every argument `TypeError`.
pub const INVALID_ARG_TYPE: &str = "ERR_INVALID_ARG_TYPE";

/// Throws a `TypeError` with Bun's `ERR_INVALID_ARG_TYPE` code and `message`.
///
/// The code goes on as an own property after construction, which is how both
/// Node's `ERR_INVALID_ARG_TYPE` subclass and Bun's plain `TypeError` present
/// it: `e instanceof TypeError` is true and `e.code` is the string.
pub fn throw_invalid_arg(scope: &mut v8::PinScope, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    set_code(scope, exception, INVALID_ARG_TYPE);
    scope.throw_exception(exception);
}

/// Throws a `TypeError` carrying `code`.
///
/// Node's argument-validators throw `TypeError` subclasses whose `code` is a
/// string; `fileURLToPath` on a non-`file:` URL is `ERR_INVALID_URL_SCHEME` in
/// that shape, which is a `TypeError` and not a plain `Error`.
pub fn throw_type_error_with_code(scope: &mut v8::PinScope, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    set_code(scope, exception, code);
    scope.throw_exception(exception);
}

/// Throws a `TypeError` with `message` and no code.
///
/// Used only where Bun genuinely has no code, which in this group is nowhere —
/// it is kept so a future member cannot quietly reuse
/// [`throw_invalid_arg`] for an error that should not carry the code.
pub fn throw_type_error(scope: &mut v8::PinScope, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a plain `Error` with `message` and no code.
///
/// Bun uses this for the file-system router's "Unable to find directory": it is
/// an `Error`, not a `TypeError`, and `error.code` is `undefined`.
pub fn throw_plain_error(scope: &mut v8::PinScope, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a plain `Error` carrying `code`, with `message` as given.
pub fn throw_error(scope: &mut v8::PinScope, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    set_code(scope, exception, code);
    scope.throw_exception(exception);
}

/// A syscall failure, in the shape Bun reports it.
///
/// `errno` is recorded because the `Error` Bun throws carries it alongside the
/// code, and a caller that rethrows through `util.getSystemErrorName` needs the
/// number rather than the string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallError {
    /// The `raw_os_error` value, or 0 when the failure did not come from a
    /// syscall.
    pub errno: i32,
    /// The `<CODE>` half of the message, also installed as `code`.
    pub code: &'static str,
    /// The full message, which is Bun's and is not always Node's.
    pub message: String,
}

impl SyscallError {
    /// Builds the message Bun would for `path` and `syscall`.
    ///
    /// Bun's form is `<CODE>: <reason>, <syscall> '<path>'`, with the reason
    /// taken from the `strerror` table. It is the same shape Node's
    /// `UVException` produces, which is why most cases are indistinguishable
    /// between the two runtimes.
    pub fn new(error: &io::Error, syscall: &str, path: &str) -> Self {
        let errno = error.raw_os_error().unwrap_or(0);
        let code = code_of(errno);
        let reason = reason_of(error);
        Self {
            errno,
            code,
            message: format!("{code}: {reason}, {syscall} '{path}'"),
        }
    }
}

/// The `code` Bun reports for `errno`.
///
/// The mapping is `uv_err_name`, and only the codes this crate can produce are
/// listed. An unrecognised number becomes `UNKNOWN`, which is what libuv also
/// answers rather than inventing a name.
pub fn code_of(errno: i32) -> &'static str {
    match errno {
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::EEXIST => "EEXIST",
        libc::EISDIR => "EISDIR",
        libc::ENOTDIR => "ENOTDIR",
        libc::EINVAL => "EINVAL",
        libc::ENOSPC => "ENOSPC",
        libc::EROFS => "EROFS",
        libc::EMFILE => "EMFILE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ELOOP => "ELOOP",
        libc::ENOMEM => "ENOMEM",
        libc::EPERM => "EPERM",
        _ => "UNKNOWN",
    }
}

/// The `strerror` reason for an `io::Error`, in libuv's capitalisation.
///
/// Public so a caller that formats its own message (the `mmap` syscall failures,
/// which carry no path) can reuse the same reasoning without a second copy.
pub fn reason_for(error: &io::Error) -> String {
    reason_of(error)
}

/// The reason text for a code, without the `(os error N)` Rust appends.
///
/// `io::Error`'s `Display` is `<strerror> (os error <n>)`; Bun (through libuv)
/// prints only the `strerror` text, so the suffix is stripped. Dropping it is
/// observable: `Bun.file('nope').text()` rejects with
/// `ENOENT: no such file or directory, open 'nope'`, with no parenthesised
/// errno.
fn reason_of(error: &io::Error) -> String {
    let errno = error.raw_os_error().unwrap_or(0);
    // libuv has its own `uv_strerror` table and two entries differ from glibc's
    // `strerror` on this platform. The difference is visible in every message
    // that carries the reason, so it is corrected here rather than at each site.
    if errno == libc::EISDIR {
        return "illegal operation on a directory".to_string();
    }
    let display = error.to_string();
    let stripped = match display.find(" (os error ") {
        Some(index) => display[..index].to_string(),
        None => display,
    };
    // Rust's Display capitalises the first word (`No such file or directory`);
    // libuv, and therefore Bun and Node, prints it lower-case.
    lowercase_initial(&stripped)
}

/// Lower-cases the first character of `text`.
///
/// Only the initial character, not the whole string: `Permission denied` becomes
/// `permission denied`, while `EISDIR` or `Too many open files` keep the rest of
/// their case. Non-ASCII initials are left alone, since `strerror` text is ASCII.
fn lowercase_initial(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) if first.is_ascii_uppercase() => {
            let mut out = String::with_capacity(text.len());
            out.push(first.to_ascii_lowercase());
            out.push_str(characters.as_str());
            out
        }
        _ => text.to_string(),
    }
}

/// Installs `code` as an own property on a freshly built exception.
fn set_code(scope: &mut v8::PinScope, exception: v8::Local<v8::Value>, code: &str) {
    let Some(object) = v8::Local::<v8::Object>::try_from(exception).ok() else {
        return;
    };
    let (Some(key), Some(value)) = (v8::String::new(scope, "code"), v8::String::new(scope, code))
    else {
        return;
    };
    object.set(scope, key.into(), value.into());
}

/// `error` as an `Error` value with `code` and `errno`, for rejecting a promise.
///
/// Separate from [`throw_syscall`] because a rejection needs the value rather
/// than a throw: settling a promise with it is not an exception until somebody
/// awaits.
pub fn syscall_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    error: &SyscallError,
) -> v8::Local<'s, v8::Value> {
    let Some(text) = v8::String::new(scope, &error.message) else {
        return v8::undefined(scope).into();
    };
    let exception = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let (Some(key), Some(value)) = (
            v8::String::new(scope, "code"),
            v8::String::new(scope, error.code),
        ) {
            let _ = object.set(scope, key.into(), value.into());
        }
        if let Some(key) = v8::String::new(scope, "errno") {
            let value = v8::Number::new(scope, f64::from(error.errno));
            let _ = object.set(scope, key.into(), value.into());
        }
    }
    exception
}

/// Throws a `SyscallError` as an `Error` with `code` and `errno`.
pub fn throw_syscall(scope: &mut v8::PinScope, error: &SyscallError) {
    let value = syscall_value(scope, error);
    scope.throw_exception(value);
}

/// Builds the `ResolveMessage` Bun throws from `Bun.resolve`.
///
/// The class is Bun's own: `e.constructor.name` is `"ResolveMessage"` and
/// `e instanceof Error` is true, with `code` set and **no enumerable own
/// properties** (`Object.keys(e)` is `[]`, because Bun defines the fields
/// non-enumerable). A test must check the constructor name — `instanceof Error`
/// alone would pass for a plain `Error`, which is exactly the confusion the
/// recorded shape warns about.
///
/// # Why the class is built per call
///
/// It is created here rather than cached on the isolate because the only thing
/// that carries across calls is the name, and a `Global` per error would outlive
/// the error. The cost is one function construction per thrown resolve error,
/// which is the failure path.
pub fn resolve_message<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    message: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let source = v8::String::new(
        scope,
        r#"
        (function (message) {
          class ResolveMessage extends Error {
            constructor(text) {
              super(text);
              Object.defineProperty(this, 'name', { value: 'ResolveMessage', configurable: true, writable: true });
              Object.defineProperty(this, 'code', { value: 'ERR_MODULE_NOT_FOUND', enumerable: false, configurable: true, writable: true });
            }
          }
          return new ResolveMessage(message);
        })
        "#,
    )?;
    let script = v8::Script::compile(scope, source, None)?;
    let factory: v8::Local<v8::Function> = script.run(scope)?.try_into().ok()?;
    let text = v8::String::new(scope, message)?;
    factory.call(scope, v8::undefined(scope).into(), &[text.into()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_errno_mapping_names_the_codes_this_crate_raises() {
        assert_eq!(code_of(libc::ENOENT), "ENOENT");
        assert_eq!(code_of(libc::EISDIR), "EISDIR");
        assert_eq!(code_of(libc::EINVAL), "EINVAL");
        // libuv's own fallback rather than an invented name.
        assert_eq!(code_of(999_999), "UNKNOWN");
    }

    #[test]
    fn the_message_omits_rusts_errno_suffix() {
        // `io::Error`'s Display appends ` (os error 2)`; Bun's does not. Leaving
        // it in would make every message in this group differ from the oracle.
        let error = io::Error::from_raw_os_error(libc::ENOENT);
        let built = SyscallError::new(&error, "open", "nope.txt");
        assert_eq!(
            built.message,
            "ENOENT: no such file or directory, open 'nope.txt'"
        );
        assert_eq!(built.code, "ENOENT");
        assert_eq!(built.errno, libc::ENOENT);
    }

    #[test]
    fn the_reason_lowercases_only_the_initial_character() {
        // libuv prints glibc's text with a lower-case initial, so `Permission
        // denied` becomes `permission denied` and nothing else changes.
        assert_eq!(
            reason_of(&io::Error::from_raw_os_error(libc::EACCES)),
            "permission denied"
        );
        assert_eq!(
            reason_of(&io::Error::from_raw_os_error(libc::ENOENT)),
            "no such file or directory"
        );
        // An already-lower-case text is untouched.
        assert_eq!(lowercase_initial("already lower"), "already lower");
        assert_eq!(lowercase_initial(""), "");
    }

    #[test]
    fn eisdir_uses_libuvs_wording_and_not_glibcs() {
        // glibc says `Is a directory`; libuv, and therefore Bun, says
        // `illegal operation on a directory`. The difference reaches every
        // `Bun.write` into a directory, so it is mapped explicitly.
        assert_eq!(
            reason_of(&io::Error::from_raw_os_error(libc::EISDIR)),
            "illegal operation on a directory"
        );
    }
}
