//! `Bun.resolve` / `Bun.resolveSync`, and the `file:` URL conversions.
//!
//! # What is reused
//!
//! `pathToFileURL` and `fileURLToPath` are **identical to `node:url` on every
//! case measured**, including the two a hand-rolled encoder gets wrong: `%23` /
//! `%3F` escaping, and the `localhost` authority strip. So they call
//! `rn-bind-url`'s implementations — the same code `node:url` calls — rather than
//! a second copy. There is nothing to reconcile, and a reimplementation would be
//! a second answer to a settled question.
//!
//! # Where Bun's resolver differs from Node's
//!
//! `Bun.resolveSync` **does not** agree with `createRequire(...).resolve` on
//! builtins:
//!
//! ```text
//! Bun.resolveSync("node:fs", dir)  => "node:fs"
//! Bun.resolveSync("fs", dir)       => "node:fs"    Node: "fs"
//! ```
//!
//! That is a real divergence and is reproduced rather than normalised away:
//! builtins answer with the `node:` prefix, and a bare builtin name gains one.
//! Bun also answers `"bun:test"` and other `bun:` specifiers as themselves.
//!
//! For a filesystem path, resolution is the loader's own — relative to the `from`
//! directory, with the extension probes Bun applies (a `.ts` beside a `.js`
//! prefers the `.ts`, and an extensionless specifier is tried against each
//! extension in turn). `rn-module`'s resolver is the seam that owns those rules;
//! what is new here is only the builtin answer that happens before it.
//!
//! # The error
//!
//! A miss is a `ResolveMessage` with `code: "ERR_MODULE_NOT_FOUND"` and the
//! message `Cannot find module '<specifier>' imported from <dir>`. It is still
//! `instanceof Error`, and has **no enumerable own properties**, so
//! `e.constructor.name` is the check that distinguishes it from a plain `Error`.

use std::path::{Path, PathBuf};

use rn_v8_sys::v8;

use crate::error;

/// `Bun.resolveSync(specifier, from)`.
pub fn bun_resolve_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if args.length() == 0 {
        // Measured: no argument at all reports both halves of the signature.
        error::throw_invalid_arg(scope, "Expected a specifier and a from path");
        return;
    }
    if args.length() == 1 {
        error::throw_invalid_arg(scope, "Expected a from path");
        return;
    }

    let specifier = args.get(0);
    let from = args.get(1);
    if !specifier.is_string() || !from.is_string() {
        error::throw_invalid_arg(scope, "Expected a specifier and a from path");
        return;
    }

    let specifier = specifier.to_rust_string_lossy(scope);
    let from = from.to_rust_string_lossy(scope);

    match resolve(&specifier, &from) {
        Some(path) => match v8::String::new(scope, &path) {
            Some(value) => rv.set(value.into()),
            None => error::throw_type_error(scope, "cannot allocate the resolved path"),
        },
        None => throw_resolve_message(scope, &specifier, &from),
    }
}

/// `Bun.resolve(specifier, from)`, a promise of the same answer.
///
/// Measured: the error is thrown from the *call*, not delivered as a rejection,
/// so a bad argument count is a synchronous `TypeError` here too.
pub fn bun_resolve<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if args.length() == 0 {
        error::throw_invalid_arg(scope, "Expected a specifier and a from path");
        return;
    }
    if args.length() == 1 {
        error::throw_invalid_arg(scope, "Expected a from path");
        return;
    }
    let specifier = args.get(0);
    let from = args.get(1);
    if !specifier.is_string() || !from.is_string() {
        error::throw_invalid_arg(scope, "Expected a specifier and a from path");
        return;
    }
    let specifier = specifier.to_rust_string_lossy(scope);
    let from = from.to_rust_string_lossy(scope);

    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        error::throw_type_error(scope, "cannot create a promise");
        return;
    };
    let promise = resolver.get_promise(scope);
    match resolve(&specifier, &from) {
        Some(path) => {
            if let Some(value) = v8::String::new(scope, &path) {
                resolver.resolve(scope, value.into());
            }
        }
        None => {
            let value = crate::error::resolve_message(
                scope,
                &format!("Cannot find module '{specifier}' imported from {from}"),
            );
            if let Some(value) = value {
                resolver.reject(scope, value);
            }
        }
    }
    rv.set(promise.into());
}

/// Throws the `ResolveMessage` Bun throws for a miss.
fn throw_resolve_message(scope: &mut v8::PinScope, specifier: &str, from: &str) {
    match crate::error::resolve_message(
        scope,
        &format!("Cannot find module '{specifier}' imported from {from}"),
    ) {
        Some(value) => {
            scope.throw_exception(value);
        }
        None => error::throw_type_error(scope, "cannot build the resolve error"),
    }
}

/// Resolves `specifier` from the `from` directory, the way Bun answers.
///
/// Order matters and is Bun's: a builtin answers as `node:<name>` before any
/// filesystem lookup happens, so a directory containing a file called `fs.js` does
/// not shadow the builtin. Then the loader's own resolution runs.
pub fn resolve(specifier: &str, from: &str) -> Option<String> {
    if let Some(builtin) = builtin_specifier(specifier) {
        return Some(builtin);
    }

    let base = Path::new(from);
    let candidate = if specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier == "."
        || specifier == ".."
    {
        base.join(specifier)
    } else if Path::new(specifier).is_absolute() {
        PathBuf::from(specifier)
    } else {
        // A bare specifier goes through the real resolver, which is the only
        // place `node_modules` walking and `exports` live.
        return resolve_bare(specifier, base);
    };

    resolve_candidate(&candidate).map(|path| normalise(&path))
}

/// The loader's answer for a bare specifier, or `None`.
fn resolve_bare(specifier: &str, from: &Path) -> Option<String> {
    let anchor = from.join("noop.js");
    match rn_module::resolver::resolve(specifier, &anchor) {
        Ok(path) => Some(path.to_string_lossy().into_owned()),
        Err(_) => None,
    }
}

/// Lexically normalises `.` and `..` segments.
///
/// Measured: `Bun.resolveSync("./hello.txt", dir)` answers
/// `"/tmp/.../hello.txt"`, not `"/tmp/..././hello.txt"`. The bytes are the same
/// file but the string differs, and a caller comparing paths would see it.
/// `..` is resolved lexically rather than through the filesystem, which is what
/// Bun does: a symlinked directory is not followed.
fn normalise(path: &std::path::Path) -> String {
    use std::path::Component;
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() {
                    parts.pop();
                }
            }
            other => parts.push(other.as_os_str().to_os_string()),
        }
    }
    let mut out = std::path::PathBuf::new();
    for part in parts {
        out.push(part);
    }
    out.to_string_lossy().into_owned()
}

/// Tries `candidate`, then its extension probes.
///
/// The probes are the ones Bun applies: the path as given, then each of the
/// source extensions, then an `index` file inside it. `.ts` is probed before
/// `.js`, which is the one ordering a Node resolver gets wrong for a TypeScript
/// project.
fn resolve_candidate(candidate: &Path) -> Option<PathBuf> {
    if candidate.is_file() {
        return Some(candidate.to_path_buf());
    }
    for extension in ["ts", "tsx", "js", "jsx", "mjs", "cjs", "json"] {
        let mut probe = candidate.as_os_str().to_os_string();
        probe.push(".");
        probe.push(extension);
        let probe = PathBuf::from(probe);
        if probe.is_file() {
            return Some(probe);
        }
    }
    if candidate.is_dir() {
        for index in [
            "index.ts",
            "index.tsx",
            "index.js",
            "index.jsx",
            "index.mjs",
        ] {
            let probe = candidate.join(index);
            if probe.is_file() {
                return Some(probe);
            }
        }
    }
    None
}

/// The answer for a builtin specifier, or `None` for anything else.
///
/// Measured: `"node:fs"` answers itself and `"fs"` answers `"node:fs"`, which is
/// the divergence from Node recorded in the spec. `bun:` specifiers are Bun's own
/// and answer as themselves.
pub fn builtin_specifier(specifier: &str) -> Option<String> {
    if specifier.starts_with("bun:") {
        return Some(specifier.to_string());
    }
    if specifier.starts_with("node:") {
        return Some(specifier.to_string());
    }
    if crate::path::is_node_builtin(specifier) {
        return Some(format!("node:{specifier}"));
    }
    None
}

/// A `Stats`-shaped object for `metadata`.
///
/// Bun's own-key order, which is not Node's:
///
/// ```text
/// dev, ino, mode, nlink, uid, gid, rdev, size, blksize, blocks,
/// atimeMs, mtimeMs, ctimeMs, birthtimeMs
/// ```
///
/// Node puts `ino` after `blksize`. The difference is observable through
/// `Object.keys(stats)`, so the order is built rather than left to a struct.
/// `mtimeMs` keeps its fractional part, because both runtimes derive it from the
/// same nanosecond-resolution statx data and a rounded value would differ.
pub fn stats_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    metadata: &std::fs::Metadata,
) -> Option<v8::Local<'s, v8::Object>> {
    use std::os::unix::fs::MetadataExt;

    let object = v8::Object::new(scope);
    let set = |name: &str, value: f64| -> Option<()> {
        let key = v8::String::new(scope, name)?;
        let number = v8::Number::new(scope, value);
        object.set(scope, key.into(), number.into())?;
        Some(())
    };

    set("dev", metadata.dev() as f64)?;
    set("ino", metadata.ino() as f64)?;
    set("mode", metadata.mode() as f64)?;
    set("nlink", metadata.nlink() as f64)?;
    set("uid", metadata.uid() as f64)?;
    set("gid", metadata.gid() as f64)?;
    set("rdev", metadata.rdev() as f64)?;
    set("size", metadata.size() as f64)?;
    set("blksize", metadata.blksize() as f64)?;
    set("blocks", metadata.blocks() as f64)?;

    // Seconds plus nanoseconds, kept as a float so the fractional millisecond
    // survives. `MetadataExt` reports each of these in two parts.
    let millis = |seconds: i64, nanos: i64| (seconds as f64) * 1000.0 + (nanos as f64) / 1e6;
    set("atimeMs", millis(metadata.atime(), metadata.atime_nsec()))?;
    set("mtimeMs", millis(metadata.mtime(), metadata.mtime_nsec()))?;
    set("ctimeMs", millis(metadata.ctime(), metadata.ctime_nsec()))?;

    // Linux reports the creation time through `statx`, which `std` does not
    // expose; Bun and Node both fall back to the ctime when it is missing.
    set(
        "birthtimeMs",
        millis(metadata.ctime(), metadata.ctime_nsec()),
    )?;

    // The prototype the four `*Is` checks and the Date accessors live on. Bun's
    // set, without Node 28's `*Instant` getters, which Bun does not have.
    let source = v8::String::new(
        scope,
        r#"
        (function (self, isFile, isDirectory, isSymbolicLink, isBlockDevice,
                    isCharacterDevice, isFIFO, isSocket, atime, mtime, ctime, birthtime) {
          const proto = {};
          const define = (name, value) => Object.defineProperty(proto, name, { value, enumerable: false, configurable: true, writable: true });
          define('isFile', function () { return isFile; });
          define('isDirectory', function () { return isDirectory; });
          define('isSymbolicLink', function () { return isSymbolicLink; });
          define('isBlockDevice', function () { return isBlockDevice; });
          define('isCharacterDevice', function () { return isCharacterDevice; });
          define('isFIFO', function () { return isFIFO; });
          define('isSocket', function () { return isSocket; });
          for (const [name, value] of [['atime', atime], ['mtime', mtime], ['ctime', ctime], ['birthtime', birthtime]]) {
            Object.defineProperty(proto, name, { get() { return new Date(value); }, enumerable: false, configurable: true });
          }
          Object.defineProperty(proto, 'constructor', {
            value: function Stats() {},
            enumerable: false,
            configurable: true,
            writable: true,
          });
          proto.constructor.name = 'Stats';
          Object.setPrototypeOf(self, proto);
          return self;
        })
        "#,
    )?;
    let script = v8::Script::compile(scope, source, None)?;
    let factory: v8::Local<v8::Function> = script.run(scope)?.try_into().ok()?;
    let atime = v8::Number::new(scope, millis(metadata.atime(), metadata.atime_nsec()));
    let mtime = v8::Number::new(scope, millis(metadata.mtime(), metadata.mtime_nsec()));
    let ctime = v8::Number::new(scope, millis(metadata.ctime(), metadata.ctime_nsec()));
    let birthtime = v8::Number::new(scope, millis(metadata.ctime(), metadata.ctime_nsec()));
    let file_type = metadata.file_type();
    let result = factory.call(
        scope,
        v8::undefined(scope).into(),
        &[
            object.into(),
            v8::Boolean::new(scope, file_type.is_file()).into(),
            v8::Boolean::new(scope, file_type.is_dir()).into(),
            v8::Boolean::new(scope, file_type.is_symlink()).into(),
            v8::Boolean::new(scope, false).into(),
            v8::Boolean::new(scope, false).into(),
            v8::Boolean::new(scope, false).into(),
            v8::Boolean::new(scope, false).into(),
            atime.into(),
            mtime.into(),
            ctime.into(),
            birthtime.into(),
        ],
    )?;
    v8::Local::<v8::Object>::try_from(result).ok()
}

/// `Bun.pathToFileURL(path)`, identical to `node:url`'s.
///
/// Measured: the return value is a **`URL` object**, not a string —
/// `Bun.pathToFileURL("/tmp/x") instanceof URL` is true and `.href` reads off it.
/// So the serialised href is passed to the realm's own `URL` constructor rather
/// than returned directly; handing back the string was a real divergence the
/// `instanceof` check caught.
pub fn bun_path_to_file_url<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let input = args.get(0);
    let Ok(text) = v8::Local::<v8::String>::try_from(input) else {
        error::throw_invalid_arg(
            scope,
            "The \"path\" argument must be of type string or an instance of URL",
        );
        return;
    };
    let path = text.to_rust_string_lossy(scope);
    let Some(href) = crate::path::path_to_file_url(&path) else {
        error::throw_type_error(scope, "cannot encode the path as a file URL");
        return;
    };

    // `new URL(href)` from the realm, so the object is the realm's own `URL` and
    // `instanceof URL` holds. A `URL` this crate built would be a second one.
    let global = scope.get_current_context().global(scope);
    let Some(key) = v8::String::new(scope, "URL") else {
        return;
    };
    let Some(url) = global.get(scope, key.into()) else {
        return;
    };
    let Ok(url) = v8::Local::<v8::Function>::try_from(url) else {
        error::throw_type_error(scope, "URL is not a constructor");
        return;
    };
    let Some(href) = v8::String::new(scope, &href) else {
        return;
    };
    match url.new_instance(scope, &[href.into()]) {
        Some(object) => rv.set(object.into()),
        None => error::throw_type_error(scope, "cannot build the file URL"),
    }
}

/// `Bun.fileURLToPath(url)`, identical to `node:url`'s.
///
/// A non-`file:` URL is `ERR_INVALID_URL_SCHEME` with
/// `The URL must be of scheme file`, which is Node's message and code.
pub fn bun_file_url_to_path<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let input = args.get(0);
    let text = if let Ok(text) = v8::Local::<v8::String>::try_from(input) {
        text.to_rust_string_lossy(scope)
    } else if let Ok(object) = v8::Local::<v8::Object>::try_from(input) {
        // A `URL` object answers through its `href`.
        let Some(key) = v8::String::new(scope, "href") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        if !value.is_string() {
            error::throw_invalid_arg(
                scope,
                "The \"url\" argument must be of type string or an instance of URL",
            );
            return;
        }
        value.to_rust_string_lossy(scope)
    } else {
        error::throw_invalid_arg(
            scope,
            "The \"url\" argument must be of type string or an instance of URL",
        );
        return;
    };

    match crate::path::file_url_to_path(&text) {
        Ok(path) => match v8::String::new(scope, &path) {
            Some(value) => rv.set(value.into()),
            None => error::throw_type_error(scope, "cannot allocate the path"),
        },
        // Measured: the class is `TypeError` (Node's own argument validation),
        // with `ERR_INVALID_URL_SCHEME` on it, not a plain `Error`.
        Err(failure) => error::throw_type_error_with_code(scope, failure.message(), failure.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_builtin_gains_the_node_prefix() {
        // The recorded divergence: Node answers `"fs"`, Bun answers `"node:fs"`.
        assert_eq!(builtin_specifier("fs").as_deref(), Some("node:fs"));
        assert_eq!(builtin_specifier("path").as_deref(), Some("node:path"));
    }

    #[test]
    fn a_prefixed_builtin_answers_itself() {
        assert_eq!(builtin_specifier("node:fs").as_deref(), Some("node:fs"));
    }

    #[test]
    fn a_bun_specifier_answers_itself() {
        assert_eq!(builtin_specifier("bun:test").as_deref(), Some("bun:test"));
    }

    #[test]
    fn a_relative_specifier_is_not_a_builtin() {
        assert_eq!(builtin_specifier("./fs"), None);
        assert_eq!(builtin_specifier("not-a-builtin"), None);
    }

    #[test]
    fn a_ts_file_is_preferred_over_a_js_one_beside_it() {
        // Bun resolves TypeScript, and probing `.js` first would answer a file
        // that is not the one the specifier names.
        let dir = std::env::temp_dir().join("rn-bun-resolve-ts");
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("mod.ts"), b"").expect("ts");
        std::fs::write(dir.join("mod.js"), b"").expect("js");

        let found = resolve("./mod", dir.to_str().expect("utf8")).expect("resolves");
        assert!(found.ends_with("mod.ts"), "resolved to {found}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
