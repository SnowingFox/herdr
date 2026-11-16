//! `Bun.file`, and the argument handling its siblings share.
//!
//! # What `Bun.file` accepts
//!
//! A path string, a `file:` `URL`, or an open file descriptor — and nothing
//! else. Measured:
//!
//! ```text
//! Bun.file("/abs/hello.txt")   => size 11, name "/abs/hello.txt"
//! Bun.file("rel.txt")          => size 11, name "rel.txt"
//! Bun.file(new URL("file:...")) => size 11, name "/tmp/.../hello.txt"
//! Bun.file(fd)                 => size of the open file
//! Bun.file(nonexistent)        => size 0, no throw
//! Bun.file()                   !! TypeError ERR_INVALID_ARG_TYPE
//! Bun.file(Bun.file("x"))      !! TypeError ERR_INVALID_ARG_TYPE
//! ```
//!
//! The last line is the one worth naming: a `Blob` is *not* accepted even though
//! it is what this function returns, so the check is for a string, number or
//! `URL` rather than for anything blob-shaped.
//!
//! # `name` is the path as given
//!
//! `Bun.file("./rel.txt").name` is `"./rel.txt"`, not the resolved path, and
//! `Bun.file(fd).name` is `undefined`. The name is therefore a property of the
//! argument and not of the file, which is why the Blob's `name` accessor reads
//! the string that was stored rather than re-deriving one from the handle.

use rn_v8_sys::v8;

use crate::blob;
use crate::error;

/// Installs every member of this group on the `Bun` object.
///
/// This is the crate's one entry point. `target` is the `Bun` global another
/// crate owns; nothing here creates or replaces it, so the surface is additive
/// and the members are published as function values rather than as a second
/// object.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // The file-backed blob handle is what `Bun.file` is built on, so it has to be
    // installed before the entry point that uses it exists — the handle templates
    // are what `create_file_blob` reaches for.
    blob::install(scope, target)?;

    // Every member here reports `length` 1 (measured on Bun 1.4.4), where
    // `rn_core::set_method` publishes 0 because that is what Node's `SetMethod`
    // does. `Bun` is not a Node binding namespace, so Node's rule does not apply
    // and the measured arity is the honest one: a script that inspects
    // `Bun.write.length` is asking about Bun, not about a binding.
    rn_core::set_named_method_with_length(scope, target, "write", 1, crate::write::bun_write)?;
    rn_core::set_named_method_with_length(scope, target, "mmap", 1, crate::mmap::bun_mmap)?;
    rn_core::set_named_method_with_length(scope, target, "which", 1, crate::which::bun_which)?;
    rn_core::set_named_method_with_length(scope, target, "resolve", 1, crate::fspath::bun_resolve)?;
    rn_core::set_named_method_with_length(
        scope,
        target,
        "resolveSync",
        1,
        crate::fspath::bun_resolve_sync,
    )?;
    rn_core::set_named_method_with_length(
        scope,
        target,
        "fileURLToPath",
        1,
        crate::fspath::bun_file_url_to_path,
    )?;
    rn_core::set_named_method_with_length(
        scope,
        target,
        "pathToFileURL",
        1,
        crate::fspath::bun_path_to_file_url,
    )?;

    // The two classes are published as constructors, so they go on as values
    // rather than through `set_method`.
    crate::glob::install(scope, target)?;
    crate::router::install(scope, target)?;

    // `Bun.file`'s own entry point is installed by `blob::install` above, which is
    // where the handle it needs lives.
    Ok(())
}

/// The type Bun infers for a path with no extension, and for binary types.
///
/// Measured: both `Bun.file("noext")` and `Bun.file("a.bin")` report
/// `application/octet-stream`.
pub const OCTET_STREAM: &str = "application/octet-stream";

/// `Bun.file(path)`.
///
/// Builds the Blob through `internal/blob`'s `createBlob` so the result is the
/// realm's own `Blob` — see [`crate::blob`] for why that is the only way to get
/// `instanceof Blob` right.
pub fn bun_file<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(source) = path_argument(scope, args.get(0)) else {
        error::throw_invalid_arg(scope, "Expected file path string or file descriptor");
        return;
    };

    if let Err(reason) = blob::resolve_create(scope) {
        error::throw_type_error(scope, &reason);
        return;
    }

    let name = source.name.clone();
    let type_name = media_type(name.as_deref().unwrap_or(&source.path));
    let value = match blob::create_file_blob(scope, &source.path, &type_name) {
        Ok(value) => value,
        Err(reason) => {
            error::throw_type_error(scope, &reason);
            return;
        }
    };

    // The blob is Node's, built by `internal/blob`. The Bun members and the path
    // they read go on afterwards: see `crate::bprototype` for why they cannot live
    // on `Blob.prototype` itself.
    if let Err(reason) = crate::bprototype::adopt(scope, value, name.as_deref()) {
        error::throw_type_error(scope, &reason);
        return;
    }
    rv.set(value);
}

/// A `Bun.file` argument, resolved to the path a read will open.
struct PathArgument {
    /// What the read opens. A relative path stays relative, so it resolves
    /// against the working directory at read time.
    path: String,
    /// What `.name` reports, or `None` for a descriptor.
    name: Option<String>,
}

/// Interprets `value` as a `Bun.file` argument.
///
/// Returns `None` for anything that is not a string, a number or a `URL`, which
/// is what makes `Bun.file(Bun.file("x"))` a `TypeError` rather than a copy.
fn path_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Option<PathArgument> {
    if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
        let path = text.to_rust_string_lossy(scope);
        return Some(PathArgument {
            name: Some(path.clone()),
            path,
        });
    }

    if value.is_number() {
        let descriptor = value.number_value(scope)?;
        // A descriptor names an already-open file, which has no path. Reading it
        // means reading the descriptor, so the Blob is pointed at the
        // `/proc/self/fd/<n>` link, which resolves to the same open file on
        // Linux and keeps every read going through the path-shaped handle.
        let path = format!("/proc/self/fd/{descriptor}");
        return Some(PathArgument { path, name: None });
    }

    if let Ok(object) = v8::Local::<v8::Object>::try_from(value) {
        // A `URL` is recognised by its `href` and `protocol`, which is the pair
        // `Bun.file` needs and the pair a plain object would not have. Checking
        // the protocol is what refuses a `http:` URL rather than reading
        // nonsense from it.
        if let (Some(href), Some(protocol)) = (
            property(scope, object, "href"),
            property(scope, object, "protocol"),
        ) {
            let href = href.to_rust_string_lossy(scope);
            let protocol = protocol.to_rust_string_lossy(scope);
            if protocol == "file:" {
                match file_url_path(&href) {
                    Some(path) => {
                        return Some(PathArgument {
                            name: Some(path.clone()),
                            path,
                        })
                    }
                    None => return None,
                }
            }
        }
    }

    None
}

fn property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    if value.is_undefined() {
        None
    } else {
        Some(value)
    }
}

/// The filesystem path a `file:` URL names.
fn file_url_path(href: &str) -> Option<String> {
    let bytes = rn_bind_url::file_url::file_url_to_path(href.as_bytes()).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Bun's media type for a path, by extension.
///
/// Measured for every extension in the spec's table. Text types carry
/// `;charset=utf-8` and binary types do not; `.bin` and an extensionless path
/// both fall back to `application/octet-stream`. Matching is on the last
/// extension and is case-insensitive, which is what both Bun and Node do.
pub fn media_type(path: &str) -> String {
    let extension = match path.rsplit_once('.') {
        Some((_, extension)) if !extension.contains('/') => extension.to_ascii_lowercase(),
        _ => return OCTET_STREAM.to_string(),
    };
    match extension.as_str() {
        "txt" => "text/plain;charset=utf-8",
        "json" => "application/json;charset=utf-8",
        "html" | "htm" => "text/html;charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript;charset=utf-8",
        "css" => "text/css;charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "wasm" => "application/wasm",
        "md" => "text/markdown",
        _ => OCTET_STREAM,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_type_table_matches_the_spec() {
        // Every row the spec records, in one place, so a change to the table
        // cannot pass by being tested against itself.
        for (path, expected) in [
            ("a.txt", "text/plain;charset=utf-8"),
            ("a.json", "application/json;charset=utf-8"),
            ("a.html", "text/html;charset=utf-8"),
            ("a.js", "text/javascript;charset=utf-8"),
            ("a.css", "text/css;charset=utf-8"),
            ("a.png", "image/png"),
            ("a.jpg", "image/jpeg"),
            ("a.wasm", "application/wasm"),
            ("a.bin", "application/octet-stream"),
            ("a.md", "text/markdown"),
            ("noext", "application/octet-stream"),
        ] {
            assert_eq!(media_type(path), expected, "for {path}");
        }
    }

    #[test]
    fn text_types_carry_utf8_and_binary_ones_do_not() {
        // The two halves of the rule, stated separately: a text type without the
        // charset and a binary type with one are both divergences.
        assert!(media_type("x.txt").ends_with(";charset=utf-8"));
        assert!(media_type("x.json").ends_with(";charset=utf-8"));
        assert!(!media_type("x.png").contains("charset"));
        assert!(!media_type("x.wasm").contains("charset"));
    }

    #[test]
    fn an_uppercase_extension_is_recognised() {
        assert_eq!(media_type("A.TXT"), "text/plain;charset=utf-8");
    }

    #[test]
    fn a_dot_in_a_directory_name_is_not_an_extension() {
        // `some.dir/file` has no extension, so it must not be typed from `dir`.
        assert_eq!(media_type("some.dir/file"), OCTET_STREAM);
    }
}
