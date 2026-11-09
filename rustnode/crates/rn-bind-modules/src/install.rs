//! Building the `internalBinding('modules')` object.
//!
//! Every member here exists because a line of `lib/**` reads it. The shapes are
//! Node's, and three of them are easy to get wrong in ways that only show up
//! much later:
//!
//! * `readPackageJSON` and friends return a **six-element array**, not an
//!   object. `lib/internal/modules/package_json_reader.js` destructures it by
//!   index, so element order is the contract:
//!
//!   ```text
//!   0 name  1 main  2 type  3 imports  4 exports  5 filePath  (6 private)
//!   ```
//!
//!   `undefined` in a slot means "not present". `type` is never `undefined`:
//!   it is `"none"` when the file did not choose one.
//! * `getPackageScopeConfig` returns *either* that array *or* a string. The
//!   string is the path of the `package.json` the walk would have read, which
//!   is how the JavaScript layer distinguishes "no package here" from "a
//!   package with no fields".
//! * `compileCacheStatus`, `cachedCodeTypes` and `moduleFormats` are
//!   null-prototype objects (and `compileCacheStatus` an array) because user
//!   code must not be able to reach them through `Object.prototype`.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::compile_cache;
use crate::json;
use crate::packages::{self, Lookup, ReadError};

/// Members exposed on the namespace object, matching `contracts/modules.json`.
///
/// This lists what the object actually installs. The two WebAssembly cache
/// members are deliberately absent — they are declared in [`DEFERRED`] instead,
/// because `rn-compat` only checks a deferral that `members` omits. Listing a
/// member in both places would make the contract check pass without ever
/// noticing the gap, which is how `zlib.crc32c` shipped missing.
pub const MEMBERS: &[&str] = &[
    "cachedCodeTypes",
    "compileCacheStatus",
    "enableCompileCache",
    "flushCompileCache",
    "getCompileCacheDir",
    "getCompileCacheEntry",
    "getNearestParentPackageJSON",
    "getNearestParentPackageJSONType",
    "getPackageScopeConfig",
    "getPackageType",
    "getRootPackageJSON",
    "moduleFormats",
    "parsePackageJSON",
    "readPackageJSON",
    "saveCompileCacheEntry",
];

/// Members the namespace needs but this crate does not install yet.
///
/// Both are the WebAssembly half of the compile cache, and both need V8 APIs the
/// linked `v8` crate does not expose: `saveWasmCompileCacheEntry` must call
/// `v8::WasmModuleObject::GetCompiledModule().Serialize()`, and
/// `getWasmCompileCacheEntry` must feed those bytes back through
/// `v8::WasmModuleCompilation` with a module-caching callback. Without a way to
/// produce the bytes there is nothing to store, so an entry could never carry a
/// `module` and the cache would silently never hit.
///
/// They are load-safe: `lib/internal/modules/esm/translators.js` destructures
/// both inside `translateWasm`, so `require`ing that module does not touch them.
pub const DEFERRED: &[(&str, &str)] = &[
    ("getWasmCompileCacheEntry", "needs v8::WasmModuleCompilation with a module-caching callback, which the v8 crate does not expose; an entry could never carry a deserialized module"),
    ("saveWasmCompileCacheEntry", "needs v8::WasmModuleObject::CompiledModule::Serialize(), which the v8 crate does not expose; there are no cached bytes to persist"),
];

/// `internalBinding('modules')`.
pub struct Modules;

impl BindingModule for Modules {
    fn namespace(&self) -> &'static str {
        "modules"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        // Hoisted so no `scope`-taking call is nested inside a `set` argument.
        let status = string_array(scope, compile_cache::COMPILE_CACHE_STATUS)?;
        let code_types = int_object(scope, compile_cache::CACHED_CODE_TYPES)?;
        let formats = int_object(scope, &[("kCommonJS", 0), ("kModule", 1)])?;
        let values: [(&str, v8::Local<v8::Value>); 15] = [
            ("cachedCodeTypes", code_types),
            ("compileCacheStatus", status),
            (
                "enableCompileCache",
                function(scope, "enableCompileCache", enable_compile_cache)?,
            ),
            (
                "flushCompileCache",
                function(scope, "flushCompileCache", flush_compile_cache)?,
            ),
            (
                "getCompileCacheDir",
                function(scope, "getCompileCacheDir", get_compile_cache_dir)?,
            ),
            (
                "getCompileCacheEntry",
                function(scope, "getCompileCacheEntry", get_compile_cache_entry)?,
            ),
            (
                "getNearestParentPackageJSON",
                function(
                    scope,
                    "getNearestParentPackageJSON",
                    get_nearest_parent_package_json,
                )?,
            ),
            (
                "getNearestParentPackageJSONType",
                function(
                    scope,
                    "getNearestParentPackageJSONType",
                    get_nearest_parent_package_json_type,
                )?,
            ),
            (
                "getPackageScopeConfig",
                function(scope, "getPackageScopeConfig", get_package_scope_config)?,
            ),
            (
                "getPackageType",
                function(scope, "getPackageType", get_package_type)?,
            ),
            (
                "getRootPackageJSON",
                function(scope, "getRootPackageJSON", get_root_package_json)?,
            ),
            ("moduleFormats", formats),
            (
                "parsePackageJSON",
                function(scope, "parsePackageJSON", parse_package_json)?,
            ),
            (
                "readPackageJSON",
                function(scope, "readPackageJSON", read_package_json)?,
            ),
            (
                "saveCompileCacheEntry",
                function(scope, "saveCompileCacheEntry", save_compile_cache_entry)?,
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the `modules` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Modules);
}

// ---------------------------------------------------------------------------
// Package metadata
// ---------------------------------------------------------------------------

/// `readPackageJSON(path, isESM, base, specifier)`.
fn read_package_json(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(path) = arg_string(scope, &args, 0) else {
        return;
    };
    let error_context = ErrorContext::from_args(scope, &args);
    let result = packages::with_cache(|cache| match cache.read(&path) {
        Ok(Lookup::Found(config)) => Ok(Some(config)),
        Ok(Lookup::Absent) => Ok(None),
        Err(error) => Err(error),
    });
    finish_lookup(scope, &mut rv, result, &path, error_context);
}

/// `parsePackageJSON(source, jsonPath, isESM, base, specifier)`.
///
/// Unlike `readPackageJSON` this never touches the filesystem or the cache: the
/// caller already has the bytes, which is how a virtual filesystem supplies its
/// own `package.json`.
fn parse_package_json(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(path) = arg_string(scope, &args, 1) else {
        return;
    };
    let error_context = ErrorContext::from_args_at(scope, &args, 2);
    let Some(source) = arg_bytes(scope, &args, 0) else {
        return;
    };
    match json::parse(&source) {
        Ok(fields) => {
            let config = packages::PackageConfig {
                fields,
                file_path: path,
            };
            rv.set(serialize(scope, &config).into());
        }
        Err(_) => throw_invalid_package_config(scope, &path, error_context.as_ref()),
    }
}

/// `getNearestParentPackageJSON(checkPath)`.
fn get_nearest_parent_package_json(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(path) = arg_string(scope, &args, 0) else {
        return;
    };
    let result = packages::with_cache(|cache| packages::nearest_parent_package_json(cache, &path));
    finish_lookup(scope, &mut rv, result, &path, None);
}

/// `getNearestParentPackageJSONType(checkPath)`.
///
/// Returns the bare `type` string, or `undefined` when no `package.json` was
/// found. `lib/internal/modules/run_main.js` uses it to decide whether the
/// entry point is CommonJS, so `undefined` here is what keeps a plain
/// `.js` file on the CommonJS path.
fn get_nearest_parent_package_json_type(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(path) = arg_string(scope, &args, 0) else {
        return;
    };
    let result = packages::with_cache(|cache| packages::nearest_parent_package_json(cache, &path));
    match result {
        Ok(Some(config)) => set_string(scope, &mut rv, config.type_field()),
        Ok(None) => {}
        Err(error) => throw_read_error(scope, &path, &error),
    }
}

/// `getRootPackageJSON(checkPath)`.
fn get_root_package_json(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(path) = arg_string(scope, &args, 0) else {
        return;
    };
    let result = packages::with_cache(|cache| packages::root_package_json(cache, &path));
    finish_lookup(scope, &mut rv, result, &path, None);
}

/// `getPackageScopeConfig(resolvedURL)`.
fn get_package_scope_config(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(url) = arg_string(scope, &args, 0) else {
        return;
    };
    let result = packages::with_cache(|cache| packages::package_scope(cache, &url));
    match result {
        Ok(packages::ScopeResult::Found(config)) => {
            rv.set(serialize(scope, &config).into());
        }
        Ok(packages::ScopeResult::Absent { path }) => {
            // A string, not `undefined`: the JavaScript layer tests
            // `ArrayIsArray(result)` to tell the two answers apart.
            set_string(scope, &mut rv, &path);
        }
        Err(packages::ScopeError::Url(error)) => throw_invalid_url(scope, &url, error),
        // A `package.json` along the walk exists but is unusable. Node reports
        // it as an import failure from the queried URL, which is the only
        // context a scope walk has.
        Err(packages::ScopeError::Read(error)) => {
            throw_invalid_package_config(scope, &url, Some(&ErrorContext::esm(&url)));
            let _ = error;
        }
    }
}

/// `getPackageType(url)`.
fn get_package_type(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(url) = arg_string(scope, &args, 0) else {
        return;
    };
    let result = packages::with_cache(|cache| packages::package_scope(cache, &url));
    match result {
        Ok(found) => {
            if let Some(type_field) = found.type_field() {
                set_string(scope, &mut rv, type_field);
            }
            // Nothing found: `undefined`, which
            // `lib/internal/modules/package_json_reader.js` turns into "none".
        }
        Err(packages::ScopeError::Url(error)) => throw_invalid_url(scope, &url, error),
        Err(packages::ScopeError::Read(error)) => throw_read_error(scope, &url, &error),
    }
}

/// Turns a `read` result into the array Node returns, or throws.
///
/// The walks and the direct read differ only in whether absence is represented
/// as `None` or [`Lookup::Absent`], so both funnel through here.
fn finish_lookup(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    result: Result<Option<packages::PackageConfig>, ReadError>,
    path: &str,
    error_context: Option<ErrorContext>,
) {
    match result {
        Ok(Some(config)) => {
            rv.set(serialize(scope, &config).into());
        }
        // Absent: `undefined`, not an empty array. The JavaScript side treats
        // `undefined` as "no package.json here" and still reports the path.
        Ok(None) => {}
        // Node reports both a malformed file and an unreadable one as
        // `ERR_INVALID_PACKAGE_CONFIG` at the path that was read.
        Err(_) => throw_invalid_package_config(scope, path, error_context.as_ref()),
    }
}

/// `PackageConfig::Serialize`: the seven-slot array.
fn serialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    config: &packages::PackageConfig,
) -> v8::Local<'s, v8::Array> {
    let undefined = v8::undefined(scope);
    let values: [v8::Local<v8::Value>; 7] = [
        config
            .fields
            .name
            .as_deref()
            .and_then(|value| v8::String::new(scope, value))
            .map_or_else(|| undefined.into(), |value| value.into()),
        config
            .fields
            .main
            .as_deref()
            .and_then(|value| v8::String::new(scope, value))
            .map_or_else(|| undefined.into(), |value| value.into()),
        v8::String::new(scope, config.type_field())
            .map_or_else(|| undefined.into(), |value| value.into()),
        config
            .fields
            .imports
            .as_deref()
            .and_then(|value| v8::String::new(scope, value))
            .map_or_else(|| undefined.into(), |value| value.into()),
        config
            .fields
            .exports
            .as_deref()
            .and_then(|value| v8::String::new(scope, value))
            .map_or_else(|| undefined.into(), |value| value.into()),
        v8::String::new(scope, &config.file_path)
            .map_or_else(|| undefined.into(), |value| value.into()),
        config.fields.is_private.map_or_else(
            || undefined.into(),
            |value| v8::Boolean::new(scope, value).into(),
        ),
    ];
    v8::Array::new_with_elements(scope, &values)
}

// ---------------------------------------------------------------------------
// Compile cache
// ---------------------------------------------------------------------------

/// `enableCompileCache(cacheDir, portable, readOnly, keyRoot)`.
///
/// Returns `[status, message, directory]`. The JavaScript wrapper in
/// `lib/internal/modules/helpers.js` turns that into an object, dropping empty
/// strings, so the empty slots must be empty strings rather than `undefined`.
fn enable_compile_cache(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(directory) = arg_string(scope, &args, 0) else {
        // Node throws `ERR_INVALID_ARG_TYPE` here rather than defaulting,
        // because `directory` has already been defaulted in JavaScript and a
        // non-string means user code passed something wrong.
        throw_invalid_arg_type(scope, "cacheDir should be a string");
        return;
    };
    let portable = args.get(1).is_true();
    let read_only = args.get(2).is_true();
    let result = compile_cache::with_cache(|cache| cache.enable(&directory, portable, read_only));
    let values: [v8::Local<v8::Value>; 3] = [
        v8::Integer::new(scope, i32::from(result.status)).into(),
        v8::String::new(scope, &result.message)
            .map_or_else(|| v8::undefined(scope).into(), |value| value.into()),
        v8::String::new(scope, &result.directory)
            .map_or_else(|| v8::undefined(scope).into(), |value| value.into()),
    ];
    rv.set(v8::Array::new_with_elements(scope, &values).into());
}

/// `getCompileCacheDir()`.
///
/// Returns `""` when disabled. The JavaScript wrapper is
/// `_getCompileCacheDir() || undefined`, so the empty string is load-bearing.
fn get_compile_cache_dir(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let directory = compile_cache::with_cache(|cache| cache.tagged_directory().to_string());
    set_string(scope, &mut rv, &directory);
}

/// `flushCompileCache(keepDeserializedCache)`.
fn flush_compile_cache(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let keep = args.get(0);
    if !keep.is_boolean() && !keep.is_undefined() {
        throw_invalid_arg_type(scope, "keepDeserializedCache should be a boolean");
        return;
    }
    compile_cache::with_cache(|cache| cache.flush());
    rv.set_undefined();
}

/// `getCompileCacheEntry(source, filename, type)`.
///
/// Returns a null-prototype object with an `external` handle, plus `transpiled`
/// when a validated cache entry was found. `undefined` means the cache is off.
fn get_compile_cache_entry(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(source) = arg_string(scope, &args, 0) else {
        return;
    };
    let Some(filename) = arg_string(scope, &args, 1) else {
        return;
    };
    let code_type = args.get(2).uint32_value(scope).unwrap_or(0) as i32;
    let Some((key, transpiled)) = compile_cache::with_cache(|cache| {
        cache.get_or_insert(source.as_bytes(), &filename, code_type)
    }) else {
        // The cache is off: `undefined`, which `lib/**` checks for.
        return;
    };

    let external = v8::External::new(scope, pointer_from_key(key));
    let mut names = vec![v8::String::new(scope, "external").expect("key").into()];
    let mut values: Vec<v8::Local<v8::Value>> = vec![external.into()];
    if let Some(transpiled) = transpiled {
        names.push(v8::String::new(scope, "transpiled").expect("key").into());
        values.push(
            v8::String::new(scope, &transpiled)
                .map_or_else(|| v8::undefined(scope).into(), |value| value.into()),
        );
    }
    let null = v8::null(scope);
    rv.set(v8::Object::with_prototype_and_properties(scope, null.into(), &names, &values).into());
}

/// `saveCompileCacheEntry(external, transpiled)`.
fn save_compile_cache_entry(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let handle = args.get(0);
    if !handle.is_external() {
        // Node uses `CHECK`, which aborts; a missing cache is not worth
        // taking the process down, and no `lib/**` caller can reach this
        // without a real handle.
        return;
    }
    let Ok(handle) = v8::Local::<v8::External>::try_from(handle) else {
        return;
    };
    let Some(payload) = arg_string(scope, &args, 1) else {
        return;
    };
    let key = key_from_pointer(handle.value());
    compile_cache::with_cache(|cache| cache.save(key, &payload));
    rv.set_undefined();
}

/// Round-trips a cache key through an `External` handle.
///
/// Node stores a pointer to the native entry. This crate only needs the key, so
/// the key is carried as the pointer value. Cache keys are `u32` and never
/// null for a real entry, and nothing dereferences the handle.
fn pointer_from_key(key: u32) -> *mut std::ffi::c_void {
    // The key is a crc32, which can legitimately be 0; 1 is added so that a
    // null pointer unambiguously means "no handle".
    (usize::try_from(key).unwrap_or(0) + 1) as *mut std::ffi::c_void
}

fn key_from_pointer(pointer: *mut std::ffi::c_void) -> u32 {
    let value = pointer as usize;
    u32::try_from(value.saturating_sub(1)).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// How a `package.json` error message names the importer.
#[derive(Debug, Clone)]
struct ErrorContext {
    /// Absolute URL of the importing module, when the caller supplied one.
    base: Option<String>,
    /// The specifier being imported.
    specifier: String,
}

impl ErrorContext {
    /// Reads `isESM, base, specifier` from argument slot `start`.
    fn from_args(
        scope: &mut v8::PinScope<'_, '_>,
        args: &v8::FunctionCallbackArguments<'_>,
    ) -> Option<Self> {
        // `readPackageJSON(path, isESM, base, specifier)`: the flag is slot 1.
        Self::from_args_at(scope, args, 1)
    }

    fn from_args_at(
        scope: &mut v8::PinScope<'_, '_>,
        args: &v8::FunctionCallbackArguments<'_>,
        start: i32,
    ) -> Option<Self> {
        if !args.get(start).is_true() {
            return None;
        }
        let base = args
            .get(start + 1)
            .to_string(scope)
            .filter(|value| value.is_string())
            .map(|value| value.to_rust_string_lossy(scope));
        let specifier = args
            .get(start + 2)
            .to_string(scope)
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_default();
        Some(Self { base, specifier })
    }

    /// The context a scope walk reports, which is always an ESM import.
    fn esm(url: &str) -> Self {
        Self {
            base: Some(url.to_string()),
            specifier: String::new(),
        }
    }
}

/// Throws `ERR_INVALID_PACKAGE_CONFIG` with Node's wording.
///
/// Node builds this message from three optional pieces:
/// `Invalid package config <path>[ while importing "<specifier>" from <base>].`
fn throw_invalid_package_config(
    scope: &mut v8::PinScope<'_, '_>,
    path: &str,
    context: Option<&ErrorContext>,
) {
    // For a scope walk the error context's base is the queried URL and the
    // specifier is that URL too, which is what `GetPackageScopeConfig` sets.
    let mut message = format!("Invalid package config {path}");
    if let Some(context) = context {
        if let Some(base) = &context.base {
            let specifier = if context.specifier.is_empty() {
                path
            } else {
                &context.specifier
            };
            message.push_str(&format!(
                " while importing \"{specifier}\" from {}",
                file_path_from_url(base).unwrap_or_else(|| base.clone())
            ));
        }
    }
    message.push('.');
    throw_with_code(scope, "ERR_INVALID_PACKAGE_CONFIG", &message, false);
}

/// Throws `ERR_INVALID_PACKAGE_CONFIG` for a read failure, naming the errno.
fn throw_read_error(scope: &mut v8::PinScope<'_, '_>, path: &str, error: &ReadError) {
    let message = match error {
        ReadError::Invalid => format!("Invalid package config {path}."),
        ReadError::Unreadable { errno } => {
            format!("Cannot read package config {path}: {}.", errno_text(*errno))
        }
    };
    throw_with_code(scope, "ERR_INVALID_PACKAGE_CONFIG", &message, false);
}

/// Throws `ERR_INVALID_URL` the way `url::ThrowInvalidURL` does.
///
/// The `input` property is part of the contract: `lib/internal/url.js` checks
/// for it to turn a failed parse into a `TypeError` with the original string.
fn throw_invalid_url(scope: &mut v8::PinScope<'_, '_>, input: &str, error: crate::url::UrlError) {
    let (message, is_type_error) = match error {
        crate::url::UrlError::Invalid => ("Invalid URL".to_string(), true),
        crate::url::UrlError::Host => (
            "File URL host must be \"localhost\" or empty on linux".to_string(),
            true,
        ),
        crate::url::UrlError::EncodedSlash => (
            "File URL path must not include encoded / characters".to_string(),
            true,
        ),
    };
    let Some(text) = v8::String::new(scope, &message) else {
        return;
    };
    let exception = if is_type_error {
        v8::Exception::type_error(scope, text)
    } else {
        v8::Exception::error(scope, text)
    };
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(key) = v8::String::new(scope, "code") {
            if let Some(code) = v8::String::new(scope, "ERR_INVALID_URL") {
                let _ = object.set(scope, key.into(), code.into());
            }
        }
        // `input` is part of the contract: `lib/internal/url.js` reads it to
        // report which string failed to parse.
        if let Some(input) = v8::String::new(scope, input) {
            if let Some(key) = v8::String::new(scope, "input") {
                let _ = object.set(scope, key.into(), input.into());
            }
        }
    }
    scope.throw_exception(exception);
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
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, code),
    ) {
        if let Some(key) = v8::String::new(scope, "code") {
            let _ = object.set(scope, key.into(), code_value.into());
        }
    }
    scope.throw_exception(exception);
}

fn throw_invalid_arg_type(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    throw_with_code(scope, "ERR_INVALID_ARG_TYPE", message, true);
}

/// `uv_strerror` wording for an errno.
fn errno_text(errno: i32) -> String {
    let mut buffer = [0i8; 256];
    // SAFETY: `buffer` is a valid writable region of the length passed, and
    // `strerror_r` (the XSI variant) writes only within it.
    let result = unsafe { libc::strerror_r(errno, buffer.as_mut_ptr(), buffer.len()) };
    if result != 0 {
        return format!("errno {errno}");
    }
    // SAFETY: on success `strerror_r` NUL-terminates inside `buffer`.
    unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Argument and value helpers
// ---------------------------------------------------------------------------

fn arg_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<String> {
    let value = args.get(index);
    if !value.is_string() {
        return None;
    }
    value
        .to_string(scope)
        .map(|v| v.to_rust_string_lossy(scope))
}

/// Reads a string or an `ArrayBufferView` as bytes.
fn arg_bytes(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<Vec<u8>> {
    let value = args.get(index);
    if value.is_string() {
        return value
            .to_string(scope)
            .map(|text| text.to_rust_string_lossy(scope).into_bytes());
    }
    let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) else {
        return None;
    };
    let length = view.byte_length();
    let data = view.data().cast::<u8>();
    if length == 0 {
        return Some(Vec::new());
    }
    if data.is_null() {
        return None;
    }
    // SAFETY: `view` is a live `ArrayBufferView`, so its backing store holds at
    // least `byte_length()` readable bytes starting at `data()`, which already
    // accounts for `byteOffset`.
    Some(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

fn set_string(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, value: &str) {
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
        .ok_or_else(|| format!("cannot allocate modules.{name}"))?;
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

/// An array of strings. `compileCacheStatus` is an array in Node, because the
/// JavaScript layer indexes it to build a name-to-value object.
fn string_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[&str],
) -> Result<v8::Local<'s, v8::Value>, String> {
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        let value = v8::String::new(scope, entry).ok_or("cannot allocate a status name")?;
        values.push(value.into());
    }
    Ok(v8::Array::new_with_elements(scope, &values).into())
}

/// A null-prototype object of integer fields.
fn int_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[(&str, i32)],
) -> Result<v8::Local<'s, v8::Value>, String> {
    let mut names = Vec::with_capacity(entries.len());
    let mut values = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        names.push(
            v8::String::new(scope, name)
                .ok_or("cannot allocate a key")?
                .into(),
        );
        values.push(v8::Integer::new(scope, *value).into());
    }
    let null = v8::null(scope);
    Ok(v8::Object::with_prototype_and_properties(scope, null.into(), &names, &values).into())
}

/// The path part of a `file:` URL, for an error message.
fn file_path_from_url(url: &str) -> Option<String> {
    crate::url::parse_file_url(url)
        .ok()
        .map(|parsed| parsed.pathname)
}
