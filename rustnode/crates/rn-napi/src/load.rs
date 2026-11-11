//! Loading a `.node` file and invoking its entry point.
//!
//! Node's `DLOpenImpl` in `src/node_binding.cc` is the reference for everything
//! here: the probe order, the error text, and which object becomes
//! `module.exports`.
//!
//! # What Node probes, in order
//!
//! 1. `node_register_module_v<NODE_MODULE_VERSION>` — the legacy `NODE_MODULE`
//!    macro. At the pin `NODE_MODULE_VERSION` is 153.
//! 2. `napi_register_module_v1` — `NAPI_MODULE_INIT()`. This is the modern path
//!    and the one every current addon uses.
//! 3. Nothing found: `Module did not self-register: '<path>'.`
//!
//! # Why the entry point is probed with `dlsym`
//!
//! The addon's `napi_*` imports are resolved by the dynamic loader against the
//! rustnode binary's exports when the library is opened. The entry point is
//! different: it is a symbol rustnode looks *for*, in the addon, by name. That is
//! a `dlsym` on the handle, and it is why a missing entry point is a clean
//! `ERR_DLOPEN_FAILED` rather than a resolution failure at open time.

use std::path::Path;

use rn_v8_sys::v8;

use crate::abi::{
    NapiAddonGetApiVersionFunc, NapiAddonRegisterFunc, NapiEnv, NapiValue, GET_API_VERSION_SYMBOL,
    LEGACY_MODULE_VERSION, NAPI_DEFAULT_MODULE_API_VERSION, NAPI_SUPPORTED_VERSION_MAX,
    REGISTER_MODULE_SYMBOL,
};
use crate::env::Env;
use crate::platform;

/// Why a `.node` file could not be loaded.
///
/// The variants exist because the messages differ, and Node's messages are what
/// a user sees when an addon is built for the wrong runtime. Collapsing them
/// into one string would lose the distinction between "the file is not there",
/// "the file is not a shared object", and "the file is a shared object that was
/// never meant to be an addon" — the three cases a real installation encounters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The dynamic loader refused to open the file. The text is the loader's own,
    /// which already names the path and the reason.
    Open(String),
    /// The library opened but exported no entry point this runtime understands.
    NotAnAddon(String),
    /// The addon declared a Node-API version this runtime does not support.
    UnsupportedVersion {
        /// The addon's `file://` module URL, which Node names in the message.
        module_name: String,
        module_version: i32,
    },
    /// The library opened and had an entry point, but invoking it failed.
    Registration(String),
}

impl LoadError {
    /// Node's error code for this failure, so `err.code` matches.
    pub fn code(&self) -> &'static str {
        // Every case `DLOpenImpl` produces is `ERR_DLOPEN_FAILED`.
        // `MODULE_NOT_FOUND` is the CommonJS loader's, thrown before reaching
        // here, and this crate deliberately does not reproduce it.
        "ERR_DLOPEN_FAILED"
    }

    /// The message Node would produce, so a test can compare the two directly.
    pub fn message(&self) -> String {
        match self {
            Self::Open(text) => text.clone(),
            Self::NotAnAddon(path) => format!("Module did not self-register: '{path}'."),
            Self::UnsupportedVersion {
                module_name,
                module_version,
            } => format!(
                // `v8impl::ThrowNodeApiVersionError` in `src/node_api.cc`. The text
                // says "Node.js" even though this runtime is not Node: an addon or a
                // test may match on it, and changing the wording would be a
                // compatibility break dressed up as honesty.
                "{module_name} requires Node-API version {module_version}, \
                 but this version of Node.js only supports version \
                 {NAPI_SUPPORTED_VERSION_MAX} add-ons."
            ),
            Self::Registration(text) => text.clone(),
        }
    }
}

/// A loaded addon: the library plus the environment its functions run against.
///
/// The library handle is kept alive deliberately. Dropping it would `dlclose` the
/// object and invalidate every function pointer the addon handed to JavaScript,
/// which would turn the next call into a jump into unmapped memory.
pub struct LoadedAddon {
    /// Held only for its lifetime; never read.
    _library: platform::Library,
    /// Leaked on purpose: the addon keeps the pointer, and this slice has no
    /// environment teardown path.
    env: *mut Env,
}

// SAFETY: the addon and its environment are created and used on the isolate's
// own thread. The raw pointers are not dereferenced on another one.
unsafe impl Send for LoadedAddon {}

impl LoadedAddon {
    /// The environment the addon's callbacks receive.
    pub fn env(&self) -> *mut NapiEnv {
        self.env.cast::<NapiEnv>()
    }
}

/// What a successful load produced.
pub struct LoadResult {
    /// The library handle and the environment the addon runs against.
    pub addon: LoadedAddon,
    /// The `napi_value` the addon's entry point returned, if it returned one.
    ///
    /// Node replaces `module.exports` only when this is a *different* object than
    /// the one it passed in, so the caller decides; a null return means the addon
    /// mutated the exports object in place.
    pub returned_exports: Option<*mut NapiValue>,
}

/// Loads `path` and invokes its Node-API entry point with `exports`.
///
/// # Safety
///
/// Must be called with a live `v8::PinScope` on this thread. The addon's exported
/// values are V8 handles from `scope`, so `scope` must outlive them — which holds
/// because the caller re-exports the result into the module's `exports` before the
/// scope ends.
pub unsafe fn load<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    path: &Path,
    exports: v8::Local<'s, v8::Object>,
) -> Result<LoadResult, LoadError> {
    let path_text = path.to_string_lossy().into_owned();
    let library = platform::Library::open(path).map_err(LoadError::Open)?;

    let callback = library
        .symbol::<NapiAddonRegisterFunc>(REGISTER_MODULE_SYMBOL)
        .ok()
        .and_then(|symbol| *symbol);

    let Some(callback) = callback else {
        // Node falls back to `node_register_module_v<N>` here. That path needs a
        // `napi_module` structure and a `node::Module` this runtime does not
        // expose, so it stays deferred; the message is still Node's, because that
        // is what a user comparing the two runtimes matches on.
        return Err(LoadError::NotAnAddon(path_text));
    };

    let declared_version = library
        .symbol::<NapiAddonGetApiVersionFunc>(GET_API_VERSION_SYMBOL)
        .ok()
        .and_then(|symbol| *symbol)
        .map(|get_version| {
            // SAFETY: the addon exported this entry point, and
            // `NODE_API_MODULE_GET_API_VERSION` defines it as a function taking no
            // arguments.
            unsafe { get_version() }
        })
        .unwrap_or(NAPI_DEFAULT_MODULE_API_VERSION);

    let filename = module_filename_url(path);

    // Node's validation, from `node_napi_env__::New` in `src/node_api.cc`:
    //
    // * below the default the version is *raised* to the default rather than
    //   rejected, so an addon built with `NAPI_VERSION 4` runs with the version-8
    //   surface;
    // * above the maximum is an error, except for `NAPI_VERSION_EXPERIMENTAL`
    //   (`INT32_MAX`), which is accepted.
    //
    // Reproducing the clamp matters: `test_reference_by_node_api_version` builds
    // addons at several declared versions and expects them all to load.
    let module_api_version = if declared_version < NAPI_DEFAULT_MODULE_API_VERSION {
        NAPI_DEFAULT_MODULE_API_VERSION
    } else if declared_version > NAPI_SUPPORTED_VERSION_MAX && declared_version != i32::MAX {
        return Err(LoadError::UnsupportedVersion {
            module_name: filename,
            module_version: declared_version,
        });
    } else {
        declared_version
    };

    let env = Box::into_raw(Box::new(Env::new(module_api_version, &filename)));

    // The guard is what makes every `napi_*` call the addon makes from here on
    // resolve to this scope.
    let guard = crate::scope::ScopeGuard::enter(scope);
    // Record the isolate and context now, so a finalizer or a backing-store
    // deleter that runs with no Node-API scope can still re-enter V8 later. This
    // is the first point where an addon exists that could outlive a callback.
    crate::scope::remember_context(scope);
    let handle = crate::values::to_napi(exports.into());
    // SAFETY: `callback` is the addon's own exported function, `env` is the box
    // just created, and `handle` is a value from the scope the guard published.
    let returned = unsafe { callback(env.cast::<NapiEnv>(), handle) };
    drop(guard);

    Ok(LoadResult {
        addon: LoadedAddon {
            _library: library,
            env,
        },
        returned_exports: (!returned.is_null()).then_some(returned),
    })
}

/// A `node_register_module_v<NODE_MODULE_VERSION>` probe.
///
/// Kept as a named helper so the deferred legacy path is visible in the code
/// rather than implied by an absence.
pub fn legacy_entry_point_symbol() -> String {
    format!("node_register_module_v{LEGACY_MODULE_VERSION}")
}

/// Converts a filesystem path into the `file://` URL Node reports through
/// `node_api_get_module_file_name`.
///
/// Node derives it from `module.filename` with `node::url::FromFilePath`.
/// Percent-encoding matters: `test_general` copies an addon into a directory named
/// `foo%#bar` and requires the reported name to be the *encoded* URL.
pub fn module_filename_url(path: &Path) -> String {
    let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = absolute.to_string_lossy();
    let mut encoded = String::with_capacity(text.len() + 8);
    encoded.push_str("file://");
    for byte in text.bytes() {
        match byte {
            b'%' => encoded.push_str("%25"),
            b'#' => encoded.push_str("%23"),
            b'?' => encoded.push_str("%3F"),
            b' ' => encoded.push_str("%20"),
            _ => encoded.push(byte as char),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_entry_point_uses_nodes_wording() {
        // Copied from `node_binding.cc`: a shared object that is not an addon
        // produces exactly this, including the period inside the quotes.
        let error = LoadError::NotAnAddon("/tmp/dlprobe/nosym.node".to_string());
        assert_eq!(
            error.message(),
            "Module did not self-register: '/tmp/dlprobe/nosym.node'."
        );
    }

    #[test]
    fn every_load_error_reports_dlopen_failed() {
        // `MODULE_NOT_FOUND` comes from the CommonJS loader before this path, so
        // nothing here may report it.
        for error in [
            LoadError::Open("whatever".to_string()),
            LoadError::NotAnAddon("/tmp/x.node".to_string()),
            LoadError::UnsupportedVersion {
                module_name: "file:///tmp/x.node".to_string(),
                module_version: 99,
            },
            LoadError::Registration("boom".to_string()),
        ] {
            assert_eq!(error.code(), "ERR_DLOPEN_FAILED");
        }
    }

    #[test]
    fn a_version_mismatch_uses_nodes_exact_wording() {
        // `test_module_version_mismatch` matches this text with a regular
        // expression, so the wording and the trailing "add-ons." are load-bearing.
        let error = LoadError::UnsupportedVersion {
            module_name: "file:///tmp/x.node".to_string(),
            module_version: 2147483646,
        };
        assert_eq!(
            error.message(),
            "file:///tmp/x.node requires Node-API version 2147483646, \
             but this version of Node.js only supports version 10 add-ons."
        );
    }

    #[test]
    fn the_legacy_symbol_carries_the_pinned_module_version() {
        assert_eq!(legacy_entry_point_symbol(), "node_register_module_v153");
    }

    #[test]
    fn a_module_filename_url_escapes_the_characters_node_escapes() {
        // `test_general` copies the addon into `foo%#bar` and requires the
        // reported URL to be percent-encoded.
        let url = module_filename_url(Path::new("/tmp/foo%#bar/addon.node"));
        assert!(
            url.ends_with("foo%25%23bar/addon.node"),
            "unexpected encoding: {url}"
        );
        assert!(url.starts_with("file://"));
    }

    #[test]
    fn a_module_filename_url_leaves_ordinary_paths_alone() {
        let url = module_filename_url(Path::new("/tmp/dlprobe/addon.node"));
        assert_eq!(url, "file:///tmp/dlprobe/addon.node");
    }
}
