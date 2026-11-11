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
pub(crate) fn dlopen(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
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
        // `undefined` keeps the default, matching Node's
        // `args[2]->IsUndefined()` escape; anything else must be an integer.
        if !flags.is_undefined() && !flags.is_int32() && !flags.is_uint32() {
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
