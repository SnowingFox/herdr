//! `internalBinding('modules')` for rustnode.
//!
//! This is the namespace that makes CommonJS file loading possible.
//! `lib/internal/modules/cjs/loader.js` and `lib/internal/modules/helpers.js`
//! both read it, and so does `lib/internal/modules/package_json_reader.js`,
//! which every resolution step passes through. Until this namespace exists
//! `require()` can only reach builtins; no user file can load.
//!
//! The members fall into three groups, and each is a different kind of work:
//!
//! ## Package metadata
//!
//! `readPackageJSON`, `parsePackageJSON`, `getNearestParentPackageJSON`,
//! `getNearestParentPackageJSONType`, `getRootPackageJSON`,
//! `getPackageScopeConfig` and `getPackageType` are all views of one question:
//! which `package.json`, if any, governs this path, and what does it say. The
//! answer decides whether a `.js` file is CommonJS or an ES module, so getting
//! it wrong changes module semantics without raising an error. [`packages`] has
//! the three distinct walks Node uses and why they differ; [`json`] has the
//! parser, which reproduces the on-demand validation simdjson does rather than
//! the stricter whole-document validation a general JSON parser would apply.
//!
//! ## Compile cache
//!
//! `enableCompileCache`, `getCompileCacheDir`, `flushCompileCache`,
//! `getCompileCacheEntry` and `saveCompileCacheEntry` are implemented;
//! [`compile_cache`] explains the file format and the atomic write. The two
//! WebAssembly members are deferred, with the reason in [`DEFERRED`]: both need
//! V8 APIs the `v8` crate does not expose, and a cache that can never hit is
//! worse than an honest absence. `enableCompileCache` still works, which is what
//! `module.enableCompileCache()` in `lib/module.js` calls.
//!
//! ## Constants
//!
//! `moduleFormats`, `cachedCodeTypes` and `compileCacheStatus` are
//! null-prototype values. Their numeric values are compared by `lib/**`, so
//! they come from Node's own enums rather than being counted here.
//!
//! ## The esmodule lexer
//!
//! `src/node_modules.cc` does *not* call `cjs_module_lexer`. ESM syntax
//! detection lives in `containsModuleSyntax` on the `contextify` namespace
//! (`src/node_contextify.cc`), which `lib/internal/modules/esm/get_format.js`
//! and the CommonJS loader call directly. This crate therefore has no lexer to
//! port, and `parsePackageJSON` — despite its name — only parses JSON. The
//! deferred frontier for ESM detection is `contextify.containsModuleSyntax`,
//! not a member of this namespace; see the crate README.

pub mod compile_cache;
pub mod install;
pub mod json;
pub mod packages;
pub mod url;

#[cfg(test)]
mod tests;

pub use install::{Modules, DEFERRED, MEMBERS};

/// V8 version this runtime is pinned to, from `tools/node-pin.toml`.
///
/// Used to derive the compile cache's version tag, so a cache written by a
/// different V8 lands in a different directory instead of being misread as
/// compatible.
pub const V8_VERSION: &str = "15.6.75";

/// Registers the `modules` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    install::register(registry);
}
