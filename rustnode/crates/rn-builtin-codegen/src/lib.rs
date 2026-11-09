//! Compiling one Node builtin with V8, and the code cache around that.
//!
//! This is `BuiltinLoader::LookupAndCompile` from `src/node_builtins.cc`: given
//! a builtin's id, source and kind, produce the function its wrapper parameters
//! describe.
//!
//! It is shared by the runtime, which compiles builtins as user scripts reach
//! them, and by the `rn-builtin-codegen` binary, which compiles the same
//! builtins ahead of time to produce their code caches. Both go through
//! [`compile`], so a cache is generated from exactly the compile that later
//! consumes it. That matters because a V8 code cache is only valid for the
//! compile that produced it: different wrapper parameters, a different kind, or
//! a different V8 build all make the blob unusable.
//!
//! # The code cache
//!
//! `Function::create_code_cache` serialises the parsed and compiled form of a
//! function. Handing those bytes back through `Source::new_with_cached_data`
//! with `CompileOptions::ConsumeCodeCache` skips parsing and bytecode
//! generation. Measured over the 65 builtins an empty script loads: about 19 ms
//! cold against 0.3 ms warm, with no rejections.
//!
//! # Why the cache cannot make anything wrong
//!
//! A cache can only make a compile faster. V8 stamps each blob with a version
//! tag covering its own build and flags, and marks the `CachedData` rejected
//! rather than parsing it when the tag or the source does not match. A rejected
//! blob is therefore not an error and not a fallback path with its own logic:
//! [`compile`] reports it, and the caller keeps the function V8 compiled from
//! source. Nothing about the resulting function depends on the cache.

#![deny(missing_docs)]

use rn_js2c::BuiltinKind;
use rn_v8_sys::v8;

pub mod build_cache;

/// The builtin code-cache plan, owned by `rn-builtins` so the crate that
/// compiles the builtins and the crate that ships them cannot disagree.
#[path = "../../rn-builtins/src/cache_plan.rs"]
pub mod cache_plan;

/// A compiled builtin.
pub struct Compiled<'s> {
    function: v8::Local<'s, v8::Function>,
    supplied_cache: bool,
    consumed_cache: bool,
    rejected_cache: bool,
}

impl<'s> Compiled<'s> {
    /// The function to call.
    pub fn function(&self) -> v8::Local<'s, v8::Function> {
        self.function
    }

    /// Whether a cache was offered to V8 at all.
    pub fn supplied_cache(&self) -> bool {
        self.supplied_cache
    }

    /// Whether the cached parse was reused.
    pub fn consumed_cache(&self) -> bool {
        self.consumed_cache
    }

    /// Whether an offered cache was rejected, so the source was compiled.
    pub fn rejected_cache(&self) -> bool {
        self.rejected_cache
    }
}

/// Compiles `source` as the builtin `id` of `kind`.
///
/// The script name is `node:<id>`, not `<id>`. `node_builtins.cc:344` builds
/// `filename_s` that way, and the scheme is load-bearing rather than cosmetic:
/// `lib/internal/util/inspect.js` decides whether a stack frame is internal with
/// `/^ {4}at (?:[^/\\(]+ \()?node:(.+):\d+:\d+\)?$/` and greys it only when the
/// captured id is also a real builtin. Without the prefix every frame from
/// `internal/**` looks like user code, so `util.inspect(error, { colors: true })`
/// leaves the loader's own frames uncoloured and
/// `parallel/test-util-inspect.js`'s cross-platform check fails.
///
/// This is why the code cache is generated through this function rather than by
/// a separate compile: the script name is part of what the cached parse is keyed
/// to, so a generator with a different origin would produce blobs V8 rejects.
///
/// `cached_data` is a blob from an earlier compile of the same builtin, or
/// `None`. A stale blob is safe to pass: V8 validates it and falls back to
/// compiling the source, which [`Compiled::rejected_cache`] reports.
pub fn compile<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: &str,
    source: &str,
    kind: BuiltinKind,
    cached_data: Option<&[u8]>,
) -> Option<Compiled<'s>> {
    let origin_name = v8::String::new(scope, &format!("node:{id}"))?;
    let origin = v8::ScriptOrigin::new(
        scope,
        origin_name.into(),
        0,
        0,
        false,
        0,
        None,
        false,
        false,
        false,
        None,
    );
    let text = v8::String::new(scope, source)?;

    let supplied_cache = cached_data.map(|bytes| !bytes.is_empty()).unwrap_or(false);
    let mut source_text = match cached_data.filter(|bytes| !bytes.is_empty()) {
        Some(bytes) => v8::script_compiler::Source::new_with_cached_data(
            text,
            Some(&origin),
            v8::script_compiler::CachedData::new(bytes),
        ),
        None => v8::script_compiler::Source::new(text, Some(&origin)),
    };
    let parameters: Vec<v8::Local<v8::String>> = kind
        .parameters()
        .iter()
        .filter_map(|parameter| v8::String::new(scope, parameter))
        .collect();
    let options = if supplied_cache {
        v8::script_compiler::CompileOptions::ConsumeCodeCache
    } else {
        v8::script_compiler::CompileOptions::NoCompileOptions
    };
    let function = v8::script_compiler::compile_function(
        scope,
        &mut source_text,
        &parameters,
        &[],
        options,
        v8::script_compiler::NoCacheReason::NoReason,
    )?;
    let rejected_cache = source_text
        .get_cached_data()
        .map(v8::script_compiler::CachedData::rejected)
        .unwrap_or(false);
    Some(Compiled {
        function,
        supplied_cache,
        consumed_cache: supplied_cache && !rejected_cache,
        rejected_cache,
    })
}

/// The one way to prepare V8 before compiling a builtin.
///
/// A code cache's version tag covers V8's *flags* as well as its build, so a
/// blob generated under one flag set is rejected under another. Every caller
/// that produces or consumes a builtin cache therefore has to arrive at V8 the
/// same way, and this is that way:
///
/// * `--no-freeze-flags-after-init`, because the runtime sets it so that
///   `v8.setFlagsFromString()` keeps working after `V8::Initialize` (see the
///   note in `rn-cli`'s `main`);
/// * a default platform with the argument each caller decides for itself.
///
/// The runtime's own `main` sets the same flag before calling
/// [`v8::V8::initialize`]. `crates/rn-builtins/tests` asserts a generated cache
/// is consumed rather than rejected, which is what fails if that ever drifts.
pub fn set_runtime_flags() {
    v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
}

/// Compiles `source` and returns the code cache V8 would consume next time.
///
/// Returns `None` when V8 declines to serialise the function, which happens for
/// a source it cannot cache. That is not an error: the caller simply has no
/// cache for this builtin and compiles it from source at startup.
pub fn code_cache<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    id: &str,
    source: &str,
    kind: BuiltinKind,
) -> Option<Vec<u8>> {
    let compiled = compile(scope, id, source, kind, None)?;
    compiled
        .function()
        .create_code_cache()
        .map(|cache| cache.to_vec())
}
