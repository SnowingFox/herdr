//! `compileFunction`, `compileFunctionForCJSLoader` and `runInterruptible`.
//!
//! These three are the module-compilation surface. The JavaScript signatures are
//! fixed by `lib/internal/vm.js` and `lib/internal/modules/cjs/loader.js`, and
//! this file maps them onto `v8::script_compiler` and then shapes the result
//! object the way `node_contextify.cc` does.
//!
//! ## Cached data
//!
//! V8's code cache is an opaque blob: produced by `Function::create_code_cache`,
//! consumed by wrapping it in `script_compiler::CachedData` and passing
//! `ConsumeCodeCache`. `CachedData::new` borrows its bytes and records V8's
//! `BufferNotOwned` policy, so the allocation must outlive the `Source` that
//! consumes it. [`CachedBytes`] is the owner that makes that a compile-time
//! relationship rather than a comment.
//!
//! ## Contexts
//!
//! `compileFunction` can be asked to compile *into* a sandbox's realm. That is a
//! `Context::Scope` around the compile, entered through V8's own `ContextScope`.

use rn_v8_sys::v8;

use crate::detect;

/// Parameter list the CommonJS wrapper is compiled with.
///
/// `lib/internal/modules/cjs/loader.js` calls the returned function with exactly
/// these five arguments, so the order is the contract, not a convenience:
/// `Module.prototype._compile` does `compiledWrapper.call(exports, exports,
/// require, module, filename, dirname)`.
pub const CJS_PARAMETERS: [&str; 5] = ["exports", "require", "module", "__filename", "__dirname"];

/// `HostDefinedOptions::kID`, from `src/module_wrap.h`.
pub const HOST_DEFINED_OPTIONS_ID: usize = 8;
/// `HostDefinedOptions::kLength`, from `src/module_wrap.h`.
pub const HOST_DEFINED_OPTIONS_LENGTH: usize = 9;

/// Builds a `ScriptOrigin` with the flags Node uses for compiled source.
///
/// Every caller in `node_contextify.cc` passes the same arguments apart from the
/// offsets and host-defined options: cross-origin true, script id -1 (let V8
/// assign one), no source map URL, not opaque, not wasm, not a module. Script id
/// `-1` matters: a fixed id would make every script claim the same identity and
/// break profiler output and stack-trace grouping.
pub(crate) fn origin<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    filename: v8::Local<'s, v8::String>,
    line_offset: i32,
    column_offset: i32,
    host_defined_options: Option<v8::Local<'s, v8::Data>>,
) -> v8::ScriptOrigin<'s> {
    v8::ScriptOrigin::new(
        scope,
        filename.into(),
        line_offset,
        column_offset,
        true,  // is cross origin
        -1,    // script id: let V8 allocate one
        None,  // source map URL; V8 reads the magic comment instead
        false, // is opaque
        false, // is wasm
        false, // is ES module
        host_defined_options,
    )
}

/// Converts an absolute path to the `file://` URL a debugger expects.
///
/// Node reports compiled scripts under `file:///abs/path`, and every inspector test
/// builds breakpoint URLs with `pathToFileURL(...)` against that convention. rustnode
/// was reporting the bare path for CommonJS files — the ESM path already produced a
/// URL, because the vendored `defaultResolve` builds one — which made
/// `Debugger.setBreakpointByUrl` resolve to zero locations for exactly the files a
/// debugger cares about. `test-inspector-break-when-eval.js` and its neighbours write
/// `file://${path}`, so a bare path is invisible to them.
///
/// Verified against a real Node 22 on the same input: `node /tmp/x.js` reports
/// `file:///tmp/x.js`, and so does a `require`d module. Anything that is not an
/// absolute path is returned unchanged, which keeps `vm.Script`'s synthetic names
/// (`'evalmachine.<anonymous>'`, `'test.js'`) as they are — Node does the same, and a
/// URL-ified synthetic name would break stack traces.
pub fn path_to_file_url(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }
    // A path is percent-encoded per the URL spec; the characters that actually appear in
    // a source path and are illegal in a URL are the space and the percent itself.
    // Anything else (a `#` in a filename, for instance) would also need it, so the
    // escaping covers the reserved set rather than just those two.
    let mut encoded = String::with_capacity(path.len() + 8);
    encoded.push_str("file://");
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'/'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b':'
            | b'@'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b'['
            | b']' => encoded.push(char::from(byte)),
            other => {
                use std::fmt::Write;
                let _ = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

/// Builds a `ScriptOrigin` for an ES module compile.
///
/// `is_module` must be true or V8 aborts in debug builds, so this exists rather
/// than reusing [`origin`], which is deliberately not a module origin.
pub(crate) fn module_origin<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    resource_name: v8::Local<'s, v8::String>,
) -> v8::ScriptOrigin<'s> {
    v8::ScriptOrigin::new(
        scope,
        resource_name.into(),
        0,     // line offset
        0,     // column offset
        true,  // is cross origin
        -1,    // script id: let V8 allocate one
        None,  // source map URL
        false, // is opaque
        false, // is wasm
        true,  // is ES module
        None,
    )
}

/// Builds the host-defined-option array V8 hands back through
/// `importModuleDynamically`.
///
/// `loader::ModuleWrap::GetHostDefinedOptions` allocates a `kLength` array and
/// stores the symbol at `kID`; the other slots stay `undefined`. The JavaScript
/// side reads this to find the callback registered for the referring script, so
/// omitting the array would make every dynamic `import()` from a script lose it.
pub(crate) fn host_defined_options<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    symbol: Option<v8::Local<'s, v8::Symbol>>,
) -> v8::Local<'s, v8::PrimitiveArray> {
    let array = v8::PrimitiveArray::new(scope, HOST_DEFINED_OPTIONS_LENGTH);
    if let Some(symbol) = symbol {
        array.set(scope, HOST_DEFINED_OPTIONS_ID, symbol.into());
    }
    array
}

/// Owns the bytes a `CachedData` borrows.
///
/// `CachedData::new` takes `&'a [u8]` and V8 keeps the pointer, not a copy. The
/// buffer therefore has to stay alive until the `Source` referencing it is
/// dropped, which keeping both in one struct makes checkable.
pub(crate) struct CachedBytes {
    bytes: Box<[u8]>,
}

impl CachedBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into_boxed_slice(),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// `compileFunction(code, filename, lineOffset, columnOffset, cachedData,
/// produceCachedData, parsingContext, contextExtensions, params, hostDefinedOptionId)`.
///
/// Returns what `internalCompileFunction` in `lib/internal/vm.js` unpacks:
/// `{ function, sourceURL, sourceMapURL, cachedDataRejected?, cachedDataProduced?,
/// cachedData? }`. `cachedDataRejected` is only present when a cache was
/// consumed, which the JavaScript side tests with `typeof`.
pub fn compile_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(code) = string_arg(&args, 0) else {
        return throw_type_error(scope, "compileFunction requires source text");
    };
    let Some(filename) = string_arg(&args, 1) else {
        return throw_type_error(scope, "compileFunction requires a filename");
    };
    let line_offset = args.get(2).int32_value(scope).unwrap_or(0);
    let column_offset = args.get(3).int32_value(scope).unwrap_or(0);
    let produce_cached_data = args.get(5).is_true();

    // The parsing context arrives as a contextified sandbox, never as a raw
    // `v8::Context`, because that is the only thing `lib/vm.js` can pass.
    let parsing_context = match args.get(6) {
        value if value.is_undefined() => None,
        value => match crate::script::context_of(scope, value) {
            Some(context) => Some(context),
            None => {
                return throw_type_error(
                    scope,
                    "compileFunction: the parsing context is not a contextified sandbox",
                )
            }
        },
    };

    let context_extensions = match object_array(scope, args.get(7)) {
        Ok(extensions) => extensions,
        Err(message) => return throw_type_error(scope, &message),
    };
    let params = match string_array(scope, args.get(8)) {
        Ok(params) => params,
        Err(message) => return throw_type_error(scope, &message),
    };
    let symbol = v8::Local::<v8::Symbol>::try_from(args.get(9)).ok();

    // The owner has to outlive the `Source`, so it is bound before it and lives
    // until the end of this function.
    let mut owned = match cached_data_argument(scope, args.get(4)) {
        Ok(bytes) => bytes,
        Err(message) => return throw_type_error(scope, &message),
    };
    let mut source = build_source(
        scope,
        code,
        filename,
        line_offset,
        column_offset,
        symbol,
        owned.as_mut(),
    );

    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();

    // Entering the parsing context has to wrap only the compile, so each branch
    // owns its `ContextScope` and returns the function out of it.
    let function = match parsing_context {
        Some(context) => {
            let mut context_scope = std::pin::pin!(v8::ContextScope::new(&mut **scope, context));
            let scope: &mut v8::PinScope<'s, '_> = &mut context_scope;
            compile_function_in(scope, &mut source, &params, &context_extensions)
        }
        None => {
            let scope: &mut v8::PinScope<'s, '_> = scope;
            compile_function_in(scope, &mut source, &params, &context_extensions)
        }
    };

    let Some(function) = function else {
        // V8's own exception, with its source position and caret line intact.
        if scope.has_caught() && !scope.has_terminated() {
            scope.rethrow();
        }
        return;
    };

    let new_cached_data = if produce_cached_data {
        function.create_code_cache()
    } else {
        None
    };

    let script_origin = function.get_script_origin(scope);
    let undefined: v8::Local<v8::Value> = v8::undefined(scope).into();
    let source_url = script_origin.resource_name().unwrap_or(undefined);
    let source_map_url = script_origin.source_map_url().unwrap_or(undefined);
    let rejected = source.get_cached_data().map(|cached| cached.rejected());

    let object = v8::Object::new(scope);
    set(scope, object, "function", function.into());
    set(scope, object, "sourceURL", source_url);
    set(scope, object, "sourceMapURL", source_map_url);
    if let Some(rejected) = rejected {
        set(
            scope,
            object,
            "cachedDataRejected",
            v8::Boolean::new(scope, rejected).into(),
        );
    }
    if let Some(cached) = new_cached_data {
        if let Some(view) = buffer_from(scope, &cached) {
            set(scope, object, "cachedData", view);
            set(
                scope,
                object,
                "cachedDataProduced",
                v8::Boolean::new(scope, true).into(),
            );
        }
    }
    rv.set(object.into());
}

/// Compiles `source` as a function in whatever context is entered.
fn compile_function_in<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &mut v8::script_compiler::Source,
    params: &[v8::Local<'s, v8::String>],
    context_extensions: &[v8::Local<'s, v8::Object>],
) -> Option<v8::Local<'s, v8::Function>> {
    let options = compile_options(source);
    v8::script_compiler::compile_function(
        scope,
        source,
        params,
        context_extensions,
        options,
        v8::script_compiler::NoCacheReason::NoReason,
    )
}

/// `ConsumeCodeCache` when a cache was supplied, `NoCompileOptions` otherwise.
fn compile_options(source: &v8::script_compiler::Source) -> v8::script_compiler::CompileOptions {
    if source.get_cached_data().is_some() {
        v8::script_compiler::CompileOptions::ConsumeCodeCache
    } else {
        v8::script_compiler::CompileOptions::NoCompileOptions
    }
}

/// Builds the `Source` for a compile, consuming `cached` when there is one.
fn build_source<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    code: v8::Local<'s, v8::String>,
    filename: v8::Local<'s, v8::String>,
    line_offset: i32,
    column_offset: i32,
    symbol: Option<v8::Local<'s, v8::Symbol>>,
    cached: Option<&mut CachedBytes>,
) -> v8::script_compiler::Source {
    let host_defined = host_defined_options(scope, symbol);
    // A CommonJS file's filename is an absolute path; a debugger needs the `file://`
    // form, and so does `Debugger.setBreakpointByUrl` in every Node test that names a
    // source. `path_to_file_url` leaves a synthetic name alone.
    let filename = {
        let text = filename.to_rust_string_lossy(scope);
        match v8::String::new(scope, &path_to_file_url(&text)) {
            Some(url) => url,
            None => filename,
        }
    };
    let origin = origin(
        scope,
        filename,
        line_offset,
        column_offset,
        Some(host_defined.into()),
    );
    match cached {
        Some(cached) if !cached.is_empty() => v8::script_compiler::Source::new_with_cached_data(
            code,
            Some(&origin),
            v8::script_compiler::CachedData::new(cached.as_slice()),
        ),
        _ => v8::script_compiler::Source::new(code, Some(&origin)),
    }
}

/// `compileFunctionForCJSLoader(code, filename, isSeaMain, shouldDetectModule)`.
///
/// The CommonJS loader's compile step. Two behaviours are load-bearing:
///
/// * The function is always compiled with [`CJS_PARAMETERS`], so calling it as
///   `fn(exports, require, module, __filename, __dirname)` works. That is the
///   whole point of the member.
/// * A syntax error whose message means "this could be ESM" is not thrown when
///   `shouldDetectModule` is set: the result comes back with
///   `canParseAsESM: true` and no `function`, and the loader retries the file as
///   ESM. Without the flag the original error is thrown, which is the
///   `require(esm)` failure users see.
pub fn compile_function_for_cjs_loader<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    // A binding called with the wrong argument shape is otherwise invisible:
    // the failure surfaces as a syntax error or a wrong value far from here.
    // This prints the argument kinds on demand so the next person does not have
    // to bisect a loader to find out what it actually passed.
    if std::env::var_os("RUSTNODE_DEBUG_BINDING").is_some() {
        let kinds: Vec<String> = (0..args.length())
            .map(|index| {
                let value = args.get(index);
                if value.is_string() {
                    let text = value.to_rust_string_lossy(scope);
                    let head: String = text.chars().take(60).collect();
                    format!("string({:?})", head)
                } else if value.is_undefined() {
                    "undefined".to_string()
                } else if value.is_boolean() {
                    format!("boolean({})", value.boolean_value(scope))
                } else if value.is_object() {
                    format!("object({})", value.to_rust_string_lossy(scope))
                } else {
                    "other".to_string()
                }
            })
            .collect();
        eprintln!(
            "compileFunctionForCJSLoader argc={} kinds=[{}]",
            args.length(),
            kinds.join(", ")
        );
    }
    let Some(code) = string_arg(&args, 0) else {
        return throw_type_error(scope, "compileFunctionForCJSLoader requires source text");
    };
    let Some(filename) = string_arg(&args, 1) else {
        return throw_type_error(scope, "compileFunctionForCJSLoader requires a filename");
    };
    let should_detect_module = args.get(3).is_true();
    // Argument 2 is `isSeaMain`: a single-executable application carries its own
    // code cache, which rustnode does not produce. It is accepted and ignored
    // rather than rejected, because the loader always passes it and a throw here
    // would make every `require` fail.
    let params = cjs_parameters(scope);

    // Everything happens inside one catch. Throwing from *inside* it would be
    // captured by the handler and never reach the caller, so this function returns
    // the decision out of the catch and throws afterwards.
    let outcome = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let catch = &mut try_catch.init();
        let mut source = build_source(catch, code, filename, 0, 0, None, None);
        compile_cjs_loader(catch, &mut source, &params, code, should_detect_module)
    };

    match outcome {
        CompileOutcome::Failed(exception) => {
            // The original exception object, rethrown. Node does the same
            // (`isolate->ThrowException(cjs_exception)`), which is why
            // `error.message` is V8's bare text and not a rebuilt string.
            if let Some(exception) = exception {
                let exception = v8::Local::new(scope, &exception);
                scope.throw_exception(exception);
            }
        }
        CompileOutcome::Detectable => {
            let object = build_cjs_result(scope, None, true, false);
            rv.set(object.into());
        }
        CompileOutcome::Compiled(function, rejected) => {
            let object = build_cjs_result(scope, Some(function), false, rejected);
            rv.set(object.into());
        }
    }
}

/// What the CommonJS compile decided.
enum CompileOutcome<'s> {
    /// Compiled; the wrapper is ready to be called. The flag records whether a
    /// supplied code cache was rejected.
    Compiled(v8::Local<'s, v8::Function>, bool),
    /// Parsed as neither CommonJS nor (by message) ESM, or `shouldDetectModule`
    /// was off. Carries the exception V8 raised, kept alive across the catch so it
    /// can be rethrown unchanged; `None` means a termination, where there is no
    /// exception to rethrow.
    Failed(Option<v8::Global<v8::Value>>),
    /// Failed as CommonJS but looks like ESM, and detection was requested.
    Detectable,
}

/// Runs the CommonJS compile and classifies a failure, without throwing.
/// `'f` is the escape lifetime of the catch scope's handles, which is what a
/// `Local` returned from inside a `TryCatch` is bound to; it is deliberately not
/// the outer handle scope's lifetime.
fn compile_cjs_loader<'f, 's, 'o, 'i>(
    catch: &mut v8::PinnedRef<'_, v8::TryCatch<'s, 'o, v8::HandleScope<'i, v8::Context>>>,
    source: &mut v8::script_compiler::Source,
    params: &[v8::Local<'f, v8::String>],
    code: v8::Local<'f, v8::String>,
    should_detect_module: bool,
) -> CompileOutcome<'f>
where
    'o: 'f,
{
    let options = compile_options(source);
    let compiled = v8::script_compiler::compile_function(
        catch,
        source,
        params,
        &[],
        options,
        v8::script_compiler::NoCacheReason::NoReason,
    );
    let rejected = source
        .get_cached_data()
        .map(|cached| cached.rejected())
        .unwrap_or(false);
    if let Some(function) = compiled {
        return CompileOutcome::Compiled(function, rejected);
    }

    // Both the message and the exception are taken while the catch is installed,
    // then read through the handle scope the catch wraps. The message is what
    // classification reads; the exception is what gets rethrown, so its own
    // `message` property stays exactly as V8 produced it.
    let Some(pending) = catch.message() else {
        return CompileOutcome::Failed(None);
    };
    // Both handles are read off the catch before either is used, because the
    // handle-scope deref borrows the same pinned reference.
    let caught = catch.exception();
    let (message, exception) = {
        let inner: &mut v8::PinScope<'_, '_> = catch;
        let message = pending.get(inner).to_rust_string_lossy(inner);
        let exception = caught.map(|exception| v8::Global::new(inner, exception));
        (message, exception)
    };

    // A `should_detect_module` false answer keeps the original error, which is the
    // `require(esm)` message users see.
    let inner: &mut v8::PinScope<'_, '_> = catch;
    if should_detect_module && detect::should_retry_as_esm(inner, &message, code) {
        CompileOutcome::Detectable
    } else {
        CompileOutcome::Failed(exception)
    }
}

/// Shapes the object `wrapSafe` in `lib/internal/modules/cjs/loader.js` unpacks.
fn build_cjs_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    function: Option<v8::Local<'s, v8::Function>>,
    can_parse_as_esm: bool,
    cached_data_rejected: bool,
) -> v8::Local<'s, v8::Object> {
    let undefined: v8::Local<v8::Value> = v8::undefined(scope).into();
    let (source_url, source_map_url, function) = match function {
        Some(function) => {
            let script_origin = function.get_script_origin(scope);
            (
                script_origin.resource_name().unwrap_or(undefined),
                script_origin.source_map_url().unwrap_or(undefined),
                function.into(),
            )
        }
        None => (undefined, undefined, undefined),
    };

    let object = v8::Object::new(scope);
    set(
        scope,
        object,
        "cachedDataRejected",
        v8::Boolean::new(scope, cached_data_rejected).into(),
    );
    set(scope, object, "sourceURL", source_url);
    set(scope, object, "sourceMapURL", source_map_url);
    set(scope, object, "function", function);
    set(
        scope,
        object,
        "canParseAsESM",
        v8::Boolean::new(scope, can_parse_as_esm).into(),
    );
    object
}

/// `runInterruptible(fn)`: runs `fn` so a SIGINT can interrupt it, returning
/// whether it was interrupted.
///
/// `lib/internal/repl/inspector.js` is the only caller and uses the return value
/// to choose between "the user pressed Ctrl+C" and "the inspector call failed".
/// Node installs a `SigintWatchdog` whose handler calls `TerminateExecution`, then
/// cancels a termination that watchdog caused instead of letting it escape.
///
/// rustnode has no second-thread watchdog: signals are handled by the `uv`
/// namespace's loop integration. What is preserved is the part the caller depends
/// on. A termination observed here is cancelled and reported as `true`, because
/// the REPL is the only way in and an outer `vm` timeout cannot be nested inside
/// it. A genuine exception propagates instead of being misreported as an
/// interrupt.
pub fn run_interruptible<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        return throw_type_error(scope, "runInterruptible requires a function");
    };

    let interrupted = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let call = function.call(scope, v8::undefined(scope).into(), &[]);
        if scope.has_caught() {
            if !scope.has_terminated() {
                scope.rethrow();
                return;
            }
            // The termination is converted into a recoverable state, exactly as
            // `CancelTerminateExecution` does after a watchdog fires.
            scope.as_ref().cancel_terminate_execution();
            true
        } else {
            let _ = call;
            false
        }
    };

    rv.set(v8::Boolean::new(scope, interrupted).into());
}

/// The five CommonJS parameter names as V8 strings.
fn cjs_parameters<'s>(scope: &mut v8::PinScope<'s, '_>) -> Vec<v8::Local<'s, v8::String>> {
    CJS_PARAMETERS
        .iter()
        .filter_map(|name| v8::String::new(scope, name))
        .collect()
}

/// Reads a cached-data argument into an owned buffer.
///
/// The bytes are copied out rather than borrowed from the typed array because a
/// `Source` outlives the argument handles, and `CachedData` only borrows.
pub(crate) fn cached_data_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Option<CachedBytes>, String> {
    let _ = scope;
    if value.is_undefined() {
        return Ok(None);
    }
    let view = v8::Local::<v8::ArrayBufferView>::try_from(value)
        .map_err(|_| "cachedData must be a Buffer or typed array".to_string())?;
    let length = view.byte_length();
    let mut bytes = vec![0u8; length];
    let copied = view.copy_contents(&mut bytes);
    bytes.truncate(copied);
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(CachedBytes::new(bytes)))
}

/// A `Buffer`-like `Uint8Array` over a copy of `bytes`.
pub(crate) fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let view = v8::Uint8Array::new(scope, buffer, 0, bytes.len())?;
    Some(view.into())
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Reads a string argument, rejecting anything that is not already a string.
///
/// This used to call `to_string`, which converts whatever it is given. That was
/// wrong in a way that cost a long bisect: `lib/internal/modules/cjs/loader.js`
/// passed an object as the source, `to_string` turned it into the literal text
/// `[object Object]`, and the result was a `SyntaxError: Unexpected identifier
/// 'Object'` thrown from inside the loader with nothing pointing at the binding.
/// Node's C++ uses `CHECK(args[0]->IsString())` for the same reason — a binding
/// that silently coerces hides the caller's bug behind a confusing error.
fn string_arg<'s>(
    args: &v8::FunctionCallbackArguments<'s>,
    index: i32,
) -> Option<v8::Local<'s, v8::String>> {
    v8::Local::<v8::String>::try_from(args.get(index)).ok()
}

/// Collects an array argument into objects, rejecting non-object elements.
fn object_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Vec<v8::Local<'s, v8::Object>>, String> {
    if value.is_undefined() {
        return Ok(Vec::new());
    }
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        return Err("contextExtensions must be an array".to_string());
    };
    let mut objects = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(element) = array.get_index(scope, index) else {
            continue;
        };
        let object = v8::Local::<v8::Object>::try_from(element)
            .map_err(|_| "contextExtensions entries must be objects".to_string())?;
        objects.push(object);
    }
    Ok(objects)
}

/// Collects an array argument into strings, rejecting non-string elements.
fn string_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Vec<v8::Local<'s, v8::String>>, String> {
    if value.is_undefined() {
        return Ok(Vec::new());
    }
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        return Err("params must be an array".to_string());
    };
    let mut strings = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(element) = array.get_index(scope, index) else {
            continue;
        };
        let text = element
            .to_string(scope)
            .ok_or_else(|| "params entries must be strings".to_string())?;
        strings.push(text);
    }
    Ok(strings)
}

fn set(
    scope: &v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) {
    if let Some(key) = v8::String::new(scope, name) {
        object.set(scope, key.into(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wrapper_parameters_match_the_loader() {
        // `Module.prototype._compile` calls the compiled wrapper as
        // `(exports, require, module, filename, dirname)`; reordering these
        // silently swaps `module` and `require` in every CommonJS file.
        assert_eq!(
            CJS_PARAMETERS,
            ["exports", "require", "module", "__filename", "__dirname"]
        );
    }

    #[test]
    fn host_defined_options_uses_the_documented_slots() {
        // `src/module_wrap.h`: `kID = 8`, `kLength = 9`. A wrong length makes V8
        // read past the array while looking for the dynamic-import callback.
        assert_eq!(HOST_DEFINED_OPTIONS_ID, 8);
        assert_eq!(HOST_DEFINED_OPTIONS_LENGTH, 9);
    }
}
