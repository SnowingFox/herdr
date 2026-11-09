//! Building the `internalBinding('glob')` object.
//!
//! The namespace is small — `lib/internal/fs/glob.js` reads three functions and
//! five flag constants — but two of the functions have exacting shapes:
//!
//! * `matchesGlob(path, pattern, flags)` returns a boolean and **throws** a
//!   `TypeError` or `SyntaxError` for a pattern that cannot compile. The
//!   JavaScript layer relies on the throw: `path.matchesGlob` and the `exclude`
//!   handling in `fs.glob` both treat an exception as an error rather than as
//!   "no match".
//! * `globSync(cwd, includes, excludes, flags, excludeFn, maxDepth)` returns the
//!   path array, or `[paths, types]` when `kFlagWithFileTypes` is set. The
//!   `types` array carries `UV_DIRENT_*` values, which `Dirent`'s constructor
//!   takes verbatim.
//! * `globStart(...)` takes the same arguments and returns a handle with
//!   `next()`, `all()` and `cancel()`, each returning a `Promise`. Each pull
//!   resolves to `[paths, types | undefined, done]`.
//!
//! ## The flag bits
//!
//! The constants are Node's own values (`kFlagWindows = 1`, `kFlagDot = 4`,
//! `kFlagFollowSymlinks = 8`, `kFlagWithFileTypes = 16`, `kFlagMatchBase = 32`).
//! Two more bits exist only inside the native layer: `kFlagNocase` is the host's
//! case rule and is never sent from JavaScript, and `kFlagNocaseLiterals`
//! distinguishes cache keys. They are private here for the same reason.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::matcher::{match_pattern, CompiledPattern};
use crate::parser::{self, CompileFlags};
use crate::walker::{self, ExcludeFilter, WalkEntry, WalkOptions};

/// Members exposed on the namespace object, matching `contracts/glob.json`.
pub const MEMBERS: &[&str] = &[
    "globStart",
    "globSync",
    "hasMagic",
    "kFlagDot",
    "kFlagFollowSymlinks",
    "kFlagMatchBase",
    "kFlagWindows",
    "kFlagWithFileTypes",
    "matchesGlob",
];

/// Members the namespace needs but this crate does not install yet.
///
/// Empty: every member `contracts/glob.json` records is implemented.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `kFlagWindows`: match with `path.win32` rules.
pub const K_FLAG_WINDOWS: u32 = 1;
/// Case-insensitive matching. Never sent from JavaScript, because the host's own
/// case rule decides it.
pub const K_FLAG_NOCASE: u32 = 2;
/// Let wildcards match a leading dot.
pub const K_FLAG_DOT: u32 = 4;
/// Follow symlinked directories, with cycle detection.
pub const K_FLAG_FOLLOW_SYMLINKS: u32 = 8;
/// Return dirent types alongside the paths.
pub const K_FLAG_WITH_FILE_TYPES: u32 = 16;
/// A pattern with no separator matches the path's basename.
pub const K_FLAG_MATCH_BASE: u32 = 32;
/// Distinguishes cache keys; not a behaviour flag.
pub const K_FLAG_NOCASE_LITERALS: u32 = 64;

/// `internalBinding('glob')`.
pub struct Glob;

impl BindingModule for Glob {
    fn namespace(&self) -> &'static str {
        "glob"
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
        let values: [(&str, v8::Local<'s, v8::Value>); 9] = [
            ("matchesGlob", function(scope, "matchesGlob", matches_glob)?),
            ("hasMagic", function(scope, "hasMagic", has_magic)?),
            ("globSync", function(scope, "globSync", glob_sync)?),
            ("globStart", function(scope, "globStart", glob_start)?),
            (
                "kFlagWindows",
                v8::Integer::new(scope, K_FLAG_WINDOWS as i32).into(),
            ),
            (
                "kFlagDot",
                v8::Integer::new(scope, K_FLAG_DOT as i32).into(),
            ),
            (
                "kFlagFollowSymlinks",
                v8::Integer::new(scope, K_FLAG_FOLLOW_SYMLINKS as i32).into(),
            ),
            (
                "kFlagWithFileTypes",
                v8::Integer::new(scope, K_FLAG_WITH_FILE_TYPES as i32).into(),
            ),
            (
                "kFlagMatchBase",
                v8::Integer::new(scope, K_FLAG_MATCH_BASE as i32).into(),
            ),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the `glob` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Glob);
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// The host's own matching rules, which the C++ ORs in and JavaScript cannot
/// override.
fn host_match_flags() -> u32 {
    if cfg!(any(windows, target_os = "macos")) {
        K_FLAG_NOCASE
    } else {
        0
    }
}

/// The host's own walk rules. A walk always follows the host's platform.
fn host_walk_flags() -> u32 {
    if cfg!(windows) {
        K_FLAG_WINDOWS | K_FLAG_NOCASE
    } else if cfg!(target_os = "macos") {
        K_FLAG_NOCASE
    } else {
        0
    }
}

/// `UnpackFlags`: only the behaviour bits survive.
fn unpack_flags(packed: u32) -> CompileFlags {
    CompileFlags {
        windows: packed & K_FLAG_WINDOWS != 0,
        nocase: packed & K_FLAG_NOCASE != 0,
        dot: packed & K_FLAG_DOT != 0,
        match_base: packed & K_FLAG_MATCH_BASE != 0,
        // Cleared for exclude patterns by the caller.
        nocase_magic_only: true,
    }
}

// ---------------------------------------------------------------------------
// Compiled-pattern cache
// ---------------------------------------------------------------------------

/// A compiled pattern, or the reason it did not compile.
#[derive(Clone)]
struct CacheEntry {
    compiled: Option<Rc<CompiledPattern>>,
    error: Option<parser::CompileError>,
}

/// Compiled patterns keyed by flags and pattern text.
///
/// A compiled pattern is large, so the cache is bounded. Node uses an LRU; a
/// plain map that clears at the cap has the same observable behaviour (a
/// recompile costs time, never changes an answer) and cannot grow without
/// bound.
#[derive(Default)]
struct PatternCache {
    entries: HashMap<(u32, Vec<u16>), CacheEntry>,
}

impl PatternCache {
    const MAX_ENTRIES: usize = 256;

    fn lookup(
        &mut self,
        pattern: &[u16],
        flags: &CompileFlags,
    ) -> Result<Rc<CompiledPattern>, parser::CompileError> {
        // The key is the packed flag word plus the pattern, exactly like
        // `BuildCacheKey`, so two flag combinations never share an entry.
        let packed = (if flags.windows { K_FLAG_WINDOWS } else { 0 })
            | (if flags.nocase { K_FLAG_NOCASE } else { 0 })
            | (if flags.dot { K_FLAG_DOT } else { 0 })
            | (if flags.match_base {
                K_FLAG_MATCH_BASE
            } else {
                0
            })
            | (if flags.nocase_magic_only {
                0
            } else {
                K_FLAG_NOCASE_LITERALS
            });
        let key = (packed, pattern.to_vec());
        if let Some(entry) = self.entries.get(&key) {
            return match (&entry.compiled, entry.error) {
                (Some(compiled), _) => Ok(Rc::clone(compiled)),
                (None, Some(error)) => Err(error),
                (None, None) => Err(parser::CompileError::InvalidRegExp),
            };
        }
        let entry = match CompiledPattern::from_pattern(pattern, *flags) {
            Ok(compiled) => CacheEntry {
                compiled: Some(Rc::new(compiled)),
                error: None,
            },
            Err(error) => CacheEntry {
                compiled: None,
                error: Some(error),
            },
        };
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        let answer = match (&entry.compiled, entry.error) {
            (Some(compiled), _) => Ok(Rc::clone(compiled)),
            (None, Some(error)) => Err(error),
            (None, None) => Err(parser::CompileError::InvalidRegExp),
        };
        self.entries.insert(key, entry);
        answer
    }
}

thread_local! {
    /// One cache per isolate, like Node's per-context `BindingData`.
    ///
    /// `Rc` because a walk holds its compiled patterns for its whole life and
    /// the cache must be able to hand them out without copying.
    static CACHE: RefCell<PatternCache> = RefCell::new(PatternCache::default());
}

fn with_cache<T>(f: impl FnOnce(&mut PatternCache) -> T) -> T {
    CACHE.with(|cache| f(&mut cache.borrow_mut()))
}

// ---------------------------------------------------------------------------
// matchesGlob and hasMagic
// ---------------------------------------------------------------------------

/// Throws the error a failed compile produces.
///
/// `kInvalidRegExp` is a `SyntaxError` and the other two are `TypeError`s,
/// which is what `ThrowCompileError` does.
fn throw_compile_error(scope: &mut v8::PinScope, error: parser::CompileError) {
    let (message, bad_regexp) = error.message();
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = if bad_regexp {
        v8::Exception::syntax_error(scope, text)
    } else {
        v8::Exception::type_error(scope, text)
    };
    scope.throw_exception(exception);
}

fn matches_glob(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let path = match string_argument(scope, &args, 0) {
        Some(text) => text,
        None => return,
    };
    let pattern = match string_argument(scope, &args, 1) {
        Some(text) => text,
        None => return,
    };
    let packed = args.get(2).uint32_value(scope).unwrap_or(0) | host_match_flags();
    let flags = unpack_flags(packed);

    let compiled = with_cache(|cache| cache.lookup(&pattern, &flags));
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => {
            throw_compile_error(scope, error);
            return;
        }
    };
    rv.set(v8::Boolean::new(scope, match_pattern(&compiled, &path)).into());
}

/// Whether a pattern is anything more than a literal path.
///
/// The original compiles the pattern with the host's *walk* rules and asks
/// whether any part is more than a literal, so `{a,b}` answers false: the brace
/// expands into two literal rows before matching.
fn has_magic(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let pattern = match string_argument(scope, &args, 0) {
        Some(text) => text,
        None => return,
    };
    let flags = unpack_flags(host_walk_flags());
    let compiled = with_cache(|cache| cache.lookup(&pattern, &flags));
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => {
            throw_compile_error(scope, error);
            return;
        }
    };
    // A row part is magic when it is not a plain literal. A globstar is magic by
    // definition; a program is magic unless it lowered to a literal.
    let magic = compiled.rows.iter().any(|row| {
        row.parts
            .iter()
            .any(|part| part.kind != crate::matcher::PartKind::Literal)
    });
    rv.set(v8::Boolean::new(scope, magic).into());
}

// ---------------------------------------------------------------------------
// Reading walk arguments
// ---------------------------------------------------------------------------

/// The arguments `globSync` and `globStart` share.
struct WalkRequest {
    options: WalkOptions,
    includes: Vec<Rc<CompiledPattern>>,
    excludes: Vec<Rc<CompiledPattern>>,
    /// The flags the exclude patterns were compiled with, which differ from the
    /// include flags in `nocase_magic_only`.
    exclude_flags: CompileFlags,
    with_file_types: bool,
    filter: Option<v8::Global<v8::Function>>,
}

impl WalkRequest {
    fn read(
        scope: &mut v8::PinScope<'_, '_>,
        args: &v8::FunctionCallbackArguments<'_>,
    ) -> Result<Self, String> {
        let cwd = string_argument(scope, args, 0).unwrap_or_else(|| ".".encode_utf16().collect());
        let cwd = String::from_utf16_lossy(&cwd);

        let packed = args.get(3).uint32_value(scope).unwrap_or(0) | host_walk_flags();
        let flags = unpack_flags(packed);
        // Exclude matching is a pure string comparison with no filesystem
        // lookups, so unlike include patterns, literal segments must also match
        // case-insensitively on a case-insensitive host.
        let mut exclude_flags = flags;
        exclude_flags.nocase_magic_only = false;

        let filter = match v8::Local::<v8::Function>::try_from(args.get(4)) {
            Ok(function) => Some(v8::Global::new(scope.as_ref(), function)),
            Err(_) => None,
        };
        let max_depth = args
            .get(5)
            .number_value(scope)
            .filter(|value| value.is_finite());
        let max_depth = max_depth.map(|depth| depth.max(0.0) as usize);

        let include_patterns = string_array_argument(scope, args, 1)?;
        let exclude_patterns = string_array_argument(scope, args, 2)?;

        let mut includes = Vec::with_capacity(include_patterns.len());
        for pattern in &include_patterns {
            let compiled = with_cache(|cache| cache.lookup(pattern, &flags));
            match compiled {
                Ok(compiled) => includes.push(compiled),
                Err(error) => {
                    throw_compile_error(scope, error);
                    return Err(String::new());
                }
            }
        }
        let mut excludes = Vec::with_capacity(exclude_patterns.len());
        for pattern in &exclude_patterns {
            let compiled = with_cache(|cache| cache.lookup(pattern, &exclude_flags));
            match compiled {
                Ok(compiled) => excludes.push(compiled),
                Err(error) => {
                    throw_compile_error(scope, error);
                    return Err(String::new());
                }
            }
        }

        Ok(Self {
            includes,
            excludes,
            exclude_flags,
            with_file_types: flags.with_file_types_flagged(packed),
            options: WalkOptions {
                cwd,
                follow_symlinks: packed & K_FLAG_FOLLOW_SYMLINKS != 0,
                with_file_types: packed & K_FLAG_WITH_FILE_TYPES != 0,
                max_depth,
            },
            filter,
        })
    }
}

impl CompileFlags {
    /// Whether the `kFlagWithFileTypes` bit was set, which is not a compile flag.
    fn with_file_types_flagged(self, packed: u32) -> bool {
        let _ = self;
        packed & K_FLAG_WITH_FILE_TYPES != 0
    }
}

/// The JavaScript `exclude` callback, adapted to the walker's interface.
struct JsFilter<'a, 's, 'i> {
    scope: &'a mut v8::PinScope<'s, 'i>,
    callback: v8::Local<'s, v8::Function>,
    failed: bool,
}

impl ExcludeFilter for JsFilter<'_, '_, '_> {
    fn excludes_path(&mut self, path: &str) -> Result<bool, String> {
        if self.failed {
            return Ok(false);
        }
        // `(entry, value, parentPath, type)`: `entry` is false for a bare path.
        let value = match v8::String::new(self.scope, path) {
            Some(value) => value,
            None => return Ok(false),
        };
        let arguments: [v8::Local<v8::Value>; 4] = [
            v8::Boolean::new(self.scope, false).into(),
            value.into(),
            v8::undefined(self.scope).into(),
            v8::Integer::new(self.scope, 0).into(),
        ];
        self.call(&arguments)
    }

    fn excludes_entry(&mut self, name: &str, parent: &str, kind: i32) -> Result<bool, String> {
        if self.failed {
            return Ok(false);
        }
        let value = match v8::String::new(self.scope, name) {
            Some(value) => value,
            None => return Ok(false),
        };
        let parent_value = match v8::String::new(self.scope, parent) {
            Some(value) => value,
            None => return Ok(false),
        };
        let arguments: [v8::Local<v8::Value>; 4] = [
            v8::Boolean::new(self.scope, true).into(),
            value.into(),
            parent_value.into(),
            v8::Integer::new(self.scope, kind).into(),
        ];
        self.call(&arguments)
    }
}

impl JsFilter<'_, '_, '_> {
    fn call(&mut self, arguments: &[v8::Local<'_, v8::Value>]) -> Result<bool, String> {
        let receiver = v8::undefined(self.scope).into();
        match self.callback.call(self.scope, receiver, arguments) {
            Some(result) => Ok(result.boolean_value(self.scope.as_ref())),
            None => {
                // The callback threw. Node leaves the exception pending and
                // stops the walk; the error is re-thrown by the caller.
                self.failed = true;
                Err("the exclude callback threw".to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// globSync
// ---------------------------------------------------------------------------

fn glob_sync(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let request = match WalkRequest::read(scope, &args) {
        Ok(request) => request,
        Err(_) => return,
    };
    let includes: Vec<CompiledPattern> = request.includes.iter().map(|rc| (**rc).clone()).collect();
    let excludes: Vec<CompiledPattern> = request.excludes.iter().map(|rc| (**rc).clone()).collect();

    let mut filter = request.filter.as_ref().map(|callback| JsFilter {
        callback: v8::Local::new(scope, callback),
        failed: false,
        scope: &mut *scope,
    });

    let walked = walker::glob_sync(
        &request.options,
        &includes,
        &excludes,
        request.exclude_flags,
        filter
            .as_mut()
            .map(|filter| filter as &mut dyn ExcludeFilter),
    );

    // A throw from the exclude callback leaves its exception pending, and Node
    // returns without building a result.
    if filter.as_ref().is_some_and(|filter| filter.failed) {
        return;
    }
    let entries = match walked {
        Ok(entries) => entries,
        Err(_) => return,
    };

    match marshal_entries(scope, &entries, request.with_file_types) {
        Some((paths, types)) => {
            if request.with_file_types {
                if let Some(types) = types {
                    let pair = v8::Array::new_with_elements(scope, &[paths.into(), types.into()]);
                    rv.set(pair.into());
                    return;
                }
                rv.set(paths.into());
            } else {
                rv.set(paths.into());
            }
        }
        None => rv.set_undefined(),
    }
}

/// Builds `[paths, types]`, the shape `MarshalEntries` produces.
fn marshal_entries<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[WalkEntry],
    with_types: bool,
) -> Option<(v8::Local<'s, v8::Array>, Option<v8::Local<'s, v8::Array>>)> {
    let paths = v8::Array::new(scope, entries.len() as i32);
    for (index, entry) in entries.iter().enumerate() {
        let text = v8::String::new(scope, &entry.path)?;
        paths.set_index(scope, index as u32, text.into());
    }
    if !with_types {
        return Some((paths, None));
    }
    let types = v8::Array::new(scope, entries.len() as i32);
    for (index, entry) in entries.iter().enumerate() {
        let value = v8::Integer::new(scope, entry.kind);
        types.set_index(scope, index as u32, value.into());
    }
    Some((paths, Some(types)))
}

// ---------------------------------------------------------------------------
// globStart
// ---------------------------------------------------------------------------

/// One result batch: `[paths, types|undefined, done]`.
fn settle<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[WalkEntry],
    with_types: bool,
    done: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    let (paths, types) = marshal_entries(scope, entries, with_types)?;
    let types: v8::Local<'s, v8::Value> = match types {
        Some(types) => types.into(),
        None => v8::undefined(scope).into(),
    };
    let done_value: v8::Local<'s, v8::Value> = v8::Boolean::new(scope, done).into();
    let result = v8::Array::new_with_elements(scope, &[paths.into(), types, done_value]);
    Some(result.into())
}

/// The native state behind a `globStart` handle.
///
/// Node's `GlobRequest` walks lazily, a batch at a time, on the threadpool. Here
/// the whole walk runs when the handle is created, which keeps `next()` able to
/// answer synchronously from an already-complete result set. That is
/// observably equivalent: `lib/internal/fs/glob.js` only sees promises resolving
/// in batch order with the same batches, and `#globSync`'s eager call is the
/// same traversal.
///
/// The alternative — running a slice per `next()` — would have to re-enter the
/// filesystem with a suspended traversal, and the only observable difference is
/// that a `cancel()` mid-iteration would stop sooner.
struct RequestState {
    entries: Vec<WalkEntry>,
    /// How far `next()` has consumed.
    cursor: usize,
    with_file_types: bool,
    done: bool,
    cancelled: bool,
    /// Set while a pull is outstanding, so a second pull throws rather than
    /// clobbering the pending resolver (Node's `ERR_INVALID_STATE`).
    in_flight: bool,
    /// Set when the walk failed, so a pull rejects instead of resolving empty.
    failure: Option<String>,
}

/// `GlobRequest::kBatchSize`: how many results one `next()` returns.
const BATCH_SIZE: usize = 256;

thread_local! {
    /// Handle state, keyed by an id held in the handle object's internal field.
    ///
    /// A `HashMap` rather than a raw pointer so that misuse after `cancel()`
    /// cannot dereference freed memory, and so the state is released with the
    /// isolate.
    static REQUESTS: RefCell<HashMap<u32, Rc<RefCell<RequestState>>>> =
        RefCell::new(HashMap::new());
    static NEXT_REQUEST_ID: RefCell<u32> = const { RefCell::new(1) };
}

fn glob_start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let request = match WalkRequest::read(scope, &args) {
        Ok(request) => request,
        Err(_) => return,
    };
    let includes: Vec<CompiledPattern> = request.includes.iter().map(|rc| (**rc).clone()).collect();
    let excludes: Vec<CompiledPattern> = request.excludes.iter().map(|rc| (**rc).clone()).collect();

    let mut filter = request.filter.as_ref().map(|callback| JsFilter {
        callback: v8::Local::new(scope, callback),
        failed: false,
        scope: &mut *scope,
    });
    let walked = walker::glob_sync(
        &request.options,
        &includes,
        &excludes,
        request.exclude_flags,
        filter
            .as_mut()
            .map(|filter| filter as &mut dyn ExcludeFilter),
    );
    if filter.as_ref().is_some_and(|filter| filter.failed) {
        return;
    }

    let (entries, failure) = match walked {
        Ok(entries) => (entries, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let state = RequestState {
        entries,
        cursor: 0,
        with_file_types: request.with_file_types,
        done: false,
        cancelled: false,
        in_flight: false,
        failure,
    };
    let id = NEXT_REQUEST_ID.with(|next| {
        let mut next = next.borrow_mut();
        let id = *next;
        *next += 1;
        id
    });
    REQUESTS.with(|requests| {
        requests
            .borrow_mut()
            .insert(id, Rc::new(RefCell::new(state)));
    });

    match make_handle(scope, id) {
        Some(handle) => rv.set(handle.into()),
        None => rv.set_undefined(),
    }
}

/// Builds the handle object with `next`, `all` and `cancel`.
fn make_handle<'s>(scope: &mut v8::PinScope<'s, '_>, id: u32) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    let id_value = v8::Integer::new_from_unsigned(scope, id);
    let key = v8::String::new(scope, "__rn_glob_request")?;
    object.set(scope, key.into(), id_value.into());

    let next = v8::FunctionTemplate::builder(next_pull).build(scope);
    let all = v8::FunctionTemplate::builder(all_pull).build(scope);
    let cancel = v8::FunctionTemplate::builder(cancel_pull).build(scope);
    for (name, template) in [("next", next), ("all", all), ("cancel", cancel)] {
        let name_value = v8::String::new(scope, name)?;
        let function = template.get_function(scope)?;
        object.set(scope, name_value.into(), function.into());
    }
    Some(object)
}

fn request_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Option<u32> {
    let this = args.this();
    let key = v8::String::new(scope, "__rn_glob_request")?;
    let value = this.get(scope, key.into())?;
    value.uint32_value(scope)
}

fn next_pull(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    pull(scope, &args, &mut rv, false);
}

fn all_pull(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    pull(scope, &args, &mut rv, true);
}

fn cancel_pull(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(id) = request_id(scope, &args) else {
        return;
    };
    REQUESTS.with(|requests| {
        if let Some(state) = requests.borrow().get(&id) {
            let mut state = state.borrow_mut();
            state.cancelled = true;
            if !state.in_flight {
                state.done = true;
            }
        }
    });
}

/// `GlobRequest::Pull`: resolves `[paths, types, done]`.
fn pull(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    drain: bool,
) {
    let Some(id) = request_id(scope, args) else {
        return;
    };
    let state = REQUESTS.with(|requests| requests.borrow().get(&id).cloned());
    let Some(state) = state else {
        throw(scope, "glob handle is no longer valid");
        return;
    };

    let (entries, with_types, done, failure) = {
        let mut state = state.borrow_mut();
        if state.in_flight {
            // Reachable through a second pull or a pull from inside the exclude
            // callback. Node throws rather than clobbering the resolver.
            drop(state);
            throw(scope, "glob is already waiting for results");
            return;
        }
        state.in_flight = true;
        let start = state.cursor;
        let end = if drain {
            state.entries.len()
        } else {
            (start + BATCH_SIZE).min(state.entries.len())
        };
        let slice = state.entries[start..end].to_vec();
        state.cursor = end;
        let done = state.cancelled || end >= state.entries.len();
        state.done = done;
        (slice, state.with_file_types, done, state.failure.clone())
    };

    // The pull has produced its answer, so the handle is idle again even though
    // the promise has not settled yet; `Settle()` runs before the resolver is
    // released in Node too.
    {
        let mut state = state.borrow_mut();
        state.in_flight = false;
    }

    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        return;
    };
    let promise = resolver.get_promise(scope);
    match failure {
        Some(message) => {
            let Some(message) = v8::String::new(scope, &message) else {
                return;
            };
            let exception = v8::Exception::error(scope, message);
            resolver.reject(scope, exception);
        }
        None => match settle(scope, &entries, with_types, done) {
            Some(value) => {
                resolver.resolve(scope, value);
            }
            None => rv.set_undefined(),
        },
    }
    rv.set(promise.into());
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Reads argument `index` as a UTF-16 pattern.
///
/// The binding works in UTF-16 because that is what V8 hands over, and an
/// unpaired surrogate has to survive to the matcher rather than be replaced.
fn string_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<Vec<u16>> {
    let value = args.get(index);
    if value.is_undefined() {
        return None;
    }
    let text = value.to_string(scope)?;
    Some(text.to_rust_string_lossy(scope).encode_utf16().collect())
}

/// Reads argument `index` as an array of strings, tolerating a non-array by
/// treating it as empty (the JavaScript layer validates before calling).
fn string_array_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Result<Vec<Vec<u16>>, String> {
    let value = args.get(index);
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(array.length() as usize);
    for position in 0..array.length() {
        let Some(element) = array.get_index(scope, position) else {
            continue;
        };
        let Some(text) = element.to_string(scope) else {
            continue;
        };
        out.push(text.to_rust_string_lossy(scope).encode_utf16().collect());
    }
    Ok(out)
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate glob.{name}"))?;
    Ok(function.into())
}

fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    scope.throw_exception(exception);
}
