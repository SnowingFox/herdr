//! `Bun.Glob`: pattern matching and directory scanning.
//!
//! # What is reused and what is new
//!
//! The matching engine is `rn-bind-glob`'s — the same parser, brace expander,
//! matcher and walker that back `fs.glob`, ported from `src/glob/**`. Re-deriving
//! glob semantics would be a second answer to a question this project has
//! already answered, and the two would drift. What is new here is only Bun's
//! *surface*:
//!
//! * `match(subject)` compares against a **single path component**, so a slash
//!   never matches `*.js` and a leading `./` is not normalised away.
//! * `scan(options)` / `scanSync(options)` take `cwd`, `absolute`, `dot` and
//!   `onlyFiles`, and the options object is the first argument — the pattern is
//!   on the instance, not passed to the scan.
//! * The instances carry **no own properties**, so the pattern lives in a
//!   private property rather than a field.
//!
//! # Two measured shapes
//!
//! ```text
//! new Bun.Glob("*.js").match("a.js")      => true
//! new Bun.Glob("*.js").match("sub/a.js")  => false     (slash never matches)
//! new Bun.Glob("*.js").match("./a.js")    => false     (no normalisation)
//! Object.getOwnPropertyNames(new Bun.Glob("x")) => []  (no own fields)
//! ```
//!
//! The `"./a.js"` case is the one a `minimatch`-style implementation gets wrong:
//! `minimatch` strips the `./` and answers `true`.
//!
//! # `onlyFiles` and `dot`
//!
//! `onlyFiles` defaults to **true**, and `dot` defaults to false, matching Bun
//! rather than `fs.glob`'s flags. `scanSync({onlyFiles: false})` includes
//! directories in the result, which is why the walk asks for dirent kinds.

use std::cell::RefCell;

use rn_bind_glob::matcher::CompiledPattern;
use rn_bind_glob::parser::CompileFlags;
use rn_bind_glob::walker::{glob_sync, WalkOptions};
use rn_v8_sys::v8;

use crate::error;

/// The private property holding an instance's pattern.
const KEY_PATTERN: &str = "rn-bun-glob-pattern";

thread_local! {
    /// The `Glob` constructor template, built once per isolate.
    static TEMPLATE: RefCell<Option<v8::Global<v8::FunctionTemplate>>> =
        const { RefCell::new(None) };
}

/// Installs `Bun.Glob` on `target`.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(glob_constructor)
        .constructor_behavior(v8::ConstructorBehavior::Allow)
        .length(1)
        .build(scope);
    template.set_class_name(v8::String::new(scope, "Glob").ok_or("cannot name Glob")?);

    let prototype = template.prototype_template(scope);
    for (name, callback) in [
        ("match", rn_core::class(glob_match).build(scope)),
        ("scan", rn_core::class(glob_scan).build(scope)),
        ("scanSync", rn_core::class(glob_scan_sync).build(scope)),
    ] {
        let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot name {name}"))?;
        prototype.set(key.into(), callback.into());
    }

    let function = template
        .get_function(scope)
        .ok_or("cannot instantiate the Glob constructor")?;
    // The recorded arity is 1 for the constructor and 1 for each method, and V8
    // names prototype members from their property key, so nothing else is set.
    let key = v8::String::new(scope, "Glob").ok_or("cannot allocate the Glob key")?;
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| "cannot install Bun.Glob".to_string())?;

    TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, template)));
    Ok(())
}

/// `new Bun.Glob(pattern)`.
fn glob_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let pattern = args.get(0);
    if !pattern.is_string() {
        // Measured: `new Bun.Glob()` and `new Bun.Glob(42)` both throw this,
        // including the no-argument case, so there is no default pattern.
        error::throw_invalid_arg(scope, "pattern must be a string");
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(name) = v8::String::new(scope, KEY_PATTERN) else {
        return;
    };
    let key = v8::Private::for_api(scope, Some(name));
    if this.set_private(scope, key, pattern).is_none() {
        error::throw_type_error(scope, "cannot store the glob pattern");
    }
}

/// The pattern stored on `this`.
fn pattern_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    this: v8::Local<'s, v8::Value>,
) -> Option<String> {
    let object = v8::Local::<v8::Object>::try_from(this).ok()?;
    let name = v8::String::new(scope, KEY_PATTERN)?;
    let key = v8::Private::for_api(scope, Some(name));
    let value = object.get_private(scope, key)?;
    Some(value.to_rust_string_lossy(scope))
}

/// `glob.match(subject)`.
///
/// Compares against one path component: the pattern is compiled with
/// `match_base` off and the subject is not normalised, so `"sub/a.js"` and
/// `"./a.js"` both fail a `*.js` pattern.
fn glob_match<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(pattern) = pattern_of(scope, args.this().into()) else {
        error::throw_type_error(scope, "match must be called on a Glob");
        return;
    };
    let subject = args.get(0);
    if !subject.is_string() {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    }
    let subject = subject.to_rust_string_lossy(scope);

    let flags = CompileFlags {
        windows: false,
        nocase: false,
        nocase_magic_only: true,
        // `dot: true` for `match`: a pattern that names a leading dot must be
        // able to match it, and `match` is given a bare name rather than walking
        // a directory, so the walker's dot rule does not apply.
        dot: true,
        match_base: false,
    };
    let pattern_units: Vec<u16> = pattern.encode_utf16().collect();
    let Ok(compiled) = CompiledPattern::from_pattern(&pattern_units, flags) else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    let subject_units: Vec<u16> = subject.encode_utf16().collect();
    let matched = rn_bind_glob::match_pattern(&compiled, &subject_units);
    rv.set(v8::Boolean::new(scope, matched).into());
}

/// `glob.scanSync(options?)`.
fn glob_scan_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(pattern) = pattern_of(scope, args.this().into()) else {
        error::throw_type_error(scope, "scanSync must be called on a Glob");
        return;
    };
    let options = ScanOptions::read(scope, args.get(0));
    match scan(&pattern, &options) {
        Ok(entries) => match to_array(scope, &entries) {
            Some(array) => rv.set(array.into()),
            None => error::throw_type_error(scope, "cannot allocate the result array"),
        },
        Err(failure) => error::throw_syscall(scope, &failure),
    }
}

/// `glob.scan(options?)`, an async iterable.
///
/// The result is an array with `Symbol.asyncIterator` installed on it, which is
/// what `for await (const path of glob.scan())` and `[...]`-style collection both
/// consume. The walk itself is synchronous — Bun's is too on this path — so the
/// iterator yields already-collected entries rather than walking lazily.
fn glob_scan<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(pattern) = pattern_of(scope, args.this().into()) else {
        error::throw_type_error(scope, "scan must be called on a Glob");
        return;
    };
    let options = ScanOptions::read(scope, args.get(0));
    let entries = match scan(&pattern, &options) {
        Ok(entries) => entries,
        Err(failure) => {
            error::throw_syscall(scope, &failure);
            return;
        }
    };
    match async_iterable(scope, &entries) {
        Some(value) => rv.set(value),
        None => error::throw_type_error(scope, "cannot build the async iterable"),
    }
}

/// The options a scan was given.
struct ScanOptions {
    cwd: String,
    absolute: bool,
    dot: bool,
    only_files: bool,
}

impl ScanOptions {
    /// Reads the options object, defaulting every field the way Bun does.
    ///
    /// `onlyFiles` defaults to **true**, so `scanSync()` over `"*"` returns files
    /// and not directories; `dot` defaults to false; `cwd` defaults to `.`.
    fn read<'s>(scope: &mut v8::PinScope<'s, '_>, value: v8::Local<'s, v8::Value>) -> Self {
        let mut options = Self {
            cwd: ".".to_string(),
            absolute: false,
            dot: false,
            only_files: true,
        };
        let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
            return options;
        };
        if let Some(flag) = property(scope, object, "absolute") {
            options.absolute = flag.is_true();
        }
        if let Some(flag) = property(scope, object, "dot") {
            options.dot = flag.is_true();
        }
        if let Some(flag) = property(scope, object, "onlyFiles") {
            // An explicit `false` is the only way to include directories, so an
            // absent value keeps the default rather than reading as false.
            options.only_files = !flag.is_false();
        }
        if let Some(cwd) = property(scope, object, "cwd") {
            if let Ok(text) = v8::Local::<v8::String>::try_from(cwd) {
                options.cwd = text.to_rust_string_lossy(scope);
            }
        }
        options
    }
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

/// Walks `cwd` for `pattern`.
///
/// The pattern is compiled once and handed to the shared walker, which is the
/// same call `fs.glob` makes. `onlyFiles` and `dot` map to the walk's options;
/// `absolute` is applied to the results afterwards, because the walker reports
/// paths relative to its cwd.
fn scan(pattern: &str, options: &ScanOptions) -> Result<Vec<String>, crate::error::SyscallError> {
    let flags = CompileFlags {
        windows: false,
        nocase: false,
        nocase_magic_only: true,
        dot: options.dot,
        match_base: false,
    };
    let units: Vec<u16> = pattern.encode_utf16().collect();
    let compiled =
        CompiledPattern::from_pattern(&units, flags).map_err(|_| crate::error::SyscallError {
            errno: libc::EINVAL,
            code: "EINVAL",
            message: format!("EINVAL: invalid argument, glob '{pattern}'"),
        })?;

    let includes = [compiled];
    let walk = WalkOptions {
        cwd: options.cwd.clone(),
        follow_symlinks: false,
        with_file_types: false,
        max_depth: None,
    };

    let entries = glob_sync(&walk, &includes, &[], flags, None).map_err(|reason| {
        crate::error::SyscallError {
            errno: libc::ENOENT,
            code: "ENOENT",
            message: format!("ENOENT: no such file or directory, open '{}'", options.cwd),
        }
        .tap(&reason)
    })?;

    let mut results = Vec::new();
    for entry in entries {
        if options.only_files && !is_file(entry.kind) {
            continue;
        }
        results.push(if options.absolute {
            // A relative `cwd` must be resolved first: measured, Bun answers
            // `["/tmp/.../g/a.js"]` for both `cwd: "g"` and an absolute cwd, so
            // the join is against the *resolved* directory rather than the string
            // that was passed.
            let base = std::path::absolute(&options.cwd)
                .unwrap_or_else(|_| std::path::PathBuf::from(&options.cwd));
            base.join(&entry.path).to_string_lossy().into_owned()
        } else {
            entry.path
        });
    }
    Ok(results)
}

/// Whether a `UV_DIRENT_*` value is a regular file.
///
/// `UV_DIRENT_FILE` is 1 and `UV_DIRENT_LINK` is 7; a symlink is reported as a
/// file only when it resolves to one, which the walk already decided.
fn is_file(kind: i32) -> bool {
    kind == 1 || kind == 7
}

/// A `Vec<String>` as a JavaScript array.
fn to_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[String],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, entries.len() as i32);
    for (index, entry) in entries.iter().enumerate() {
        let value = v8::String::new(scope, entry)?;
        array.set_index(scope, index as u32, value.into())?;
    }
    Some(array)
}

/// An array carrying `Symbol.asyncIterator`, for `glob.scan()`.
///
/// The iterator is written in JavaScript because it is four lines of protocol
/// (`next()` returning `{value, done}` wrapped in a promise) and doing it in Rust
/// would be the same four lines with more `Local` juggling. The entries are
/// passed in as data, so nothing is captured that could outlive the call.
fn async_iterable<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[String],
) -> Option<v8::Local<'s, v8::Value>> {
    let array = to_array(scope, entries)?;
    let source = v8::String::new(
        scope,
        r#"
        (function (entries) {
          const iterator = {
            index: 0,
            next() {
              if (this.index < entries.length) {
                return Promise.resolve({ value: entries[this.index++], done: false });
              }
              return Promise.resolve({ value: undefined, done: true });
            },
            [Symbol.asyncIterator]() { return this; },
          };
          Object.defineProperty(entries, Symbol.asyncIterator, {
            value: () => iterator,
            enumerable: false,
            configurable: true,
          });
          return entries;
        })
        "#,
    )?;
    let script = v8::Script::compile(scope, source, None)?;
    let factory: v8::Local<v8::Function> = script.run(scope)?.try_into().ok()?;
    factory.call(scope, v8::undefined(scope).into(), &[array.into()])
}

/// Adds the walker's own reason to a failure without changing the message.
trait Tap {
    fn tap(self, reason: &str) -> Self;
}

impl Tap for crate::error::SyscallError {
    fn tap(mut self, reason: &str) -> Self {
        // The message stays Bun's; the walker's reason is kept only so a future
        // reader can find where it came from, and is appended as a hidden note
        // only when the walk failed for something other than ENOENT.
        if !reason.is_empty() && !reason.contains("no such file") {
            self.message = format!("{} [{}]", self.message, reason);
        }
        self
    }
}
