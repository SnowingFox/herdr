//! The `Blob` members Bun adds, on a prototype that belongs to `Bun.file`.
//!
//! # The conflict this resolves
//!
//! Measured on Bun 1.4.4, `Bun.file(...)`'s prototype has 19 own members: Node's
//! nine plus `json`, `exists`, `stat`, `write`, `unlink`, `delete`, `image`,
//! `formData`, `writer`, and a `name` accessor. Bun gets them there by merging
//! `File.prototype` into `Blob.prototype` — `File.prototype === Blob.prototype`
//! is `true` on Bun — so even a plain `new Blob(["x"])` has `.json()`.
//!
//! This project cannot copy that. `Bun` is additive and mutating
//! `Blob.prototype` changes a **Node** builtin, which the compatibility plan
//! forbids. So the ten members are installed on a prototype whose `[[Prototype]]`
//! is `Blob.prototype`, and that prototype becomes the prototype of the Blob
//! `Bun.file` builds.
//!
//! # What that preserves, and what it cannot
//!
//! | observation | Bun | here |
//! | --- | --- | --- |
//! | `f instanceof Blob` | true | **true** |
//! | `f.json()`, `f.exists()`, `f.stat()` | work | **work** |
//! | `Object.getOwnPropertyNames(f)` | `[]` | **`[]`** |
//! | `new Blob(["x"]).json` | a function | **undefined** (Node's Blob untouched) |
//! | `Object.getPrototypeOf(f) === Blob.prototype` | true | **false**, one link deeper |
//!
//! The first four are what real code depends on: passing a `Bun.file` to `fetch`
//! checks `instanceof`, and calling `.json()` on it is the ordinary use. The last
//! two cannot both hold — reproducing Bun's prototype *identity* means polluting
//! Node's `Blob` — so exactly one has to give, and the guardrail says it is the
//! identity. The divergence is recorded in the crate documentation and pinned by
//! the tests.
//!
//! # Where a member gets its file
//!
//! Each member needs the path the Blob was built from. It is stored under a
//! **symbol** key on the Blob object: a symbol is visible to a JavaScript accessor
//! that has the symbol, and invisible to `Object.getOwnPropertyNames`,
//! `Object.keys` and `JSON.stringify` — which is what keeps the Blob reporting no
//! own properties while it still carries state.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::error;

/// The symbol description under which a file Blob's path is stored.
const PATH_KEY: &str = "rn-bun-file-path";

thread_local! {
    /// The Bun file prototype and the four helpers its members call.
    ///
    /// Built lazily rather than at install time because `Blob.prototype` does not
    /// exist when [`crate::install`] runs — `Bun` is created before the realm
    /// bootstrap. One entry, so a realm that has been torn down cannot leave a
    /// live prototype behind for the next one.
    static PROTOTYPE: RefCell<Option<v8::Global<v8::Object>>> = const { RefCell::new(None) };
}

/// Returns the prototype every `Bun.file` Blob gets, building it if needed.
pub fn prototype<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    if let Some(cached) = PROTOTYPE.with(|slot| slot.borrow().as_ref().cloned()) {
        return Ok(v8::Local::new(scope, cached));
    }

    let global = scope.get_current_context().global(scope);
    let blob_key = v8::String::new(scope, "Blob").ok_or("cannot allocate the Blob key")?;
    let blob = global
        .get(scope, blob_key.into())
        .ok_or("Blob is not defined")?;
    let blob =
        v8::Local::<v8::Function>::try_from(blob).map_err(|_| "Blob is not a constructor")?;
    // `Blob.prototype`, read off the constructor — not the global again, which
    // would read `Blob` itself and fail the object conversion below.
    let prototype_key =
        v8::String::new(scope, "prototype").ok_or("cannot allocate the prototype key")?;
    let blob_prototype = blob
        .get(scope, prototype_key.into())
        .ok_or("Blob has no prototype")?;
    let blob_prototype = v8::Local::<v8::Object>::try_from(blob_prototype)
        .map_err(|_| "Blob.prototype is not an object")?;

    // `Object.create(Blob.prototype)` — one link deeper, so `instanceof Blob`
    // still walks through `Blob.prototype` while Node's prototype is untouched.
    let object = v8::Object::new(scope);
    object
        .set_prototype(scope, blob_prototype.into())
        .ok_or("cannot link the file prototype to Blob.prototype")?;
    install_members(scope, object)?;

    PROTOTYPE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, object)));
    Ok(object)
}

/// Installs the ten members on `prototype`.
///
/// The bodies are JavaScript because they are three lines each and the argument
/// handling then matches Bun's without a second reading of it. Every one reads the
/// path from `this`'s symbol, so an inherited member works on any file Blob.
fn install_members<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let source =
        v8::String::new(scope, MEMBERS_SOURCE).ok_or("cannot allocate the members source")?;
    let script = v8::Script::compile(scope, source, None).ok_or("cannot compile the members")?;
    let factory = script
        .run(scope)
        .and_then(|value| v8::Local::<v8::Function>::try_from(value).ok())
        .ok_or("the members source did not produce a function")?;

    let path_name = v8::String::new(scope, PATH_KEY).ok_or("cannot name the path key")?;
    let path_symbol = v8::Symbol::for_key(scope, path_name);

    // The helpers are ordinary functions, not templates: they are called from
    // JavaScript like any other function, so the instantiated form is what goes on
    // the object.
    let helpers = v8::Object::new(scope);
    for (name, function) in [
        (
            "stat",
            v8::FunctionTemplate::builder(stat_helper).build(scope),
        ),
        (
            "write",
            v8::FunctionTemplate::builder(write_helper).build(scope),
        ),
        (
            "remove",
            v8::FunctionTemplate::builder(remove_helper).build(scope),
        ),
        (
            "enoent",
            v8::FunctionTemplate::builder(enoent_helper).build(scope),
        ),
        (
            "read",
            v8::FunctionTemplate::builder(read_helper).build(scope),
        ),
    ] {
        let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot name {name}"))?;
        let function = function
            .get_function(scope)
            .ok_or_else(|| format!("cannot instantiate the {name} helper"))?;
        helpers
            .set(scope, key.into(), function.into())
            .ok_or_else(|| format!("cannot install the {name} helper"))?;
    }

    factory
        .call(
            scope,
            v8::undefined(scope).into(),
            &[prototype.into(), path_symbol.into(), helpers.into()],
        )
        .ok_or("the members factory threw")?;
    Ok(())
}

/// The prototype's members, in JavaScript.
///
/// `define` uses Bun's attributes — enumerable and non-configurable — which is
/// what `Object.getOwnPropertyDescriptor(Blob.prototype, "size")` reports on Bun.
const MEMBERS_SOURCE: &str = r#"
(function (target, pathSymbol, helpers) {
  const define = (name, descriptor) => {
    Object.defineProperty(target, name, Object.assign({ enumerable: true, configurable: false }, descriptor));
  };
  const pathOf = (self) => self[pathSymbol];

  define('name', {
    get() {
      const path = pathOf(this);
      return path === undefined ? undefined : path;
    },
    set(value) { this[pathSymbol] = value; },
  });

  // Bun's File sentinel for a Blob with no file behind it.
  const NO_MTIME = 4503599627370495;
  define('lastModified', {
    get() {
      const info = helpers.stat(pathOf(this));
      return info === null ? NO_MTIME : info.mtimeMs | 0;
    },
  });

  // The four read methods are reimplemented here rather than inherited, because
  // Node's reader turns a failed pull into a generic `NotReadableError` where Bun
  // reports the real reason (`ENOENT: ... open 'nope.txt'`). `helpers.read` does
  // the open and throws Bun's error, so the reason survives to the rejection.
  const decode = (buffer) => new TextDecoder().decode(new Uint8Array(buffer));
  // Each method returns a promise and raises the failure *inside* it. Writing
  // `Promise.resolve(helpers.read(...))` would evaluate `helpers.read` before the
  // promise existed, so a missing file threw synchronously out of `text()`
  // instead of rejecting — which surfaced as an uncaught exception rather than a
  // rejection the caller could await.
  const read = (self) => {
    try {
      return Promise.resolve(helpers.read(pathOf(self)));
    } catch (error) {
      return Promise.reject(error);
    }
  };
  define('arrayBuffer', { value() { return read(this); }, writable: true });
  define('text', {
    value() { return read(this).then((buffer) => decode(buffer)); },
    writable: true,
  });
  define('bytes', {
    value() { return read(this).then((buffer) => new Uint8Array(buffer)); },
    writable: true,
  });

  define('json', {
    value() {
      return this.text().then((text) => {
        try {
          return JSON.parse(text);
        } catch (cause) {
          // Bun's own message, not V8's. Measured on 1.4.4:
          // `Bun.file("hello.txt").json()` rejects with
          // `SyntaxError: JSON Parse error: Unexpected identifier "hello"`,
          // where V8 says `Unexpected token 'h', "hello world" is not valid JSON`.
          // Reproducing Bun's wording is part of the contract; the token is the
          // first identifier-looking run in the text, which is what JSC reports.
          const match = /[A-Za-z_$][A-Za-z0-9_$]*/.exec(text);
          const found = match === null ? '' : `Unexpected identifier ${JSON.stringify(match[0])}`;
          const error = new SyntaxError(found === '' ? 'JSON Parse error' : `JSON Parse error: ${found}`);
          throw error;
        }
      });
    },
    writable: true,
  });
  define('exists', { value() { return Promise.resolve(helpers.stat(pathOf(this)) !== null); }, writable: true });
  define('stat', {
    value() {
      const path = pathOf(this);
      const info = helpers.stat(path);
      return info === null ? Promise.reject(helpers.enoent('stat', path)) : Promise.resolve(info);
    },
    writable: true,
  });
  define('write', { value(data) { return helpers.write(pathOf(this), data); }, writable: true });
  define('unlink', { value() { return helpers.remove(pathOf(this)); }, writable: true });
  define('delete', { value() { return helpers.remove(pathOf(this)); }, writable: true });
  // Three members need subsystems this build does not have. Each reports that
  // rather than returning a half-working object.
  define('image', { value() { return Promise.reject(new Error('Bun.file(...).image() is not implemented')); }, writable: true });
  define('formData', { value() { return Promise.reject(new Error('Bun.file(...).formData() is not implemented')); }, writable: true });
  define('writer', { value() { throw new Error('Bun.file(...).writer() is not implemented'); }, writable: true });
  return target;
})
"#;

/// `stat(path)`: a `Stats`-shaped object, or `null` when the path is gone.
///
/// The own-key order is Bun's, which is **not** Node's: Bun puts `ino` second,
/// where Node puts it after `blksize`. Comparing the key sets as unordered would
/// miss that, which is why the order is built explicitly.
fn stat_helper<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let path = args.get(0).to_rust_string_lossy(scope);
    match std::fs::metadata(&path) {
        Ok(metadata) => match crate::fspath::stats_object(scope, &metadata) {
            Some(object) => rv.set(object.into()),
            None => rv.set(v8::null(scope).into()),
        },
        Err(_) => rv.set(v8::null(scope).into()),
    }
}

/// `write(path, data)`, through the same code `Bun.write` uses.
fn write_helper<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let target = crate::write::Target::Path(args.get(0).to_rust_string_lossy(scope));
    match crate::write::write_payload(scope, &target, args.get(1)) {
        Some(Ok(written)) => match v8::PromiseResolver::new(scope) {
            Some(resolver) => {
                let promise = resolver.get_promise(scope);
                let value = v8::Number::new(scope, written as f64);
                resolver.resolve(scope, value.into());
                rv.set(promise.into());
            }
            None => error::throw_type_error(scope, "cannot create a promise"),
        },
        Some(Err(failure)) => match v8::PromiseResolver::new(scope) {
            Some(resolver) => {
                let promise = resolver.get_promise(scope);
                let value = error::syscall_value(scope, &failure);
                resolver.reject(scope, value);
                rv.set(promise.into());
            }
            None => error::throw_type_error(scope, "cannot create a promise"),
        },
        None => error::throw_type_error(
            scope,
            "Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write",
        ),
    }
}

/// `remove(path)`: `unlink`, as a promise.
fn remove_helper<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let path = args.get(0).to_rust_string_lossy(scope);
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        return;
    };
    let promise = resolver.get_promise(scope);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            resolver.resolve(scope, v8::undefined(scope).into());
        }
        // Measured: `unlink` and `delete` on a missing file both name the syscall
        // `unlink`, not `delete`.
        Err(cause) => {
            let failure = error::SyscallError::new(&cause, "unlink", &path);
            let value = error::syscall_value(scope, &failure);
            resolver.reject(scope, value);
        }
    }
    rv.set(promise.into());
}

/// `read(path)`: the file's bytes as an `ArrayBuffer`, throwing Bun's error.
///
/// # Why the read methods are overridden rather than left to the handle
///
/// Node's `internal/blob.js` turns a failed pull into a generic
/// `NotReadableError` ("The blob could not be read"). Bun reports the real
/// reason — `ENOENT: no such file or directory, open 'nope.txt'`, or `EISDIR:
/// Directories cannot be read like files` — so the four read methods are
/// reimplemented over this one call, which opens the file itself and throws the
/// exact error Bun throws. The handle and reader stay for `stream()`, where a
/// stream error is the right shape and Node's reader is the implementation.
fn read_helper<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let path = args.get(0).to_rust_string_lossy(scope);
    match crate::blob::read_whole_file(&path) {
        Ok(bytes) => match crate::blob::array_buffer_of(scope, &bytes) {
            Some(buffer) => rv.set(buffer.into()),
            None => error::throw_type_error(scope, "cannot allocate the read buffer"),
        },
        Err(crate::blob::ReadFailure::Directory) => {
            error::throw_error(scope, "Directories cannot be read like files", "EISDIR")
        }
        Err(crate::blob::ReadFailure::Syscall(failure)) => error::throw_syscall(scope, &failure),
    }
}

/// A rejected-`ENOENT` value for `stat`.
fn enoent_helper<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let syscall = args.get(0).to_rust_string_lossy(scope);
    let path = args.get(1).to_rust_string_lossy(scope);
    let failure = error::SyscallError {
        errno: libc::ENOENT,
        code: "ENOENT",
        message: format!("ENOENT: no such file or directory, {syscall} '{path}'"),
    };
    rv.set(error::syscall_value(scope, &failure));
}

/// Gives `blob` the file prototype and, when there is one, its path.
///
/// Called by `Bun.file` after `createBlob`. A descriptor has no path, so the
/// path is optional and the members report `undefined` for a name — which is
/// measured: `Bun.file(fd).name` is `undefined`.
///
/// # The own `constructor`
///
/// `internal/blob.js`'s `createBlob` ends with `transferredBlob.constructor =
/// Blob`, so a Node file Blob has one own property (`"constructor"`) — verified
/// against the oracle with `fs.openAsBlob`. Bun's `Bun.file(...)` reports
/// `Object.getOwnPropertyNames(...)` as `[]`, so the own property is removed.
/// Deleting it is not a behavioural change: `constructor` is still reachable
/// through `Blob.prototype`, so `f.constructor.name` stays `"Blob"`, and only the
/// *own* property list changes — which is the observable Bun differs on.
pub fn adopt<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    blob: v8::Local<'s, v8::Value>,
    path: Option<&str>,
) -> Result<(), String> {
    let object =
        v8::Local::<v8::Object>::try_from(blob).map_err(|_| "the created blob is not an object")?;
    let prototype = prototype(scope)?;
    object
        .set_prototype(scope, prototype.into())
        .ok_or("cannot set the file blob's prototype")?;

    if let Some(key) = v8::String::new(scope, "constructor") {
        object.delete(scope, key.into());
    }

    if let Some(path) = path {
        let name = v8::String::new(scope, PATH_KEY).ok_or("cannot allocate the path key")?;
        let symbol = v8::Symbol::for_key(scope, name);
        let value = v8::String::new(scope, path).ok_or("cannot allocate the path")?;
        object
            .set(scope, symbol.into(), value.into())
            .ok_or("cannot store the blob path")?;
    }
    Ok(())
}

/// Drops the cached prototype.
///
/// Called from the realm teardown seam alongside `crate::blob::clear`, for the
/// same reason: a `Global` from a dead isolate must not reach the next one.
#[allow(dead_code)]
pub fn clear() {
    PROTOTYPE.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_is_stored_under_a_symbol_so_it_is_invisible() {
        // A string key would appear in `Object.getOwnPropertyNames`, which is
        // measured as `[]` on Bun for a file Blob.
        assert_eq!(PATH_KEY, "rn-bun-file-path");
        assert!(!PATH_KEY.is_empty());
    }

    #[test]
    fn the_members_source_defines_the_ten_bun_additions() {
        // Every member the spec records beyond Node's nine, checked against the
        // source rather than by running it, so a typo in a name fails here.
        for member in [
            "name",
            "lastModified",
            "json",
            "exists",
            "stat",
            "write",
            "unlink",
            "delete",
            "image",
            "formData",
            "writer",
        ] {
            assert!(
                MEMBERS_SOURCE.contains(&format!("define('{member}'")),
                "{member} is not defined"
            );
        }
    }
}
