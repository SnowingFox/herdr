//! The `Bun` global.
//!
//! `Bun` is a **global**, not an `internalBinding` namespace: `Bun.hash`,
//! `Bun.file` and the rest are read as bare identifiers off `globalThis`, the way
//! they are in Bun. [`install`] therefore puts one object on the global object
//! rather than returning a namespace object for `internalBinding()` to cache.
//!
//! # How members get in
//!
//! This crate does not implement any `Bun.*` member. It owns the object, the
//! installation point, and the startup cost; the members come from **contribution
//! crates** that declare themselves through [`rn_bun_api::BunModule`]. The list of
//! contribution crates is generated from `crates/` by
//! `tools/regen-bun-contributions.sh` into `rn-bun-members`, so:
//!
//! * adding a member group means adding a crate, never editing this file;
//! * a crate cannot add a member that silently does not work, because
//!   [`rn_bun_api::BunRegistry`] compares each module's declaration against the
//!   object it actually built in both directions and refuses duplicate names
//!   across crates;
//! * `rn-bun` cannot drift from the contribution list, because the list is
//!   derived from the directory rather than maintained here.
//!
//! # Where it is installed, and why there
//!
//! `rn-realm::install_early_globals` calls [`install`] on the main thread and on
//! every worker thread, before the `require` early-return in that function. Two
//! facts make that the right point:
//!
//! * nothing in `Bun`'s assembly needs a Node builtin, so it must not be gated on
//!   `require` existing — a worker whose loader failed should still see `Bun`;
//! * it has to be in place before the first user script, and before
//!   `internal/bootstrap/node.js`'s globals, because a Bun-targeted script may
//!   read `Bun.version` on its first line.
//!
//! It is deliberately *not* installed from `install_globals` (the `bootstrap.js`
//! hand-off): that function runs before `realm.js`, and it deletes its `__`-prefixed
//! hand-off names on the way out — anything defined there has to be redefined as a
//! node global afterwards anyway. `install_early_globals` is both later and the
//! established place for globals that only need bindings already present.
//!
//! # Enumerable or not
//!
//! Bun itself defines `globalThis.Bun` with `enumerable: true`. This installs it
//! **non-enumerable**, which is the same call `rn-realm::set_global` already makes
//! for every Node global, for a measured reason: `vendor/libnode-js/test`'s
//! `common/index.js` walks `Object.keys(globalThis)` at exit and fails a test for
//! any name it does not recognise. One enumerable `Bun` cost that audit 388 files
//! in a previous form of this tree. `Object.getOwnPropertyNames(globalThis)` still
//! reports `Bun`, so nothing that looks for the global by name is affected;
//! `for…in` and `Object.keys` do not. `crates/rn-cli/tests/m0_foundation.rs` pins
//! the enumerable-global count, and this choice is what keeps that count at 9.
//!
//! # Startup cost
//!
//! Building the object eagerly creates one function template per function member.
//! That is measured against `master` in `docs/bun-compat-plan.md`'s terms and
//! recorded in the PR that landed this crate; [`Mode`] exists because the answer
//! may be "cheaper to build on first access", and the two paths are both real and
//! both tested rather than one being dead code.

use rn_bun_api::BunRegistry;
use rn_v8_sys::v8;

/// How `globalThis.Bun` is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Build the object during bootstrap and install it as a data property.
    ///
    /// Matches Bun's own descriptor shape most closely: a data property holding a
    /// fully built object.
    Eager,
    /// Install an accessor that builds the object on first read and caches it.
    ///
    /// `Object.getOwnPropertyDescriptor(globalThis, "Bun")` reports a getter
    /// rather than a value, which is the one observable difference from
    /// [`Mode::Eager`]. Nothing in `Bun`'s own surface can see it; a script that
    /// introspects the *global's* descriptor can. Every access after the first goes
    /// through the same cache, so the object identity and its members are
    /// identical.
    Lazy,
}

/// The mode this build installs.
///
/// `RUSTNODE_BUN_EAGER=1` overrides it, which is what the startup measurement
/// uses to compare the two on one binary instead of two builds. The override is
/// read once per install and only affects how the global is built, so it cannot
/// change what any member does.
pub const DEFAULT_MODE: Mode = Mode::Eager;

/// Builds and installs the `Bun` global on the current context.
///
/// Returns `Err` when a contribution crate contradicts its own declaration, names
/// a member another crate already claimed, or cannot be published. Every one of
/// those is a build-time mistake that would otherwise surface as `undefined` in
/// user code, so the caller reports it as a startup failure.
/// # Startup cost
///
/// Building the object eagerly creates one function template per function member.
/// Measured against `master` (e8a7c1b0) with `tools/bun-startup-measure.py`,
/// interleaved, median of 30, `-e ''`:
///
/// | build | install_bun phase | median delta vs master | paired MAD |
/// | --- | --- | --- | --- |
/// | one member (`Bun.nanoseconds`) | 0.04 ms | +0.07 to +0.55 ms | ~1.2 ms |
/// | 101 members (synthetic probe) | 0.24 ms | -0.19 to +0.24 ms | ~1.3 ms |
///
/// Both are inside the noise band, so the eager path is what ships and [`Mode`]
/// exists for the measurement rather than for a production need: a 100-member
/// surface costs about 0.2 ms of a ~25 ms start, which is 0.8% and below what this
/// harness can resolve. The lazy path was measured too and is not faster — the
/// accessor costs as much as building the object (0.03 ms versus 0.04 ms for one
/// member) because the object is built either way before `Bun.x` is read.
pub fn install(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    install_with(scope, mode_from_environment())
}

/// [`install`] with the mode chosen by the caller.
pub fn install_with(scope: &mut v8::PinScope<'_, '_>, mode: Mode) -> Result<(), String> {
    // The start clock is captured in both modes at the same point, so that
    // `Bun.nanoseconds` measures from bootstrap rather than from the first read of
    // the global. Without this a lazy install would report an origin later in the
    // process, and the two modes would disagree about a member neither of them
    // implements.
    rn_bun_api::record_process_start();

    match mode {
        Mode::Eager => install_eager(scope),
        Mode::Lazy => install_lazy(scope),
    }
}

fn mode_from_environment() -> Mode {
    match std::env::var("RUSTNODE_BUN_EAGER").as_deref() {
        Ok("0") => Mode::Lazy,
        _ => DEFAULT_MODE,
    }
}

/// Builds the registry and the object, then installs it as a data property.
fn install_eager(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    let registry = rn_bun_members::install_all()?;
    let bun = registry.build(scope)?;
    publish(scope, bun)
}

/// Installs an accessor whose first read builds the object.
///
/// The cache lives outside the object, in a thread-local, for the reason
/// `rn-builtins`' lazy members record: replacing the accessor from inside its own
/// getter re-enters it through `define_own_property` and never settles.
///
/// # Why `define_property` and not `set_accessor`
///
/// `Object::set_accessor` is `v8::Object::SetAccessor`, which on the **global
/// proxy** silently does nothing observable: it reports success and
/// `Object.getOwnPropertyDescriptor(globalThis, "Bun")` still reads a data
/// property. That was measured, not assumed — the eager install put a data
/// property there, so the two modes must agree on the member set and only differ
/// on the descriptor, and `set_accessor` produced a descriptor that said `data`.
/// `v8::Object::DefineProperty` with an explicit get/set pair does stick, which is
/// the same route `Object.defineProperty` takes from JavaScript.
fn install_lazy(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Bun").ok_or("cannot allocate the Bun key")?;
    // A getter with no `[[Construct]]` and length 0, built the way this tree builds
    // every method. It carries no name because it is not published as a member —
    // it is the accessor for the `Bun` global itself.
    let getter = rn_core::method_function(lazy_bun_getter)
        .build(scope)
        .ok_or("cannot build the Bun accessor")?;
    let mut descriptor =
        v8::PropertyDescriptor::new_from_get_set(getter.into(), v8::undefined(scope).into());
    // Non-enumerable for the reason in the module docs, configurable so a later
    // bootstrap step or a test can replace it.
    descriptor.set_enumerable(false);
    descriptor.set_configurable(true);
    global
        .define_property(scope, key.into(), &descriptor)
        .ok_or_else(|| "cannot define the Bun accessor".to_string())?;
    Ok(())
}

thread_local! {
    /// The built object, per isolate. A `v8::Global` belongs to one isolate, so a
    /// worker that installs its own `Bun` must not see the main thread's handle.
    static LAZY_BUN: std::cell::RefCell<Option<v8::Global<v8::Object>>> =
        const { std::cell::RefCell::new(None) };
}

fn lazy_bun_getter(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let existing =
        LAZY_BUN.with(|slot| slot.borrow().as_ref().map(|bun| v8::Local::new(scope, bun)));
    if let Some(bun) = existing {
        rv.set(bun.into());
        return;
    }
    // A failure here cannot throw from inside an accessor without leaving the
    // global permanently half-installed, so the reason is reported on stderr and
    // the read yields `undefined` — the same answer a missing member gives, but
    // with the reason printed rather than silently absent.
    let built = rn_bun_members::install_all().and_then(|registry| registry.build(scope));
    match built {
        Ok(bun) => {
            let global = v8::Global::new(scope, bun);
            LAZY_BUN.with(|slot| *slot.borrow_mut() = Some(global));
            rv.set(bun.into());
        }
        Err(message) => {
            rn_core::hook_slot::write_stderr(&format!("rustnode: Bun is unavailable: {message}\n"));
            rv.set(v8::undefined(scope).into());
        }
    }
}

/// Installs `bun` on the global object, non-enumerable and writable.
///
/// `define_own_property` rather than `set`: `set` creates an enumerable property,
/// and the enumerability is the whole point (see the module docs). Bun's own
/// descriptor is non-configurable, but this one is configurable so that a later
/// bootstrap step — or a test — can replace it; nothing in `lib/**` depends on the
/// global being frozen, and a non-configurable property here would make a second
/// install in the same context a hard failure.
fn publish(scope: &mut v8::PinScope<'_, '_>, bun: v8::Local<v8::Object>) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Bun").ok_or("cannot allocate the Bun key")?;
    global
        .define_own_property(
            scope,
            key.into(),
            bun.into(),
            v8::PropertyAttribute::DONT_ENUM,
        )
        .ok_or_else(|| "cannot define the Bun global".to_string())?;
    Ok(())
}

/// `Bun`'s own surface, read from the object that is really installed.
///
/// The structure test uses [`installed_members`] against a real [`install`] and
/// checks the answer against the registry, which is what makes those two functions
/// live rather than aspirational API. The gate does its reading through the built
/// binary instead (`tools/bun-surface-guard.py`), because that is the object users
/// get; this is the in-process half so a crate author can see the answer from
/// `cargo test` without building the CLI.
pub fn installed<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Bun")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Every own property name of the installed `Bun`, sorted.
///
/// This is the measurement the gate compares against Bun 1.4.4. It reads the
/// object that is really installed rather than any declaration, which is the
/// difference between measuring the surface and measuring a list.
pub fn installed_members(scope: &mut v8::PinScope<'_, '_>) -> Vec<String> {
    let Some(bun) = installed(scope) else {
        return Vec::new();
    };
    let args = v8::GetPropertyNamesArgs {
        mode: v8::KeyCollectionMode::OwnOnly,
        property_filter: v8::PropertyFilter::ALL_PROPERTIES,
        index_filter: v8::IndexFilter::SkipIndices,
        key_conversion: v8::KeyConversionMode::ConvertToString,
    };
    let Some(names) = bun.get_own_property_names(scope, args) else {
        return Vec::new();
    };
    let mut collected = Vec::with_capacity(names.length() as usize);
    for index in 0..names.length() {
        let Some(value) = names.get_index(scope, index) else {
            continue;
        };
        let Ok(name) = v8::Local::<v8::Name>::try_from(value) else {
            continue;
        };
        if !name.is_string() {
            continue;
        }
        collected.push(name.to_rust_string_lossy(scope));
    }
    collected.sort();
    collected
}

/// The registry this build assembles, for a caller that wants the declarations
/// without installing anything.
///
/// The gate reads this through `tools/rn-bun-check` rather than a Rust caller, so
/// this is the library form of the same question: what does this build claim,
/// before any isolate exists.
pub fn registry() -> Result<BunRegistry, String> {
    rn_bun_members::install_all()
}
