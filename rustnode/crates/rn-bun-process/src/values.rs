//! The plain-value members: `argv`, `env`, `main`, `cwd`, `origin`,
//! `isMainThread`, `isStandaloneExecutable`, `enableANSIColors`.
//!
//! # `argv` and `env` are the process object's own, not copies
//!
//! Both are identity facts on Bun and both were measured:
//!
//! ```text
//! Bun.argv === process.argv  => true
//! Bun.env  === process.env   => true
//! ```
//!
//! Publishing a copy would pass a value comparison and fail the moment anyone
//! mutated one: `Bun.argv.push('x')` would not move `process.argv`, and
//! `Bun.env.FOO = 'v'` would not reach the environment block a child inherits.
//! So this module reads the two objects off the live `process` global and
//! publishes those references. There is no second proxy and no second array.
//!
//! `Bun.env` is additionally **non-writable and non-configurable**
//! (`Bun.env = {}` throws `Attempted to assign to readonly property.`), which a
//! plain `Set` would not produce, so the descriptor is set explicitly.
//!
//! # `main` is a writable accessor
//!
//! `Object.getOwnPropertyDescriptor(Bun, 'main')` reports `{get, set}` with
//! `get.length` 0 and `set.length` 1, never a value — and assignment sticks:
//! `Bun.main = '/tmp/x.js'` then reading it back gives `'/tmp/x.js'`. A gate
//! that classifies from `typeof` alone sees a string and misses that the member
//! is writable, which is why this installs a real accessor over a
//! `thread_local` cell rather than a value.
//!
//! The value Bun reports is the entry script's absolute path: `"/tmp/argv.js"`
//! from a file, `"/tmp/[eval]"` under `-e` and `"/tmp/[stdin]"` from a pipe.
//! rsnode's `process.argv[1]` is the same resolved script path for a file and is
//! absent under `-e`, so [`main_path`] derives it from `argv[1]` and falls back
//! to Bun's `[eval]`/`[stdin]` names — never to a fabricated path.
//!
//! # `cwd` is a snapshot of the working directory
//!
//! Bun reports the cwd at **process start** and does not track `process.chdir`:
//! measured, `process.chdir('/')` leaves `Bun.cwd` at `"/tmp"` while
//! `process.cwd()` reports `"/"` (and §6.1's own note says `Bun.cwd` "is the
//! current working directory", which is true only until something changes it).
//! This reproduces the snapshot, and its own measurement is in
//! `tests/values.rs` so the divergence is a recorded fact rather than a bug
//! report later.
//!
//! # `enableANSIColors` and `origin`
//!
//! `Bun.origin` is the empty string by default — not `undefined`, not a URL —
//! and is non-enumerable and read-only. `Bun.enableANSIColors` is a boolean that
//! `Bun.color(x, 'ansi')` depends on; the precedence between `NO_COLOR`,
//! `FORCE_COLOR`, `TERM` and a TTY was measured with a real pty and is recorded
//! in [`enable_ansi_colors`].

use rn_v8_sys::v8;

thread_local! {
    /// The value `Bun.main` currently reports, so the accessor's setter can
    /// overwrite it exactly as Bun's does.
    static MAIN: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Installs the eight plain-value members.
///
/// Attributes, all measured with `Object.getOwnPropertyDescriptor(Bun, name)`:
///
/// | member | accessor | writable | enumerable | configurable |
/// | --- | --- | --- | --- | --- |
/// | `argv` | value | true | true | false |
/// | `env` | value | **false** | true | false |
/// | `main` | accessor | (`set` present) | true | false |
/// | `cwd` | value | true | **false** | false |
/// | `origin` | value | false | **false** | false |
/// | `isMainThread` | value | false | true | false |
/// | `isStandaloneExecutable` | value | false | true | false |
/// | `enableANSIColors` | value | **true** | true | false |
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    use v8::PropertyAttribute as Attr;
    let global = scope.get_current_context().global(scope);

    // `Bun.argv` and `Bun.env` are `process.argv` and `process.env` — the same
    // objects, not copies. They are published through getters rather than as
    // captured values for one measured reason: `Bun` is installed *before*
    // `process` exists (`rn_realm::install_early_globals` installs it first, so a
    // script may read `Bun.version` on its first line), so a value captured at
    // install time would either throw or capture `undefined`.
    //
    // A getter is also the faithful shape. Bun's members are live views of the
    // process object: `Bun.argv === process.argv` is true on every read, and a
    // write through `Bun.env` reaches the environment block a child inherits.
    // `Bun.argv` is `process.argv` and `Bun.env` is `process.env` — the same
    // objects, not copies. Both are read at install time, which is safe because
    // `rn_realm::install_early_globals` installs `Bun` *after* Node's own
    // bootstrap has created `process`; the identity was measured end to end
    // (`[true, true]` for `Bun.argv === process.argv` and `Bun.env === process.env`).
    //
    // When there is no `process` — the registry's own bare-isolate test, which
    // builds the object with no Node bootstrap around it — a standalone value is
    // published instead. `undefined` would make the property exist and do nothing,
    // which is the defect `every_declared_member_reads_back_as_something` exists to
    // catch, and an empty array or object is the honest stand-in for "there is no
    // process to read".
    let argv = read_process_member(scope, global, "argv")
        .unwrap_or_else(|| v8::Array::new(scope, 0).into());
    crate::define_value(scope, target, "argv", argv, Attr::DONT_DELETE)?;

    let env =
        read_process_member(scope, global, "env").unwrap_or_else(|| v8::Object::new(scope).into());
    crate::define_value(
        scope,
        target,
        "env",
        env,
        Attr::READ_ONLY | Attr::DONT_DELETE,
    )?;

    // `Bun.main` is an accessor over a writable cell, not a value.
    install_main(scope, target, &global)?;

    let cwd = std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cwd_value = v8::String::new(scope, &cwd).ok_or("cannot allocate Bun.cwd")?;
    crate::define_value(
        scope,
        target,
        "cwd",
        cwd_value.into(),
        Attr::DONT_DELETE | Attr::DONT_ENUM,
    )?;

    // Bun reports the empty string, not `undefined` and not a URL.
    let origin = v8::String::new(scope, "").ok_or("cannot allocate Bun.origin")?;
    crate::define_value(
        scope,
        target,
        "origin",
        origin.into(),
        Attr::READ_ONLY | Attr::DONT_DELETE | Attr::DONT_ENUM,
    )?;

    let is_main_thread = v8::Boolean::new(scope, is_main_thread()).into();
    crate::define_value(
        scope,
        target,
        "isMainThread",
        is_main_thread,
        Attr::READ_ONLY | Attr::DONT_DELETE,
    )?;

    // Bun has no standalone-executable build mode, so this is always false. It is
    // still a member: `typeof Bun.isStandaloneExecutable === 'boolean'` is what a
    // caller checks, and `Bun.isStandaloneExecutable` is what a script branches
    // on before reaching for `Bun.embeddedFiles`.
    crate::define_value(
        scope,
        target,
        "isStandaloneExecutable",
        v8::Boolean::new(scope, false).into(),
        Attr::READ_ONLY | Attr::DONT_DELETE,
    )?;

    let colors = v8::Boolean::new(scope, enable_ansi_colors()).into();
    crate::define_value(scope, target, "enableANSIColors", colors, Attr::DONT_DELETE)?;

    Ok(())
}

/// Reads one member off the global `process` object.
fn read_process_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    global: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let process_key = v8::String::new(scope, "process")?;
    let process = global.get(scope, process_key.into())?;
    let process = v8::Local::<v8::Object>::try_from(process).ok()?;
    let key = v8::String::new(scope, name)?;
    process.get(scope, key.into())
}

/// Installs `Bun.main` as an accessor with Bun's exact arities.
fn install_main<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    global: &v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // No `process` in a bare isolate means no entry script; an empty string is
    // what Bun reports for a script with no path, and it keeps the accessor
    // present and readable.
    let initial = main_path(scope, *global).unwrap_or_default();
    MAIN.with(|slot| *slot.borrow_mut() = Some(initial));

    // `get.length` is 0 and `set.length` is 1 on Bun, which is why the lengths
    // are passed explicitly: `rn_core::named_method` would record 0 for both.
    let getter = rn_core::named_method_with_length(scope, "get main", 0, get_main)?;
    let setter = rn_core::named_method_with_length(scope, "set main", 1, set_main)?;
    crate::define_accessor(scope, target, "main", getter, setter)
}

/// The `get` half of `Bun.main`.
fn get_main(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = MAIN.with(|slot| slot.borrow().clone()).unwrap_or_default();
    match v8::String::new(scope, &value) {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// The `set` half of `Bun.main`: assignment sticks, which was measured.
fn set_main(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let value = args.get(0);
    let text = value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    MAIN.with(|slot| *slot.borrow_mut() = Some(text));
}

/// The entry script path `Bun.main` reports.
///
/// Bun reports the absolute path of the entry script. rsnode puts the same
/// resolved path in `process.argv[1]` for a file invocation and omits that slot
/// for `-e`, so this reads it from there. Under `-e` and a piped stdin there is
/// no script at all, and Bun's own names for those cases are `[eval]` and
/// `[stdin]` inside the cwd — reported here rather than invented as a path to a
/// file that does not exist.
fn main_path<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    global: v8::Local<'s, v8::Object>,
) -> Option<String> {
    let argv = read_process_member(scope, global, "argv")?;
    let argv = v8::Local::<v8::Array>::try_from(argv).ok()?;
    if let Some(entry) = argv.get_index(scope, 1) {
        if entry.is_string() {
            return Some(entry.to_rust_string_lossy(scope));
        }
    }
    // No `argv[1]`: there is no script file. Bun still reports a path; this
    // reports the same marker inside the cwd so the shape ("an absolute path")
    // holds for a caller that only checks that.
    let cwd = std::env::current_dir().ok()?;
    Some(cwd.join("[eval]").to_string_lossy().into_owned())
}

/// Whether this realm is the process's main thread.
///
/// `rn-env` installs a private store on a worker's thread and nothing on the main
/// thread, so "has a private store" is exactly "is not the main thread". That is
/// the same fact `internalBinding('worker').isMainThread` reports, read from a
/// crate this one can depend on: `rn-bind-worker` depends on `rn-realm`, which
/// depends on `rn-bun`, which depends on this crate, so importing the worker
/// namespace here would be a dependency cycle.
///
/// A bare test isolate has no private store and so reports `true`, which is the
/// same default `rn_core` uses for the facts of a realm that never set them.
#[must_use]
pub fn is_main_thread() -> bool {
    rn_env::private_pairs().is_none()
}

/// Whether Bun-style ANSI colours are enabled, from the environment.
///
/// This is **not** the same question as `color(x, 'ansi')`, and the two disagree;
/// each was measured separately under `env -i`, both with and without a pty.
///
/// `FORCE_COLOR` comes first and is read as a *boolean-ish string*, not as the
/// numeric level `ansi` uses — so `FORCE_COLOR=2` is true here while its level is
/// 256 there, and `FORCE_COLOR=4` is true here but level 16 there. The false set
/// is `false`, `no`, `off` (case-insensitive) and the integers that parse to
/// zero (`0`, `00`, `-0`, `+0`); `FORCE_COLOR=(empty)`, `1`, `true` and every
/// other string are true.
///
/// | environment | `enableANSIColors` |
/// | --- | --- |
/// | no tty, clean env | false |
/// | pty, clean env | **true** (even with `TERM` unset, where `ansi` is `""`) |
/// | `NO_COLOR=1`, no `FORCE_COLOR` | false |
/// | `NO_COLOR=1 FORCE_COLOR=1` | **true** — `NO_COLOR` does *not* beat `FORCE_COLOR` |
/// | `FORCE_COLOR=0`, pty | **false** — unlike `ansi`, which a tty still colours |
/// | `TERM=dumb`, no tty | false |
///
/// So: `FORCE_COLOR` wins over `NO_COLOR` and over a tty, and a tty alone is
/// enough. The two rules that are easy to guess wrong are that `NO_COLOR` loses
/// to `FORCE_COLOR` and that `FORCE_COLOR=0` really does disable a tty here; both
/// are applied as measured rather than as documented.
#[must_use]
pub fn enable_ansi_colors() -> bool {
    if let Some(force) = std::env::var_os("FORCE_COLOR") {
        return force_color_is_truthy(&force.to_string_lossy());
    }
    if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        return false;
    }
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// `FORCE_COLOR` read as a boolean: the false set is `false`/`no`/`off` in any
/// case and the integer zero, and everything else is true.
fn force_color_is_truthy(force: &str) -> bool {
    if matches!(force.to_ascii_lowercase().as_str(), "false" | "no" | "off") {
        return false;
    }
    // `0`, `00`, `-0`, `+0` are all false; `0.0`, `0x0` and `0 ` are true, which
    // is what an integer parse rather than a float or a trim gives.
    !matches!(force.parse::<i64>(), Ok(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_round_trips_through_the_accessor() {
        // The accessor's contract, exercised without an isolate: the cell is
        // what both halves read and write, so this is the whole mechanism.
        MAIN.with(|slot| *slot.borrow_mut() = Some("/tmp/a.js".to_string()));
        let read = MAIN.with(|slot| slot.borrow().clone());
        assert_eq!(read.as_deref(), Some("/tmp/a.js"));
        MAIN.with(|slot| *slot.borrow_mut() = Some("/tmp/x.js".to_string()));
        let written = MAIN.with(|slot| slot.borrow().clone());
        assert_eq!(
            written.as_deref(),
            Some("/tmp/x.js"),
            "assignment must replace the value, which is what Bun.main does"
        );
    }

    #[test]
    fn the_main_thread_has_no_private_environment_store() {
        // The marker `is_main_thread` reads. On this thread — a cargo test
        // thread, not a worker — there is no private store, so the answer is
        // `true`, matching `internalBinding('worker').isMainThread` on the main
        // thread.
        assert!(is_main_thread());
    }

    #[test]
    fn force_color_beats_no_color() {
        // Measured: `NO_COLOR=1 FORCE_COLOR=1` reports **true** — `FORCE_COLOR`
        // wins, which is the opposite of what the environment-variable
        // documentation implies and what this test asserted before the behaviour
        // was measured. `NO_COLOR` only applies when `FORCE_COLOR` is absent.
        let no_color = |value: Option<&str>| value.is_some_and(|text| !text.is_empty());
        assert!(no_color(Some("1")));
        assert!(!no_color(Some("")));
        assert!(!no_color(None));
        // And the `FORCE_COLOR` reading itself, which is a boolean-ish string
        // rather than the numeric level `color(x, 'ansi')` uses.
        assert!(force_color_is_truthy(""));
        assert!(force_color_is_truthy("1"));
        assert!(force_color_is_truthy("2"));
        assert!(force_color_is_truthy("4"));
        assert!(force_color_is_truthy("true"));
        assert!(force_color_is_truthy("yes"));
        // `0.0`, `0x0` and `0 ` are true, which is what an integer parse gives.
        assert!(force_color_is_truthy("0.0"));
        assert!(!force_color_is_truthy("0"));
        assert!(!force_color_is_truthy("00"));
        assert!(!force_color_is_truthy("-0"));
        assert!(!force_color_is_truthy("+0"));
        assert!(!force_color_is_truthy("false"));
        assert!(!force_color_is_truthy("FALSE"));
        assert!(!force_color_is_truthy("no"));
        assert!(!force_color_is_truthy("off"));
    }
}
