//! The `Bun` global's process and system members, for rsnode.
//!
//! `rn-bun` owns the `Bun` object itself; this crate contributes seventeen members
//! to it through [`rn_bun_api::BunModule`], so it never creates or publishes the
//! global. All seventeen are implemented; nothing here is deferred.
//!
//! | member | where |
//! | --- | --- |
//! | `spawn`, `spawnSync` | [`spawn`] |
//! | `udpSocket` | [`udp`] |
//! | `argv`, `env`, `main`, `cwd`, `origin`, `isMainThread`, `isStandaloneExecutable`, `enableANSIColors` | [`values`] |
//! | `color` | [`color`] |
//! | `gc`, `generateHeapSnapshot` | [`gc`] |
//! | `version`, `revision`, `version_with_sha` | [`version`] |
//!
//! # The rule this crate is built on
//!
//! Every value and every failure mode below is a recorded observation of Bun
//! 1.4.4, not a guess. `docs/bun-tier1-spec.md` §6 holds the measurements and
//! this crate's `internal/` report holds the recording scripts; where this crate
//! diverges it says so at the member and a test pins the divergence.
//!
//! # Identity, not equality
//!
//! Two of these members are object *identities*, and a value comparison would pass
//! against the wrong implementation:
//!
//! * `Bun.argv === process.argv` is `true` on Bun. Publishing a copy looks correct
//!   until user code pushes onto one and reads the other, so this crate publishes
//!   the process object's own array.
//! * `Bun.env === process.env` is `true`, and `Bun.env` is non-writable
//!   (`Bun.env = {}` throws `Attempted to assign to readonly property.`) while
//!   `Bun.env.FOO = 'x'` reaches the environment block a child inherits. Both hold
//!   because the same object is published with the same descriptor.
//!
//! The same trap appears in `Bun.spawn`: `Object.keys(proc)` is `[]` because every
//! member is an enumerable getter on a custom prototype, so a test written against
//! `Object.keys` would pass on an empty object. [`spawn`] builds a real prototype
//! and its tests read the prototype chain.
//!
//! # Property attributes are part of the surface
//!
//! Bun sets these individually and they disagree with each other, so each one is
//! reproduced from measurement rather than defaulted. `version_with_sha`, `cwd`
//! and `origin` are non-enumerable; `main` is a getter/setter accessor whose
//! `get.length` is 0 and `set.length` is 1 and which accepts assignment;
//! everything is non-configurable.
//!
//! # `Bun.version` is a compatibility marker
//!
//! `Bun.version` reports `"1.4.4-rsnode"`: the 1.4.4 surface as a semver
//! prerelease, so `>= "1.4.4"` is `false` and `>= "1.0"` is `true` under a real
//! semver comparison without ever claiming to be a Bun release. `Bun.version_with_sha`
//! derives its version half from the same constant, so the two agree by
//! construction. See [`version`] for the candidates and why this one was chosen.

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

pub mod color;
pub mod gc;
pub mod spawn;
pub mod udp;
pub mod values;
pub mod version;

/// Every member this crate installs.
///
/// The registry compares this against the object [`Process::install`] builds, in
/// both directions, before `Bun` is published: a name here that `install` never
/// sets is a startup failure, and so is a name `install` sets that is not here.
/// `crates/rn-bun-process/tests/members.rs` pins the list against Bun's recorded
/// surface as well.
pub const MEMBERS: &[&str] = &[
    "argv",
    "color",
    "cwd",
    "enableANSIColors",
    "env",
    "gc",
    "generateHeapSnapshot",
    "isMainThread",
    "isStandaloneExecutable",
    "main",
    "origin",
    "revision",
    "spawn",
    "spawnSync",
    "udpSocket",
    "version",
    "version_with_sha",
];

/// Members this crate needs but does not install, each with its reason.
///
/// Empty: every member in [`MEMBERS`] is installed. The list stays because
/// [`rn_bun_api::BunModule`] requires an answer to the question, and an empty one
/// says "none" out loud where a missing method would leave a reader guessing.
pub const DEFERRED: &[(&str, &str)] = &[];

/// The `Bun` contribution for process and system members.
pub struct Process;

impl BunModule for Process {
    fn contributor(&self) -> &'static str {
        "rn-bun-process"
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
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String> {
        values::install(scope, target)?;
        color::install(scope, target)?;
        gc::install(scope, target)?;
        spawn::install(scope, target)?;
        udp::install(scope, target)?;
        version::install(scope, target)?;
        Ok(())
    }
}

/// Registers this crate with the Bun contribution registry.
///
/// `tools/regen-bun-contributions.sh` discovers this declaration and calls it from
/// the generated aggregator, so a new contribution crate never edits a shared
/// file. The signature is what the matcher looks for: `registry` as the only
/// parameter, `&mut BunRegistry`.
pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Process)
}

/// Defines `name` on `target` as a value with Bun's attribute set.
///
/// `attributes` is the complement of what Bun reports: passing `READ_ONLY` makes
/// `writable` false, and `DONT_ENUM`/`DONT_DELETE` turn `enumerable`/
/// `configurable` off. Bun reports `configurable: false` for every member in this
/// group, so every call site passes `DONT_DELETE`.
pub(crate) fn define_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
    attributes: v8::PropertyAttribute,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    target
        .define_own_property(scope, key.into(), value, attributes)
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

/// Defines `name` on `target` as a getter/setter pair.
///
/// Bun's `Bun.main` is a real accessor (`Object.getOwnPropertyDescriptor` reports
/// `get` and `set`, never a value), and assignment through it sticks.
/// `get.length` and `set.length` are 0 and 1 on Bun, which
/// [`rn_core::named_method`] cannot produce — it always records length 0 — so the
/// two functions are built with the explicit lengths here.
pub(crate) fn define_accessor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    getter: v8::Local<'s, v8::Function>,
    setter: v8::Local<'s, v8::Function>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    let mut descriptor = v8::PropertyDescriptor::new_from_get_set(getter.into(), setter.into());
    // Bun reports `{get, set, enumerable: true, configurable: false}`.
    descriptor.set_enumerable(true);
    descriptor.set_configurable(false);
    target
        .define_property(scope, key.into(), &descriptor)
        .ok_or_else(|| format!("cannot define the {name} accessor"))?;
    Ok(())
}

/// Publishes `callback` as a method named `name` with an explicit `length`.
///
/// `Bun.color.length` is 2 and `Bun.spawn.length` is 1: Bun records the real
/// arity, unlike Node's `SetMethod` which records 0. `rn_core::set_method` is
/// therefore the wrong primitive for these, and this is the one this crate needs.
/// `ConstructorBehavior::Throw` is still what `named_method_with_length` builds,
/// so `new Bun.color()` is a `TypeError` as it is on Bun.
pub(crate) fn define_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = rn_core::named_method_with_length(scope, name, length, callback)?;
    // Bun's methods are `{writable: true, enumerable: true, configurable: true}`,
    // the opposite of its value members, so the attribute word is `NONE`.
    define_value(
        scope,
        target,
        name,
        function.into(),
        v8::PropertyAttribute::NONE,
    )
}

/// The members this crate expects Bun's recorded surface to contain.
///
/// Read by `crates/rn-bun-process/tests/members.rs`, which checks every name
/// against `tools/bun-surface.json` and against `MEMBERS ∪ DEFERRED`. Kept here so
/// the expectation and the declaration cannot drift.
#[cfg(test)]
pub(crate) fn expected_surface() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = MEMBERS.to_vec();
    names.extend(DEFERRED.iter().map(|(member, _)| *member));
    names.sort_unstable();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_and_the_deferral_are_disjoint() {
        for member in MEMBERS {
            assert!(
                !DEFERRED.iter().any(|(name, _)| name == member),
                "{member} is both installed and deferred, which the registry refuses"
            );
        }
    }

    #[test]
    fn every_deferral_states_a_reason() {
        for (member, reason) in DEFERRED {
            assert!(!reason.trim().is_empty(), "{member} has no reason");
        }
    }

    #[test]
    fn the_declaration_is_sorted_and_unique() {
        // Sorted so the list reads predictably and a duplicate is visible; the
        // registry would refuse a duplicate name, but only at startup.
        let mut sorted = MEMBERS.to_vec();
        sorted.sort_unstable();
        assert_eq!(MEMBERS, sorted.as_slice());
        let mut unique = sorted.clone();
        unique.dedup();
        assert_eq!(unique.len(), MEMBERS.len(), "a name is declared twice");
    }

    #[test]
    fn every_member_is_one_buns_surface_records() {
        // `tools/bun-surface.json` is the recorded 117-member surface of Bun
        // 1.4.4. A name that is not in it is fabricated, and the gate refuses it;
        // checking here means the failure names the member rather than a JSON
        // path.
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/bun-surface.json"),
        )
        .expect("the recorded Bun surface is readable");
        let parsed: serde_json::Value =
            serde_json::from_str(&raw).expect("the recorded surface is JSON");
        let members = parsed
            .get("members")
            .and_then(|value| value.as_object())
            .expect("the surface has a members object");
        for name in expected_surface() {
            assert!(
                members.contains_key(name),
                "Bun.{name} is not in the recorded 1.4.4 surface"
            );
        }
    }

    #[test]
    fn registering_contributes_every_declared_member_and_no_deferral() {
        let mut registry = rn_bun_api::BunRegistry::new();
        register(&mut registry).expect("registration succeeds");
        let declared: Vec<&str> = registry
            .declarations()
            .iter()
            .map(|entry| entry.member.as_str())
            .collect();
        let mut expected = MEMBERS.to_vec();
        expected.sort_unstable();
        assert_eq!(declared, expected);
        // `version` used to be the one deferral; it is installed now, and a
        // reintroduced deferral here would be a member the object no longer has.
        assert!(
            registry.deferrals().is_empty(),
            "rn-bun-process defers nothing: {:?}",
            registry.deferrals()
        );
    }
}
