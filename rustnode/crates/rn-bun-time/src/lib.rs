//! `Bun.nanoseconds` and the members that report process-relative time.
//!
//! This crate exists for two reasons, and the second is the one that matters.
//!
//! **`Bun.nanoseconds` is a Tier-1 member.** It reports nanoseconds since the
//! process started, as a JavaScript `Number` — `typeof` `"number"`,
//! `Number.isInteger` `true` — measured against Bun 1.4.4: `1_004_000_000`-ish
//! after a one-second `await Bun.sleep(1000)`, `~3_400_000` at the top of a fresh
//! `-e` script. It takes no arguments (extra ones are ignored), is not a
//! constructor (`new Bun.nanoseconds()` is a `TypeError` in Bun, so it must be here
//! too), and reports `name` `"nanoseconds"` with `length` `0`.
//!
//! **It is the reference contribution.** The shared foundation is only worth
//! anything if adding a member group needs no edit to `rn-bun`, `rn-bun-members` or
//! any other shared file, and the only way to know that is to have one group that
//! was added that way and is exercised end to end. This crate is copied by the six
//! Tier-1 workers; the recipe is in `docs/contributing-bun-members.md` and the
//! shape below is deliberately the smallest complete example of it.
//!
//! # Adding a member to this crate
//!
//! 1. add the name to [`MEMBERS`];
//! 2. set it in [`Time::install`] through `rn_core::set_method` (see the note
//!    there about why a member must never be published with a bare
//!    `FunctionTemplate::builder`);
//! 3. add the differential case to `tests/differential.rs` if the member has
//!    behaviour worth comparing.
//!
//! Nothing else. `Bun.nanoseconds` is registered by the generated aggregator the
//! moment this crate exists, which is the property the foundation has to have.

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

/// Members this crate installs.
///
/// Every name here is checked against the object [`Time::install`] really builds,
/// in both directions, before `Bun` is published. A name added here and not
/// installed is a startup failure rather than an `undefined` member, which is the
/// defect this whole registry exists to prevent.
pub const MEMBERS: &[&str] = &["nanoseconds"];

/// Members this crate needs but does not install yet.
///
/// `Bun.sleep` and `Bun.sleepSync` belong to the text/misc worker, not here; they
/// are not deferred from this crate because a deferral is a statement this crate
/// *owes* the member, and it does not.
pub const DEFERRED: &[(&str, &str)] = &[];

pub struct Time;

impl BunModule for Time {
    fn contributor(&self) -> &'static str {
        "rn-bun-time"
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
        // `SetMethod` in Bun terms: named after the property, length 0, no
        // `[[Construct]]`. Bun's own `Bun.nanoseconds.name` is `"nanoseconds"` and
        // its `length` is `0`, and `new Bun.nanoseconds()` is a `TypeError`, so
        // `rn_core::set_method` is exactly the primitive this needs. A bare
        // `FunctionTemplate::builder` would default to `ConstructorBehavior::Allow`
        // and let `new` succeed here while failing on Bun.
        rn_core::set_method(scope, target, "nanoseconds", nanoseconds)?;
        Ok(())
    }
}

/// `Bun.nanoseconds()`: nanoseconds since the process started.
///
/// The origin is recorded once by `rn-bun`'s install, so two reads from one
/// process cannot disagree about when it started. The value is a `Number`: Bun
/// reports a safe integer, and this returns a `u64` narrowed to `f64`, which is
/// exact below 2^53 ns — about 104 days of uptime, well past any real process.
fn nanoseconds(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let value = rn_bun_api::nanoseconds_since_start() as f64;
    rv.set(v8::Number::new(scope, value).into());
}

/// Registers this crate with the Bun contribution registry.
///
/// `tools/regen-bun-contributions.sh` discovers this declaration and calls it from
/// the generated aggregator, so a new contribution crate never edits a shared
/// file. The signature is what the matcher looks for: `registry` as the only
/// parameter, `&mut BunRegistry`.
pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_names_the_member_bun_has() {
        assert_eq!(MEMBERS, ["nanoseconds"]);
        assert!(DEFERRED.is_empty(), "nothing here is deferred");
    }

    #[test]
    fn registering_contributes_the_declaration() {
        let mut registry = rn_bun_api::BunRegistry::new();
        register(&mut registry).expect("registration succeeds");
        assert_eq!(registry.declarations().len(), 1);
        assert_eq!(registry.declarations()[0].member, "nanoseconds");
        assert_eq!(registry.declarations()[0].contributor, "rn-bun-time");
    }
}
