//! Aggregates the `Bun.*` contribution crates into one registry.
//!
//! `Bun` has no namespace key, so every contribution writes into one flat
//! property space. `rn-bun-api`'s [`BunRegistry`] is what makes that space safe:
//! it refuses duplicate names across crates and compares each module's
//! declaration against the object it really builds. This crate is only the
//! assembly — the list of contribution crates on disk.
//!
//! [`install_all`] is **generated** by `tools/regen-bun-contributions.sh` from the
//! crates present in `crates/`, so adding a contribution crate never edits this
//! file, `rn-bun`, or any other shared source. The generator's matcher is the one
//! `tools/regen-bindings.sh` uses, with the declaration changed to
//! `pub fn register(registry: &mut BunRegistry)` — see that script's comments for
//! why the match is on a declaration and not a substring, and
//! `tools/regen-bun-contributions.test.sh` for the cases it pins.
//!
//! # Why this is a separate crate from `rn-bun`
//!
//! `rn-bun` installs the global and owns the startup cost, so it must stay
//! independent of how many contribution crates exist. This crate is the one that
//! depends on all of them. Keeping the two apart is what stops a worker from
//! touching the installation code while adding a member.

mod install_all;

pub use install_all::install_all;
