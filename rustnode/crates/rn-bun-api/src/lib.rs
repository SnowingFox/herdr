//! The contract a `Bun.*` contribution crate implements.
//!
//! `Bun` is a **global**, not an `internalBinding` namespace, so it cannot use
//! [`rn_core::BindingModule`]: that trait builds a fresh object per namespace and
//! the runtime publishes it under `internalBinding(name)`. `Bun` is one object
//! that many crates contribute to, and the runtime installs it on `globalThis`.
//!
//! # Why a second registry at all
//!
//! The `internalBinding` registry is keyed by namespace, so two crates can only
//! collide by choosing the same namespace name — a mistake that is loud, because
//! the second registration wins and the first crate's members disappear. `Bun`
//! has no such key: every member lives in one flat property space, so two
//! workers in parallel can each add `Bun.hash` and the build succeeds with one
//! silently overwriting the other.
//!
//! So the flat space is mediated here. [`BunModule`] declares the member names it
//! installs, [`BunRegistry`] installs each module into a **staging object** and
//! then compares that object's own keys against the declaration. Three defects
//! become startup failures instead of silent `undefined`s:
//!
//! * a member declared in [`BunModule::members`] and never set — the case
//!   `namespace_structure` catches for `internalBinding`;
//! * a member set and never declared — invisible to every contract check, and
//!   exactly what a worker copying an install line would produce;
//! * one name contributed by two crates — impossible to see in review when the
//!   two crates are written in different branches.
//!
//! A deferred member is the fourth case: it is declared, not installed, and
//! carries a written reason, so `rn-compat`-style accounting can report a
//! partition rather than an absence. A name that is deferred **and** installed is
//! a contradiction and fails, because that pair is how `sqlite.backup` stayed
//! green while `node:sqlite.backup` was `undefined`.
//!
//! # Publication
//!
//! An installed member is not necessarily a function — `Bun.version` is a string,
//! `Bun.env` an object — so [`BunRegistry`] cannot decide how a member is
//! published. That is the module's call, through [`rn_core::set_method`],
//! [`rn_core::set_class`] or a plain `set`. What the registry does own is that
//! whatever the module publishes is *declared*, which is the property the gate
//! needs.

pub mod clock;

pub use clock::{milliseconds_since_start, nanoseconds_since_start, record_process_start};

use rn_v8_sys::v8;

/// One crate's contribution to the `Bun` global.
///
/// A contribution crate implements this for a zero-sized type and exports
///
/// ```ignore
/// pub fn register(registry: &mut rn_bun_api::BunRegistry) {
///     registry.register_module(Encoding);
/// }
/// ```
///
/// `tools/regen-bun-contributions.sh` discovers that declaration and generates
/// the aggregator, so a new contribution crate never edits `rn-bun` or any other
/// shared file. See the crate's module docs for the three-step recipe.
pub trait BunModule {
    /// The crate this module belongs to, for diagnostics.
    ///
    /// Used in every mismatch message, because "a member is missing" is not
    /// actionable on a surface six workers are editing in parallel. This is the
    /// cargo package name, e.g. `"rn-bun-encoding"`.
    fn contributor(&self) -> &'static str;

    /// The member names this module installs, exactly as they appear on `Bun`.
    ///
    /// This is a **declaration**, not a reading. The registry compares it against
    /// the staging object in both directions, so it has to be complete and
    /// exact: a name here that `install` does not set is a startup failure, and so
    /// is a name `install` sets that is not here.
    fn members(&self) -> &'static [&'static str];

    /// Members this module needs but does not install yet, each with its reason.
    ///
    /// Defaults to none. A deferred member must not appear in [`Self::members`],
    /// must not be installed, and must carry a non-empty reason; all three are
    /// checked, because a deferral that overlaps its own member list is the
    /// arithmetic that made `rn-compat` report `sqlite 5 0 0 ok` with `backup`
    /// undefined.
    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Installs this module's members into `target`.
    ///
    /// `target` is a fresh object the registry owns, not the global. The module
    /// must set exactly [`Self::members`] on it and nothing else. It must not
    /// throw a JavaScript exception; return `Err` and let the runtime surface it
    /// as a startup failure.
    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String>;
}

/// A member name and the crate that declared it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    /// Property name on `Bun`, e.g. `"nanoseconds"`.
    pub member: String,
    /// `BunModule::contributor` of the crate that declared it.
    pub contributor: String,
}

/// A deferred member: a name, the crate that declared the deferral, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferral {
    pub member: String,
    pub contributor: String,
    pub reason: String,
}

/// Every module contributing to `Bun`, keyed so that collisions are visible.
///
/// The registry owns no isolate state: it is assembled once from
/// `rn_bun_members::install_all` at bootstrap (and again per worker isolate, the
/// way `BindingRegistry` is), and [`Self::declarations`] answers the gate's
/// question without a V8 scope.
#[derive(Default)]
pub struct BunRegistry {
    modules: Vec<Box<dyn BunModule>>,
    declarations: Vec<Declaration>,
    deferrals: Vec<Deferral>,
}

impl BunRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one contribution crate.
    ///
    /// Duplicate names are rejected here rather than at install time so that the
    /// error arrives while `install_all` runs, before any isolate exists, and so
    /// `rn-compat` reports it without booting a runtime.
    pub fn register_module<M: BunModule + 'static>(&mut self, module: M) -> Result<(), String> {
        let contributor = module.contributor();
        for member in module.members() {
            self.claim(contributor, member)?;
        }
        for (member, reason) in module.deferred() {
            if reason.trim().is_empty() {
                return Err(format!(
                    "{contributor} defers Bun.{member} with no reason; a deferral must name why"
                ));
            }
            if module.members().contains(member) {
                return Err(format!(
                    "{contributor} both installs and defers Bun.{member}; those are contradictory \
                     declarations, and the contract arithmetic cancels them out"
                ));
            }
            if self
                .declarations
                .iter()
                .any(|entry| entry.member == *member)
            {
                return Err(format!(
                    "{contributor} defers Bun.{member}, which another crate installs"
                ));
            }
            self.deferrals.push(Deferral {
                member: (*member).to_string(),
                contributor: contributor.to_string(),
                reason: (*reason).to_string(),
            });
        }
        self.modules.push(Box::new(module));
        Ok(())
    }

    fn claim(&mut self, contributor: &str, member: &str) -> Result<(), String> {
        if member.is_empty() {
            return Err(format!("{contributor} declares an empty Bun member name"));
        }
        if let Some(existing) = self
            .declarations
            .iter()
            .find(|declaration| declaration.member == member)
        {
            return Err(format!(
                "Bun.{member} is declared by both {} and {contributor}; one of them would \
                 overwrite the other with nothing reporting it",
                existing.contributor
            ));
        }
        if let Some(existing) = self
            .deferrals
            .iter()
            .find(|deferral| deferral.member == member)
        {
            return Err(format!(
                "Bun.{member} is deferred by {} and installed by {contributor}",
                existing.contributor
            ));
        }
        self.declarations.push(Declaration {
            member: member.to_string(),
            contributor: contributor.to_string(),
        });
        Ok(())
    }

    /// Every installed-by-declaration member, sorted by name.
    pub fn declarations(&self) -> &[Declaration] {
        &self.declarations
    }

    /// Every deferred member, sorted by name.
    pub fn deferrals(&self) -> &[Deferral] {
        &self.deferrals
    }

    /// Builds the `Bun` object and proves it matches the declarations.
    ///
    /// Each module installs into its own staging object, which is then compared
    /// against its declaration before any of its members are copied to `bun`. A
    /// module that declares a member it does not install, or installs one it does
    /// not declare, fails here with both names, and the partially built object is
    /// never returned — a half-populated `Bun` is worse than none, because a
    /// missing member reads `undefined` and the caller's failure names something
    /// else entirely.
    pub fn build<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let bun = v8::Object::new(scope);
        for module in &self.modules {
            let contributor = module.contributor();
            // A fresh object per module: two modules copying into one staging
            // object would let the second hide the first's undeclared member.
            let staging = v8::Object::new(scope);
            module.install(scope, staging)?;
            let installed = own_names(scope, staging);
            let declared: Vec<&str> = module.members().to_vec();
            let missing: Vec<&str> = declared
                .iter()
                .copied()
                .filter(|member| !installed.iter().any(|name| name == member))
                .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "{contributor} declares {} Bun member(s) it never installs: {}",
                    missing.len(),
                    missing.join(", ")
                ));
            }
            let undeclared: Vec<&str> = installed
                .iter()
                .filter(|name| !declared.iter().any(|member| member == *name))
                .map(String::as_str)
                .collect();
            if !undeclared.is_empty() {
                return Err(format!(
                    "{contributor} installs {} undeclared Bun member(s): {}; add them to \
                     members() so the contract and the gate can see them",
                    undeclared.len(),
                    undeclared.join(", ")
                ));
            }
            for name in installed {
                let Some(key) = v8::String::new(scope, &name) else {
                    return Err(format!(
                        "{contributor} cannot allocate the key for Bun.{name}"
                    ));
                };
                let Some(value) = staging.get(scope, key.into()) else {
                    return Err(format!("{contributor} cannot read back Bun.{name}"));
                };
                // `create_data_property` rather than `set`: the target is a plain
                // fresh object, and this keeps a future `__proto__` member from
                // walking into the prototype chain.
                if bun.create_data_property(scope, key.into(), value) != Some(true) {
                    return Err(format!("{contributor} cannot publish Bun.{name}"));
                }
            }
        }
        Ok(bun)
    }
}

/// Every own string-keyed property name of `object`.
///
/// `get_own_property_names` with `ALL_PROPERTIES` includes non-enumerable keys —
/// `Bun.cwd` and `Bun.origin` are non-enumerable in Bun itself, and a member this
/// runtime installed with `DONT_ENUM` would otherwise look absent to the very
/// check that exists to notice absences. Symbols are dropped because
/// `Object.getOwnPropertyNames` does not see them either, which is the surface the
/// gate compares.
fn own_names(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) -> Vec<String> {
    let args = v8::GetPropertyNamesArgs {
        mode: v8::KeyCollectionMode::OwnOnly,
        property_filter: v8::PropertyFilter::ALL_PROPERTIES,
        index_filter: v8::IndexFilter::SkipIndices,
        key_conversion: v8::KeyConversionMode::ConvertToString,
    };
    let Some(names) = object.get_own_property_names(scope, args) else {
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Contribution {
        contributor: &'static str,
        members: &'static [&'static str],
        deferred: &'static [(&'static str, &'static str)],
    }

    impl BunModule for Contribution {
        fn contributor(&self) -> &'static str {
            self.contributor
        }

        fn members(&self) -> &'static [&'static str] {
            self.members
        }

        fn deferred(&self) -> &'static [(&'static str, &'static str)] {
            self.deferred
        }

        fn install<'s>(
            &self,
            _scope: &mut v8::PinScope<'s, '_>,
            _target: v8::Local<'s, v8::Object>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn contribution(
        contributor: &'static str,
        members: &'static [&'static str],
        deferred: &'static [(&'static str, &'static str)],
    ) -> Contribution {
        Contribution {
            contributor,
            members,
            deferred,
        }
    }

    #[test]
    fn two_crates_cannot_declare_the_same_member() {
        let mut registry = BunRegistry::new();
        registry
            .register_module(contribution("rn-bun-hash", &["hash"], &[]))
            .expect("the first declaration is accepted");
        let error = registry
            .register_module(contribution("rn-bun-crypto", &["hash"], &[]))
            .expect_err("a second declaration of Bun.hash must be refused");
        assert!(
            error.contains("Bun.hash is declared by both rn-bun-hash and rn-bun-crypto"),
            "the collision must name both crates, got: {error}"
        );
    }

    #[test]
    fn a_deferral_that_overlaps_its_own_member_list_is_refused() {
        let mut registry = BunRegistry::new();
        let error = registry
            .register_module(contribution(
                "rn-bun-files",
                &["file"],
                &[("file", "needs a lazily-backed handle")],
            ))
            .expect_err("installed-and-deferred must be refused");
        assert!(
            error.contains("both installs and defers Bun.file"),
            "got: {error}"
        );
    }

    #[test]
    fn a_deferral_without_a_reason_is_refused() {
        let mut registry = BunRegistry::new();
        let error = registry
            .register_module(contribution("rn-bun-serve", &[], &[("serve", "  ")]))
            .expect_err("a reasonless deferral must be refused");
        assert!(error.contains("no reason"), "got: {error}");
    }

    #[test]
    fn a_deferral_cannot_collide_with_an_installed_member() {
        let mut registry = BunRegistry::new();
        registry
            .register_module(contribution("rn-bun-serve", &[], &[("serve", "tier 2")]))
            .expect("the deferral is accepted on its own");
        let error = registry
            .register_module(contribution("rn-bun-http", &["serve"], &[]))
            .expect_err("installing a member another crate deferred must be refused");
        assert!(
            error.contains("deferred by rn-bun-serve and installed by rn-bun-http"),
            "got: {error}"
        );
    }

    #[test]
    fn declarations_and_deferrals_are_reported_separately() {
        let mut registry = BunRegistry::new();
        registry
            .register_module(contribution(
                "rn-bun-text",
                &["stripANSI"],
                &[("inspect", "tier 1, not started")],
            ))
            .expect("registration succeeds");
        assert_eq!(
            registry.declarations(),
            [Declaration {
                member: "stripANSI".to_string(),
                contributor: "rn-bun-text".to_string(),
            }]
        );
        assert_eq!(registry.deferrals().len(), 1);
        assert_eq!(registry.deferrals()[0].member, "inspect");
    }
}
