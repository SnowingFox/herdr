//! The `Bun` object's structure, checked against its own declarations.
//!
//! `tools/bun-surface-guard.py` is the differential half: it compares the installed
//! object against Bun 1.4.4 and against the registry, and it needs a built binary
//! and an oracle. This file is the same relationship checked *in process*, with no
//! oracle, so a crate author gets the answer from `cargo test -p rn-bun` before
//! their pull request reaches the gate:
//!
//! * every member a crate declares is on the object;
//! * every member on the object is declared;
//! * no name is claimed by two crates;
//! * a deferred name is neither installed nor in its own crate's `members()`.
//!
//! It builds the object through the same `BunRegistry::build` the runtime uses, so
//! a crate that passes here but fails in the guard is a difference in the *runtime*
//! rather than in its declaration, which is the distinction that makes two checks
//! worth having instead of one.

use rn_v8_sys::v8;

/// A V8 scope with no bootstrap. `Bun`'s assembly needs no Node builtin, which is
/// why this test can run in a bare isolate — and that fact is itself load-bearing:
/// if a contribution crate ever started needing `require`, this test would fail and
/// the change would be visible before it broke a worker.
fn with_scope<R>(body: impl for<'s> FnOnce(&mut v8::PinScope<'s, '_>) -> R) -> R {
    static V8: std::sync::Once = std::sync::Once::new();
    V8.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

/// Own string-keyed property names of `object`, sorted.
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
    let mut collected = Vec::new();
    for index in 0..names.length() {
        let Some(value) = names.get_index(scope, index) else {
            continue;
        };
        let Ok(name) = v8::Local::<v8::Name>::try_from(value) else {
            continue;
        };
        if name.is_string() {
            collected.push(name.to_rust_string_lossy(scope));
        }
    }
    collected.sort();
    collected
}

/// The registry this build assembles. A refusal here is already a defect, so the
/// message says which crate, not just that assembly failed.
fn registry() -> rn_bun_api::BunRegistry {
    rn_bun_members::install_all()
        .expect("the contribution registry must assemble; a refusal names the crates")
}

#[test]
fn the_registry_assembles_without_a_duplicate_or_contradiction() {
    let registry = registry();
    // A count of zero is not a pass: this test would then be asserting nothing
    // about the surface. `rn-bun-time` is the floor today, and the number only
    // grows as the Tier-1 workers add crates.
    assert!(
        !registry.declarations().is_empty(),
        "the registry declares no Bun member at all, so every assertion below is \
         vacuous — the aggregator is probably empty"
    );
}

#[test]
fn every_declared_member_is_installed_and_every_installed_member_is_declared() {
    let registry = registry();
    with_scope(|scope| {
        let bun = registry
            .build(scope)
            .expect("the registry's own object must build; a failure names the crate");
        let installed = own_names(scope, bun);

        let declared: Vec<String> = registry
            .declarations()
            .iter()
            .map(|declaration| declaration.member.clone())
            .collect();
        let mut declared_sorted = declared.clone();
        declared_sorted.sort();

        // `build` already refuses both directions, so reaching here means they
        // agree. The assertion is still worth making: it pins the property for a
        // future `build` that returns the object before checking, and it prints the
        // two sets rather than a boolean when it fails.
        assert_eq!(
            installed, declared_sorted,
            "the installed Bun members and the registry's declarations differ"
        );
        assert!(
            !installed.is_empty(),
            "the built Bun object has no members, which cannot be a pass"
        );
    });
}

#[test]
fn a_deferred_member_is_not_also_installed_or_claimed() {
    let registry = registry();
    let claimed: Vec<&str> = registry
        .declarations()
        .iter()
        .map(|declaration| declaration.member.as_str())
        .collect();
    for deferral in registry.deferrals() {
        assert!(
            !claimed.contains(&deferral.member.as_str()),
            "{} both declares and defers Bun.{}; the two cancel each other out in \
             any contract arithmetic",
            deferral.contributor,
            deferral.member
        );
        assert!(
            !deferral.reason.trim().is_empty(),
            "{} defers Bun.{} with no reason",
            deferral.contributor,
            deferral.member
        );
    }
}

#[test]
fn every_declared_member_reads_back_as_something() {
    // A member can be declared, installed, and still be useless: `set(scope, key,
    // undefined)` on a fresh object leaves the property present and the value
    // absent, and `Object.getOwnPropertyNames` cannot tell the two apart. That is
    // the "silently does not work" shape this whole registry exists to prevent, so
    // it is checked as a value read, not as a key.
    //
    // `undefined` is the only value rejected. A member whose honest value *is*
    // `undefined` would have to be a deliberate decision, and no Bun member is.
    let registry = registry();
    with_scope(|scope| {
        let bun = registry.build(scope).expect("the object builds");
        for declaration in registry.declarations() {
            let key = v8::String::new(scope, &declaration.member)
                .expect("a declared member name is allocatable");
            let value = bun
                .get(scope, key.into())
                .unwrap_or_else(|| panic!("Bun.{} cannot be read", declaration.member));
            assert!(
                !value.is_undefined(),
                "{} declares Bun.{} but the value is undefined; the property exists \
                 and does nothing",
                declaration.contributor,
                declaration.member
            );
        }
    });
}

/// The check above can fail. A test whose defect it guards has never been observed
/// is a test that might be measuring nothing, and this file exists in a tree that
/// has been burned by exactly that. So the shape is reproduced here directly: a
/// property that is present with an `undefined` value, which the read has to
/// reject.
#[test]
fn a_present_but_undefined_member_is_detectable() {
    with_scope(|scope| {
        let object = v8::Object::new(scope);
        let key = v8::String::new(scope, "presentButEmpty").expect("key");
        object.set(scope, key.into(), v8::undefined(scope).into());

        // The key is there, so a name-only check would accept it.
        let names = own_names(scope, object);
        assert_eq!(
            names,
            ["presentButEmpty"],
            "the name-only view must see the property; if this fails the defect \
             shape below is not the one being tested"
        );

        // The value read is what rejects it.
        let value = object.get(scope, key.into()).expect("the property reads");
        assert!(
            value.is_undefined(),
            "the value must read as undefined for this shape to be the defect"
        );
    });
}

#[test]
fn the_real_install_publishes_the_registrys_members() {
    // The tests above check `BunRegistry::build`, which is one function short of
    // what a running process does: `install` also puts the object on `globalThis`,
    // and a defect in *that* step — the wrong name, an enumerable property, a
    // global that is never set — would pass every test above. This runs the real
    // `install` and reads the result back through `installed_members`, the same
    // two functions the runtime uses.
    let registry = registry();
    let mut declared: Vec<String> = registry
        .declarations()
        .iter()
        .map(|declaration| declaration.member.clone())
        .collect();
    declared.sort();

    with_scope(|scope| {
        rn_bun::install_with(scope, rn_bun::Mode::Eager).expect("the eager install succeeds");
        assert_eq!(
            rn_bun::installed_members(scope),
            declared,
            "the eager install published a different member set than the registry declares"
        );
    });

    with_scope(|scope| {
        rn_bun::install_with(scope, rn_bun::Mode::Lazy).expect("the lazy install succeeds");
        // Reading the members is what builds the lazy object, which is exactly the
        // path a script's first `Bun.x` takes.
        assert_eq!(
            rn_bun::installed_members(scope),
            declared,
            "the lazy install published a different member set than the registry declares"
        );
    });
}

#[test]
fn the_bun_global_is_non_enumerable_and_an_own_property() {
    // `common/index.js` walks `Object.keys(globalThis)`, so the enumerability is a
    // correctness property and not a style choice. It is asserted here as well as
    // in the built-binary tests because this is the layer that decides it.
    with_scope(|scope| {
        rn_bun::install_with(scope, rn_bun::Mode::Eager).expect("the install succeeds");
        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "Bun").expect("key");
        let descriptor = global
            .get_own_property_descriptor(scope, key.into())
            .expect("Bun must be an own property of the global");
        let descriptor =
            v8::Local::<v8::Object>::try_from(descriptor).expect("a descriptor object");
        let enumerable_key = v8::String::new(scope, "enumerable").expect("key");
        let enumerable = descriptor
            .get(scope, enumerable_key.into())
            .expect("the descriptor has an enumerable field");
        assert!(
            enumerable.is_false(),
            "the Bun global must be non-enumerable; an enumerable global costs \
             test/common's globals audit every test in the suite"
        );
    });
}
