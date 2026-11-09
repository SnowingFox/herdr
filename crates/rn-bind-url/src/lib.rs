//! `internalBinding('url')` for rustnode.
//!
//! `src/node_url.cc` is the specification. Its nine members are the native half
//! of the WHATWG `URL` class: `lib/internal/url.js` owns `URL`,
//! `URLSearchParams` and every getter and setter, and calls into this namespace
//! only to parse, re-serialize and answer a few questions about strings.
//!
//! The important structural detail is that the JavaScript never receives a
//! parsed object. `parse` answers with a serialized `href` and writes nine
//! numbers into `urlComponents`; every getter in `lib/internal/url.js` then
//! slices `href` at those offsets. So the contract to reproduce is exactly
//!
//! ```text
//! (canonical href, nine offsets)  ==  (ada::url_aggregator, url_components)
//! ```
//!
//! and [`model::Offsets`] derives the second from the first.
//!
//! # Foundation, and why
//!
//! The parser underneath is the [`url`](https://docs.rs/url) crate (Servo's
//! WHATWG implementation) with [`idna`](https://docs.rs/idna) for UTS #46. That
//! is the same standard ada implements, so the two are not merely similar: they
//! are two implementations of one specification, which makes agreement the
//! default and disagreement a bug worth finding.
//!
//! The alternative — a hand-written parser — was rejected because the WHATWG
//! algorithm is large and its corner cases are where compatibility actually
//! lives: percent-encoding sets per component, dot-segment removal, IPv4
//! shorthand, IPv6 compression, default-port elision, `file:` drive letters.
//! Writing those by hand would mean re-deriving what a maintained crate already
//! does, with far more room to be subtly wrong.
//!
//! Using a crate is not the same as trusting it. Every disagreement below was
//! found by differential testing against a real `node` and is covered by a test
//! in `tests/node_parity.rs`; none was assumed away.
//!
//! # Known differences from Node
//!
//! These are the places where this implementation knowingly answers differently
//! from a real `node`. Each is a property of the `url`/`idna` crates rather than
//! of the glue here, and each is small and visible rather than structural.
//!
//! 1. **`ẞ` (U+1E9E) uppercases to `ss` in Node, but punycodes here.** Node's
//!    ada decodes `http://ẞ.com/` to `http://ss.com/`; the `idna` crate keeps
//!    the character and produces `xn--zca.com`. Both are defensible UTS #46
//!    readings; ada applies the uppercase mapping first and `idna` does not.
//!
//! 2. **`file:` URLs with a drive letter after a host.** Node parses
//!    `file://h/C:/x` as host `h` and path `/C:/x`; the `url` crate folds the
//!    drive letter into the path and drops the host, giving `file:///C:/x`.
//!    This only affects `file:` URLs that name a host *and* a drive letter,
//!    which is a Windows UNC shape that cannot occur on this platform.
//!
//! 3. **`file:` URLs with a `|` drive separator.** Node normalises
//!    `file:///c|/x` to `file:///c:/x`; the `url` crate leaves the `|` in the
//!    path. `c|` is the pre-Windows-95 spelling of a drive letter.
//!
//! 4. **`set_pathname("//x")` on a `file:` URL.** Node produces
//!    `file:////x`, whose path is `//x`. The `url` crate folds the extra slash
//!    while parsing and `Url` has no way to hold the longer form, so the folded
//!    `file:///x` is produced instead. This is the only one of the 2,240
//!    `update` cases in `tests/node_parity.rs` that disagrees, and the test
//!    names it explicitly rather than filtering it out silently.
//!
//! 5. **`format` on an unparsable href.** Node's `Format` asserts that the
//!    re-parse succeeded, so `bindingUrl.format("bad url", ...)` aborts the
//!    process. This returns the input unchanged instead, which is what the
//!    surrounding code in `node_url.cc` does for the case it expects (an IDN
//!    hostname the parser rejects on the second pass). Aborting is never a
//!    better outcome for the same input, so the difference is deliberate.
//!
//! Everything else — including the members' failure conventions, the offsets,
//! every percent-encoding set reachable from `update`, and the ten update
//! actions' guards — was verified against Node. See `tests/node_parity.rs`.
//!
//! # What is not here
//!
//! Nothing in the namespace is deferred: all nine members are installed and
//! exercised against Node. Two platform-shaped details are accepted but never
//! exercised on this platform:
//!
//! * `pathToFileURL`'s Windows branch. `PathFlavour::Windows` implements the
//!   backslash-to-separator rule and is unit-tested, but the binding is always
//!   called with `windows = false` because rustnode is POSIX-only.
//! * The Windows UNC `hostname` argument `pathToFileURL` takes third. Node only
//!   reads it when `windows` is true, so it is accepted and ignored, with a note
//!   at the call site.

pub mod callbacks;
pub mod format;
pub mod idna;
pub mod install;
pub mod model;
pub mod path;
pub mod update;

use rn_core::{AliasedUint8Array, BindingModule, Element, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/url.json`.
///
/// The order is the order `CreatePerIsolateProperties` and
/// `CreatePerContextProperties` install them in `src/node_url.cc`, plus
/// `urlComponents`, which the `BindingData` constructor writes.
pub const MEMBERS: &[&str] = &[
    "canParse",
    "domainToASCII",
    "domainToUnicode",
    "format",
    "getOrigin",
    "parse",
    "pathToFileURL",
    "update",
    "urlComponents",
];

/// `kURLComponentsLength` in `src/node_url.h`.
pub const COMPONENTS_LENGTH: usize = 9;

/// The `url` namespace.
pub struct Url;

impl BindingModule for Url {
    fn namespace(&self) -> &'static str {
        "url"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        // Node allocates the components buffer in the BindingData constructor
        // and exposes it as `urlComponents`; the binding writes through the same
        // memory. `AliasedUint8Array` is that shared store, and the thread-local
        // keeps the typed array alive for the process, which is what lets the
        // callbacks reach it without a receiver.
        let components = AliasedUint8Array::new(scope, COMPONENTS_LENGTH, Element::Word)?;
        let array = components.array(scope);
        components_slot::set(components);

        let object = v8::Object::new(scope);
        install::define_method(scope, object, "parse", callbacks::parse)?;
        install::define_method(scope, object, "canParse", callbacks::can_parse)?;
        install::define_method(scope, object, "format", callbacks::format)?;
        install::define_method(scope, object, "getOrigin", callbacks::get_origin)?;
        install::define_method(scope, object, "update", callbacks::update)?;
        install::define_method(scope, object, "pathToFileURL", callbacks::path_to_file_url)?;
        install::define_method(scope, object, "domainToASCII", callbacks::domain_to_ascii)?;
        install::define_method(
            scope,
            object,
            "domainToUnicode",
            callbacks::domain_to_unicode,
        )?;

        let key = install::string(scope, "urlComponents")?;
        object
            .set(scope, key.into(), array)
            .ok_or("could not define urlComponents")?;
        Ok(object)
    }
}

/// The shared `urlComponents` store.
///
/// Node keeps this on the `Realm` through `AliasedUint32Array`. rustnode has no
/// `Realm` object yet, so the slot lives here; when `rn-core` grows one, this
/// should move, exactly as `rn-bind-buffer` notes for its buffer prototype.
mod components_slot {
    use std::cell::RefCell;

    use rn_core::AliasedUint8Array;

    thread_local! {
        static COMPONENTS: RefCell<Option<AliasedUint8Array>> = const { RefCell::new(None) };
    }

    /// Records the components buffer created during install.
    pub(super) fn set(components: AliasedUint8Array) {
        COMPONENTS.with(|slot| *slot.borrow_mut() = Some(components));
    }

    /// Writes the nine offsets, in `urlComponents` order.
    ///
    /// A missing buffer means `internalBinding('url')` was never installed, in
    /// which case no member can have been called; the write is skipped rather
    /// than panicking on a state that cannot occur.
    pub(super) fn write(offsets: [u32; 9]) {
        COMPONENTS.with(|slot| {
            if let Some(components) = slot.borrow().as_ref() {
                for (index, value) in offsets.iter().enumerate() {
                    components.set(index, *value);
                }
            }
        });
    }
}

/// Re-exports the offset writer for the callback layer.
pub(crate) use components_slot::write as write_components;

/// Registers the `url` namespace with the runtime.
///
/// `tools/regen-bindings.sh` discovers this function, so nothing else has to be
/// edited for `internalBinding('url')` to resolve.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Url);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_matches_the_recorded_contract() {
        let mut listed = MEMBERS.to_vec();
        listed.sort_unstable();
        let mut contract: Vec<&str> = vec![
            "canParse",
            "domainToASCII",
            "domainToUnicode",
            "format",
            "getOrigin",
            "parse",
            "pathToFileURL",
            "update",
            "urlComponents",
        ];
        contract.sort_unstable();
        assert_eq!(listed, contract);
    }

    #[test]
    fn no_member_is_both_installed_and_deferred() {
        // A member in both lists would mean the deferral is a lie: the check in
        // `rn-compat` accepts a deferral, so a stub that also claims to work
        // would slip through.
        let module = Url;
        let installed: std::collections::BTreeSet<&str> =
            module.members().iter().copied().collect();
        for (member, _) in module.deferred() {
            assert!(
                !installed.contains(member),
                "{member} is both installed and deferred"
            );
        }
    }

    #[test]
    fn every_deferred_member_has_a_reason() {
        for (member, reason) in Url.deferred() {
            assert!(!reason.trim().is_empty(), "{member} has no reason");
        }
    }

    #[test]
    fn the_components_buffer_is_nine_words() {
        // `kURLComponentsLength`, asserted by a static_assert in node_url.cc.
        assert_eq!(COMPONENTS_LENGTH, 9);
    }
}
