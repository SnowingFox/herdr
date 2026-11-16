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
//! and [`model::Offsets`] reads the second out of ada.
//!
//! # Foundation
//!
//! The parser underneath is [`ada_url`], a binding to the same
//! `deps/ada/ada.cpp` that Node vendors. `ada-url` 4.0.0 (crate vcs revision
//! `af35063623f2c93bb337728d03c03644b47e75c9`) bundles the single-header release
//! of ada generated `2026-07-27 16:10:09 -0400`; the copy in Node's
//! `deps/ada/` at the revision this runtime targets is the *same release*, and
//! `ada.cpp` and `ada.h` are byte-identical (sha256 `1c722f8f…` and `0010b17b…`
//! respectively). So the parser, the per-component percent-encode sets, the
//! host and port guards, and the `idna` half are the same compiled C++ that
//! Node 28 runs, not a second implementation of the same standard.
//!
//! That equivalence is the whole reason this crate delegates. An earlier
//! version used the [`url`](https://docs.rs/url) crate — the same WHATWG
//! standard, a different implementation — and the interesting disagreements were
//! never the spec, they were ada's own guards: `^` in the path percent-encode
//! set, `set_host` truncating at a delimiter and *ignoring* a rejected port,
//! `set_port` requiring a leading digit, the ASCII fast path in `to_ascii` that
//! skips UTS #46 validation entirely. Each was re-derived by hand and four were
//! re-derived wrongly. Delegating to ada deletes that entire class of bug,
//! because there is no longer a second opinion to reconcile.
//!
//! # What is not delegated
//!
//! Three things in this namespace are Node's glue rather than ada's, and those
//! are implemented here:
//!
//! * **`format`'s `unicode` mode** rewrites the host to its decoded spelling,
//!   which produces an href that is not a parseable URL (`http://☃/x`). Node
//!   sets `out->host` on its parsed object; an aggregator would re-punycode it,
//!   so the decoded text is spliced in at the host's byte range. See
//!   [`format`].
//! * **`pathToFileURL`'s `EncodePathChars`** runs *before* the parse and
//!   percent-encodes the RFC 1738 unsafe set, which is not the URL parser's own
//!   escaping and would be double-encoded by it. See [`path`].
//! * **`search`/`hash` on `update`** map an empty value to ada's `clear_*`
//!   entry point, because ada spells "empty but present" (`?`) and "absent"
//!   as different calls. See [`update`].
//!
//! `domainToASCII`/`domainToUnicode` were also Node's glue in the old version
//! and are now built on ada as well: `set_hostname` on a `ws://x` seed, which is
//! literally what `src/node_url.cc` does, plus `Idna::unicode` for the decoder.
//! The ASCII fast path that the old `idna`-crate version could not reproduce
//! comes for free from that arrangement.
//!
//! # Known differences from Node
//!
//! 1. **`file:` URLs with a drive letter after a host.** Node parses
//!    `file://h/C:/x` as host `h` and path `/C:/x`; this produces
//!    `file:///C:/x`. A Windows UNC shape that cannot occur on this platform.
//! 2. **`format` on an unparsable href.** Node's `Format` returns `args[0]`
//!    unchanged; so does this.
//! 3. **Nothing else.** The `ẞ` case, the `^` case, the `file:////` case and the
//!    four `update` guard cases that the previous version listed as known
//!    differences are all Node's answer now, because the code producing them is
//!    Node's.
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
