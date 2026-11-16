//! `Bun.revision` and `Bun.version_with_sha`, and the decision `Bun.version`
//! waits on.
//!
//! # Why `version` is deferred
//!
//! On real Bun these three name the Bun release that built the binary:
//! `"1.4.4"`, `"38afee6c84fcf48c0edb2466aa4b27d287a59c30"` and
//! `"v1.4.4 (38afee6c8)"`. rsnode is not Bun — it is a different runtime built
//! from different code — so a Bun release number would be a false claim about the
//! running process, and the specific harm is that a feature check takes Bun's
//! branch with no signal:
//!
//! ```js
//! if (Bun.version.startsWith('1.')) useBunServeFastPath();  // runs, and is wrong
//! ```
//!
//! The alternatives each fail differently, which is why this is a product decision
//! rather than a measurement:
//!
//! * **`"1.4.4"`.** The lie above.
//! * **rsnode's own crate version, `"0.1.0"`.** Truthful about the package and
//!   misleading about the API: every `Bun.version >= "1.1"` gate takes the *oldest*
//!   branch even though this runtime implements the 1.4.4 surface, so it hides the
//!   work rather than the risk.
//! * **A bare `"rsnode"`.** Unordered against every numeric comparison, so both
//!   `>= "1.1"` and `< "1.0"` are `false` — a check that can neither pass nor fail.
//! * **`"1.4.4-rsnode"`.** A semver prerelease of the surface it tracks: `>=
//!   "1.4.4"` is `false` (honest — this is not that release) and `>= "1.0"` is
//!   `true` (honest — the surface is present). `typeof` stays `"string"` with no
//!   prefix, which is the one shape fact §6.1 pins.
//!
//! [`COMPAT_MARKER`] is the placeholder this crate would use if the user picks the
//! last option; **`version` is not installed**, so nothing here reaches
//! `Bun.version` until that decision is made. When it is, moving the name from
//! [`crate::DEFERRED`] to [`crate::MEMBERS`] and setting it here is the whole
//! change.
//!
//! # `revision` is this binary's own commit
//!
//! `Bun.revision` is a full 40-digit git sha. Reporting Bun's would name code that
//! is not in this process, and inventing one would be worse than either
//! alternative, so the value comes from `build.rs`, which asks git for the
//! checkout's `HEAD` and falls back to an explicit all-zero sha when there is no
//! git metadata to read.
//!
//! # `version_with_sha` derives from the same constant
//!
//! It is `"v{marker} ({short sha})"` — the same derivation Bun uses (`"v1.4.4
//! (38afee6c8)"`) — so it is installed and truthful about the *revision* while its
//! version half is the documented placeholder. The deferral reason names it, so a
//! reader of `Bun.version_with_sha` learns that its prefix is not a Bun release.

use rn_v8_sys::v8;

/// The Bun surface this runtime implements, as a compatibility marker.
///
/// **A placeholder, not the answer.** `Bun.version` does not report it; see the
/// module docs for what the user has to decide. It is here because
/// [`version_with_sha`] needs a version half and because the decision, once made,
/// changes exactly this constant.
pub const COMPAT_MARKER: &str = "1.4.4-rsnode";

/// `Bun.revision` when the build had no git revision to record.
///
/// All zeroes rather than a plausible-looking sha, because a value that cannot be
/// a real commit is the only honest way to say "there is no commit here".
pub const FALLBACK_REVISION: &str = "0000000000000000000000000000000000000000";

/// This build's own revision, recorded by `build.rs`.
pub const REVISION: &str = env!("RUSTNODE_BUN_REVISION");

/// `Bun.version_with_sha`: the marker with a leading `v` and the short sha.
#[must_use]
pub fn version_with_sha() -> String {
    let short = &REVISION[..8.min(REVISION.len())];
    format!("v{COMPAT_MARKER} ({short})")
}

/// Installs `revision` and `version_with_sha`.
///
/// Measured attributes, from §6.1:
///
/// | member | writable | enumerable | configurable |
/// | --- | --- | --- | --- |
/// | `revision` | false | true | false |
/// | `version_with_sha` | false | **false** | false |
///
/// `version` is deliberately absent: it is in [`crate::DEFERRED`], and the
/// registry refuses a name that is both installed and deferred.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let revision = v8::String::new(scope, REVISION).ok_or("cannot allocate the revision")?;
    crate::define_value(
        scope,
        target,
        "revision",
        revision.into(),
        v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
    )?;

    let with_sha =
        v8::String::new(scope, &version_with_sha()).ok_or("cannot allocate version_with_sha")?;
    crate::define_value(
        scope,
        target,
        "version_with_sha",
        with_sha.into(),
        v8::PropertyAttribute::READ_ONLY
            | v8::PropertyAttribute::DONT_DELETE
            | v8::PropertyAttribute::DONT_ENUM,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_installed() {
        // The one thing this module must not do while the decision is open.
        let installed = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/version.rs"),
        )
        .expect("this file is readable");
        let install_body = installed
            .split("pub(crate) fn install")
            .nth(1)
            .expect("the install function is present");
        assert!(
            !install_body.contains("\"version\","),
            "Bun.version is deferred, so install() must not publish it"
        );
    }

    #[test]
    fn the_marker_is_not_a_bare_bun_release_number() {
        // Whichever option is chosen, a bare release number is the one that must
        // never ship: it is the value that lets `startsWith('1.')` pass.
        assert_ne!(COMPAT_MARKER, "1.4.4");
        assert!(COMPAT_MARKER.starts_with("1.4.4"));
        assert!(COMPAT_MARKER.len() > "1.4.4".len());
    }

    #[test]
    fn version_with_sha_has_buns_shape() {
        let value = version_with_sha();
        assert!(value.starts_with('v'), "{value}");
        assert!(value.contains(COMPAT_MARKER), "{value}");
        assert!(value.ends_with(')'), "{value}");
        let short = &REVISION[..8.min(REVISION.len())];
        assert_eq!(value, format!("v{COMPAT_MARKER} ({short})"));
    }

    #[test]
    fn the_revision_is_a_full_sha_or_the_documented_fallback() {
        assert_eq!(REVISION.len(), 40, "{REVISION} is not a full sha");
        assert!(
            REVISION.chars().all(|c| c.is_ascii_hexdigit()),
            "{REVISION} is not hexadecimal"
        );
        if REVISION == FALLBACK_REVISION {
            assert!(REVISION.chars().all(|c| c == '0'));
        }
    }
}
