//! `Bun.version`, `Bun.revision` and `Bun.version_with_sha`, and why `version`
//! reports a compatibility marker rather than a Bun release.
//!
//! # Why `version` reports [`COMPAT_MARKER`]
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
//! Four candidates were considered, and they fail differently. The last one is
//! the one installed:
//!
//! * **`"1.4.4"`.** The lie above. Rejected.
//! * **rsnode's own crate version, `"0.1.0"`.** Truthful about the package and
//!   misleading about the API: every `Bun.version >= "1.1"` gate takes the *oldest*
//!   branch even though this runtime implements the 1.4.4 surface, so it hides the
//!   work rather than the risk. Rejected.
//! * **A bare `"rsnode"`.** Unordered against every numeric comparison, so both
//!   `>= "1.1"` and `< "1.0"` are `false` — a check that can neither pass nor fail.
//!   Rejected.
//! * **`"1.4.4-rsnode"` — installed.** A semver prerelease of the surface it
//!   tracks, so a real semver comparison (not string ordering, which puts it
//!   *after* `"1.4.4"`) gives `>= "1.4.4"` = `false`, honest because this is not
//!   that release, and `>= "1.0"` = `true`, honest because the 1.4.4 surface is
//!   present. `typeof` stays `"string"` with no prefix, which is the one shape fact
//!   §6.1 pins, and it is not a Bun release number, so nothing silently reports
//!   one.
//!
//! The value lives in exactly one constant, so preferring a different candidate
//! later is a one-line change to [`COMPAT_MARKER`] and nothing else.
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
//! (38afee6c8)"`) — so its version half is exactly [`COMPAT_MARKER`], the same
//! string `Bun.version` reports, and only the revision half names this build.

use rn_v8_sys::v8;

/// The Bun surface this runtime implements, as a compatibility marker.
///
/// Reported by both [`install`] as `Bun.version` and [`version_with_sha`] as its
/// version half. It is a semver prerelease of Bun 1.4.4 rather than that release,
/// so `Bun.version >= "1.4.4"` is `false` and `Bun.version >= "1.0"` is `true`
/// under a real semver comparison; see the module docs for why that pair is the
/// honest one.
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

/// Installs `version`, `revision` and `version_with_sha`.
///
/// Measured attributes, from §6.1:
///
/// | member | writable | enumerable | configurable |
/// | --- | --- | --- | --- |
/// | `version` | false | true | false |
/// | `revision` | false | true | false |
/// | `version_with_sha` | false | **false** | false |
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let version = v8::String::new(scope, COMPAT_MARKER).ok_or("cannot allocate the version")?;
    crate::define_value(
        scope,
        target,
        "version",
        version.into(),
        v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
    )?;

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
    fn version_and_version_with_sha_share_the_marker() {
        // `Bun.version` and the version half of `Bun.version_with_sha` have to be
        // the same string. Both read one constant, so they cannot drift; this pins
        // the constant and the derivation. That `install` actually publishes it is
        // checked at runtime by the registry's declaration comparison and by
        // `tests/differential.rs`, which reads `Bun.version` off the binary.
        assert_eq!(COMPAT_MARKER, "1.4.4-rsnode");
        let short = &REVISION[..8.min(REVISION.len())];
        assert_eq!(version_with_sha(), format!("v{COMPAT_MARKER} ({short})"));
    }

    #[test]
    fn the_marker_is_not_a_bare_bun_release_number() {
        // Whichever option is chosen, a bare release number is the one that must
        // never ship: it is the value that lets `startsWith('1.')` pass.
        assert_ne!(COMPAT_MARKER, "1.4.4");
        assert!(COMPAT_MARKER.starts_with("1.4.4"));
        assert!(COMPAT_MARKER.len() > "1.4.4".len());
    }

    /// The boundary the marker was chosen for, under a real semver comparison.
    ///
    /// `rn_bun_text::semver::order` is the same ordering `Bun.semver.order`
    /// implements (and `Bun.version` is compared with it by callers that do not
    /// use string ordering), so this is the comparison the design claim is about:
    /// the prerelease sorts *below* `1.4.4` and *above* `1.0`/`1.0.0`, and equal
    /// to itself. A string comparison would put it *above* `"1.4.4"`, which is
    /// exactly the wrong answer, and `Bun.semver.satisfies` is not used here
    /// because npm-style range matching deliberately excludes prereleases.
    #[test]
    fn the_marker_orders_as_the_compatibility_boundary_designed() {
        use rn_bun_text::semver::order;
        let at_least = |range: &str| order(Some(COMPAT_MARKER), Some(range)).expect("valid") >= 0;
        assert!(
            !at_least("1.4.4"),
            "the marker must not claim the 1.4.4 release"
        );
        assert!(at_least("1.0"), "the 1.4.4 surface is present");
        assert!(at_least("1.0.0"));
        assert_eq!(
            order(Some(COMPAT_MARKER), Some(COMPAT_MARKER)).ok(),
            Some(0)
        );
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
