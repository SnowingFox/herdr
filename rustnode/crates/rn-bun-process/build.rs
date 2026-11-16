//! Records the revision of *this* runtime for `Bun.revision`.
//!
//! `Bun.revision` on real Bun is the full git sha of the Bun commit that built
//! the binary. rsnode must not report Bun's sha — that would name code this
//! process is not running — so it reports its own commit instead. Reading it
//! from git at build time is the only way to get a value that is true of the
//! binary rather than aspirational: a hard-coded sha drifts the first time
//! anything is committed.
//!
//! When there is no git metadata (a source tarball, a vendored build) the
//! revision is reported as [`FALLBACK_REVISION`] rather than invented.

use std::process::Command;

/// What is reported when the build has no git revision to name.
pub const FALLBACK_REVISION: &str = "0000000000000000000000000000000000000000";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTNODE_GIT_SHA");

    // An explicit override wins, so a release build can stamp the tag it was
    // cut from even though the checkout has no `.git`.
    let revision = std::env::var("RUSTNODE_GIT_SHA")
        .ok()
        .filter(|sha| !sha.trim().is_empty())
        .or_else(git_revision)
        .unwrap_or_else(|| FALLBACK_REVISION.to_string());
    println!("cargo:rustc-env=RUSTNODE_BUN_REVISION={revision}");
}

/// The checkout's `HEAD`, or `None` when git cannot answer.
///
/// The working directory is this crate's, which is inside the repository whose
/// history is being built. `--short` is deliberately not used: `Bun.revision` is
/// a full sha and the 8-character form belongs to `Bun.version_with_sha`.
fn git_revision() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(std::env::var("CARGO_MANIFEST_DIR").ok()?)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
    // A sha is 40 hex digits; anything else is a git warning or an error page
    // and must not become `Bun.revision`.
    if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(sha)
    } else {
        None
    }
}
