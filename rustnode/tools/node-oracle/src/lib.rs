//! Resolves the Node binary the differential tests compare rustnode against.
//!
//! A differential test is only as meaningful as the oracle it compares to.
//! Eighteen test targets used to spawn a bare `node`, or shell out to
//! `command -v node`, which meant "whatever the CI image happens to ship".
//! GitHub's `ubuntu-latest` ships Node 22 on `PATH` while `tools/node-pin.toml`
//! pins Node 28, and the two disagree about the crypto surface, so
//! `rn-bind-crypto/tests/differential.rs` failed on CI against a Node rustnode
//! does not target while passing locally against the right one. A test that
//! measures the wrong binary is not a weaker test; it is a different one.
//!
//! The nine named in the issue were found by grepping for
//! `Command::new("node")`. Nine more had the same defect in a form that grep did
//! not show: five passed a bare `"node"` string to a helper, `rn-bind-cares` and
//! `rn-bind-encoding` each ran their own `command -v node` search (and skipped
//! *silently*, so a green run could not be told from one that compared nothing),
//! `rn-bind-v8` had its own `RUSTNODE_PARITY_NODE` override, and one more hid
//! behind a shared `same_output_as_node` helper. All of them now go through this
//! crate.
//!
//! This crate makes the oracle explicit and makes the fallback honest.
//!
//! # Resolution order
//!
//! 1. `RN_NODE_ORACLE`: an absolute path to the pinned binary. `tools/check.sh`
//!    and the CI workflow set it, so a gate run never depends on `PATH`.
//! 2. The pin file: `tools/node-pin.toml`'s `oracle` directory, expanded to its
//!    `bin/node`. This is the recorded location, so a developer who ran
//!    `tools/fetch-node-oracle.sh` needs no environment at all.
//! 3. `PATH`: a bare `node`. Reached only when nothing is pinned, and reported
//!    as [`Source::Path`] so it is never mistaken for the oracle.
//!
//! # Skip versus fail
//!
//! There are three distinct outcomes and they must not collapse into one:
//!
//! * **The oracle is the pinned version.** Compare, and print which binary and
//!   version were used.
//! * **No oracle at all.** Skip, loudly. A machine without Node should still be
//!   able to run the vector tests, and "absent" is unambiguous.
//! * **A Node that is not the pinned version.** Fail, unless
//!   `RN_NODE_ORACLE_ALLOW_VERSION_MISMATCH=1` says otherwise. This is the case
//!   that caused the defect: Node 22 was present, so the tests ran, compared
//!   against the wrong engine, and reported a verdict about compatibility with a
//!   Node rustnode does not target. A version mismatch is not a degraded oracle,
//!   it is a different oracle, and a green run against it says nothing. Skipping
//!   would be quieter than failing but equally dishonest, because the gate would
//!   still report success without having performed the comparison; so the
//!   mismatch fails and names both versions.
//!
//! The escape hatch exists because a maintainer may deliberately want to see how
//! rustnode compares against another Node. Setting it is a decision recorded in
//! the environment, and [`Oracle::describe`] then prints the mismatch on every
//! line so no log can read as pinned-oracle evidence.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The environment variable an explicit oracle path comes from.
pub const ORACLE_ENV: &str = "RN_NODE_ORACLE";

/// Set to `1` to downgrade a version mismatch from a failure to a warning.
pub const ALLOW_MISMATCH_ENV: &str = "RN_NODE_ORACLE_ALLOW_VERSION_MISMATCH";

/// Where a resolved binary came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// `RN_NODE_ORACLE`.
    Env,
    /// The `oracle` directory recorded in `tools/node-pin.toml`.
    PinFile,
    /// A bare `node` found on `PATH`.
    Path,
}

impl Source {
    /// The name used in test output and in failure messages.
    pub fn label(self) -> &'static str {
        match self {
            Source::Env => ORACLE_ENV,
            Source::PinFile => "tools/node-pin.toml",
            Source::Path => "PATH",
        }
    }
}

/// What the pin file says the oracle is.
#[derive(Clone, Debug)]
pub struct Pin {
    /// `[node] version`, for example `28.0.0`.
    pub version: String,
    /// `[node] commit`, the revision the JavaScript layer came from.
    pub commit: String,
    /// `[node] oracle` as an absolute directory, if the pin names one.
    pub oracle_dir: Option<PathBuf>,
    /// `[node] oracle_version`: the exact string the oracle reports to
    /// `--version`. A nightly embeds its date and short SHA, so this is not
    /// derivable from [`version`](Pin::version) alone.
    pub oracle_version: Option<String>,
}

impl Pin {
    /// The `--version` output a usable oracle must produce.
    ///
    /// When the pin records an explicit `oracle_version` that is authoritative;
    /// otherwise the release version is the expectation and a nightly oracle
    /// simply reports the longer string, which [`matches_oracle`] tolerates
    /// because it is the same release.
    pub fn expected_version(&self) -> String {
        self.oracle_version
            .clone()
            .unwrap_or_else(|| format!("v{}", self.version))
    }

    /// Whether `reported` is the build this pin describes.
    ///
    /// A recorded `oracle_version` must match exactly: it names one build, and
    /// "a different nightly of the same release" is still a different engine to
    /// compare against. Without one, a `v<version>` prefix match accepts both the
    /// release and its nightlies, which are built from the same source.
    pub fn matches_oracle(&self, reported: &str) -> bool {
        let reported = normalize_version(reported.trim());
        match &self.oracle_version {
            Some(exact) => reported == normalize_version(exact),
            None => {
                let version = normalize_version(&self.version);
                reported == version
                    || reported
                        .strip_prefix(version)
                        .is_some_and(|rest| rest.starts_with('-'))
            }
        }
    }

    /// Reads `tools/node-pin.toml` from the workspace root above `manifest_dir`.
    ///
    /// The crate is a dev-dependency, so `CARGO_MANIFEST_DIR` is the *test's*
    /// crate directory, not this one; the pin is found by walking up until a
    /// `tools/node-pin.toml` is reached. That keeps the helper usable from every
    /// crate without each one knowing the workspace layout.
    pub fn load(manifest_dir: &Path) -> Option<Pin> {
        let text = std::fs::read_to_string(find_pin_file(manifest_dir)?).ok()?;
        parse_pin(&text)
    }
}

/// Parses the `[node]` table of a pin file.
///
/// Only the three keys the oracle needs are read; the rest of the file is
/// documentation and counts consumed by other tools. Parsing by table matters:
/// `[counts]` also has a `version`-shaped neighbour, so a bare
/// `version = "..."` scan would happily read the wrong key if the file were
/// reordered. A key is only accepted while the active section is `node`.
pub fn parse_pin(text: &str) -> Option<Pin> {
    let mut section = String::new();
    let mut version = None;
    let mut commit = None;
    let mut oracle = None;
    let mut oracle_version = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if section != "node" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(value) = toml_string(value) else {
            continue;
        };
        match key.trim() {
            "version" => version = Some(value),
            "commit" => commit = Some(value),
            "oracle" => oracle = Some(PathBuf::from(value)),
            "oracle_version" => oracle_version = Some(value),
            _ => {}
        }
    }
    Some(Pin {
        version: version?,
        commit: commit.unwrap_or_default(),
        oracle_dir: oracle,
        oracle_version,
    })
}

/// The value of a double-quoted TOML string, or `None` for any other shape.
fn toml_string(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

/// Walks up from `start` looking for `tools/node-pin.toml`.
fn find_pin_file(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        let candidate = current.join("tools").join("node-pin.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = current.parent();
    }
    None
}

/// A resolved Node binary and the evidence for trusting it.
#[derive(Clone, Debug)]
pub struct Oracle {
    /// The executable.
    pub path: PathBuf,
    /// What `--version` reported, with the leading `v` kept as Node prints it.
    pub version: String,
    /// Where the path came from.
    pub source: Source,
    /// The pin the version was checked against.
    pub pin: Pin,
    /// True when the version does not match the pin and the caller allowed it.
    pub mismatch_allowed: bool,
}

impl Oracle {
    /// True when the binary is the build `tools/node-pin.toml` describes.
    pub fn is_pinned_version(&self) -> bool {
        self.pin.matches_oracle(&self.version)
    }

    /// The line every differential test prints so a log names its oracle.
    ///
    /// It is emitted as a test failure message as well as on success, so a
    /// failing log identifies the binary that produced the failure without the
    /// reader having to guess from a version string in stderr.
    pub fn describe(&self) -> String {
        let mut text = format!(
            "oracle: {} ({} via {})",
            self.path.display(),
            self.version,
            self.source.label()
        );
        if self.is_pinned_version() {
            text.push_str(&format!(" pin {}", self.pin.expected_version()));
        } else {
            text.push_str(&format!(
                " pin {} MISMATCH{}",
                self.pin.expected_version(),
                if self.mismatch_allowed {
                    " (allowed by RN_NODE_ORACLE_ALLOW_VERSION_MISMATCH=1)"
                } else {
                    ""
                }
            ));
        }
        text
    }

    /// Runs `args` and returns the output, panicking with the oracle's identity
    /// when the binary itself cannot be executed.
    pub fn command(&self) -> Command {
        Command::new(&self.path)
    }

    /// The oracle's path as a `&str`, for helpers that take a command name.
    ///
    /// Some test helpers spawn either runtime through one string-typed function.
    /// Passing the oracle's path through that seam keeps the helper unchanged
    /// while still measuring the pinned binary.
    pub fn reference_path(&self) -> &str {
        self.path
            .to_str()
            .unwrap_or_else(|| panic!("{} is not valid UTF-8", self.path.display()))
    }

    /// `node -e <script>`, returning trimmed stdout.
    pub fn eval(&self, script: &str) -> String {
        let output = self
            .command()
            .arg("-e")
            .arg(script)
            .output()
            .unwrap_or_else(|error| panic!("cannot run {}: {error}", self.describe()));
        assert!(
            output.status.success(),
            "{} failed on {script:?}: {}",
            self.describe(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// A one-line summary used by [`OracleError`] when the caller fails.
    pub fn summary(&self) -> String {
        format!("{} ({})", self.path.display(), self.version)
    }
}

impl fmt::Display for Oracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

/// Why no usable oracle was resolved.
///
/// Each variant is a different situation and the caller must not merge them:
/// [`Missing`](OracleError::Missing) is a skip, while
/// [`WrongVersion`](OracleError::WrongVersion) and
/// [`Unusable`](OracleError::Unusable) are failures.
#[derive(Clone, Debug)]
pub enum OracleError {
    /// Nothing was found: no environment override, no pinned directory, no
    /// `node` on `PATH`.
    Missing {
        /// The pin the search was aiming at, when the pin file was readable.
        pin: Option<Box<Pin>>,
        /// The paths that were tried, in order, for the message.
        searched: Vec<PathBuf>,
    },
    /// A binary was found but reports a different version than the pin.
    WrongVersion {
        /// The path that was found.
        path: PathBuf,
        /// Its `--version` output.
        version: String,
        /// Where it came from.
        source: Source,
        /// The pin it was checked against.
        pin: Box<Pin>,
    },
    /// The pin file itself could not be read, so there is nothing to check a
    /// version against. This is a repository defect, not a missing toolchain.
    Unusable { reason: String },
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleError::Missing { pin, searched } => {
                write!(
                    f,
                    "no Node oracle found. Set {ORACLE_ENV} to the pinned binary"
                )?;
                if let Some(pin) = pin {
                    write!(
                        f,
                        " (Node {}, commit {})",
                        pin.version,
                        short_commit(&pin.commit)
                    )?;
                    if let Some(dir) = &pin.oracle_dir {
                        write!(
                            f,
                            "; the pin records {} but no executable is there",
                            dir.display()
                        )?;
                    }
                }
                write!(f, ". Searched:")?;
                for path in searched {
                    write!(f, " {}", path.display())?;
                }
                Ok(())
            }
            OracleError::WrongVersion {
                path,
                version,
                source,
                pin,
            } => write!(
                f,
                "refusing to compare against the wrong Node: {} reports {} via {}, \
                 but tools/node-pin.toml pins {}. A differential test against a \
                 different Node version is a different test, not a weaker one. \
                 Point {ORACLE_ENV} at Node {}, or set {ALLOW_MISMATCH_ENV}=1 to \
                 compare against this binary on purpose.",
                path.display(),
                version,
                source.label(),
                pin.expected_version(),
                pin.expected_version()
            ),
            OracleError::Unusable { reason } => write!(f, "{reason}"),
        }
    }
}

/// Resolves the oracle for a test whose crate directory is `manifest_dir`.
///
/// Returns the resolved oracle or the reason none could be used. This does no
/// printing and takes no policy decision: [`require_oracle`] holds the
/// skip-versus-fail rule, and this function is what a test that wants its own
/// wording should call.
///
/// `path` is the value of the process `PATH`, passed in rather than read here so
/// a unit test can drive the search without mutating the environment of a
/// parallel test binary.
pub fn resolve_with(manifest_dir: &Path, path: Option<&str>) -> Result<Oracle, OracleError> {
    let pin = Pin::load(manifest_dir);
    let mut searched: Vec<PathBuf> = Vec::new();

    // 1. The explicit override. It is authoritative: if it names something that
    //    does not run, that is a mistake worth reporting rather than silently
    //    falling through to a different binary.
    if let Some(explicit) = std::env::var_os(ORACLE_ENV) {
        let path = PathBuf::from(&explicit);
        if path.as_os_str().is_empty() {
            return Err(OracleError::Unusable {
                reason: format!("{ORACLE_ENV} is set but empty"),
            });
        }
        searched.push(path.clone());
        let Some(version) = probe_version(&path) else {
            return Err(OracleError::Unusable {
                reason: format!(
                    "{ORACLE_ENV} is set to {} but it could not be run as a Node binary",
                    path.display()
                ),
            });
        };
        return check_version(path, version, Source::Env, pin);
    }

    // 2. The directory the pin records.
    if let Some(pin_value) = &pin {
        if let Some(dir) = &pin_value.oracle_dir {
            let path = dir.join("bin").join(node_exe());
            searched.push(path.clone());
            if let Some(version) = probe_version(&path) {
                return check_version(path, version, Source::PinFile, pin);
            }
        }
    }

    // 3. Whatever `node` is on `PATH`.
    if let Some(path_var) = path {
        for dir in std::env::split_paths(path_var) {
            let candidate = dir.join(node_exe());
            searched.push(candidate.clone());
            if let Some(version) = probe_version(&candidate) {
                return check_version(candidate, version, Source::Path, pin);
            }
        }
    }

    Err(OracleError::Missing {
        pin: pin.map(Box::new),
        searched,
    })
}

/// Resolves using this process's environment.
pub fn resolve() -> Result<Oracle, OracleError> {
    let path = std::env::var("PATH").ok();
    resolve_with(Path::new(env!("CARGO_MANIFEST_DIR")), path.as_deref())
}

fn check_version(
    path: PathBuf,
    version: String,
    source: Source,
    pin: Option<Pin>,
) -> Result<Oracle, OracleError> {
    let Some(pin) = pin else {
        return Err(OracleError::Unusable {
            reason: format!(
                "{} was found but tools/node-pin.toml could not be read, so its \
                 version cannot be checked against the pin",
                path.display()
            ),
        });
    };
    let mismatch_allowed = std::env::var(ALLOW_MISMATCH_ENV)
        .map(|value| value == "1")
        .unwrap_or(false);
    if !pin.matches_oracle(&version) && !mismatch_allowed {
        return Err(OracleError::WrongVersion {
            path,
            version,
            source,
            pin: Box::new(pin),
        });
    }
    Ok(Oracle {
        path,
        version,
        source,
        pin,
        mismatch_allowed,
    })
}

/// `--version` of `path`, or `None` when it is not a runnable Node.
fn probe_version(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.starts_with('v') && version.len() > 1 {
        Some(version)
    } else {
        None
    }
}

fn node_exe() -> &'static str {
    if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    }
}

/// Compares versions ignoring a leading `v`, so `v28.0.0` and `28.0.0` agree.
fn normalize_version(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

fn short_commit(commit: &str) -> &str {
    let end = commit.len().min(12);
    &commit[..end]
}

/// Writes one line to stderr without going through libtest's capture.
///
/// `eprintln!` is captured by the harness and *discarded when the test passes*,
/// so a passing run would print nothing about its oracle and a log would only
/// ever show the identity of an oracle that had already failed. A direct write
/// to the process stderr handle is not intercepted, which is what makes the
/// oracle line appear in a green CI log as well as a red one.
pub fn announce(line: &str) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
    let _ = stderr.flush();
}

/// The policy every differential test follows.
///
/// Returns `Some(oracle)` when a comparison should run, and `None` when there is
/// no oracle at all. It panics when an oracle exists but must not be used:
/// a wrong-version binary and an unreadable pin are both failures, because
/// either one would otherwise turn into a green run that compared against the
/// wrong thing.
///
/// A test calls this once at its start and again for each comparison it makes,
/// so the oracle's identity is in the log next to the verdict either way:
///
/// ```ignore
/// let Some(oracle) = rn_node_oracle::require_oracle("the crypto surface") else {
///     return;
/// };
/// ```
///
/// `subject` names what is being compared, so the announcement reads as a
/// sentence in a log with many tests in it.
pub fn require_oracle(subject: &str) -> Option<Oracle> {
    match resolve() {
        Ok(oracle) => {
            announce(&format!("{}: using {}", subject, oracle.describe()));
            Some(oracle)
        }
        Err(error @ OracleError::Missing { .. }) => {
            announce(&format!(
                "{subject}: SKIPPED, {error}. This differential test did not run; \
                 its vector and recorded-expectation tests are the always-on \
                 equivalent."
            ));
            None
        }
        Err(error) => {
            announce(&format!("{subject}: FAILED, {error}"));
            panic!("{subject}: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = r#"
# A comment with version = "9.9.9" that must not be read.
[node]
repository = "https://github.com/nodejs/node"
commit = "f344e7f552e"
version = "28.0.0"
oracle = "/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64"
oracle_version = "v28.0.0-nightly20261111e8c1160d20"

[counts]
builtin_files = 435
version = "not-the-node-version"
"#;

    #[test]
    fn pin_is_read_from_the_node_table_only() {
        let pin = parse_pin(PIN).expect("the pin parses");
        assert_eq!(pin.version, "28.0.0");
        assert_eq!(pin.commit, "f344e7f552e");
        assert_eq!(
            pin.oracle_dir.as_deref(),
            Some(Path::new(
                "/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64"
            ))
        );
    }

    /// `[counts]` also has a `version`, and a naive scan would read it.
    #[test]
    fn a_later_tables_version_does_not_override_the_nodes() {
        let pin = parse_pin(PIN).expect("the pin parses");
        assert_ne!(pin.version, "not-the-node-version");
    }

    #[test]
    fn a_pin_without_a_version_is_rejected() {
        assert!(parse_pin("[node]\ncommit = \"abc\"\n").is_none());
    }

    #[test]
    fn the_pin_records_where_the_oracle_lives() {
        let pin = parse_pin(PIN).expect("the pin parses");
        assert_eq!(
            pin.oracle_dir.as_deref(),
            Some(Path::new(
                "/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64"
            ))
        );
    }

    #[test]
    fn versions_compare_ignoring_the_leading_v() {
        assert_eq!(normalize_version("v28.0.0"), normalize_version("28.0.0"));
        assert_ne!(normalize_version("v22.23.4"), normalize_version("28.0.0"));
    }

    /// A recorded `oracle_version` names one build, so another nightly of the
    /// same release is still the wrong oracle.
    #[test]
    fn a_recorded_oracle_version_must_match_exactly() {
        let pin = parse_pin(PIN).expect("the pin parses");
        assert!(pin.matches_oracle("v28.0.0-nightly20261111e8c1160d20"));
        assert!(!pin.matches_oracle("v28.0.0-nightly20261115c07db8c5c1"));
        assert!(!pin.matches_oracle("v28.0.0"));
        assert!(!pin.matches_oracle("v22.23.4"));
    }

    /// Without an explicit oracle version, a nightly of the pinned release is
    /// the same source, so it is accepted; another release is not.
    #[test]
    fn a_pin_without_an_oracle_version_accepts_that_releases_nightlies() {
        let pin =
            parse_pin("[node]\ncommit = \"abc\"\nversion = \"28.0.0\"\n").expect("the pin parses");
        assert!(pin.matches_oracle("v28.0.0"));
        assert!(pin.matches_oracle("v28.0.0-nightly20261111e8c1160d20"));
        assert!(!pin.matches_oracle("v28.1.0"));
        assert!(!pin.matches_oracle("v22.23.4"));
    }

    /// The repository's own pin must stay readable by this crate, or every
    /// differential test silently degrades to "no oracle".
    #[test]
    fn the_workspace_pin_is_readable() {
        let pin =
            Pin::load(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("the workspace pin loads");
        assert_eq!(pin.version, "28.0.0");
        assert_eq!(pin.commit, "f344e7f552e");
        assert!(
            pin.oracle_dir.is_some(),
            "the pin must record where the oracle lives, or the search has nothing to fall back to"
        );
        assert!(
            pin.oracle_version.is_some(),
            "the pin must record the exact version the oracle reports, or a different \
             nightly of the same release would be accepted as the oracle"
        );
    }

    /// `PATH` resolution is driven in a unit test rather than through the real
    /// environment, so the message shapes can be asserted without a Node.
    #[test]
    fn a_missing_oracle_reports_every_path_it_tried() {
        let pin = parse_pin(PIN).expect("the pin parses");
        let error = OracleError::Missing {
            pin: Some(Box::new(pin)),
            searched: vec![
                PathBuf::from("/nonexistent-a/node"),
                PathBuf::from("/nonexistent-b/node"),
            ],
        };
        let text = error.to_string();
        assert!(text.contains("no Node oracle found"), "{text}");
        assert!(text.contains("/nonexistent-a"), "{text}");
        assert!(text.contains("/nonexistent-b"), "{text}");
        assert!(text.contains("28.0.0"), "{text}");
        assert!(text.contains(ORACLE_ENV), "{text}");
    }

    /// A `PATH` with no `node` in it never yields an oracle.
    ///
    /// The `PATH` half is exercised against a directory that cannot contain a
    /// `node`, so whatever resolves here did not come from `PATH`. Both other
    /// sources are legitimate: the environment override when a test harness has
    /// one set, and the pin's recorded directory when `tools/fetch-node-oracle.sh`
    /// has run. What must never happen is a `Source::Path` result, because that
    /// would mean the search walked `PATH` after all.
    #[test]
    fn an_empty_path_never_resolves_to_the_machine_s_node() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        match resolve_with(dir, Some("/nonexistent-only")) {
            Err(OracleError::Missing { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(oracle) => assert_ne!(
                oracle.source,
                Source::Path,
                "only the environment override or the pin's directory may resolve here: {oracle:?}"
            ),
        }
    }

    /// A found-but-wrong binary is an error, never a silent success.
    #[test]
    fn a_wrong_version_is_reported_with_both_versions() {
        let error = OracleError::WrongVersion {
            path: PathBuf::from("/usr/bin/node"),
            version: "v22.23.4".to_string(),
            source: Source::Path,
            pin: Box::new(parse_pin(PIN).expect("the pin parses")),
        };
        let text = error.to_string();
        assert!(text.contains("/usr/bin/node"), "{text}");
        assert!(text.contains("v22.23.4"), "{text}");
        assert!(text.contains("28.0.0"), "{text}");
        assert!(text.contains(ORACLE_ENV), "{text}");
        assert!(text.contains(ALLOW_MISMATCH_ENV), "{text}");
        assert!(
            text.contains("a different test, not a weaker one"),
            "the message must say why a mismatch fails rather than skip: {text}"
        );
    }

    #[test]
    fn describe_names_the_path_version_and_source() {
        let oracle = Oracle {
            path: PathBuf::from("/oracle/bin/node"),
            version: "v28.0.0-nightly20261111e8c1160d20".to_string(),
            source: Source::Env,
            pin: parse_pin(PIN).expect("the pin parses"),
            mismatch_allowed: false,
        };
        let line = oracle.describe();
        assert!(line.contains("/oracle/bin/node"), "{line}");
        assert!(line.contains("v28.0.0"), "{line}");
        assert!(line.contains(ORACLE_ENV), "{line}");
        assert!(!line.contains("MISMATCH"), "{line}");
    }

    /// An allowed mismatch must still be visible on the line, or a log would
    /// read as pinned-oracle evidence.
    #[test]
    fn an_allowed_mismatch_stays_visible() {
        let oracle = Oracle {
            path: PathBuf::from("/usr/bin/node"),
            version: "v22.23.4".to_string(),
            source: Source::Path,
            pin: parse_pin(PIN).expect("the pin parses"),
            mismatch_allowed: true,
        };
        let line = oracle.describe();
        assert!(line.contains("MISMATCH"), "{line}");
        assert!(line.contains(ALLOW_MISMATCH_ENV), "{line}");
        assert!(!oracle.is_pinned_version());
    }
}
