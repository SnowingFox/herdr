//! The environment scope's startup scrub.
//!
//! Enforcing `--permission` removes every environment variable that
//! `--allow-env` does not grant access to, at startup, before any code that
//! could read it runs. That is what makes the scope enforceable at all: unlike
//! the filesystem scopes there is no per-call hook to consult, because C
//! libraries, `getenv()` and every child process read the process block
//! directly.
//!
//! Ported from `permission/env_permission.cc`:
//!
//! * [`RUNTIME_ENVIRONMENT_DEFAULTS`] is `kRuntimeEnvironmentDefaults` — the
//!   variables Node reads itself after startup, which the scrub always keeps;
//! * [`find_denied`] is `FindUnmatchedEnvironmentVariables`;
//! * [`scrub`] is `ScrubProcessEnvironment`, minus the Linux initial-block wipe,
//!   which [`initial_block_wiped`] states the absence of.
//!
//! Audit mode records the names instead of removing them (`record_audited`,
//! `RecordAuditedEnvironmentVariables`), so a `process.permission.has('env', …)`
//! and the diagnostics still see what enforcing would have removed while nothing
//! actually disappears.
//!
//! # What is not here
//!
//! Node also overwrites the entries in the environment block the process started
//! with so `/proc/<pid>/environ` no longer exposes them. That needs the address
//! of `environ`'s original strings and is only meaningful on Linux, so it is kept
//! visible as a stated gap rather than approximated.

use std::collections::BTreeSet;

/// The variables Node itself reads after startup, kept by the scrub.
///
/// `kRuntimeEnvironmentDefaults` in `permission/env_permission.cc`, in its
/// order. A trailing `*` is a prefix match, which is what `LC_*` needs.
pub const RUNTIME_ENVIRONMENT_DEFAULTS: &[&str] = &[
    // Read by Node.js itself after startup.
    "NODE_BENCH_CONTEXT",
    "NODE_BENCH_FILE_RUN_ID",
    "NODE_BENCH_RUN_ID",
    "NODE_CHANNEL_FD",
    "NODE_CHANNEL_SERIALIZATION_MODE",
    "NODE_CLUSTER_SCHED_POLICY",
    "NODE_COMPILE_CACHE",
    "NODE_COMPILE_CACHE_PORTABLE",
    "NODE_COMPILE_CACHE_READONLY",
    "NODE_DEBUG",
    "NODE_DEBUG_NATIVE",
    "NODE_DISABLE_COLORS",
    "NODE_DISABLE_COMPILE_CACHE",
    "NODE_EXTRA_CA_CERTS",
    "NODE_ICU_DATA",
    "NODE_INSPECT_RESUME_ON_START",
    "NODE_NO_WARNINGS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_PENDING_DEPRECATION",
    "NODE_PENDING_PIPE_INSTANCES",
    "NODE_PRESERVE_SYMLINKS",
    "NODE_REDIRECT_WARNINGS",
    "NODE_REPL_EXTERNAL_MODULE",
    "NODE_REPL_HISTORY",
    "NODE_TEST_CONTEXT",
    "NODE_TEST_WORKER_ID",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "NODE_UNIQUE_ID",
    "NODE_USE_ENV_PROXY",
    "NODE_USE_SYSTEM_CA",
    "NODE_V8_COVERAGE",
    "WATCH_REPORT_DEPENDENCIES",
    // Terminal and CI detection, see lib/internal/tty.js.
    "APPVEYOR",
    "BUILDKITE",
    "CI",
    "CI_NAME",
    "CIRCLECI",
    "COLORTERM",
    "DRONE",
    "FORCE_COLOR",
    "GITEA_ACTIONS",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "NO_COLOR",
    "TEAMCITY_VERSION",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TMUX",
    "TRAVIS",
    // libuv.
    "HOME",
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "UV_THREADPOOL_SIZE",
    "UV_USE_IO_URING",
    // Copied into child process environments by libuv on Windows, and read
    // by lib/child_process.js.
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOGONSERVER",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "USERDOMAIN",
    "USERNAME",
    "WINDIR",
    // c-ares and the system resolver.
    "HOSTALIASES",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    // ICU, the time zone and the locale.
    "ICU_DATA",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "TZ",
    // OpenSSL.
    "OPENSSL_CONF",
    "OPENSSL_CONF_INCLUDE",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    // The dynamic loader, for addons and FFI.
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
    "LIBPATH",
];

/// Whether `name` is one of [`RUNTIME_ENVIRONMENT_DEFAULTS`].
///
/// `EnvPermission::is_granted` consults this before the granted patterns, which
/// is what makes `process.permission.has('env', 'TZ')` answer `true` under
/// `--permission` even though no flag named it.
pub fn is_runtime_default(name: &str) -> bool {
    RUNTIME_ENVIRONMENT_DEFAULTS
        .iter()
        .any(|pattern| matches_pattern(pattern, name))
}

pub use crate::model::env_name_matches as matches_pattern;

/// Splits `--allow-env` values into individual patterns.
///
/// Each occurrence may hold a comma-separated list, and Node splits every one:
/// `--allow-env=A,B*` grants both. An empty entry is dropped rather than being
/// treated as a pattern, because splitting a trailing comma would otherwise
/// produce one that matches nothing.
pub fn parse_allow_list<S: AsRef<str>>(values: &[S]) -> Vec<String> {
    let mut patterns = Vec::new();
    for value in values {
        for pattern in value.as_ref().split(',') {
            if !pattern.is_empty() {
                patterns.push(pattern.to_string());
            }
        }
    }
    patterns
}

/// `IsValidEnvAllowPattern`: `*`, a variable name, or a name prefix ending `*`.
///
/// The C++ is one expression, and every part of it rejects something a test
/// actually passes:
///
/// ```text
/// !pattern.empty() && pattern.find('=') == npos &&
///     (wildcard == npos || wildcard == pattern.size() - 1)
/// ```
///
/// so `A*B` fails because the `*` is not last, `*A` for the same reason, `A=B`
/// because of the `=`, and `A,B*C` because it is a malformed comma list entry.
/// `--allow-env` is the one permission flag whose value Node validates at
/// startup rather than treating an unusable pattern as granting nothing.
pub fn is_valid_pattern(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.contains('=') {
        return false;
    }
    match pattern.find('*') {
        None => true,
        Some(index) => index == pattern.len() - 1,
    }
}

/// The variables [`scrub`] would remove: everything in the process environment
/// that neither `allow` nor [`RUNTIME_ENVIRONMENT_DEFAULTS`] matches.
///
/// Sorted, so the list a test or a diagnostic report prints is stable.
pub fn find_denied(allow: &[String]) -> Vec<String> {
    let mut denied = Vec::new();
    for (name, _) in std::env::vars() {
        if name.is_empty() {
            continue;
        }
        if is_runtime_default(&name) {
            continue;
        }
        if allow.iter().any(|pattern| matches_pattern(pattern, &name)) {
            continue;
        }
        denied.push(name);
    }
    denied.sort();
    denied
}

/// `ScrubProcessEnvironment`: removes every variable `allow` does not keep.
///
/// Returns the names it removed, which the caller records on the model so
/// `takeRemovedEnvVarWarning` can answer for them.
///
/// The environment is modified without any lock a native `getenv()` caller
/// participates in, so this runs before the platform thread pool starts. In
/// rustnode that is before V8 is initialised at all.
pub fn scrub(allow: &[String]) -> Vec<String> {
    // `*` grants everything, so there is nothing to remove and the whole pass
    // can be skipped.
    if allow.iter().any(|pattern| pattern == "*") {
        return Vec::new();
    }
    let removed = find_denied(allow);
    for name in &removed {
        std::env::remove_var(name);
    }
    removed
}

/// `RecordAuditedEnvironmentVariables`: records what enforcing would remove.
///
/// Audit mode removes nothing, so this is what lets the diagnostics channel and
/// `process.permission.has('env', …)` still report a denial for a variable the
/// enforcing model would have taken away.
pub fn record_audited(allow: &[String]) -> Vec<String> {
    if allow.iter().any(|pattern| pattern == "*") {
        return Vec::new();
    }
    find_denied(allow)
}

/// Whether this build can overwrite the environment block the process started
/// with, so `/proc/<pid>/environ` no longer exposes removed variables.
///
/// `false`: Node's `WipeInitialEnvironmentEntries` walks `environ`'s original
/// strings through `/proc/self/environ` and overwrites them in place, which this
/// build does not do.
///
/// Returning `false` rather than nothing keeps the gap a value a test can assert
/// on, instead of an absence nothing notices.
pub fn initial_block_wiped() -> bool {
    false
}

/// One warning's worth of names: the first `limit`, then a count of the rest.
///
/// Matches how Node lists the variables a non-owning embedder has to scrub, and
/// keeps a diagnostic from printing a whole environment block.
pub fn summarize(names: &[String], limit: usize) -> String {
    let mut text = names
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > limit {
        text.push_str(&format!(", and {} more", names.len().saturating_sub(limit)));
    }
    text
}

/// The names removed by the scrub, as the set the model answers warnings from.
pub fn removed_set(names: &[String]) -> BTreeSet<String> {
    names
        .iter()
        .map(|name| crate::model::normalize_env_name(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_list_keeps_what_node_reads() {
        for name in [
            "HOME",
            "PATH",
            "TMPDIR",
            "TZ",
            "NODE_OPTIONS",
            "LD_LIBRARY_PATH",
        ] {
            assert!(is_runtime_default(name), "{name} must be kept");
        }
        assert!(is_runtime_default("LC_ALL"), "LC_* is a prefix pattern");
        assert!(!is_runtime_default("PERMISSION_ENV_SECRET"));
        assert!(!is_runtime_default("NODE_AUTH_TOKEN"));
    }

    #[test]
    fn patterns_are_split_on_commas() {
        assert_eq!(
            parse_allow_list(&["A,B*".to_string(), "C".to_string()]),
            ["A", "B*", "C"]
        );
        assert!(parse_allow_list(&["".to_string()]).is_empty());
    }

    #[test]
    fn invalid_patterns_are_rejected_the_way_node_rejects_them() {
        // Every one of these is a value `test-permission-env-cli.js` passes and
        // expects exit 9 for.
        for pattern in ["A*B", "*A", "A=B", "A,B*C", ""] {
            assert!(!is_valid_pattern(pattern), "{pattern} must be rejected");
        }
        for pattern in ["*", "A", "A*", "PERMISSION_ENV_PREFIX_*"] {
            assert!(is_valid_pattern(pattern), "{pattern} must be accepted");
        }
    }

    #[test]
    fn a_star_grant_removes_nothing() {
        // `--allow-env=*` grants every variable, so the pass is skipped entirely
        // rather than comparing every name against a pattern that always
        // matches.
        assert!(scrub(&["*".to_string()]).is_empty());
    }

    #[test]
    fn the_denied_list_excludes_runtime_defaults_and_grants() {
        let denied = find_denied(&["RN_PERMISSION_TEST_*".to_string()]);
        assert!(!denied.iter().any(|name| is_runtime_default(name)));
        assert!(!denied.iter().any(|name| name == "PATH"));
    }

    #[test]
    fn summarize_bounds_the_list() {
        let names: Vec<String> = (0..7).map(|index| format!("V{index}")).collect();
        assert_eq!(summarize(&names, 3), "V0, V1, V2, and 4 more");
        assert_eq!(summarize(&names[..2], 3), "V0, V1");
    }

    #[test]
    fn this_build_does_not_wipe_the_initial_block() {
        // Pinned so the gap is a decision rather than an oversight: the test
        // starts failing if someone claims the wipe without implementing it.
        assert!(!initial_block_wiped());
    }
}
