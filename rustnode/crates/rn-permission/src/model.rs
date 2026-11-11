//! The permission model: scopes, grants and the checks other crates call.
//!
//! Ported from `src/permission/` in the pinned Node checkout. The structure is
//! deliberately the same so the JavaScript layer cannot tell the difference:
//!
//! * [`PermissionScope`] is `PermissionScope` from `permission_base.h`, and
//!   [`PermissionScope::from_label`] is `Permission::StringToPermission`;
//! * filesystem scopes use [`path::RadixTree`] like `FSPermission`;
//! * every other scope is a boolean: `DenyOnlyPermission` (grants are
//!   irrevocable) or `AllowRevokePermission` (`--allow-net`);
//! * a disabled model grants everything without touching the filesystem, which
//!   is the property that keeps the checks free for normal runs.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use crate::path::{self, RadixTree};

/// The permission scopes, in the order `permission_base.h` declares them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionScope {
    FileSystem,
    FileSystemRead,
    FileSystemWrite,
    ChildProcess,
    Wasi,
    WorkerThreads,
    Inspector,
    Net,
    Addon,
    Ffi,
    OpenSSLStore,
    Env,
}

/// The boolean scopes, in the order their slots are indexed.
const BOOLEAN_SCOPES: [PermissionScope; 8] = [
    PermissionScope::ChildProcess,
    PermissionScope::Wasi,
    PermissionScope::WorkerThreads,
    PermissionScope::Inspector,
    PermissionScope::Net,
    PermissionScope::Addon,
    PermissionScope::Ffi,
    PermissionScope::OpenSSLStore,
];

impl PermissionScope {
    /// Every scope a `--allow-*` flag can grant. [`PermissionScope::FileSystem`]
    /// is excluded because it is a composite of the read and write scopes
    /// rather than something that is granted on its own.
    pub const GRANTABLE: [PermissionScope; 11] = [
        PermissionScope::FileSystemRead,
        PermissionScope::FileSystemWrite,
        PermissionScope::ChildProcess,
        PermissionScope::Wasi,
        PermissionScope::WorkerThreads,
        PermissionScope::Inspector,
        PermissionScope::Net,
        PermissionScope::Addon,
        PermissionScope::Ffi,
        PermissionScope::OpenSSLStore,
        PermissionScope::Env,
    ];

    /// The string `lib/**` passes to `has()` and `drop()`.
    pub fn label(self) -> &'static str {
        match self {
            PermissionScope::FileSystem => "fs",
            PermissionScope::FileSystemRead => "fs.read",
            PermissionScope::FileSystemWrite => "fs.write",
            PermissionScope::ChildProcess => "child",
            PermissionScope::Wasi => "wasi",
            PermissionScope::WorkerThreads => "worker",
            PermissionScope::Inspector => "inspector",
            PermissionScope::Net => "net",
            PermissionScope::Addon => "addon",
            PermissionScope::Ffi => "ffi",
            PermissionScope::OpenSSLStore => "openssl.store",
            PermissionScope::Env => "env",
        }
    }

    /// Port of `Permission::PermissionToString`, which the error object uses.
    /// Differs from [`Self::label`] for the filesystem scopes, where Node
    /// reports the C++ enumerator name.
    pub fn error_name(self) -> &'static str {
        match self {
            PermissionScope::FileSystem => "FileSystem",
            PermissionScope::FileSystemRead => "FileSystemRead",
            PermissionScope::FileSystemWrite => "FileSystemWrite",
            PermissionScope::ChildProcess => "ChildProcess",
            PermissionScope::Wasi => "WASI",
            PermissionScope::WorkerThreads => "WorkerThreads",
            PermissionScope::Inspector => "Inspector",
            PermissionScope::Net => "Net",
            PermissionScope::Addon => "Addon",
            PermissionScope::Ffi => "FFI",
            PermissionScope::OpenSSLStore => "OpenSSLStore",
            PermissionScope::Env => "Env",
        }
    }

    /// Port of `Permission::StringToPermission`. Returns `None` for the
    /// permissions root, which has no scope of its own; callers treat that as
    /// an unknown scope and answer `false` rather than throwing.
    pub fn from_label(label: &str) -> Option<PermissionScope> {
        match label {
            "fs" => Some(PermissionScope::FileSystem),
            "fs.read" => Some(PermissionScope::FileSystemRead),
            "fs.write" => Some(PermissionScope::FileSystemWrite),
            "child" => Some(PermissionScope::ChildProcess),
            "wasi" => Some(PermissionScope::Wasi),
            "worker" => Some(PermissionScope::WorkerThreads),
            "inspector" => Some(PermissionScope::Inspector),
            "net" => Some(PermissionScope::Net),
            "addon" => Some(PermissionScope::Addon),
            "ffi" => Some(PermissionScope::Ffi),
            "openssl.store" => Some(PermissionScope::OpenSSLStore),
            "env" => Some(PermissionScope::Env),
            _ => None,
        }
    }

    /// The flag `GetErrorFlagSuggestion` names in a denial message.
    pub fn flag(self) -> &'static str {
        match self {
            PermissionScope::FileSystem => "",
            PermissionScope::FileSystemRead => "--allow-fs-read",
            PermissionScope::FileSystemWrite => "--allow-fs-write",
            PermissionScope::ChildProcess => "--allow-child-process",
            PermissionScope::Wasi => "--allow-wasi",
            PermissionScope::WorkerThreads => "--allow-worker",
            PermissionScope::Inspector => "--allow-inspector",
            PermissionScope::Net => "--allow-net",
            PermissionScope::Addon => "--allow-addons",
            PermissionScope::Ffi => "--allow-ffi",
            PermissionScope::OpenSSLStore => "--allow-openssl-store",
            PermissionScope::Env => "--allow-env",
        }
    }

    /// Slot in [`PermissionModel`]'s boolean array, for the scopes that are a
    /// yes/no grant.
    fn boolean_slot(self) -> Option<usize> {
        BOOLEAN_SCOPES.iter().position(|scope| *scope == self)
    }
}

/// One filesystem scope's grants, the counterpart of `FSPermission`.
///
/// Node keeps a `deny_all` / `allow_all` pair plus a radix tree and rebuilds
/// the tree when a grant is dropped. Grants are a handful of paths, so this
/// keeps the same shape instead of tracking which tree nodes to remove.
#[derive(Debug)]
struct FsScope {
    granted_paths: Vec<Vec<u8>>,
    allow_all: bool,
    deny_all: bool,
    tree: RadixTree,
}

impl FsScope {
    fn new() -> Self {
        Self {
            granted_paths: Vec::new(),
            allow_all: false,
            deny_all: true,
            tree: RadixTree::default(),
        }
    }

    fn grant(&mut self, path: Vec<u8>) {
        if self.granted_paths.contains(&path) {
            return;
        }
        if !self.tree.lookup(&path) {
            self.tree.insert(&path);
        }
        self.granted_paths.push(path);
        self.deny_all = false;
    }

    fn grant_all(&mut self) {
        self.allow_all = true;
        self.deny_all = false;
    }

    fn revoke(&mut self, path: &[u8]) {
        let before = self.granted_paths.len();
        self.granted_paths.retain(|granted| granted != path);
        if self.granted_paths.len() != before {
            self.rebuild();
        }
    }

    fn drop_all(&mut self) {
        self.deny_all = true;
        self.allow_all = false;
        self.granted_paths.clear();
        self.tree = RadixTree::default();
    }

    fn rebuild(&mut self) {
        self.tree = RadixTree::default();
        if self.granted_paths.is_empty() {
            self.deny_all = true;
            return;
        }
        for path in &self.granted_paths {
            self.tree.insert(path);
        }
    }

    fn grants_any(&self) -> bool {
        self.allow_all
    }

    fn grants_path(&self, resolved: &[u8]) -> bool {
        !self.deny_all && (self.allow_all || self.tree.lookup(resolved))
    }
}

/// How a boolean scope behaves, mirroring `boolean_permission.h`.
///
/// The C++ stores a single `flag_` whose *meaning* differs per kind, so the
/// methods below are not symmetric:
///
/// ```text
/// DenyOnly:      Apply -> flag_ = true,  Drop -> flag_ = true,  granted = !flag_
/// AllowRevoke:   Apply -> flag_ = true,  Drop -> flag_ = false, granted =  flag_
/// ```
///
/// For `DenyOnlyPermission` that means `flag_` is "denied": a scope is granted
/// only while nothing has touched it, and both `Apply` and `Drop` leave it
/// denied for good. That is what the header's own comment describes — "once
/// denied, the permission cannot be re-granted" — and it is why
/// `--allow-child-process` followed by `process.permission.drop('child')` has to
/// deny the spawn rather than keep allowing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BooleanKind {
    /// `DenyOnlyPermission`: `Apply` and `Drop` both deny, permanently.
    DenyOnly,
    /// `AllowRevokePermission`: `Apply` grants, `Drop` revokes, `Apply` again
    /// grants again.
    AllowRevoke,
}

#[derive(Debug)]
struct BooleanScope {
    kind: BooleanKind,
    granted: bool,
    /// For [`BooleanKind::DenyOnly`]: whether something has denied the scope, so
    /// a later `Apply` cannot grant it again.
    irrevocably_denied: bool,
}

impl BooleanScope {
    fn new(kind: BooleanKind) -> Self {
        Self {
            kind,
            granted: false,
            irrevocably_denied: false,
        }
    }

    fn grant(&mut self) {
        // `Apply` on a `DenyOnlyPermission` sets the same `flag_` that `Drop`
        // does, so a scope that has been denied stays denied.
        if self.kind == BooleanKind::DenyOnly && self.irrevocably_denied {
            return;
        }
        self.granted = true;
    }

    /// `Drop` on a `DenyOnlyPermission` denies the scope for good; on an
    /// `AllowRevokePermission` it only revokes the current grant.
    fn drop_all(&mut self) {
        self.granted = false;
        if self.kind == BooleanKind::DenyOnly {
            self.irrevocably_denied = true;
        }
    }

    fn is_granted(&self) -> bool {
        self.granted
    }
}

/// Environment-variable scope: `--allow-env` patterns plus runtime drops.
///
/// Separate from the boolean scopes because `has('env', name)` answers per
/// variable. Scrubbing the process environment belongs to the env binding; this
/// owns only the grant bookkeeping `has()` and `drop()` answer from.
#[derive(Debug, Default)]
struct EnvScope {
    patterns: Vec<String>,
    dropped: Vec<String>,
    allow_all: bool,
    drop_all: bool,
}

impl EnvScope {
    fn grant(&mut self, patterns: Vec<String>) {
        for pattern in patterns {
            if pattern == "*" {
                self.allow_all = true;
            }
            if !self.patterns.contains(&pattern) {
                self.patterns.push(pattern);
            }
        }
    }

    fn drop_name(&mut self, name: &str) {
        let name = normalize_env_name(name);
        if !self.dropped.contains(&name) {
            self.dropped.push(name);
        }
    }

    fn drop_scope(&mut self) {
        self.drop_all = true;
        self.allow_all = false;
        self.patterns.clear();
        self.dropped.clear();
    }

    fn is_granted(&self, name: &str) -> bool {
        if name.is_empty() {
            // `is_granted(env, kEnv, "")` answers `granted_all()`.
            return self.allow_all && !self.drop_all;
        }
        let normalized = normalize_env_name(name);
        if self.dropped.contains(&normalized) {
            return false;
        }
        if self.drop_all {
            return false;
        }
        // `IsRuntimeEnvironmentDefault(param)` comes before the granted
        // patterns in the C++: the variables Node itself reads stay readable
        // whatever `--allow-env` says, which is what makes `TZ` and `PATH`
        // answer `true` under a bare `--permission`.
        crate::env::is_runtime_default(name)
            || self.allow_all
            || self
                .patterns
                .iter()
                .any(|pattern| env_name_matches(pattern, &normalized))
    }
}

/// `EnvNameMatchesPattern`: `*`, an exact name, or a prefix followed by `*`.
/// Names are case-insensitive on Windows, where environment names are.
pub fn env_name_matches(pattern: &str, name: &str) -> bool {
    let (pattern, name) = if cfg!(windows) {
        (pattern.to_ascii_uppercase(), name.to_ascii_uppercase())
    } else {
        (pattern.to_string(), name.to_string())
    };
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

/// The key under which a name is stored in the dropped and warned sets.
///
/// Case-insensitive on Windows, where environment variable names are.
pub fn normalize_env_name(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_uppercase()
    } else {
        name.to_string()
    }
}

/// Why a check failed, in the shape the JavaScript layer reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDenied {
    pub scope: PermissionScope,
    /// The resource Node names in the `resource` field: a path for filesystem
    /// checks, the executable for a child process, empty for the rest.
    pub resource: String,
}

impl AccessDenied {
    pub fn new(scope: PermissionScope, resource: impl Into<String>) -> Self {
        Self {
            scope,
            resource: resource.into(),
        }
    }

    /// The error code. Always `ERR_ACCESS_DENIED`; a method so callers building
    /// an error object read the value instead of hard-coding it.
    pub fn code(&self) -> &'static str {
        "ERR_ACCESS_DENIED"
    }

    /// The `permission` field, e.g. `FileSystemRead`.
    pub fn permission(&self) -> &'static str {
        self.scope.error_name()
    }

    /// The `resource` field.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Port of `CreateAccessDeniedError`'s message, including the
    /// `GetErrorFlagSuggestion` tail.
    pub fn message(&self) -> String {
        let flag = self.scope.flag();
        if flag.is_empty() {
            "Access to this API has been restricted.".to_string()
        } else {
            format!("Access to this API has been restricted. Use {flag} to manage permissions.")
        }
    }
}

impl std::fmt::Display for AccessDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for AccessDenied {}

/// Configuration for a [`PermissionModel`], one field per supported CLI flag.
#[derive(Debug, Clone, Default)]
pub struct PermissionConfig {
    /// `--permission`: enforce.
    pub enabled: bool,
    /// `--permission-audit`: check and publish, never deny.
    pub audit: bool,
    /// `--allow-fs-read` values, one per flag occurrence.
    pub allow_fs_read: Vec<String>,
    /// `--allow-fs-write` values, one per flag occurrence.
    pub allow_fs_write: Vec<String>,
    /// `--allow-child-process`.
    pub allow_child_process: bool,
    /// `--allow-worker`.
    pub allow_worker: bool,
    /// `--allow-addons`.
    pub allow_addons: bool,
    /// `--allow-wasi`.
    pub allow_wasi: bool,
    /// `--allow-net`.
    pub allow_net: bool,
    /// `--allow-inspector`.
    pub allow_inspector: bool,
    /// `--allow-env` values, one per flag occurrence. Each may be a
    /// comma-separated list, which Node still splits.
    pub allow_env: Vec<String>,
}

impl PermissionConfig {
    /// A model that is switched off, the default for every process.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Enforcing, with nothing granted: `--permission`.
    pub fn enforce() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    /// Audit-only, with nothing granted: `--permission-audit`.
    pub fn audit() -> Self {
        Self {
            enabled: true,
            audit: true,
            ..Self::default()
        }
    }

    /// Reads the `--permission*` and `--allow-*` flags from a process argument
    /// list, in either the `--flag=value` or `--flag value` form.
    ///
    /// Unknown flags are skipped rather than rejected: this is a permission
    /// parser, not the CLI's option parser.
    pub fn from_args<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut config = Self::default();
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect();

        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            let (name, inline_value) = match arg.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (arg.as_str(), None),
            };

            // A separate value is the next argument, unless that looks like
            // another flag: Node rejects a missing value rather than eating it.
            let separate = inline_value.is_none();
            let value = match inline_value {
                Some(value) => Some(value.to_string()),
                None => args
                    .get(index + 1)
                    .filter(|next| !next.starts_with('-'))
                    .cloned(),
            };

            match name {
                "--permission" => config.enabled = true,
                "--permission-audit" => {
                    config.enabled = true;
                    config.audit = true;
                }
                "--allow-child-process" => config.allow_child_process = true,
                "--allow-worker" => config.allow_worker = true,
                "--allow-addons" => config.allow_addons = true,
                "--allow-wasi" => config.allow_wasi = true,
                "--allow-net" => config.allow_net = true,
                "--allow-inspector" => config.allow_inspector = true,
                "--allow-fs-read" | "--allow-fs-write" | "--allow-env" => {
                    if let Some(value) = value {
                        if separate {
                            index += 1;
                        }
                        match name {
                            "--allow-fs-read" => config.allow_fs_read.push(value),
                            "--allow-fs-write" => config.allow_fs_write.push(value),
                            _ => config.allow_env.push(value),
                        }
                    }
                }
                _ => {}
            }
            index += 1;
        }

        config
    }
}

/// The permission model other crates check against.
///
/// Shared through [`PermissionShared`]). A check takes no lock and does no path
/// work when the model is disabled, which is the common case.
#[derive(Debug)]
pub struct PermissionModel {
    enabled: bool,
    audit: bool,
    cwd: String,
    fs_read: RwLock<FsScope>,
    fs_write: RwLock<FsScope>,
    booleans: [RwLock<BooleanScope>; BOOLEAN_SCOPES.len()],
    env: RwLock<EnvScope>,
    /// Names the env scope removed from the process environment at startup.
    /// Filled by the env binding so `takeRemovedEnvVarWarning` can answer.
    removed_env_vars: RwLock<BTreeSet<String>>,
    /// Names that already produced a removal warning.
    warned_env_vars: RwLock<BTreeSet<String>>,
}

impl Default for PermissionModel {
    fn default() -> Self {
        Self::disabled()
    }
}

impl PermissionModel {
    /// A model that grants everything and never canonicalises a path.
    pub fn disabled() -> Self {
        Self::with_cwd("", PermissionConfig::default())
    }

    /// A model that denies by default: `--permission` with no grants.
    pub fn enforcing(cwd: impl Into<String>) -> Self {
        Self::with_cwd(cwd, PermissionConfig::enforce())
    }

    /// Builds a model from a configuration, resolving the filesystem grants
    /// against `cwd`.
    ///
    /// Resolution and the "is this an existing directory" probe run here, once,
    /// so [`Self::check_fs_read`] and friends only do a tree lookup.
    pub fn with_cwd(cwd: impl Into<String>, config: PermissionConfig) -> Self {
        let model = Self {
            enabled: config.enabled,
            audit: config.audit,
            cwd: cwd.into(),
            fs_read: RwLock::new(FsScope::new()),
            fs_write: RwLock::new(FsScope::new()),
            booleans: std::array::from_fn(|slot| {
                let kind = if BOOLEAN_SCOPES[slot] == PermissionScope::Net {
                    BooleanKind::AllowRevoke
                } else {
                    BooleanKind::DenyOnly
                };
                RwLock::new(BooleanScope::new(kind))
            }),
            env: RwLock::new(EnvScope::default()),
            removed_env_vars: RwLock::new(BTreeSet::new()),
            warned_env_vars: RwLock::new(BTreeSet::new()),
        };

        if !config.enabled {
            return model;
        }

        model.apply_fs_allow(PermissionScope::FileSystemRead, &config.allow_fs_read);
        model.apply_fs_allow(PermissionScope::FileSystemWrite, &config.allow_fs_write);

        for (granted, scope) in [
            (config.allow_child_process, PermissionScope::ChildProcess),
            (config.allow_worker, PermissionScope::WorkerThreads),
            (config.allow_addons, PermissionScope::Addon),
            (config.allow_wasi, PermissionScope::Wasi),
            (config.allow_net, PermissionScope::Net),
            (config.allow_inspector, PermissionScope::Inspector),
        ] {
            if granted {
                model.grant(scope);
            }
        }

        if !config.allow_env.is_empty() {
            model.apply_env_allow(&config.allow_env);
        }

        model
    }

    /// Builds a model straight from a process argument list.
    pub fn from_args<I, S>(cwd: impl Into<String>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::with_cwd(cwd, PermissionConfig::from_args(args))
    }

    /// Whether any permission is enforced. `false` short-circuits every check.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// `--permission-audit`: checks report a denial but callers must not act on
    /// it.
    pub fn is_audit(&self) -> bool {
        self.audit
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    fn fs_scope(&self, scope: PermissionScope) -> Option<&RwLock<FsScope>> {
        match scope {
            PermissionScope::FileSystemRead => Some(&self.fs_read),
            PermissionScope::FileSystemWrite => Some(&self.fs_write),
            _ => None,
        }
    }

    fn apply_fs_allow(&self, scope: PermissionScope, allow: &[String]) {
        let Some(target) = self.fs_scope(scope) else {
            return;
        };
        let mut guard = lock_write(target);
        for value in allow {
            if value == "*" {
                guard.grant_all();
                return;
            }
            guard.grant(self.expand_grant(value.as_bytes()));
        }
    }

    /// Resolves a grant and adds the wildcard Node adds for an existing
    /// directory.
    fn expand_grant(&self, value: &[u8]) -> Vec<u8> {
        let resolved = path::resolve_path_bytes(self.cwd.as_bytes(), value);
        path::wildcard_if_dir_bytes(&resolved, path::is_existing_directory_bytes(&resolved))
    }

    fn apply_env_allow(&self, allow: &[String]) {
        let mut guard = lock_write(&self.env);
        let mut patterns = Vec::new();
        for value in allow {
            for pattern in value.split(',') {
                if !pattern.is_empty() {
                    patterns.push(pattern.to_string());
                }
            }
        }
        guard.grant(patterns);
    }

    /// Grants a boolean scope, the equivalent of `Permission::Apply`.
    fn grant(&self, scope: PermissionScope) {
        if let Some(slot) = scope.boolean_slot() {
            lock_write(&self.booleans[slot]).grant();
        }
    }

    /// Grants a filesystem path at runtime.
    pub fn grant_fs(&self, scope: PermissionScope, path: &str) {
        match scope {
            PermissionScope::FileSystem => {
                self.grant_fs(PermissionScope::FileSystemRead, path);
                self.grant_fs(PermissionScope::FileSystemWrite, path);
            }
            PermissionScope::FileSystemRead | PermissionScope::FileSystemWrite => {
                let target = match self.fs_scope(scope) {
                    Some(target) => target,
                    None => return,
                };
                lock_write(target).grant(self.expand_grant(path.as_bytes()));
            }
            other => self.grant(other),
        }
    }

    /// `permission.drop(scope, reference)`, the runtime revocation API.
    ///
    /// Dropping a scope without a reference drops every grant in it. Dropping a
    /// reference only works for the exact path that was granted.
    pub fn drop_permission(&self, scope: PermissionScope, reference: &str) {
        match scope {
            PermissionScope::FileSystemRead | PermissionScope::FileSystemWrite => {
                if let Some(target) = self.fs_scope(scope) {
                    self.drop_fs(target, reference);
                }
            }
            PermissionScope::FileSystem => {
                self.drop_permission(PermissionScope::FileSystemRead, reference);
                self.drop_permission(PermissionScope::FileSystemWrite, reference);
            }
            PermissionScope::Env => {
                let mut guard = lock_write(&self.env);
                if reference.is_empty() {
                    guard.drop_scope();
                } else {
                    guard.drop_name(reference);
                }
            }
            other => {
                if let Some(slot) = other.boolean_slot() {
                    lock_write(&self.booleans[slot]).drop_all();
                }
            }
        }
    }

    fn drop_fs(&self, target: &RwLock<FsScope>, reference: &str) {
        let mut guard = lock_write(target);
        if reference.is_empty() {
            guard.drop_all();
            return;
        }
        // A wildcard grant cannot be narrowed; only the whole scope can go.
        if guard.grants_any() {
            return;
        }
        guard.revoke(&self.expand_grant(reference.as_bytes()));
    }

    /// `permission.has(scope)` / `permission.has(scope, reference)`, the answer
    /// `process.permission.has()` returns.
    pub fn has(&self, scope: PermissionScope, reference: Option<&str>) -> bool {
        if !self.enabled {
            return true;
        }
        match scope {
            PermissionScope::FileSystemRead | PermissionScope::FileSystemWrite => {
                let Some(target) = self.fs_scope(scope) else {
                    return false;
                };
                let guard = lock_read(target);
                match reference {
                    None => guard.grants_any(),
                    Some("") => false,
                    Some(reference) => guard.grants_path(&path::resolve_path_bytes(
                        self.cwd.as_bytes(),
                        reference.as_bytes(),
                    )),
                }
            }
            PermissionScope::FileSystem => match reference {
                Some(reference) => {
                    self.has(PermissionScope::FileSystemRead, Some(reference))
                        && self.has(PermissionScope::FileSystemWrite, Some(reference))
                }
                None => {
                    self.has(PermissionScope::FileSystemRead, None)
                        && self.has(PermissionScope::FileSystemWrite, None)
                }
            },
            PermissionScope::Env => {
                let guard = lock_read(&self.env);
                guard.is_granted(reference.unwrap_or_default())
            }
            other => match other.boolean_slot() {
                Some(slot) => lock_read(&self.booleans[slot]).is_granted(),
                None => false,
            },
        }
    }

    /// Checks a filesystem read.
    ///
    /// The only work when the model is disabled is a boolean load; when it is
    /// enabled the path is resolved lexically and looked up in the tree.
    pub fn check_fs_read(&self, path: &str) -> Result<(), AccessDenied> {
        self.check_fs(path.as_bytes(), PermissionScope::FileSystemRead)
    }

    /// Checks a filesystem write.
    pub fn check_fs_write(&self, path: &str) -> Result<(), AccessDenied> {
        self.check_fs(path.as_bytes(), PermissionScope::FileSystemWrite)
    }

    /// [`Self::check_fs_read`] for a path that is not known to be UTF-8.
    ///
    /// The binding layer receives paths as `Buffer`s as often as `string`s, and
    /// Node compares the raw bytes, so the check has to accept them without a
    /// conversion step that could change which grant matches. Only the denial's
    /// `resource` field goes through `String::from_utf8_lossy`, which is what
    /// Node's `ToV8Value` does to a `std::string_view` too.
    pub fn check_fs_read_bytes(&self, path: &[u8]) -> Result<(), AccessDenied> {
        self.check_fs(path, PermissionScope::FileSystemRead)
    }

    /// [`Self::check_fs_write`] for a path that is not known to be UTF-8.
    pub fn check_fs_write_bytes(&self, path: &[u8]) -> Result<(), AccessDenied> {
        self.check_fs(path, PermissionScope::FileSystemWrite)
    }

    fn check_fs(&self, path: &[u8], scope: PermissionScope) -> Result<(), AccessDenied> {
        if !self.enabled {
            return Ok(());
        }
        let granted = match self.fs_scope(scope) {
            Some(target) => {
                lock_read(target).grants_path(&path::resolve_path_bytes(self.cwd.as_bytes(), path))
            }
            None => false,
        };
        if granted {
            Ok(())
        } else {
            Err(AccessDenied::new(
                scope,
                String::from_utf8_lossy(path).into_owned(),
            ))
        }
    }

    /// Checks spawning a child process.
    ///
    /// This is the shape the binding crate contract asks for. Node names the
    /// executable being spawned in the denial's `resource` field, so call sites
    /// that have it should use [`Self::check_child_process_resource`].
    pub fn check_child_process(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::ChildProcess, "")
    }

    /// Checks spawning `resource`, the executable, which Node reports as the
    /// denial's `resource`. `process_wrap.cc` and `spawn_sync.cc` both pass the
    /// file here.
    pub fn check_child_process_resource(&self, resource: &str) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::ChildProcess, resource)
    }

    /// Checks creating a worker. Node reports an empty `resource` here.
    pub fn check_worker(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::WorkerThreads, "")
    }

    /// Checks loading a native addon.
    ///
    /// Node passes an empty `resource` for `process.dlopen()` and the module
    /// name for `internalBinding()` of a linked binding; use
    /// [`Self::check_addon_named`] for the latter.
    pub fn check_addon(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Addon, "")
    }

    /// Checks loading the named addon, which Node reports as the denial's
    /// `resource`.
    pub fn check_addon_named(&self, resource: &str) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Addon, resource)
    }

    /// Checks instantiating WASI.
    pub fn check_wasi(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Wasi, "")
    }

    /// Checks enabling the inspector.
    pub fn check_inspector(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Inspector, "")
    }

    /// [`Self::check_inspector`] with the resource Node names.
    ///
    /// `inspector_agent.cc` passes its own entry-point name (`"StartIoThread"`,
    /// `"WaitForConnect"`) rather than a user-supplied string, so the denial's
    /// `resource` identifies where the inspector was reached from.
    pub fn check_inspector_named(&self, resource: &str) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Inspector, resource)
    }

    /// Checks opening a network server or socket.
    pub fn check_net(&self, resource: &str) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Net, resource)
    }

    /// Checks an FFI call.
    pub fn check_ffi(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::Ffi, "")
    }

    /// Checks using an OpenSSL STORE loader.
    pub fn check_openssl_store(&self) -> Result<(), AccessDenied> {
        self.check_boolean(PermissionScope::OpenSSLStore, "")
    }

    fn check_boolean(&self, scope: PermissionScope, resource: &str) -> Result<(), AccessDenied> {
        if !self.enabled {
            return Ok(());
        }
        let granted = match scope.boolean_slot() {
            Some(slot) => lock_read(&self.booleans[slot]).is_granted(),
            None => false,
        };
        if granted {
            Ok(())
        } else {
            Err(AccessDenied::new(scope, resource))
        }
    }

    /// Records the environment variables the env scope removed from the process
    /// environment at startup, so [`Self::take_removed_env_var_warning`] can
    /// report them. In audit mode nothing is removed, so nothing is recorded.
    pub fn record_removed_env_vars<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut removed = lock_write(&self.removed_env_vars);
        removed.clear();
        if !self.enabled || self.audit {
            return;
        }
        for name in names {
            removed.insert(normalize_env_name(name.as_ref()));
        }
    }

    /// `permission.takeRemovedEnvVarWarning(name)`: true the first time it is
    /// asked about a variable the environment scope removed, false afterwards.
    /// Mirrors `WasRemovedByEnvironmentScrub() && ShouldWarnAboutRemovedEnvVar()`.
    pub fn take_removed_env_var_warning(&self, name: &str) -> bool {
        let name = normalize_env_name(name);
        if !lock_read(&self.removed_env_vars).contains(&name) {
            return false;
        }
        lock_write(&self.warned_env_vars).insert(name)
    }

    /// Whether the environment scope removed `name` at startup, without
    /// consuming the warning.
    pub fn env_var_was_removed(&self, name: &str) -> bool {
        let name = normalize_env_name(name);
        lock_read(&self.removed_env_vars).contains(&name)
    }
}

fn lock_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lock_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A model shared between `internalBinding('permission')` and the enforcement
/// points. `Arc` rather than `Rc` because workers may hold one.
pub type PermissionShared = Arc<PermissionModel>;

#[cfg(test)]
mod tests {
    use super::*;

    fn cwd() -> String {
        "/work/app".to_string()
    }

    #[test]
    fn scope_labels_round_trip() {
        for scope in PermissionScope::GRANTABLE {
            assert_eq!(PermissionScope::from_label(scope.label()), Some(scope));
        }
        assert_eq!(
            PermissionScope::from_label("fs"),
            Some(PermissionScope::FileSystem)
        );
        assert_eq!(PermissionScope::from_label("nope"), None);
        assert_eq!(PermissionScope::from_label(""), None);
    }

    #[test]
    fn disabled_model_grants_everything() {
        let model = PermissionModel::disabled();
        assert!(!model.is_enabled());
        assert!(model.check_fs_read("/etc/passwd").is_ok());
        assert!(model.check_fs_write("/etc/passwd").is_ok());
        assert!(model.check_child_process().is_ok());
        assert!(model.check_worker().is_ok());
        assert!(model.check_addon().is_ok());
        assert!(model.check_wasi().is_ok());
        assert!(model.check_inspector().is_ok());
        assert!(model.check_net("example.com").is_ok());
        assert!(model.check_ffi().is_ok());
        assert!(model.check_openssl_store().is_ok());
        assert!(model.has(PermissionScope::FileSystemRead, Some("/etc/passwd")));
    }

    #[test]
    fn enforcement_denies_by_default() {
        let model = PermissionModel::enforcing(cwd());
        assert!(model.is_enabled());
        assert!(!model.is_audit());
        let denied = model.check_fs_read("/etc/passwd").unwrap_err();
        assert_eq!(denied.code(), "ERR_ACCESS_DENIED");
        assert_eq!(denied.permission(), "FileSystemRead");
        assert_eq!(denied.resource(), "/etc/passwd");
        assert_eq!(
            denied.message(),
            "Access to this API has been restricted. Use --allow-fs-read to manage permissions."
        );
        assert!(model.check_fs_write("/tmp/x").is_err());
        assert!(model.check_child_process().is_err());
        assert!(model.check_worker().is_err());
        assert!(model.check_addon().is_err());
        assert!(model.check_wasi().is_err());
        assert!(model.check_inspector().is_err());
        assert!(model.check_net("example.com").is_err());
        assert!(model.check_ffi().is_err());
        assert!(model.check_openssl_store().is_err());
    }

    #[test]
    fn allow_list_grants_a_path() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["/tmp/rn-permission-does-not-exist".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        // The path does not exist, so no directory wildcard is added and only
        // the exact path is granted.
        assert!(model
            .check_fs_read("/tmp/rn-permission-does-not-exist")
            .is_ok());
        assert!(model
            .check_fs_read("/tmp/rn-permission-does-not-exist/child")
            .is_err());
        assert!(model.check_fs_read("/tmp").is_err());
    }

    #[test]
    fn allow_star_grants_the_whole_scope() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_fs_read("/").is_ok());
        assert!(model.check_fs_read("/etc/passwd").is_ok());
        assert!(model.check_fs_read("/any/where/at/all").is_ok());
        // The bare read scope is granted; write is not, so the composite is not.
        assert!(model.has(PermissionScope::FileSystemRead, None));
        assert!(!model.has(PermissionScope::FileSystemWrite, None));
        assert!(!model.has(PermissionScope::FileSystem, None));
        assert!(model.check_fs_write("/etc/passwd").is_err());
    }

    #[test]
    fn allow_star_on_both_scopes_grants_the_composite() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                allow_fs_write: vec!["*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.has(PermissionScope::FileSystem, None));
        assert!(model.has(PermissionScope::FileSystem, Some("/x")));
        assert!(model.check_fs_write("/x").is_ok());
    }

    #[test]
    fn a_relative_grant_resolves_against_the_working_directory() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["data".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_fs_read("/work/app/data").is_ok());
        assert!(model.check_fs_read("data").is_ok());
        assert!(model.check_fs_read("/work/app/other").is_err());
    }

    #[test]
    fn wildcard_grants_match_like_node() {
        // The expectations here are what Node 22 answers for the same flags;
        // see `tests/parity.rs` for the recorded matrix.
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec![
                    "/a/b/*".to_string(),
                    "/etc/passwd.*".to_string(),
                    "/home/*.js".to_string(),
                ],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_fs_read("/a/b/c").is_ok());
        assert!(model.check_fs_read("/a/b").is_ok());
        assert!(model.check_fs_read("/a/c/c").is_err());
        assert!(model.check_fs_read("/etc/passwd").is_err());
        assert!(model.check_fs_read("/home/another-file.md").is_ok());
    }

    #[test]
    fn boolean_grants_are_per_scope() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_child_process: true,
                allow_worker: true,
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_child_process().is_ok());
        assert!(model.check_worker().is_ok());
        assert!(model.check_addon().is_err());
        assert!(model.check_wasi().is_err());
        assert!(model.has(PermissionScope::ChildProcess, None));
        assert!(!model.has(PermissionScope::Addon, None));
    }

    #[test]
    fn child_process_denial_carries_the_executable() {
        let model = PermissionModel::enforcing(cwd());
        let denied = model
            .check_child_process_resource("/usr/bin/git")
            .unwrap_err();
        assert_eq!(denied.permission(), "ChildProcess");
        assert_eq!(denied.resource(), "/usr/bin/git");
        assert_eq!(
            denied.message(),
            "Access to this API has been restricted. Use --allow-child-process to manage permissions."
        );
    }

    #[test]
    fn worker_denial_has_an_empty_resource() {
        let model = PermissionModel::enforcing(cwd());
        let denied = model.check_worker().unwrap_err();
        assert_eq!(denied.permission(), "WorkerThreads");
        assert_eq!(denied.resource(), "");
        assert_eq!(
            denied.message(),
            "Access to this API has been restricted. Use --allow-worker to manage permissions."
        );
    }

    /// Creates an empty directory under the test temp root and returns its
    /// absolute path. Directory grants depend on the path existing, because
    /// `WildcardIfDir` probes the filesystem once per grant.
    fn temp_dir(name: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("rn-permission-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path.to_str().expect("temp dir is utf-8").to_string()
    }

    #[test]
    fn dropping_a_grant_revokes_exactly_that_path() {
        let first = temp_dir("drop-a");
        let second = temp_dir("drop-b");
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec![format!("{first}/*"), format!("{second}/*")],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_fs_read(&format!("{first}/x")).is_ok());
        assert!(model.check_fs_read(&format!("{second}/x")).is_ok());
        // Dropping the directory that was granted removes the wildcard grant;
        // dropping a path inside it would not, which the next assertion shows.
        model.drop_permission(PermissionScope::FileSystemRead, &first);
        assert!(model.check_fs_read(&format!("{first}/x")).is_err());
        assert!(model.check_fs_read(&format!("{second}/x")).is_ok());
    }

    #[test]
    fn dropping_a_directory_grant_adds_the_same_wildcard_it_was_granted_with() {
        let directory = temp_dir("drop-wildcard");
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec![directory.clone()],
                ..PermissionConfig::enforce()
            },
        );
        // Granting an existing directory covers its contents...
        assert!(model.check_fs_read(&format!("{directory}/file")).is_ok());
        // ...and dropping it as a file path does not match the stored grant.
        model.drop_permission(
            PermissionScope::FileSystemRead,
            &format!("{directory}/file"),
        );
        assert!(model.check_fs_read(&format!("{directory}/file")).is_ok());
        // Dropping the directory itself does.
        model.drop_permission(PermissionScope::FileSystemRead, &directory);
        assert!(model.check_fs_read(&format!("{directory}/file")).is_err());
    }

    #[test]
    fn dropping_a_whole_scope_revokes_every_grant() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_fs_read("/x").is_ok());
        model.drop_permission(PermissionScope::FileSystemRead, "");
        assert!(model.check_fs_read("/x").is_err());
        assert!(!model.has(PermissionScope::FileSystemRead, None));
    }

    #[test]
    fn a_star_grant_cannot_be_narrowed() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        model.drop_permission(PermissionScope::FileSystemRead, "/x");
        assert!(model.check_fs_read("/x").is_ok());
    }

    #[test]
    fn dropping_a_deny_only_scope_denies_it_for_good() {
        // `BooleanPermission<true>::Drop` sets the same `flag_` that `Apply`
        // does, and `is_granted` returns `!flag_`, so a drop revokes the grant
        // and a later apply cannot restore it. That is what
        // `test-permission-drop-child-process.js` and
        // `test-permission-drop-addons.js` assert.
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_child_process: true,
                allow_net: true,
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.check_child_process().is_ok());
        model.drop_permission(PermissionScope::ChildProcess, "");
        assert!(!model.has(PermissionScope::ChildProcess, None));
        assert!(model.check_child_process().is_err());
        // Re-applying cannot grant it again, which is the "deny only" half.
        model.grant_fs(PermissionScope::ChildProcess, "");
        assert!(model.check_child_process().is_err());

        // `net` is an allow-revoke scope: it goes away, and a re-apply grants it
        // again.
        model.drop_permission(PermissionScope::Net, "");
        assert!(!model.has(PermissionScope::Net, None));
        assert!(model.check_net("example.com").is_err());
        model.grant_fs(PermissionScope::Net, "");
        assert!(model.check_net("example.com").is_ok());
    }

    #[test]
    fn has_with_an_empty_reference_is_false() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_fs_read: vec!["*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(!model.has(PermissionScope::FileSystemRead, Some("")));
        assert!(model.has(PermissionScope::FileSystemRead, None));
    }

    #[test]
    fn env_scope_matches_patterns() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_env: vec!["PORT".to_string(), "APP_*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.has(PermissionScope::Env, Some("PORT")));
        assert!(model.has(PermissionScope::Env, Some("APP_TOKEN")));
        // `IsRuntimeEnvironmentDefault(param)` is part of the C++ `is_granted`,
        // so the variables Node reads itself answer `true` without a grant.
        // `test-permission-env-scrub.js` pins exactly this for `TZ`, and the
        // scrub keeps the same list, so `has()` and the surviving environment
        // agree.
        assert!(model.has(PermissionScope::Env, Some("TZ")));
        assert!(model.has(PermissionScope::Env, Some("PATH")));
        assert!(!model.has(PermissionScope::Env, Some("RN_NOT_A_RUNTIME_DEFAULT")));
        assert!(!model.has(PermissionScope::Env, Some("*")));
        assert!(!model.has(PermissionScope::Env, None));
        model.drop_permission(PermissionScope::Env, "PORT");
        assert!(!model.has(PermissionScope::Env, Some("PORT")));
        assert!(model.has(PermissionScope::Env, Some("APP_TOKEN")));
    }

    #[test]
    fn env_allow_accepts_comma_separated_values() {
        let model = PermissionModel::with_cwd(
            cwd(),
            PermissionConfig {
                allow_env: vec!["A,B*".to_string()],
                ..PermissionConfig::enforce()
            },
        );
        assert!(model.has(PermissionScope::Env, Some("A")));
        assert!(model.has(PermissionScope::Env, Some("BETA")));
        assert!(!model.has(PermissionScope::Env, Some("C")));
    }

    #[test]
    fn removed_env_var_warnings_fire_once() {
        let model = PermissionModel::enforcing(cwd());
        model.record_removed_env_vars(["HTTP_PROXY", "NO_PROXY"]);
        assert!(model.env_var_was_removed("HTTP_PROXY"));
        assert!(model.take_removed_env_var_warning("HTTP_PROXY"));
        assert!(!model.take_removed_env_var_warning("HTTP_PROXY"));
        assert!(!model.take_removed_env_var_warning("PATH"));
    }

    #[test]
    fn audit_mode_removes_nothing() {
        let model = PermissionModel::with_cwd(cwd(), PermissionConfig::audit());
        model.record_removed_env_vars(["HTTP_PROXY"]);
        assert!(!model.env_var_was_removed("HTTP_PROXY"));
    }

    #[test]
    fn parses_flags_in_both_forms() {
        let config = PermissionConfig::from_args([
            "--permission",
            "--allow-fs-read=/tmp/*",
            "--allow-fs-read",
            "/var/*",
            "--allow-fs-write=/out",
            "--allow-child-process",
            "--allow-worker",
            "--allow-addons",
            "--allow-wasi",
            "--allow-inspector",
            "--allow-net",
            "--unrelated",
        ]);
        assert!(config.enabled);
        assert!(!config.audit);
        assert_eq!(config.allow_fs_read, vec!["/tmp/*", "/var/*"]);
        assert_eq!(config.allow_fs_write, vec!["/out"]);
        assert!(config.allow_child_process);
        assert!(config.allow_worker);
        assert!(config.allow_addons);
        assert!(config.allow_wasi);
        assert!(config.allow_inspector);
        assert!(config.allow_net);
    }

    #[test]
    fn a_flag_value_cannot_swallow_the_next_flag() {
        let config =
            PermissionConfig::from_args(["--permission", "--allow-fs-read", "--allow-net"]);
        assert!(config.allow_fs_read.is_empty());
        assert!(config.allow_net);
    }

    #[test]
    fn audit_mode_is_enabled_but_marked() {
        let config = PermissionConfig::from_args(["--permission-audit"]);
        assert!(config.enabled);
        assert!(config.audit);
        let model = PermissionModel::with_cwd(cwd(), config);
        assert!(model.is_enabled());
        assert!(model.is_audit());
    }

    #[test]
    fn no_permission_flag_means_a_disabled_model() {
        let config = PermissionConfig::from_args(["--allow-fs-read=/tmp"]);
        assert!(!config.enabled);
        let model = PermissionModel::with_cwd(cwd(), config);
        assert!(!model.is_enabled());
        assert!(model.check_fs_read("/etc/passwd").is_ok());
    }

    #[test]
    fn model_builds_from_a_process_argument_list() {
        let model = PermissionModel::from_args(cwd(), ["--permission", "--allow-fs-read=/tmp/*"]);
        assert!(model.is_enabled());
        assert!(model.check_fs_read("/tmp/x").is_ok());
        assert!(model.check_fs_read("/etc/passwd").is_err());
    }
}
