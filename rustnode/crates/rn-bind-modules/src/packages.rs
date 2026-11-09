//! Walking the filesystem for `package.json`, and the per-process cache.
//!
//! Node keeps three separate walks in `src/node_modules.cc`, and they are not
//! interchangeable — choosing the wrong one changes which `package.json` a
//! module is judged against, which silently changes whether its code is parsed
//! as CommonJS or as an ES module:
//!
//! | member | walk | stops at |
//! | --- | --- | --- |
//! | `getNearestParentPackageJSON`, `getNearestParentPackageJSONType` | parent of the given path, upwards | the root, or a directory named `node_modules` |
//! | `getPackageScopeConfig`, `getPackageType` | `package.json` beside the URL, then `../package.json` | the root, or `node_modules/package.json` |
//! | `getRootPackageJSON` | upwards through `node_modules`, collecting private packages | the root; a non-private package wins |
//!
//! The cache matters too. Node caches by *path across calls and never
//! invalidates*, so a `package.json` read once keeps its value for the life of
//! the process even if the file changes on disk. That is observable, so it is
//! reproduced rather than "improved": code that rewrites `package.json` and
//! then reloads depends on getting the stale answer.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;

use crate::json::{self, PackageFields};

/// Names `"type"` reports when no `package.json` supplied one.
pub const TYPE_NONE: &str = "none";

/// A `package.json` that exists and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageConfig {
    /// Fields the loader cares about.
    pub fields: PackageFields,
    /// Path of the file that was read, in the form the caller passed it.
    pub file_path: String,
}

impl PackageConfig {
    /// `"commonjs"`, `"module"`, or `"none"`.
    pub fn type_field(&self) -> &str {
        &self.fields.type_field
    }
}

/// Why a `package.json` could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The file is present but is not valid JSON, or a field has the wrong
    /// type. Node reports `ERR_INVALID_PACKAGE_CONFIG`.
    Invalid,
    /// The file exists but could not be read for a reason other than absence,
    /// not-a-directory or is-a-directory. Node reports
    /// `ERR_INVALID_PACKAGE_CONFIG` with the errno text.
    Unreadable { errno: i32 },
}

/// One read of `package.json` at a known path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The file is there and parsed.
    Found(PackageConfig),
    /// No such file. Cached, so the filesystem is not asked twice.
    Absent,
}

/// Per-context `package.json` cache.
///
/// Node hangs this off `BindingData`, which is per-realm. rustnode installs a
/// namespace once per isolate, so one cache per install is the closest
/// equivalent: two realms in one isolate share it, and two isolates do not.
#[derive(Debug, Default)]
pub struct PackageCache {
    entries: HashMap<String, Lookup>,
}

impl PackageCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads `package.json` at `path`, caching the answer.
    pub fn read(&mut self, path: &str) -> Result<Lookup, ReadError> {
        if let Some(cached) = self.entries.get(path) {
            return Ok(cached.clone());
        }
        let lookup = match load(path)? {
            Some(config) => Lookup::Found(config),
            None => Lookup::Absent,
        };
        self.entries.insert(path.to_string(), lookup.clone());
        Ok(lookup)
    }

    /// Number of cached paths, for tests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

thread_local! {
    /// The cache the installed namespace uses.
    ///
    /// V8 objects cannot be stored across a `&mut scope` boundary without a
    /// slot, and this cache holds no V8 state, so a thread-local is enough.
    /// Each isolate runs on one thread.
    static CACHE: RefCell<PackageCache> = RefCell::new(PackageCache::new());
}

/// Runs `body` with the installed namespace's cache.
pub fn with_cache<T>(body: impl FnOnce(&mut PackageCache) -> T) -> T {
    CACHE.with(|cache| body(&mut cache.borrow_mut()))
}

/// Drops every cached answer. Only tests need this; Node never invalidates.
pub fn clear_cache() {
    CACHE.with(|cache| cache.borrow_mut().entries.clear());
}

/// Reads one `package.json` without consulting the cache.
///
/// `Ok(None)` means "no file here", which is the only outcome the walks treat
/// as a normal miss. Everything else becomes an error, because Node decided
/// that a `package.json` which exists but cannot be read must not look absent:
/// doing so would silently drop `exports` or `type` and could resolve a
/// specifier to a different file.
fn load(path: &str) -> Result<Option<PackageConfig>, ReadError> {
    match std::fs::read(path) {
        Ok(bytes) => match json::parse(&bytes) {
            Ok(fields) => Ok(Some(PackageConfig {
                fields,
                file_path: path.to_string(),
            })),
            Err(_) => Err(ReadError::Invalid),
        },
        Err(error) => match error.kind() {
            // Node accepts these three errnos as "no package config here"; a
            // directory named `package.json` is included because reading it
            // fails with EISDIR.
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => Ok(None),
            _ => {
                let errno = error.raw_os_error().unwrap_or(libc::EIO);
                if errno == libc::EISDIR {
                    Ok(None)
                } else {
                    Err(ReadError::Unreadable { errno })
                }
            }
        },
    }
}

/// `BindingData::NormalizePath`.
///
/// On Unix this is almost a no-op: `ToNamespacedPath` only rewrites paths on
/// Windows, so the walk operates on the caller's string as given, and a relative
/// path stays relative (and therefore resolves against the working directory by
/// virtue of the filesystem calls). The one thing it does preserve is a trailing
/// separator, which changes where the walk starts.
fn normalize_path(raw: &str) -> String {
    raw.to_string()
}

/// `std::filesystem::path::parent_path`, which is not `Path::parent`.
///
/// The difference matters: a trailing separator means "this path names a
/// directory", so `parent_path("/a/b/")` is `/a/b`, while Rust's `Path::parent`
/// answers `/a`. Getting this wrong makes `getNearestParentPackageJSON("/a/b/")`
/// skip the `package.json` in `/a/b`.
fn parent_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        // `/`, `///`, or the empty path: the root is its own parent, and the
        // empty path is too, which is what terminates the walk.
        return if path.is_empty() {
            String::new()
        } else {
            "/".to_string()
        };
    }
    if trimmed.len() != path.len() {
        return trimmed.to_string();
    }
    match trimmed.rfind('/') {
        // `/a` -> `/`
        Some(0) => "/".to_string(),
        Some(index) => trimmed[..index].to_string(),
        // `a` -> ``
        None => String::new(),
    }
}

/// `std::filesystem::path::filename`.
///
/// Empty when the path ends in a separator, because then it names a directory
/// rather than an entry in one.
fn file_name(path: &str) -> &str {
    if path.ends_with('/') {
        return "";
    }
    match path.rfind('/') {
        Some(index) => &path[index + 1..],
        None => path,
    }
}

/// `BindingData::TraverseParent`.
///
/// Starts at the *parent* of `check_path`, so a trailing separator is
/// significant: `getNearestParentPackageJSON("/a/b/")` first looks in `/a/b`,
/// while the same path without the separator starts in `/a`.
pub fn nearest_parent_package_json(
    cache: &mut PackageCache,
    check_path: &str,
) -> Result<Option<PackageConfig>, ReadError> {
    let mut current = normalize_path(check_path);
    loop {
        let parent = parent_path(&current);
        if parent == current {
            // The parent is the root or the empty path; nothing above to look
            // in. Node breaks here rather than testing `/package.json`, so a
            // `package.json` in `/` is not found by this walk.
            return Ok(None);
        }
        if file_name(&parent) == "node_modules" {
            return Ok(None);
        }
        let candidate = format!("{parent}/package.json");
        if let Lookup::Found(config) = cache.read(&candidate)? {
            return Ok(Some(config));
        }
        current = parent;
    }
}

/// `BindingData::FindNodeModulesPackage`.
///
/// Walks to the root remembering the last two components, so when it reaches a
/// directory named `node_modules` it knows which package below it owns
/// `check_path`. Scoped packages are one level deeper.
pub fn root_package_json(
    cache: &mut PackageCache,
    check_path: &str,
) -> Result<Option<PackageConfig>, ReadError> {
    let mut current = normalize_path(check_path);
    let mut child = String::new();
    let mut grandchild = String::new();
    let mut innermost: Option<PackageConfig> = None;

    loop {
        let parent = parent_path(&current);
        if parent == current {
            // Reached the filesystem root.
            break;
        }
        if file_name(&current) == "node_modules" {
            let child_name = file_name(&child);
            let package_root = if child_name.starts_with('@') {
                &grandchild
            } else {
                &child
            };
            if package_root.is_empty() {
                // The path points at `node_modules` itself, or at a bare scope
                // directory, rather than into a package.
                return Ok(None);
            }
            let candidate = format!("{package_root}/package.json");
            if let Lookup::Found(config) = cache.read(&candidate)? {
                if !config.fields.is_private.unwrap_or(false) {
                    // A publishable package encloses the file.
                    return Ok(None);
                }
                if innermost.is_none() {
                    innermost = Some(config);
                }
            }
            // A directory under `node_modules` with no `package.json` is not a
            // package (pnpm's `.pnpm` store is the usual example); keep going.
        }
        grandchild = std::mem::take(&mut child);
        child = current;
        current = parent;
    }

    Ok(innermost)
}

/// `GetPackageScopeConfig`, both variants.
///
/// `return_only_type` selects `getPackageType`, which answers `"module"`,
/// `"commonjs"` or `"none"` and gives up on absence, while the full form
/// reports the `PackageConfig` or the path it would have read.
#[derive(Debug)]
pub enum ScopeResult {
    /// A `package.json` was found.
    Found(PackageConfig),
    /// Nothing was found; this is the path of the `package.json` that the walk
    /// started from and that does not exist.
    Absent { path: String },
}

impl ScopeResult {
    /// The `type` value to report, or `None` when nothing was found.
    pub fn type_field(&self) -> Option<&str> {
        match self {
            ScopeResult::Found(config) => Some(config.type_field()),
            ScopeResult::Absent { .. } => None,
        }
    }
}

/// Walks from `href`'s directory towards the root looking for `package.json`.
pub fn package_scope(cache: &mut PackageCache, href: &str) -> Result<ScopeResult, ScopeError> {
    let start = crate::url::parse_file_url(href).map_err(ScopeError::Url)?;
    let mut current = crate::url::resolve_reference(&start.pathname, "./package.json");
    // The walk stops before reading a `package.json` that belongs to
    // `node_modules` itself: a directory inside a dependency never inherits
    // the type of the dependencies directory.
    const NODE_MODULES: &str = "/node_modules/package.json";

    loop {
        if current.ends_with(NODE_MODULES) {
            break;
        }
        if let Lookup::Found(config) = cache.read(&current)? {
            return Ok(ScopeResult::Found(config));
        }
        let next = crate::url::resolve_reference(&current, "../package.json");
        if next == current {
            // Terminates at the root, where `../package.json` is a fixed
            // point. Checking for `/package.json` directly would be wrong on
            // Windows, which is why Node compares pathnames.
            break;
        }
        current = next;
    }

    Ok(ScopeResult::Absent { path: current })
}

/// Why a scope walk failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// The argument was not a usable `file:` URL.
    Url(crate::url::UrlError),
    /// A `package.json` along the walk exists but could not be used.
    Read(ReadError),
}

impl From<ReadError> for ScopeError {
    fn from(error: ReadError) -> Self {
        ScopeError::Read(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// A temporary directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "rn-bind-modules-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(&base).expect("temp dir");
            Self(base)
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.0.join(relative)
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent dirs");
            }
            fs::write(&path, contents).expect("write");
            path
        }

        fn as_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cache() -> PackageCache {
        PackageCache::new()
    }

    #[test]
    fn reads_a_package_json_without_a_type() {
        let dir = TempDir::new("plain");
        let path = dir.write("package.json", r#"{"name":"pkg","main":"index.js"}"#);
        let mut cache = cache();
        let Lookup::Found(config) = cache.read(&path.to_string_lossy()).expect("reads") else {
            panic!("expected a package.json");
        };
        assert_eq!(config.fields.name.as_deref(), Some("pkg"));
        assert_eq!(config.fields.main.as_deref(), Some("index.js"));
        assert_eq!(config.type_field(), "none");
    }

    #[test]
    fn reads_a_package_json_with_type_module() {
        let dir = TempDir::new("esm");
        let path = dir.write("package.json", r#"{"name":"pkg","type":"module"}"#);
        let mut cache = cache();
        let Lookup::Found(config) = cache.read(&path.to_string_lossy()).expect("reads") else {
            panic!("expected a package.json");
        };
        assert_eq!(config.type_field(), "module");
    }

    #[test]
    fn malformed_package_json_is_an_error_not_absence() {
        let dir = TempDir::new("bad");
        let path = dir.write("package.json", r#"{"name":broken"#);
        let mut cache = cache();
        assert_eq!(cache.read(&path.to_string_lossy()), Err(ReadError::Invalid));
    }

    #[test]
    fn a_directory_named_package_json_is_absent() {
        let dir = TempDir::new("pkgdir");
        fs::create_dir_all(dir.path("package.json")).expect("mkdir");
        let mut cache = cache();
        assert_eq!(
            cache.read(&dir.path("package.json").to_string_lossy()),
            Ok(Lookup::Absent)
        );
    }

    #[test]
    fn absence_is_cached_so_a_later_file_is_not_seen() {
        // This is Node's behaviour, not an accident of this implementation:
        // the negative entry exists precisely so the filesystem is not asked
        // twice, and it is never invalidated.
        let dir = TempDir::new("negative");
        let path = dir.path("package.json");
        let mut cache = cache();
        assert_eq!(cache.read(&path.to_string_lossy()), Ok(Lookup::Absent));
        fs::write(&path, r#"{"name":"created"}"#).expect("write");
        assert_eq!(cache.read(&path.to_string_lossy()), Ok(Lookup::Absent));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_found_entry_is_cached_so_edits_are_not_seen() {
        let dir = TempDir::new("stale");
        let path = dir.write("package.json", r#"{"name":"before"}"#);
        let mut cache = cache();
        let Lookup::Found(first) = cache.read(&path.to_string_lossy()).expect("reads") else {
            panic!("expected a package.json");
        };
        assert_eq!(first.fields.name.as_deref(), Some("before"));
        fs::write(&path, r#"{"name":"after","type":"module"}"#).expect("write");
        let Lookup::Found(second) = cache.read(&path.to_string_lossy()).expect("reads") else {
            panic!("expected a package.json");
        };
        assert_eq!(second.fields.name.as_deref(), Some("before"));
        assert_eq!(second.type_field(), "none");
    }

    #[test]
    fn nearest_parent_finds_a_package_json_above_the_file() {
        let dir = TempDir::new("nearest");
        dir.write("package.json", r#"{"type":"module"}"#);
        let check = dir.path("sub/dir/x.js");
        fs::create_dir_all(dir.path("sub/dir")).expect("dirs");
        let mut cache = cache();
        let found = nearest_parent_package_json(&mut cache, &check.to_string_lossy())
            .expect("walks")
            .expect("finds a package.json");
        assert_eq!(found.type_field(), "module");
    }

    #[test]
    fn nearest_parent_starts_at_the_parent_of_the_given_path() {
        // With a trailing separator the path itself is the first directory
        // examined; without it, the walk starts one level higher.
        let dir = TempDir::new("trailing");
        dir.write("package.json", r#"{"name":"outer"}"#);
        dir.write("inner/package.json", r#"{"name":"inner"}"#);
        let inner = dir.path("inner");
        let mut cache = cache();

        let with_separator =
            nearest_parent_package_json(&mut cache, &format!("{}/", inner.display()))
                .expect("walks")
                .expect("finds the inner package.json");
        assert_eq!(with_separator.fields.name.as_deref(), Some("inner"));

        let without_separator =
            nearest_parent_package_json(&mut cache, &inner.display().to_string())
                .expect("walks")
                .expect("finds the outer package.json");
        assert_eq!(without_separator.fields.name.as_deref(), Some("outer"));
    }

    #[test]
    fn nearest_parent_stops_at_node_modules() {
        let dir = TempDir::new("boundary");
        dir.write("package.json", r#"{"type":"module"}"#);
        let check = dir.path("node_modules/dep/sub/x.js");
        fs::create_dir_all(dir.path("node_modules/dep/sub")).expect("dirs");
        let mut cache = cache();
        assert_eq!(
            nearest_parent_package_json(&mut cache, &check.to_string_lossy()).expect("walks"),
            None,
            "a path inside node_modules must not inherit the enclosing package type"
        );
    }

    #[test]
    fn nearest_parent_at_the_root_is_absent() {
        let mut cache = cache();
        assert_eq!(
            nearest_parent_package_json(&mut cache, "/x.js").expect("walks"),
            None
        );
    }

    #[test]
    fn scope_config_walks_up_from_a_url() {
        let dir = TempDir::new("scope");
        dir.write("package.json", r#"{"name":"scope-pkg","type":"module"}"#);
        fs::create_dir_all(dir.path("lib/deep")).expect("dirs");
        let url = format!("file://{}/lib/deep/x.js", dir.as_str());
        let mut cache = cache();
        let ScopeResult::Found(config) = package_scope(&mut cache, &url).expect("walks") else {
            panic!("expected a package.json");
        };
        assert_eq!(config.fields.name.as_deref(), Some("scope-pkg"));
        assert_eq!(config.type_field(), "module");
    }

    #[test]
    fn scope_config_stops_at_node_modules() {
        let dir = TempDir::new("scope-boundary");
        dir.write("package.json", r#"{"type":"module"}"#);
        fs::create_dir_all(dir.path("node_modules/dep/lib")).expect("dirs");
        let url = format!("file://{}/node_modules/dep/lib/x.js", dir.as_str());
        let mut cache = cache();
        let ScopeResult::Absent { path } = package_scope(&mut cache, &url).expect("walks") else {
            panic!("the walk must not read node_modules/package.json");
        };
        assert!(
            path.ends_with("/node_modules/package.json"),
            "expected the node_modules sentinel, got {path}"
        );
    }

    #[test]
    fn scope_config_at_the_root_reports_the_root_package_json() {
        let mut cache = cache();
        let ScopeResult::Absent { path } =
            package_scope(&mut cache, "file:///x.js").expect("walks")
        else {
            panic!("there is no package.json at /");
        };
        assert_eq!(path, "/package.json");
    }

    #[test]
    fn scope_config_rejects_a_non_file_url() {
        let mut cache = cache();
        assert_eq!(
            package_scope(&mut cache, "https://example.com/x.js").unwrap_err(),
            ScopeError::Url(crate::url::UrlError::Invalid)
        );
    }

    #[test]
    fn root_package_json_finds_a_private_package_in_node_modules() {
        let dir = TempDir::new("rootprivate");
        dir.write(
            "node_modules/dep/package.json",
            r#"{"name":"dep","private":true}"#,
        );
        let check = dir.path("node_modules/dep/lib/x.js");
        fs::create_dir_all(dir.path("node_modules/dep/lib")).expect("dirs");
        let mut cache = cache();
        let found = root_package_json(&mut cache, &check.to_string_lossy())
            .expect("walks")
            .expect("finds the private package.json");
        assert_eq!(found.fields.name.as_deref(), Some("dep"));
    }

    #[test]
    fn root_package_json_refuses_a_publishable_package() {
        // A non-private package encloses the file, so there is no root
        // package.json to report.
        let dir = TempDir::new("rootpublic");
        dir.write("node_modules/dep/package.json", r#"{"name":"dep"}"#);
        let check = dir.path("node_modules/dep/lib/x.js");
        fs::create_dir_all(dir.path("node_modules/dep/lib")).expect("dirs");
        let mut cache = cache();
        assert_eq!(
            root_package_json(&mut cache, &check.to_string_lossy()).expect("walks"),
            None
        );
    }

    #[test]
    fn root_package_json_handles_scoped_packages() {
        let dir = TempDir::new("rootscoped");
        dir.write(
            "node_modules/@scope/dep/package.json",
            r#"{"name":"@scope/dep","private":true}"#,
        );
        let check = dir.path("node_modules/@scope/dep/lib/x.js");
        fs::create_dir_all(dir.path("node_modules/@scope/dep/lib")).expect("dirs");
        let mut cache = cache();
        let found = root_package_json(&mut cache, &check.to_string_lossy())
            .expect("walks")
            .expect("finds the scoped package.json");
        assert_eq!(found.fields.name.as_deref(), Some("@scope/dep"));
    }

    #[test]
    fn root_package_json_is_absent_without_node_modules() {
        let dir = TempDir::new("rootnone");
        dir.write("package.json", r#"{"name":"top"}"#);
        let check = dir.path("lib/x.js");
        fs::create_dir_all(dir.path("lib")).expect("dirs");
        let mut cache = cache();
        assert_eq!(
            root_package_json(&mut cache, &check.to_string_lossy()).expect("walks"),
            None
        );
    }
}
