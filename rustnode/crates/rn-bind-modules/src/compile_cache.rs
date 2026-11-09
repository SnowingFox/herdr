//! The on-disk module compile cache.
//!
//! Node's cache has two separate concerns and this module keeps them apart the
//! same way `src/compile_cache.cc` does:
//!
//! * **Storage.** A cache directory holds one file per source file, named by a
//!   CRC-32 of the file path and cached-code type. Each file is a five-word
//!   header followed by the payload. The header is what makes a stale or
//!   truncated file a cache *miss* rather than a crash:
//!
//!   ```text
//!   [u32] magic
//!   [u32] source size
//!   [u32] payload size
//!   [u32] source hash
//!   [u32] payload hash
//!   ```
//!
//! * **Compilation.** Asking V8 for cached data, and handing it back, is the
//!   caller's job in Node: `getCompileCacheEntry` returns an `{ external }`
//!   handle that `saveCompileCacheEntry` later uses. The `v8` crate this
//!   runtime links exposes no way to build or consume
//!   `ScriptCompiler::CachedData` for a script, so the two V8-blob members are
//!   declared deferred in the crate root rather than faked.
//!
//! What remains is genuinely useful and is implemented in full:
//!
//! * enabling the cache and reporting its directory, including the
//!   version/arch/V8/uid subdirectory Node uses so incompatible caches never
//!   share a directory;
//! * the TypeScript transpile cache, whose payloads are plain text rather than
//!   V8 blobs — `lib/internal/modules/typescript.js` is the only consumer of
//!   `getCompileCacheEntry`/`saveCompileCacheEntry`, and it stores exactly that;
//! * flushing to disk with the write-then-rename Node relies on, so a reader
//!   never sees a half-written cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Node version this crate reports, matching `tools/node-pin.toml`.
pub const NODE_VERSION: &str = "28.0.0";

/// Status values, in `COMPILE_CACHE_STATUS` order.
///
/// `lib/internal/modules/helpers.js` builds its `compileCacheStatus` object by
/// walking this array and taking each entry's index as the value, so the order
/// is the contract, not a convenience.
pub const COMPILE_CACHE_STATUS: &[&str] = &["FAILED", "ENABLED", "ALREADY_ENABLED", "DISABLED"];

/// Cached-code types, matching `CACHED_CODE_TYPES`.
pub const CACHED_CODE_TYPES: &[(&str, i32)] = &[
    ("kCommonJS", 0),
    ("kESM", 1),
    ("kStrippedTypeScript", 2),
    ("kWasm", 3),
];

/// `CachedCodeType::kStrippedTypeScript`, the type the transpile cache uses.
pub const K_STRIPPED_TYPESCRIPT: i32 = 2;

/// Cache-file magic, from `src/compile_cache.cc`.
const MAGIC: u32 = 0x8adf_dbb2;

/// Header words before the payload.
const HEADER_WORDS: usize = 5;

/// The enable result Node returns as `[status, message, directory]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableResult {
    /// Index into [`COMPILE_CACHE_STATUS`].
    pub status: u8,
    /// Set only when the status is `FAILED`.
    pub message: String,
    /// The base directory, without the version subdirectory.
    pub directory: String,
}

impl EnableResult {
    fn failed(message: impl Into<String>) -> Self {
        Self {
            status: 0,
            message: message.into(),
            directory: String::new(),
        }
    }
}

/// One entry in the in-memory store.
#[derive(Debug, Clone)]
struct Entry {
    /// Source hash, so a changed file invalidates the entry.
    code_hash: u32,
    /// Source size, written into the cache file header.
    code_size: u32,
    /// Cached code, already validated against the on-disk header.
    cache: Option<Vec<u8>>,
    /// Whether `cache` changed and needs writing.
    refreshed: bool,
    persisted: bool,
}

/// The cache as a whole.
#[derive(Debug, Default)]
pub struct CompileCache {
    /// Base directory as the caller gave it, made absolute.
    base_directory: String,
    /// Directory including the version tag, where cache files live.
    cache_directory: String,
    enabled: bool,
    /// Set when the cache is only to be read, so nothing is written.
    read_only: bool,
    /// Keyed by cache key, a CRC-32 of path and type.
    entries: HashMap<u32, Entry>,
}

impl CompileCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an entry can be produced at all.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The tagged directory, or `""` when disabled.
    ///
    /// `getCompileCacheDir` reports the *tagged* directory, because that is
    /// where a caller would look, while `enableCompileCache` reports the base.
    /// Node does the same and the difference is visible from JavaScript.
    pub fn tagged_directory(&self) -> &str {
        if self.enabled {
            &self.cache_directory
        } else {
            ""
        }
    }

    /// Enables the cache, creating the tagged directory.
    ///
    /// `portable` drops the uid from the tag so a cache can be shipped between
    /// users. `read_only` requires the directory to exist and suppresses every
    /// write.
    pub fn enable(&mut self, directory: &str, portable: bool, read_only: bool) -> EnableResult {
        // Node checks this first and refuses even to look at the directory, so
        // a user who disabled the cache never sees a write.
        let disabled_by_env = std::env::var_os("NODE_DISABLE_COMPILE_CACHE").is_some();
        self.enable_with_env(directory, portable, read_only, disabled_by_env)
    }

    /// [`Self::enable`] with the environment check supplied.
    ///
    /// Split out because tests run in one process and cannot safely mutate the
    /// environment, and because a test that wants to exercise a real cache must
    /// not inherit `NODE_DISABLE_COMPILE_CACHE` from the machine it runs on.
    pub fn enable_with_env(
        &mut self,
        directory: &str,
        portable: bool,
        read_only: bool,
        disabled_by_env: bool,
    ) -> EnableResult {
        if self.enabled {
            return EnableResult {
                status: 2,
                message: String::new(),
                directory: self.cache_directory.clone(),
            };
        }
        if disabled_by_env {
            return EnableResult {
                status: 3,
                message: "Disabled by NODE_DISABLE_COMPILE_CACHE".to_string(),
                directory: String::new(),
            };
        }

        let base = absolute(directory);
        let cache_directory = format!("{base}/{}", cache_version_tag(portable));

        if read_only {
            if !Path::new(&cache_directory).is_dir() {
                return EnableResult::failed(format!(
                    "Cache directory does not exist (read-only): {cache_directory}"
                ));
            }
        } else if let Err(error) = std::fs::create_dir_all(&cache_directory) {
            // `create_dir_all` on an existing directory is a success, which is
            // what Node's `MKDirpSync` + `UV_EEXIST` handling amounts to.
            return EnableResult::failed(format!("Cannot create cache directory: {error}"));
        }

        self.base_directory = base;
        self.cache_directory = cache_directory;
        self.enabled = true;
        self.read_only = read_only;
        EnableResult {
            status: 1,
            message: String::new(),
            directory: self.base_directory.clone(),
        }
    }

    /// `getCompileCacheEntry`: looks up cached code for `source`.
    ///
    /// Returns the cache key, which stands in for the `external` handle Node
    /// hands back, plus the payload when an on-disk entry validates.
    pub fn get_or_insert(
        &mut self,
        source: &[u8],
        filename: &str,
        code_type: i32,
    ) -> Option<(u32, Option<String>)> {
        if !self.enabled {
            return None;
        }
        let key = cache_key(filename, code_type);
        let code_hash = crc32(source);
        let code_size = source.len() as u32;

        let stale = match self.entries.get(&key) {
            Some(entry) if entry.code_hash == code_hash => {
                let cached = entry
                    .cache
                    .as_ref()
                    .and_then(|bytes| String::from_utf8(bytes.clone()).ok());
                return Some((key, cached));
            }
            // A mismatch means the source changed and the entry is discarded.
            Some(_) => true,
            None => false,
        };
        let _ = stale;

        let cache = read_cache_file(&self.cache_directory, key, code_hash, code_size);
        let cached = cache
            .as_ref()
            .and_then(|bytes| String::from_utf8(bytes.clone()).ok());
        self.entries.insert(
            key,
            Entry {
                code_hash,
                code_size,
                cache,
                refreshed: false,
                persisted: false,
            },
        );
        Some((key, cached))
    }

    /// `saveCompileCacheEntry` for the plain-text payloads Node stores.
    pub fn save(&mut self, key: u32, payload: &str) {
        if !self.enabled || self.read_only {
            return;
        }
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.cache = Some(payload.as_bytes().to_vec());
            entry.refreshed = true;
        }
    }

    /// Writes every refreshed entry, then empties the store.
    ///
    /// The returned count is how many files were written, which makes a silent
    /// failure visible in tests instead of only in a debug log.
    pub fn flush(&mut self) -> usize {
        if !self.enabled || self.read_only || self.cache_directory.is_empty() {
            return 0;
        }
        let mut written = 0;
        // Collected first so the file I/O does not hold a mutable borrow of a
        // map that a later `persisted` update needs.
        let pending: Vec<(u32, Entry)> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.refreshed && !entry.persisted)
            .map(|(key, entry)| (*key, entry.clone()))
            .collect();
        for (key, entry) in pending {
            let Some(cache) = &entry.cache else {
                continue;
            };
            if write_cache_file(
                &self.cache_directory,
                key,
                entry.code_hash,
                entry.code_size,
                cache,
            ) {
                if let Some(stored) = self.entries.get_mut(&key) {
                    stored.persisted = true;
                }
                written += 1;
            }
        }
        self.entries.clear();
        written
    }
}

thread_local! {
    /// The process-wide cache, matching the one handler per environment Node
    /// keeps on `Environment`.
    static CACHE: std::cell::RefCell<CompileCache> = std::cell::RefCell::new(CompileCache::new());
}

/// Runs `body` with the compile cache.
pub fn with_cache<T>(body: impl FnOnce(&mut CompileCache) -> T) -> T {
    CACHE.with(|cache| body(&mut cache.borrow_mut()))
}

/// Resets the cache. Tests only: the runtime enables it once.
pub fn reset_cache() {
    CACHE.with(|cache| *cache.borrow_mut() = CompileCache::new());
}

/// Node's cache-directory tag: version, arch, V8 tag, and uid.
fn cache_version_tag(portable: bool) -> String {
    let tag = format!(
        "v{}-{}-{}",
        NODE_VERSION,
        std::env::consts::ARCH,
        hex32(v8_cache_tag())
    );
    if portable {
        tag
    } else {
        // SAFETY: `getuid` takes no arguments and cannot fail.
        format!("{tag}-{}", unsafe { libc::getuid() })
    }
}

/// Stands in for `ScriptCompiler::CachedDataVersionTag`.
///
/// The `v8` crate does not expose that call, and the value only has to
/// distinguish incompatible caches, so it is derived from the pinned V8 version
/// instead. Two runtimes with different V8 versions therefore never share a
/// cache directory, which is the property that matters.
fn v8_cache_tag() -> u32 {
    let mut hash = 0u32;
    for byte in crate::V8_VERSION.as_bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(u32::from(*byte));
    }
    hash
}

/// Cache key: `crc32(type_byte ++ filename)`.
///
/// `CachedCodeType` is one byte wide, so only the low byte of `code_type`
/// participates. The JavaScript layer passes small integers read from the
/// `cachedCodeTypes` object.
pub fn cache_key(filename: &str, code_type: i32) -> u32 {
    let state = crc32(&[(code_type & 0xff) as u8]);
    crc32_seeded(state, filename.as_bytes())
}

/// Reads one cache file, validating every header field.
fn read_cache_file(directory: &str, key: u32, code_hash: u32, code_size: u32) -> Option<Vec<u8>> {
    let bytes = std::fs::read(format!("{directory}/{}", hex32(key))).ok()?;
    if bytes.len() < HEADER_WORDS * 4 {
        return None;
    }
    let header: Vec<u32> = bytes[..HEADER_WORDS * 4]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .collect();
    if header[0] != MAGIC {
        return None;
    }
    if header[1] != code_size || header[3] != code_hash {
        // The source changed since this cache was written.
        return None;
    }
    let payload = &bytes[HEADER_WORDS * 4..];
    if header[2] as usize != payload.len() || header[4] != crc32(payload) {
        // Truncated, or corrupted in a way the size check missed.
        return None;
    }
    Some(payload.to_vec())
}

/// Writes one cache file atomically.
///
/// The temporary-then-rename dance is Node's, and it matters here for the same
/// reason: another process can be reading this directory while this one
/// writes, and a rename is the only way it never observes a partial file.
fn write_cache_file(
    directory: &str,
    key: u32,
    code_hash: u32,
    code_size: u32,
    payload: &[u8],
) -> bool {
    let target = PathBuf::from(format!("{directory}/{}", hex32(key)));
    let temporary = PathBuf::from(format!("{}.{}.tmp", target.display(), std::process::id()));
    let mut data = Vec::with_capacity(HEADER_WORDS * 4 + payload.len());
    for word in [
        MAGIC,
        code_size,
        payload.len() as u32,
        code_hash,
        crc32(payload),
    ] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    data.extend_from_slice(payload);
    if std::fs::write(&temporary, &data).is_err() {
        return false;
    }
    if std::fs::rename(&temporary, &target).is_err() {
        let _ = std::fs::remove_file(&temporary);
        return false;
    }
    true
}

fn absolute(directory: &str) -> String {
    let path = Path::new(directory);
    if path.is_absolute() {
        directory.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path).to_string_lossy().into_owned(),
            Err(_) => directory.to_string(),
        }
    }
}

fn hex32(value: u32) -> String {
    format!("{value:08x}")
}

/// CRC-32, as zlib computes it.
///
/// Node hashes cache keys and payloads with zlib's `crc32`, so the value has to
/// match exactly: it is the file name on disk and the corruption check in the
/// header. Implemented here rather than depended on so one function does not
/// pull a zlib dependency into this crate.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_seeded(0, data)
}

/// CRC-32 continued from an earlier state, so that
/// `crc32_seeded(crc32(a), b) == crc32(a ++ b)`.
pub fn crc32_seeded(state: u32, data: &[u8]) -> u32 {
    let mut crc = !state;
    for byte in data {
        crc = CRC_TABLE[((crc ^ u32::from(*byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// The reflected CRC-32 polynomial, `0xEDB88320`.
const CRC_POLYNOMIAL: u32 = 0xedb8_8320;

static CRC_TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC_POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_reference_values() {
        // The canonical check value for CRC-32.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_seeded_composes() {
        assert_eq!(crc32_seeded(crc32(b"abc"), b"def"), crc32(b"abcdef"));
    }

    #[test]
    fn crc32_is_order_dependent() {
        assert_ne!(crc32(b"ab"), crc32(b"ba"));
    }

    #[test]
    fn status_names_are_in_node_order() {
        assert_eq!(COMPILE_CACHE_STATUS[0], "FAILED");
        assert_eq!(COMPILE_CACHE_STATUS[1], "ENABLED");
        assert_eq!(COMPILE_CACHE_STATUS[2], "ALREADY_ENABLED");
        assert_eq!(COMPILE_CACHE_STATUS[3], "DISABLED");
    }

    #[test]
    fn cache_keys_separate_code_types_and_files() {
        assert_ne!(cache_key("/a/b.ts", 2), cache_key("/a/b.ts", 1));
        assert_ne!(cache_key("/a/b.ts", 2), cache_key("/a/c.ts", 2));
        assert_eq!(cache_key("/a/b.ts", 2), cache_key("/a/b.ts", 2));
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "rn-bind-modules-cache-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&base).expect("temp dir");
            Self(base)
        }

        fn str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn enabled(dir: &TempDir) -> CompileCache {
        let mut cache = CompileCache::new();
        let result = cache.enable_with_env(&dir.str(), false, false, false);
        assert_eq!(result.status, 1, "enable failed: {}", result.message);
        cache
    }

    #[test]
    fn enable_reports_the_base_directory_and_later_the_tagged_one() {
        let dir = TempDir::new("tagged");
        let mut cache = CompileCache::new();
        let result = cache.enable_with_env(&dir.str(), false, false, false);
        assert_eq!(result.status, 1);
        assert_eq!(result.directory, dir.str());
        assert!(cache.tagged_directory().starts_with(&dir.str()));
        assert!(
            cache.tagged_directory().contains(NODE_VERSION),
            "the tag must carry the version so other runtimes' caches are never read"
        );
    }

    #[test]
    fn enabling_twice_reports_already_enabled() {
        let dir = TempDir::new("twice");
        let mut cache = enabled(&dir);
        let second = cache.enable_with_env("/ignored", false, false, false);
        assert_eq!(second.status, 2);
        assert_eq!(second.directory, cache.tagged_directory());
    }

    #[test]
    fn a_round_trip_persists_and_reloads_an_entry() {
        let dir = TempDir::new("roundtrip");
        let mut cache = enabled(&dir);
        let source = b"const a: number = 1;\n";
        let (key, cached) = cache
            .get_or_insert(source, "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        assert_eq!(cached, None, "nothing on disk yet");
        cache.save(key, "const a = 1;\n");
        assert_eq!(cache.flush(), 1);

        let mut reopened = enabled(&dir);
        let (_, cached) = reopened
            .get_or_insert(source, "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        assert_eq!(cached.as_deref(), Some("const a = 1;\n"));
    }

    #[test]
    fn a_changed_source_is_a_miss() {
        let dir = TempDir::new("changed");
        let mut cache = enabled(&dir);
        let (key, _) = cache
            .get_or_insert(b"one", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        cache.save(key, "first");
        cache.flush();

        let mut reopened = enabled(&dir);
        let (_, cached) = reopened
            .get_or_insert(b"two", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        assert_eq!(cached, None, "a different source must not reuse the entry");
    }

    #[test]
    fn a_truncated_cache_file_is_a_miss_not_a_crash() {
        let dir = TempDir::new("truncated");
        let mut cache = enabled(&dir);
        let (key, _) = cache
            .get_or_insert(b"source", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        cache.save(key, "payload");
        cache.flush();

        let path = format!("{}/{}", cache.tagged_directory(), hex32(key));
        let mut bytes = std::fs::read(&path).expect("cache file");
        bytes.truncate(bytes.len() - 3);
        std::fs::write(&path, &bytes).expect("write");

        let mut reopened = enabled(&dir);
        let (_, cached) = reopened
            .get_or_insert(b"source", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        assert_eq!(cached, None);
    }

    #[test]
    fn a_corrupt_header_is_a_miss() {
        let dir = TempDir::new("corrupt");
        let mut cache = enabled(&dir);
        let (key, _) = cache
            .get_or_insert(b"source", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        cache.save(key, "payload");
        cache.flush();

        let path = format!("{}/{}", cache.tagged_directory(), hex32(key));
        let mut bytes = std::fs::read(&path).expect("cache file");
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).expect("write");

        let mut reopened = enabled(&dir);
        let (_, cached) = reopened
            .get_or_insert(b"source", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        assert_eq!(cached, None);
    }

    #[test]
    fn a_disabled_cache_returns_no_entry() {
        let mut cache = CompileCache::new();
        assert_eq!(
            cache.get_or_insert(b"x", "/app/x.js", 0),
            None,
            "a disabled cache reports absence rather than inventing an entry"
        );
        assert_eq!(cache.tagged_directory(), "");
    }

    #[test]
    fn read_only_refuses_to_create_the_directory() {
        let dir = TempDir::new("readonly");
        let target = dir.0.join("missing");
        let mut cache = CompileCache::new();
        let result = cache.enable_with_env(&target.to_string_lossy(), false, true, false);
        assert_eq!(result.status, 0);
        assert!(result.message.contains("read-only"));
    }

    #[test]
    fn read_only_never_writes() {
        let dir = TempDir::new("readonlywrite");
        let tagged = {
            let writable = enabled(&dir);
            writable.tagged_directory().to_string()
        };

        let mut cache = CompileCache::new();
        let result = cache.enable_with_env(&dir.str(), false, true, false);
        assert_eq!(result.status, 1, "{}", result.message);
        assert_eq!(cache.tagged_directory(), tagged);
        let (key, _) = cache
            .get_or_insert(b"source", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        cache.save(key, "payload");
        assert_eq!(cache.flush(), 0);
    }

    #[test]
    fn a_portable_cache_omits_the_uid() {
        let portable = cache_version_tag(true);
        assert!(!portable.ends_with(&format!("-{}", uid())));
        assert!(cache_version_tag(false).ends_with(&format!("-{}", uid())));
    }

    fn uid() -> u32 {
        // SAFETY: `getuid` takes no arguments and cannot fail.
        unsafe { libc::getuid() }
    }
}
