//! The on-disk module compile cache.
//!
//! This is a port of `src/compile_cache.cc` plus the parts of
//! `src/node_contextify.cc` and `src/module_wrap.cc` that drive it. Node splits
//! the work in three and this module keeps the same split:
//!
//! * **Storage.** A cache directory holds one file per source file, named by a
//!   CRC-32 of the cached-code type and the file's cache key path. Each file is
//!   a five-word header followed by the payload. The header is what makes a
//!   stale or truncated file a cache *miss* rather than a crash:
//!
//!   ```text
//!   [u32] magic
//!   [u32] source size
//!   [u32] payload size
//!   [u32] source hash
//!   [u32] payload hash
//!   ```
//!
//! * **Compilation.** The payload of a `kCommonJS` or `kESM` entry is V8's own
//!   code cache, produced by `Function::create_code_cache` (CJS) or
//!   `UnboundModuleScript::create_code_cache` (ESM) and consumed by the next
//!   compile through `ScriptCompiler::CachedData` with `ConsumeCodeCache`. The
//!   *compile* itself belongs to the crate that owns it — [`crate`]-external
//!   callers reach it through [`lookup`] and [`store_code_cache`], which is the
//!   same split Node has between `compile_cache.cc` and `node_contextify.cc`.
//!
//! * **Tracing.** `NODE_DEBUG_NATIVE=COMPILE_CACHE` turns on the trace lines
//!   Node's own tests assert against. They are the observable interface of this
//!   module, so [`trace`] is used to produce them verbatim.
//!
//! The TypeScript transpile cache is the one entry type whose payload is plain
//! text rather than a V8 blob, which is why [`CompileCache::get_or_insert_bytes`]
//! is byte-oriented and only the JavaScript-facing member cares which kind it
//! was given.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Node version this crate reports, matching `process.version` without its `v`.
///
/// The cache directory tag is built from this string, so it has to be the same
/// identity `process.version` reports — a shortened `28.0.0` would put a cache
/// written by this runtime in a directory no other runtime looks at, which is
/// correct, but it would also disagree with the directory Node's own tests
/// derive from `process.version`.
pub const NODE_VERSION: &str = "28.0.0-nightly20261111e8c1160d20";

/// Status values, in `COMPILE_CACHE_STATUS` order.
///
/// `lib/internal/modules/helpers.js` builds its `compileCacheStatus` object by
/// walking this array and taking each entry's index as the value, so the order
/// is the contract, not a convenience.
pub const COMPILE_CACHE_STATUS: &[&str] = &["FAILED", "ENABLED", "ALREADY_ENABLED", "DISABLED"];

/// `CompileCacheEnableStatus::FAILED`.
pub const STATUS_FAILED: u8 = 0;
/// `CompileCacheEnableStatus::ENABLED`.
pub const STATUS_ENABLED: u8 = 1;
/// `CompileCacheEnableStatus::ALREADY_ENABLED`.
pub const STATUS_ALREADY_ENABLED: u8 = 2;
/// `CompileCacheEnableStatus::DISABLED`.
pub const STATUS_DISABLED: u8 = 3;

/// Cached-code types, matching `CACHED_CODE_TYPES`.
pub const CACHED_CODE_TYPES: &[(&str, i32)] = &[
    ("kCommonJS", 0),
    ("kESM", 1),
    ("kStrippedTypeScript", 2),
    ("kWasm", 3),
];

/// `CachedCodeType::kCommonJS`.
pub const K_COMMONJS: i32 = 0;
/// `CachedCodeType::kESM`.
pub const K_ESM: i32 = 1;
/// `CachedCodeType::kStrippedTypeScript`, the type the transpile cache uses.
pub const K_STRIPPED_TYPESCRIPT: i32 = 2;
/// `CachedCodeType::kWasm`.
pub const K_WASM: i32 = 3;

/// `CompileCacheEntry::type_name`, by numeric type.
///
/// Public because the namespace's trace lines name the type, and the mapping has
/// to come from one place: `CommonJS` versus `ESM` versus `Wasm` is what Node's
/// own test regexes distinguish a cache hit by.
pub fn type_name_of(code_type: i32) -> &'static str {
    type_name(code_type)
}

/// Cache-file magic, from `src/compile_cache.cc`.
const MAGIC: u32 = 0x8adf_dbb2;

/// Header words before the payload.
const HEADER_WORDS: usize = 5;

/// `CompileCacheEntry::type_name`.
fn type_name(code_type: i32) -> &'static str {
    match code_type {
        K_COMMONJS => "CommonJS",
        K_ESM => "ESM",
        K_STRIPPED_TYPESCRIPT => "StrippedTypeScript",
        K_WASM => "Wasm",
        _ => "Unknown",
    }
}

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
            status: STATUS_FAILED,
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
    /// The filename as the caller gave it, for trace lines only.
    source_filename: String,
    /// Numeric type, so a trace can name it.
    code_type: i32,
}

/// A cache lookup, standing in for the `CompileCacheEntry*` Node hands back.
///
/// Node returns a pointer into the store; the store can rehash, so this crate
/// returns the key and the payload instead and the caller hands the key back to
/// [`store_code_cache`]. Nothing dereferences the key, which is why it can also
/// travel through the `external` handle the JavaScript layer holds.
#[derive(Debug, Clone)]
pub struct Lookup {
    /// The cache key, `crc32(type_byte ++ key_path)`.
    pub key: u32,
    /// The cached payload, when an on-disk entry validated.
    pub cached: Option<Vec<u8>>,
    /// The filename as given, for trace lines that follow the lookup.
    pub source_filename: String,
    /// The numeric code type.
    pub code_type: i32,
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
    /// Set when cache keys are computed from paths relative to [`Self::key_root`].
    portable: bool,
    /// What a portable cache's relative keys are computed against.
    key_root: String,
    /// Keyed by cache key, a CRC-32 of key path and type.
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

    /// Whether existing entries may be read but nothing written.
    pub fn is_read_only(&self) -> bool {
        self.read_only
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
    /// write. `key_root` is the internal fourth argument
    /// `module.enableCompileCache()` passes: the directory a portable cache's
    /// keys are relative to, defaulting to the tagged cache directory.
    pub fn enable(
        &mut self,
        directory: &str,
        portable: bool,
        read_only: bool,
        key_root: &str,
    ) -> EnableResult {
        // Node checks this before it looks at the directory, so a user who
        // disabled the cache never sees a write.
        let disabled_by_env = rn_env::contains("NODE_DISABLE_COMPILE_CACHE");
        self.enable_with_env(directory, portable, read_only, key_root, disabled_by_env)
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
        key_root: &str,
        disabled_by_env: bool,
    ) -> EnableResult {
        if self.enabled {
            return EnableResult {
                status: STATUS_ALREADY_ENABLED,
                message: String::new(),
                directory: self.cache_directory.clone(),
            };
        }
        if disabled_by_env {
            let message = "Disabled by NODE_DISABLE_COMPILE_CACHE".to_string();
            trace(format_args!("[compile cache] {message}.\n"));
            return EnableResult {
                status: STATUS_DISABLED,
                message,
                directory: String::new(),
            };
        }

        let base = resolve_path(directory);
        let tag = cache_version_tag(portable);
        let cache_directory = format!("{base}/{tag}");
        trace(format_args!(
            "[compile cache] resolved path {directory} + {tag} -> {cache_directory}\n"
        ));

        if !read_only {
            // `permission()->is_granted(kFileSystemWrite, cache_dir_with_tag)`.
            // The denial itself is discarded: Node reports a *failed enable* with
            // this message rather than propagating the `ERR_ACCESS_DENIED` the
            // model would produce, which is why the wording is rebuilt here.
            if rn_permission::runtime::deny_fs_write(cache_directory.as_bytes()).is_some() {
                let message = format!(
                    "Skipping compile cache because write permission for {cache_directory} is not granted"
                );
                trace(format_args!("[compile cache] {message}\n"));
                return EnableResult::failed(message);
            }
        }
        if rn_permission::runtime::deny_fs_read(cache_directory.as_bytes()).is_some() {
            let message = format!(
                "Skipping compile cache because read permission for {cache_directory} is not granted"
            );
            trace(format_args!("[compile cache] {message}\n"));
            return EnableResult::failed(message);
        }

        if read_only {
            let found = Path::new(&cache_directory).is_dir();
            trace(format_args!(
                "[compile cache] read-only cache directory {cache_directory}...{}\n",
                if found { "found" } else { "not found" }
            ));
            if !found {
                return EnableResult::failed(format!(
                    "Cache directory does not exist (read-only): {cache_directory}"
                ));
            }
        } else {
            // `create_dir_all` on an existing directory is a success, which is
            // what Node's `MKDirpSync` + `UV_EEXIST` handling amounts to.
            let created = std::fs::create_dir_all(&cache_directory);
            trace(format_args!(
                "[compile cache] creating cache directory {cache_directory}...{}\n",
                match &created {
                    Ok(()) => "success".to_string(),
                    Err(error) => errno_text(error),
                }
            ));
            if let Err(error) = created {
                return EnableResult::failed(format!(
                    "Cannot create cache directory: {}",
                    errno_text(&error)
                ));
            }
        }

        self.base_directory = base;
        self.cache_directory = cache_directory;
        self.enabled = true;
        self.read_only = read_only;
        self.portable = portable;
        // `NormalizeFileURLOrPath` on the cache directory itself, not the raw
        // path: Node passes `compile_cache_dir_` through the same normalizer it
        // uses for a key root, and the normalizer drops the leading separator.
        // Comparing that with a normalized *relative* file path is what produces
        // the `../../script.js` key a moved portable cache relies on; comparing a
        // relative path against an absolute root yields no common prefix and
        // silently falls back to the absolute key.
        self.key_root = if key_root.is_empty() {
            normalize_file_url_or_path(&self.cache_directory)
        } else {
            normalize_file_url_or_path(key_root)
        };
        EnableResult {
            status: STATUS_ENABLED,
            message: String::new(),
            directory: self.base_directory.clone(),
        }
    }

    /// `getCompileCacheEntry`: looks up cached code for `source`.
    pub fn get_or_insert(
        &mut self,
        source: &[u8],
        filename: &str,
        code_type: i32,
    ) -> Option<(u32, Option<String>)> {
        let (key, cached) = self.get_or_insert_bytes(source, filename, code_type)?;
        // The TypeScript transpile cache is the only consumer of the text
        // shape, so a blob that is not valid UTF-8 means a non-text entry was
        // asked for through the text path; report it as a miss rather than as
        // replacement characters.
        Some((key, cached.and_then(|bytes| String::from_utf8(bytes).ok())))
    }

    /// [`Self::get_or_insert`] without the UTF-8 assumption.
    pub fn get_or_insert_bytes(
        &mut self,
        source: &[u8],
        filename: &str,
        code_type: i32,
    ) -> Option<(u32, Option<Vec<u8>>)> {
        Some((self.lookup(source, filename, code_type)?.key, {
            let key = self.key_of(filename, code_type);
            self.entries.get(&key).and_then(|entry| entry.cache.clone())
        }))
    }

    /// The full [`Lookup`] shape, which is what a compile path needs.
    ///
    /// Returns `None` when the cache is off, which is the caller's signal that
    /// no cache entry exists at all. A `Some` with `cached: None` is a miss that
    /// still has a key, so the compiled result can be filed under it.
    pub fn lookup(&mut self, source: &[u8], filename: &str, code_type: i32) -> Option<Lookup> {
        if !self.enabled {
            return None;
        }
        let key_path = self.key_path(filename);
        let key = cache_key(&key_path, code_type);
        let code_hash = crc32(source);
        let code_size = source.len() as u32;

        if let Some(entry) = self.entries.get(&key) {
            if entry.code_hash == code_hash {
                return Some(Lookup {
                    key,
                    cached: entry.cache.clone(),
                    source_filename: filename.to_string(),
                    code_type,
                });
            }
            // A hash mismatch means the source changed, so the stale entry is
            // replaced by the read below.
        }

        let cache = self.read_cache_file(key, code_hash, code_size, filename, code_type);
        self.entries.insert(
            key,
            Entry {
                code_hash,
                code_size,
                cache: cache.clone(),
                refreshed: false,
                persisted: false,
                source_filename: filename.to_string(),
                code_type,
            },
        );
        Some(Lookup {
            key,
            cached: cache,
            source_filename: filename.to_string(),
            code_type,
        })
    }

    /// `saveCompileCacheEntry` for the plain-text payloads the TypeScript
    /// transpile cache stores.
    pub fn save(&mut self, key: u32, payload: &str) {
        self.save_bytes(key, payload.as_bytes());
    }

    /// Stores an opaque payload for `key`.
    ///
    /// The TypeScript transpile cache stores text and the WebAssembly half
    /// stores serialized V8 blobs, so the store itself is byte-oriented; only
    /// the JavaScript-facing member cares which kind it was given.
    pub fn save_bytes(&mut self, key: u32, payload: &[u8]) {
        if !self.enabled || self.read_only {
            return;
        }
        if let Some(entry) = self.entries.get_mut(&key) {
            trace(format_args!(
                "[compile cache] saving transpilation cache for {} {}\n",
                type_name(entry.code_type),
                entry.source_filename
            ));
            entry.cache = Some(payload.to_vec());
            entry.refreshed = true;
        }
    }

    /// `CompileCacheHandler::MaybeSaveImpl` for a V8 code cache.
    ///
    /// `produced` is what V8 serialized for this compile, or `None` when it
    /// produced nothing. `rejected` says V8 refused the cached data it was
    /// given, which makes the new payload a refresh rather than a keep.
    pub fn store_code_cache(&mut self, key: u32, produced: Option<Vec<u8>>, rejected: bool) {
        let Some(entry) = self.entries.get(&key) else {
            return;
        };
        let type_name = type_name(entry.code_type);
        let source_filename = entry.source_filename.clone();
        let had_cache = entry.cache.is_some();
        let state = if rejected {
            "rejected"
        } else if had_cache {
            "accepted"
        } else {
            "not initialized"
        };
        if had_cache && !rejected {
            trace(format_args!(
                "[compile cache] V8 code cache for {type_name} {source_filename} was {state}, keeping the in-memory entry\n"
            ));
            return;
        }
        if self.read_only {
            trace(format_args!(
                "[compile cache] V8 code cache for {type_name} {source_filename} was {state}, read-only, not serializing\n"
            ));
            return;
        }
        let action = if had_cache {
            "refreshing"
        } else {
            "initializing"
        };
        trace(format_args!(
            "[compile cache] V8 code cache for {type_name} {source_filename} was {state}, {action} the in-memory entry\n"
        ));
        let Some(payload) = produced else {
            trace(format_args!(
                "[compile cache] nothing to serialize for {type_name} {source_filename}\n"
            ));
            return;
        };
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.cache = Some(payload);
            entry.refreshed = true;
        }
    }

    /// Writes every entry that changed, then empties the store.
    ///
    /// Returns how many files were written, which makes a silent failure
    /// visible in tests instead of only in a debug log.
    pub fn persist(&mut self) -> usize {
        if !self.enabled || self.cache_directory.is_empty() {
            return 0;
        }
        if self.read_only {
            trace(format_args!(
                "[compile cache] read-only, skipping persistence\n"
            ));
            return 0;
        }
        let mut written = 0;
        // Collected first so the file I/O does not hold a mutable borrow of a
        // map that a later `persisted` update needs.
        let pending: Vec<(u32, Entry)> = self
            .entries
            .iter()
            .map(|(key, entry)| (*key, entry.clone()))
            .collect();
        for (key, entry) in pending {
            let name = type_name(entry.code_type);
            let Some(cache) = &entry.cache else {
                trace(format_args!(
                    "[compile cache] skip persisting {name} {} because the cache was not initialized\n",
                    entry.source_filename
                ));
                continue;
            };
            if !entry.refreshed {
                trace(format_args!(
                    "[compile cache] skip persisting {name} {} because cache was the same\n",
                    entry.source_filename
                ));
                continue;
            }
            if entry.persisted {
                trace(format_args!(
                    "[compile cache] skip persisting {name} {} because cache was already persisted\n",
                    entry.source_filename
                ));
                continue;
            }
            if self.write_cache_file(&entry, key, cache) {
                if let Some(stored) = self.entries.get_mut(&key) {
                    stored.persisted = true;
                    stored.refreshed = false;
                }
                written += 1;
            }
        }
        trace(format_args!("[compile cache] Clear deserialized cache.\n"));
        self.entries.clear();
        written
    }

    /// The cache key path for `filename`, which is relative for a portable cache.
    fn key_path(&self, filename: &str) -> String {
        if !self.portable || !is_absolute_file_path(filename) {
            return filename.to_string();
        }
        let normalized = normalize_file_url_or_path(filename);
        if normalized.is_empty() {
            return filename.to_string();
        }
        let relative = lexically_relative(&normalized, &self.key_root);
        // Node only tests `!relative_path.empty()`, so a `"."` answer is used
        // like any other. `lexically_relative` returns an empty string when the
        // two paths have no common prefix at all.
        if relative.is_empty() {
            return filename.to_string();
        }
        trace(format_args!(
            "[compile cache] using relative path {relative} from {}\n",
            self.key_root
        ));
        relative
    }

    /// The key for `filename` and `code_type` without touching the store.
    fn key_of(&self, filename: &str, code_type: i32) -> u32 {
        cache_key(&self.key_path(filename), code_type)
    }

    /// `CompileCacheHandler::ReadCacheFile`, with Node's trace lines.
    #[allow(clippy::too_many_arguments)]
    fn read_cache_file(
        &self,
        key: u32,
        code_hash: u32,
        code_size: u32,
        filename: &str,
        code_type: i32,
    ) -> Option<Vec<u8>> {
        let path = format!("{}/{key:08x}", self.cache_directory);
        let name = type_name(code_type);
        trace(format_args!(
            "[compile cache] reading cache from {path} for {name} {filename}..."
        ));
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                trace(format_args!(" {}\n", errno_text(&error)));
                return None;
            }
        };
        if bytes.len() < HEADER_WORDS * 4 {
            trace(format_args!(
                "reading header failed, bytes read {}\n",
                bytes.len()
            ));
            return None;
        }
        let header: Vec<u32> = bytes[..HEADER_WORDS * 4]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect();
        trace(format_args!(
            "[{} {} {} {} {}]...",
            header[0], header[1], header[2], header[3], header[4]
        ));
        if header[0] != MAGIC {
            trace(format_args!(
                "magic number mismatch: expected {MAGIC}, actual {}\n",
                header[0]
            ));
            return None;
        }
        if header[1] != code_size {
            trace(format_args!(
                "code size mismatch: expected {code_size}, actual {}\n",
                header[1]
            ));
            return None;
        }
        if header[3] != code_hash {
            trace(format_args!(
                "code hash mismatch: expected {code_hash}, actual {}\n",
                header[3]
            ));
            return None;
        }
        let payload = &bytes[HEADER_WORDS * 4..];
        if header[2] as usize != payload.len() {
            trace(format_args!(
                "cache size mismatch: expected {}, actual {}\n",
                header[2],
                payload.len()
            ));
            return None;
        }
        let hash = crc32(payload);
        if header[4] != hash {
            trace(format_args!(
                "cache hash mismatch: expected {}, actual {hash}\n",
                header[4]
            ));
            return None;
        }
        trace(format_args!(" success, size={}\n", payload.len()));
        Some(payload.to_vec())
    }

    /// Writes one entry to disk, with Node's trace lines.
    ///
    /// The temporary-then-rename dance is Node's, and it matters here for the
    /// same reason: another process can be reading this directory while this one
    /// writes, and a rename is the only way it never observes a partial file.
    fn write_cache_file(&self, entry: &Entry, key: u32, payload: &[u8]) -> bool {
        let name = type_name(entry.code_type);
        let target = PathBuf::from(format!("{}/{key:08x}", self.cache_directory));
        let temporary = target.with_file_name(format!("{key:08x}.{}", temp_suffix()));
        trace(format_args!(
            "[compile cache] Creating temporary file for cache of {} ({name})...",
            entry.source_filename
        ));
        trace(format_args!(" -> {}\n", temporary.display()));

        let mut data = Vec::with_capacity(HEADER_WORDS * 4 + payload.len());
        let headers = [
            MAGIC,
            entry.code_size,
            payload.len() as u32,
            entry.code_hash,
            crc32(payload),
        ];
        for word in headers {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(payload);
        trace(format_args!(
            "[compile cache] writing cache for {name} {} to temporary file {} [{} {} {} {} {}]...",
            entry.source_filename,
            temporary.display(),
            headers[0],
            headers[1],
            headers[2],
            headers[3],
            headers[4]
        ));
        if let Err(error) = std::fs::write(&temporary, &data) {
            trace(format_args!("failed: {}\n", errno_text(&error)));
            return false;
        }
        trace(format_args!("success\n"));
        trace(format_args!(
            "[compile cache] Renaming {} to {}...",
            temporary.display(),
            target.display()
        ));
        if let Err(error) = std::fs::rename(&temporary, &target) {
            let _ = std::fs::remove_file(&temporary);
            trace(format_args!("failed: {}\n", errno_text(&error)));
            return false;
        }
        trace(format_args!("success\n"));
        true
    }
}

/// The process-wide cache, matching the one handler per environment Node keeps
/// on `Environment`.
///
/// A process-wide mutex rather than a thread-local, for two reasons:
///
/// * **The exit flush has to reach it.** Node registers
///   `Environment::FlushCompileCache` through `AtExit`, and libc's `atexit` is
///   the equivalent hook here. Rust runs thread-local destructors *before*
///   `atexit` handlers, so a thread-local cache has already been destroyed by
///   the time the flush runs and touching it panics with
///   `cannot access a Thread Local Storage value during or after destruction`.
/// * **Workers share the directory anyway.** A worker compiles into the same
///   tagged directory with code caches V8 considers interchangeable across
///   isolates of one version, so a shared store is what a worker and its parent
///   should see. Node reaches the same place through two handlers on one
///   directory; this reaches it through one store.
///
/// The lock is never held across a call into JavaScript, so re-entrancy is not a
/// hazard: every closure passed to [`with_cache`] is pure Rust plus file I/O.
static CACHE: std::sync::Mutex<Option<CompileCache>> = std::sync::Mutex::new(None);

/// Runs `body` with the compile cache.
///
/// A poisoned lock is recovered rather than propagated: the cache is an
/// optimisation, so a panic elsewhere must not turn every later compile into a
/// second panic. The poisoned contents are still a valid `CompileCache` — nothing
/// in this module leaves it half-updated across a statement that can panic.
pub fn with_cache<T>(body: impl FnOnce(&mut CompileCache) -> T) -> T {
    let mut guard = match CACHE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    body(guard.get_or_insert_with(CompileCache::new))
}

/// Returns the tagged directory when the cache is enabled.
///
/// A separate accessor rather than `with_cache(|cache| ...)` at the call site so
/// the `MutexGuard` never escapes into a closure the caller controls.
pub fn tagged_directory() -> Option<String> {
    with_cache(|cache| {
        let directory = cache.tagged_directory();
        (!directory.is_empty()).then(|| directory.to_string())
    })
}

/// Resets the cache. Tests only: the runtime enables it once.
pub fn reset_cache() {
    let mut guard = match CACHE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = None;
}

/// Flushes a cache that was enabled, for an `atexit` handler.
///
/// Node registers `Environment::FlushCompileCache` through `AtExit` when the
/// cache is enabled, so the write happens however the process ends. The closest
/// equivalent here is libc's `atexit`, which `std::process::exit` reaches from
/// every exit path this runtime has — including `process.reallyExit`, which
/// calls `std::process::exit` directly rather than the CLI's own helper.
pub fn persist_at_exit() {
    with_cache(|cache| {
        if cache.is_enabled() {
            cache.persist();
        }
    });
}

/// Registers [`persist_at_exit`] once per process.
///
/// Called from the enable path rather than from startup, because Node registers
/// its `AtExit` callback *inside* `Environment::EnableCompileCache` — which is why
/// `module.enableCompileCache()` writes its cache just as a `NODE_COMPILE_CACHE`
/// run does. Registering only at startup left the API path writing nothing.
pub fn register_exit_flush() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(|| {
        // SAFETY: `persist_at_exit` only takes the cache mutex and does file I/O.
        // `atexit` handlers are ordered before `.fini_array`, so the mutex is
        // still constructible, and the static above guarantees exactly one
        // registration.
        unsafe {
            libc::atexit(flush_at_exit);
        }
    });
}

/// The `extern "C"` shim `atexit` needs.
extern "C" fn flush_at_exit() {
    persist_at_exit();
}

/// `Environment::InitializeCompileCache`.
///
/// Called once on the main thread, before any module is compiled, so a
/// `NODE_COMPILE_CACHE` set in the environment is in effect for the whole run.
/// Returns whether the cache ended up enabled.
pub fn initialize_from_env() -> bool {
    let Some(directory) = rn_env::get("NODE_COMPILE_CACHE") else {
        return false;
    };
    if directory.is_empty() {
        return false;
    }
    let portable = rn_env::get("NODE_COMPILE_CACHE_PORTABLE").is_some_and(|value| value == "1");
    if portable {
        trace(format_args!("[compile cache] using relative path\n"));
    }
    let read_only = rn_env::get("NODE_COMPILE_CACHE_READONLY").is_some_and(|value| value == "1");
    let enabled = with_cache(|cache| cache.enable(&directory, portable, read_only, ""));
    if enabled.status == STATUS_ENABLED {
        register_exit_flush();
        return true;
    }
    false
}

/// Node's cache-directory tag: `v` + version + arch + V8 tag + uid.
fn cache_version_tag(portable: bool) -> String {
    let tag = format!(
        "v{}-{}-{}",
        NODE_VERSION,
        process_arch(),
        hex32(v8_cache_tag())
    );
    if portable {
        return tag;
    }
    // `NODE_IMPLEMENTS_POSIX_CREDENTIALS`: platforms without uids omit the
    // suffix and live with the occasional permission mismatch, which Node
    // explains is fine because their local directories are already per user.
    #[cfg(unix)]
    {
        // SAFETY: `getuid` takes no arguments and cannot fail.
        format!("{tag}-{}", unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        tag
    }
}

/// `process.arch` for this build.
///
/// Rust's `std::env::consts::ARCH` and Node's `NODE_ARCH` are not the same
/// vocabulary: Rust says `x86_64`, Node says `x64`. The tag is derived from
/// `process.arch` on the JavaScript side of Node's own test, so the Node
/// spelling is the one that has to be produced.
fn process_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "powerpc64" => "ppc64",
        other => other,
    }
}

/// `ScriptCompiler::CachedDataVersionTag`, which is the value V8 itself uses to
/// decide whether cached data is compatible.
///
/// Asking V8 is strictly better than imitating it, because V8's tag also moves
/// when a build-time feature changes, which a version string cannot see — the v8
/// header is explicit that the tag guards "the same version with different
/// features enabled".
fn v8_cache_tag() -> u32 {
    rn_v8_sys::v8::script_compiler::cached_data_version_tag()
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

/// Emits one `NODE_DEBUG_NATIVE=COMPILE_CACHE` trace line.
///
/// Node's `EnabledDebugList::Parse` splits the variable on commas and enables a
/// category when its lowercase name appears anywhere in an entry, which is why
/// `COMPILE_CACHE` and `compile_cache` both work and `CACHE` does not.
pub fn trace(arguments: std::fmt::Arguments<'_>) {
    if debug_enabled() {
        // Written straight to stderr rather than through a buffer: a trace line
        // that a crash swallowed would be worthless, and Node's `FPrintF` does
        // the same.
        use std::io::Write;
        let _ = std::io::stderr().write_fmt(arguments);
    }
}

/// Whether `NODE_DEBUG_NATIVE` enables the `COMPILE_CACHE` category.
fn debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        let Some(categories) = rn_env::get("NODE_DEBUG_NATIVE") else {
            return false;
        };
        categories.split(',').any(|wanted| {
            let wanted = wanted.to_ascii_lowercase();
            "compile_cache".contains(&wanted) && !wanted.is_empty()
        })
    })
}

fn hex32(value: u32) -> String {
    format!("{value:08x}")
}

/// `PathResolve` over a single path: the cwd is prepended when the path is
/// relative, then the whole thing is lexically normalized.
///
/// Transcribed from `src/path.cc` rather than delegated to `std::path`, because
/// the trailing separator it appends is load-bearing: `NormalizeString` treats
/// the final segment only when a separator terminates it, so normalizing
/// `/a/../b` without one yields `/a/../b` while Node resolves it to `/b`.
fn resolve_path(directory: &str) -> String {
    let joined = if directory.starts_with('/') {
        format!("{directory}/")
    } else {
        let cwd = match std::env::current_dir() {
            Ok(cwd) => cwd.to_string_lossy().into_owned(),
            // Node tolerates a failed `process.cwd()` by resolving relative to
            // nothing, which is what an empty prefix amounts to.
            Err(_) => String::new(),
        };
        format!("{cwd}/{directory}/")
    };
    let absolute = joined.starts_with('/');
    let normalized = normalize_string(&joined, !absolute, "/");
    if absolute {
        return format!("/{normalized}");
    }
    if normalized.is_empty() {
        return ".".to_string();
    }
    normalized
}

/// `IsAbsoluteFilePath`.
fn is_absolute_file_path(path: &str) -> bool {
    path.starts_with("file://") || path.starts_with('/')
}

/// `NormalizeFileURLOrPath`: a file URL becomes a path, then both are
/// lexically normalized.
fn normalize_file_url_or_path(path: &str) -> String {
    let mut normalized = path.to_string();
    if let Some(rest) = normalized.strip_prefix("file://") {
        match crate::url::parse_file_url(&format!("file://{rest}")) {
            Ok(parsed) => normalized = parsed.pathname,
            Err(_) => return String::new(),
        }
    }
    normalize_string(&normalized, false, "/")
}

/// Node's `NormalizeString`, which is `path.posix.normalize` without the
/// trailing-slash rule.
///
/// Transcribed rather than reimplemented with `std::path`, because the output is
/// a *cache key*: two spellings of one path that normalize differently produce
/// two cache files, and the portable tests depend on a moved directory producing
/// the same key.
fn normalize_string(path: &str, allow_above_root: bool, separator: &str) -> String {
    let bytes = path.as_bytes();
    let mut result = String::new();
    let mut last_segment_length: i32 = 0;
    let mut last_slash: i32 = -1;
    let mut dots: i32 = 0;
    let mut code: u8 = 0;
    let mut index = 0usize;
    loop {
        if index < bytes.len() {
            code = bytes[index];
        } else if code == b'/' {
            break;
        } else {
            code = b'/';
        }
        if code == b'/' {
            if last_slash == index as i32 - 1 || dots == 1 {
                // NOOP
            } else if dots == 2 {
                let length = result.len();
                let tail_is_dots = length >= 2
                    && result.as_bytes()[length - 1] == b'.'
                    && result.as_bytes()[length - 2] == b'.'
                    && last_segment_length == 2;
                if length < 2 || !tail_is_dots {
                    if length > 2 {
                        match result.rfind(separator) {
                            None => {
                                result.clear();
                                last_segment_length = 0;
                            }
                            Some(slash) => {
                                result.truncate(slash);
                                let length = result.len();
                                // `-1` for a path with no separator at all, which
                                // is what `find_last_of` returns as `npos`.
                                let previous = result.rfind(separator).map_or(-1, |s| s as i32);
                                last_segment_length = length as i32 - 1 - previous;
                            }
                        }
                        last_slash = index as i32;
                        dots = 0;
                        index += 1;
                        continue;
                    } else if length != 0 {
                        result.clear();
                        last_segment_length = 0;
                        last_slash = index as i32;
                        dots = 0;
                        index += 1;
                        continue;
                    }
                }
                if allow_above_root {
                    if result.is_empty() {
                        result.push_str("..");
                    } else {
                        result.push_str(separator);
                        result.push_str("..");
                    }
                    last_segment_length = 2;
                }
            } else {
                let segment = &path[last_slash as usize + 1..index];
                if !result.is_empty() {
                    result.push_str(separator);
                }
                result.push_str(segment);
                last_segment_length = index as i32 - last_slash - 1;
            }
            last_slash = index as i32;
            dots = 0;
        } else if code == b'.' && dots != -1 {
            dots += 1;
        } else {
            dots = -1;
        }
        index += 1;
    }
    // A root-only path normalizes to an empty tail, and the caller puts the
    // leading separator back. Node's `PathResolve` returns `"/" + ""`, which is
    // why this must not invent a separator of its own.
    result
}

/// `std::filesystem::path::lexically_relative`, over already-normalized paths.
///
/// Node derives a portable cache key this way, so a directory that is moved as a
/// whole keeps its keys. An empty answer means the two paths have no common
/// prefix, which Node treats as "use the absolute path".
fn lexically_relative(path: &str, base: &str) -> String {
    if path.is_empty() || base.is_empty() {
        return String::new();
    }
    let path_parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let base_parts: Vec<&str> = base.split('/').filter(|part| !part.is_empty()).collect();
    let path_absolute = path.starts_with('/');
    let base_absolute = base.starts_with('/');
    if path_absolute != base_absolute {
        return String::new();
    }
    let mut common = 0;
    while common < path_parts.len()
        && common < base_parts.len()
        && path_parts[common] == base_parts[common]
    {
        common += 1;
    }
    if common == 0 && path_absolute {
        return String::new();
    }
    let mut parts: Vec<&str> = vec![".."; base_parts.len() - common];
    parts.extend_from_slice(&path_parts[common..]);
    if parts.is_empty() {
        return ".".to_string();
    }
    parts.join("/")
}

/// The six-character suffix `uv_fs_mkstemp` generates for a `XXXXXX` template.
fn temp_suffix() -> String {
    // Pseudo-random and unique enough for a temp name: two writers that collided
    // would only race on a rename that is atomic anyway, and the pid plus a
    // counter makes a collision inside one process impossible.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = COUNTER.fetch_add(1, Ordering::Relaxed)
        ^ (u64::from(std::process::id()) << 20)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos() as u64)
            .unwrap_or(0);
    let mut suffix = String::with_capacity(6);
    for _ in 0..6 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        suffix.push(ALPHABET[(state >> 33) as usize % ALPHABET.len()] as char);
    }
    suffix
}

/// `uv_strerror` wording for an I/O error.
///
/// libuv's messages are lower case where `strerror` capitalizes the first
/// letter, and the trace lines compare against libuv's spelling.
fn errno_text(error: &std::io::Error) -> String {
    let text = match error.raw_os_error() {
        Some(errno) => {
            let mut buffer = [0i8; 256];
            // SAFETY: `buffer` is a valid writable region of the length passed,
            // and `strerror_r` (the XSI variant) writes only within it.
            let result = unsafe { libc::strerror_r(errno, buffer.as_mut_ptr(), buffer.len()) };
            if result != 0 {
                error.to_string()
            } else {
                // SAFETY: on success `strerror_r` NUL-terminates inside `buffer`.
                unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            }
        }
        None => error.to_string(),
    };
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => text,
    }
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
        let result = cache.enable_with_env(&dir.str(), false, false, "", false);
        assert_eq!(result.status, 1, "enable failed: {}", result.message);
        cache
    }

    #[test]
    fn enable_reports_the_base_directory_and_later_the_tagged_one() {
        let dir = TempDir::new("tagged");
        let mut cache = CompileCache::new();
        let result = cache.enable_with_env(&dir.str(), false, false, "", false);
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
        let second = cache.enable_with_env("/ignored", false, false, "", false);
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
        assert_eq!(cache.persist(), 1);

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
        cache.persist();

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
        cache.persist();

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
        cache.persist();

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
        let result = cache.enable_with_env(&target.to_string_lossy(), false, true, "", false);
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
        let result = cache.enable_with_env(&dir.str(), false, true, "", false);
        assert_eq!(result.status, 1, "{}", result.message);
        assert_eq!(cache.tagged_directory(), tagged);
        let (key, _) = cache
            .get_or_insert(b"source", "/app/mod.ts", K_STRIPPED_TYPESCRIPT)
            .expect("enabled");
        cache.save(key, "payload");
        assert_eq!(cache.persist(), 0);
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

    #[test]
    fn a_portable_cache_keys_from_a_relative_path() {
        // The whole point of a portable cache: a directory moved as a whole keeps
        // its keys. The expectation is the oracle's own `using relative path
        // ../../script.js from tmp/...` line, taken from a `NODE_COMPILE_CACHE`
        // run under a moved working directory.
        //
        // The key root is *inside* the moved tree, so the relative form is
        // computed against the cache directory that moved with it. That is what
        // makes the key stable; keying on the absolute path would not be.
        let dir = TempDir::new("portablekey");
        let work = dir.0.join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        let mut cache = CompileCache::new();
        let result =
            cache.enable_with_env(&work.join("cc").to_string_lossy(), true, false, "", false);
        assert_eq!(result.status, STATUS_ENABLED, "{}", result.message);
        let script = work.join("script.js").to_string_lossy().into_owned();
        // `key_path` is private, so the observable proxy is the key itself: the
        // relative form must differ from the absolute one.
        let relative_key = cache.key_of(&script, K_COMMONJS);
        let absolute_key = cache_key(&script, K_COMMONJS);
        assert_ne!(
            relative_key, absolute_key,
            "a portable cache must not key on the absolute path"
        );

        // Now move the whole tree, cache included, and enable again against the
        // new location. The key must not move.
        let moved = dir.0.join("work_moved");
        std::fs::rename(&work, &moved).expect("rename work dir");
        let mut moved_cache = CompileCache::new();
        let result = moved_cache.enable_with_env(
            &moved.join("cc").to_string_lossy(),
            true,
            false,
            "",
            false,
        );
        assert_eq!(result.status, STATUS_ENABLED, "{}", result.message);
        let moved_script = moved.join("script.js").to_string_lossy().into_owned();
        assert_eq!(
            relative_key,
            moved_cache.key_of(&moved_script, K_COMMONJS),
            "moving the working directory must not change a portable key"
        );
    }

    #[test]
    fn a_written_header_validates_against_a_fresh_read() {
        // The five-word header is the only thing between a stale file and a
        // wrong payload, so a round trip that a *second* store accepts is worth
        // pinning separately from the text path's.
        let dir = TempDir::new("header");
        let mut cache = enabled(&dir);
        let source = b"export const x = 1;\n";
        let lookup = cache.lookup(source, "/app/m.mjs", K_ESM).expect("enabled");
        assert!(lookup.cached.is_none(), "nothing on disk yet");
        cache.store_code_cache(lookup.key, Some(b"v8-blob".to_vec()), false);
        assert_eq!(cache.persist(), 1);

        let mut reopened = enabled(&dir);
        let lookup = reopened
            .lookup(source, "/app/m.mjs", K_ESM)
            .expect("enabled");
        assert_eq!(lookup.cached.as_deref(), Some(&b"v8-blob"[..]));
    }

    #[test]
    fn a_rejected_entry_is_refreshed_rather_than_kept() {
        // V8 refuses cached data compiled against a different engine layout, and
        // `MaybeSaveImpl` treats that as a refresh. Keeping the rejected payload
        // would freeze the entry at data V8 will never accept.
        let dir = TempDir::new("rejected");
        let mut cache = enabled(&dir);
        let lookup = cache
            .lookup(b"src", "/app/m.js", K_COMMONJS)
            .expect("enabled");
        cache.store_code_cache(lookup.key, Some(b"old".to_vec()), false);
        cache.persist();

        let mut reopened = enabled(&dir);
        let lookup = reopened
            .lookup(b"src", "/app/m.js", K_COMMONJS)
            .expect("enabled");
        assert_eq!(lookup.cached.as_deref(), Some(&b"old"[..]));
        reopened.store_code_cache(lookup.key, Some(b"new".to_vec()), true);
        assert_eq!(reopened.persist(), 1);

        let mut third = enabled(&dir);
        let lookup = third
            .lookup(b"src", "/app/m.js", K_COMMONJS)
            .expect("enabled");
        assert_eq!(lookup.cached.as_deref(), Some(&b"new"[..]));
    }

    #[test]
    fn a_produced_cache_is_stored_and_an_empty_one_is_not() {
        // `create_code_cache` returns `None` when V8 has nothing to serialize,
        // which has to leave the entry uninitialized so the flush reports
        // `skip persisting ... because the cache was not initialized` rather
        // than writing a zero-length payload.
        let dir = TempDir::new("produced");
        let mut cache = enabled(&dir);
        let lookup = cache
            .lookup(b"src", "/app/n.js", K_COMMONJS)
            .expect("enabled");
        cache.store_code_cache(lookup.key, None, false);
        assert_eq!(cache.persist(), 0);

        let mut reopened = enabled(&dir);
        let lookup = reopened
            .lookup(b"src", "/app/n.js", K_COMMONJS)
            .expect("enabled");
        assert!(lookup.cached.is_none(), "nothing may have been written");
    }

    #[test]
    fn resolve_path_matches_the_oracle_samples() {
        // Every expectation was taken from the oracle's own
        // `[compile cache] resolved path <input> + <tag> -> <output>` line.
        // `NormalizeString` runs over the resolved *directory* after one
        // trailing separator is appended, which is why a bare `/tmp/np2/b/c`
        // and `/tmp/np2/a/../b//c/` agree.
        assert_eq!(resolve_path("/tmp/np2/b/c"), "/tmp/np2/b/c");
        assert_eq!(resolve_path("/tmp/np2/a/../b//c/"), "/tmp/np2/b/c");
        assert_eq!(resolve_path("/tmp/./np2/y"), "/tmp/np2/y");
    }

    #[test]
    fn the_cache_tag_names_the_process_arch_the_way_process_arch_does() {
        // Node's own test derives the subdirectory name from `process.version`
        // and `process.arch`, so the tag has to agree with both. Rust's
        // `consts::ARCH` says `x86_64` where Node says `x64`.
        let tag = cache_version_tag(true);
        assert!(
            tag.starts_with(&format!("v{NODE_VERSION}-")),
            "the tag must start with the reported version: {tag}"
        );
        assert!(
            tag.contains(&format!("-{}-", process_arch())),
            "the tag must carry the Node spelling of the arch: {tag}"
        );
        assert_ne!(
            process_arch(),
            std::env::consts::ARCH.to_string() + "-never"
        );
    }
}

#[cfg(test)]
mod cache_tag_tests {
    use super::*;

    /// The tag must come from V8, not from a transcribed version string.
    ///
    /// The constant it replaced said `"15.6.75"` — the version Node's pin names —
    /// while the linked engine reports `15.2.124.1-rusty`. A tag is supposed to
    /// keep two engines' caches apart, so a value naming neither engine defeats
    /// the property it exists for.
    #[test]
    fn the_cache_tag_is_v8s_own_and_not_the_transcribed_hash() {
        let tag = v8_cache_tag();
        assert_ne!(tag, 0, "V8's cached-data version tag must not be zero");

        let mut from_old_constant = 0u32;
        for byte in "15.6.75".as_bytes() {
            from_old_constant = from_old_constant
                .wrapping_mul(31)
                .wrapping_add(u32::from(*byte));
        }
        assert_ne!(
            tag, from_old_constant,
            "the real V8 tag must differ from the hash of the old hardcoded version"
        );
    }

    /// The linked engine is not the pin's engine, which is why the constant was
    /// wrong. This fails if that ever stops being true, so the reasoning above
    /// does not quietly go stale.
    #[test]
    fn the_linked_engine_is_not_the_pinned_one() {
        let linked = crate::v8_version();
        assert!(!linked.is_empty(), "V8 reports a version string");
        assert_ne!(
            linked, "15.6.75",
            "if the linked engine ever matches the pin, revisit whether deriving \
             the tag from a string is acceptable again; when this constant was \
             written the engine was 15.2.x against a 15.6 pin"
        );
    }
}
