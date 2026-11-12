//! The process environment: the real block, plus a per-thread copy for workers.
//!
//! Node has two kinds of environment store. The main thread's `process.env` is
//! an interceptor over the real block — the `environ` array libuv mutates with
//! `uv_os_setenv` / `uv_os_unsetenv` and reads with `uv_os_getenv` /
//! `uv_os_environ`. A worker thread gets a `MapKVStore` instead: a copy taken
//! when the worker was created, unless the caller asked for `SHARE_ENV`. Writes
//! inside the worker go to that copy, which is why
//! `test/parallel/test-worker-process-env.js` can assert both that a worker's
//! assignment is invisible to its parent *and* that a child process the worker
//! spawns still inherits it.
//!
//! So this crate has one concept with two implementations, chosen per thread:
//!
//! * [`Store::Real`] — libuv, the whole process, inherited by every child.
//! * [`Store::Map`] — a private copy, used by a worker that was not given
//!   `SHARE_ENV`.
//!
//! [`get`], [`set`], [`unset`], [`contains`], [`vars`] and [`pairs`] dispatch on
//! whichever store the current thread has, so every caller — the `process.env`
//! interceptor, `os.tmpdir()`, `getEnvPairs()` — sees the right one without
//! knowing this distinction exists.
//!
//! # Why the real block is read through libuv and not `libc`
//!
//! `uv_os_getenv` is a thin wrapper over `getenv` on Unix, and the difference
//! shows only at the edges: it reports `UV_ENOENT` for an unset variable rather
//! than handing back a null pointer, and it reports `UV_ENOBUFS` plus the size
//! it needs rather than truncating. Node's `RealEnvStore` is written against
//! those codes, and `uv_os_environ` is what produces the key list `Object.keys`
//! sees. Using libuv keeps the shape Node's own code reads, and
//! `uv_os_setenv` mutates the block `spawn()` copies, which is the whole reason
//! `process.env.RN_PARENT = 'x'` reaches a child.
//!
//! # Cost
//!
//! A real-store `get` is one `getenv`-equivalent call, which is the same cost
//! Node pays per `process.env.X` read. Nothing is memoised: a cache would have to
//! be invalidated by every write, including writes libuv performs on behalf of a
//! library that calls `setenv` directly. A map-store `get` is one `BTreeMap`
//! lookup.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};

use uv::{
    uv_env_item_t, uv_os_environ, uv_os_free_environ, uv_os_getenv, uv_os_setenv, uv_os_unsetenv,
};

/// One variable, as the store reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// Which environment a thread's `process.env` reads.
#[derive(Debug, Clone, Default)]
pub enum Store {
    /// The real process environment, through libuv.
    #[default]
    Real,
    /// A private copy, which is what a worker gets.
    ///
    /// Node's `MapKVStore`. Ordered by name so enumeration is stable and a test
    /// that compares a key list twice gets the same list; Node's is an
    /// `unordered_map`, whose iteration order is unspecified but, for the small
    /// maps a test builds, usually insertion order.
    Map(BTreeMap<String, String>),
}

thread_local! {
    /// The store this thread's realm reads.
    ///
    /// `None` means "the real environment", so a thread that never becomes a
    /// worker pays one `thread_local` read and no allocation. A worker replaces
    /// it before its realm runs.
    static STORE: RefCell<Option<Store>> = const { RefCell::new(None) };
}

/// Makes this thread use a private copy of `entries`.
///
/// Called on a worker's own thread, before its realm bootstraps. The copy is what
/// makes the worker's assignments invisible to the parent while still reaching
/// the children it spawns.
pub fn install_map<I, K, V>(entries: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let map: BTreeMap<String, String> = entries
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect();
    STORE.with(|slot| {
        *slot.borrow_mut() = Some(Store::Map(map));
    });
}

/// Makes this thread use the real process environment again.
///
/// The default, so only a test that installed a map needs it; a worker thread
/// dies with its store.
pub fn install_real() {
    STORE.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

/// A snapshot of everything the real block holds, for a worker to copy.
///
/// Node's `env->env_vars()->Clone(isolate)`: the worker gets the parent's
/// environment as it was when the `Worker` was constructed, so a variable the
/// parent assigns after that point is not inherited. `test-worker-process-env.js`
/// pins exactly this with `SET_IN_PARENT_AFTER_CREATION`.
#[must_use]
pub fn snapshot() -> Vec<(String, String)> {
    vars()
        .into_iter()
        .map(|entry| (entry.name, entry.value))
        .collect()
}

/// Reads one variable from this thread's store.
///
/// `None` when it is not set. A variable set to the empty string is `Some("")` —
/// that distinction is load-bearing: `process.env.X === ''` and
/// `X in process.env` are both true for it, and `os.tmpdir()`'s
/// `TMPDIR`/`TMP`/`TEMP` fallback walks past it because the native code checks
/// `dir.empty()` itself.
#[must_use]
pub fn get(name: &str) -> Option<String> {
    let mapped = STORE.with(|slot| match slot.borrow().as_ref() {
        Some(Store::Map(map)) => Some(map.get(name).cloned()),
        _ => None,
    });
    match mapped {
        Some(result) => result,
        None => real_get(name),
    }
}

/// Writes one variable, creating it if necessary.
///
/// Returns the store's result code; `0` on success.
pub fn set(name: &str, value: &str) -> i32 {
    let stored = STORE.with(|slot| {
        let mut slot = slot.borrow_mut();
        match slot.as_mut() {
            Some(Store::Map(map)) => {
                if !name.is_empty() {
                    map.insert(name.to_string(), value.to_string());
                }
                Some(0)
            }
            _ => None,
        }
    });
    stored.unwrap_or_else(|| real_set(name, value))
}

/// Removes one variable from this thread's store.
pub fn unset(name: &str) -> i32 {
    let removed = STORE.with(|slot| {
        let mut slot = slot.borrow_mut();
        match slot.as_mut() {
            Some(Store::Map(map)) => {
                map.remove(name);
                Some(0)
            }
            _ => None,
        }
    });
    removed.unwrap_or_else(|| real_unset(name))
}

/// Whether `name` is set, without materialising its value.
///
/// `RealEnvStore::Query` is this question, and it is asked on every `in`, every
/// property-attribute query and every `Object.hasOwn`. For the real store it uses
/// a two-byte stack buffer rather than allocating a `String` for a value it
/// discards.
#[must_use]
pub fn contains(name: &str) -> bool {
    let mapped = STORE.with(|slot| match slot.borrow().as_ref() {
        Some(Store::Map(map)) => Some(map.contains_key(name)),
        _ => None,
    });
    mapped.unwrap_or_else(|| real_contains(name))
}

/// Every variable in this thread's store, ordered as the store reports it.
#[must_use]
pub fn vars() -> Vec<EnvVar> {
    let mapped = STORE.with(|slot| match slot.borrow().as_ref() {
        Some(Store::Map(map)) => Some(
            map.iter()
                .map(|(name, value)| EnvVar {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
        ),
        _ => None,
    });
    mapped.unwrap_or_else(real_vars)
}

/// The `KEY=value` strings this thread's **private** store holds, if it has one.
///
/// `None` on a thread reading the real process block. A worker gets `Some`, so a
/// caller that must not go through libuv's allocator can still answer with the
/// worker's own environment.
#[must_use]
pub fn private_pairs() -> Option<Vec<String>> {
    STORE.with(|slot| match slot.borrow().as_ref() {
        Some(Store::Map(map)) => Some(
            map.iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect(),
        ),
        _ => None,
    })
}

/// The `KEY=value` strings `spawn()` without an `env` option passes to the
/// child.
///
/// This is `KVStore::Pairs()`: `src/process_wrap.cc` builds `envPairs` from it,
/// and `lib/child_process.js` documents the shortcut as one native pass over the
/// environment rather than one interceptor round trip per variable.
#[must_use]
pub fn pairs() -> Vec<String> {
    vars()
        .into_iter()
        .map(|entry| format!("{}={}", entry.name, entry.value))
        .collect()
}

// ---------------------------------------------------------------------------
// The real block, through libuv
// ---------------------------------------------------------------------------
fn real_get(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    // `uv_os_getenv` reports the needed size in `size` when the caller's buffer
    // is too small, so a loop of one retry covers every value rather than a
    // growing sequence of guesses. 256 is Node's own first attempt.
    let mut size = 256usize;
    loop {
        let mut buffer = vec![0i8; size];
        let mut written = size;
        // SAFETY: `name` is NUL-terminated, and `buffer` is writable for the
        // `written` bytes whose address is passed.
        let result = unsafe { uv_os_getenv(name.as_ptr(), buffer.as_mut_ptr(), &mut written) };
        if result == 0 {
            // `written` is the length without the NUL.
            let bytes: Vec<u8> = buffer[..written].iter().map(|byte| *byte as u8).collect();
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        // `UV_ENOBUFS`: `written` now holds the size that would have fit.
        if result == uv::UV_ENOBUFS && written > size {
            size = written;
            continue;
        }
        // `UV_ENOENT` for an unset variable, and anything else is treated the
        // same way: Node's `RealEnvStore::Get` returns `nullopt` for every
        // failure, and a variable it cannot read is one the JavaScript side must
        // see as absent rather than as an empty string.
        return None;
    }
}

fn real_set(name: &str, value: &str) -> i32 {
    let (Ok(name), Ok(value)) = (CString::new(name), CString::new(value)) else {
        return uv::UV_EINVAL;
    };
    // SAFETY: both arguments are NUL-terminated and live for the call.
    unsafe { uv_os_setenv(name.as_ptr(), value.as_ptr()) }
}

fn real_unset(name: &str) -> i32 {
    let Ok(name) = CString::new(name) else {
        return uv::UV_EINVAL;
    };
    // SAFETY: the argument is NUL-terminated and lives for the call.
    unsafe { uv_os_unsetenv(name.as_ptr()) }
}

fn real_contains(name: &str) -> bool {
    let Ok(name) = CString::new(name) else {
        return false;
    };
    let mut buffer = [0i8; 2];
    let mut size = buffer.len();
    // SAFETY: `name` is NUL-terminated, and `buffer` is writable for its two
    // bytes. A longer value is reported as `UV_ENOBUFS`, which still answers
    // "the variable exists".
    let result = unsafe { uv_os_getenv(name.as_ptr(), buffer.as_mut_ptr(), &mut size) };
    result != uv::UV_ENOENT
}

fn real_vars() -> Vec<EnvVar> {
    let mut items: *mut uv_env_item_t = std::ptr::null_mut();
    let mut count: std::os::raw::c_int = 0;
    // SAFETY: both out-parameters are valid, and a non-zero return means
    // `items` was not allocated and must not be freed.
    let result = unsafe { uv_os_environ(&mut items, &mut count) };
    if result != 0 || items.is_null() {
        return Vec::new();
    }

    let mut entries = Vec::with_capacity(count.max(0) as usize);
    // SAFETY: on success libuv allocated an array of `count` items and each
    // item's `name` and `value` point inside one NUL-terminated allocation
    // that lives until `uv_os_free_environ`.
    unsafe {
        for index in 0..count.max(0) as usize {
            let item = &*items.add(index);
            if item.name.is_null() || item.value.is_null() {
                continue;
            }
            let name = CStr::from_ptr(item.name).to_string_lossy().into_owned();
            let value = CStr::from_ptr(item.value).to_string_lossy().into_owned();
            entries.push(EnvVar { name, value });
        }
        uv_os_free_environ(items, count);
    }
    entries
}

/// The libuv entry points and result codes this crate uses.
///
/// The functions are re-exported rather than reimplemented: the process links
/// one libuv, and it has to be the same one the loop and every other binding
/// use, or a `setenv` here would not be the block a `spawn()` copies.
mod uv {
    use std::os::raw::c_int;

    pub use libuv_sys2::uv_env_item_t;
    pub use libuv_sys2::{
        uv_os_environ, uv_os_free_environ, uv_os_getenv, uv_os_setenv, uv_os_unsetenv,
    };

    /// `UV_ENOENT`: no such variable.
    pub const UV_ENOENT: c_int = -libc::ENOENT;
    /// `UV_ENOBUFS`: the buffer was too small; the needed size was written back.
    pub const UV_ENOBUFS: c_int = -libc::ENOBUFS;
    /// `UV_EINVAL`: a rejected argument, such as a name containing a NUL.
    pub const UV_EINVAL: c_int = -libc::EINVAL;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The variables these tests own. Each test cleans up after itself, and the
    /// names are distinctive so a leaked one is obvious in a failing run.
    const SCRATCH: &str = "RN_ENV_TEST_SCRATCH";

    /// Serialises the tests that touch the **real** block.
    ///
    /// The store is thread-local but the process environment is not: cargo runs
    /// these on parallel threads, so two tests that each set and clear `SCRATCH`
    /// interleave — one clears what the other just wrote and the failure points
    /// at the wrong assertion. Measured before this existed: the
    /// `a=b=c` round-trip test failed while every individual step was correct.
    /// The map-store test does not need it, because it never touches the block.
    static REAL_BLOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Takes the lock for a test that touches the real block.
    ///
    /// A poisoned lock is still a lock: an earlier failure must not cascade into
    /// unrelated failures that hide it.
    fn real() -> std::sync::MutexGuard<'static, ()> {
        let guard = REAL_BLOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_real();
        guard
    }

    fn clear(name: &str) {
        unset(name);
        assert_eq!(get(name), None, "{name} should be gone");
    }

    #[test]
    fn a_written_variable_reads_back() {
        let _real = real();
        clear(SCRATCH);
        assert_eq!(set(SCRATCH, "value"), 0);
        assert_eq!(get(SCRATCH).as_deref(), Some("value"));
        clear(SCRATCH);
    }

    #[test]
    fn a_variable_that_was_never_set_is_none_not_empty() {
        // The distinction `process.env.X === undefined` depends on: an unset
        // variable is absent, and one set to the empty string is present.
        let _real = real();
        clear(SCRATCH);
        assert_eq!(get(SCRATCH), None);
        assert_eq!(set(SCRATCH, ""), 0);
        assert_eq!(get(SCRATCH).as_deref(), Some(""));
        assert!(contains(SCRATCH));
        clear(SCRATCH);
        assert!(!contains(SCRATCH));
    }

    #[test]
    fn a_long_value_survives_the_initial_buffer_size() {
        // 4 KiB is well past the 256-byte first attempt, so this exercises the
        // `UV_ENOBUFS` retry rather than the common path.
        let _real = real();
        clear(SCRATCH);
        let value = "x".repeat(4096);
        assert_eq!(set(SCRATCH, &value), 0);
        assert_eq!(get(SCRATCH).as_deref(), Some(value.as_str()));
        clear(SCRATCH);
    }

    #[test]
    fn a_value_containing_an_equals_sign_round_trips() {
        // `uv_os_environ` splits at the *first* `=`, so a value with more of
        // them has to survive both the get and the enumeration.
        let _real = real();
        clear(SCRATCH);
        assert_eq!(set(SCRATCH, "a=b=c"), 0);
        assert_eq!(get(SCRATCH).as_deref(), Some("a=b=c"));
        let entry = vars().into_iter().find(|entry| entry.name == SCRATCH);
        assert_eq!(entry.map(|entry| entry.value).as_deref(), Some("a=b=c"));
        clear(SCRATCH);
    }

    #[test]
    fn enumeration_sees_a_variable_written_through_the_same_block() {
        // The property that matters for `spawn()`: a value assigned from
        // JavaScript is in the block a child copies, because both go through
        // libuv rather than through a Rust-side `std::env` mirror.
        let _real = real();
        clear(SCRATCH);
        assert_eq!(set(SCRATCH, "seen-by-child"), 0);
        let names: Vec<String> = vars().into_iter().map(|entry| entry.name).collect();
        assert!(
            names.iter().any(|name| name == SCRATCH),
            "the variable the block was just given should be enumerated"
        );
        let pairs = pairs();
        assert!(
            pairs
                .iter()
                .any(|pair| pair == &format!("{SCRATCH}=seen-by-child")),
            "the spawn form should carry the value the block was given"
        );
        clear(SCRATCH);
    }

    #[test]
    fn unsetting_a_variable_that_is_not_set_is_not_an_error() {
        // `delete process.env.NON_EXISTING` returns true in Node, so the layer
        // above must not see a failure here.
        let _real = real();
        clear(SCRATCH);
        assert_eq!(unset(SCRATCH), 0);
        assert_eq!(unset(SCRATCH), 0);
    }

    #[test]
    fn a_name_with_a_nul_is_rejected_rather_than_truncated() {
        // `CString::new` refuses it, and a truncated name would silently write
        // a different variable.
        let _real = real();
        assert_eq!(set("RN_ENV\0BAD", "x"), uv::UV_EINVAL);
        assert_eq!(get("RN_ENV\0BAD"), None);
        assert!(!contains("RN_ENV\0BAD"));
    }

    #[test]
    fn a_map_store_is_private_to_the_thread_that_installed_it() {
        // A worker's environment: the parent's assignments are invisible, and
        // the worker's do not escape. This is what
        // `test/worker/test-worker-process-env.js` asserts from JavaScript.
        //
        // This test *does* read the real block once, to seed the parent-only
        // variable, so it takes the lock too.
        let _real = real();
        clear(SCRATCH);
        set("RN_ENV_TEST_PARENT_ONLY", "parent");

        install_map([("RN_ENV_TEST_WORKER_ONLY", "worker")]);
        assert_eq!(
            get("RN_ENV_TEST_WORKER_ONLY").as_deref(),
            Some("worker"),
            "the worker's own variable is readable in the worker"
        );
        assert_eq!(
            get("RN_ENV_TEST_PARENT_ONLY"),
            None,
            "the parent's variable is not in a copy taken before it was set"
        );
        set("RN_ENV_TEST_WORKER_WRITE", "1");
        assert_eq!(get("RN_ENV_TEST_WORKER_WRITE").as_deref(), Some("1"));
        let keys: Vec<String> = vars().into_iter().map(|entry| entry.name).collect();
        assert_eq!(
            keys,
            vec![
                "RN_ENV_TEST_WORKER_ONLY".to_string(),
                "RN_ENV_TEST_WORKER_WRITE".to_string()
            ],
            "a map store enumerates only its own entries, in name order"
        );
        unset("RN_ENV_TEST_WORKER_WRITE");
        assert_eq!(get("RN_ENV_TEST_WORKER_WRITE"), None);

        install_real();
        assert_eq!(
            get("RN_ENV_TEST_WORKER_WRITE"),
            None,
            "the worker's write must not have reached the real block"
        );
        unset("RN_ENV_TEST_PARENT_ONLY");
    }

    #[test]
    fn snapshot_copies_the_real_block() {
        let _real = real();
        clear(SCRATCH);
        assert_eq!(set(SCRATCH, "before"), 0);
        let copied = snapshot();
        assert!(copied
            .iter()
            .any(|(name, value)| name == SCRATCH && value == "before"));
        assert_eq!(set(SCRATCH, "after"), 0);
        let still = copied
            .iter()
            .find(|(name, _)| name == SCRATCH)
            .map(|(_, value)| value.as_str());
        assert_eq!(
            still,
            Some("before"),
            "a snapshot is a copy, not a view of the live block"
        );
        clear(SCRATCH);
    }
}
