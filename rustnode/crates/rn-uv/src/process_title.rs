//! The process title and the inspector port, which libuv and the CLI own.
//!
//! `process.title` is not a string stored on an object. Node's
//! `ProcessTitleSetter` (`src/node_process_object.cc:44`) calls
//! `uv_set_process_title`, which rewrites the process's `argv[0]` area in place,
//! so `ps`, `top` and `/proc/<pid>/cmdline` all show the new name. A plain
//! assignment to a Rust-side `String` would read back correctly and change
//! nothing observable, which is exactly the defect this module exists to avoid.
//!
//! # Why `uv_setup_args` has to run first
//!
//! `uv_set_process_title` answers `UV_ENOBUFS` until `uv_setup_args` has copied
//! the argument block into the memory libuv will overwrite
//! (`libuv/src/unix/proctitle.c`: `if (args_mem == NULL) return UV_ENOBUFS`).
//! Node calls it at the very start of `main`, before anything else looks at
//! `argv`. [`setup_args`] is the equivalent, and until it has run the title is
//! unsettable — so it is called once from `main` rather than lazily.
//!
//! # The title is the executable path until it is changed
//!
//! `uv_setup_args` seeds the title with `argv[0]`, and `uv_get_process_title`
//! then reports that. Node's `GetProcessTitle("node")` falls back to the literal
//! `"node"` only when libuv has no title at all, so before any assignment the
//! oracle reports its own resolved executable path. [`process_title`] reproduces
//! that: libuv's answer when there is one, `"node"` when there is not.

use std::ffi::CString;
use std::sync::OnceLock;

use libuv_sys2 as uv;

/// The inspector port `process.debugPort` reports and its setter validates.
///
/// Node keeps this in the environment's `HostPort` (`ExclusiveAccess<HostPort>`),
/// which holds the port a `--inspect-port` asked for whether or not an endpoint
/// was opened. There is no endpoint object to hang it on here, so it is one
/// process-wide cell — the same scope Node's main-thread environment has.
static DEBUG_PORT: OnceLock<std::sync::atomic::AtomicU16> = OnceLock::new();

/// The default `--inspect-port`, which is Node's `9229`.
pub const DEFAULT_DEBUG_PORT: u16 = 9229;

fn debug_port_cell() -> &'static std::sync::atomic::AtomicU16 {
    DEBUG_PORT.get_or_init(|| std::sync::atomic::AtomicU16::new(DEFAULT_DEBUG_PORT))
}

/// The port `process.debugPort` reports.
pub fn debug_port() -> u16 {
    debug_port_cell().load(std::sync::atomic::Ordering::Relaxed)
}

/// Stores the port `process.debugPort` reports.
///
/// Validation belongs to the caller: `DebugPortSetter` in Node refuses anything
/// but `0` and `1024..=65535` and throws `ERR_OUT_OF_RANGE`, and the CLI's own
/// parser rejects a bad `--inspect-port` before this is reached. A second check
/// here would be a second answer to the same question.
pub fn set_debug_port(port: u16) {
    debug_port_cell().store(port, std::sync::atomic::Ordering::Relaxed);
}

/// Hands libuv the argument block it needs before the title can be rewritten.
///
/// This must run before any `process.title` write, and before anything else
/// reads `argv` through libuv.
///
/// # Why this takes no arguments
///
/// `uv_setup_args` does not copy the strings: it keeps the pointers it is given
/// and rewrites *that* memory on every title change, and `ps` and
/// `/proc/<pid>/cmdline` read the same block. So the block handed over has to be
/// the process's real `argv`, which glibc exposes as
/// `program_invocation_name` — the address of `argv[0]` in the kernel-provided
/// block, immediately followed by the later arguments.
///
/// Passing freshly allocated copies, which is what a `Vec<CString>` built from
/// `std::env::args_os()` would be, still makes `ps -o comm=` change (that reads
/// the comm name libuv sets separately) while `/proc/<pid>/cmdline` keeps showing
/// the original command line. That is a half-rename, and it is what the first
/// version of this function did.
///
/// # Contiguity
///
/// The arguments are walked from `program_invocation_name` until the strings stop
/// matching `std::env::args_os()`, which is where the kernel's `argv` block ends.
/// Only the contiguous prefix is handed over: libuv's own length computation
/// (`pt.cap = argv[i - 1] + size - argv[0]`) assumes one block, so a pointer
/// table assembled across separate allocations would be wrong. In practice the
/// whole of `argv` is contiguous, and the walk asserts it rather than assuming
/// it.
pub fn setup_args() {
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: `program_invocation_name` is a glibc global pointing at `argv[0]`
    // in the kernel-provided block, which lives for the whole process.
    let base = unsafe { program_invocation_name() };
    if base.is_null() {
        return;
    }

    let arguments: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if arguments.is_empty() {
        return;
    }

    // Collect the addresses of the contiguous prefix.
    let mut pointers: Vec<*mut libc::c_char> = Vec::with_capacity(arguments.len() + 1);
    let mut cursor = base;
    for argument in &arguments {
        // SAFETY: `cursor` starts at `argv[0]` and only ever advances past a
        // NUL-terminated string inside the same block. Reading a string with no
        // terminator in the block would be undefined, which is why the walk stops
        // at the first argument that does not match the real one below.
        let here = unsafe { std::ffi::CStr::from_ptr(cursor) };
        if here.to_bytes() != argument.as_bytes() {
            break;
        }
        pointers.push(cursor);
        // SAFETY: as above — advancing by the string's length plus its NUL stays
        // inside the block for every argument that matched.
        cursor = unsafe { cursor.add(here.to_bytes().len() + 1) };
    }
    if pointers.is_empty() {
        return;
    }
    pointers.push(std::ptr::null_mut());

    // SAFETY: `pointers` is a null-terminated table of addresses inside the live
    // kernel `argv` block, which `uv_setup_args` only reads. It records the block
    // so later title changes rewrite the memory `ps` reads.
    unsafe {
        uv::uv_setup_args((pointers.len() - 1) as i32, pointers.as_mut_ptr());
    }
}

/// The address of `argv[0]` in the kernel-provided argument block.
///
/// glibc's `program_invocation_name` is exactly that pointer. Declared here
/// rather than through `libc` because the crate's `libc` version does not export
/// it, and the alternative — declaring `__libc_argv` — is not part of glibc's
/// stable ABI while this symbol is the documented glibc extension.
#[cfg(target_env = "gnu")]
unsafe fn program_invocation_name() -> *mut libc::c_char {
    extern "C" {
        static mut program_invocation_name: *mut libc::c_char;
    }
    // SAFETY: the caller guarantees this runs in a normal glibc process, where
    // the symbol is initialised by the C runtime before `main`.
    unsafe { program_invocation_name }
}

/// No equivalent global outside glibc.
///
/// On musl and the BSDs `uv_setup_args` also needs the real `argv`, but there is
/// no documented way to reach it from a Rust `main`, so the title cannot be
/// rewritten there. Returning null leaves the title at libuv's fallback rather
/// than renaming a copy that `ps` would not see.
#[cfg(not(target_env = "gnu"))]
unsafe fn program_invocation_name() -> *mut libc::c_char {
    std::ptr::null_mut()
}

/// `process.title`: libuv's current title, or Node's `"node"` fallback.
pub fn process_title() -> Option<String> {
    // libuv's buffer size is fixed at `uv_setup_args` time. Its documented
    // approach is a `uv_get_process_title` call with a buffer, retrying with a
    // larger one when it answers `UV_ENOBUFS`; the title is bounded by the
    // original argv block, so a few rounds always settle.
    let mut capacity = 512usize;
    for _ in 0..8 {
        let mut buffer = vec![0 as libc::c_char; capacity];
        // SAFETY: `buffer` is `capacity` writable bytes, which is what
        // `uv_get_process_title` writes at most.
        let status = unsafe { uv::uv_get_process_title(buffer.as_mut_ptr(), capacity) };
        if status == 0 {
            // SAFETY: on success libuv wrote a NUL-terminated string.
            let text = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
            return Some(text.to_string_lossy().into_owned());
        }
        if status == uv::uv_errno_t_UV_ENOBUFS {
            capacity *= 2;
            continue;
        }
        break;
    }
    // Node's `GetProcessTitle` falls back to this literal when libuv has no
    // title, which is the state when `uv_setup_args` never ran.
    Some("node".to_string())
}

/// `process.title = value`: renames the process the way Node's setter does.
///
/// Returns whether libuv accepted it. A failure is not thrown: Node's setter
/// ignores `uv_set_process_title`'s return value, so a title that could not be
/// stored is a silent no-op there too. The boolean is for tests and logs.
pub fn set_process_title(title: &str) -> bool {
    // An interior NUL would truncate the title at the C boundary; Node's
    // `Utf8Value` would carry it through and libuv's `strlen` would stop there,
    // so truncating matches.
    let bytes = title.as_bytes();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let Ok(value) = CString::new(&bytes[..end]) else {
        return false;
    };
    // SAFETY: `value` is a live NUL-terminated string for the duration of the
    // call, and libuv copies from it before returning.
    unsafe { uv::uv_set_process_title(value.as_ptr()) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default port is Node's, and a set value reads back.
    ///
    /// This is the invariant `process.debugPort` depends on: the getter must see
    /// what the setter stored, or a `--inspect-port=9339` would report 9229.
    #[test]
    fn the_debug_port_round_trips_and_defaults_to_nodes() {
        assert_eq!(DEFAULT_DEBUG_PORT, 9229, "Node's --inspect-port default");
        let original = debug_port();
        set_debug_port(9339);
        assert_eq!(debug_port(), 9339);
        set_debug_port(original);
    }

    /// Before `uv_setup_args` the title falls back to Node's literal.
    ///
    /// A thread of its own, because `uv_setup_args` is process-global and this
    /// must observe a process where it has not run. The assertion is on the
    /// fallback rather than on `None` because Node's `GetProcessTitle("node")`
    /// substitutes that string.
    #[test]
    fn the_title_falls_back_to_node_without_setup_args() {
        // A title set here cannot be stored, so the read-back stays the fallback.
        // This is the documented consequence of calling the setter before
        // `uv_setup_args`, not a bug: `uv_set_process_title` answers UV_ENOBUFS.
        if uv_setup_ran() {
            return;
        }
        assert_eq!(process_title().as_deref(), Some("node"));
    }

    /// Whether this process has handed libuv its argument block yet.
    ///
    /// Probed rather than recorded, because `setup_args` runs from `main` and the
    /// test binary's `main` is the harness's: a process where the title is
    /// already a real path has had it called.
    fn uv_setup_ran() -> bool {
        let mut buffer = vec![0 as libc::c_char; 64];
        // SAFETY: the buffer is 64 writable bytes.
        let status = unsafe { uv::uv_get_process_title(buffer.as_mut_ptr(), 64) };
        status == 0
    }
}
