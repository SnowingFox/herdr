//! Builds the C test addon, or fails loudly.
//!
//! Every test in this crate's addon suite needs a compiled `.node` file, and the
//! one thing that must never happen is a test passing against a **stale** binary
//! from an earlier build. That has masked a real regression twice in this project
//! (see `rustnode/AGENTS.md` and `tools/check.sh`), so this helper:
//!
//! * recompiles the addon unconditionally on every test run — no timestamp check,
//!   no cache;
//! * deletes the output before compiling, so a failed compile cannot leave the
//!   previous artifact in place for the test to load;
//! * [`build_addon_or_abort`] calls `abort()` when the compile fails, so a run
//!   cannot report "1 passed" from a binary nobody built;
//! * and the compiled library is verified to actually export
//!   `napi_register_module_v1` before it is handed to a test.
//!
//! The `abort` in step three is the whole point: a normal Rust panic would still
//! be caught and reported as a test failure that a wrapper script might interpret
//! as "the build is fine, just one test failed". `abort` kills the process with
//! `SIGABRT`, which no summary line can turn into a pass.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The addon source, next to this file.
pub fn source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/addon")
}

/// Where the compiled addon is written.
///
/// A per-process directory so two test binaries running at once cannot overwrite
/// each other's artifact mid-load. `dlopen` keeps reading the file it mapped, so a
/// clobber would not crash — it would silently change which build a later assertion
/// was made against, which is worse.
pub fn output_path() -> PathBuf {
    std::env::temp_dir()
        .join(format!(
            "rn-napi-addon-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
        .join("addon.node")
}

/// The result of a compile attempt.
pub struct Build {
    pub path: PathBuf,
    /// Everything the compiler said.
    ///
    /// A warning from the addon's own build is worth seeing when a test is being
    /// debugged, so it is kept rather than discarded. Nothing asserts on it.
    #[allow(dead_code)]
    pub diagnostics: String,
}

/// Compiles the addon, returning an error string on failure.
///
/// The output file is removed first: a compile that fails must not leave a previous
/// artifact behind for anything to find.
pub fn build_addon() -> Result<Build, String> {
    let source = source_dir();
    let output = output_path();
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("mkdir: {error}"))?;
    }
    // Remove before compiling, not after. If this line is skipped a failed compile
    // leaves the old library in place and every test silently measures it.
    let _ = std::fs::remove_file(&output);

    let compile = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
        // The pinned Node-API headers live beside the source so the ABI under test
        // is the project's pin rather than whatever `node` is installed.
        .arg("-I")
        .arg(&source)
        .arg("-o")
        .arg(&output)
        // Two translation units: the synchronous bridge in `addon.c` and the
        // asynchronous surface in `addon_async.c`. They are one addon, so both
        // objects go into the one `.node` and share `report_failure`.
        .arg(source.join("addon.c"))
        .arg(source.join("addon_async.c"))
        .arg(source.join("addon_wrap.c"))
        // `addon_async.c` starts a real producer thread with `pthread_create`, which
        // is the point: the thread-safe function has to be called from a thread
        // that is not the isolate's. Linking pthread is what makes that a real
        // second thread rather than a signal handler.
        .arg("-pthread")
        .output()
        .map_err(|error| format!("could not run cc: {error}"))?;

    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );

    if !compile.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!(
            "addon.c failed to compile ({}):\n{diagnostics}",
            compile.status
        ));
    }

    // A successful `cc` that produced nothing would make every test fail with a
    // confusing `dlopen` error; name the real problem instead.
    if !output.is_file() {
        return Err(format!(
            "cc reported success but {} does not exist:\n{diagnostics}",
            output.display()
        ));
    }

    // The entry point is what the runtime looks for, so a build that does not
    // export it is not a usable addon regardless of what the compiler said.
    verify_entry_point(&output)?;

    Ok(Build {
        path: output,
        diagnostics,
    })
}

/// Compiles the addon or aborts the whole process.
///
/// Aborting rather than panicking is deliberate: see the module docs. A test that
/// cannot build its fixture has measured nothing, and must not be able to report a
/// result at all.
pub fn build_addon_or_abort() -> Build {
    match build_addon() {
        Ok(build) => build,
        Err(error) => {
            // Written straight to stderr so it appears even when the harness
            // captures stdout, and then a signal no summary can swallow.
            eprintln!("FATAL: the Node-API test addon could not be built.\n{error}");
            eprintln!("Refusing to report a test result against a binary that was not built.");
            std::process::abort();
        }
    }
}

/// Checks the compiled library exports `napi_register_module_v1`.
///
/// `nm -D --defined-only` prints the dynamic symbol table; the entry point must be
/// there or the runtime would report `Module did not self-register` for a fixture
/// that was supposed to work.
fn verify_entry_point(path: &Path) -> Result<(), String> {
    let symbols = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(path)
        .output()
        .map_err(|error| format!("could not run nm: {error}"))?;
    let text = String::from_utf8_lossy(&symbols.stdout);
    if text.contains("napi_register_module_v1") {
        Ok(())
    } else {
        Err(format!(
            "{} does not export napi_register_module_v1; its dynamic symbols were:\n{text}",
            path.display()
        ))
    }
}

/// The undefined `napi_*` symbols an addon requires from the host.
///
/// Used by the symbol test to prove the addon really does import the functions this
/// runtime exports, rather than having been compiled against something that
/// resolved them locally.
#[allow(dead_code)]
pub fn required_napi_imports(path: &Path) -> Result<Vec<String>, String> {
    let symbols = Command::new("nm")
        .args(["-u"])
        .arg(path)
        .output()
        .map_err(|error| format!("could not run nm: {error}"))?;
    let text = String::from_utf8_lossy(&symbols.stdout);
    Ok(text
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|name| name.starts_with("napi_") || name.starts_with("node_api_"))
        .map(str::to_string)
        .collect())
}
