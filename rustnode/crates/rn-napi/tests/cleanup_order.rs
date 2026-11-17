//! Addon cleanup hooks run at exit, in Node's order.
//!
//! # What this pins, and why the obvious test does not
//!
//! `test/node-api/test_cleanup_hook` registers two hooks, removes one, and asserts
//! exactly one ran — so it covers *removal* but **cannot cover order**, because
//! only one hook survives to run. And before this change the hooks never ran at
//! all, because the runtime had no environment teardown path: `Env::run_cleanup_hooks`
//! existed and was correct, and nothing called it.
//!
//! So the two properties worth their own test are:
//!
//! * a hook **runs** at all, which is what was missing; and
//! * hooks run **newest-first**, which is Node's contract and the one an
//!   implementation is most likely to get backwards without any test noticing.
//!
//! The addon registers three hooks that each print their name, so stdout is the
//! whole assertion: `h3`, `h2`, `h1`. Registration order is `h1`, `h2`, `h3`, so a
//! passing run proves the drain reverses it.
//!
//! # Why the addon is compiled here rather than reused
//!
//! The shared `support` helper builds the crate's own addon, which has no cleanup
//! hooks. This test needs a different C file, so it compiles its own — and it
//! follows the same discipline: recompiled on every run, output deleted first, and
//! a failed compile aborts rather than fails. A stale `.node` here would produce a
//! pass against code nobody built.
//!
//! # Oracle comparison
//!
//! The expected order is not this crate's opinion: `node -e 'require(...)'` on the
//! same addon prints `h3 h2 h1` too. That is recorded in the report rather than
//! asserted against the oracle at test time, because the gate must not require a
//! Node binary to pass — the same reason the other addon tests do not.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The addon's source. Three hooks, printing their own names.
const ADDON_C: &str = r#"
#include <node_api.h>
#include <stdio.h>

static void h1(void* a) { printf("h1\n"); }
static void h2(void* a) { printf("h2\n"); }
static void h3(void* a) { printf("h3\n"); }

static napi_value Init(napi_env env, napi_value exports) {
  // Registered oldest-first. Node drains reverse-registration order, so the
  // expected stdout is h3, h2, h1.
  napi_add_env_cleanup_hook(env, h1, NULL);
  napi_add_env_cleanup_hook(env, h2, NULL);
  napi_add_env_cleanup_hook(env, h3, NULL);
  return NULL;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
"#;

const BINDING_GYP: &str = r#"{
  "targets": [
    {
      "target_name": "cleanup_order",
      "sources": ["addon.c"]
    }
  ]
}
"#;

/// The `rustnode` binary `cargo test` built alongside this test.
fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// Compiles the ordering addon into a per-process directory.
///
/// Per-process so two test binaries running at once cannot overwrite each other's
/// artifact mid-load. Deleting the output first means a failed compile cannot
/// leave the previous build for a later run to load.
fn build_addon() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rn-napi-cleanup-order-{:?}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory for the addon");
    std::fs::write(dir.join("addon.c"), ADDON_C).expect("the addon source is writable");
    std::fs::write(dir.join("binding.gyp"), BINDING_GYP).expect("binding.gyp is writable");

    let output = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-o",
            dir.join("cleanup_order.node").to_str().expect("utf-8 path"),
            dir.join("addon.c").to_str().expect("utf-8 path"),
            "-I",
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/addon")
                .to_str()
                .expect("utf-8 path"),
        ])
        .output()
        .expect("a C compiler is required to build the test addon");

    // `abort` rather than `panic`: a panic is caught and reported as one failing
    // test that a wrapper script can read as "build fine, one assertion failed".
    // This project has reported a pass against a stale binary before.
    if !output.status.success() {
        eprintln!(
            "the ordering addon did not compile:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::process::abort();
    }

    let path = dir.join("cleanup_order.node");
    assert!(
        path.is_file(),
        "the compile reported success and wrote nothing"
    );
    path
}

/// Runs `script` through the real binary and returns `(stdout, stderr, success)`.
fn run(script: &str) -> (String, String, bool) {
    let binary = rustnode();
    assert!(
        binary.is_file(),
        "{} does not exist; the CLI must be built before these tests (the gate does this)",
        binary.display()
    );
    let output = Command::new(&binary)
        .arg("-e")
        .arg(script)
        .output()
        .expect("the rustnode binary must be runnable");
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
        output.status.success(),
    )
}

/// Every registered cleanup hook runs when the process exits.
///
/// Before the teardown path existed this printed nothing: the hooks were
/// registered and never called, which is precisely what `test_cleanup_hook` fails
/// on upstream.
#[test]
fn cleanup_hooks_run_at_exit() {
    let addon = build_addon();
    let script = format!(r#"require({:?});"#, addon.to_str().expect("utf-8 path"));
    let (stdout, stderr, success) = run(&script);

    assert!(
        success,
        "the process exited non-zero; stderr was {stderr:?}"
    );
    assert!(
        !stdout.is_empty(),
        "no cleanup hook ran at all: the environment teardown path is not reached, \
         so `napi_add_env_cleanup_hook` registrations are stored and never invoked"
    );
}

/// Hooks run newest-first, which is Node's reverse-registration contract.
///
/// This is the property a single-hook test cannot see, and the one an
/// implementation most plausibly gets backwards while still "running the hooks".
#[test]
fn cleanup_hooks_run_in_reverse_registration_order() {
    let addon = build_addon();
    let script = format!(r#"require({:?});"#, addon.to_str().expect("utf-8 path"));
    let (stdout, stderr, success) = run(&script);

    assert!(
        success,
        "the process exited non-zero; stderr was {stderr:?}"
    );
    assert_eq!(
        stdout, "h3\nh2\nh1",
        "cleanup hooks must drain in reverse registration order (registered h1, h2, h3; \
         Node prints h3, h2, h1). Got {stdout:?}"
    );
}

/// A hook that is removed before exit does not run.
///
/// The same property `test_cleanup_hook` covers upstream, pinned here because the
/// drain takes the list before iterating it and a removal is therefore easy to
/// lose.
#[test]
fn a_removed_cleanup_hook_does_not_run() {
    let dir = std::env::temp_dir().join(format!("rn-napi-cleanup-remove-{:?}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory");
    std::fs::write(
        dir.join("addon.c"),
        r#"
#include <node_api.h>
#include <stdio.h>
static void kept(void* a) { printf("kept\n"); }
static void removed(void* a) { printf("removed\n"); }
static napi_value Init(napi_env env, napi_value exports) {
  napi_add_env_cleanup_hook(env, kept, NULL);
  napi_add_env_cleanup_hook(env, removed, NULL);
  napi_remove_env_cleanup_hook(env, removed, NULL);
  return NULL;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
"#,
    )
    .expect("the addon source is writable");

    let output = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-o",
            dir.join("cleanup_remove.node")
                .to_str()
                .expect("utf-8 path"),
            dir.join("addon.c").to_str().expect("utf-8 path"),
            "-I",
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/addon")
                .to_str()
                .expect("utf-8 path"),
        ])
        .output()
        .expect("a C compiler is required to build the test addon");
    if !output.status.success() {
        eprintln!(
            "the removal addon did not compile:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::process::abort();
    }

    let addon = dir.join("cleanup_remove.node");
    let script = format!(r#"require({:?});"#, addon.to_str().expect("utf-8 path"));
    let (stdout, stderr, success) = run(&script);

    assert!(
        success,
        "the process exited non-zero; stderr was {stderr:?}"
    );
    assert_eq!(
        stdout, "kept",
        "a hook removed before teardown must not run; got {stdout:?}"
    );
}
