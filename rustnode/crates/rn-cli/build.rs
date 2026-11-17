//! Publishes the symbols an addon resolves against this binary's dynamic table.
//!
//! # Why this file has to exist in the binary crate
//!
//! A `.node` addon is a shared object whose `napi_*` imports are undefined. When
//! the dynamic loader opens it, those imports are resolved against the global scope
//! of the process, which for a normal executable contains only what the linker was
//! asked to publish. The rustnode binary therefore has to export the `napi_*`
//! functions `rn-napi` defines, and the libuv functions an addon gets from
//! `#include <uv.h>`.
//!
//! `cargo::rustc-link-arg` applies to the crate whose build script emits it, and
//! cargo does **not** forward it from a library dependency to the final binary. That
//! is not a guess: with the flag emitted from `rn-napi`'s build script the built
//! executable's `.dynsym` still contained zero `napi_*` entries, and the same flag
//! emitted here puts all of them in. So the flag lives here, beside the `[[bin]]`
//! target, and `rn-napi`'s crate docs point at this file.
//!
//! # Why the pattern form and not `--export-dynamic`
//!
//! `--export-dynamic` (`-rdynamic`) publishes every global symbol: thousands of
//! entries, a larger `.dynsym`, slower startup, and every internal symbol made
//! interposable by any addon that declares a matching name. `--export-dynamic-symbol`
//! publishes exactly the named families and nothing else.
//!
//! # Why `uv_*` is one of those families
//!
//! Node-API's `napi_get_uv_event_loop` hands an addon a `uv_loop_t*`, and once an
//! addon has that it is expected to be able to drive the loop with anything
//! `uv.h` declares — `uv_timer_init`, `uv_check_init`, `uv_async_init`, the
//! `uv_mutex_*` and `uv_thread_*` families, `uv_queue_work`. These are ordinary
//! libuv calls the addon makes itself, not Node-API entry points, so `napi_*`
//! alone cannot cover them, and six files of Node's `test/node-api/` failed on
//! exactly that: the addon built, then `dlopen` aborted on
//! `symbol lookup error: undefined symbol: uv_sleep`.
//!
//! The whole family, rather than the five names those six files happened to
//! need. The oracle build exports 318 `uv_*` symbols from a statically linked
//! libuv (`nm -D` on the pinned Node 28 nightly), so an addon that links against
//! Node may use any of them and expect the host to resolve it. A hand-picked list
//! would be a list of the calls the tests written so far happen to make, and would
//! break again — at load time, with the same opaque loader message — on the next
//! addon that calls something else. Publishing what Node publishes is the
//! compatible choice, and it is not an overreach: this is the surface Node has
//! always had.
//!
//! What the glob publishes is narrower than it looks, and the reason is libuv's
//! build rather than the pattern's shape: libuv is compiled with
//! `-fvisibility=hidden`, so its `uv__` internals are not in the binary's symbol
//! table for any pattern to match. Widening this glob to `uv*` publishes zero
//! additional names — measured — so `uv_*` and `uv*` are equivalent here, and the
//! underscore is kept because it states the intent. No Rust crate in this
//! workspace defines a `uv_*` symbol of its own, so the family is exactly the
//! public libuv API, which is the same set `--export-dynamic` would publish for
//! libuv without publishing the thousands of Rust internals alongside it.
//!
//! One consequence worth knowing when this is next touched: `uv_*` and `napi_*`
//! are now part of the binary's visible ABI, the same way they are part of Node's.
//! An addon binds them at open time, so renaming one or dropping the libuv
//! dependency would break already-built addons with the loader error above rather
//! than a compile error in this repository.
//!
//! # Windows
//!
//! Windows has no link-time equivalent: a DLL export is declared on the definition
//! (`__declspec(dllexport)`) and an addon links against an import library. That is
//! separate work, recorded as deferred rather than silently omitted, so a Windows
//! build says so at compile time instead of failing at addon load. Adding `uv_*`
//! here does not change that: these flags are emitted for `unix` targets only, and
//! a Windows addon still needs the import library that does not exist yet.

fn main() {
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if family == "unix" {
        // Each glob is expanded by the linker against defined symbols. `napi_*` and
        // `node_api_*` cover Node-API's two spellings; `uv_*` covers the libuv
        // surface an addon is handed a loop to drive (see above).
        println!("cargo::rustc-link-arg=-Wl,--export-dynamic-symbol=napi_*");
        println!("cargo::rustc-link-arg=-Wl,--export-dynamic-symbol=node_api_*");
        println!("cargo::rustc-link-arg=-Wl,--export-dynamic-symbol=uv_*");
    }
    if family == "windows" {
        println!(
            "cargo::warning=rn-napi publishes Node-API and libuv symbols from the binary on \
             Unix only; a Windows addon needs the import-library path, which is not built"
        );
    }
    println!("cargo::rerun-if-changed=build.rs");
}
