# rustnode

A Node runtime with its native layer rewritten in Rust.

`rustnode` keeps the parts that determine observable behaviour and replaces the
parts that only exist to glue them to the OS.

| Layer | Source | Status |
| --- | --- | --- |
| JavaScript engine | V8, pinned to the version Node 28 ships | reused unchanged |
| Node builtin JS (`lib/**` 435 files + `deps/undici/undici.js`) | vendored byte-identical from Node 28 | reused unchanged, hash-frozen |
| Native layer (`src/**`, ~156k lines of C++) | this repository, Rust | being rewritten |
| Event loop | libuv semantics first, io_uring backend later | in progress |

## Why this differs from Bun

Bun replaces the engine with JSC and reimplements Node's JavaScript layer, so
behaviour differences are tracked by patching individual gaps. `rustnode`
replaces neither: the engine is the same V8, and every builtin JS file is the
same file Node ships. Compatibility is therefore structural, not per-API.

The only thing that changes is the native layer, which the JavaScript layer
reaches through `internalBinding()`.

## Guarantees enforced in CI

- `vendor/libnode-js/LIBJS.sha256` freezes all 435 `lib/**` builtin files and the
  `deps/undici/undici.js` bundle. Any edit fails the build, so behaviour cannot
  drift into a JS fork. The two trees keep separate exact counts, so one gaining
  a file while the other loses one cannot balance out.
- `contracts/*.json` records the exact shape every `internalBinding()` namespace
  must expose, captured from a real Node binary. `rn-compat` fails the build
  when a Rust namespace does not match.
- The acceptance suite is Node's own `test/` tree, not a curated subset.

## Layout

```text
crates/rn-v8-sys    pinned V8 identity and linkage
crates/rn-core      Env, BaseObject, AsyncWrap kernel
crates/rn-bindings   the 73 internalBinding namespaces
crates/rn-builtin-codegen
                    compiles a builtin, and generates its V8 code cache
crates/rn-module    CJS and ESM loading
crates/rn-io        event loop backends
crates/rn-napi      Node-API for prebuilt addons
crates/rn-cli       the rustnode executable
tools/contract-gen  records binding shapes from a real Node binary
tools/compat        checks Rust bindings against those contracts
tools/harness       pass-rate dashboard over Node's test suite
contracts           generated binding contracts
vendor/libnode-js   hash-frozen Node builtin JavaScript
```

## Building

```bash
rustup toolchain install 1.96.1
cargo build
./target/debug/rustnode -p '1+1'
```

V8 arrives as the prebuilt `v8` crate. No local V8 build is required.

## Environment switches

`rustnode` runs on libuv's loop on every platform. On Linux the *readiness wait*
inside that loop has two implementations, and the default is the one every
release has shipped:

| Variable | Effect |
| --- | --- |
| `HERDR_URING=1` | Serve the loop's readiness wait from an `io_uring` submission queue instead of `epoll_pwait(2)`. Readiness is reported as a poll mask, so reads, writes and accepts produce the same completions the epoll path produces. Timers, signals and threadpool work are unaffected. |
| unset, `0`, or anything else | `epoll_pwait(2)`, libuv's own path. |

The switch is a request, not a requirement. If `io_uring_setup(2)` fails — an
older kernel (`ENOSYS`), a seccomp filter or `kernel.io_uring_disabled` (`EPERM`),
or no memory for the rings (`ENOMEM`) — the loop logs a warning and uses epoll.
A program is never aborted because the kernel would not provide a ring.

It is opt-in because the io_uring path is newer than the epoll one, and a broken
accelerator must not be able to break users who did not ask for it. The epoll
path is unchanged by its presence: when the variable is unset, the interposed
wait is a direct pass-through to the same syscall.

## Milestones

M0 evaluates JavaScript and reports errors with Node's exit codes. Later
milestones are tracked in the project tracker.
