# herdr TypeScript port

Work-in-progress rewrite of herdr in TypeScript with a napi-rs native module. The Rust code
under `../src` stays intact and is the parity oracle until cutover. The migration plan lives in
the project store (`docs/typescript-rewrite-plan.md`).

## Layout

| Package | Purpose |
|---|---|
| `packages/native` (`@herdr/native`) | napi-rs crate (own Cargo workspace): PTY, terminal emulation via the vendored `libghostty-vt` (reused through `../../crates/ghostty-vt`), process inspection, unicode width |
| `packages/core` (`@herdr/core`) | Pure state: ids, BSP layout, tabs, workspaces, `AppState`. No I/O, no native imports (enforced by `architecture.test.ts`) |

Dependency direction: `core` has no dependencies; only later runtime packages may import `native`.

## Prerequisites

- Node 22+, pnpm 10
- Rust 1.96.1 (pinned by `packages/native/rust-toolchain.toml`)
- Zig 0.16.0 on `PATH` or in `ZIG` (required to build `libghostty-vt`, same as the Rust binary)

## Commands

```bash
pnpm install
pnpm build:native:debug   # napi build (debug), writes packages/native/*.node + index.{js,d.ts}
pnpm check                # native debug build + typecheck + vitest
cd packages/native && cargo test && cargo clippy --all-targets -- -D warnings
```

`just ts-check` runs all of the above.

## Native API conventions

- Coarse-grained calls, typed-array snapshots; never per-cell or per-byte FFI in render/parse loops.
- One coalesced wake-up per session: native threads queue events and JS drains them with `takeEvents()`.
- Native errors are thrown as `CODE: message`; `lib/errors.ts` turns them into `NativeError` with a `code`.
- OS-specific Rust lives only in `packages/native/src/platform/`.
