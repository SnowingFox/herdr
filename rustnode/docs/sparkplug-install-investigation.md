# Sparkplug install crash investigation (`test-diagnostics-channel-child-process`)

## Final outcome

The crash was fixed in `rn-bind-process-wrap` by aligning failed-spawn handle
lifecycle with Node.

## Repro setup

All runs were executed from `/tmp/rustnode-node-src` with:

- `env -u NODE_DISABLE_COMPILE_CACHE`
- release `rustnode` binary
- target: `test/parallel/test-diagnostics-channel-child-process.js`

## Before/after counts (30-run samples)

- before fix (`2b07ea18`): **18/30 pass, 12/30 segfault**
- before-fix control (`--no-baseline-batch-compilation`): **30/30 pass**
- after fix (`922a1189`): **30/30 pass, 0/30 segfault**

## Root cause

`ProcessWrap::spawn` in rustnode diverged from Node's lifecycle semantics on
`uv_spawn` error paths:

- rustnode used to mark a handle as initialized only on `uv_spawn == 0`
- rustnode set `uv_process_t.data` only on success
- `close()` therefore took a direct free path on failed spawns

But libuv can still leave a handle state that must be retired by `uv_close`
even when `uv_spawn` returns an error (reproducibly with failing child spawns,
for example EACCES). Freeing that state outside libuv creates stale-pointer /
memory-corruption behavior, which later surfaced in unrelated interrupt handling
paths such as `ConcurrentBaselineCompiler::InstallBatch`.

## Why Node does not reproduce at the same V8 commit

Node's `ProcessWrap::Spawn` marks the handle initialized once `uv_spawn` has
been called and keeps close/teardown on libuv's normal path even for spawn
errors. That avoids the stale-handle lifetime gap above, so the V8 crash does
not reproduce there under the same V8 revision.
