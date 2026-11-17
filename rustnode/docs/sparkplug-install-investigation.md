# Sparkplug install crash investigation (`test-diagnostics-channel-child-process`)

## Repro and controls (release binary)

All runs were executed from `/tmp/rustnode-node-src` with:

- `env -u NODE_DISABLE_COMPILE_CACHE`
- `/agent/repos/herdr-worktrees/sparkplug/rustnode/target/release/rustnode`
- target: `test/parallel/test-diagnostics-channel-child-process.js`

Latest clean-branch measurements:

- baseline: **23/30 pass, 7/30 segfault**
- `--no-baseline-batch-compilation`: **30/30 pass**
- `--no-sparkplug`: **30/30 pass**
- `--jitless`: **30/30 pass**
- `--single-threaded`: **16/30 pass, 14/30 segfault**

## Crash evidence

A core dump from a baseline failure (`/tmp/core.rustnode.170624`) shows:

```
Program terminated with signal SIGSEGV
#0 v8::internal::baseline::BaselineCompilerTask::Install(v8::internal::Isolate*)
#1 v8::internal::baseline::ConcurrentBaselineCompiler::InstallBatch()
#2 v8::internal::StackGuard::HandleInterrupts(...)
#3 v8::internal::Runtime_StackGuard(...)
```

At the faulting instruction, the pointer used by `Install()` was non-canonical
(`rax = 0x1100000000000`), consistent with stale/corrupted task payload state.

## Node vs rustnode embedder differences found

Node (`src/api/embed_helpers.cc`) drives V8 with `MultiIsolatePlatform` and
calls `platform->DrainTasks(isolate)` at each event-loop spin.

rustnode currently:

- initializes V8 with `v8::new_default_platform(0, false)`
- does **not** implement Node's `MultiIsolatePlatform::DrainTasks` flow
- does not have Node's isolate registration/unregistration lifecycle on its
  platform abstraction

This is a substantive runtime-driving difference in the same area as the crash
(`InstallBatch` via stack-guard interrupts), but no patch in this session could
eliminate the crash at the required 30-run confidence.

## What was ruled out

- Path/setup artifacts: reproduction requires `--release` and node-source tree;
  reproduced repeatedly under the intended setup.
- "Just a V8 upstream race": contradicted by the original oracle measurement
  (Node nightly at same V8 pin passing 25/25) and by rustnode-only failures.
- One-off timing fluke: repeated 30-run samples continue to fail on rustnode.

## Patch attempts in this session

Two runtime-side attempts were tested and reverted because they did not satisfy
the 30-run bar:

1. Pumping V8 platform message loop from `rn-realm` scheduler drains.
2. Extra yield-and-drain quiesce rounds at loop-to-exit boundary in `rn-cli`.

They occasionally improved a sample but were not stable and did not remove
segfaults.
