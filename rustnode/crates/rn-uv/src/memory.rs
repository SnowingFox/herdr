//! The machine's memory, as libuv reports it.
//!
//! Node sizes every isolate's heap from these two numbers
//! (`src/api/environment.cc::SetIsolateCreateParamsForNode`) and reports them
//! through `process.report`'s `resourceUsage`, so they are part of the
//! observable surface rather than an implementation detail.
//!
//! `uv_get_total_memory` is the machine's physical memory.
//! `uv_get_constrained_memory` is the cgroup limit the process is inside, and is
//! **0** when there is none — which is why the pair is exposed rather than a
//! single "usable memory", since 0 means "no limit" to both Node and libuv.
//!
//! Both are wrapped because the libuv signatures are `unsafe` and neither has a
//! failure mode worth propagating: libuv answers 0 when the platform cannot say,
//! and every caller treats 0 as "unknown".

use libuv_sys2 as uv;

/// `uv_get_total_memory()`: the machine's physical memory in bytes, or 0.
#[must_use]
pub fn total_memory() -> u64 {
    // SAFETY: `uv_get_total_memory` takes no arguments and only reads kernel
    // state.
    unsafe { uv::uv_get_total_memory() }
}

/// `uv_get_constrained_memory()`: the cgroup limit in bytes, or 0 when none.
#[must_use]
pub fn constrained_memory() -> u64 {
    // SAFETY: `uv_get_constrained_memory` takes no arguments and only reads
    // kernel state.
    unsafe { uv::uv_get_constrained_memory() }
}
