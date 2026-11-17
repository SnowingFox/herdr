// `v8::Isolate::SetStackLimit`, which the pinned `v8` crate does not bind.
//
// Node calls this in `Worker::Run` (`src/node_worker.cc:204`) after creating a
// worker isolate, and `resourceLimits.stackSizeMb` does nothing without it:
// `CreateParams::set_stack_limit` alone leaves the isolate on V8's default limit,
// which was measured by removing this call — the worker then overflowed its real
// thread stack and the process aborted instead of throwing a RangeError.
//
// # Why this is a declaration rather than an include
//
// `SetStackLimit` IS public V8 API, declared in `v8-isolate.h`. The problem is
// getting that header at build time: the `v8` crate has no `links` key and
// publishes no include metadata, so there is no supported way for a sibling crate
// to find it. Shelling out to `cargo metadata` from a build script to locate it is
// worse than the disease — it asks the running build's own tool for state the
// build is already holding.
//
// # The invariant this file depends on
//
// Re-declaring a class V8 also defines is an ODR violation, and it is safe only
// while this declaration and V8's agree on the class layout and this method's
// place in the vtable. It is not self-checking, so it is pinned to a known header:
//
//   v8-isolate.h @ v8 152.2.0 (the pinned crate), the declaration on the line
//   whose comment begins `\note  If you are using threads then you should hold
//   the V8::Locker lock`.
//
// Re-check this declaration whenever the `v8` crate moves. If a future version of
// the crate ever binds `Isolate::SetStackLimit`, delete this file and call the
// binding instead — that is the only version of this shim with no invariant.
#include <cstdint>

namespace v8 {
class Isolate {
 public:
  void SetStackLimit(uintptr_t stack_limit);
};
}  // namespace v8

extern "C" void rn_v8_sys__set_stack_limit(v8::Isolate* isolate,
                                            uintptr_t stack_limit) {
  isolate->SetStackLimit(stack_limit);
}
