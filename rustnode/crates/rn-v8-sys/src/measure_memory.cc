// `v8::MeasureMemoryDelegate::Default` plus `v8::Isolate::MeasureMemory`, the
// pair `vm.measureMemory()` needs. The pinned `v8` crate binds neither.
//
// Node's call, `src/node_contextify.cc:2005`, is three steps against the current
// context: make a `Promise::Resolver`, build the delegate with
// `MeasureMemoryDelegate::Default(isolate, context, resolver, mode)`, then hand
// the delegate to `isolate->MeasureMemory(std::move(delegate), execution)`. The
// promise the delegate resolves is what `vm.measureMemory()` returns.
//
// # Why the whole call lives here
//
// `MeasureMemory` takes a `std::unique_ptr` **by value**. Constructing that
// unique_ptr on the Rust side would mean hand-rolling libc++'s layout, its
// deleter, and its move semantics across the boundary. The instructions cross
// as a pointer and two enums into this file instead and the unique_ptr never
// leaves C++: it is created by `Default`, moved into `MeasureMemory`, and
// destroyed by V8. Ownership transfers exactly once, in the one place that can
// see the real type.
//
// # Why this is a declaration rather than an include
//
// Both symbols are public V8 API, declared in `v8-statistics.h` and
// `v8-isolate.h`. The problem is getting those headers at build time: the `v8`
// crate has no `links` key and publishes no include metadata, so there is no
// supported way for a sibling crate to find them — the same wall
// `isolate_stack_limit.cc` documents, and the reason this file is shaped like
// it. Compiling against the crate's own copy under `~/.cargo` would mean
// locating the registry from a build script, and the headers there are written
// for the Chromium clang and its libc++ (they require clang 21+ and fail on
// this image's clang 18 and gcc 13), so they are not usable by `cc` here either.
//
// # The invariants this file depends on
//
// Every declaration below is a class V8 also defines, so each is an ODR
// violation that is safe only while the layout and the calling convention
// agree with V8's own. Nothing here is self-checking, so each is pinned to the
// header it mirrors and to the evidence that the compiled archive agrees.
//
//   V8 152.2.0 (the pinned crate):
//     v8-statistics.h: `class V8_EXPORT MeasureMemoryDelegate`, the two enums,
//       and `static std::unique_ptr<MeasureMemoryDelegate> Default(...)`.
//     v8-isolate.h:    `bool Isolate::MeasureMemory(std::unique_ptr<...>,
//       MeasureMemoryExecution)`.
//
// The archive confirms the ABI rather than assuming it. Disassembling
// `librusty_v8.a` at this pin:
//
//   Isolate::MeasureMemory  `mov %rsi,%r15` ... `mov (%r15),%rax` ...
//                           `mov %r15,%rdi` ... `call *0x10(%rax)`
//
// reads `rsi` as the delegate object itself — it takes the vtable from it and
// calls vtable slot 0x10, `ShouldMeasure` — not as a pointer to a unique_ptr
// holding it. So the unique_ptr crosses in ONE register, which means libc++
// was built with `_LIBCPP_ABI_ENABLE_UNIQUE_PTR_TRIVIAL_ABI`. The V8 tree's
// `buildtools/third_party/libc++/__config_site` sets it, through
// `_LIBCPP_ABI_VERSION 2`. `Default` correspondingly returns in `%rax` with no
// sret argument (`mov %r14,%rax; ret`). The `std::__Cr` namespace in the
// mangled names is that same config site's `_LIBCPP_ABI_NAMESPACE`.
//
// That single-register fact is what makes the `unique_ptr` below a correct
// stand-in: with trivial_abi it is one pointer passed in a register, which is
// exactly what a one-pointer class is. If a future pin turns trivial_abi off,
// V8's own convention changes while this declaration does not, so the call
// would pass a pointer where V8 reads a struct — re-check this file whenever
// the `v8` crate moves.
//
// `v8::Local` is one pointer for the same kind of reason. This pin builds with
// `v8_enable_direct_handle = false` (the `v8.gni` default), so a Local is an
// `IndirectHandleBase` holding one `Address*`. Nothing here inspects a Local;
// the shim only copies the pointer in and hands it to V8, so what matters is
// that the size and the by-value convention match, and `static_assert` below
// holds this side of that.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace std {
// `_LIBCPP_ABI_NAMESPACE` in the V8 tree's libc++ config site, which is what
// the archive's `NSt4__Cr10unique_ptr...` manglings spell.
inline namespace __Cr {

template <typename T>
struct default_delete {};

// Deliberately a single pointer with no destructor and no move: see the
// trivial_abi note above. Ownership is transferred into V8 on the call and the
// only owner that ever destroys the delegate is V8's own instantiation.
template <typename T, typename D = default_delete<T>>
class unique_ptr {
 public:
  explicit unique_ptr(T* pointer) : pointer_(pointer) {}

  T* pointer_;
};

}  // namespace __Cr
}  // namespace std

namespace v8 {

class Context;
class Isolate;

class Promise {
 public:
  class Resolver;
};

// One pointer wide, never inspected. See the `v8::Local` note above.
template <typename T>
class Local {
 public:
  T* slot_;
};

enum class MeasureMemoryMode { kSummary, kDetailed };
enum class MeasureMemoryExecution { kDefault, kEager, kLazy };

class MeasureMemoryDelegate {
 public:
  static std::__Cr::unique_ptr<MeasureMemoryDelegate> Default(
      Isolate* isolate, Local<Context> context,
      Local<Promise::Resolver> promise_resolver, MeasureMemoryMode mode);
};

class Isolate {
 public:
  bool MeasureMemory(std::__Cr::unique_ptr<MeasureMemoryDelegate> delegate,
                     MeasureMemoryExecution execution);
};

}  // namespace v8

// Copies a handle's single pointer into a `Local` without inspecting it.
template <typename T>
static v8::Local<T> local_from_ptr(const void* slot) {
  v8::Local<T> local;
  static_assert(sizeof(local) == sizeof(slot),
                "v8::Local must be one pointer for this copy to be the whole "
                "handle");
  std::memcpy(&local, &slot, sizeof(local));
  return local;
}

// Returns whether V8 accepted the request, which Node discards; the promise is
// the only observable result either way.
extern "C" bool rn_v8_sys__measure_memory(void* isolate, const void* context,
                                         const void* resolver, int32_t mode,
                                         int32_t execution) {
  v8::Isolate* raw_isolate = static_cast<v8::Isolate*>(isolate);

  std::__Cr::unique_ptr<v8::MeasureMemoryDelegate> delegate =
      v8::MeasureMemoryDelegate::Default(
          raw_isolate, local_from_ptr<v8::Context>(context),
          local_from_ptr<v8::Promise::Resolver>(resolver),
          static_cast<v8::MeasureMemoryMode>(mode));

  return raw_isolate->MeasureMemory(
      std::__Cr::unique_ptr<v8::MeasureMemoryDelegate>(delegate.pointer_),
      static_cast<v8::MeasureMemoryExecution>(execution));
}
