// `v8::Isolate::MeasureMemory` plus `v8::MeasureMemoryDelegate::Default`, which
// the pinned `v8` crate does not bind.
//
// Node wires `contextify.measureMemory` by creating a `Promise::Resolver`,
// building the delegate with `MeasureMemoryDelegate::Default`, then transferring
// that delegate into `Isolate::MeasureMemory` (`src/node_contextify.cc`).
// rustnode mirrors that flow, but has to cross Rust FFI at the final call.
//
// # Why this is a declaration rather than an include
//
// The pinned `v8` crate still does not expose include-path metadata, so sibling
// crates cannot include `v8.h` through a supported build interface.
//
// # The invariants this file depends on
//
// Re-declaring V8 classes is an ODR-sensitive stopgap. This shim is safe only
// while these declarations stay layout- and signature-compatible with V8 152.2.0
// (the pinned crate). Re-check on every `v8` crate bump:
//
// * `v8::Local<T>` remains pointer-sized.
// * `MeasureMemoryDelegate::Default` keeps this signature.
// * `Isolate::MeasureMemory` keeps this signature.
// * `std::__Cr::unique_ptr` stays pointer-sized and trivial, so it is passed and
//   returned in a single register rather than through a hidden return slot.
//
// That last point is not stylistic. This file first declared `unique_ptr` with a
// user-provided destructor, which made it non-trivial; the compiler then returned
// `Default` through a hidden sret pointer while V8's own copy returns in `%rax`.
// The call linked and then faulted on entry, and the disassembly of the archive's
// `api.o` is what settled it:
//
//   * `v8::MeasureMemoryDelegate::Default` tail-calls
//     `Heap::CreateDefaultMeasureMemoryDelegate` with `%rax` as the result.
//   * `v8::Isolate::MeasureMemory` forwards the delegate in `%rsi` and the
//     execution mode in `%edx`, with `%rdi` as the isolate.
//   * `Heap::MeasureMemory` reads the delegate straight from `%rsi` and takes the
//     pointer out of it, so the deleter is never called on this side.
//
// The `static_assert` below pins the size half of that; the disassembly is the
// evidence for the register half. Ownership still transfers exactly once: V8
// takes the pointer by value and disposes of it after the measurement completes.
//
// If the `v8` crate gains direct bindings for these APIs, delete this file and
// call those bindings instead.
#include <cassert>

namespace std {
namespace __Cr {
template <class T>
struct default_delete {};

template <class T, class D = default_delete<T>>
struct unique_ptr {
  // Trivial on purpose. See the file header: a non-trivial `unique_ptr` makes the
  // compiler return `Default` through a hidden sret pointer, which does not match
  // how V8's own build returns it, and the mismatch faults at the call.
  T* value;
};

template <class T, class D>
unique_ptr<T, D>&& move(unique_ptr<T, D>& pointer) {
  return static_cast<unique_ptr<T, D>&&>(pointer);
}
}  // namespace __Cr
}  // namespace std

namespace v8 {
template <class T>
class Local {
 public:
  Local() : value_(nullptr) {}
  explicit Local(T* value) : value_(value) {}
  T* operator*() const { return value_; }

 private:
  T* value_;
};

class Context;
class Promise {
 public:
  class Resolver;
};
class Isolate;

enum class MeasureMemoryMode : int;
enum class MeasureMemoryExecution : int;

class MeasureMemoryDelegate {
 public:
  static std::__Cr::unique_ptr<MeasureMemoryDelegate> Default(
      Isolate* isolate, Local<Context> context,
      Local<Promise::Resolver> promise_resolver, MeasureMemoryMode mode);
};

class Isolate {
 public:
  void MeasureMemory(std::__Cr::unique_ptr<MeasureMemoryDelegate> delegate,
                     MeasureMemoryExecution execution);
};
}  // namespace v8

template <class T>
inline v8::Local<T> local_from_ptr(const T* pointer) {
  static_assert(sizeof(v8::Local<T>) == sizeof(T*),
                "v8::Local<T> must stay pointer-sized");
  auto local = *reinterpret_cast<const v8::Local<T>*>(&pointer);
  assert(*local == pointer);
  return local;
}

template <class T, class D>
inline T* unique_ptr_get(const std::__Cr::unique_ptr<T, D>& pointer) {
  return pointer.value;
}

extern "C" bool rn_v8_sys__measure_memory(v8::Isolate* isolate,
                                          const v8::Context* context,
                                          const v8::Promise::Resolver* resolver,
                                          int mode,
                                          int execution) {
  if (isolate == nullptr || context == nullptr || resolver == nullptr) {
    return false;
  }
  if (mode < 0 || mode > 1 || execution < 0 || execution > 1) {
    return false;
  }

  auto delegate = v8::MeasureMemoryDelegate::Default(
      isolate, local_from_ptr(context), local_from_ptr(resolver),
      static_cast<v8::MeasureMemoryMode>(mode));
  static_assert(sizeof(std::__Cr::unique_ptr<v8::MeasureMemoryDelegate>) ==
                    sizeof(void*),
                "measure-memory shim assumes pointer-sized unique_ptr");
  if (unique_ptr_get(delegate) == nullptr) {
    return false;
  }

  isolate->MeasureMemory(std::__Cr::move(delegate),
                         static_cast<v8::MeasureMemoryExecution>(execution));
  return true;
}
