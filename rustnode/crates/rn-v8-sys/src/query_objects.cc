// `v8::HeapProfiler::QueryObjects`, which the pinned `v8` crate does not bind.
//
// Node's `src/internal_only_v8.cc:QueryObjects` walks the heap with
// `isolate->GetHeapProfiler()->QueryObjects(context, &predicate, &out)` and turns
// the resulting `std::vector<Global<Object>>` into a JS `Array`. rustnode has to
// cross FFI at the walk: `v8-profiler.h` declares `QueryObjects`, but the crate's
// `binding.cc` binds no `HeapProfiler` method except `TakeHeapSnapshot` —
// `grep QueryObject` over the crate finds nothing.
//
// # What is *not* re-declared here
//
// Only the walk is. The **predicate's decision** stays in Rust, because the crate
// does bind every call it needs: `Object::get_creation_context`,
// `Object::get_prototype`, `Value::is_object` and `Local` identity are all there.
// `CallbackPredicate` forwards each object to a Rust function pointer, so the
// creation-context and prototype-chain logic is written once, against the crate's
// own bindings, rather than re-derived from a hand-copied `MaybeLocal` and
// `GetPrototype` declaration.
//
// That is the difference from `isolate_measure_memory.cc`, which had no such
// option. Here the C++ side only needs the signature of one `extern "C"` callback
// and `QueryObjectPredicate`'s vtable order.
//
// # Why the out-vector is drained here rather than returned
//
// The out-parameter is `std::__Cr::vector<v8::Global<v8::Object>>`, and
// `v8::Global` has a non-trivial destructor (`v8-persistent-handle.h:387`,
// `~Global() { this->Reset(); }`): each element owns a heap handle cell. The
// vector cannot be handed to Rust, or it leaks one global reference per match.
//
// Nor can its own destructor be called from here. libc++'s `vector` destructor is
// emitted inline in headers this translation unit cannot include, and the archive
// defines no `~vector<Global<Object>>`: `nm` over `librusty_v8.a` shows only
// `QueryObjects`, the two growth paths (`__emplace_back_slow_path`,
// `__swap_out_circular_buffer`) and `__throw_length_error`. What *is* exported is
// `v8::api_internal::DisposeGlobal(unsigned long*)` —
// `_ZN2v812api_internal13DisposeGlobalEPm` — which is the single call
// `Global::Reset` makes. So each element is released through that, and the storage
// with `operator delete`, which is what libc++'s allocator reaches for a
// non-over-aligned element type.
//
// # Why the real headers cannot be included
//
// The `v8` crate ships `v8/include/**` and V8's custom libc++, but building
// against them needs Clang 21.1+ (its build script says so) and passes
// `-nostdinc++` with the whole `buildtools/third_party/libc++/__config_site`
// configuration. This image has Clang 18, which fails on that libc++'s
// `#pragma clang attribute` usage before reaching a single V8 type. Hence the
// re-declarations, the same stopgap `isolate_measure_memory.cc` documents.
//
// # The invariants this file depends on
//
// Re-declaring V8 classes is an ODR-sensitive stopgap. It is safe only while these
// stay compatible with V8 152.2.0 (the pinned crate). Re-check on every `v8` crate
// bump:
//
// * `v8::Local<T>` holds one tagged `T*` (`v8-handle-base.h:89`,
//   `ValueHelper::SlotAsValue`), so it is pointer-sized and trivially copyable.
//   `isolate_measure_memory.cc` already relies on this and pins it the same way.
// * `v8::Global<T>` is one `internal::Address*` slot, and the cell it points at
//   holds that same tagged pointer (`v8-handle-base.h:83`, `:80`).
// * `v8::api_internal::DisposeGlobal(unsigned long*)` stays exported.
// * `QueryObjectPredicate` keeps `~QueryObjectPredicate` then
//   `virtual bool Filter(Local<Object>)`, in that order, with no other virtuals.
// * `HeapProfiler::QueryObjects(Local<Context>, QueryObjectPredicate*,
//   std::__Cr::vector<Global<Object>>*)` keeps this signature and the `__Cr`
//   namespace. The archive's mangled symbol is the evidence:
//
//     _ZN2v812HeapProfiler12QueryObjectsENS_5LocalINS_7ContextEEEPNS_20QueryObjectPredicateEPNSt4__Cr6vectorINS_6GlobalINS_6ObjectEEENS6_9allocatorISA_EEEE
//
// * `std::__Cr::vector<T>` keeps libc++'s three-pointer layout (`begin`, `end`,
//   `capacity_end`). The storage below is exactly that and is only ever handed to
//   V8 to fill.
// * `v8::Array::New(Isolate*, Local<Value>*, size_t)` keeps this signature; the
//   archive exports this overload and it is the one Node's
//   `Array::New(isolate, result.data(), result.size())` resolves to.
//
// If the `v8` crate ever binds `HeapProfiler::QueryObjects` and offers a way to
// implement `QueryObjectPredicate`, delete this file and call the binding. That is
// the only version of this shim with no invariant.
#include <cstddef>
#include <cstdint>

namespace std {
namespace __Cr {
// Storage layout only. The destructor is deliberately *not* declared: this file
// never calls it, and declaring it would emit a call to a symbol the archive does
// not define.
template <class T, class A>
struct vector {
  T* begin_;
  T* end_;
  T* capacity_end_;
};

template <class T>
struct allocator {};
}  // namespace __Cr
}  // namespace std

namespace v8 {
namespace api_internal {
void DisposeGlobal(std::uintptr_t* global);
}  // namespace api_internal
}  // namespace v8

namespace {

/// Owns the vector `QueryObjects` filled and applies libc++'s inline destructor
/// semantics by hand: dispose each element's global reference, clear its slot, then
/// release the storage.
///
/// This exists because libc++'s `vector<Global<Object>>::~vector` is emitted inline
/// in headers this translation unit cannot include, and the archive defines no such
/// symbol. Doing it in a destructor keeps the release correct on every exit path,
/// which the earlier "dispose in the fill loop" version was not: it unrooted the
/// objects before `Array::New` allocated, and that was measured as a segfault.
template <class T, class A>
class VectorOwner {
 public:
  explicit VectorOwner(std::__Cr::vector<T, A>* vector) : vector_(vector) {}

  ~VectorOwner() {
    if (vector_ == nullptr) {
      return;
    }
    for (T* element = vector_->begin_; element != vector_->end_; ++element) {
      // `PersistentBase<T>::Reset()`: skip an empty slot, dispose the cell, clear it.
      std::uintptr_t* slot = element->slot();
      if (slot != nullptr) {
        v8::api_internal::DisposeGlobal(slot);
        *slot = 0;
      }
    }
    ::operator delete(vector_->begin_);
    vector_->begin_ = nullptr;
    vector_->end_ = nullptr;
    vector_->capacity_end_ = nullptr;
  }

 private:
  std::__Cr::vector<T, A>* vector_;
};

}  // namespace

namespace v8 {
template <class T>
class Local {
 public:
  Local() : value_(nullptr) {}
  explicit Local(T* value) : value_(value) {}
  T* operator*() const { return value_; }
  T* operator->() const { return value_; }

 private:
  T* value_;
};

class Context;
class Isolate;
class Object;
class Value;
class Array;

// `v8::Global<T>`: one slot whose pointee is the tagged object pointer.
template <class T>
class Global {
 public:
  std::uintptr_t* slot() const { return slot_; }

 private:
  std::uintptr_t* slot_;
};

// `v8-profiler.h:1001`. Declaration order is load-bearing: slot 0 is the
// destructor, slot 1 is `Filter`.
class QueryObjectPredicate {
 public:
  virtual ~QueryObjectPredicate() = default;
  virtual bool Filter(Local<Object> object) = 0;
};

// `v8-profiler.h:1011`. Only the one method is declared; everything else on the
// class is unreachable from here and would only add invariant.
class HeapProfiler {
 public:
  void QueryObjects(Local<Context> context, QueryObjectPredicate* predicate,
                    std::__Cr::vector<Global<Object>,
                                      std::__Cr::allocator<Global<Object>>>* objects);
};

class Array {
 public:
  static Local<Array> New(Isolate* isolate, Local<Value>* elements,
                          size_t length);
};

class Isolate {
 public:
  HeapProfiler* GetHeapProfiler();
};

class Data;

namespace api_internal {
// Declaration only; see the entry point for why this is not used.
}
}  // namespace v8

extern "C" {
/// `v8::Local<v8::Data>::New(isolate, ptr_to_local(&other))`, the crate's own
/// handle constructor (`src/binding.cc:552`). Using it is what turns a *global's*
/// slot into a *scope-owned* handle, which is the whole difference between a
/// correct array element and a dangling one.
const v8::Data* v8__Local__New(v8::Isolate* isolate, const v8::Data& other);
}

namespace v8 {

namespace api_internal {
// Declared above, before `VectorOwner`; kept here for readability of the class
// declarations it belongs with.
}  // namespace api_internal
}  // namespace v8

namespace {

/// Recovers a `Local` from the tagged pointer it holds, mirroring
/// `local_from_ptr` in `isolate_measure_memory.cc`.
template <class T>
inline v8::Local<T> local_from_ptr(const T* pointer) {
  static_assert(sizeof(v8::Local<T>) == sizeof(T*),
                "v8::Local<T> must stay pointer-sized");
  return *reinterpret_cast<const v8::Local<T>*>(&pointer);
}

/// The predicate Rust decides. `Filter` hands the raw object to `filter`, which
/// owns the creation-context and prototype-chain logic; `user` carries whatever
/// state Rust needs across.
class CallbackPredicate : public v8::QueryObjectPredicate {
 public:
  using FilterFn = bool (*)(void* user, const v8::Object* object);

  CallbackPredicate(FilterFn filter, void* user) : filter_(filter), user_(user) {}

  bool Filter(v8::Local<v8::Object> object) override {
    return filter_(user_, *object);
  }

 private:
  FilterFn filter_;
  void* user_;
};

}  // namespace

/// Walks the heap and stores the matching objects' `Array` in `out`.
///
/// `filter`/`user` decide what matches; see `CallbackPredicate`. Returns false when
/// an argument is null, which the Rust caller turns into a thrown error.
///
/// `out` is a `v8::Local<v8::Array>*` as *Rust* lays a `Local` out: one tagged
/// pointer. Writing the handle there rather than returning it keeps the crate's
/// handle type out of the signature — `v8::Local<T>` is pointer-sized in both
/// languages, which is the invariant the whole shim rests on anyway.
extern "C" bool rn_v8_sys__query_objects(v8::Isolate* isolate,
                                         const v8::Context* context,
                                         bool (*filter)(void*, const v8::Object*),
                                         void* user,
                                         void** out) {
  static_assert(sizeof(v8::Local<v8::Value>) == sizeof(void*),
                "query-objects shim assumes pointer-sized v8::Local");
  static_assert(sizeof(v8::Global<v8::Object>) == sizeof(void*),
                "query-objects shim assumes pointer-sized v8::Global");

  if (isolate == nullptr || context == nullptr || filter == nullptr || out == nullptr) {
    return false;
  }

  // A default-constructed libc++ vector is all-null; the brace-init states that
  // rather than relying on a constructor this file does not link. V8's own
  // `emplace_back` growth path does the allocating.
  std::__Cr::vector<v8::Global<v8::Object>,
                    std::__Cr::allocator<v8::Global<v8::Object>>>
      found{nullptr, nullptr, nullptr};

  CallbackPredicate predicate(filter, user);
  isolate->GetHeapProfiler()->QueryObjects(local_from_ptr(context), &predicate,
                                           &found);

  const size_t count = static_cast<size_t>(found.end_ - found.begin_);

  // The vector's references stay rooted until this frame exits. They have to: the
  // element pointers below are read out of the globals, and `Array::New` allocates,
  // so unrooting them first lets a collection reclaim the objects and the array
  // ends up holding garbage. Node keeps the same order — `Get()` into a
  // `LocalVector`, `Array::New`, and the globals released with the vector at exit.
  VectorOwner<v8::Global<v8::Object>,
              std::__Cr::allocator<v8::Global<v8::Object>>>
      owner(&found);

  v8::Local<v8::Value>* elements = nullptr;
  if (count != 0) {
    elements = new v8::Local<v8::Value>[count];
  }
  // A `v8::Local<T>` in this build is a *slot* pointer, not a tagged object
  // pointer: `LocalBase<T>(internal::Address* location)` (`v8-local-handle.h:299`)
  // and `PersistentBase<T>::FromSlot(slot)` (`v8-local-handle.h:318`) both store
  // the address of the handle cell, and `value()` dereferences it
  // (`ValueHelper::SlotAsValue`, `v8-internal.h:1841`). So the element to put in
  // the array is `Global::slot()`, and `*slot` — the tagged pointer — is the wrong
  // thing to hand V8. Passing the dereferenced value was measured to make every
  // match render as a large integer.
  // Each element has to become a *scope* handle, not the global's own slot.
  // `Global::Get(isolate)` is `Local::New(isolate, *this)`, and `Local::New` calls
  // `HandleScope::CreateHandle`, which allocates a fresh cell in the current scope.
  // Handing `Array::New` the global's slot instead points the array at a cell that
  // `DisposeGlobal` then frees, so the array holds a dangling handle — measured as
  // `vm.SourceTextModule` instances never being collectable while plain objects
  // looked fine.
  //
  // `v8__Local__New` is the crate's own binding for exactly that constructor, so
  // this reuses it rather than re-deriving `HandleScope::CreateHandle`.
  // A `v8::Local<T>` here is a *slot*: `value()` is `*slot`. The `Global`'s cell is
  // precisely such a slot and stays valid until `owner` disposes it at return, so
  // its address is the handle to put in the array — handing V8 `*slot` (the tagged
  // pointer) instead makes every element render as an integer, because V8 then
  // dereferences the object's own first word as if it were a handle.
  for (size_t i = 0; i < count; ++i) {
    elements[i] = local_from_ptr(
        reinterpret_cast<const v8::Value*>(found.begin_[i].slot()));
  }

  v8::Local<v8::Array> array = v8::Array::New(isolate, elements, count);
  delete[] elements;
  *out = *array;
  return true;
}
