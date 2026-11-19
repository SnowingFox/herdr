// `v8::HeapProfiler::TakeHeapSnapshot(options)`, which the pinned `v8` crate
// does not bind with an options argument.
//
// The crate's `v8__HeapProfiler__TakeHeapSnapshot`
// (`v8-152.2.0/src/binding.cc:4068`) calls `TakeHeapSnapshot()` with no
// argument, so V8 always applies a default-constructed `HeapSnapshotOptions`:
// `snapshot_mode = kRegular`, `numerics_mode = kHideNumericValues`. Node's
// `src/heap_utils.cc` does not use that path. `GetHeapSnapshotOptions` turns the
// `Uint8Array([+exposeInternals, +exposeNumericValues])` from
// `lib/internal/heap_utils.js` into a `HeapSnapshotOptions` and calls
// `TakeHeapSnapshot(options)`; `TakeSnapshot` then serializes the result. That
// overload is declared in `v8-profiler.h` and exported by the archive — the
// missing piece is only the binding.
//
// # Why this re-declares instead of including `v8-profiler.h`
//
// The other two shims here (`isolate_measure_memory.cc`,
// `query_objects.cc`) re-declare for the same reason this one does. The crate
// ships `v8/include/**` but no include-path metadata, and it compiles its own
// binding against V8's bundled libc++ with `-nostdinc++`, which this image's
// Clang is too old to consume. Reaching into the crate's registry checkout for
// an include path would also make the build depend on the cargo home layout.
// So the types this call needs are re-declared, and `build.rs` asserts nothing
// about them — the `static_assert`s below are what pin the layout, and they are
// checked on every build rather than against a header that may not exist.
//
// # The invariants this file depends on
//
// Re-declaring V8 classes is an ODR-sensitive stopgap. It is safe only while
// these stay compatible with V8 152.2.0 (the pinned crate). Re-check on every
// `v8` crate bump by compiling `v8-profiler.h`'s `HeapSnapshotOptions` and
// comparing:
//
//   sizeof(HeapSnapshotOptions)                     == 32
//   offsetof(control)                               == 0
//   offsetof(context_name_resolver)                 == 8
//   offsetof(snapshot_mode)                         == 16
//   offsetof(numerics_mode)                         == 20
//   offsetof(stack_state)                           == 24
//   HeapSnapshotMode::kRegular                      == 0
//   HeapSnapshotMode::kExposeInternals              == 1
//   NumericsMode::kHideNumericValues                == 0
//   NumericsMode::kExposeNumericValues              == 1
//
// The vtable facts, which the `static_assert`s cannot check and the archive's
// exported symbols are the evidence for:
//
// * `v8::OutputStream` declares `~OutputStream`, `EndOfStream`,
//   `GetChunkSize`, `WriteAsciiChunk`, `WriteHeapStatsChunk` in that order
//   (`v8-profiler.h:201`). `Sink` overrides the first four and inherits the
//   fifth, so its vtable has exactly that shape.
// * `HeapSnapshot::Serialize(OutputStream*, SerializationFormat)` keeps this
//   signature and `SerializationFormat::kJSON` stays 0.
// * `HeapSnapshot::Delete()` is const-qualified on the caller's side only in the
//   sense that `TakeHeapSnapshot` returns a pointer to const; the method itself
//   is non-const, which is why the call below casts.
//
// The mangled names this translation unit emits are the ones the archive
// defines:
//
//   _ZN2v812HeapProfiler16TakeHeapSnapshotERKNS0_19HeapSnapshotOptionsE
//   _ZN2v813HeapSnapshot9SerializeEPNS_11OutputStreamENS0_19SerializationFormatE
//   _ZN2v813HeapSnapshot6DeleteEv
//   _ZN2v87Isolate15GetHeapProfilerEv
//
// If the `v8` crate ever binds `TakeHeapSnapshot(options)`, delete this file and
// call the binding. That is the only version of this shim with no invariant.
#include <cstddef>
#include <cstdint>

namespace v8 {

class Isolate;
template <class T>
class Local;

// `v8-profiler.h:1130`, `:1146`. The default constructor leaves `control` and
// `context_name_resolver` null, which is what Node passes; the zero-initialized
// struct below states that rather than relying on a constructor this file does
// not link.
enum class EmbedderStackState : std::uint8_t {
  kMayContainHeapPointers = 0,
  kNoHeapPointers = 1,
};

class HeapProfiler {
 public:
  enum class HeapSnapshotMode {
    kRegular = 0,
    kExposeInternals = 1,
  };

  enum class NumericsMode {
    kHideNumericValues = 0,
    kExposeNumericValues = 1,
  };

  struct HeapSnapshotOptions final {
    void* control;
    void* context_name_resolver;
    HeapSnapshotMode snapshot_mode;
    NumericsMode numerics_mode;
    EmbedderStackState stack_state;
  };

  // `v8-profiler.h:1177`. Only the options overload is declared: the other one
  // is unreachable from here and would only add invariant.
  const class HeapSnapshot* TakeHeapSnapshot(
      const HeapSnapshotOptions& options);
};

// `v8-profiler.h:201`. Declaration order is load-bearing — the vtable slots are
// this order, so `Sink` below must override them in it.
class OutputStream {
 public:
  enum WriteResult { kContinue = 0, kAbort = 1 };
  virtual ~OutputStream() = default;
  virtual void EndOfStream() = 0;
  // `v8-profiler.h:208` defines this one inline, so it is defined inline here
  // too and never emitted as an external symbol: only `HeapSnapshot`'s
  // serializer calls it, and that call resolves inside the archive.
  virtual int GetChunkSize() { return 1024; }
  virtual WriteResult WriteAsciiChunk(char* data, int size) = 0;
  // `v8-profiler.h:220`, likewise inline. `Sink` inherits this slot unchanged.
  virtual WriteResult WriteHeapStatsChunk(void* /*data*/, int /*count*/) {
    return kAbort;
  }
};

// `v8-profiler.h:657`. Only the two members used here are declared.
class HeapSnapshot {
 public:
  enum SerializationFormat {
    kJSON = 0,
  };

  void Serialize(OutputStream* stream,
                 SerializationFormat format = kJSON) const;
  void Delete();
};

class Isolate {
 public:
  HeapProfiler* GetHeapProfiler();
};

}  // namespace v8

static_assert(sizeof(v8::HeapProfiler::HeapSnapshotOptions) == 32,
              "HeapSnapshotOptions grew a field; re-check its layout against "
              "v8-profiler.h and update the offsets in this file");
static_assert(offsetof(v8::HeapProfiler::HeapSnapshotOptions, control) == 0,
              "HeapSnapshotOptions.control moved");
static_assert(
    offsetof(v8::HeapProfiler::HeapSnapshotOptions, context_name_resolver) == 8,
    "HeapSnapshotOptions.context_name_resolver moved");
static_assert(
    offsetof(v8::HeapProfiler::HeapSnapshotOptions, snapshot_mode) == 16,
    "HeapSnapshotOptions.snapshot_mode moved");
static_assert(
    offsetof(v8::HeapProfiler::HeapSnapshotOptions, numerics_mode) == 20,
    "HeapSnapshotOptions.numerics_mode moved");
static_assert(
    offsetof(v8::HeapProfiler::HeapSnapshotOptions, stack_state) == 24,
    "HeapSnapshotOptions.stack_state moved");
static_assert(
    static_cast<int>(v8::HeapProfiler::HeapSnapshotMode::kRegular) == 0 &&
        static_cast<int>(v8::HeapProfiler::HeapSnapshotMode::kExposeInternals) ==
            1,
    "HeapSnapshotMode values changed");
static_assert(
    static_cast<int>(v8::HeapProfiler::NumericsMode::kHideNumericValues) == 0 &&
        static_cast<int>(
            v8::HeapProfiler::NumericsMode::kExposeNumericValues) == 1,
    "NumericsMode values changed");
static_assert(static_cast<int>(v8::HeapSnapshot::kJSON) == 0,
              "SerializationFormat::kJSON is no longer 0");

namespace {

// Collects the serialized document in caller-provided storage.
//
// `GetChunkSize` is 65536 like Node's `FileOutputStream` and
// `HeapSnapshotStream`. It only decides how much V8 hands over at a time; the
// callback appends, so a caller that reallocates is unaffected.
class Sink : public v8::OutputStream {
 public:
  using Write = bool (*)(void* user, const char* data, std::size_t size);

  Sink(Write write, void* user) : write_(write), user_(user) {}

  int GetChunkSize() override { return 65536; }

  void EndOfStream() override {}

  WriteResult WriteAsciiChunk(char* data, int size) override {
    if (size < 0) {
      return kAbort;
    }
    return write_(user_, data, static_cast<std::size_t>(size)) ? kContinue
                                                              : kAbort;
  }

 private:
  Write write_;
  void* user_;
};

}  // namespace

/// Serializes a heap snapshot taken with `options` into `write`.
///
/// `expose_internals` and `expose_numeric_values` are the two bytes Node reads
/// out of the options array, in that order (`heap_utils.cc:427`). Returns false
/// when no snapshot was produced, which V8 reports on allocation failure and
/// which Node treats as a failed `CHECK`.
///
/// The snapshot is deleted before returning; the crate's own binding does the
/// same with a `const_cast`, and without it every snapshot stays in the
/// profiler's list for the life of the isolate.
extern "C" bool rn_v8_sys__take_heap_snapshot(
    v8::Isolate* isolate, bool expose_internals, bool expose_numeric_values,
    bool (*write)(void* user, const char* data, std::size_t size), void* user) {
  if (isolate == nullptr || write == nullptr) {
    return false;
  }

  v8::HeapProfiler* profiler = isolate->GetHeapProfiler();
  if (profiler == nullptr) {
    return false;
  }

  // Value-initialized, so `control` and `context_name_resolver` are null and
  // `stack_state` is `kMayContainHeapPointers` — the same three values
  // `HeapSnapshotOptions`' default constructor sets, and the three Node leaves
  // alone.
  v8::HeapProfiler::HeapSnapshotOptions options{};
  options.snapshot_mode =
      expose_internals
          ? v8::HeapProfiler::HeapSnapshotMode::kExposeInternals
          : v8::HeapProfiler::HeapSnapshotMode::kRegular;
  options.numerics_mode =
      expose_numeric_values
          ? v8::HeapProfiler::NumericsMode::kExposeNumericValues
          : v8::HeapProfiler::NumericsMode::kHideNumericValues;

  const v8::HeapSnapshot* snapshot = profiler->TakeHeapSnapshot(options);
  if (snapshot == nullptr) {
    return false;
  }

  Sink sink(write, user);
  snapshot->Serialize(&sink);
  const_cast<v8::HeapSnapshot*>(snapshot)->Delete();
  return true;
}
