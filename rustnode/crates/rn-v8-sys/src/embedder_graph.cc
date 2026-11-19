// `v8::HeapProfiler::AddBuildEmbedderGraphCallback`, and the small
// `v8::EmbedderGraph` a callback needs, which the pinned `v8` crate does not
// bind.
//
// Node registers `Environment::BuildEmbedderGraph` at isolate creation
// (`src/node.cc:240`) and walks its `MemoryRetainer` tree from there, so a
// snapshot of a Node process contains native nodes such as `Node / MessagePort`
// with their internal edges. Without a callback V8 adds no embedder nodes at
// all, which is why `test/pummel/test-worker-take-heapsnapshot.js` finds none of
// the `Node / MessagePort` nodes it looks for.
//
// This shim exposes the two things such a callback needs and nothing else:
// register one, and add nodes and edges to the graph it is handed. What to walk
// stays in Rust.
//
// # The invariants this file depends on
//
// Re-declaring V8 classes is an ODR-sensitive stopgap, and this file re-declares
// more of the API than the other shims because an `EmbedderGraph::Node` subclass
// has to agree with V8's vtable slot for slot. It is safe only while these stay
// compatible with V8 152.2.0. Re-check on every `v8` crate bump:
//
// * `EmbedderGraph::Node`'s virtuals are `~Node`, `Name`, `SizeInBytes`,
//   `WrapperNode`, `IsRootNode`, `IsEmbedderNode`, `NamePrefix`,
//   `GetNativeObject`, `GetDetachedness`, `GetAddress` — in that order
//   (`v8-profiler.h:869`). `RustNode` overrides them in that order.
// * `EmbedderGraph`'s virtuals are `V8Node(Local<Value>)`,
//   `V8Node(Local<Data>)`, `AddNode`, `AddEdge`, `AddWeakEdge`,
//   `AddNativeSize`, `~EmbedderGraph`. Only `AddNode` and `AddEdge` are called
//   from here; the rest are declared so the order is pinned.
// * `std::__Cr::unique_ptr<T>` stays pointer-sized and trivially copyable, so
//   `AddNode` receives it in a register. `isolate_measure_memory.cc` pins the
//   same fact and records the disassembly that established it.
// * `BuildEmbedderGraphCallback` is `void (*)(Isolate*, EmbedderGraph*, void*)`
//   (`v8-profiler.h:1025`), and `AddBuildEmbedderGraphCallback` takes it plus a
//   `void*` (`:1274`).
//
// The registration pair must stay exact: `RemoveBuildEmbedderGraphCallback`
// matches on the function pointer *and* its data, so both are held in one
// per-thread slot rather than reconstructed.
//
// The mangled names this file emits are the ones the archive defines:
//
//   _ZN2v812HeapProfiler29AddBuildEmbedderGraphCallbackEPFvPNS_7IsolateEPNS_13EmbedderGraphEPvES5_
//   _ZN2v812HeapProfiler32RemoveBuildEmbedderGraphCallbackEPFvPNS_7IsolateEPNS_13EmbedderGraphEPvES5_
//
// # Why nodes are allocated here rather than in Rust
//
// `AddNode` takes ownership and V8's own `EmbedderGraphImpl` keeps the node
// alive for the duration of the snapshot. A Rust type cannot be that `Node`
// without re-implementing the vtable from Rust, which is the same ODR bet with
// no benefit. So `RustNode` holds the name and size Rust hands over, and V8 owns
// it from `AddNode` until the snapshot is deleted.
#include <cstddef>
#include <cstdint>
#include <string>

namespace std {
namespace __Cr {
// Storage layout and nothing else. The destructor is deliberately not declared:
// this file never runs it, and declaring it would emit a call to a symbol the
// archive does not define for this element type.
template <class T>
struct default_delete {};

template <class T, class D = default_delete<T>>
struct unique_ptr {
  T* value;
};

template <class T, class D>
unique_ptr<T, D>&& move(unique_ptr<T, D>& pointer) {
  return static_cast<unique_ptr<T, D>&&>(pointer);
}
}  // namespace __Cr
}  // namespace std

namespace v8 {

class Isolate;
class Data;
class Value;

template <class T>
class Local {
 public:
  Local() : value_(nullptr) {}
  explicit Local(T* value) : value_(value) {}

 private:
  T* value_;
};

class EmbedderGraph {
 public:
  class Node {
   public:
    enum class Detachedness : std::uint8_t {
      kUnknown = 0,
      kAttached = 1,
      kDetached = 2,
    };

    Node() = default;
    virtual ~Node() = default;
    virtual const char* Name() = 0;
    virtual size_t SizeInBytes() = 0;
    virtual Node* WrapperNode() { return nullptr; }
    virtual bool IsRootNode() { return false; }
    virtual bool IsEmbedderNode() { return true; }
    virtual const char* NamePrefix() { return nullptr; }
    virtual void* GetNativeObject() { return nullptr; }
    virtual Detachedness GetDetachedness() { return Detachedness::kUnknown; }
    virtual const void* GetAddress() { return nullptr; }

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
  };

  virtual Node* V8Node(const Local<Value>& value) = 0;
  virtual Node* V8Node(const Local<Data>& value);
  virtual Node* AddNode(std::__Cr::unique_ptr<Node> node) = 0;
  virtual void AddEdge(Node* from, Node* to, const char* name = nullptr) = 0;
  virtual void AddWeakEdge(Node* from, Node* to, const char* name = nullptr) {
    AddEdge(from, to, name);
  }
  virtual void AddNativeSize(size_t /*size*/) {}
  virtual ~EmbedderGraph() = default;
};

class HeapProfiler {
 public:
  using BuildEmbedderGraphCallback = void (*)(Isolate* isolate,
                                              EmbedderGraph* graph,
                                              void* data);

  void AddBuildEmbedderGraphCallback(BuildEmbedderGraphCallback callback,
                                    void* data);
  void RemoveBuildEmbedderGraphCallback(BuildEmbedderGraphCallback callback,
                                       void* data);
};

class Isolate {
 public:
  HeapProfiler* GetHeapProfiler();
};

}  // namespace v8

static_assert(sizeof(std::__Cr::unique_ptr<v8::EmbedderGraph::Node>) ==
                  sizeof(void*),
              "embedder-graph shim assumes pointer-sized unique_ptr");

namespace {

/// The `Node` subclass every Rust-requested node becomes.
///
/// Node's `MemoryRetainerNode::Name()` is the bare class name and its
/// `NamePrefix()` is `"Node /"` (`memory_tracker-inl.h:67`); V8 joins them, which
/// is what makes a snapshot call it `Node / MessagePort`. The same two pieces are
/// here, so a node added from Rust is named the way Node's is.
class RustNode : public v8::EmbedderGraph::Node {
 public:
  RustNode(const char* name, size_t size) : name_(name), size_(size) {}

  const char* Name() override { return name_.c_str(); }
  size_t SizeInBytes() override { return size_; }
  const char* NamePrefix() override { return "Node /"; }

 private:
  std::string name_;
  size_t size_;
};

/// What the Rust side registered: its callback and the state it carries.
struct Registration {
  void (*callback)(void* user, void* graph);
  void* user;
};

/// The registration for *this* thread.
///
/// Thread-local rather than global because the callback runs on the thread
/// taking the snapshot, and a worker's snapshot must run the worker's walk. Two
/// threads therefore never see each other's registration, which is the same
/// scope `Isolate` itself has.
thread_local Registration* g_registration = nullptr;

/// The `extern "C"` body V8 calls; `data` is unused because the registration is
/// found per-thread rather than passed back through V8.
void GraphCallback(v8::Isolate* /*isolate*/, v8::EmbedderGraph* graph,
                   void* /*data*/) {
  if (g_registration == nullptr) {
    return;
  }
  g_registration->callback(g_registration->user, graph);
}

}  // namespace

/// Adds one node to the graph and returns it as an opaque handle.
///
/// The pointer stays valid until the snapshot is destroyed, because V8's
/// `EmbedderGraphImpl` owns the node from the moment `AddNode` returns. Returns
/// null when `graph` or `name` is null, which Rust reports as a failed walk.
extern "C" void* rn_v8_sys__embedder_graph_add_node(void* graph,
                                                   const char* name,
                                                   size_t size) {
  if (graph == nullptr || name == nullptr) {
    return nullptr;
  }
  std::__Cr::unique_ptr<v8::EmbedderGraph::Node> node{
      new RustNode(name, size)};
  return static_cast<v8::EmbedderGraph*>(graph)->AddNode(std::__Cr::move(node));
}

/// Adds a named edge between two nodes the same graph returned.
extern "C" void rn_v8_sys__embedder_graph_add_edge(void* graph, void* from,
                                                  void* to, const char* name) {
  if (graph == nullptr || from == nullptr || to == nullptr || name == nullptr) {
    return;
  }
  static_cast<v8::EmbedderGraph*>(graph)->AddEdge(
      static_cast<v8::EmbedderGraph::Node*>(from),
      static_cast<v8::EmbedderGraph::Node*>(to), name);
}

/// Registers `callback` to add embedder nodes to every snapshot of `isolate`.
///
/// `callback` receives `user` and the opaque graph handle, runs on the thread
/// taking the snapshot, and must only call the two functions above. Returns
/// false when the isolate has no heap profiler, which the Rust caller reports as
/// a failed install rather than pretending the walk will happen.
extern "C" bool rn_v8_sys__add_build_embedder_graph_callback(
    v8::Isolate* isolate, void (*callback)(void* user, void* graph),
    void* user) {
  if (isolate == nullptr || callback == nullptr) {
    return false;
  }
  v8::HeapProfiler* profiler = isolate->GetHeapProfiler();
  if (profiler == nullptr) {
    return false;
  }
  // The slot is allocated once and updated in place, so the pair V8 holds is the
  // pair the removal below passes, whatever the callback and user are.
  if (g_registration == nullptr) {
    g_registration = new Registration{callback, user};
  } else {
    g_registration->callback = callback;
    g_registration->user = user;
  }
  profiler->AddBuildEmbedderGraphCallback(GraphCallback, nullptr);
  return true;
}

/// Unregisters the callback registered for this thread.
///
/// Called when a worker's isolate goes away. The registration itself is kept
/// because it is one small allocation for the life of the thread, and freeing it
/// would race a snapshot that is already in progress.
extern "C" void rn_v8_sys__remove_build_embedder_graph_callback(
    v8::Isolate* isolate) {
  if (isolate == nullptr || g_registration == nullptr) {
    return;
  }
  v8::HeapProfiler* profiler = isolate->GetHeapProfiler();
  if (profiler != nullptr) {
    profiler->RemoveBuildEmbedderGraphCallback(GraphCallback, nullptr);
  }
}
