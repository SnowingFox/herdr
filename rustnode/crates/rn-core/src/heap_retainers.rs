//! The native retainers a heap snapshot reports, and the walk that adds them.
//!
//! Node's `Environment::BuildEmbedderGraph` (`src/env.cc:2281`) hands a
//! `MemoryTracker` to `Environment::Track`, and every `MemoryRetainer` reachable
//! from it describes itself through `MemoryInfo`. That walk is what puts
//! `Node / ZlibStream --native_to_javascript--> Zlib` into a snapshot. rustnode
//! has no `Environment` and no `BaseObject` tree, so each binding crate records
//! its own live native objects here and describes them with the same names,
//! sizes and edge names the oracle reports.
//!
//! # Why a registry rather than one central walk
//!
//! The object a retainer describes belongs to the crate that owns it — a
//! `ZlibStream` lives in `rn-bind-zlib`, a worker in `rn-bind-worker`. A single
//! walk in one crate would have to depend on all of them, and `rn-bind-worker`
//! already sits on the far side of a dependency cycle from `rn-bindings`. So the
//! walk lives where the isolate does and each owner registers a closure that
//! describes its own objects.
//!
//! # Thread locality
//!
//! Both the registry and the walk are thread-local, for the reason
//! [`rn_v8_sys::register_embedder_graph`] is: a worker's snapshot must report the
//! worker's retainers, not the main thread's. A registration is made and dropped
//! on the isolate's own thread, so a `v8::Weak` in one never crosses threads.

use std::cell::RefCell;
use std::rc::Rc;

use rn_v8_sys::v8;
use rn_v8_sys::{EmbedderGraph, EmbedderNode};

/// One native node and the children `MemoryInfo` would have tracked under it.
///
/// The shape mirrors `MemoryRetainer`: a name (which the graph prefixes with
/// `Node /`), a `SelfSize()`, and a set of named child retainers. The wrapper is
/// the JavaScript object the retainer belongs to, which produces the
/// `native_to_javascript` / `javascript_to_native` edge pair.
pub struct HeapNode<'s> {
    /// `MemoryInfoName()`. The graph renders it as `Node / <name>`.
    pub name: &'static str,
    /// `SelfSize()`, in bytes, as the oracle reports it.
    pub size: usize,
    /// `WrappedObject()`, when the retainer has one.
    ///
    /// A scoped handle rather than a `Global`, because a strong reference would
    /// keep the wrapper alive and stop its finalizer ever running. The retainer
    /// holds a `v8::Weak` and resolves it here, inside the walk's scope.
    pub wrapper: Option<v8::Local<'s, v8::Value>>,
    /// The edges `MemoryInfo` adds.
    pub children: Vec<HeapChild<'s>>,
}

/// One edge of a [`HeapNode`]: `TrackField(edge, child)`.
pub struct HeapChild<'s> {
    pub edge: &'static str,
    pub node: HeapNode<'s>,
}

impl<'s> HeapNode<'s> {
    /// A node with a size, no wrapper and no children.
    #[must_use]
    pub fn new(name: &'static str, size: usize) -> Self {
        Self {
            name,
            size,
            wrapper: None,
            children: Vec::new(),
        }
    }

    /// The same node with `wrapper` as its JavaScript object.
    #[must_use]
    pub fn with_wrapper(mut self, wrapper: v8::Local<'s, v8::Value>) -> Self {
        self.wrapper = Some(wrapper);
        self
    }

    /// The same node with one more tracked child.
    #[must_use]
    pub fn with_child(mut self, edge: &'static str, node: HeapNode<'s>) -> Self {
        self.children.push(HeapChild { edge, node });
        self
    }
}

/// A registration, released with [`unregister`] when the object goes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetainerId(u64);

impl RetainerId {
    /// An id that registers nothing.
    ///
    /// Used for the field a value must have before it can be registered, so a
    /// state is never observed holding an id that names another state's
    /// registration. [`unregister`] ignores it.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }
}

/// What a retainer's description closure is called with.
///
/// The isolate is the snapshot's own, offered so a retainer can turn its
/// `v8::Weak` or `v8::Global` back into a handle. A retainer opens the
/// `HandleScope` it needs itself, because only it knows whether one is required
/// and how long the handles must live.
pub type Describe = dyn Fn(&EmbedderGraph, &mut v8::Isolate);

thread_local! {
    /// The live retainers on this thread, in registration order.
    ///
    /// A `Vec` rather than a map: the walk is already O(retainers), and the
    /// number of live native objects at any moment is small enough that the
    /// linear scan for a removal costs less than hashing a key.
    static RETAINERS: RefCell<Vec<(RetainerId, Rc<Describe>)>> = const { RefCell::new(Vec::new()) };

    static NEXT_ID: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Records `describe` as a live retainer this thread's snapshots report.
///
/// `describe` runs once per snapshot, inside a scope the walk opens for it, so it
/// may read Rust state and write to the graph but must not call into JavaScript.
/// It must describe exactly the objects that are alive at that moment: a
/// retainer kept after its object is gone makes the snapshot claim memory that
/// nothing holds.
#[must_use]
pub fn register(describe: impl Fn(&EmbedderGraph, &mut v8::Isolate) + 'static) -> RetainerId {
    let id = NEXT_ID.with(|next| {
        let id = next.get() + 1;
        next.set(id);
        RetainerId(id)
    });
    RETAINERS.with(|retainers| {
        retainers
            .borrow_mut()
            .push((id, Rc::new(describe) as Rc<Describe>));
    });
    id
}

/// Drops a registration.
///
/// Safe to call for an id that is already gone, which happens when a finalizer
/// and an explicit close both run.
pub fn unregister(id: RetainerId) {
    if id == RetainerId::none() {
        return;
    }
    RETAINERS.with(|retainers| {
        retainers.borrow_mut().retain(|(other, _)| *other != id);
    });
}

/// Runs every retainer this thread registered.
///
/// This is the body of the embedder-graph build callback: the CLI and each worker
/// call it from the walk they already register.
///
/// # Why the isolate is passed rather than a scope
///
/// V8 runs the build callback with no scope of its own and no `&mut Isolate`
/// reachable, so the walk re-enters the isolate recorded at registration. It
/// hands the result to each retainer rather than a scope, because the two kinds
/// of handle a retainer holds need different scopes: a `v8::Weak` resolves
/// through `Weak::to_local`, which takes a context-bearing scope, while a
/// `v8::Global` needs only `Local::new`. Every retainer here opens its own scope
/// and keeps it for exactly as long as the handles it creates are needed — V8
/// merges a wrapper node into the object's own node after the build callback
/// returns, so a handle must not outlive the walk.
pub fn add_embedder_nodes(graph: &EmbedderGraph) {
    if !graph.has_isolate() {
        // The walk needs an isolate to open a scope. A registration without one
        // cannot describe a wrapper, and reporting the native nodes alone would
        // be a snapshot missing exactly the edges the tests assert.
        return;
    }
    // The closures are cloned out of the `RefCell` before any of them runs. A
    // closure can allocate, and an allocation can drop the last reference to a
    // retainer, whose `Drop` calls [`unregister`]. Holding the borrow across the
    // iteration would panic on that re-entry rather than reporting the smaller
    // set that is actually live.
    let closures: Vec<Rc<Describe>> = RETAINERS.with(|retainers| {
        retainers
            .borrow()
            .iter()
            .map(|(_, describe)| Rc::clone(describe))
            .collect()
    });
    if closures.is_empty() {
        return;
    }
    // SAFETY: the graph is live for this call and its isolate is the one the
    // snapshot is of, so every handle a closure builds is valid here.
    unsafe {
        graph.with_isolate(|isolate| {
            for describe in closures {
                describe(graph, isolate);
            }
        });
    }
}

/// Adds `node`, its wrapper edges and its children to `graph`.
///
/// This is `MemoryTracker::AddNode` (`src/memory_tracker-inl.h:396`): add the
/// node, add `native_to_javascript` and `javascript_to_native` around its
/// wrapper when it has one, and then recurse into each tracked field. Doing it
/// here rather than in every binding keeps the edge names and their directions
/// in one place, which is where a mistake would silently produce a snapshot the
/// tests still accept.
///
/// Returns the native node so a caller can add an edge to it from outside the
/// tree it describes.
pub fn add_node(graph: &EmbedderGraph, node: &HeapNode<'_>) -> Option<EmbedderNode> {
    let native = graph.add_node(node.name, node.size)?;
    if let Some(wrapper) = node.wrapper {
        if let Some(js) = graph.v8_node(wrapper) {
            graph.add_edge(native, js, "native_to_javascript");
            graph.add_edge(js, native, "javascript_to_native");
        }
    }
    for child in &node.children {
        if let Some(added) = add_node(graph, &child.node) {
            graph.add_edge(native, added, child.edge);
        }
    }
    Some(native)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registration_can_be_dropped_and_reregistered() {
        let id = register(|_, _| {});
        unregister(id);
        // Dropping an id twice is what a finalizer racing a close does.
        unregister(id);
        let again = register(|_, _| {});
        assert_ne!(
            again, id,
            "ids are not reused, so a stale id cannot free a live one"
        );
        unregister(again);
    }

    #[test]
    fn a_node_starts_childless_and_wrapperless() {
        let node = HeapNode::new("ZlibStream", 496);
        assert_eq!(node.name, "ZlibStream");
        assert_eq!(node.size, 496);
        assert!(node.wrapper.is_none());
        assert!(node.children.is_empty());
    }

    #[test]
    fn children_keep_their_edge_names() {
        let node = HeapNode::new("ZlibStream", 496)
            .with_child("compression context", HeapNode::new("ZlibContext", 240));
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].edge, "compression context");
        assert_eq!(node.children[0].node.name, "ZlibContext");
        assert_eq!(node.children[0].node.size, 240);
    }
}
