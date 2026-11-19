//! The port pair behind `MessagePort`, and the queue a posted message lands in.
//!
//! # The shape Node builds
//!
//! `src/node_messaging.cc` separates two things that are easy to conflate:
//!
//! * `MessagePortData` — the queue and the entanglement. It is shared by the
//!   two ends of a channel and outlives either `MessagePort` object, which is
//!   what lets a message posted before a listener exists still be there when
//!   one is attached.
//! * `MessagePort` — the JavaScript object, owning one `MessagePortData` and a
//!   `uv_async_t` the sender triggers.
//!
//! A `SiblingGroup` holds the ports that can reach each other; `MessageChannel`
//! makes an anonymous group of exactly two. Posting walks the group and appends
//! the message to every member except the sender, which is why a channel
//! delivers to the peer and not back to the poster.
//!
//! This module keeps that split for the same reason. The queue lives in a
//! `MessagePortData` behind an `Rc`, the JavaScript object holds an `Rc` to it,
//! and closing a port drops *its* reference rather than the queue, so a peer
//! that is still receiving sees the messages posted before the close and then a
//! close of its own.
//!
//! # Where the async handle went
//!
//! Node signals a port with `uv_async_send`, and delivery happens when the loop
//! runs the async callback. rustnode has no libuv and no per-handle async
//! queue, so the same thing is expressed as a thread-local pending list that the
//! loop drains from its check phase — the phase libuv would have run the async
//! callback in.
//!
//! A port with no listener is not drained by the loop. That is Node's rule too:
//! `start()` sets `receiving_messages_`, and `setupPortReferencing` in
//! `lib/internal/worker/io.js` calls it only when the first listener arrives.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex, Weak as SharedWeak};

use rn_core::host_object::TransferData;
use rn_v8_sys::v8;

/// One serialized message on its way through a channel.
///
/// Node keeps a `MallocedBuffer` plus the transferred `ArrayBuffer` backing
/// stores. This keeps the same two pieces: the bytes V8's serializer produced,
/// and the backing stores the transfer list detached, which the receiver's
/// deserializer re-attaches in the order the serializer numbered them.
///
/// It also carries the clone payloads of the native host objects the payload
/// references. Node keeps those in `Message::transferables_` and resolves an id
/// against a `host_objects` vector built from it, so the ids the payload carries
/// are indices into one vector: transfer-list entries first, then clones.
/// [`transferred_count`] records where that vector splits, which is Node's
/// `first_cloned_object_index_`.
///
/// There is exactly *one* vector. A transferred `MessagePort` is a
/// [`PortTransferData`] entry in it, not a second vector of `Global`s: the
/// serializer writes one id space, so the deserializer must resolve an id against
/// one list or the two sides can disagree about which object an id names.
pub struct Message {
    /// The serialized payload, exactly as `ValueSerializer` produced it.
    pub data: Vec<u8>,
    /// Transferred `ArrayBuffer` backing stores, in transfer-id order.
    pub array_buffers: Vec<v8::SharedRef<v8::BackingStore>>,
    /// Shared buffer backing stores the payload referenced, in id order.
    ///
    /// Node's `Message::shared_array_buffers_`. These are *not* transfers: a
    /// shared buffer stays usable on the sending side, and the receiver attaches
    /// the same allocation rather than a copy. Without this list a message
    /// containing a `Uint32Array` over a `SharedArrayBuffer` could not be read
    /// back at all, which is what stopped `new Worker()` from constructing.
    pub shared_array_buffers: Vec<v8::SharedRef<v8::BackingStore>>,
    /// Transfer-list entries and clones, in the order the serializer numbered
    /// them. Shared with every recipient, the way Node shares the
    /// `shared_ptr<Message>` itself.
    ///
    /// A transferred port is here as its [`PortTransferData`], which is what lets
    /// rebuilding it move the queue out of the sender's object and into the
    /// receiver's.
    pub host_objects: Arc<Vec<Arc<dyn TransferData>>>,
    /// How many transfer-list entries sit in front of the clones in
    /// [`host_objects`].
    ///
    /// Node's `first_cloned_object_index_`. The deserializer resolves every id
    /// against the one vector, so it does not need this; the serializer's `Finish`
    /// loop does, because that is where the clones begin.
    pub transferred_count: usize,
    /// Whether this entry is the close marker rather than a real message.
    ///
    /// Node appends an empty `Message` to a queue when a port is disentangled, and
    /// `ReceiveMessage` turns it into `Close()`. So close is ordered *after*
    /// everything already queued, which is what makes
    /// `postMessage(1); postMessage(2); close()` deliver `1`, `2`, then `close`.
    pub close: bool,
    /// The `MessagePortData` addresses this message hands over, in transfer-list
    /// order.
    ///
    /// `SiblingGroup::Dispatch` compares a message's transferables against the
    /// ports it is about to deliver to, so it can report the "posted to itself"
    /// warning instead of delivering a payload that names an object the receiver
    /// is taking over. Node does that with a pointer comparison because a
    /// transferred port's `TransferData` *is* its `MessagePortData`; keeping the
    /// addresses is the same comparison without downcasting `Arc<dyn>`.
    transferred_ports: Vec<usize>,
}

impl Message {
    /// A real message carrying `data`.
    ///
    /// `transferred_ports` names the ports the transfer list handed over, as
    /// `MessagePortData` addresses. [`MessagePortData::dispatch`] is its only
    /// reader.
    pub fn new(
        data: Vec<u8>,
        array_buffers: Vec<v8::SharedRef<v8::BackingStore>>,
        shared_array_buffers: Vec<v8::SharedRef<v8::BackingStore>>,
        host_objects: Vec<Arc<dyn TransferData>>,
        transferred_count: usize,
        transferred_ports: Vec<usize>,
    ) -> Self {
        Self {
            data,
            array_buffers,
            shared_array_buffers,
            host_objects: Arc::new(host_objects),
            transferred_count,
            close: false,
            transferred_ports,
        }
    }

    /// The close marker [`MessagePortData::disentangle`] queues.
    pub fn close_marker() -> Self {
        Self {
            data: Vec::new(),
            array_buffers: Vec::new(),
            shared_array_buffers: Vec::new(),
            host_objects: Arc::new(Vec::new()),
            transferred_count: 0,
            close: true,
            transferred_ports: Vec::new(),
        }
    }

    /// Whether this message hands anything over, Node's `has_transferables`.
    ///
    /// `!transferables_.empty() || !array_buffers_.empty()`: a transferred
    /// `ArrayBuffer` counts as much as a transferred port, because either one makes
    /// the message undeliverable to more than one destination. A *shared* buffer
    /// does not, since it is referenced rather than moved.
    #[must_use]
    pub fn has_transferables(&self) -> bool {
        self.transferred_count > 0 || !self.array_buffers.is_empty()
    }

    /// Whether `port` is one of the ports this message transfers.
    ///
    /// `SiblingGroup::Dispatch` walks `message->transferables()` for this, so a
    /// destination that the transfer list just moved out of the group is reported
    /// with Node's warning rather than delivered a payload naming itself.
    fn transfers_port(&self, port: &MessagePortData) -> bool {
        let address = std::ptr::from_ref(port) as usize;
        self.transferred_ports.contains(&address)
    }
}

/// What [`MessagePortData::dispatch`] did with a message.
///
/// Node's `v8::Maybe<bool>` from `SiblingGroup::Dispatch`, plus the warning it
/// writes through its `error` out-parameter. The shapes are distinct at the API
/// and cannot be collapsed into one `false`:
///
/// * [`Self::NotEntangled`] and [`Self::TransferablesMultipleDestinations`] are
///   `Nothing()`: `postMessage` returns `undefined` and throws nothing.
/// * [`Self::NoDestinations`] is `Just(false)`, which `postMessage` returns as
///   `false` — and which `io.js`'s `BroadcastChannel.postMessage` turns into
///   `DOMException('Message could not be posted.')`.
/// * [`Self::DeliveredWithWarning`] is a successful post that also emits a
///   process warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// The sender is in no group at all, Node's "MessagePortData is not entangled".
    NotEntangled,
    /// The group has no member other than the sender.
    NoDestinations,
    /// A transfer list with more than one other member, which cannot be honoured.
    TransferablesMultipleDestinations,
    /// Delivered to every other member.
    Delivered,
    /// Delivered, and Node warns that a destination was itself transferred.
    DeliveredWithWarning(&'static str),
}

/// `Dispatch`'s warning for a post whose target is one of its own transferables.
///
/// `src/node_messaging.cc`'s text, verbatim: the message reaches nobody else, and
/// the channel the target was moved onto is the one that was posted to.
pub const DISPATCH_WARNING_TARGET_TRANSFERRING: &str =
    "The target port was posted to itself, and the communication channel was lost";

/// Which thread a port belongs to, and which port on it.
///
/// A queue that grows on a foreign thread cannot reach the owning `PortInner`:
/// that is `Rc` and holds a `v8::Weak`, so touching it off-thread is undefined
/// behaviour rather than a race. So the owner is recorded as a location, and the
/// owner's own wake callback resolves it. This is Node's `owner_` pointer
/// expressed so it cannot outlive the thread it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// The id the owning thread registered the port under.
    pub id: u64,
    /// Which thread that is.
    pub thread: u64,
    /// The owning thread's wake handle, if it had one when this was recorded.
    ///
    /// This is the piece that makes a cross-thread post arrive *at post time*.
    /// Without it, `enqueue` found no local `PortInner` on a foreign thread and
    /// did nothing, so the receiving loop only noticed the message on its next
    /// turn — 347ms for a worker that posted and then busy-looped for 300ms,
    /// against node's 26ms. Node's `TriggerAsync` is the same idea: the sender
    /// signals the owner's `uv_async_t` instead of touching the owner.
    pub token: Option<rn_uv::wake::ThreadToken>,
}

thread_local! {
    /// The ports that exist on this thread, by id.
    ///
    /// Weak, because the registry must not keep a port alive; pruned on every
    /// scan so a thread that creates many short-lived ports does not accumulate
    /// dead entries.
    static LOCAL_PORTS: RefCell<Vec<(u64, std::rc::Weak<PortInner>)>> =
        const { RefCell::new(Vec::new()) };
}

/// This thread's identity, as recorded in [`Owner`].
fn current_thread() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    thread_local! {
        static ID: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    ID.with(|id| {
        if id.get() == 0 {
            id.set(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        }
        id.get()
    })
}

/// The next port id to hand out.
fn next_port_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// This thread's port with id `id`, if it is still alive.
fn lookup_local(id: u64) -> Option<Rc<PortInner>> {
    LOCAL_PORTS.with(|ports| {
        let mut ports = ports.borrow_mut();
        ports.retain(|(_, port)| port.strong_count() > 0);
        ports
            .iter()
            .find(|(other, _)| *other == id)
            .and_then(|(_, port)| port.upgrade())
    })
}

/// Registers a port on this thread so a foreign wake can find it.
fn register_local(id: u64, port: &Rc<PortInner>) {
    LOCAL_PORTS.with(|ports| ports.borrow_mut().push((id, Rc::downgrade(port))));
}

/// Schedules every port on this thread whose queue another thread grew.
///
/// The body of the cross-thread wake callback: a sender can only signal this
/// thread's `uv_async_t`, so the resolution happens here, where the objects live.
pub fn schedule_ports_with_mail() {
    let waiting: Vec<Rc<PortInner>> = LOCAL_PORTS.with(|ports| {
        let mut ports = ports.borrow_mut();
        ports.retain(|(_, port)| port.strong_count() > 0);
        ports
            .iter()
            .filter_map(|(_, port)| port.upgrade())
            .collect()
    });
    for port in waiting {
        if !port.data.is_empty() {
            port.schedule();
        }
    }
}

/// Records this thread's wake token on every port it owns.
///
/// A port attached before the thread installed a cross-thread wake handle keeps
/// `None` in its [`Owner`], and a foreign sender then queues its message with
/// nothing to signal — the receiving loop stays parked. The worker's environment
/// port is exactly that case: it is built before `install_check_phase` runs, so
/// the parent's `stdioWantsMoreData` answer for a stdout payload never woke the
/// worker, its `Writable` stayed `writing`, and the process hung with no active
/// handle on either side to explain it.
///
/// Runs after the handle exists, for every port already registered, so the
/// correctness of cross-thread delivery does not depend on the creation order of
/// one port against one install call.
pub fn refresh_owner_tokens(token: rn_uv::wake::ThreadToken) {
    let ports: Vec<Rc<PortInner>> = LOCAL_PORTS.with(|ports| {
        let mut ports = ports.borrow_mut();
        ports.retain(|(_, port)| port.strong_count() > 0);
        ports
            .iter()
            .filter_map(|(_, port)| port.upgrade())
            .collect()
    });
    for port in ports {
        port.data.refresh_owner_token(token);
    }
}

/// How many ports this thread still has registered.
///
/// Exposed for tests: a create/terminate loop that leaves this climbing has leaked
/// a port per worker.
#[must_use]
pub fn live_port_count() -> usize {
    LOCAL_PORTS.with(|ports| {
        let mut ports = ports.borrow_mut();
        ports.retain(|(_, port)| port.strong_count() > 0);
        ports.len()
    })
}

/// Locks `mutex`, recovering a poisoned guard.
///
/// A `Message` may now cross a thread (`TransferData: Send + Sync`), so this state
/// is behind `Mutex` rather than `RefCell`. Poisoning only happens if a thread
/// panicked while holding the lock; the data behind it is a queue or a list of
/// weak references, neither of which can be left structurally broken by a panic in
/// this module, so recovering is correct and refusing every later access would
/// turn one panic into a permanently unusable port.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The group of ports that can reach each other, Node's `SiblingGroup`.
///
/// One shared object, not a per-port peer list: Node erases a leaving port from
/// the *group*, so disentangling both ends in turn closes each exactly once.
/// Separate per-port lists would queue a second close for a port that had
/// already been closed by its peer's departure, which is observable as a
/// duplicate `close` event.
///
/// # Anonymous and named groups are not the same thing
///
/// A `MessageChannel` makes an anonymous group of exactly two, and losing one end
/// closes the other because nothing can ever reach it again. A `BroadcastChannel`
/// joins a group *by name*, which is process-wide: `SiblingGroup::Get` in
/// `src/node_messaging.cc` keeps `groups_`, an `unordered_map<string,
/// weak_ptr<SiblingGroup>>` behind one mutex, so two channels on one name land in
/// the same group whether they were built on one thread or two. A named group has
/// no fixed size and no survivor rule: closing one member leaves the rest open,
/// which is why [`MessagePortData::disentangle`] only closes a last peer when
/// `name` is empty.
#[derive(Default)]
pub struct SiblingGroup {
    /// The ends, in entanglement order.
    ///
    /// Weak, because membership must not keep a port alive: Node's `ports_` holds
    /// raw pointers and a port removes itself on close.
    ports: Mutex<Vec<SharedWeak<MessagePortData>>>,
    /// The name a `BroadcastChannel` group is shared under, empty when anonymous.
    ///
    /// Node's `const std::string name_`, and the emptiness is load-bearing rather
    /// than cosmetic: it is the only thing that distinguishes "close the survivor"
    /// from "leave the other channels alone".
    name: String,
}

/// The process-wide table of named groups, Node's `SiblingGroup::groups_`.
///
/// Weak values, and an entry whose group is gone is replaced rather than reused,
/// which is `SiblingGroup::Get`'s `i->second.expired()` branch. That is what makes
/// a name reusable after every channel on it closed — observable, and the case a
/// strong map would break by handing the next `BroadcastChannel('n')` a group
/// nobody is listening to.
fn named_groups() -> &'static Mutex<std::collections::HashMap<String, SharedWeak<SiblingGroup>>> {
    static GROUPS: std::sync::OnceLock<
        Mutex<std::collections::HashMap<String, SharedWeak<SiblingGroup>>>,
    > = std::sync::OnceLock::new();
    GROUPS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

impl SiblingGroup {
    /// Joins `a` and `b` into one new anonymous group.
    pub fn entangle(a: &Arc<MessagePortData>, b: &Arc<MessagePortData>) {
        let group = Arc::new(Self::default());
        group.add(a);
        group.add(b);
        *lock(&a.group) = Some(Arc::clone(&group));
        *lock(&b.group) = Some(Arc::clone(&group));
    }

    /// The named group for `name`, creating it if no live channel holds it.
    ///
    /// Node's `SiblingGroup::Get`. The lock covers creation *and* insertion so two
    /// threads racing on one name cannot make two groups for it, which is the whole
    /// reason the table is behind one mutex rather than per-name.
    pub fn get_or_create(name: &str) -> Arc<Self> {
        let mut groups = lock(named_groups());
        if let Some(existing) = groups.get(name).and_then(SharedWeak::upgrade) {
            return existing;
        }
        let group = Arc::new(Self {
            ports: Mutex::new(Vec::new()),
            name: name.to_string(),
        });
        groups.insert(name.to_string(), Arc::downgrade(&group));
        group
    }

    /// Whether this group is shared by name rather than being one channel's pair.
    fn is_named(&self) -> bool {
        !self.name.is_empty()
    }

    fn add(&self, port: &Arc<MessagePortData>) {
        lock(&self.ports).push(Arc::downgrade(port));
    }

    /// The live ends, excluding any that were collected.
    fn members(&self) -> Vec<Arc<MessagePortData>> {
        let mut ports = lock(&self.ports);
        ports.retain(|member| member.strong_count() > 0);
        ports.iter().filter_map(SharedWeak::upgrade).collect()
    }

    /// The live ends other than `port`.
    fn peers_of(&self, port: &MessagePortData) -> Vec<Arc<MessagePortData>> {
        self.members()
            .into_iter()
            .filter(|member| !std::ptr::eq(member.as_ref(), port))
            .collect()
    }

    /// Removes `port`, and returns how many ends remain in the group.
    fn remove(&self, port: &MessagePortData) -> usize {
        let mut ports = lock(&self.ports);
        ports.retain(|member| {
            member
                .upgrade()
                .is_some_and(|member| !std::ptr::eq(member.as_ref(), port))
        });
        ports.len()
    }
}

/// The queue and the group membership one end of a channel owns.
///
/// Shared through `Rc` so both ends of a `MessageChannel` can reach the group.
/// Node holds the group in a `shared_ptr` and the queue behind a mutex because
/// two threads may touch it; a single-threaded runtime needs neither, but the
/// *lifetime* rules are the same and they are what this type encodes.
pub struct MessagePortData {
    /// Messages waiting to be received, oldest first.
    queue: Mutex<VecDeque<Message>>,
    /// The group this end belongs to, while it belongs to one.
    group: Mutex<Option<Arc<SiblingGroup>>>,
    /// The port object that owns this end, if any.
    ///
    /// Weak, so a queued message does not pin the object, and empty after the
    /// port closed or was transferred — Node's `owner_` pointer, nulled by
    /// `Detach()`. A queue with no owner still exists, so a message posted into
    /// it before the port is claimed is delivered when it is.
    owner: Mutex<Option<Owner>>,
}

impl MessagePortData {
    /// A detached end with no group.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            group: Mutex::new(None),
            owner: Mutex::new(None),
        })
    }

    /// Joins two ends into one anonymous group, the way `MessageChannel` does.
    pub fn entangle(a: &Arc<Self>, b: &Arc<Self>) {
        SiblingGroup::entangle(a, b);
    }

    /// Joins the process-wide group called `name`, the way `BroadcastChannel` does.
    ///
    /// Node's `MessagePort::New(env, context, {}, SiblingGroup::Get(name))`, whose
    /// only effect is `sibling_group->Entangle(port->data_.get())`. A channel joins
    /// whatever group already holds that name, creating one if none does, so two
    /// channels on one name share a group whether or not anything else on the name
    /// exists yet.
    pub fn join_named(self: &Arc<Self>, name: &str) {
        let group = SiblingGroup::get_or_create(name);
        group.add(self);
        *lock(&self.group) = Some(group);
    }

    /// Records the port that owns this end.
    pub fn attach(&self, inner: &Rc<PortInner>) {
        *lock(&self.owner) = Some(Owner {
            id: inner.id,
            thread: current_thread(),
            // Captured here, on the owning thread, because the `uv_async_t` it
            // names belongs to this thread's loop. A sender on another thread
            // can only signal it, never reach the port itself.
            token: rn_uv::wake::current_thread_token(),
        });
    }

    /// Records this thread's wake token on an owner that was attached without one.
    ///
    /// A port created before its thread had a cross-thread wake handle records
    /// `None` in [`Owner::token`], and a foreign sender then has no way to wake
    /// this thread's loop: [`Self::enqueue`] queues the message and the loop
    /// stays parked. That is what left a worker's `process.stdout` stream
    /// `writing` with bytes still buffered — the parent answers the first
    /// `_writev` with `stdioWantsMoreData`, the worker's environment port is the
    /// owner, and that port was attached before the worker installed its wake
    /// handle, so the answer never woke the worker's loop.
    ///
    /// Called once the handle exists, for every port this thread owns, so the
    /// fix does not depend on each port's creation site being ordered after it.
    pub fn refresh_owner_token(&self, token: rn_uv::wake::ThreadToken) {
        let mut owner = lock(&self.owner);
        let Some(owner) = owner.as_mut() else {
            return;
        };
        // Only this thread may amend its own record: the token names a handle
        // on the thread that attached the port.
        if owner.thread != current_thread() {
            return;
        }
        owner.token = Some(token);
    }

    /// Drops the owner link, Node's `Detach()`.
    pub fn detach(&self) {
        *lock(&self.owner) = None;
    }

    /// The owning port, while it is still alive on this thread.
    ///
    /// `None` from a foreign thread is the honest answer: `PortInner` is `Rc` and
    /// holds a `v8::Weak`, so it must never be reached from anywhere but the
    /// thread that built it. Cross-thread delivery goes through the wake token in
    /// [`Owner`] instead of through this accessor.
    pub fn owner(&self) -> Option<Rc<PortInner>> {
        let owner = *lock(&self.owner);
        let owner = owner?;
        if owner.thread != current_thread() {
            return None;
        }
        lookup_local(owner.id)
    }

    /// The owning port's location, whoever it belongs to.
    pub fn owner_record(&self) -> Option<Owner> {
        *lock(&self.owner)
    }

    /// Appends a message and wakes whoever must read it.
    ///
    /// Two cases, and the second is the one that took a bug to notice:
    ///
    /// * the owner is on this thread, so it can be scheduled directly;
    /// * the owner is on another thread, in which case [`Self::owner`] returns
    ///   `None` by design and nothing would happen. That was the whole of
    ///   CLA-137: a worker posted and then busy-looped, and the parent only saw
    ///   the message when the worker's loop came back around. Node signals the
    ///   owner's `uv_async_t` at post time; `Owner::token` is how the same
    ///   signal is sent here.
    pub fn enqueue(&self, message: Message) {
        lock(&self.queue).push_back(message);
        if let Some(owner) = self.owner() {
            owner.schedule();
            return;
        }
        // Foreign owner: signal its loop. A token whose thread has exited is
        // inert and returns false, which is the ordinary race — the message
        // stays queued rather than being lost.
        if let Some(owner) = self.owner_record() {
            if let Some(token) = owner.token {
                // `false` means the thread's handle is gone; the message stays
                // queued, so this is a lost wake rather than a lost message.
                let _ = token.notify();
            }
        }
    }

    /// Takes the oldest message, if there is one.
    pub fn dequeue(&self) -> Option<Message> {
        lock(&self.queue).pop_front()
    }

    /// The front message's close flag, without removing it.
    ///
    /// `ReceiveMessage` peeks for exactly this: a port that is not receiving still
    /// has to honour a close marker, because otherwise a port whose peer closed
    /// would never notice.
    pub fn front_is_close(&self) -> Option<bool> {
        lock(&self.queue).front().map(|message| message.close)
    }

    /// How many messages are queued.
    pub fn len(&self) -> usize {
        lock(&self.queue).len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        lock(&self.queue).is_empty()
    }

    /// The ends this one can reach, excluding itself.
    pub fn peers(&self) -> Vec<Arc<MessagePortData>> {
        lock(&self.group)
            .as_ref()
            .map(|group| group.peers_of(self))
            .unwrap_or_default()
    }

    /// Delivers `message` to every other end of the group.
    ///
    /// This is `SiblingGroup::Dispatch`, and its refusals are real rather than
    /// defensive. The shapes are distinct at the API — see [`Dispatch`] — because
    /// `postMessage` answers `undefined`, `false` or `true` depending on which one
    /// happened, and `io.js` maps only `undefined` to "Message could not be
    /// posted."
    pub fn dispatch(&self, message: &Message) -> Dispatch {
        let group = lock(&self.group).clone();
        let Some(group) = group else {
            // `MessagePortData::Dispatch`'s "not entangled", which is `Nothing`.
            return Dispatch::NotEntangled;
        };
        let peers = group.peers_of(self);
        if peers.is_empty() {
            // `if (size() <= 1) return Just(false);`
            return Dispatch::NoDestinations;
        }
        // `if (size() > 2 && message->has_transferables())`: a transfer names one
        // receiver, so a group with room for more cannot honour it.
        if peers.len() > 1 && message.has_transferables() {
            return Dispatch::TransferablesMultipleDestinations;
        }
        let mut warned = None;
        for peer in peers {
            // A destination the transfer list just moved out of the group has
            // nowhere to deliver to; Node answers `Just(true)` with a warning
            // rather than failing the post.
            if message.transfers_port(&peer) {
                warned = Some(DISPATCH_WARNING_TARGET_TRANSFERRING);
                continue;
            }
            peer.enqueue(message.clone_for_peer());
        }
        match warned {
            Some(text) => Dispatch::DeliveredWithWarning(text),
            None => Dispatch::Delivered,
        }
    }

    /// Leaves the group, queueing a close for this end and for a last peer.
    ///
    /// This is `SiblingGroup::Disentangle`, and its order matters: the leaving
    /// port is removed from the group *first*, so the size check at the end sees
    /// only the ends that are still members. An anonymous two-port group
    /// therefore closes each end exactly once however many times this runs.
    ///
    /// A *named* group never closes its survivors. Node's check is
    /// `if (size() == 1 && name_.empty())`, so the last member of a
    /// `BroadcastChannel` group stays open and usable: it can be posted to again
    /// once another channel joins the name. Closing it would make
    /// `new BroadcastChannel('n'); peer.close(); channel.postMessage(...)` throw
    /// where Node accepts it, and would make a name unusable after its first pair
    /// of channels went away.
    pub fn disentangle(&self) {
        let group = lock(&self.group).take();
        let Some(group) = group else {
            // Already out of the group; a second close must stay silent.
            return;
        };
        let remaining = group.remove(self);

        self.enqueue(Message::close_marker());
        if remaining == 1 && !group.is_named() {
            if let Some(last) = group.members().first() {
                last.enqueue(Message::close_marker());
            }
        }
    }
}

/// A message is shared by every recipient, so cloning one copies the bytes.
///
/// Node shares a `shared_ptr<Message>` between recipients; copying is the same
/// observable behaviour for the one-recipient channel this build supports, and
/// it avoids a second reference-counted wrapper around the serializer output.
fn clone_message(message: &Message) -> Message {
    Message {
        data: message.data.clone(),
        array_buffers: message.array_buffers.clone(),
        // A `SharedRef` clone points at the same allocation, which is exactly what
        // a shared buffer is: every recipient, and the sender, must see one buffer.
        shared_array_buffers: message.shared_array_buffers.clone(),
        // `Arc`, so a second recipient shares the same payloads. A transferred
        // port's queue is shared the same way, which is what Node's
        // `shared_ptr<Message>` means when one message reaches two ports.
        host_objects: Arc::clone(&message.host_objects),
        transferred_count: message.transferred_count,
        close: message.close,
        transferred_ports: message.transferred_ports.clone(),
    }
}

impl Message {
    /// A copy for one more recipient.
    ///
    /// The payload bytes and the backing stores are reference-counted either way,
    /// and `host_objects` is `Arc`, so this clones the small parts and shares the
    /// large ones — the same thing Node's `shared_ptr<Message>` achieves.
    fn clone_for_peer(&self) -> Message {
        clone_message(self)
    }
}

/// A transferred `MessagePort`, as it travels in a message.
///
/// Node's `MessagePort::TransferData`. It stands in the message's host-object
/// vector for the port, so the id the payload wrote for it resolves to this
/// payload on the receiving side and rebuilds the receiving object from the queue
/// the sender gave up.
///
/// Only the queue crosses. [`PortInner`] must not: it is `Rc` and holds a
/// `v8::Weak`, so sending it to another thread would be undefined behaviour
/// rather than a transfer. `MessagePortData` is `Arc` + `Mutex`, which is why it
/// is the part that can move.
pub struct PortTransferData {
    /// The queue and group membership the receiving port takes over.
    data: Arc<MessagePortData>,
}

impl PortTransferData {
    /// A payload around the queue `port` is giving up.
    pub fn for_port(data: Arc<MessagePortData>) -> Arc<dyn TransferData> {
        Arc::new(Self { data })
    }

    /// The address of the queue this payload hands over.
    ///
    /// `Message::transferred_ports` records these so `dispatch` can ask whether a
    /// port it is about to deliver to is one the transfer list just moved.
    pub fn address(data: &MessagePortData) -> usize {
        std::ptr::from_ref(data) as usize
    }
}

impl TransferData for PortTransferData {
    fn rebuild<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _target: v8::Local<'s, v8::Context>,
    ) -> Option<v8::Local<'s, v8::Object>> {
        // Node's `NewPortObject`: a fresh object around the transferred queue. It
        // runs `oninit`, which is the hook that wires up the event target — and
        // the reason this cannot happen from inside `read_host_object`, where
        // JavaScript is disallowed.
        //
        // A port has no context restriction: `MessagePortData::Deserialize` builds
        // it in whatever context the message is being delivered to, which is the
        // mechanism the whole `moveMessagePortToContext` path relies on.
        crate::new_port_object(scope, Arc::clone(&self.data)).ok()
    }
}

/// The per-port state a `MessagePort` object owns.
///
/// This is the part of `MessagePort` that is not the channel: whether the port
/// is receiving, whether it is ref'd, whether it is closing, and which object it
/// is. Separate from [`MessagePortData`] because these are properties of *this
/// object*, not of the channel — closing one end does not stop the other.
pub struct PortInner {
    /// The queue this end owns.
    ///
    /// `Arc`, because the two ends may live in different isolates and a sender
    /// appends to the receiver's queue from its own thread.
    pub data: Arc<MessagePortData>,
    /// The id this port is registered under on its thread.
    pub id: u64,
    /// `receiving_messages_`: set by `start()` and by the first listener.
    pub receiving: Cell<bool>,
    /// libuv's ref bit.
    pub refed: Cell<bool>,
    /// Set once `close()` ran.
    pub closing: Cell<bool>,
    /// Set once the close event ran.
    pub closed: Cell<bool>,
    /// Whether this port currently holds one [`rn_uv::wake::acquire`].
    ///
    /// Node gives every port its own `uv_async_t` and refs it while the port is
    /// live, so libuv counts the loop alive and a foreign `uv_async_send` is
    /// dispatched. rustnode has one wake handle per thread shared by every port on
    /// it, so "this port is ref'd" has to be translated into a refcount on that
    /// shared handle — and the ref/deref pair has to be balanced, which is why the
    /// port remembers whether it holds one.
    wake_refed: Cell<bool>,
    /// Whether the queue has been given up, Node's `data_ == nullptr`.
    ///
    /// Set by [`Self::detach_for_move`], which is `MessagePort::MoveToContext`'s
    /// `port->Detach()`. That is *not* `close()`: the old object keeps its handle,
    /// so `postMessage` on it still serializes (and still validates its transfer
    /// list), returns `true`, and dispatches nothing. Folding this into `closing`
    /// would change what `postMessage` returns and skip the serialization Node
    /// performs, so it is a separate fact.
    data_detached: Cell<bool>,
    /// Identity of this port, so two ports never compare equal.
    identity: Rc<()>,
    /// The JavaScript object, weakly.
    ///
    /// Delivery needs the object to pass as `this` to `emitMessage`. A strong
    /// root here would keep every port alive for the process' life.
    object: RefCell<Option<v8::Weak<v8::Object>>>,
    /// A strong handle to that object while it must not be collected.
    ///
    /// Node's `BaseObject` holds its wrapper strongly and only calls `MakeWeak()`
    /// once nothing needs it; the port half of that rule is `receiving_messages_`.
    /// A receiving port is a live handle, so its wrapper has to survive the
    /// script dropping its last reference — otherwise a queued message is
    /// delivered to an object that no longer exists and the event never fires.
    /// Cleared as soon as the port stops receiving or closes, which is what keeps
    /// it from pinning the process open.
    pinned: RefCell<Option<v8::Global<v8::Object>>>,
}

thread_local! {
    /// Ports that became ready to receive and have not been drained yet.
    ///
    /// Node queues an async handle on the loop instead; this is the same list of
    /// "work the loop must run", drained from the check phase.
    static PENDING: RefCell<Vec<Rc<PortInner>>> = const { RefCell::new(Vec::new()) };

    /// Ports whose `close()` ran and whose close event is still owed.
    ///
    /// Node's `uv_close` callback runs in the loop's close phase and dispatches
    /// the event from there, which is why `port.close()` does not fire the event
    /// synchronously.
    static CLOSING: RefCell<Vec<CloseOwed>> = const { RefCell::new(Vec::new()) };

    /// Every port that is still receiving, ref'd and open.
    ///
    /// Separate from [`PENDING`] because the two answer different questions:
    /// `PENDING` is "what to run this turn" and drains, while this is libuv's
    /// `uv__loop_alive()` — "is any handle keeping the process up" — which has to
    /// stay true for as long as the port is ref'd, whether or not a message is
    /// waiting. Without it a script whose only work is a `message` listener would
    /// exit immediately, where Node stays alive.
    static LIVE: RefCell<Vec<std::rc::Weak<PortInner>>> = const { RefCell::new(Vec::new()) };

    /// The callback that starts the loop's check phase for a port.
    ///
    /// Node signals a port's `uv_async_t` from `TriggerAsync`, and that handle's
    /// own ref bit decides whether the signal holds the loop open. rustnode has no
    /// per-port handle — the check handle is shared — so the callback is told
    /// whether anything still keeps the loop alive. See [`wake_loop`].
    static CHECK_PHASE_ARMED: Cell<Option<fn(bool)>> = const { Cell::new(None) };
}

/// Registers the function that starts the loop's check phase.
///
/// Called once by the CLI when it starts the loop. One slot, replaced rather
/// than accumulated: there is one loop and one check handle.
pub fn set_check_phase_armed(armed: fn(bool)) {
    CHECK_PHASE_ARMED.with(|slot| slot.set(Some(armed)));
}

/// Starts the check phase so a queued delivery runs on the next turn.
///
/// The arm never reffs the shared check handle, and never unrefs it either.
/// Reffing would hold the loop open past the point Node stops — and because the
/// handle is shared with `setImmediate` and every other producer of check-phase
/// work, a ref taken here outlives the port that took it. Unreffing is just as
/// wrong in the other direction: it releases a ref an outstanding immediate took,
/// which stops the loop reaching its own timer phase.
///
/// Port liveness is expressed by [`any_keeps_loop_alive`], which the loop consults
/// through `has_message_port_work`. That is Node's own split: `uv__loop_alive`
/// counts a handle only when it is both active and ref'd, and a port's ref bit is
/// what `ref()`/`unref()` set.
fn wake_loop() {
    let Some(armed) = CHECK_PHASE_ARMED.with(|slot| slot.get()) else {
        return;
    };
    // `false`: the wake never reffs the shared check handle. A port's claim on the
    // loop comes from its own ref bit, reported through `has_message_port_work`,
    // and reffing here would make `port2.on('message', f); port2.unref();
    // port1.postMessage('x')` deliver a message Node drops.
    armed(false);
}

impl PortInner {
    /// Builds the port state for a queue.
    pub fn new(data: Arc<MessagePortData>) -> Rc<Self> {
        let inner = Rc::new(Self {
            data,
            id: next_port_id(),
            receiving: Cell::new(false),
            // `setupPortReferencing` in `lib/internal/worker/io.js` calls
            // `port.unref()` from `oninit`, so every port Node builds starts
            // unref'd. Starting ref'd made a port pin the loop that Node would let
            // the process exit with.
            refed: Cell::new(false),
            closing: Cell::new(false),
            closed: Cell::new(false),
            wake_refed: Cell::new(false),
            data_detached: Cell::new(false),
            identity: Rc::new(()),
            object: RefCell::new(None),
            pinned: RefCell::new(None),
        });
        inner.data.attach(&inner);
        register_local(inner.id, &inner);
        // Every port is a liveness candidate from birth, because liveness is a
        // function of the ref bit and not of `start()`: `new MessageChannel()
        // .port2.ref()` alone pins the process in Node and never calls `start()`.
        //
        // Registered *weakly*. A strong `Rc` here would keep every port alive for
        // the process' life, and since `any_keeps_loop_alive` answers from this
        // list, a worker's closed ports would go on holding its loop open — which
        // made a worker's `setTimeout` and `fs.readFile` never run while the loop
        // spun. `LIVE` is a registry to scan, never an owner.
        LIVE.with(|live| {
            let mut live = live.borrow_mut();
            if !live
                .iter()
                .filter_map(std::rc::Weak::upgrade)
                .any(|other| other.same(&inner))
            {
                live.push(Rc::downgrade(&inner));
            }
        });
        inner
    }

    /// Records the object this port belongs to.
    pub fn attach_object(&self, weak: v8::Weak<v8::Object>) {
        *self.object.borrow_mut() = Some(weak);
    }


    /// The owning object, while it is still alive.
    pub fn object<'s>(&self, scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
        self.object.borrow().as_ref()?.to_local(scope)
    }

    /// Whether the object this port belongs to is still alive.
    ///
    /// A port whose object was collected must stop holding the loop open; the
    /// `Weak` is the only thing that can answer that without a scope.
    pub fn has_object(&self) -> bool {
        self.object
            .borrow()
            .as_ref()
            .is_some_and(|object| !object.is_empty())
    }

    /// Whether `other` is the same port.
    pub fn same(&self, other: &Rc<PortInner>) -> bool {
        Rc::ptr_eq(&self.identity, &other.identity)
    }

    /// Same identity check for a bare reference.
    fn same_ref(&self, other: &PortInner) -> bool {
        std::ptr::eq(Rc::as_ptr(&self.identity), Rc::as_ptr(&other.identity))
    }

    /// Queues the async work a posted message creates.
    ///
    /// Node's `MessagePortData::AddToIncomingQueue` always calls
    /// `owner_->TriggerAsync()`, and `TriggerAsync` bails out only when the handle
    /// is closing. `receiving_messages_` does **not** gate the wake — it gates what
    /// `ReceiveMessage` does once it runs, and a close marker bypasses that gate
    /// entirely.
    ///
    /// So the port is always queued and only the arm is conditional. A worker's
    /// `parentPort` is unref'd for most of its life, and dropping its message
    /// because nothing happened to be ref'd lost every `parentPort.postMessage`
    /// from a worker whose loop had other work.
    pub fn schedule(self: &Rc<Self>) {
        if self.closing.get() {
            return;
        }
        PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            if !pending.iter().any(|other| other.same(self)) {
                pending.push(Rc::clone(self));
            }
        });
        wake_loop();
    }

    /// Holds the port's object strongly because it has a message to deliver.
    ///
    /// `start()` is not the only thing that makes a port deliverable: a port whose
    /// `onmessage` was assigned is put into the receiving state by
    /// `setupPortReferencing` in `io.js`, and a web stream's internal pair is
    /// written to before either end calls `start()`. In every one of those cases a
    /// queued message has to reach the wrapper, so the wrapper is pinned as soon as
    /// the queue is scheduled and released when the port stops.
    pub fn pin_for_delivery(self: &Rc<Self>, scope: &mut v8::PinScope<'_, '_>) {
        if self.closing.get() || self.closed.get() {
            return;
        }
        self.pin_object(scope);
    }

    /// Marks this port as receiving and wakes it if messages are already queued.
    pub fn start(self: &Rc<Self>) {
        self.receiving.set(true);
        if !self.data.is_empty() {
            self.schedule();
        }
    }

    /// Holds the port's object strongly, Node's `ClearWeak()`.
    ///
    /// A receiving port is a live handle: the queue is delivered *to* its wrapper,
    /// so the wrapper must survive the script dropping its last reference. Without
    /// this, a port the script only reaches through its own event target is
    /// collected with messages still queued and every one of them is lost with no
    /// event — which is a hang, not a failure.
    ///
    /// Idempotent, and a no-op when the object has already gone.
    pub fn pin_object(&self, scope: &mut v8::PinScope<'_, '_>) {
        if self.pinned.borrow().is_some() {
            return;
        }
        let Some(object) = self.object(scope) else {
            return;
        };
        *self.pinned.borrow_mut() = Some(v8::Global::new(scope, object));
    }

    /// Releases the strong handle, Node's `MakeWeak()`.
    ///
    /// Called once the port stops receiving or closes. Keeping the root would pin
    /// the process open for a port nothing can deliver to, which is the same
    /// failure the weak reference was there to avoid.
    pub fn unpin_object(&self) {
        *self.pinned.borrow_mut() = None;
    }

    /// Stops draining this port, `stopMessagePort`.
    pub fn stop(&self) {
        // `stopMessagePort` clears `receiving_messages_` and nothing else: the
        // handle stays in the registry and is judged by `keeps_loop_alive`.
        self.receiving.set(false);
        // A port that is no longer receiving has nothing to deliver to, so its
        // wrapper stops needing to exist — `BaseObject::decrease_refcount`'s
        // `MakeWeak()`.
        self.unpin_object();
    }

    /// Detaches a port whose queue is being re-homed into another realm.
    ///
    /// `MessagePort::MoveToContext` calls `port->Detach()`, not
    /// `TransferForMessaging`: the old object keeps its handle — so `postMessage`
    /// on it still answers `true` and delivers nothing — and the port is not
    /// marked closing, so no `close` event is owed. What changes is that this
    /// object no longer owns the queue, which is what stops it competing with the
    /// new object for messages.
    pub fn detach_for_move(&self) {
        self.receiving.set(false);
        self.data_detached.set(true);
        self.drop_wake();
        self.data.detach();
    }

    /// Whether this port has given its queue away, Node's `data_ == nullptr`.
    ///
    /// True only after [`Self::detach_for_move`]; a transferred port is `closing`
    /// instead, which is what `PostMessage` already answers differently.
    pub fn is_detached(&self) -> bool {
        self.data_detached.get()
    }

    /// Detaches a port that is being transferred to another owner.
    ///
    /// Node's `TransferForMessaging` closes and detaches; the queue lives on in
    /// the receiving object, so this drops the owner link and stops delivery
    /// here without queueing a close for the peer.
    pub fn detach_for_transfer(self: &Rc<Self>) {
        self.closing.set(true);
        self.receiving.set(false);
        self.drop_wake();
        self.data.detach();
        // `TransferForMessaging` is `Close(); return Detach();`, so the sender's
        // end owes the same `close` event a `close()` call would queue — and,
        // like `close()`, earns the iteration that dispatches it.
        CLOSING.with(|closing| {
            let mut closing = closing.borrow_mut();
            if !closing.iter().any(|owed| owed.port.same(self)) {
                closing.push(CloseOwed {
                    port: Rc::clone(self),
                    creates_iteration: true,
                    deferred: 0,
                });
            }
        });
        wake_loop();
    }

    /// Whether the loop should keep running for this port.
    ///
    /// libuv keeps a loop alive for an active, ref'd handle. A port is active
    /// once it is receiving, which is what makes `port.on('message', ...)` pin
    /// the process and `port.unref()` release it.
    pub fn keeps_loop_alive(&self) -> bool {
        !self.closed.get() && (self.refed.get() || self.owes_close_event())
    }

    /// Whether this port still owes its own `close` event.
    ///
    /// This is libuv's `closing_handles` term, bounded by the thing that actually
    /// ends it: the event being dispatched. `uv_close` puts a handle on
    /// `closing_handles` and keeps the loop alive until its callback runs, so a
    /// closed port earns exactly one more iteration — the one that dispatches its
    /// own `close`. Keying that on the `CLOSING` queue rather than on the
    /// `closing` flag is what stops it from being unbounded: a port whose object
    /// was dropped, or one already dispatched, leaves the queue.
    pub fn owes_close_event(&self) -> bool {
        CLOSING.with(|queue| {
            queue.borrow().iter().any(|owed| {
                owed.creates_iteration && owed.port.same_ref(self) && !self.closed.get()
            })
        })
    }

    /// `HandleWrap::HasRef`.
    pub fn has_ref(&self) -> bool {
        !self.closed.get() && self.refed.get()
    }

    /// Takes this thread's wake handle ref, if this port does not already hold it.
    ///
    /// Node's port owns a `uv_async_t` that is ref'd for exactly as long as the
    /// port is ref'd, and libuv then counts the loop alive. The distinction matters
    /// in a *worker*: its loop has no other ref'd handle most of the time, so
    /// `uv_run(UV_RUN_NOWAIT)` — which is what
    /// [`crate::has_message_port_work`]'s caller falls back to — returns
    /// immediately without running the async callback. A `postMessage` from another
    /// thread then sits in the queue and is never delivered, even though
    /// `uv_async_send` reported success.
    ///
    /// Keyed on the ref bit rather than on `receiving`, because that is what libuv
    /// counts: `port.ref()` with no listener pins the process in Node, and
    /// `stop()` does not unref anything.
    fn hold_wake(&self) {
        if self.wake_refed.get() {
            return;
        }
        self.wake_refed.set(true);
        rn_uv::wake::acquire();
    }

    /// Gives back the wake ref taken by [`Self::hold_wake`].
    ///
    /// Balanced by construction: `wake_refed` records whether this port holds one,
    /// so releasing a ref this port never took cannot unref the shared handle while
    /// another port still needs it.
    fn drop_wake(&self) {
        if !self.wake_refed.get() {
            return;
        }
        self.wake_refed.set(false);
        rn_uv::wake::release();
    }

    /// `ref()`: takes the wake ref and records the bit.
    pub fn set_ref(&self) {
        self.refed.set(true);
        if !self.closed.get() {
            self.hold_wake();
        }
    }

    /// `unref()`: releases the wake ref and clears the bit.
    pub fn clear_ref(&self) {
        self.refed.set(false);
        self.drop_wake();
    }

    /// `HandleWrap::OnClose`'s `kClosed`.
    pub fn mark_closed(&self) {
        self.closed.set(true);
    }

    /// Closes this port, queueing the close event for the close phase.
    ///
    /// Idempotent: Node's `HandleWrap::Close` returns early unless the handle is
    /// still initialized, which is what makes a second `close()` harmless.
    pub fn close(self: &Rc<Self>) {
        self.close_with(true);
    }

    /// `close()`, saying whether this call is the one that owes the event.
    ///
    /// Only a close the user initiated keeps the loop alive for its own `close`
    /// event. A peer's marker consumed by [`crate::delivery::deliver`] also calls
    /// `Close()` on the receiver — that is what makes a port whose peer went away
    /// stop pinning the loop — but it must not *create* an iteration: Node
    /// exits without dispatching it. So the receiver is closed quietly.
    pub fn close_quietly(self: &Rc<Self>) {
        self.close_with(false);
    }

    fn close_with(self: &Rc<Self>, owes_event: bool) {
        if self.closing.get() {
            return;
        }
        self.closing.set(true);
        self.receiving.set(false);
        // A closed port is no longer a handle anything can deliver to, so its
        // wrapper must not stay rooted. `close_event` still needs the object, and
        // it reads it through the `Weak` while the frame that called `close()`
        // keeps it alive.
        self.unpin_object();
        // The port's handle is going away, so it gives up its claim on the
        // thread's wake handle. Node drops the port's own `uv_async_t` here.
        self.drop_wake();
        // `SiblingGroup::Disentangle`, inline. Node runs it from
        // `MessagePort::OnClose`, but its only observable effect is the close
        // marker it queues for the peer, and that marker is honoured by
        // `deliver` calling `close()` on the receiver — which is the fix for a
        // port whose peer went away pinning the loop forever.
        self.data.disentangle();
        // The event is queued either way: Node dispatches a peer's `close` when
        // anything else keeps the loop turning (`port2.on('close', f);
        // port1.close(); setTimeout(...)` fires it). `owes_event` only decides
        // whether the queue itself earns the iteration.
        CLOSING.with(|closing| {
            let mut closing = closing.borrow_mut();
            if !closing.iter().any(|owed| owed.port.same(self)) {
                closing.push(CloseOwed {
                    port: Rc::clone(self),
                    creates_iteration: owes_event,
                    deferred: 0,
                });
            }
        });
        // Only a close this code initiated earns the iteration. A port closed
        // because its peer sent a close marker must not: Node exits without
        // dispatching that event (`port2.on('close', f); port1.close()` prints
        // nothing), and waking here would make it print.
        if owes_event {
            wake_loop();
        }
    }
}

/// Takes every port the loop should drain.
///
/// Draining the list rather than borrowing it means a delivery that posts another
/// message cannot observe a half-drained list: the new work lands in the next
/// turn, which is also when Node's async handle would fire it.
pub fn take_pending() -> Vec<Rc<PortInner>> {
    PENDING.with(|pending| std::mem::take(&mut *pending.borrow_mut()))
}

/// Puts ports back after a drain that hit its message limit.
///
/// Node's `OnMessage` processes at most 1000 messages and re-triggers the handle
/// for the rest, which stops one busy channel from starving timers.
pub fn requeue(ports: Vec<Rc<PortInner>>) {
    PENDING.with(|pending| pending.borrow_mut().extend(ports));
}

/// One owed `close` event, and whether it is allowed to earn an iteration.
///
/// Node's `closing_handles` counts a handle from `uv_close` until its callback
/// runs, so the port that *called* `close` keeps the loop alive for the iteration
/// that dispatches its own event. A peer closed by a close marker never went
/// through `uv_close` from this code, and Node exits without dispatching it — so
/// its event is still queued (anything else that keeps the loop turning will
/// dispatch it) but does not itself create an iteration.
pub struct CloseOwed {
    /// The port that owes the event.
    pub port: Rc<PortInner>,
    /// Whether this event is the reason the loop ran the close phase.
    pub creates_iteration: bool,
    /// How many close phases this event has been deferred out of.
    ///
    /// An event owed by a port that a close marker closed is dispatched one phase
    /// *after* the one that consumed the marker, which is Node's ordering and only
    /// happens if something else keeps the loop turning. One deferral is therefore
    /// enough; a second would never terminate, because the deferred event is the
    /// only thing left.
    pub deferred: u32,
}

/// Takes every port whose close event is owed.
pub fn take_closing() -> Vec<CloseOwed> {
    CLOSING.with(|closing| std::mem::take(&mut *closing.borrow_mut()))
}

/// Puts back the events that another close phase has to dispatch.
pub fn requeue_closing(owed: Vec<CloseOwed>) {
    CLOSING.with(|closing| closing.borrow_mut().extend(owed));
}

/// Whether a delivery is queued for the check phase.
///
/// True when a posted message or a close event is waiting to be dispatched. This
/// is what starts the check handle; [`any_keeps_loop_alive`] answers the
/// different question of whether a port pins the process open.
pub fn has_delivery_pending() -> bool {
    // Only an event that earns an iteration keeps the phase armed. A deferred one
    // is dispatched if the loop turns for another reason, and must not be the
    // reason it turns: `port2.on('close', f); port1.close()` exits without printing
    // it, while the same script with a pending timer prints it.
    let closing = CLOSING.with(|queue| {
        queue
            .borrow()
            .iter()
            .any(|owed| owed.creates_iteration && !owed.port.closed.get())
    });
    if closing {
        return true;
    }
    // A queued port is work only when its front entry will actually be consumed.
    // A close marker on a listener-less port must not be: Node exits without
    // dispatching it (`port2.on('close', f); port1.close()` prints nothing), so
    // counting it here would run an iteration Node never runs *and* spin, since
    // draining it re-queues nothing while the predicate stays true.
    PENDING.with(|queue| {
        queue
            .borrow()
            .iter()
            .any(|port| port.receiving.get() && !port.data.is_empty() && !port.closed.get())
    })
}

/// Whether a queued port has a message waiting.
pub fn has_deliverable_message() -> bool {
    PENDING.with(|queue| {
        queue.borrow().iter().any(|port| {
            !port.closed.get()
                && port.receiving.get()
                && !port.data.is_empty()
                && port.data.front_is_close() == Some(false)
        })
    })
}

/// Whether any port is keeping the loop alive.
///
/// This is libuv's `uv__loop_alive()` for the ports: a port that is receiving,
/// ref'd and not closing holds the process open, whether or not a message is
/// waiting for it. `MessageChannel`'s ports start unref'd, so a script that
/// attaches no listener exits; `port.on('message', ...)` re-refs and pins.
pub fn any_keeps_loop_alive() -> bool {
    LIVE.with(|live| {
        // Drop ports that are gone or whose object was collected, then answer from
        // what is left. A closed port keeps its object until the `close` event ran,
        // so the liveness test below is what retires it rather than this prune.
        let mut live = live.borrow_mut();
        live.retain(|port| port.upgrade().is_some_and(|port| port.has_object()));
        live.iter()
            .filter_map(std::rc::Weak::upgrade)
            .any(|port| port.keeps_loop_alive())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port() -> (Arc<MessagePortData>, Rc<PortInner>) {
        let data = MessagePortData::new();
        let inner = PortInner::new(Arc::clone(&data));
        (data, inner)
    }

    #[test]
    fn a_channel_delivers_to_the_peer_and_not_to_the_poster() {
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);

        assert!(matches!(
            a.dispatch(&Message::new(
                vec![1],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
                Vec::new(),
            )),
            Dispatch::Delivered
        ));

        assert_eq!(a.len(), 0, "the poster must not receive its own message");
        assert_eq!(b.len(), 1);
        assert_eq!(b.dequeue().map(|message| message.data), Some(vec![1]));
    }

    #[test]
    fn a_message_posted_before_a_listener_exists_is_still_queued() {
        // What `receiveMessageOnPort` depends on: nothing has called `start()`
        // yet, so nothing drains the queue, and the message has to survive.
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);

        a.dispatch(&Message::new(
            vec![7],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            Vec::new(),
        ));

        assert_eq!(b.len(), 1);
        assert_eq!(b.front_is_close(), Some(false));
    }

    #[test]
    fn closing_one_end_queues_a_close_after_the_messages_already_sent() {
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);

        a.dispatch(&Message::new(
            vec![1],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            Vec::new(),
        ));
        a.dispatch(&Message::new(
            vec![2],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            Vec::new(),
        ));
        b.disentangle();
        a.disentangle();

        // Measured from `node`: posting 1 and 2 then closing delivers
        // `1`, `2`, `close` on the peer, in that order.
        let queued: Vec<(bool, Vec<u8>)> = std::iter::from_fn(|| b.dequeue())
            .map(|message| (message.close, message.data))
            .collect();
        assert_eq!(
            queued,
            vec![(false, vec![1]), (false, vec![2]), (true, Vec::new()),]
        );

        // The closing end's own queue holds close markers and nothing else; the
        // second one is queued by its own `disentangle` and never delivered
        // because the port is already closing by then, which is also what Node
        // does.
        let own: Vec<bool> = std::iter::from_fn(|| a.dequeue())
            .map(|message| message.close)
            .collect();
        assert!(
            own.iter().all(|close| *close),
            "the closing port must not receive the messages it posted"
        );
    }

    #[test]
    fn the_surviving_end_of_a_closed_channel_is_closed_too() {
        // `SiblingGroup::Disentangle`: an anonymous group whose size drops to
        // one closes that last port, because nothing can ever reach it again.
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);

        b.disentangle();

        assert_eq!(a.front_is_close(), Some(true));
    }

    #[test]
    fn a_group_of_one_dispatches_nothing() {
        let a = MessagePortData::new();
        assert_eq!(
            a.dispatch(&Message::new(
                vec![1],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
                Vec::new(),
            )),
            Dispatch::NotEntangled,
            "an unentangled port has no peer to warn about"
        );
    }

    /// A name nobody else in the process uses, so these tests cannot see a group
    /// another test left behind.
    fn unique_name(label: &str) -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        format!(
            "rn-test-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    #[test]
    fn a_named_group_delivers_to_every_other_member_and_never_to_the_poster() {
        // `BroadcastChannel`'s whole reason to exist, and the case the removed
        // deferral reason said needed a second thread: three members of one name,
        // all on this thread, one post reaching two of them.
        let name = unique_name("three-way");
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        let c = MessagePortData::new();
        a.join_named(&name);
        b.join_named(&name);
        c.join_named(&name);

        assert_eq!(
            a.dispatch(&Message::new(
                vec![9],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
                Vec::new(),
            )),
            Dispatch::Delivered
        );

        assert_eq!(a.len(), 0, "the poster must not receive its own message");
        assert_eq!(b.len(), 1);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn a_named_group_whose_last_peer_left_has_no_destinations() {
        // Distinct from `NotEntangled`: the sender is still in a live group, there
        // is just nobody else in it. `postMessage` answers `false` here and
        // `undefined` there, and `io.js` turns only the first into
        // "Message could not be posted."
        let name = unique_name("solo");
        let a = MessagePortData::new();
        a.join_named(&name);

        assert_eq!(
            a.dispatch(&Message::new(
                vec![1],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
                Vec::new(),
            )),
            Dispatch::NoDestinations
        );
    }

    #[test]
    fn a_name_becomes_reusable_once_every_channel_on_it_closed() {
        // `SiblingGroup::Get` replaces an expired entry, so a later channel on the
        // same name gets a new group rather than one nobody is in. A strong map
        // would hand it the dead group and the next pair would never talk.
        let name = unique_name("reuse");
        let first = MessagePortData::new();
        let first_peer = MessagePortData::new();
        first.join_named(&name);
        first_peer.join_named(&name);
        first.disentangle();
        first_peer.disentangle();

        let second = MessagePortData::new();
        let second_peer = MessagePortData::new();
        second.join_named(&name);
        second_peer.join_named(&name);

        assert_eq!(
            second.dispatch(&Message::new(
                vec![2],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
                Vec::new(),
            )),
            Dispatch::Delivered
        );
        assert_eq!(second_peer.len(), 1);
    }

    #[test]
    fn a_named_group_keeps_its_survivor_open() {
        // `Disentangle` closes a last peer only for an anonymous group. A named one
        // must not, or closing one `BroadcastChannel` would close every other
        // channel on the name — and the name would be unusable afterwards.
        let name = unique_name("survivor");
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        a.join_named(&name);
        b.join_named(&name);

        b.disentangle();

        assert_eq!(
            a.front_is_close(),
            None,
            "a named group must not close its survivor"
        );
    }

    #[test]
    fn a_transfer_list_with_more_than_one_destination_is_refused() {
        // `SiblingGroup::Dispatch`'s `size() > 2` branch: a transfer names one
        // receiver, so a group with room for more cannot honour it.
        let name = unique_name("transfer");
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        let c = MessagePortData::new();
        a.join_named(&name);
        b.join_named(&name);
        c.join_named(&name);

        // `transferred_count` of 1 is what `has_transferables()` reads, so this is
        // a message that hands something over without needing a real port payload.
        let message = Message::new(vec![3], Vec::new(), Vec::new(), Vec::new(), 1, Vec::new());
        assert!(message.has_transferables());
        assert_eq!(
            a.dispatch(&message),
            Dispatch::TransferablesMultipleDestinations
        );
        assert_eq!(b.len(), 0, "nothing may be delivered when it is refused");
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn a_moved_port_is_detached_without_being_closed() {
        // `MessagePort::MoveToContext` calls `Detach()`, so the old handle keeps
        // its identity and owes no `close` event; only the queue moves. Folding this
        // into `closing` would change what `postMessage` answers on the old handle.
        let (data, inner) = port();
        inner.detach_for_move();

        assert!(inner.is_detached());
        assert!(!inner.closing.get(), "a move is not a close");
        assert_eq!(data.owner_record(), None, "the queue lost its owner");
    }

    #[test]
    fn a_fresh_port_is_unrefed_and_pins_nothing() {
        // Two facts from `io.js`: `setupPortReferencing` unrefs every port its
        // constructor builds, and `MessagePort::Start` only sets
        // `receiving_messages_`. Neither is what makes the loop alive.
        let (_data, inner) = port();
        assert!(!inner.receiving.get(), "a fresh port is not receiving");
        assert!(!inner.refed.get(), "io.js unrefs every port it builds");
        assert!(!inner.keeps_loop_alive(), "an unref'd port pins nothing");
    }

    #[test]
    fn liveness_follows_the_ref_bit_not_the_receiving_flag() {
        // libuv's `uv__loop_alive` is `active_handles || active_reqs ||
        // closing_handles`, and a port's `uv_async_t` is active from
        // `uv_async_init` — not from `start()`. Measured on the pinned oracle:
        // `new MessageChannel().port2.ref()` alone never exits, while
        // `port2.start()` alone exits.
        let (_data, inner) = port();
        inner.start();
        assert!(
            !inner.keeps_loop_alive(),
            "start() does not ref: only the ref bit decides"
        );
        inner.refed.set(true);
        assert!(inner.keeps_loop_alive(), "a ref'd port pins");
        inner.stop();
        assert!(
            inner.keeps_loop_alive(),
            "stopMessagePort does not unref; io.js's removeListener does that"
        );
        inner.refed.set(false);
        assert!(!inner.keeps_loop_alive(), "an unref'd port does not");
    }

    #[test]
    fn a_port_owing_its_close_event_keeps_the_loop_alive_once() {
        // `uv_close` puts the handle on `closing_handles`, which keeps the loop
        // alive until the callback runs — that is the iteration that dispatches
        // the event. The term has to end, or a closed port would pin the process
        // forever: it is the `CLOSING` queue, not the `closing` flag.
        let _ = take_closing();
        let (_data, inner) = port();
        assert!(!inner.owes_close_event());
        inner.clone().close();
        assert!(inner.owes_close_event(), "close() owes its own event");
        let owed = take_closing();
        assert!(owed.iter().any(|owed| owed.port.same(&inner)));
        assert!(
            !inner.owes_close_event(),
            "a dispatched event ends the obligation"
        );
    }

    #[test]
    fn has_ref_reports_true_between_close_and_its_close_event() {
        // `HandleWrap::HasRef` is `IsAlive(wrap) && uv_has_ref(handle)`, and
        // `IsAlive` excludes `kClosed` but not `kClosing`. Measured on the
        // oracle: `port.on('message'); port.close(); port.hasRef()` is `true`.
        let (_data, inner) = port();
        inner.refed.set(true);
        assert!(inner.has_ref());
        inner.clone().close();
        assert!(inner.has_ref(), "closing is not closed");
        inner.mark_closed();
        assert!(!inner.has_ref());
        let _ = take_closing();
    }

    #[test]
    fn scheduling_twice_queues_one_delivery() {
        let (_data, inner) = port();
        inner.start();
        let _ = take_pending();
        inner.schedule();
        inner.schedule();
        assert_eq!(take_pending().len(), 1, "one port is one unit of work");
    }

    #[test]
    fn a_closing_port_schedules_nothing() {
        let (_data, inner) = port();
        inner.start();
        inner.closing.set(true);
        let _ = take_pending();
        inner.schedule();
        assert!(take_pending().is_empty());
    }

    #[test]
    fn two_ports_are_not_the_same_port() {
        let (_a_data, a) = port();
        let (_b_data, b) = port();
        assert!(a.same(&a));
        assert!(!a.same(&b), "identity must not compare equal across ports");
    }

    #[test]
    fn closing_queues_the_close_event_once() {
        let (_data, inner) = port();
        let _ = take_closing();
        inner.close();
        inner.close();
        assert_eq!(take_closing().len(), 1, "close() is idempotent");
    }

    #[test]
    fn a_transferred_port_is_detached_and_owes_its_own_close() {
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);
        let inner = PortInner::new(Arc::clone(&a));
        inner.start();
        inner.refed.set(true);
        let _ = take_closing();

        inner.detach_for_transfer();

        // `TransferForMessaging` is `Close(); return Detach();`, so the sender's
        // end is closing and owes its own `close` event — which is why a second
        // transfer of the same object reports "already detached". The peer's
        // marker is queued by the close phase, not by the transfer, so the channel
        // the port was moved into stays open here.
        assert!(inner.closing.get());
        assert!(
            inner.keeps_loop_alive(),
            "a port that owes its own close event earns the iteration that runs it"
        );
        assert!(inner.owes_close_event(), "the sender's event is owed");
        assert!(a.owner().is_none(), "the queue lost its owner");
        assert_eq!(
            b.front_is_close(),
            None,
            "a move must not close the channel the port was moved into"
        );
        let _ = take_closing();
    }
}
