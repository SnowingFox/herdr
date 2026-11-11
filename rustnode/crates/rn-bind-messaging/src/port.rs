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
use std::rc::{Rc, Weak};

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
pub struct Message {
    /// The serialized payload, exactly as `ValueSerializer` produced it.
    pub data: Vec<u8>,
    /// Transferred `ArrayBuffer` backing stores, in transfer-id order.
    pub array_buffers: Vec<v8::SharedRef<v8::BackingStore>>,
    /// The transfer-list entries themselves, in id order.
    ///
    /// Node's `Message::transferables_` at the sending end: the deserializer
    /// resolves each port id against this, and rebuilding a port is what moves the
    /// queue out of the sender's object and into the receiver's.
    pub ports: Vec<v8::Global<v8::Object>>,
    /// Native handles and JavaScript clones this message carries, in the order the
    /// serializer numbered them. Shared with every recipient, the way Node shares
    /// the `shared_ptr<Message>` itself.
    pub host_objects: Rc<Vec<Rc<dyn TransferData>>>,
    /// How many transfer-list entries sit in front of [`host_objects`] in the id
    /// space the payload references.
    ///
    /// A clone's id is its index in the combined vector, so the deserializer
    /// subtracts this before indexing [`host_objects`]. Zero for every message
    /// that transfers nothing, which is every `structuredClone`.
    pub transferred_count: usize,
    /// Whether this entry is the close marker rather than a real message.
    ///
    /// Node appends an empty `Message` to a queue when a port is disentangled, and
    /// `ReceiveMessage` turns it into `Close()`. So close is ordered *after*
    /// everything already queued, which is what makes
    /// `postMessage(1); postMessage(2); close()` deliver `1`, `2`, then `close`.
    pub close: bool,
}

impl Message {
    /// A real message carrying `data`.
    pub fn new(
        data: Vec<u8>,
        array_buffers: Vec<v8::SharedRef<v8::BackingStore>>,
        ports: Vec<v8::Global<v8::Object>>,
        host_objects: Vec<Rc<dyn TransferData>>,
        transferred_count: usize,
    ) -> Self {
        Self {
            data,
            array_buffers,
            ports,
            host_objects: Rc::new(host_objects),
            transferred_count,
            close: false,
        }
    }

    /// The close marker [`MessagePortData::disentangle`] queues.
    pub fn close_marker() -> Self {
        Self {
            data: Vec::new(),
            array_buffers: Vec::new(),
            ports: Vec::new(),
            host_objects: Rc::new(Vec::new()),
            transferred_count: 0,
            close: true,
        }
    }
}

/// The group of ports that can reach each other, Node's `SiblingGroup`.
///
/// One shared object, not a per-port peer list: Node erases a leaving port from
/// the *group*, so disentangling both ends in turn closes each exactly once.
/// Separate per-port lists would queue a second close for a port that had
/// already been closed by its peer's departure, which is observable as a
/// duplicate `close` event.
#[derive(Default)]
pub struct SiblingGroup {
    /// The ends, in entanglement order.
    ///
    /// Weak, because membership must not keep a port alive: Node's `ports_` holds
    /// raw pointers and a port removes itself on close.
    ports: RefCell<Vec<Weak<MessagePortData>>>,
}

impl SiblingGroup {
    /// Joins `a` and `b` into one new anonymous group.
    pub fn entangle(a: &Rc<MessagePortData>, b: &Rc<MessagePortData>) {
        let group = Rc::new(Self::default());
        group.add(a);
        group.add(b);
        *a.group.borrow_mut() = Some(Rc::clone(&group));
        *b.group.borrow_mut() = Some(Rc::clone(&group));
    }

    fn add(&self, port: &Rc<MessagePortData>) {
        self.ports.borrow_mut().push(Rc::downgrade(port));
    }

    /// The live ends, excluding any that were collected.
    fn members(&self) -> Vec<Rc<MessagePortData>> {
        self.ports
            .borrow_mut()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    /// The live ends other than `port`.
    fn peers_of(&self, port: &MessagePortData) -> Vec<Rc<MessagePortData>> {
        self.members()
            .into_iter()
            .filter(|member| !std::ptr::eq(member.as_ref(), port))
            .collect()
    }

    /// Removes `port`, and returns how many ends remain in the group.
    fn remove(&self, port: &MessagePortData) -> usize {
        let mut ports = self.ports.borrow_mut();
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
    queue: RefCell<VecDeque<Message>>,
    /// The group this end belongs to, while it belongs to one.
    group: RefCell<Option<Rc<SiblingGroup>>>,
    /// The port object that owns this end, if any.
    ///
    /// Weak, so a queued message does not pin the object, and empty after the
    /// port closed or was transferred — Node's `owner_` pointer, nulled by
    /// `Detach()`. A queue with no owner still exists, so a message posted into
    /// it before the port is claimed is delivered when it is.
    owner: RefCell<Weak<PortInner>>,
}

impl MessagePortData {
    /// A detached end with no group.
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            queue: RefCell::new(VecDeque::new()),
            group: RefCell::new(None),
            owner: RefCell::new(Weak::new()),
        })
    }

    /// Joins two ends into one anonymous group, the way `MessageChannel` does.
    pub fn entangle(a: &Rc<Self>, b: &Rc<Self>) {
        SiblingGroup::entangle(a, b);
    }

    /// Records the port that owns this end.
    pub fn attach(&self, inner: &Rc<PortInner>) {
        *self.owner.borrow_mut() = Rc::downgrade(inner);
    }

    /// Drops the owner link, Node's `Detach()`.
    pub fn detach(&self) {
        *self.owner.borrow_mut() = Weak::new();
    }

    /// The owning port, while it is still alive.
    pub fn owner(&self) -> Option<Rc<PortInner>> {
        self.owner.borrow().upgrade()
    }

    /// Appends a message and wakes the owner if it is receiving.
    pub fn enqueue(&self, message: Message) {
        self.queue.borrow_mut().push_back(message);
        if let Some(owner) = self.owner() {
            owner.schedule();
        }
    }

    /// Takes the oldest message, if there is one.
    pub fn dequeue(&self) -> Option<Message> {
        self.queue.borrow_mut().pop_front()
    }

    /// The front message's close flag, without removing it.
    ///
    /// `ReceiveMessage` peeks for exactly this: a port that is not receiving
    /// still has to honour a close marker, because otherwise a port whose peer
    /// closed would never notice.
    pub fn front_is_close(&self) -> Option<bool> {
        self.queue.borrow().front().map(|message| message.close)
    }

    /// How many messages are queued.
    pub fn len(&self) -> usize {
        self.queue.borrow().len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.borrow().is_empty()
    }

    /// The ends this one can reach, excluding itself.
    pub fn peers(&self) -> Vec<Rc<MessagePortData>> {
        self.group
            .borrow()
            .as_ref()
            .map(|group| group.peers_of(self))
            .unwrap_or_default()
    }

    /// Delivers `message` to every other end of the group.
    ///
    /// Returns `false` when the sender is not part of a group, which is Node's
    /// "MessagePortData is not entangled" case: `postMessage` warns rather than
    /// throwing, so the caller has to tell the two apart.
    pub fn dispatch(&self, message: &Message) -> bool {
        let group = self.group.borrow().clone();
        let Some(group) = group else {
            return false;
        };
        for peer in group.peers_of(self) {
            peer.enqueue(clone_message(message));
        }
        true
    }

    /// Leaves the group, queueing a close for this end and for a last peer.
    ///
    /// This is `SiblingGroup::Disentangle`, and its order matters: the leaving
    /// port is removed from the group *first*, so the size check at the end sees
    /// only the ends that are still members. An anonymous two-port group
    /// therefore closes each end exactly once however many times this runs.
    pub fn disentangle(&self) {
        let group = self.group.borrow_mut().take();
        let Some(group) = group else {
            // Already out of the group; a second close must stay silent.
            return;
        };
        let remaining = group.remove(self);

        self.enqueue(Message::close_marker());
        if remaining == 1 {
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
        // A second recipient needs its own `Global` handles; they point at the same
        // objects, which is what a transfer-list entry means when one message
        // reaches more than one port.
        ports: message.ports.clone(),
        host_objects: Rc::clone(&message.host_objects),
        transferred_count: message.transferred_count,
        close: message.close,
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
    pub data: Rc<MessagePortData>,
    /// `receiving_messages_`: set by `start()` and by the first listener.
    pub receiving: Cell<bool>,
    /// libuv's ref bit.
    pub refed: Cell<bool>,
    /// Set once `close()` ran.
    pub closing: Cell<bool>,
    /// Identity of this port, so two ports never compare equal.
    identity: Rc<()>,
    /// The JavaScript object, weakly.
    ///
    /// Delivery needs the object to pass as `this` to `emitMessage`. A strong
    /// root here would keep every port alive for the process' life.
    object: RefCell<Option<v8::Weak<v8::Object>>>,
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
    static CLOSING: RefCell<Vec<Rc<PortInner>>> = const { RefCell::new(Vec::new()) };

    /// Every port that is still receiving, ref'd and open.
    ///
    /// Separate from [`PENDING`] because the two answer different questions:
    /// `PENDING` is "what to run this turn" and drains, while this is libuv's
    /// `uv__loop_alive()` — "is any handle keeping the process up" — which has to
    /// stay true for as long as the port is ref'd, whether or not a message is
    /// waiting. Without it a script whose only work is a `message` listener would
    /// exit immediately, where Node stays alive.
    static LIVE: RefCell<Vec<Rc<PortInner>>> = const { RefCell::new(Vec::new()) };

    /// The callback that wakes the loop when a message is queued.
    ///
    /// Node signals a port's `uv_async_t` from `TriggerAsync`. rustnode has no
    /// per-port handle, so the equivalent is to arm the check phase, and the
    /// CLI registers the arming function here when it starts the loop. `None`
    /// before that, which is why `schedule` tolerates it: a message queued during
    /// bootstrap is still in `PENDING` and the first check phase runs it.
    static CHECK_PHASE_ARMED: Cell<Option<fn()>> = const { Cell::new(None) };
}

/// Registers the function that wakes the loop's check phase.
///
/// Called once by the CLI when it starts the loop. One slot, replaced rather
/// than accumulated: there is one loop and one check handle.
pub fn set_check_phase_armed(armed: fn()) {
    CHECK_PHASE_ARMED.with(|slot| slot.set(Some(armed)));
}

impl PortInner {
    /// Builds the port state for a queue.
    pub fn new(data: Rc<MessagePortData>) -> Rc<Self> {
        let inner = Rc::new(Self {
            data,
            receiving: Cell::new(false),
            refed: Cell::new(true),
            closing: Cell::new(false),
            identity: Rc::new(()),
            object: RefCell::new(None),
        });
        inner.data.attach(&inner);
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
    /// Node's `TriggerAsync` does nothing when the handle is closing, and the
    /// loop then runs `OnMessage` only for a port that is receiving, so a
    /// non-receiving port is not queued here either.
    pub fn schedule(self: &Rc<Self>) {
        if self.closing.get() || !self.receiving.get() {
            return;
        }
        PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            if !pending.iter().any(|other| other.same(self)) {
                pending.push(Rc::clone(self));
            }
        });
        // Node signals the port's `uv_async_t` here, which is what wakes the
        // loop. rustnode delivers from the check phase instead, so arming the
        // check handle is the equivalent wake: without it the message would sit
        // in `PENDING` until some unrelated timer or immediate happened to keep
        // the loop turning.
        if let Some(armed) = CHECK_PHASE_ARMED.with(|slot| slot.get()) {
            armed();
        }
    }

    /// Marks this port as receiving and wakes it if messages are already queued.
    pub fn start(self: &Rc<Self>) {
        self.receiving.set(true);
        LIVE.with(|live| {
            let mut live = live.borrow_mut();
            if !live.iter().any(|other| other.same(self)) {
                live.push(Rc::clone(self));
            }
        });
        if !self.data.is_empty() {
            self.schedule();
        }
    }

    /// Stops draining this port, `stopMessagePort`.
    pub fn stop(&self) {
        self.receiving.set(false);
        LIVE.with(|live| live.borrow_mut().retain(|other| !other.same_ref(self)));
    }

    /// Detaches a port that is being moved to another owner.
    ///
    /// Node's `TransferForMessaging` closes and detaches; the queue lives on in
    /// the receiving object, so this drops the owner link and stops delivery
    /// here without queueing a close for the peer.
    pub fn detach_for_transfer(&self) {
        self.closing.set(true);
        self.receiving.set(false);
        self.data.detach();
    }

    /// Whether the loop should keep running for this port.
    ///
    /// libuv keeps a loop alive for an active, ref'd handle. A port is active
    /// once it is receiving, which is what makes `port.on('message', ...)` pin
    /// the process and `port.unref()` release it.
    pub fn keeps_loop_alive(&self) -> bool {
        self.receiving.get() && self.refed.get() && !self.closing.get()
    }

    /// Closes this port, queueing the close event for the close phase.
    ///
    /// Idempotent: Node's `HandleWrap::Close` returns early unless the handle is
    /// still initialized, which is what makes a second `close()` harmless.
    pub fn close(self: &Rc<Self>) {
        if self.closing.get() {
            return;
        }
        self.closing.set(true);
        self.receiving.set(false);
        LIVE.with(|live| live.borrow_mut().retain(|other| !other.same(self)));
        self.data.disentangle();
        CLOSING.with(|closing| {
            let mut closing = closing.borrow_mut();
            if !closing.iter().any(|other| other.same(self)) {
                closing.push(Rc::clone(self));
            }
        });
        // The close event is dispatched from the check phase, so it needs the
        // same wake a queued message does; otherwise `port.close()` would only
        // emit `close` if some other handle happened to keep the loop running.
        if let Some(armed) = CHECK_PHASE_ARMED.with(|slot| slot.get()) {
            armed();
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

/// Takes every port whose close event is owed.
pub fn take_closing() -> Vec<Rc<PortInner>> {
    CLOSING.with(|closing| std::mem::take(&mut *closing.borrow_mut()))
}

/// Whether a delivery is queued for the check phase.
///
/// True when a posted message or a close event is waiting to be dispatched. This
/// is what starts the check handle; [`any_keeps_loop_alive`] answers the
/// different question of whether a port pins the process open.
pub fn has_delivery_pending() -> bool {
    let pending = PENDING.with(|queue| !queue.borrow().is_empty());
    let closing = CLOSING.with(|queue| !queue.borrow().is_empty());
    pending || closing
}

/// Whether any port is keeping the loop alive.
///
/// This is libuv's `uv__loop_alive()` for the ports: a port that is receiving,
/// ref'd and not closing holds the process open, whether or not a message is
/// waiting for it. `MessageChannel`'s ports start unref'd, so a script that
/// attaches no listener exits; `port.on('message', ...)` re-refs and pins.
pub fn any_keeps_loop_alive() -> bool {
    LIVE.with(|live| {
        // Drop ports whose object was collected, then answer from what is left.
        live.borrow_mut().retain(|port| port.has_object());
        live.borrow().iter().any(|port| port.keeps_loop_alive())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port() -> (Rc<MessagePortData>, Rc<PortInner>) {
        let data = MessagePortData::new();
        let inner = PortInner::new(Rc::clone(&data));
        (data, inner)
    }

    #[test]
    fn a_channel_delivers_to_the_peer_and_not_to_the_poster() {
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);

        assert!(a.dispatch(&Message::new(
            vec![1],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0
        )));

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
        ));
        a.dispatch(&Message::new(
            vec![2],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
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
        assert!(
            !a.dispatch(&Message::new(
                vec![1],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0
            )),
            "an unentangled port has no peer to warn about"
        );
    }

    #[test]
    fn a_stopped_port_keeps_no_loop_alive() {
        let (_data, inner) = port();
        assert!(!inner.keeps_loop_alive(), "a fresh port is not receiving");
        inner.start();
        assert!(inner.keeps_loop_alive());
        inner.stop();
        assert!(!inner.keeps_loop_alive());
        inner.start();
        inner.refed.set(false);
        assert!(!inner.keeps_loop_alive(), "an unref'd port never pins");
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
    fn a_transferred_port_stops_receiving_without_closing_its_peer() {
        let a = MessagePortData::new();
        let b = MessagePortData::new();
        MessagePortData::entangle(&a, &b);
        let inner = PortInner::new(Rc::clone(&a));
        inner.start();

        inner.detach_for_transfer();

        assert!(!inner.keeps_loop_alive());
        assert!(a.owner().is_none(), "the queue lost its owner");
        assert_eq!(
            b.front_is_close(),
            None,
            "a move must not close the channel the port was moved into"
        );
    }
}
