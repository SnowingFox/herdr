//! A listener on a real TCP socket: bytes arrive through the mechanism, removal
//! stops delivery, and the process can still reach a closeable loop.
//!
//! This is the negative-control-shaped proof the TLS work needs. `TLSWrap` is
//! `AsyncWrap + StreamBase + StreamListener` with no libuv handle of its own, so
//! the things that have to be true before any of it can work are:
//!
//! 1. a [`StreamListener`] attached to a live socket receives that socket's
//!    bytes *instead of* `handle.onread` — nothing here goes through JavaScript,
//!    which is the point: the mechanism has to be real without V8, without TLS
//!    and without `net.js`;
//! 2. it can write to its own stream from inside that callback, which is what
//!    `TLSWrap` does on every handshake and every record — and which is only
//!    legal if no `&mut` to the stream state is held across the call;
//! 3. it can remove itself from inside its own callback, which is the
//!    `Destroy()`-from-`OnStreamRead` path `lib/net.js` creates when a listener
//!    calls `destroy()`;
//! 4. after removal the bytes go to the default destination and the removed
//!    listener sees nothing;
//! 5. the loop is left closeable. That is the `spawn_sync` lesson: a dangling
//!    watcher or a leaked ref shows up as a process that will not exit, so the
//!    close is asserted rather than assumed.
//!
//! # Topology
//!
//! The listener attaches to the **accepted** socket, because that is the socket
//! that reads — the same one a `TLSServer` attaches to, and the same shape
//! `tcp_wrap` gives JavaScript. The client is a plain libuv socket with its own
//! read callback, and it is what drives the sequence:
//!
//! ```text
//! client --FIRST-->  accepted socket --> listener.on_stream_read
//! client <--ACK----  accepted socket <-- listener writes from its callback
//! client --SECOND->  accepted socket --> (default path, listener removed)
//! ```
//!
//! The client only writes `SECOND` after the `ACK`, so by construction the
//! removal happened before the second chunk was even queued. That is what makes
//! "delivery stopped" a real assertion rather than a race between two writes.
//!
//! # Why the state is thread-local
//!
//! `uv_loop` owns one loop per thread, so each test gets its own loop and its own
//! callbacks. Context kept in `thread_local!` therefore isolates the tests from
//! each other without synchronisation, and libuv's callbacks — which are given
//! nothing but the handle — can find the cycle they belong to.

use std::cell::{Cell, RefCell};
use std::ptr;

use libuv_sys2 as uv;
use rn_uv::handle::{self, Allocation, StreamState};
use rn_uv::listener::{self, ListenerRef, ReadBuffer, StreamListener};

/// Everything one test socket owns.
///
/// The handle is a `MaybeUninit` because libuv requires it not to move after
/// `uv_tcp_init`: the box is allocated first, then initialised where it sits.
struct Socket {
    tcp: std::mem::MaybeUninit<uv::uv_tcp_t>,
    state: StreamState,
}

impl Socket {
    fn stream(&mut self) -> *mut uv::uv_stream_t {
        self.tcp.as_mut_ptr().cast()
    }

    fn tcp(&mut self) -> &mut uv::uv_tcp_t {
        // SAFETY: `socket` ran `uv_tcp_init` on this slot.
        unsafe { self.tcp.assume_init_mut() }
    }
}

/// Creates and initialises a socket on this thread's loop.
fn socket() -> Box<Socket> {
    let loop_pointer = rn_uv::uv_loop::loop_ptr().expect("the loop must be creatable");
    let mut boxed = Box::new(Socket {
        tcp: std::mem::MaybeUninit::zeroed(),
        state: StreamState::new(ptr::null_mut()),
    });
    let stream = boxed.stream();
    // SAFETY: `stream` points at the zeroed slot inside the live box.
    let status = unsafe { uv::uv_tcp_init(loop_pointer, boxed.tcp.as_mut_ptr()) };
    assert_eq!(status, 0, "uv_tcp_init must succeed");
    boxed.state = StreamState::new(stream);
    let state_pointer = &mut boxed.state as *mut StreamState;
    // SAFETY: the stream is live and lives in the same box as its state.
    unsafe { handle::set_owner(stream, state_pointer) };
    boxed
}

/// The client's first chunk, which the listener receives.
const FIRST: &[u8] = b"hello ";
/// The client's second chunk, sent only after the listener has been removed.
const SECOND: &[u8] = b"gone";
/// What the listener writes back from inside its own read callback.
const ACK: &[u8] = b"ack";

/// One cycle's configuration and observations.
#[derive(Default)]
struct Cycle {
    /// Remove the listener from inside its first read callback.
    remove_on_first_read: bool,
    /// The bytes the listener was handed.
    delivered: Vec<u8>,
    /// Reads the listener saw.
    listener_reads: usize,
    /// Reads that reached the default (no-listener) path after removal.
    fallback_reads: usize,
    /// Bytes the client received, which proves the callback's write landed.
    client_received: Vec<u8>,
    /// Whether the client has sent its second chunk.
    second_sent: bool,
    /// Whether the socket's teardown called `OnStreamDestroy`.
    destroyed: bool,
}

thread_local! {
    /// The listener under test, so the cycle can inspect it afterwards.
    static LISTENER: RefCell<Option<ListenerRef>> = const { RefCell::new(None) };
    /// The cycle's observations.
    static CYCLE: RefCell<Cycle> = const {
        RefCell::new(Cycle {
            remove_on_first_read: false,
            delivered: Vec::new(),
            listener_reads: 0,
            fallback_reads: 0,
            client_received: Vec::new(),
            second_sent: false,
            destroyed: false,
        })
    };
    /// The connecting socket, which drives the exchange.
    static CLIENT: Cell<*mut Socket> = const { Cell::new(ptr::null_mut()) };
    /// The accepted socket, which is what the listener attaches to.
    static ACCEPTED: Cell<*mut Socket> = const { Cell::new(ptr::null_mut()) };
    /// The read allocation libuv is filling, parked between the two callbacks.
    static PENDING: RefCell<Option<(*mut u8, usize)>> = const { RefCell::new(None) };
    /// Storage for chunks being written, released when the cycle ends.
    static WRITE_STORAGE: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
    /// Sockets to `uv_close` when the exchange is over.
    static CLOSERS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Registers a stream to be closed when the cycle finishes.
fn register_closer(stream: *mut uv::uv_stream_t) {
    CLOSERS.with(|slot| slot.borrow_mut().push(stream as usize));
}

/// Closes every socket the cycle opened, which is what lets the loop idle.
fn close_all() {
    let closers = CLOSERS.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
    for address in closers {
        let stream = address as *mut uv::uv_stream_t;
        // SAFETY: each address is a live stream this cycle registered, and its
        // box is freed by `free_handle` when the close completes.
        unsafe { uv::uv_close(handle::as_handle(stream), Some(free_handle)) };
    }
}

/// A close completion that frees the box the stream lived in.
///
/// This is what makes the listener detach: `Socket` owns a [`StreamState`], whose
/// `Drop` is `StreamResource::~StreamResource` and notifies every listener still
/// attached.
///
/// # Safety
///
/// Called by libuv once per closed handle, with `data` still naming the
/// `StreamState` inside a [`Socket`] box.
unsafe extern "C" fn free_handle(handle_pointer: *mut uv::uv_handle_t) {
    // SAFETY: the handle's `data` is the state the constructor stored.
    let Some(state) = (unsafe { handle::owner(handle_pointer.cast::<uv::uv_stream_t>()) }) else {
        return;
    };
    // SAFETY: `state` is the `state` field of a live `Socket`, so subtracting the
    // field's offset recovers the allocation. Nothing else frees it.
    let owner = unsafe {
        state
            .cast::<u8>()
            .sub(std::mem::offset_of!(Socket, state))
            .cast::<Socket>()
    };
    drop(unsafe { Box::from_raw(owner) });
}

/// Queues one chunk on `stream`, keeping the bytes alive until the write lands.
///
/// # Safety
///
/// `stream` must be a live stream.
unsafe fn write_chunk(stream: *mut uv::uv_stream_t, chunk: &[u8]) {
    let mut storage = chunk.to_vec().into_boxed_slice();
    let mut buffers = [uv::uv_buf_t {
        base: storage.as_mut_ptr().cast(),
        len: storage.len(),
    }];
    let request = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_write_t>::zeroed()));
    // SAFETY: `request` is a live, aligned, zeroed `uv_write_t`.
    let request = unsafe { (*request).as_mut_ptr() };
    // SAFETY: the stream is live and `storage` outlives the completion because it
    // is parked in `WRITE_STORAGE` rather than dropped here.
    let status =
        unsafe { uv::uv_write(request, stream, buffers.as_mut_ptr(), 1, Some(on_written)) };
    assert_eq!(status, 0, "the write must be queued");
    WRITE_STORAGE.with(|slot| slot.borrow_mut().push(storage));
}

/// A queued write finished.
///
/// # Safety
///
/// Called by libuv with the request `write_chunk` allocated.
unsafe extern "C" fn on_written(request: *mut uv::uv_write_t, status: i32) {
    if request.is_null() {
        return;
    }
    // SAFETY: the request came from `Box::new(MaybeUninit::zeroed())` in
    // `write_chunk`, and libuv is finished with it.
    drop(unsafe { Box::from_raw(request.cast::<std::mem::MaybeUninit<uv::uv_write_t>>()) });
    assert_eq!(status, 0, "the write must succeed");
}

/// The listener under test: records reads, and in the two interesting cases
/// writes and removes itself from inside the callback.
struct TestListener {
    /// The state of the socket this listener is attached to.
    ///
    /// This is what `TLSWrap::underlying_stream()` is derived from, and having it
    /// is what lets the callback write and remove.
    state: *mut StreamState,
}

impl StreamListener for TestListener {
    fn on_stream_read(&mut self, this: &ListenerRef, nread: isize, buffer: ReadBuffer) {
        if nread <= 0 {
            return;
        }
        let bytes = buffer
            .bytes(nread)
            .expect("a positive read must expose its bytes")
            .to_vec();
        let (remove, stream) = CYCLE.with(|cycle| {
            let mut cycle = cycle.borrow_mut();
            cycle.delivered.extend_from_slice(&bytes);
            cycle.listener_reads += 1;
            (cycle.remove_on_first_read, self.state)
        });
        // SAFETY: the socket outlives the cycle, so its `stream` field is live.
        let socket = unsafe { (*stream).stream };

        if remove && this.is_attached() {
            // Removing from inside the callback is the `Destroy()` path. It has to
            // be safe because the dispatcher holds an `Rc` to this listener, so
            // the object cannot be freed under the running call.
            // SAFETY: `stream` is live and `remove_stream_listener` takes no
            // reference to it across any listener call.
            let removed = unsafe { listener::remove_stream_listener(stream, this.id()) };
            assert!(removed, "the listener was attached when it removed itself");
        }

        // Writing to the stream from inside `on_stream_read` is `TLSWrap`'s
        // normal mode: `crypto_tls.cc`'s `EncOut` does exactly this. It is only
        // safe because `emit_read` holds no reference to the state, so this
        // re-entrant write is the borrow-discipline assertion.
        // SAFETY: `socket` is the live stream this listener reads from.
        unsafe { write_chunk(socket, ACK) };
    }

    fn on_stream_destroy(&mut self, _this: &ListenerRef) {
        CYCLE.with(|cycle| cycle.borrow_mut().destroyed = true);
    }
}

impl Cycle {
    fn destroyed(&self) -> bool {
        self.destroyed
    }
}

/// libuv's read allocator.
///
/// # Safety
///
/// Called by libuv with a writable buffer.
unsafe extern "C" fn alloc(
    _handle: *mut uv::uv_handle_t,
    suggested: usize,
    buffer: *mut uv::uv_buf_t,
) {
    let size = if suggested == 0 { 64 * 1024 } else { suggested };
    let mut memory = vec![0u8; size].into_boxed_slice();
    let pointer = memory.as_mut_ptr();
    std::mem::forget(memory);
    // SAFETY: `buffer` is libuv's out-parameter.
    unsafe {
        (*buffer).base = pointer.cast();
        (*buffer).len = size;
    }
    PENDING.with(|slot| *slot.borrow_mut() = Some((pointer, size)));
}

/// Takes the parked read allocation.
fn take_pending() -> Option<(*mut u8, usize)> {
    PENDING.with(|slot| slot.borrow_mut().take())
}

/// Frees a parked allocation.
fn release(pointer: *mut u8, length: usize) {
    // SAFETY: `alloc` created this allocation with `length` bytes and nothing
    // else owns it.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length)) });
}

/// The accepted socket's read callback: deliver through the listener chain.
///
/// This mirrors `rn_uv::stream`'s private `on_read`, which an integration test
/// cannot call. The two arms are the whole mechanism: with a listener the bytes go
/// to it, with none they go to the default destination — counted here rather than
/// handed to `onread`, because a test has no isolate.
///
/// # Safety
///
/// Called by libuv with the stream whose `data` is a `*mut StreamState`.
unsafe extern "C" fn on_accepted_read(
    stream: *mut uv::uv_stream_t,
    status: isize,
    _buffer: *const uv::uv_buf_t,
) {
    let taken = take_pending();
    // SAFETY: the socket stored its state pointer on the handle.
    let Some(state) = (unsafe { handle::owner(stream) }) else {
        if let Some((pointer, length)) = taken {
            release(pointer, length);
        }
        return;
    };
    // SAFETY: `state` is live for the whole cycle.
    if unsafe { listener::listener_count(state) } == 0 {
        if status > 0 {
            CYCLE.with(|cycle| cycle.borrow_mut().fallback_reads += 1);
        }
        if let Some((pointer, length)) = taken {
            release(pointer, length);
        }
        return;
    }
    let buffer = match taken {
        Some((pointer, length)) => {
            // SAFETY: `alloc` created this allocation with exactly this length.
            ReadBuffer::Allocated(unsafe { Allocation::from_raw(pointer, length) })
        }
        None => ReadBuffer::Listener(uv::uv_buf_t {
            base: ptr::null_mut(),
            len: 0,
        }),
    };
    // SAFETY: the state is live and `emit_read` holds no reference to it across
    // the listener call, which is what lets the listener write from inside.
    unsafe { listener::emit_read(state, status, buffer) };
}

/// The listening socket's connection callback: attach the listener, then read.
///
/// # Safety
///
/// Called by libuv with the listening stream.
unsafe extern "C" fn on_connection(server: *mut uv::uv_stream_t, status: i32) {
    assert_eq!(status, 0, "the accept must succeed");
    let mut accepted = socket();
    // SAFETY: both streams are live.
    let status = unsafe { uv::uv_accept(server, accepted.stream()) };
    assert_eq!(status, 0, "accept must succeed");
    let stream = accepted.stream();
    register_closer(stream);
    // The box must outlive the loop; the close callback frees it.
    let accepted_pointer = Box::into_raw(accepted);
    ACCEPTED.with(|slot| slot.set(accepted_pointer));

    // SAFETY: the pointer came from `Box::into_raw` above and is live.
    let state = unsafe { &mut (*accepted_pointer).state } as *mut StreamState;
    // This is the line a `TLSWrap` constructor performs:
    // `crypto_tls.cc:417`'s `stream->PushStreamListener(this)`.
    let listener = ListenerRef::new(Box::new(TestListener { state }));
    // SAFETY: `state` is live for the whole cycle.
    assert!(
        unsafe { listener::push_stream_listener(state, listener.clone()) }.is_some(),
        "the listener must attach"
    );
    LISTENER.with(|slot| slot.borrow_mut().replace(listener));

    // SAFETY: the stream is live and its `data` is its state.
    let status = unsafe { uv::uv_read_start(stream, Some(alloc), Some(on_accepted_read)) };
    assert_eq!(status, 0, "read_start must succeed");
}

/// The client's read callback: record the reply and, if it has not yet, send the
/// second chunk.
///
/// The second chunk is only sent once the `ACK` has arrived, and the `ACK` is only
/// written after the listener removed itself. That ordering is what makes
/// "delivery stopped" deterministic instead of a race with the first read.
///
/// # Safety
///
/// Called by libuv with a live stream.
unsafe extern "C" fn on_client_read(
    stream: *mut uv::uv_stream_t,
    status: isize,
    _buffer: *const uv::uv_buf_t,
) {
    let taken = take_pending();
    if status > 0 {
        if let Some((pointer, length)) = taken {
            // SAFETY: `alloc` created this allocation with `length` bytes.
            let bytes = unsafe { std::slice::from_raw_parts(pointer, status as usize) };
            CYCLE.with(|cycle| cycle.borrow_mut().client_received.extend_from_slice(bytes));
            release(pointer, length);
        }
        let send_second = CYCLE.with(|cycle| {
            let mut cycle = cycle.borrow_mut();
            if cycle.second_sent {
                false
            } else {
                cycle.second_sent = true;
                true
            }
        });
        if send_second {
            // SAFETY: the stream is live.
            write_chunk(stream, SECOND);
        }
    } else if let Some((pointer, length)) = taken {
        release(pointer, length);
    }
}

/// The client's connect callback: start reading and send the first chunk.
///
/// # Safety
///
/// Called by libuv with the request from `uv_tcp_connect`.
unsafe extern "C" fn on_connect(_request: *mut uv::uv_connect_t, status: i32) {
    assert_eq!(status, 0, "connect must succeed");
    let client = CLIENT.with(Cell::get);
    assert!(!client.is_null(), "the client must have been stored");
    // SAFETY: the pointer came from the live box the cycle owns.
    let client = unsafe { &mut *client };
    let stream = client.stream();
    // SAFETY: the stream is live.
    let status = unsafe { uv::uv_read_start(stream, Some(alloc), Some(on_client_read)) };
    assert_eq!(status, 0, "read_start must succeed");
    // SAFETY: the stream is live.
    write_chunk(stream, FIRST);
}

/// A pump bound: enough turns for a loopback round trip, few enough to fail
/// rather than hang.
const PUMP_LIMIT: usize = 20_000;

/// Pumps the loop until `done` or the bound is exhausted.
fn pump_until(limit: usize, mut done: impl FnMut() -> bool) {
    for _ in 0..limit {
        rn_uv::uv_loop::run_once();
        if done() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let (delivered, fallback, replies, sent) = CYCLE.with(|cycle| {
        let cycle = cycle.borrow();
        (
            cycle.delivered.clone(),
            cycle.fallback_reads,
            cycle.client_received.clone(),
            cycle.second_sent,
        )
    });
    panic!(
        "the loop did not reach the expected state within {limit} turns: \
         delivered={:?} fallback={fallback} replies={:?} second_sent={sent}",
        String::from_utf8_lossy(&delivered),
        String::from_utf8_lossy(&replies)
    );
}

/// Runs one attach/read/write/remove/destroy cycle on fresh sockets.
fn run_cycle(remove_on_first_read: bool) -> Cycle {
    CYCLE.with(|cycle| {
        *cycle.borrow_mut() = Cycle {
            remove_on_first_read,
            ..Cycle::default()
        }
    });
    LISTENER.with(|slot| slot.borrow_mut().take());

    // ---- a listening socket, so there is a real connection to read from -----
    let mut server = socket();
    let mut address = std::mem::MaybeUninit::<uv::sockaddr_in>::zeroed();
    // SAFETY: `address` is a live out-parameter and the literal is NUL-terminated.
    let status = unsafe { uv::uv_ip4_addr(c"127.0.0.1".as_ptr(), 0, address.as_mut_ptr()) };
    assert_eq!(status, 0, "127.0.0.1 must parse");
    // SAFETY: libuv filled the address.
    let address = unsafe { address.assume_init() };
    // SAFETY: the handle is live and the address outlives the call.
    let status = unsafe { uv::uv_tcp_bind(server.tcp(), std::ptr::from_ref(&address).cast(), 0) };
    assert_eq!(status, 0, "bind must succeed");

    let mut name = std::mem::MaybeUninit::<uv::sockaddr_storage>::zeroed();
    let mut name_length = std::mem::size_of::<uv::sockaddr_storage>() as i32;
    // SAFETY: `name` is a live out-parameter with its length.
    let status =
        unsafe { uv::uv_tcp_getsockname(server.tcp(), name.as_mut_ptr().cast(), &mut name_length) };
    assert_eq!(status, 0, "getsockname must succeed");
    // SAFETY: libuv filled it.
    let name = unsafe { name.assume_init() };
    // SAFETY: the family says this is a `sockaddr_in`.
    let port =
        u16::from_be(unsafe { (*std::ptr::from_ref(&name).cast::<uv::sockaddr_in>()).sin_port });
    assert_ne!(port, 0, "the kernel must have assigned a port");

    let server_stream = server.stream();
    register_closer(server_stream);
    // SAFETY: the server stream is live.
    let status = unsafe { uv::uv_listen(server_stream, 8, Some(on_connection)) };
    assert_eq!(status, 0, "listen must succeed");
    let _ = Box::into_raw(server);

    // ---- the client, which drives the sequence ------------------------------
    let client = socket();
    CLIENT.with(|slot| slot.set(Box::into_raw(client)));
    let client_pointer = CLIENT.with(Cell::get);
    // SAFETY: the pointer came from `Box::into_raw` above and is live.
    let client_stream = unsafe { (*client_pointer).stream() };
    register_closer(client_stream);

    let mut target = std::mem::MaybeUninit::<uv::sockaddr_in>::zeroed();
    // SAFETY: `target` is a live out-parameter.
    let status =
        unsafe { uv::uv_ip4_addr(c"127.0.0.1".as_ptr(), i32::from(port), target.as_mut_ptr()) };
    assert_eq!(status, 0, "the assigned port must parse");
    // SAFETY: libuv filled it.
    let target = unsafe { target.assume_init() };

    let request = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_connect_t>::zeroed()));
    // SAFETY: `request` is a live, aligned, zeroed request.
    let request = unsafe { (*request).as_mut_ptr() };
    // SAFETY: the client and the address are live.
    let status = unsafe {
        uv::uv_tcp_connect(
            request,
            (*client_pointer).tcp(),
            std::ptr::from_ref(&target).cast(),
            Some(on_connect),
        )
    };
    assert_eq!(status, 0, "connect must be queued");

    // ---- pump until the exchange is done -----------------------------------
    //
    // With the listener attached, everything the client sends is delivered. With
    // it removed, the second chunk has to reach the default path instead — that
    // second condition is the proof that removal actually stopped delivery, so it
    // is asserted by the pump rather than hoped for.
    // The ACK is written once per read the listener saw, so the expected reply
    // length follows from how many reads it should get: two when it stays
    // attached, one when it removes itself on the first.
    let expected_client = if remove_on_first_read {
        ACK.len()
    } else {
        ACK.len() * 2
    };
    pump_until(PUMP_LIMIT, || {
        CYCLE.with(|cycle| {
            let cycle = cycle.borrow();
            let delivered_all = cycle.delivered.len() >= FIRST.len() + SECOND.len();
            let saw_second_on_default = cycle.fallback_reads >= 1;
            let replies = cycle.client_received.len() >= expected_client;
            if remove_on_first_read {
                saw_second_on_default && replies
            } else {
                delivered_all && replies
            }
        })
    });

    // Retire the writes still in flight so the counters are final.
    for _ in 0..64 {
        if !rn_uv::uv_loop::run_once() {
            break;
        }
    }

    // The sockets are still open, so the listener must still be attached; the
    // teardown assertion happens after `close_all` below.
    let attached_before_close = LISTENER.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|listener| listener.is_attached())
    });

    close_all();
    // Retire the close callbacks, which is what frees each socket box and runs the
    // state's `Drop` — and therefore the listener's `OnStreamDestroy`.
    for _ in 0..64 {
        if !rn_uv::uv_loop::run_once() {
            break;
        }
    }

    let result = CYCLE.with(|cycle| {
        let cycle = cycle.borrow();
        Cycle {
            remove_on_first_read,
            delivered: cycle.delivered.clone(),
            listener_reads: cycle.listener_reads,
            fallback_reads: cycle.fallback_reads,
            client_received: cycle.client_received.clone(),
            second_sent: cycle.second_sent,
            destroyed: cycle.destroyed,
        }
    });
    WRITE_STORAGE.with(|slot| slot.borrow_mut().clear());
    CLIENT.with(|slot| slot.set(ptr::null_mut()));
    ACCEPTED.with(|slot| slot.set(ptr::null_mut()));
    assert!(
        attached_before_close || remove_on_first_read,
        "the listener must stay attached while the socket is open, unless it removed itself"
    );
    assert!(
        !LISTENER.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|listener| listener.is_attached())
        }),
        "the socket's teardown must have detached its listener"
    );
    result
}

#[test]
fn a_listener_receives_real_socket_bytes_instead_of_javascript() {
    let cycle = run_cycle(false);
    assert_eq!(
        cycle.delivered, b"hello gone",
        "the listener received both chunks, in order"
    );
    assert!(cycle.listener_reads >= 1, "at least one read reached it");
    assert_eq!(
        cycle.fallback_reads, 0,
        "nothing bypassed the listener while it was attached"
    );
    assert_eq!(
        cycle.client_received.len(),
        ACK.len() * 2,
        "each read's write from inside the callback reached the peer"
    );
    assert!(cycle.destroyed(), "the socket teardown notified it");
}

#[test]
fn a_listener_that_removes_itself_stops_receiving() {
    let cycle = run_cycle(true);
    assert!(
        cycle.delivered.starts_with(FIRST),
        "it saw the read that triggered its removal, got {:?}",
        String::from_utf8_lossy(&cycle.delivered)
    );
    assert_eq!(
        cycle.listener_reads, 1,
        "exactly the read in which it removed itself"
    );
    assert!(
        !cycle.delivered.ends_with(SECOND),
        "the chunk sent after removal never reached it, got {:?}",
        String::from_utf8_lossy(&cycle.delivered)
    );
    assert!(
        cycle.fallback_reads >= 1,
        "the later chunk went to the default destination instead"
    );
    assert!(cycle.second_sent, "the client did send its second chunk");
    assert!(
        cycle.client_received.len() >= ACK.len(),
        "the callback's write still landed, even though it removed itself"
    );
}

/// Twenty create/attach/read/remove/destroy cycles, then a clean exit.
///
/// A use-after-free in a once-firing callback often survives one iteration; the
/// repetition is what makes a stale pointer or a leaked ref show up. The final
/// `shutdown` is what makes "clean" mean something, because it is
/// `uv_loop_close` — the call `spawn_sync` returned `UV_EBUSY` from.
#[test]
fn twenty_listener_cycles_leave_no_work_behind() {
    for cycle in 0..20 {
        let remove = cycle % 2 == 0;
        let result = run_cycle(remove);
        if remove {
            assert_eq!(
                result.listener_reads, 1,
                "cycle {cycle}: self-removal stopped delivery"
            );
            assert!(
                result.fallback_reads >= 1,
                "cycle {cycle}: the default path took over"
            );
        } else {
            assert_eq!(
                result.delivered,
                b"hello gone",
                "cycle {cycle}: the full message arrived (reads={}, fallback={}, replies={})",
                result.listener_reads,
                result.fallback_reads,
                result.client_received.len()
            );
        }
        // A listener still attached at teardown is notified; one that removed
        // itself is already off the chain, so this is Node's behaviour too —
        // `StreamResource::~StreamResource` (`stream_base.cc:898`) only walks
        // what is left. Either way the socket must have dropped it, which
        // `run_cycle` asserts.
        if remove {
            assert!(
                !result.destroyed(),
                "cycle {cycle}: a listener that removed itself is not notified again"
            );
        } else {
            assert!(
                result.destroyed(),
                "cycle {cycle}: teardown reached a listener that was still attached"
            );
        }
        assert!(
            rn_uv::uv_loop::is_idle_for_test(),
            "cycle {cycle}: nothing is still referenced"
        );
    }

    assert!(
        rn_uv::uv_loop::shutdown(),
        "twenty cycles must leave a closeable loop, not a busy one"
    );
}
