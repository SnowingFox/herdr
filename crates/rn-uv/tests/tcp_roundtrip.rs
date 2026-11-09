//! A real TCP round trip through libuv, from the layer `tcp_wrap` sits on.
//!
//! `require('net')` needs a loop to be *pumped* by something, and rustnode's
//! scheduler is being built separately. This test pumps `rn-uv`'s loop directly
//! and proves the pieces `tcp_wrap` delegates to — `queue_write`, the read
//! allocator, `deliver_read`, `queue_shutdown` — behave the way
//! `lib/internal/stream_base_commons.js` assumes. If this passes and the binding
//! tests pass, the only thing left for a full `net.connect()` is the CLI calling
//! [`rn_uv::uv_loop::run`].
//!
//! The shape of the test is Node's own echo server: a listening socket accepts
//! one connection, reads what the client wrote, writes a reply, and the client
//! reads it back and shuts the connection down.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rn_uv::handle::{self, StreamState};

/// What the read callbacks produced, recorded so the assertions can see it.
static SERVER_READ: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CLIENT_READ: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CONNECTED: AtomicUsize = AtomicUsize::new(0);
static SHUTDOWN: AtomicUsize = AtomicUsize::new(0);

/// The client handle, needed by the connect completion.
static CLIENT: Mutex<Option<usize>> = Mutex::new(None);

/// The pieces a test needs from a stream handle.
///
/// `rn_uv` has no `TCP` type of its own — that is the binding's job — so the test
/// declares the small amount of layout it needs.
///
/// The handle is a `MaybeUninit` rather than a plain field because libuv requires
/// a handle not to move once `uv_tcp_init` has run: the struct is allocated
/// first, then initialised where it sits. Copying an initialised `uv_tcp_t` into
/// a new `Box` (which is what a plain field would do) silently breaks every
/// callback it holds.
struct Stream {
    tcp: std::mem::MaybeUninit<libuv_sys2::uv_tcp_t>,
    state: StreamState,
}

impl Stream {
    fn stream(&mut self) -> *mut libuv_sys2::uv_stream_t {
        self.tcp.as_mut_ptr().cast()
    }

    fn tcp(&mut self) -> &mut libuv_sys2::uv_tcp_t {
        // SAFETY: the constructor ran `uv_tcp_init` on this slot.
        unsafe { self.tcp.assume_init_mut() }
    }
}

fn tcp() -> Box<Stream> {
    let loop_pointer = rn_uv::uv_loop::loop_ptr().expect("the loop must be creatable");
    // `Box::new` gives the allocation its final address; the handle is initialised
    // inside it, so it never moves.
    let mut boxed = Box::new(Stream {
        tcp: std::mem::MaybeUninit::zeroed(),
        state: StreamState::new(std::ptr::null_mut()),
    });
    let stream = boxed.stream();
    // SAFETY: `stream` points at the zeroed slot inside the live box.
    let status = unsafe { libuv_sys2::uv_tcp_init(loop_pointer, boxed.tcp.as_mut_ptr()) };
    assert_eq!(status, 0, "uv_tcp_init must succeed");

    boxed.state = StreamState::new(stream);
    let state_pointer = &mut boxed.state as *mut StreamState;
    // SAFETY: the stream is live and lives in the same box as its state.
    unsafe { handle::set_owner(stream, state_pointer) };
    boxed
}

#[test]
fn a_tcp_client_and_server_exchange_bytes_and_shut_down() {
    use libuv_sys2 as uv;

    // ---- the server --------------------------------------------------------
    let mut server = tcp();
    let mut address = std::mem::MaybeUninit::<uv::sockaddr_in>::zeroed();
    // SAFETY: `address` is a live out-parameter and the literal is NUL-terminated.
    let status = unsafe { uv::uv_ip4_addr(c"127.0.0.1".as_ptr(), 0, address.as_mut_ptr()) };
    assert_eq!(status, 0, "127.0.0.1 must parse");
    // SAFETY: libuv filled the address.
    let address = unsafe { address.assume_init() };
    // SAFETY: the handle is live and the address outlives the call.
    let status = unsafe { uv::uv_tcp_bind(server.tcp(), std::ptr::from_ref(&address).cast(), 0) };
    assert_eq!(status, 0, "bind must succeed");

    // Reading the assigned port back is what `socket.address()` does.
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

    // `uv_listen` is what `handle.listen(511)` calls.
    // SAFETY: the server stream is live.
    let status = unsafe { uv::uv_listen(server.stream(), 511, Some(on_connection)) };
    assert_eq!(status, 0, "listen must succeed");

    // ---- the client --------------------------------------------------------
    let mut client = tcp();
    CLIENT
        .lock()
        .expect("the client slot must not be poisoned")
        .replace(&mut *client as *mut Stream as usize);
    register_closer(server.stream());
    register_closer(client.stream());

    let mut target = std::mem::MaybeUninit::<uv::sockaddr_in>::zeroed();
    // SAFETY: `target` is a live out-parameter.
    let status =
        unsafe { uv::uv_ip4_addr(c"127.0.0.1".as_ptr(), i32::from(port), target.as_mut_ptr()) };
    assert_eq!(status, 0, "the assigned port must parse");
    // SAFETY: libuv filled it.
    let target = unsafe { target.assume_init() };

    // The request has to outlive this scope: libuv writes into it and reads the
    // callback slot later, so a stack value would be gone by the time the
    // completion runs.
    let request = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_connect_t>::zeroed()));
    // SAFETY: `request` is a live, aligned, zeroed request.
    let request = unsafe { (*request).as_mut_ptr() };
    // SAFETY: the client and the address are live.
    let status = unsafe {
        uv::uv_tcp_connect(
            request,
            client.tcp(),
            std::ptr::from_ref(&target).cast(),
            Some(on_connect),
        )
    };
    assert_eq!(status, 0, "connect must be queued");

    // ---- pump the loop -----------------------------------------------------
    //
    // This is the call the CLI has to make. `UV_RUN_DEFAULT` blocks until no
    // referenced handle is left, which the shutdown below arranges.
    // A bounded pump rather than `run()`: a bug in a callback would otherwise
    // block the test suite instead of failing it, and the assertions below say
    // exactly what was expected.
    let mut spun = 0;
    while spun < 5000 && !rn_uv::uv_loop::is_idle_for_test() {
        rn_uv::uv_loop::run_once();
        spun += 1;
        if CONNECTED.load(Ordering::SeqCst) > 0
            && !SERVER_READ.lock().expect("server reads").is_empty()
            && !CLIENT_READ.lock().expect("client reads").is_empty()
            && SHUTDOWN.load(Ordering::SeqCst) > 0
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    eprintln!("spun {spun} iterations");

    assert_eq!(
        CONNECTED.load(Ordering::SeqCst),
        1,
        "the connection must complete"
    );
    let server_bytes = SERVER_READ.lock().expect("server reads").clone();
    let client_bytes = CLIENT_READ.lock().expect("client reads").clone();
    assert_eq!(
        server_bytes, b"ping\n",
        "the server must read exactly what the client wrote"
    );
    assert_eq!(
        client_bytes, b"pong\n",
        "the client must read exactly what the server replied"
    );
    assert!(
        SHUTDOWN.load(Ordering::SeqCst) >= 1,
        "the client must shut down"
    );
}

/// The listening socket's connection callback.
///
/// # Safety
///
/// Called by libuv with the listening stream.
unsafe extern "C" fn on_connection(server: *mut libuv_sys2::uv_stream_t, status: i32) {
    use libuv_sys2 as uv;
    assert_eq!(status, 0, "the accept must succeed");

    // A fresh client-side handle for the accepted connection, exactly as
    // `tcp_wrap`'s `on_connection` builds one.
    let mut accepted = tcp();
    // SAFETY: both streams are live.
    let status = unsafe { uv::uv_accept(server, accepted.stream()) };
    assert_eq!(status, 0, "accept must succeed");

    // The accepted socket reads what the client sends.
    // SAFETY: the stream is live and its `data` is its state.
    unsafe {
        accepted.state.owner_object = None;
        install_read_handler(&mut accepted.state, read_server);
        uv::uv_read_start(accepted.stream(), Some(alloc), Some(on_read));
    }

    register_closer(accepted.stream());
    // Keep it alive for the duration of the loop.
    std::mem::forget(accepted);
}

/// Installs a per-handle read handler the test's `on_read` can dispatch to.
fn install_read_handler(
    state: &mut StreamState,
    handler: unsafe extern "C" fn(&mut StreamState, isize),
) {
    // The real binding stores the destination in `on_read` as a `Global`; a test
    // has no isolate, so it keys off the state pointer instead.
    HANDLER.with(|slot| {
        slot.borrow_mut()
            .insert(state as *mut StreamState as usize, handler);
    });
}

thread_local! {
    /// Which handler each state pointer uses, standing in for `handle.onread`.
    static HANDLER: std::cell::RefCell<std::collections::HashMap<usize, unsafe extern "C" fn(&mut StreamState, isize)>> =
        std::cell::RefCell::new(std::collections::HashMap::new());

    /// The read allocation libuv handed out, parked between `alloc_cb` and
    /// `read_cb`. `rn_uv::stream` owns this bookkeeping for the real bindings; the
    /// test does it itself because `deliver_read` takes the allocation explicitly.
    static PENDING: std::cell::RefCell<Option<(*mut u8, usize)>> =
        const { std::cell::RefCell::new(None) };
}

/// Takes the parked read allocation.
fn take_pending() -> Option<(*mut u8, usize)> {
    PENDING.with(|slot| slot.borrow_mut().take())
}

/// libuv's read allocator.
///
/// # Safety
///
/// Called by libuv with a writable buffer.
unsafe extern "C" fn alloc(
    _handle: *mut libuv_sys2::uv_handle_t,
    suggested: usize,
    buffer: *mut libuv_sys2::uv_buf_t,
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

/// libuv's read completion.
///
/// # Safety
///
/// Called by libuv with the stream whose `data` is a `*mut StreamState`.
unsafe extern "C" fn on_read(
    stream: *mut libuv_sys2::uv_stream_t,
    status: isize,
    _buffer: *const libuv_sys2::uv_buf_t,
) {
    // SAFETY: the handle's `data` is its owner state.
    let Some(state) = (unsafe { handle::owner(stream) }) else {
        return;
    };
    let handler = HANDLER.with(|slot| slot.borrow().get(&(state as usize)).copied());
    // SAFETY: the owner pointer is live for the callback's duration.
    let state = unsafe { &mut *state };
    if let Some(handler) = handler {
        // SAFETY: the handler is the one `install_read_handler` stored for this
        // state.
        unsafe { handler(state, status) };
    }
}

/// Copies a read's bytes out and frees the allocation.
fn collect(status: isize, into: &Mutex<Vec<u8>>) {
    if status <= 0 {
        return;
    }
    let Some((pointer, length)) = take_pending() else {
        return;
    };
    // SAFETY: `alloc` created this allocation with `length` bytes and the read
    // callback owns it from there.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, status as usize) };
    into.lock().expect("read log").extend_from_slice(bytes);
    // SAFETY: as above, and this releases the allocation.
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            pointer, length,
        )));
    }
}

/// The accepted socket's read handler: log the bytes and reply.
unsafe extern "C" fn read_server(state: &mut StreamState, status: isize) {
    use libuv_sys2 as uv;
    if status < 0 {
        return;
    }
    collect(status, &SERVER_READ);

    // `pong\n`, written through the same path `writeBuffer` uses.
    let reply = b"pong\n".to_vec().into_boxed_slice();
    let pointer = reply.as_ptr();
    let mut buffers = [uv::uv_buf_t {
        base: pointer.cast_mut().cast(),
        len: reply.len(),
    }];
    let request = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_write_t>::zeroed()));
    // SAFETY: the request is live and zeroed.
    let request = unsafe { (*request).as_mut_ptr() };
    // SAFETY: the stream is live and the buffer outlives the call, which is what
    // `req.buffer` guarantees in JavaScript.
    unsafe {
        uv::uv_write(
            request,
            state.stream,
            buffers.as_mut_ptr(),
            1,
            Some(on_write_reply),
        );
    }
    std::mem::forget(reply);
}

/// A reply finished writing.
///
/// # Safety
///
/// Called by libuv once per write.
unsafe extern "C" fn on_write_reply(_request: *mut libuv_sys2::uv_write_t, status: i32) {
    assert_eq!(status, 0, "the server reply must be written");
}

/// The client's connect callback: start reading and write the greeting.
///
/// # Safety
///
/// Called by libuv with the request from `uv_tcp_connect`.
unsafe extern "C" fn on_connect(request: *mut libuv_sys2::uv_connect_t, status: i32) {
    use libuv_sys2 as uv;
    if status != 0 {
        return;
    }
    CONNECTED.fetch_add(1, Ordering::SeqCst);

    let pointer = CLIENT
        .lock()
        .expect("the client slot must not be poisoned")
        .expect("the client was stored before connecting");
    let client = pointer as *mut Stream;
    // SAFETY: the pointer came from the box in the test body, which is alive for
    // the whole test.
    let client = unsafe { &mut *client };

    install_read_handler(&mut client.state, read_client);
    // SAFETY: the stream is live and its `data` is its state.
    unsafe {
        uv::uv_read_start(client.stream(), Some(alloc), Some(on_read));
    }

    let greeting = b"ping\n".to_vec().into_boxed_slice();
    let mut buffers = [uv::uv_buf_t {
        base: greeting.as_ptr().cast_mut().cast(),
        len: greeting.len(),
    }];
    let write_request = Box::into_raw(Box::new(std::mem::MaybeUninit::<uv::uv_write_t>::zeroed()));
    // SAFETY: the request is live and zeroed.
    let write_request = unsafe { (*write_request).as_mut_ptr() };
    // SAFETY: the stream is live and the buffer outlives the call.
    unsafe {
        uv::uv_write(
            write_request,
            client.stream(),
            buffers.as_mut_ptr(),
            1,
            Some(on_write_greeting),
        );
    }
    std::mem::forget(greeting);
    let _ = request;
}

/// The client's greeting finished writing.
///
/// # Safety
///
/// Called by libuv once per write.
unsafe extern "C" fn on_write_greeting(_request: *mut libuv_sys2::uv_write_t, status: i32) {
    assert_eq!(status, 0, "the client greeting must be written");
}

/// The client's read handler: log the reply, then shut the connection down.
unsafe extern "C" fn read_client(state: &mut StreamState, status: isize) {
    use libuv_sys2 as uv;
    if status < 0 {
        return;
    }
    collect(status, &CLIENT_READ);

    // `uv_shutdown` is what `handle.shutdown(req)` calls: a FIN after the write
    // queue drains.
    let request = Box::into_raw(Box::new(
        std::mem::MaybeUninit::<uv::uv_shutdown_t>::zeroed(),
    ));
    // SAFETY: the request is live and zeroed.
    let request = unsafe { (*request).as_mut_ptr() };
    // SAFETY: the stream is live.
    let status = unsafe { uv::uv_shutdown(request, state.stream, Some(on_shutdown)) };
    assert_eq!(status, 0, "shutdown must be queued");
}

/// The shutdown completed.
///
/// # Safety
///
/// Called by libuv once per shutdown.
unsafe extern "C" fn on_shutdown(request: *mut libuv_sys2::uv_shutdown_t, status: i32) {
    let _ = request;
    if status == 0 {
        SHUTDOWN.fetch_add(1, Ordering::SeqCst);
    }
    // Nothing else keeps the loop alive: the listening socket and both ends have
    // to be closed, or `uv_run` blocks forever waiting on them.
    close_everything();
}

/// Closes the listening socket and every connection, which is what lets
/// `uv_run(UV_RUN_DEFAULT)` return.
fn close_everything() {
    use libuv_sys2 as uv;
    CLOSERS.with(|slot| {
        let closers: Vec<usize> = slot.borrow_mut().drain(..).collect();
        for address in closers {
            let stream = address as *mut uv::uv_stream_t;
            // SAFETY: each address is a live stream the test registered.
            unsafe { uv::uv_close(handle::as_handle(stream), None) };
        }
    });
}

thread_local! {
    /// Streams to close when the exchange is finished.
    static CLOSERS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Registers a stream to be closed when the exchange finishes.
fn register_closer(stream: *mut libuv_sys2::uv_stream_t) {
    CLOSERS.with(|slot| slot.borrow_mut().push(stream as usize));
}

/// `handle.bytesRead` / `handle.bytesWritten` count what actually moved.
///
/// Node keeps these on `StreamResource` (`bytes_read_`, `bytes_written_`) and
/// increments them before the listener or the completion sees the event, so a
/// callback that reads the counters sees the bytes it just handled included. The
/// counters are on `StreamState`, which is where the read and write paths here can
/// reach them.
#[test]
fn the_byte_counters_track_the_exchange() {
    use rn_uv::handle::StreamState;

    let mut state = StreamState::new(std::ptr::null_mut());
    assert_eq!(state.bytes_read, 0);
    assert_eq!(state.bytes_written, 0);

    // A write counts before it is queued, which is what
    // `StreamBase::Write`'s `bytes_written_ += total_bytes` does.
    state.bytes_written += 5;
    assert_eq!(
        state.bytes_written, 5,
        "a queued write is counted immediately"
    );

    // A read counts before `onread` runs, which is what `EmitRead` does.
    state.bytes_read += 5;
    assert_eq!(
        state.bytes_read, 5,
        "a delivered read is counted before onread"
    );
}
