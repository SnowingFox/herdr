//! The `--inspect` endpoint: an HTTP/WebSocket server on its own threads.
//!
//! Node's counterpart is three files: `inspector_socket_server.cc` (the listener
//! and session table), `inspector_socket.cc` (HTTP upgrade and WebSocket framing)
//! and `inspector_io.cc` (the thread and the queue between it and the isolate).
//! They are one module here because the split is about which C++ object owns which
//! callback, and that does not survive the translation.
//!
//! # Why a separate thread at all
//!
//! Because that is what `--inspect` promises: the process keeps running while no
//! client is attached, and a client may connect at any moment. A listener on the
//! isolate's thread would either block it or force the loop to poll the socket
//! every iteration. Node takes the thread, and so does this.
//!
//! # The handoff
//!
//! `V8InspectorSession` may only be touched from the isolate's thread, so a
//! frontend's message cannot be dispatched where it is read. The reader thread
//! pushes it onto a queue and asks the loop for a check phase through
//! `rn_core::native_immediates::set_immediate`; the check phase drains the queue
//! inside a V8 scope. Replies travel back over a per-connection channel to a writer
//! thread, because a socket write can block and the isolate must not.
//!
//! ```text
//!   reader thread ──queue──► check phase (isolate) ──session──► V8
//!                                   │
//!                                   └──channel──► writer thread ──► socket
//! ```

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rn_v8_sys::v8;

use crate::agent;

/// The default port, matching `process.debugPort`.
pub const DEFAULT_PORT: u16 = 9229;

/// One message from a frontend, waiting to be dispatched on the isolate thread.
pub struct Incoming {
    /// The connection that received it.
    pub connection: usize,
    /// The protocol message, exactly as the client sent it.
    pub message: String,
}

/// State shared between the isolate thread and the socket threads.
pub struct Shared {
    /// Messages from frontends, filled by the reader threads.
    incoming: Mutex<Vec<Incoming>>,
    /// Where each connection's replies go.
    writers: Mutex<HashMap<usize, Sender<String>>>,
    /// Whether any client is attached, which is what keeps the process alive.
    attached: AtomicBool,
    /// Set when the server should stop.
    stopping: AtomicBool,
    /// The next connection index, so indices are unique for the server's life.
    next: AtomicUsize,
}

impl Shared {
    fn new() -> Self {
        Self {
            incoming: Mutex::new(Vec::new()),
            writers: Mutex::new(HashMap::new()),
            attached: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            next: AtomicUsize::new(0),
        }
    }

    /// Takes everything a frontend has sent since the last drain.
    pub fn take_incoming(&self) -> Vec<Incoming> {
        let mut incoming = self
            .incoming
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        std::mem::take(&mut *incoming)
    }

    /// Whether a client is attached.
    pub fn is_attached(&self) -> bool {
        self.attached.load(Ordering::SeqCst)
    }

    /// Whether the server has been asked to stop.
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Queues `text` for connection `connection`.
    ///
    /// A send failure means the writer thread is gone, which means the client
    /// disconnected; the reply is dropped rather than treated as an error, because
    /// a debugger going away mid-request is normal.
    fn send_to(&self, connection: usize, text: String) {
        let sender = self
            .writers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&connection)
            .cloned();
        if let Some(sender) = sender {
            let _ = sender.send(text);
        }
    }
}

/// The running server.
pub struct Server {
    shared: Arc<Shared>,
    port: u16,
    host: String,
    listener_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Server {
    /// Binds `host:port` and starts the listener thread.
    ///
    /// `port` 0 asks the OS for one, which is what `--inspect-port=0` does and what
    /// the tests use so two runs cannot collide.
    pub fn start(host: &str, port: u16) -> Result<Self, String> {
        let listener = TcpListener::bind((host, port))
            .map_err(|error| format!("cannot bind the inspector to {host}:{port}: {error}"))?;
        let bound = listener
            .local_addr()
            .map_err(|error| format!("cannot read the bound inspector address: {error}"))?;

        let shared = Arc::new(Shared::new());
        let accept_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("inspector-listener".to_string())
            .spawn(move || accept_loop(listener, accept_shared))
            .map_err(|error| format!("cannot start the inspector thread: {error}"))?;

        Ok(Self {
            shared,
            port: bound.port(),
            host: advertised_host(host).to_string(),
            listener_thread: Mutex::new(Some(thread)),
        })
    }

    /// The port the listener actually bound.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `ws://` URL a client connects to.
    ///
    /// Node's `FormatWsAddress` brackets a v6 literal and leaves a v4 one bare, and
    /// the address has no target id — `test/inspector/test-inspector.js` matches
    /// `ws://[...]:port/` exactly.
    pub fn ws_url(&self) -> String {
        format_ws_address(&self.host, self.port, "")
    }

    /// The shared state, so the isolate can drain messages.
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// The host the listener is bound to, as a client should dial it.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Waits until a client attaches, or gives up after a timeout.
    ///
    /// `waitForDebugger` is `--inspect-brk`'s blocking wait: Node blocks on a
    /// semaphore the io thread signals, and the process does not run a line of user
    /// code until a client sends `Runtime.runIfWaitingForDebugger`. Blocking the
    /// isolate thread here is the same thing at this granularity — there is nothing
    /// else that could make progress, because the script has not started.
    ///
    /// The timeout exists so a run with no client does not hang forever: Node's
    /// wait is unbounded, and a test that forgets `--inspect` would then never
    /// finish. `test/inspector` always attaches, so the timeout is not observable
    /// there.
    pub fn wait_for_client(&self) -> bool {
        self.wait_for_client_timeout(Duration::from_secs(30))
    }

    /// [`Self::wait_for_client`] with an explicit bound, so a test can use a short
    /// one.
    pub fn wait_for_client_timeout(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.shared.is_attached() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        // The listener thread is blocked in `accept`, which a flag cannot wake.
        // Connecting to it does, and the accepted socket is closed immediately.
        let _ = TcpStream::connect_timeout(
            &format!("{}:{}", self.host, self.port)
                .parse()
                .unwrap_or_else(|_| ([127, 0, 0, 1], self.port).into()),
            Duration::from_millis(200),
        );
        if let Some(thread) = self
            .listener_thread
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
        {
            let _ = thread.join();
        }
    }
}

/// The address to tell a client to dial for a bound host.
///
/// `--inspect=0.0.0.0` binds every interface, but the address to *connect* to is
/// the loopback one; advertising `0.0.0.0` gives a client something it cannot dial.
pub fn advertised_host(host: &str) -> &str {
    match host {
        "0.0.0.0" | "" => "127.0.0.1",
        "::" | "[::]" => "::1",
        other => other,
    }
}

/// Formats `ws://host:port/`, bracketing a v6 literal the way Node does.
pub fn format_ws_address(host: &str, port: u16, target: &str) -> String {
    let host = advertised_host(host);
    let bracketed = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("ws://{bracketed}:{port}/{target}")
}

/// Accepts connections for the server's life.
fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if shared.is_stopping() {
                    return;
                }
                let Ok(stream) = upgrade(stream) else {
                    continue;
                };
                let connection = shared.next.fetch_add(1, Ordering::SeqCst);
                let (sender, receiver) = mpsc::channel();
                shared
                    .writers
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .insert(connection, sender);

                let write_stream = match stream.try_clone() {
                    Ok(clone) => clone,
                    Err(error) => {
                        tracing::warn!(%error, "cannot clone the inspector socket");
                        continue;
                    }
                };
                let writer = std::thread::Builder::new()
                    .name("inspector-writer".to_string())
                    .spawn(move || write_loop(write_stream, receiver));
                if writer.is_err() {
                    continue;
                }

                shared.attached.store(true, Ordering::SeqCst);
                let reader_shared = Arc::clone(&shared);
                let reader = std::thread::Builder::new()
                    .name("inspector-reader".to_string())
                    .spawn(move || read_loop(connection, stream, reader_shared));
                if reader.is_err() {
                    shared.attached.store(false, Ordering::SeqCst);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "the inspector listener stopped accepting");
                return;
            }
        }
    }
}

/// Reads the HTTP request, answers the upgrade, and returns the stream.
fn upgrade(mut stream: TcpStream) -> Result<TcpStream, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("cannot set the inspector read timeout: {error}"))?;

    let request = read_http_request(&mut stream)?;
    let Some(key) = header_value(&request, "sec-websocket-key") else {
        // A browser GET on the endpoint is what happens when someone pastes the URL
        // into an address bar. Answering is better than hanging; the JSON target
        // list DevTools needs is not implemented, and a 400 says so.
        let body = "Not a WebSocket request\n";
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        return Err("not a websocket upgrade".to_string());
    };

    let accept = websocket_accept(key.trim());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("cannot write the inspector upgrade: {error}"))?;
    stream
        .set_read_timeout(None)
        .map_err(|error| format!("cannot clear the inspector read timeout: {error}"))?;
    Ok(stream)
}

/// Reads one HTTP request head.
fn read_http_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                buffer.extend_from_slice(&chunk[..count]);
                if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if buffer.len() > 64 * 1024 {
                    return Err("the inspector request head is too large".to_string());
                }
            }
            Err(error) => return Err(format!("cannot read the inspector request: {error}")),
        }
    }
    String::from_utf8(buffer).map_err(|_| "the inspector request is not UTF-8".to_string())
}

/// One header value from a request head, matched case-insensitively.
fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value)
        } else {
            None
        }
    })
}

/// `Sec-WebSocket-Accept` for a client key, per RFC 6455.
///
/// The SHA-1 lives here rather than as a dependency: it is forty lines, this is its
/// only use, and pulling a crypto crate into the workspace for a handshake constant
/// would be a poor trade.
pub fn websocket_accept(client_key: &str) -> String {
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = String::with_capacity(client_key.len() + MAGIC.len());
    input.push_str(client_key);
    input.push_str(MAGIC);
    base64(&sha1(input.as_bytes()))
}

/// SHA-1, per FIPS 180-4.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    let mut message = input.to_vec();
    let bit_length = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for block in message.chunks_exact(64) {
        let mut words = [0_u32; 80];
        for (index, word) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0_u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Standard base64 with padding, which is what the handshake requires.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let first = u32::from(group[0]);
        let second = group.get(1).map_or(0, |byte| u32::from(*byte));
        let third = group.get(2).map_or(0, |byte| u32::from(*byte));
        let packed = (first << 16) | (second << 8) | third;
        out.push(char::from(ALPHABET[((packed >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((packed >> 12) & 0x3f) as usize]));
        out.push(if group.len() > 1 {
            char::from(ALPHABET[((packed >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            char::from(ALPHABET[(packed & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

/// Reads frames for one connection and queues them for dispatch.
fn read_loop(connection: usize, mut stream: TcpStream, shared: Arc<Shared>) {
    loop {
        match read_frame(&mut stream) {
            Ok(Some(Frame::Text(text))) => {
                shared
                    .incoming
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(Incoming {
                        connection,
                        message: text,
                    });
                // The isolate is asleep in `uv_run`; this asks it for one check
                // phase, which is where the queue is drained.
                request_drain();
            }
            // CDP over WebSocket is text. A binary frame is dropped rather than
            // guessed at, so a client using the CBOR form fails visibly.
            Ok(Some(Frame::Binary)) => {
                tracing::debug!("dropping a binary inspector frame");
            }
            Ok(Some(Frame::Close)) => {
                send_close(&mut stream);
                shared.attached.store(false, Ordering::SeqCst);
                return;
            }
            Ok(Some(Frame::Ping(payload))) => {
                if write_server_frame(&mut stream, 0xA, &payload).is_err() {
                    shared.attached.store(false, Ordering::SeqCst);
                    return;
                }
            }
            Ok(Some(Frame::Pong)) => {}
            Ok(None) => {
                shared.attached.store(false, Ordering::SeqCst);
                return;
            }
            Err(_) => {
                shared.attached.store(false, Ordering::SeqCst);
                return;
            }
        }
    }
}

/// Writes replies for one connection.
fn write_loop(mut stream: TcpStream, receiver: Receiver<String>) {
    while let Ok(text) = receiver.recv() {
        if write_server_frame(&mut stream, 0x1, text.as_bytes()).is_err() {
            return;
        }
    }
}

/// A decoded frame, without the payload of the kinds we discard.
#[derive(Debug)]
enum Frame {
    Text(String),
    Binary,
    Close,
    Ping(Vec<u8>),
    Pong,
}

/// Reads one WebSocket frame, or `None` at end of stream.
fn read_frame(stream: &mut TcpStream) -> std::io::Result<Option<Frame>> {
    let mut header = [0_u8; 2];
    if !read_exact_or_eof(stream, &mut header)? {
        return Ok(None);
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut length = u64::from(header[1] & 0x7f);
    if length == 126 {
        let mut extended = [0_u8; 2];
        stream.read_exact(&mut extended)?;
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        stream.read_exact(&mut extended)?;
        length = u64::from_be_bytes(extended);
    }
    // A CDP message is a few hundred bytes. A multi-gigabyte "message" is a client
    // bug or an attack, and allocating for it is how a debugger becomes a denial of
    // service.
    if length > 64 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "inspector frame is too large",
        ));
    }

    let mut mask = [0_u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload = vec![0_u8; length as usize];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    Ok(Some(match opcode {
        0x1 => Frame::Text(String::from_utf8_lossy(&payload).into_owned()),
        0x2 => Frame::Binary,
        0x8 => Frame::Close,
        0x9 => Frame::Ping(payload),
        0xA => Frame::Pong,
        // A continuation frame is legal only after a fragmented message, which no
        // CDP client sends; treating it as binary keeps it out of the dispatcher.
        _ => Frame::Binary,
    }))
}

/// Reads exactly `buffer.len()` bytes, reporting a clean end of stream.
fn read_exact_or_eof(stream: &mut TcpStream, buffer: &mut [u8]) -> std::io::Result<bool> {
    match stream.read_exact(buffer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// Answers a close frame with one of our own.
fn send_close(stream: &mut TcpStream) {
    let _ = write_server_frame(stream, 0x8, &[]);
}

/// Writes a server frame: unmasked, with the smallest length encoding.
fn write_server_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()
}

thread_local! {
    /// The isolate the sessions below belong to.
    ///
    /// A `V8InspectorSession` is only valid for the isolate its inspector was created
    /// against, and a disposed isolate's handles abort on access rather than failing.
    /// Comparing addresses is what lets a second isolate — a test's — start clean
    /// instead of dispatching into a dead one.
    static SESSION_ISOLATE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// The session for each attached connection.
    ///
    /// Created on the isolate thread, on the first message a connection sends, and
    /// kept here rather than in `Shared` because `V8InspectorSession` is not `Send`.
    /// A session is never removed: it is dropped with the process, which is what
    /// Node does too — see `agent`'s note on why the inspector has no teardown.
    static SESSIONS: std::cell::RefCell<HashMap<usize, &'static v8::inspector::V8InspectorSession>> =
        std::cell::RefCell::new(HashMap::new());
}

/// Dispatches every queued frontend message.
///
/// Called from the isolate thread: from the check-phase hook the reader threads
/// request, and once per loop turn. The session for a connection is created on its
/// first message, which is where the channel that writes the replies to that
/// connection's writer thread is built.
///
/// Returns how many messages were dispatched, which the tests assert on so a silent
/// no-op cannot pass.
pub fn drain(scope: &mut v8::PinScope<'_, '_>, shared: &Arc<Shared>) -> usize {
    // A session belongs to one isolate. If this is a different one — the CLI always
    // has exactly one, but a test creates one per case — the old sessions are dropped
    // rather than dispatched into an isolate that no longer exists.
    let raw: &v8::Isolate = scope.as_ref();
    // SAFETY: reading the address is not a dereference; it is only compared.
    let isolate =
        unsafe { std::mem::transmute::<v8::UnsafeRawIsolatePtr, usize>(raw.as_raw_isolate_ptr()) };
    let stale = SESSION_ISOLATE.with(|slot| {
        let previous = slot.get();
        if previous.is_none() {
            slot.set(Some(isolate));
            return false;
        }
        previous != Some(isolate)
    });
    if stale {
        SESSION_ISOLATE.with(|slot| slot.set(Some(isolate)));
        clear_sessions();
    }

    let incoming = shared.take_incoming();
    let count = incoming.len();
    for Incoming {
        connection,
        message,
    } in incoming
    {
        let ready = SESSIONS.with(|sessions| sessions.borrow().contains_key(&connection));
        if !ready {
            if !agent::ensure_inspector(scope) {
                continue;
            }
            let channel = v8::inspector::Channel::new(Box::new(FrontendChannel {
                connection,
                shared: Arc::clone(shared),
            }));
            let Some(session) = agent::connect(channel) else {
                continue;
            };
            SESSIONS.with(|sessions| sessions.borrow_mut().insert(connection, session));
        }
        SESSIONS.with(|sessions| {
            if let Some(session) = sessions.borrow().get(&connection) {
                let view = v8::inspector::StringView::from(message.as_bytes());
                session.dispatch_protocol_message(view);
            }
        });
    }
    count
}

/// Whether any frontend message is waiting.
pub fn has_pending(shared: &Arc<Shared>) -> bool {
    !shared
        .incoming
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .is_empty()
}

/// Asks the loop for one check phase so a queued message is dispatched.
///
/// This is `uv_async_send` in Node: `rn_core::native_immediates` owns the queue and
/// `rn-bind-timers` owns the handle, so the request goes through the same path an
/// `AsyncWrap` destroy does. Nothing happens before `set_wakeup` has been called,
/// which is the honest state before the loop exists.
pub fn request_drain() {
    rn_core::native_immediates::set_immediate(run_drain);
}

/// The native immediate that dispatches queued frontend messages.
fn run_drain(scope: &mut v8::PinScope<'_, '_>) {
    crate::drain_attached(scope);
}

/// Drops every connection's session, for a new isolate.
pub fn clear_sessions() {
    SESSIONS.with(|sessions| sessions.borrow_mut().clear());
}

/// Asks every attached frontend session to pause before its next statement.
pub fn pause_all_sessions(reason: &str) {
    SESSIONS.with(|sessions| {
        for session in sessions.borrow().values() {
            agent::schedule_pause_on_next_statement(session, reason);
        }
    });
}

/// The channel a frontend's session sends replies through.
struct FrontendChannel {
    connection: usize,
    shared: Arc<Shared>,
}

impl FrontendChannel {
    fn forward(&self, message: v8::UniquePtr<v8::inspector::StringBuffer>) -> Option<()> {
        let mut message = message;
        let text = message
            .as_mut()
            .map(|buffer| crate::session::string_view_to_string(&buffer.string()))?;
        self.shared.send_to(self.connection, text);
        Some(())
    }
}

impl v8::inspector::ChannelImpl for FrontendChannel {
    fn send_response(&self, _call_id: i32, message: v8::UniquePtr<v8::inspector::StringBuffer>) {
        self.forward(message);
    }

    fn send_notification(&self, message: v8::UniquePtr<v8::inspector::StringBuffer>) {
        self.forward(message);
    }

    fn flush_protocol_notifications(&self) {}
}
