//! The `--inspect` endpoint: a WebSocket client that speaks CDP over a socket.
//!
//! This is the test the other ones cannot substitute for. `protocol.rs` drives
//! `Connection` directly, which proves the session works; this one proves the thing
//! `node --inspect` promises — that a client on the network can connect, evaluate an
//! expression and read the value back.
//!
//! The client here is hand-written rather than a dependency: the handshake and the
//! frame format are the contract being tested, so using a library to speak them would
//! test the library. It is ~120 lines of `TcpStream`, which is cheaper than a new
//! dependency in a workspace that has none for WebSockets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use rn_bind_inspector::Server;

/// A minimal CDP-over-WebSocket client.
struct Client {
    stream: TcpStream,
}

impl Client {
    /// Connects to `ws://host:port/` and completes the upgrade.
    fn connect(host: &str, port: u16) -> Result<Self, String> {
        let mut stream = TcpStream::connect((host, port)).map_err(|error| {
            format!("cannot connect to the inspector at {host}:{port}: {error}")
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| format!("cannot set a read timeout: {error}"))?;

        // A fixed key is fine: the response is checked against the SHA-1 of it, which is
        // what the handshake is.
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("cannot write the upgrade request: {error}"))?;

        let mut response = Vec::new();
        let mut chunk = [0_u8; 512];
        loop {
            let count = stream
                .read(&mut chunk)
                .map_err(|error| format!("cannot read the upgrade response: {error}"))?;
            if count == 0 {
                return Err("the inspector closed the connection during the upgrade".to_string());
            }
            response.extend_from_slice(&chunk[..count]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&response);
        if !head.starts_with("HTTP/1.1 101") {
            return Err(format!(
                "the inspector did not upgrade the connection: {head}"
            ));
        }
        // The accept value must be the RFC 6455 answer for the key sent above, otherwise
        // a real browser would reject the connection.
        let expected = rn_bind_inspector::websocket_accept_value("dGhlIHNhbXBsZSBub25jZQ==");
        if !head.contains(&format!("Sec-WebSocket-Accept: {expected}")) {
            return Err(format!(
                "the inspector sent the wrong Sec-WebSocket-Accept; expected {expected}, response was {head}"
            ));
        }

        Ok(Self { stream })
    }

    /// Sends one masked text frame, as a client must.
    fn send(&mut self, text: &str) -> Result<(), String> {
        let payload = text.as_bytes();
        let mask = [0x12_u8, 0x34, 0x56, 0x78];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x81);
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream
            .write_all(&frame)
            .map_err(|error| format!("cannot send a frame: {error}"))
    }

    /// Reads one text frame.
    ///
    /// The reply to a CDP command is one frame, but a notification can arrive first
    /// (`Runtime.executionContextCreated` does), so the caller decides what it is looking
    /// for and this returns whatever came.
    fn read(&mut self) -> Result<String, String> {
        let mut header = [0_u8; 2];
        self.stream
            .read_exact(&mut header)
            .map_err(|error| format!("cannot read a frame header: {error}"))?;
        let mut length = u64::from(header[1] & 0x7f);
        if length == 126 {
            let mut extended = [0_u8; 2];
            self.stream
                .read_exact(&mut extended)
                .map_err(|error| format!("cannot read the frame length: {error}"))?;
            length = u64::from(u16::from_be_bytes(extended));
        } else if length == 127 {
            let mut extended = [0_u8; 8];
            self.stream
                .read_exact(&mut extended)
                .map_err(|error| format!("cannot read the frame length: {error}"))?;
            length = u64::from_be_bytes(extended);
        }
        let mut payload = vec![0_u8; length as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|error| format!("cannot read the frame payload: {error}"))?;
        Ok(String::from_utf8_lossy(&payload).into_owned())
    }
}

#[test]
fn the_server_reports_the_port_it_bound() {
    // `--inspect=0` asks the OS for a port, and the URL Node prints has to name the port
    // that was actually bound — a server that echoed the requested `0` would print
    // `ws://127.0.0.1:0/` and no client could connect.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    assert_ne!(server.port(), 0, "a bound port must be a real one");
    let url = server.ws_url();
    assert_eq!(
        url,
        format!("ws://127.0.0.1:{}/", server.port()),
        "the URL Node prints must name the bound port"
    );
}

#[test]
fn the_printed_url_brackets_an_ipv6_literal() {
    // `test/inspector/test-inspector.js` matches `ws://[...]:port/`, so the brackets are
    // part of the format rather than cosmetic.
    assert_eq!(
        rn_bind_inspector::format_ws_address("::1", 9229, ""),
        "ws://[::1]:9229/"
    );
    assert_eq!(
        rn_bind_inspector::format_ws_address("127.0.0.1", 9229, ""),
        "ws://127.0.0.1:9229/"
    );
    // `0.0.0.0` binds every interface but is not dialable, so the advertised address is
    // the loopback one.
    assert_eq!(
        rn_bind_inspector::format_ws_address("0.0.0.0", 9229, ""),
        "ws://127.0.0.1:9229/"
    );
}

#[test]
fn the_handshake_accept_value_matches_rfc_6455() {
    // The example from RFC 6455 section 1.3. If this is wrong, every real client refuses
    // the connection, and a hand-rolled test client that did not check it would pass
    // anyway.
    assert_eq!(
        rn_bind_inspector::websocket_accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

#[test]
fn sha1_matches_the_published_vectors() {
    // FIPS 180-4 examples. The handshake test above covers one input; these cover the
    // block-boundary cases a hand-written SHA-1 gets wrong.
    for (input, expected) in [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
    ] {
        let digest = rn_bind_inspector::sha1_digest(input.as_bytes());
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, expected, "sha1({input:?}) is wrong");
    }
}

#[test]
fn a_client_can_connect_and_evaluate_over_the_socket() {
    // The end-to-end claim: `node --inspect` prints a URL, a CDP client dials it, and
    // `Runtime.evaluate` comes back with the value.
    //
    // One isolate for both round trips, because that is what the claim is about: the
    // session has to survive between two drains, which is only meaningful when the
    // isolate does too.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    let port = server.port();
    let mut client = Client::connect("127.0.0.1", port).expect("the client must connect");

    with_context(|scope| {
        install_namespace(scope);
        client
            .send(r#"{"id":1,"method":"Runtime.enable"}"#)
            .expect("sending Runtime.enable");
        // The message is queued by the reader thread; V8 can only dispatch it from its
        // own thread, so the test plays the loop's part and asks for a check phase.
        let dispatched = drain_until(scope, &server, 1);
        assert_eq!(
            dispatched, 1,
            "the queued Runtime.enable must be dispatched on the isolate thread"
        );
        let reply = wait_for_reply(&mut client, 1);
        assert!(
            reply["result"].is_object(),
            "Runtime.enable must be acknowledged; reply was {reply}"
        );

        client
            .send(
                r#"{"id":2,"method":"Runtime.evaluate","params":{"expression":"21 * 2","returnByValue":true}}"#,
            )
            .expect("sending Runtime.evaluate");
        drain_until(scope, &server, 1);
        let reply = wait_for_reply(&mut client, 2);
        assert_eq!(
            reply["result"]["result"]["value"],
            serde_json::json!(42),
            "a CDP client must get the value of `21 * 2` back over the socket; reply was {reply}"
        );
    });
}

/// Reads replies until `id` arrives, skipping notifications.
fn wait_for_reply(client: &mut Client, id: i64) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let text = client.read().expect("reading a frame");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        if parsed["id"] == serde_json::json!(id) {
            return parsed;
        }
    }
    panic!("no reply with id {id} arrived");
}

/// Dispatches until `expected` messages have been handled.
fn drain_until(
    scope: &mut rn_v8_sys::v8::PinScope<'_, '_>,
    server: &Server,
    expected: usize,
) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut total = 0;
    while total < expected && Instant::now() < deadline {
        total += rn_bind_inspector::drain_for_test(scope, server.shared());
        if total < expected {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    total
}

/// Installs the inspector namespace and records the isolate.
fn install_namespace(scope: &mut rn_v8_sys::v8::PinScope<'_, '_>) {
    use rn_core::BindingModule;
    let object = rn_bind_inspector::Inspector
        .install(
            scope,
            &mut rn_core::InstallCtx {
                async_ids: &mut rn_core::AsyncIds::new(),
            },
        )
        .expect("installing the inspector namespace");
    let global = scope.get_current_context().global(scope);
    let key = rn_v8_sys::v8::String::new(scope, "__inspector").expect("allocating the key");
    global.set(scope, key.into(), object.into());
}

/// Runs `body` with a live isolate, scope and context.
fn with_context<T>(body: impl FnOnce(&mut rn_v8_sys::v8::PinScope<'_, '_>) -> T) -> T {
    use rn_v8_sys::v8;
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    rn_bind_inspector::set_isolate(&mut isolate);
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let scope = std::pin::pin!(v8::ContextScope::new(&mut scope, context));
    let mut scope = scope;
    body(&mut scope)
}

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rn_v8_sys::v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
        let platform = rn_v8_sys::v8::new_default_platform(0, false).make_shared();
        rn_v8_sys::v8::V8::initialize_platform(platform);
        rn_v8_sys::v8::V8::initialize();
    });
}
