//! The `/json` discovery routes, over a real socket.
//!
//! Node's inspector serves a small HTTP document set beside the WebSocket:
//! `/json` and `/json/list` describe the target, `/json/version` names the
//! runtime, and everything else that is not an upgrade gets the handshake-failure
//! body. `test/parallel/test-inspector.js` asserts all four, and
//! `test/common/inspector-helper.js`'s `httpGet` is how the rest of the suite
//! reads them.
//!
//! These tests are over a socket rather than over the formatting functions for
//! the same reason `socket.rs` is: the defect this file exists for is that the
//! routes were absent, and a test that called `target_list_json` directly would
//! have passed while `GET /json` answered 400.
//!
//! The expected bytes are copied from the pinned oracle, which formats them with
//! `MapToString`/`MapsToString` (`src/inspector_socket_server.cc:57-81`) — not
//! from a Rust formatter that happens to produce equivalent JSON.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rn_bind_inspector::{Server, Target};

/// Sends one request and returns the whole response, head and body.
///
/// `HTTP/1.1` with `Connection: close` so the server closes after answering and
/// one `read_to_end` is the entire document; the inspector answers `HTTP/1.0`,
/// where a close-delimited body is legal.
fn request(server: &Server, raw: &str) -> String {
    let mut stream =
        TcpStream::connect(("127.0.0.1", server.port())).expect("the inspector must be listening");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout");
    stream
        .write_all(raw.as_bytes())
        .expect("the request must be written");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("the response must be readable");
    response
}

/// The body of a response, after the blank line that ends the head.
fn body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default()
}

/// The status line of a response.
fn status(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

#[test]
fn json_and_json_list_describe_the_target() {
    // `test-inspector.js::checkListResponse` reads both paths and asserts the
    // same three things: one entry, a `devtoolsFrontendUrl`, and a
    // `webSocketDebuggerUrl` matching `/ws:\/\/localhost:\d+\/[0-9A-Fa-f]{8}-/`.
    let server =
        Server::start_for_target("127.0.0.1", 0, Target::new("/tmp/inspector-http-test.js"))
            .expect("the server must bind");

    for path in ["/json", "/json/list"] {
        let response = request(
            &server,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                server.port()
            ),
        );
        assert_eq!(
            status(&response),
            "HTTP/1.0 200 OK",
            "{path} must be served, response was {response}"
        );
        assert!(
            response.contains("Content-Type: application/json; charset=UTF-8"),
            "{path} must be JSON, response was {response}"
        );
        let body = body(&response);
        // The document is one target, and the fields the suite reads are present.
        assert!(body.starts_with("[ {\n"), "{path} body was {body}");
        assert!(body.contains("\"description\": \"node.js instance\""));
        assert!(body.contains("\"type\": \"node\""));
        assert!(
            body.contains(&format!(
                "\"webSocketDebuggerUrl\": \"ws://localhost:{}/{}\"",
                server.port(),
                server
                    .ws_url()
                    .rsplit('/')
                    .next()
                    .expect("the ws url has a target id")
            )),
            "{path} must publish the address a client upgrades at, body was {body}"
        );
        // `url` is built from the resolved path, which is what `ScriptPath` does.
        assert!(
            body.contains("\"url\": \"file://"),
            "{path} body was {body}"
        );
    }
}

#[test]
fn json_version_names_the_runtime() {
    // `checkVersion` compares the parsed document against
    // `{Browser: `node.js/${process.version}`, 'Protocol-Version': '1.1'}` after
    // `JSON.stringify`, so the key set is the contract.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    let response = request(
        &server,
        "GET /json/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), "HTTP/1.0 200 OK");
    assert_eq!(
        body(&response),
        "{\n  \"Browser\": \"node.js/28.0.0\",\n  \"Protocol-Version\": \"1.1\"\n} ",
        "the version document is `MapToString`'s exact output"
    );
    // It has to be parseable JSON, which the trailing space does not prevent.
    let parsed = serde_json::from_str::<serde_json::Value>(body(&response))
        .expect("the version document must be JSON");
    assert_eq!(parsed["Protocol-Version"], "1.1");
}

#[test]
fn the_list_echoes_the_host_header() {
    // `test-inspector-reported-host.js` sends a made-up `Host` and asserts it
    // comes back inside `webSocketDebuggerUrl`. That is how a proxy that
    // terminates TLS makes the reported address reachable.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    let response = request(
        &server,
        "GET /json HTTP/1.1\r\nHost: 111.111.111.111:11111\r\nConnection: close\r\n\r\n",
    );
    let body = body(&response);
    assert!(
        body.contains("\"webSocketDebuggerUrl\": \"ws://111.111.111.111:11111/"),
        "the reported host must be the request's, body was {body}"
    );
    // Both frontend URLs embed the same address, per `FormatAddress(host, id, false)`.
    assert!(
        body.contains("ws=111.111.111.111:11111/"),
        "the frontend URL must use the reported host, body was {body}"
    );
}

#[test]
fn an_unknown_path_is_the_handshake_failure_body() {
    // `test-inspector.js` is explicit about this: `/json/activate`,
    // `/json/activate/boom` and `/json/badpath` all have to fail with a body
    // containing `WebSockets request was expected`, and the client's
    // `JSON.parse` has to throw on it. A 404 with an empty body would satisfy
    // "not found" and fail the test.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    for path in [
        "/json/activate",
        "/json/activate/boom",
        "/json/badpath",
        "/json/nope",
        "/",
    ] {
        let response = request(
            &server,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        );
        assert_eq!(
            status(&response),
            "HTTP/1.0 400 Bad Request",
            "{path} must be refused, response was {response}"
        );
        assert_eq!(
            body(&response),
            "WebSockets request was expected\r\n",
            "{path} must carry Node's body"
        );
        assert!(
            response.contains("Content-Type: text/html; charset=UTF-8"),
            "{path} must be the handshake failure, response was {response}"
        );
    }
}

#[test]
fn only_get_reaches_the_routes() {
    // Node's `HttpHandler::OnData` refuses anything that is not a `GET` before
    // it reaches a route (`src/inspector_socket.cc:556`), so a `POST /json` is
    // the handshake failure rather than the target list.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    let response = request(
        &server,
        "POST /json/list HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), "HTTP/1.0 400 Bad Request");
    assert_eq!(body(&response), "WebSockets request was expected\r\n");
}

#[test]
fn an_upgrade_at_the_published_path_completes() {
    // The end-to-end contract: a client reads `/json`, takes the path from
    // `webSocketDebuggerUrl`, and upgrades there. The upgrade used to be
    // accepted at any path, so this is the case that proves the two halves agree.
    let server = Server::start("127.0.0.1", 0).expect("the server must bind");
    let path = format!(
        "/{}",
        server
            .ws_url()
            .rsplit('/')
            .next()
            .expect("the ws url has a target id")
    );

    let mut stream = TcpStream::connect(("127.0.0.1", server.port())).expect("a connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout");
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                server.port()
            )
            .as_bytes(),
        )
        .expect("the upgrade must be written");

    let mut head = Vec::new();
    let mut chunk = [0_u8; 256];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream
            .read(&mut chunk)
            .expect("the response must be readable");
        assert_ne!(count, 0, "the connection closed during the upgrade");
        head.extend_from_slice(&chunk[..count]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "the published path must upgrade, response was {head}"
    );
    let expected = rn_bind_inspector::websocket_accept_value("dGhlIHNhbXBsZSBub25jZQ==");
    assert!(
        head.contains(&format!("Sec-WebSocket-Accept: {expected}")),
        "the accept value must be RFC 6455's, response was {head}"
    );
}

#[test]
fn the_target_list_json_is_published_for_other_callers() {
    // The formatter is public so a caller that already has the two facts — the
    // CLI printing diagnostics, or a test — does not reimplement Node's byte
    // layout. Pinned against the oracle's output for the same inputs.
    let target = Target::new("");
    let document = rn_bind_inspector::target_list_json(&target, "127.0.0.1:9229");
    assert!(document.starts_with("[ {\n  \"description\": \"node.js instance\",\n"));
    assert!(document.ends_with("\n} ]\n\n"));
    // An interactive session has no entry point, so Node reports the process
    // name and `url` is the empty-path `file://`.
    assert!(document.contains("\"title\": \""));
    assert!(document.contains("\"url\": \"file://\","));
    let parsed =
        serde_json::from_str::<serde_json::Value>(&document).expect("the target list must be JSON");
    assert_eq!(parsed[0]["id"], target.id);
    assert_eq!(parsed[0]["type"], "node");
}
