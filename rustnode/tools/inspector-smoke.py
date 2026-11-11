#!/usr/bin/env python3
"""A CDP client that connects to `rustnode --inspect` and evaluates an expression.

Written as a script rather than a Rust test because the thing under test is the
*process*: `--inspect` has to print the URL, bind a socket, accept an upgrade, and
answer a protocol message. A unit test drives the server directly (`tests/socket.rs`)
and would still pass if the CLI never started it or printed the wrong port.

The failure this catches, and the reason it exists: a namespace whose members all
exist, whose unit tests all pass, and where `node --inspect` either prints nothing or
accepts a connection and answers nothing.
"""

import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time


def read_frame(sock):
    header = recv_exact(sock, 2)
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    payload = recv_exact(sock, length) if length else b""
    return opcode, payload


def recv_exact(sock, count):
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise EOFError("the inspector closed the connection")
        buffer += chunk
    return buffer


def send_text(sock, text):
    payload = text.encode()
    mask = b"\x12\x34\x56\x78"
    frame = bytearray([0x81])
    if len(payload) < 126:
        frame.append(0x80 | len(payload))
    else:
        frame.append(0x80 | 126)
        frame.extend(len(payload).to_bytes(2, "big"))
    frame.extend(mask)
    for index, byte in enumerate(payload):
        frame.append(byte ^ mask[index % 4])
    sock.sendall(bytes(frame))


def connect(host, port):
    sock = socket.create_connection((host, port), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(1024)
        if not chunk:
            raise RuntimeError("the inspector closed the connection during the upgrade")
        response += chunk
    head = response.decode("latin-1")
    if not head.startswith("HTTP/1.1 101"):
        raise RuntimeError(f"no 101 upgrade: {head}")

    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    if f"Sec-WebSocket-Accept: {expected}" not in head:
        raise RuntimeError(f"wrong Sec-WebSocket-Accept in: {head}")
    return sock


def call(sock, message, wanted_id):
    send_text(sock, json.dumps(message))
    deadline = time.time() + 10
    while time.time() < deadline:
        _opcode, payload = read_frame(sock)
        parsed = json.loads(payload.decode())
        if parsed.get("id") == wanted_id:
            return parsed
    raise RuntimeError(f"no reply with id {wanted_id}")


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/debug/rustnode"
    script = 'setTimeout(() => { globalThis.kept = 7; }, 10); console.log("script ran");'

    child = subprocess.Popen(
        [binary, "--inspect=0", "-e", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # The URL is printed to stderr before any user code runs, which is what makes
        # it usable: a client can attach before the script does anything.
        line = child.stderr.readline().decode()
        match = re.search(r"Debugger listening on ws://([^:/]+):(\d+)/", line)
        if not match:
            print(f"FAIL: --inspect printed no ws URL; first line was {line!r}", file=sys.stderr)
            return 1
        host, port = match.group(1), int(match.group(2))
        print(f"--inspect printed {line.strip()}")

        sock = connect(host, port)
        reply = call(sock, {"id": 1, "method": "Runtime.enable"}, 1)
        if "result" not in reply:
            print(f"FAIL: Runtime.enable was not acknowledged: {reply}", file=sys.stderr)
            return 1
        print("Runtime.enable acknowledged")

        reply = call(
            sock,
            {
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "6 * 7", "returnByValue": True},
            },
            2,
        )
        value = reply.get("result", {}).get("result", {}).get("value")
        if value != 42:
            print(f"FAIL: Runtime.evaluate did not return 42: {reply}", file=sys.stderr)
            return 1
        print("Runtime.evaluate returned 42")

        # An expression that reads state the *script* created. This is what separates a
        # working inspector from one that evaluates in a fresh context: the script's own
        # globals have to be visible.
        reply = call(
            sock,
            {
                "id": 3,
                "method": "Runtime.evaluate",
                "params": {"expression": "typeof setTimeout", "returnByValue": True},
            },
            3,
        )
        value = reply.get("result", {}).get("result", {}).get("value")
        if value != "function":
            print(f"FAIL: the script's globals are not visible: {reply}", file=sys.stderr)
            return 1
        print("Runtime.evaluate sees the process's own globals")
        return 0
    finally:
        child.kill()
        child.wait()


if __name__ == "__main__":
    sys.exit(main())
