#!/usr/bin/env python3
"""A throwaway npm registry, just enough of the protocol to install two packages.

The npm packages that ship rustnode depend on each other *by name and version*,
and the interesting question — does npm pick the right platform package on this
host — only exists when the name resolves through registry metadata. Installing a
tarball by path skips that entirely: it installs whatever you pointed at, on any
host, which is precisely the behaviour the `os`/`cpu` fields are supposed to
prevent.

So the test needs a registry that serves real metadata for locally built
tarballs. This serves:

    GET /<name>            packument, one version, dist.tarball -> this server
    GET /<name>/-/<file>   the tarball bytes

`name` may be scoped and URL-encoded (`@scope%2fname`), which is what npm sends.

It binds 127.0.0.1 and a caller-chosen port, serves only the package directories
it was given, and refuses anything else. It is a test fixture, not a registry:
there is no auth, no search, and no write path.
"""

from __future__ import annotations

import argparse
import http.server
import json
import pathlib
import socketserver
import sys
import threading
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    # Injected by serve() before the server starts handling requests.
    packages: dict[str, dict] = {}

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - base class name
        # Quiet by default: the test prints its own lines, and npm's chatter
        # about each request would bury them.
        if self.server.verbose:  # type: ignore[attr-defined]
            sys.stderr.write("registry: " + fmt % args + "\n")

    def do_GET(self) -> None:  # noqa: N802 - base class name
        raw = urllib.parse.urlparse(self.path).path.lstrip("/")
        path = urllib.parse.unquote(raw)
        if not path:
            self.send_error(404, "not a package path")
            return

        # A tarball: /<name>/-/<filename>
        if "/-/" in path:
            name, filename = path.split("/-/", 1)
            record = self.packages.get(name)
            if record is None or record["filename"] != filename:
                self.send_error(404, f"no tarball {filename} for {name}")
                return
            data = pathlib.Path(record["tarball"]).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        record = self.packages.get(path)
        if record is None:
            self.send_error(404, f"no package named {path}")
            return
        manifest = record["manifest"]
        payload = {
            "name": manifest["name"],
            "dist-tags": {"latest": manifest["version"]},
            "versions": {
                manifest["version"]: {
                    **manifest,
                    "dist": {
                        "tarball": f"{self.server.base_url}/{path}/-/{record['filename']}",
                        "shasum": record["shasum"],
                        "integrity": record["integrity"],
                    },
                }
            },
        }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, verbose: bool = False):
        super().__init__(address, Handler)
        self.verbose = verbose
        host, port = self.server_address[:2]
        self.base_url = f"http://{host}:{port}"


def serve(packages: dict[str, dict], port: int = 0, verbose: bool = False) -> tuple[Server, threading.Thread]:
    """Start the registry on `port` (0 = pick one) and return it with its thread."""
    Handler.packages = packages
    server = Server(("127.0.0.1", port), verbose=verbose)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4873)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        metavar="NAME=TARBALL",
        help="package name and tarball path; repeatable",
    )
    args = parser.parse_args(argv)
    if not args.package:
        parser.error("at least one --package is required")

    packages: dict[str, dict] = {}
    import hashlib
    import tarfile
    import base64

    for spec in args.package:
        name, _, tarball = spec.partition("=")
        path = pathlib.Path(tarball)
        with tarfile.open(path, "r:gz") as archive:
            manifest = json.loads(archive.extractfile("package/package.json").read())
        data = path.read_bytes()
        packages[name] = {
            "manifest": manifest,
            "tarball": str(path),
            "filename": path.name,
            "shasum": hashlib.sha1(data).hexdigest(),
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
        }
    server, _ = serve(packages, port=args.port, verbose=args.verbose)
    print(server.base_url, flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
