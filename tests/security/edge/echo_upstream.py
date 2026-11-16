#!/usr/bin/env python3
"""Fake tenant upstream for the edge conformance test (P1-T10a, §14.6).

Listens on 8080 (control/API port of Headscale) and 9090 (metrics port) inside the network namespace of a holder
container that carries the alias hs-<slug> on a tenant network, answers every request with 200 and a JSON marker,
and appends one JSON line per request (port, method, raw path, headers) to the log file. The conformance test reads
the log to prove which requests reached "Headscale" and which headers were stripped by the edge.

    nsenter -t <holder pid> -n python3 -I echo_upstream.py <log.jsonl>

Standard library only. Values of headers are logged as received — only test tokens are ever sent to it.
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = {"mg-echo": True}
LOCK = threading.Lock()


def make_handler(port: int, log_path: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(min(length, 1 << 20))
            rec = {"port": port, "method": self.command, "path": self.path,
                   "headers": {k: v for k, v in self.headers.items()}}
            with LOCK, open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            body = json.dumps(MARKER).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

        def log_message(self, *args) -> None:  # quiet
            pass

    return Handler


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    servers = [ThreadingHTTPServer(("0.0.0.0", port), make_handler(port, sys.argv[1])) for port in (8080, 9090)]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    servers[0].serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
