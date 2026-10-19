"""Reproducible, harmless HTTP fixture. Explicitly run with python -m pasopati.lab."""

import argparse
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import urlsplit


class LabHandler(BaseHTTPRequestHandler):
    server_version = "PASOPATI-Lab"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        pass  # Do not log potentially sensitive query strings.

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in {"/redirect", "/outside"}:
            self.send_response(302)
            port = cast(ThreadingHTTPServer, self.server).server_port
            self.send_header(
                "Location", "/" if path == "/redirect" else f"http://outside.invalid:{port}/"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status = 404 if path not in {"/", "/large", "/sensitive"} else 200
        body = {
            "/": b"<!doctype html><title>PASOPATI local lab</title><h1>Loopback fixture</h1>",
            "/large": b"x" * 65537,
            "/sensitive": b"<title>token=LAB_SECRET_DO_NOT_PERSIST</title>",
        }.get(path, b"Not found")
        self.send_response(status)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8" if path != "/large" else "application/octet-stream",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Set-Cookie", "lab-secret=DO_NOT_PERSIST")
        self.end_headers()
        with suppress(OSError):  # The bounded client may close after its sample.
            self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local-only PASOPATI HTTP recon fixture.")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    with ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler) as server:
        print(f"PASOPATI lab: http://127.0.0.1:{server.server_port}/ (Ctrl+C to stop)", flush=True)
        with suppress(KeyboardInterrupt):
            server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
