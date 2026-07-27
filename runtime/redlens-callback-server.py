#!/usr/bin/env python3
"""Callback server: recebe conexoes HTTP/DNS de alvos para validar SSRF/XXE/etc.

Roda em localhost dentro do Kali container.
- /redlens-cb/<token> -> registra hit, retorna 200
- /redlens-token/<token>.gif -> retorna 1x1 pixel transparente
- Suporta DNS callback via nameserver configurado

Uso:
  redlens_callback start --port 8080 --token <uuid>
  redlens_callback stop
  redlens_callback status --token <uuid>
  redlens_callback wait --token <uuid> --timeout 30
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

STATE_DIR = Path("/tmp/redlens-callback")
STATE_DIR.mkdir(parents=True, exist_ok=True)
HITS_FILE = STATE_DIR / "hits.jsonl"
ACTIVE_FILE = STATE_DIR / "active.json"


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        token = None
        for prefix in ("/redlens-cb/", "/redlens-token/", "/cb/"):
            if path.startswith(prefix):
                token = path[len(prefix):].split(".")[0].split("/")[0].split("?")[0]
                break
        record = {
            "at": time.time(),
            "method": "GET",
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "client": self.client_address[0],
            "token": token,
        }
        with HITS_FILE.open("a") as f:
            f.write(json.dumps(record) + "\n")

        if path.endswith(".gif"):
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            pixel = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
            self.send_header("Content-Length", str(len(pixel)))
            self.end_headers()
            self.wfile.write(pixel)
        else:
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        record = {
            "at": time.time(),
            "method": "POST",
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", errors="ignore")[:1024],
            "client": self.client_address[0],
        }
        with HITS_FILE.open("a") as f:
            f.write(json.dumps(record) + "\n")
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def write_active(port: int, pid: int) -> None:
    ACTIVE_FILE.write_text(json.dumps({"port": port, "pid": pid, "started_at": time.time()}))


def read_active() -> dict | None:
    if not ACTIVE_FILE.is_file():
        return None
    try:
        return json.loads(ACTIVE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def cmd_start(args) -> int:
    if read_active():
        print(json.dumps({"ok": False, "error": "callback ja esta rodando"}))
        return 2
    pid = os.getpid()
    server = ThreadingHTTPServer(("0.0.0.0", args.port), CallbackHandler)
    write_active(args.port, pid)
    print(json.dumps({"ok": True, "port": args.port, "pid": pid, "started_at": time.time(), "ip": get_local_ip()}), flush=True)
    server.serve_forever()
    return 0


def cmd_stop(args) -> int:
    active = read_active()
    if not active:
        print(json.dumps({"ok": False, "error": "nao esta rodando"}))
        return 2
    pid = active.get("pid")
    if pid:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    ACTIVE_FILE.unlink(missing_ok=True)
    print(json.dumps({"ok": True, "killed": pid}))
    return 0


def cmd_status(args) -> int:
    active = read_active()
    if not active:
        print(json.dumps({"ok": True, "running": False}))
        return 0
    print(json.dumps({"ok": True, "running": True, **active}))
    return 0


def cmd_hits(args) -> int:
    if not HITS_FILE.is_file():
        print(json.dumps({"ok": True, "hits": []}))
        return 0
    hits = []
    with HITS_FILE.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
                if args.token and hit.get("token") != args.token:
                    continue
                hits.append(hit)
            except json.JSONDecodeError:
                continue
    print(json.dumps({"ok": True, "count": len(hits), "hits": hits}, ensure_ascii=False, indent=2))
    return 0


def cmd_wait(args) -> int:
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if HITS_FILE.is_file():
            with HITS_FILE.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        hit = json.loads(line)
                        if hit.get("token") == args.token:
                            print(json.dumps({"ok": True, "hit": hit}, ensure_ascii=False, indent=2))
                            return 0
                    except json.JSONDecodeError:
                        continue
        time.sleep(0.5)
    print(json.dumps({"ok": False, "error": "timeout", "token": args.token}))
    return 2


def cmd_reset(args) -> int:
    HITS_FILE.unlink(missing_ok=True)
    print(json.dumps({"ok": True}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="redlens-callback")
    sub = parser.add_subparsers(dest="action", required=True)

    start = sub.add_parser("start")
    start.add_argument("--port", type=int, default=8080)

    sub.add_parser("stop")
    sub.add_parser("status")
    sub.add_parser("reset")

    hits = sub.add_parser("hits")
    hits.add_argument("--token")

    wait = sub.add_parser("wait")
    wait.add_argument("--token", required=True)
    wait.add_argument("--timeout", type=int, default=30)

    args = parser.parse_args()
    if args.action == "start":
        return cmd_start(args)
    if args.action == "stop":
        return cmd_stop(args)
    if args.action == "status":
        return cmd_status(args)
    if args.action == "hits":
        return cmd_hits(args)
    if args.action == "wait":
        return cmd_wait(args)
    if args.action == "reset":
        return cmd_reset(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())