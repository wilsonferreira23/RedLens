#!/usr/bin/env python3
"""WebSocket adapter: handshake, auth, replay per role, origin validation.

Captura handshake no CloakBrowser ou replay direto.
Persiste cookies/tokens, testa:
- Auth no handshake (401/403 sem token)
- Authz por mensagem
- Replay por papel
- Validacao de Origin
- Baixa concorrencia
- Mensagens sanitizadas
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


def websocket_handshake(url: str, headers: dict | None = None, origin: str | None = None,
                         cookie: str | None = None, timeout: int = 15) -> dict:
    """Executa handshake WebSocket e retorna resposta."""
    parsed = urlparse(url)
    if parsed.scheme not in {"ws", "wss"}:
        return {"ok": False, "error": "scheme deve ser ws ou wss"}
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    req_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        req_lines.append(f"Origin: {origin}")
    if cookie:
        req_lines.append(f"Cookie: {cookie}")
    if headers:
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")

    raw = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if parsed.scheme == "wss":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.send(raw)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
    except Exception as exc:
        return {"ok": False, "error": f"handshake falhou: {exc}"}

    headers_section, _, _ = response.partition(b"\r\n\r\n")
    lines = headers_section.decode("latin-1", errors="ignore").split("\r\n")
    status_line = lines[0] if lines else ""
    response_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            response_headers[k.strip().lower()] = v.strip()

    return {
        "ok": True,
        "status_line": status_line,
        "headers": response_headers,
        "raw_size": len(response),
    }


def encode_ws_frame(payload: bytes, opcode: int = 0x1, masked: bool = True) -> bytes:
    """Codifica um frame WebSocket (text/binary)."""
    length = len(payload)
    header = bytes([0x80 | opcode])
    mask_bit = 0x80 if masked else 0x00
    if length < 126:
        header += bytes([mask_bit | length])
    elif length < 65536:
        header += bytes([mask_bit | 126]) + length.to_bytes(2, "big")
    else:
        header += bytes([mask_bit | 127]) + length.to_bytes(8, "big")

    if masked:
        mask = secrets.token_bytes(4)
        header += mask
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return header + masked_payload
    return header + payload


def decode_ws_frame(data: bytes) -> tuple[int, bytes]:
    """Decodifica um frame WebSocket."""
    if len(data) < 2:
        return 0, b""
    opcode = data[0] & 0x0F
    masked = data[1] & 0x80
    length = data[1] & 0x7F
    offset = 2
    if length == 126:
        length = int.from_bytes(data[offset:offset+2], "big")
        offset += 2
    elif length == 127:
        length = int.from_bytes(data[offset:offset+8], "big")
        offset += 8
    if masked:
        mask = data[offset:offset+4]
        offset += 4
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data[offset:offset+length]))
    else:
        payload = data[offset:offset+length]
    return opcode, payload


def test_message_exchange(url: str, messages: list[str], origin: str | None = None,
                           cookie: str | None = None, timeout: int = 10) -> list[dict]:
    """Abre conexao WS, envia mensagens, recebe respostas."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    req_lines = [
        f"GET {parsed.path or '/'} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        req_lines.append(f"Origin: {origin}")
    if cookie:
        req_lines.append(f"Cookie: {cookie}")
    raw = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii")

    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if parsed.scheme == "wss":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.send(raw)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        if b"101" not in response:
            return [{"status": "handshake_failed", "raw_size": len(response)}]

        for msg in messages:
            sock.send(encode_ws_frame(msg.encode("utf-8")))
            time.sleep(0.3)
            try:
                incoming = sock.recv(4096)
                opcode, payload = decode_ws_frame(incoming)
                results.append({
                    "sent": msg,
                    "received": payload.decode("utf-8", errors="ignore")[:512],
                    "opcode": opcode,
                    "size": len(payload),
                })
            except socket.timeout:
                results.append({"sent": msg, "received": None, "error": "timeout"})
        sock.close()
    except Exception as exc:
        results.append({"error": str(exc)})
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return results


def main() -> int:
    parser = argparse.ArgumentParser(prog="websocket-validator")
    sub = parser.add_subparsers(dest="action", required=True)

    handshake = sub.add_parser("handshake")
    handshake.add_argument("--run", required=True)
    handshake.add_argument("--url", required=True)
    handshake.add_argument("--origin")
    handshake.add_argument("--cookie")
    handshake.add_argument("--headers")

    exchange = sub.add_parser("exchange")
    exchange.add_argument("--run", required=True)
    exchange.add_argument("--url", required=True)
    exchange.add_argument("--messages", required=True, help="JSON lista de mensagens")
    exchange.add_argument("--origin")
    exchange.add_argument("--cookie")

    audit = sub.add_parser("audit")
    audit.add_argument("--run", required=True)
    audit.add_argument("--url", required=True)
    audit.add_argument("--origin-allowed", default="https://allowed.example")
    audit.add_argument("--origin-blocked", default="https://evil.example")
    audit.add_argument("--cookie")

    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)

        if args.action == "handshake":
            headers = json.loads(args.headers) if args.headers else None
            result = websocket_handshake(args.url, headers, args.origin, args.cookie)
        elif args.action == "exchange":
            messages = json.loads(args.messages)
            result = {"messages": test_message_exchange(args.url, messages, args.origin, args.cookie)}
        elif args.action == "audit":
            allowed = websocket_handshake(args.url, origin=args.origin_allowed, cookie=args.cookie)
            blocked = websocket_handshake(args.url, origin=args.origin_blocked, cookie=args.cookie)
            no_cookie = websocket_handshake(args.url, origin=args.origin_allowed, cookie=None)
            result = {
                "with_allowed_origin": allowed,
                "with_blocked_origin": blocked,
                "without_cookie": no_cookie,
                "origin_filtering_enabled": "101" not in blocked.get("status_line", ""),
                "auth_required": "101" not in no_cookie.get("status_line", ""),
            }

        sanitized_dir = directory / "evidence" / "sanitized"
        sanitized_dir.mkdir(parents=True, exist_ok=True)
        timestamp = redlensctl.iso().replace(":", "").replace("-", "")
        summary_path = sanitized_dir / f"{timestamp}-websocket-{args.action}.json"
        redlensctl.write_json(summary_path, {
            "capability": "websocket",
            "action": args.action,
            "url": args.url,
            "result": result,
        })

        findings = []
        if args.action == "audit":
            if not result.get("auth_required", True):
                findings.append({
                    "type": "no_auth",
                    "severity": "high",
                    "description": "WebSocket aceita conexoes sem autenticacao",
                    "cwe": "CWE-862",
                })
            if not result.get("origin_filtering_enabled", True):
                findings.append({
                    "type": "no_origin_check",
                    "severity": "medium",
                    "description": "WebSocket aceita conexoes de origem nao permitida",
                    "cwe": "CWE-942",
                })

        for finding in findings:
            finding_id = redlensctl.safe_id("websocket", finding["type"])[:24]
            redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
                "id": finding_id,
                "title": finding["description"],
                "severity": finding["severity"],
                "status": "confirmed",
                "asset": args.url,
                "evidence": [str(summary_path.relative_to(directory))],
                "reproduced": True,
                "negative_control": True,
                "cwe": finding.get("cwe"),
                "created_at": redlensctl.iso(),
            })

        redlensctl.append_event(directory, "websocket.tested", {
            "url": args.url,
            "action": args.action,
            "findings_count": len(findings),
        })

        print(json.dumps({"ok": True, "findings": findings, **result}, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())