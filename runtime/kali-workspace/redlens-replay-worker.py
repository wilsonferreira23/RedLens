#!/usr/bin/env python3
"""Replay a scoped HTTP request inside Kali using a private role session."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ALLOWED_METHODS = SAFE_METHODS | MUTATING_METHODS
MAX_BODY_BYTES = 5 * 1024 * 1024
SENSITIVE_HEADER_PREFIXES = ("cookie", "authorization", "x-api-key", "token")


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in SENSITIVE_HEADER_PREFIXES or lower.startswith("x-") and "key" in lower:
            result[key] = "<redacted>"
        else:
            result[key] = value
    return result


def load_cookies(session_path: Path, target_url: str) -> list[dict]:
    if not session_path.is_file():
        return []
    data = json.loads(session_path.read_text(encoding="utf-8"))
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    cookies: list[dict] = []
    for cookie in data.get("cookies", []):
        domain = cookie.get("domain", "")
        if domain.startswith("."):
            domain = domain[1:]
        if host != domain and not host.endswith("." + domain):
            continue
        cookie_path = cookie.get("path", "/")
        if not path.startswith(cookie_path):
            continue
        cookies.append(cookie)
    return cookies


def cookie_header(cookies: list[dict]) -> str:
    return "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in cookies)


def allowed(url: str, config: dict) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme not in config["allowed_schemes"]:
        return False
    if port not in config["allowed_ports"]:
        return False
    for entry in config["allowed_domains"]:
        if entry.startswith("*.") and host.endswith("." + entry[2:]):
            return True
        if host == entry:
            return True
    return False


def replay(config: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    private_dir = output / "private"
    sanitized_dir = output / "sanitized"
    private_dir.mkdir(parents=True, exist_ok=True)
    sanitized_dir.mkdir(parents=True, exist_ok=True)

    method = config["method"].upper()
    url = config["url"]
    if method not in ALLOWED_METHODS:
        raise ValueError(f"Método não permitido para replay: {method}")
    if not allowed(url, config):
        raise ValueError(f"URL fora do escopo: {url}")

    headers: dict[str, str] = dict(config.get("headers", {}))
    session_path = Path(config["session_path"])
    cookies = load_cookies(session_path, url)
    if cookies:
        existing = headers.get("Cookie", "")
        cookie_value = cookie_header(cookies)
        headers["Cookie"] = f"{existing}; {cookie_value}".strip("; ") if existing else cookie_value

    data: bytes | None = None
    if method in MUTATING_METHODS:
        body = config.get("body")
        if body is not None:
            if isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = bytes(body)
        content_type = config.get("content_type")
        if content_type:
            headers["Content-Type"] = content_type

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        response_headers = dict(response.headers)
        status = response.status
        body = response.read(MAX_BODY_BYTES + 1)
        truncated = len(body) > MAX_BODY_BYTES
        if truncated:
            body = body[:MAX_BODY_BYTES]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(body).hexdigest()

    private_response = {
        "method": method,
        "url": url,
        "status": status,
        "headers": response_headers,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "truncated": truncated,
        "timestamp": timestamp,
    }
    private_path = private_dir / "response.json"
    private_path.write_text(json.dumps(private_response, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    sanitized_meta = {
        "method": method,
        "url": url,
        "status": status,
        "size": len(body),
        "sha256": digest,
        "truncated": truncated,
        "timestamp": timestamp,
        "request_headers": redact_headers(headers),
        "response_headers": redact_headers(response_headers),
    }
    sanitized_path = sanitized_dir / "meta.json"
    sanitized_path.write_text(json.dumps(sanitized_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    metadata = {
        "ok": True,
        "method": method,
        "url": url,
        "status": status,
        "size": len(body),
        "sha256": digest,
        "truncated": truncated,
        "private": str(private_path),
        "sanitized": str(sanitized_path),
    }
    (output / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(prog="replay-worker")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    replay(config, Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
