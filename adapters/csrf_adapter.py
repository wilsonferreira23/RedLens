#!/usr/bin/env python3
"""CSRF analyzer: inspect a request-spec for anti-CSRF controls.

It does not mutate the server; it reads the spec and reports missing tokens or
missing Origin/Referer validation. Real verification is left to the mutation
engine or browser replay.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


CSRF_TOKEN_FIELDS = {
    "csrf", "csrf_token", "csrf-token", "xsrf", "xsrf_token", "xsrf-token",
    "_token", "authenticity_token", "__requestverificationtoken",
}


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_spec(directory: Path, raw: str) -> dict:
    path = Path(raw)
    path = path.resolve() if path.is_absolute() else (directory / path).resolve()
    if directory.resolve() not in path.parents or not path.is_file():
        raise redlensctl.RedLensError("Especificação ausente ou fora da operação.")
    if "evidence/private" not in str(path):
        raise redlensctl.RedLensError("Request-spec deve ficar em evidence/private.")
    return json.loads(path.read_text(encoding="utf-8"))


def has_csrf_token(body: str, content_type: str | None) -> bool:
    if not body:
        return False
    if content_type and "json" in content_type.lower():
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return False
        if isinstance(data, dict):
            for key in data:
                if key.lower() in CSRF_TOKEN_FIELDS:
                    return True
    pairs = {}
    try:
        pairs = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
    except Exception:
        pass
    for key in pairs:
        if key.lower() in CSRF_TOKEN_FIELDS:
            return True
    return False


def analyze(run_id: str, spec_path_raw: str) -> dict:
    directory = redlensctl.run_dir(run_id)
    spec = load_spec(directory, spec_path_raw)
    url = spec["url"]
    redlensctl.scoped_url(directory, url)
    method = str(spec.get("method", "GET")).upper()
    body = spec.get("body", "")
    content_type = spec.get("content_type") or spec.get("headers", {}).get("Content-Type", "")
    headers = {k.lower(): v for k, v in spec.get("headers", {}).items()}

    missing = []
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not has_csrf_token(body, content_type):
            missing.append("csrf_token")
        if "origin" not in headers and "referer" not in headers:
            missing.append("origin_or_referer_header")

    summary = {
        "tool": "csrf-analyzer",
        "url": url,
        "method": method,
        "missing_controls": missing,
        "has_csrf_token": "csrf_token" not in missing,
        "has_origin_or_referer": "origin_or_referer_header" not in missing,
    }

    timestamp = _iso()
    sanitized_dir = directory / "evidence" / "sanitized"
    summary_path = sanitized_dir / f"{timestamp}-csrf.json"
    redlensctl.write_json(summary_path, summary)

    if missing:
        finding_id = redlensctl.safe_id("finding", "csrf", url, method)
        redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
            "id": finding_id,
            "title": f"CSRF controls missing on {method} {url}",
            "severity": "medium",
            "status": "observation",
            "asset": url,
            "evidence": [str(summary_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
            "metadata": {"missing": missing},
        })

    redlensctl.append_event(directory, "csrf.analyzed", {"url": url, "method": method, "missing": missing})

    return {"ok": True, "summary": str(summary_path.relative_to(directory)), **summary}


def main() -> int:
    parser = argparse.ArgumentParser(prog="csrf-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = analyze(args.run, args.spec)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
