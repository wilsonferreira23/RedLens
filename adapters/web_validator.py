#!/usr/bin/env python3
"""Low-impact, scoped HTTP configuration checks executed inside Kali."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402


def command(check: str, url: str) -> list[str]:
    base = [
        "curl", "-sS", "--max-time", "15", "-D", "-", "-o", "/dev/null",
        "-A", "Mozilla/5.0 (RedLens/1.0; +https://github.com/redlens) AppleWebKit/605.1.15",
        "-H", "Accept: application/json, text/html;q=0.9, */*;q=0.5",
        "-H", "Accept-Language: en-US,en;q=0.9,pt-BR;q=0.8",
    ]
    if check == "headers":
        return [*base, "-I", url]
    if check == "cors":
        return [*base, "-X", "OPTIONS", "-H", "Origin: https://redlens.invalid", url]
    if check == "methods":
        return [*base, "-X", "OPTIONS", url]
    raise redlensctl.RedLensError("Verificação HTTP desconhecida.")


def parse_headers(raw: str) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if ":" not in line or line.upper().startswith("HTTP/"):
            continue
        key, value = line.split(":", 1)
        key = key.lower().strip()
        value = value.strip()
        if key == "set-cookie":
            value = re.sub(r"=([^;]*)", "=<redacted>", value, count=1)
        headers.setdefault(key, []).append(value)
    return headers


SECURITY_HEADERS = {
    "strict-transport-security",
    "x-frame-options",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


def _record_finding(
    directory: Path, title: str, severity: str, asset: str, evidence: Path
) -> None:
    finding_id = redlensctl.safe_id("finding", title, asset)
    redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": "observation",
        "asset": asset,
        "evidence": [str(evidence.relative_to(directory))],
        "reproduced": False,
        "negative_control": False,
        "created_at": redlensctl.iso(),
    })


def _evaluate_headers(directory: Path, url: str, headers: dict[str, list[str]], evidence: Path) -> list[str]:
    missing = sorted(SECURITY_HEADERS - set(headers.keys()))
    for header in missing:
        _record_finding(
            directory, f"Missing {header} header", "low", url, evidence
        )
    return missing


def _evaluate_cors(directory: Path, url: str, headers: dict[str, list[str]], evidence: Path) -> bool:
    allow_origin = headers.get("access-control-allow-origin", [])
    allowed = [value for value in allow_origin
               if value == "*" or "redlens.invalid" in value]
    if allowed:
        _record_finding(
            directory, "CORS reflects arbitrary origin", "medium", url, evidence
        )
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(prog="web-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--check", choices=("headers", "cors", "methods"), required=True)
    args = parser.parse_args()
    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)
        result = exec_kali(command(args.check, args.url), timeout=30)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        raw = directory / "evidence" / "raw" / f"{timestamp}-{args.check}-headers.txt"
        raw.write_text(result.stdout + result.stderr, encoding="utf-8")
        summary = {
            "check": args.check,
            "url": args.url,
            "returncode": result.returncode,
            "headers": parse_headers(result.stdout),
        }
        sanitized = directory / "evidence" / "sanitized" / f"{timestamp}-{args.check}.json"
        redlensctl.write_json(sanitized, summary)
        if args.check == "headers":
            summary["missing_security_headers"] = _evaluate_headers(
                directory, args.url, summary["headers"], sanitized
            )
        if args.check == "cors":
            summary["cors_reflected"] = _evaluate_cors(
                directory, args.url, summary["headers"], sanitized
            )
        redlensctl.append_event(directory, "web.check.completed", {
            "check": args.check, "returncode": result.returncode,
        })
        print(json.dumps({"ok": result.returncode == 0,
                          "evidence": str(sanitized.relative_to(directory)), **summary},
                         ensure_ascii=False, indent=2))
        return 0 if result.returncode == 0 else 1
    except (redlensctl.RedLensError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
