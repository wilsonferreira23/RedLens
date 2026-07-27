#!/usr/bin/env python3
"""Static JavaScript analysis adapter: extract hidden endpoints and secrets."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402


JS_URL_RE = re.compile(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ENDPOINT_RE = re.compile(
    r"(?:['\"`])((?:/|https?://)[a-zA-Z0-9_\-./?&=+%#~]+)(?:['\"`])"
)
SECRET_HINTS = [
    re.compile(r"(?i)(api[_-]?key|apikey|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)bearer\s+[a-z0-9_\-\.]{20,}"),
]


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _fetch(url: str, timeout: int = 15) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "RedLens-JS-Analysis/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def _run_curl(url: str, timeout: int = 15) -> str:
    """Fallback fetch via Kali container for URLs that Python cannot reach."""
    result = exec_kali(
        ["curl", "-sS", "--max-time", str(timeout), "-L", url],
        timeout=timeout + 5,
    )
    return result.stdout or ""


def extract_js_urls(html: str, base_url: str) -> list[str]:
    urls = []
    for match in JS_URL_RE.finditer(html):
        src = match.group(1)
        full = urljoin(base_url, src)
        parsed = urlparse(full)
        if parsed.scheme in ("http", "https"):
            urls.append(full)
    return urls


def extract_endpoints(js_text: str, base_url: str) -> list[str]:
    endpoints = set()
    for match in ENDPOINT_RE.finditer(js_text):
        candidate = match.group(1)
        if candidate.startswith("http://") or candidate.startswith("https://"):
            endpoints.add(candidate)
        elif candidate.startswith("/"):
            endpoints.add(urljoin(base_url, candidate))
    return sorted(endpoints)


def find_secret_hints(js_text: str, base_url: str) -> list[dict]:
    findings = []
    for pattern in SECRET_HINTS:
        for match in pattern.finditer(js_text):
            findings.append({
                "type": "secret_hint",
                "location": base_url,
                "position": match.start(),
                "snippet": match.group(0)[:60],
            })
    return findings


def _redact_snippet(snippet: str) -> str:
    return re.sub(r"(?i)(api[_-]?key|apikey|secret|password|token)\s*[:=]\s*['\"][^'\"]+['\"]", "\\1=<redacted>", snippet)


def _update_coverage(directory: Path, evidence: Path) -> None:
    coverage_path = directory / "state" / "coverage.json"
    coverage = redlensctl.read_json(coverage_path)
    coverage["categories"]["client_side"] = {
        "status": "confirmed",
        "summary": "Analise estatica de JavaScript concluida",
        "evidence": [str(evidence.relative_to(directory))],
        "updated_at": redlensctl.iso(),
    }
    redlensctl.write_json(coverage_path, coverage)


def analyze(run_id: str, url: str, timeout: int = 15) -> dict:
    directory = redlensctl.run_dir(run_id)
    redlensctl.scoped_url(directory, url)

    timestamp = _iso()
    raw_dir = directory / "evidence" / "raw"
    sanitized_dir = directory / "evidence" / "sanitized"

    try:
        html = _fetch(url, timeout)
    except (OSError, urllib.error.URLError):
        html = _run_curl(url, timeout)

    js_urls = extract_js_urls(html, url)

    endpoints = set()
    secret_findings = []
    js_records = []

    for js_url in js_urls:
        try:
            redlensctl.scoped_url(directory, js_url)
        except redlensctl.RedLensError:
            continue
        try:
            js_text = _fetch(js_url, timeout)
        except (OSError, urllib.error.URLError):
            js_text = _run_curl(js_url, timeout)

        js_path = raw_dir / f"{timestamp}-js-{urlparse(js_url).path.replace('/', '-')}.js"
        js_path.write_text(js_text, encoding="utf-8")

        for endpoint in extract_endpoints(js_text, url):
            try:
                redlensctl.scoped_url(directory, endpoint)
                item_id, _, _ = redlensctl.record_inventory(
                    directory, "endpoint", endpoint, "tool", method="GET"
                )
                endpoints.add(item_id)
            except redlensctl.RedLensError:
                pass

        secrets = find_secret_hints(js_text, js_url)
        for secret in secrets:
            secret["snippet"] = _redact_snippet(secret["snippet"])
            secret_findings.append(secret)
        js_records.append({"url": js_url, "path": str(js_path.relative_to(directory)), "size": len(js_text)})

    secrets_path = sanitized_dir / f"{timestamp}-js-secrets.json"
    redlensctl.write_json(secrets_path, secret_findings)

    for secret in secret_findings:
        finding_id = redlensctl.safe_id("finding", "js-secret", secret["location"], str(secret["position"]))
        finding_path = directory / "findings" / f"{finding_id}.json"
        redlensctl.write_json(finding_path, {
            "id": finding_id,
            "title": "Possivel segredo em JavaScript",
            "severity": "high",
            "status": "observation",
            "asset": secret["location"],
            "evidence": [str(secrets_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
        })

    summary = {
        "tool": "js-analysis",
        "target": url,
        "js_files": len(js_records),
        "endpoints": sorted(endpoints),
        "secret_hints": len(secret_findings),
        "records": js_records,
    }
    summary_path = sanitized_dir / f"{timestamp}-js-summary.json"
    redlensctl.write_json(summary_path, summary)

    _update_coverage(directory, summary_path)

    redlensctl.append_event(directory, "js.analysis.completed", {
        "target": url,
        "js_files": len(js_records),
        "endpoints": len(endpoints),
        "secret_hints": len(secret_findings),
    })

    return {
        "ok": True,
        "target": url,
        "summary": str(summary_path.relative_to(directory)),
        "js_files": len(js_records),
        "endpoints": len(endpoints),
        "secret_hints": len(secret_findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="js-analysis-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    try:
        result = analyze(args.run, args.url, args.timeout)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except redlensctl.RedLensError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
