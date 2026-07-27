#!/usr/bin/env python3
"""Discover hidden query/body parameters by differential response analysis."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


DEFAULT_PARAMS = [
    "id", "user", "page", "search", "q", "callback", "redirect", "next",
    "debug", "test", "admin", "role", "tenant", "limit", "offset", "sort",
    "order", "filter", "include", "expand", "deleted", "active", "status",
    "name", "email", "password", "token", "api_key", "session", "csrf",
]


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _fetch(url: str, method: str = "GET", data: bytes | None = None, timeout: int = 15) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"User-Agent": "RedLens-Param-Discovery/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def _record_finding(directory: Path, title: str, severity: str, asset: str, evidence: Path) -> None:
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


def _update_coverage(directory: Path, evidence: Path) -> None:
    coverage_path = directory / "state" / "coverage.json"
    coverage = redlensctl.read_json(coverage_path)
    coverage["categories"]["api"] = {
        "status": "confirmed",
        "summary": "Descoberta de parametros ocultos concluida",
        "evidence": [str(evidence.relative_to(directory))],
        "updated_at": redlensctl.iso(),
    }
    redlensctl.write_json(coverage_path, coverage)


def analyze(
    run_id: str,
    url: str,
    method: str = "GET",
    wordlist: list[str] | None = None,
    timeout: int = 15,
) -> dict:
    directory = redlensctl.run_dir(run_id)
    redlensctl.scoped_url(directory, url)

    scope = redlensctl.read_json(directory / "scope" / "scope.json")
    delay = 1.0 / scope["max_rps"] if scope["max_rps"] > 0 else 0.5

    timestamp = _iso()
    sanitized_dir = directory / "evidence" / "sanitized"

    baseline_status, baseline_body = _fetch(url, method=method, timeout=timeout)
    baseline_len = len(baseline_body)

    params = wordlist if wordlist is not None else DEFAULT_PARAMS
    discovered = []
    findings = []

    for param in params:
        time.sleep(delay)
        probe = f"redlens_probe_{param}"
        if method == "GET":
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(probe)}"
            probe_data = None
        else:
            probe_url = url
            probe_data = urllib.parse.urlencode({param: probe}).encode("utf-8")

        try:
            status, body = _fetch(probe_url, method=method, data=probe_data, timeout=timeout)
        except (OSError, urllib.error.URLError):
            continue

        if status != baseline_status or len(body) != baseline_len:
            separator = "?" if method == "GET" else "#"
            item_id, _, _ = redlensctl.record_inventory(
                directory, "parameter", f"{method} {url}{separator}{param}", "tool"
            )
            discovered.append({"param": param, "status": status, "size": len(body), "id": item_id})
            if status != baseline_status:
                findings.append({"param": param, "status_change": True})

    summary = {
        "tool": "param-discovery",
        "target": url,
        "method": method,
        "baseline": {"status": baseline_status, "size": baseline_len},
        "discovered": discovered,
    }
    summary_path = sanitized_dir / f"{timestamp}-param-summary.json"
    redlensctl.write_json(summary_path, summary)

    for finding in findings:
        _record_finding(
            directory,
            f"Parametro '{finding['param']}' altera resposta do endpoint",
            "medium",
            url,
            summary_path,
        )

    _update_coverage(directory, summary_path)

    redlensctl.append_event(directory, "param.discovery.completed", {
        "target": url,
        "discovered": len(discovered),
    })

    return {
        "ok": True,
        "target": url,
        "summary": str(summary_path.relative_to(directory)),
        "discovered": len(discovered),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="param-discovery-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--wordlist", help="Arquivo com um parametro por linha")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    try:
        wordlist = None
        if args.wordlist:
            path = Path(args.wordlist).resolve()
            wordlist = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        result = analyze(args.run, args.url, args.method, wordlist, args.timeout)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (redlensctl.RedLensError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
