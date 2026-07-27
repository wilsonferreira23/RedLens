#!/usr/bin/env python3
"""Dalfox adapter: curated command, POC parsing, evidence and findings.

Runs Dalfox inside the Kali container with a fixed, allowlisted argument list.
The agent chooses the target URL; the adapter decides the flags and parses POCs.
"""

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


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_dalfox_output(stdout: str) -> list[dict]:
    findings = []
    # Lines look like: [POC][G][GET] https://.../?q=<script>alert(1)</script>
    for line in stdout.splitlines():
        if "[POC]" in line:
            match = re.search(r"\[POC\]\[[A-Z]\]\[(GET|POST)\]\s+(\S+)", line)
            if match:
                findings.append({
                    "method": match.group(1),
                    "url": match.group(2),
                    "line": line.strip(),
                })
    return findings


def run_dalfox(
    run_id: str,
    url: str,
    method: str,
    parameter: str | None,
    data: str | None,
) -> dict:
    directory = redlensctl.run_dir(run_id)
    redlensctl.scoped_url(directory, url)

    if not redlensctl.valid_risk_approval(directory, "intrusive-scan", url):
        raise redlensctl.RedLensError("Dalfox exige aprovação intrusive-scan.")

    command = [
        "dalfox",
        "url", url,
        "--no-color",
        "--silence",
        "--delay", "100",
        "--timeout", "10",
    ]
    if parameter:
        command.extend(["--param", parameter])
    if method == "POST":
        command.extend(["--method", "POST", "--data", data or ""])

    result = exec_kali(command, timeout=900)

    timestamp = _iso()
    raw_dir = directory / "evidence" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{timestamp}-dalfox.txt"
    raw_path.write_text(
        f"$ {' '.join(command)}\n\nSTDOUT\n{result.stdout}\n\nSTDERR\n{result.stderr}",
        encoding="utf-8",
    )

    findings = parse_dalfox_output(result.stdout)
    sanitized = []
    for item in findings:
        sanitized.append({
            "method": item["method"],
            "url": item["url"],
        })

    summary = {
        "tool": "dalfox",
        "url": url,
        "method": method,
        "parameter": parameter,
        "returncode": result.returncode,
        "findings": sanitized,
        "raw": str(raw_path.relative_to(directory)),
    }
    sanitized_dir = directory / "evidence" / "sanitized"
    summary_path = sanitized_dir / f"{timestamp}-dalfox-summary.json"
    redlensctl.write_json(summary_path, summary)

    for idx, item in enumerate(findings):
        finding_id = redlensctl.safe_id("finding", "xss", url, str(idx))
        redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
            "id": finding_id,
            "title": f"XSS refletido detectado por Dalfox em {url}",
            "severity": "high",
            "status": "observation",
            "asset": url,
            "evidence": [str(summary_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
        })

    redlensctl.append_event(directory, "dalfox.completed", {
        "url": url,
        "findings": len(findings),
    })

    return {
        "ok": True,
        "summary": str(summary_path.relative_to(directory)),
        "findings": len(findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="xss-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--parameter")
    parser.add_argument("--data")
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = run_dalfox(args.run, args.url, args.method, args.parameter, args.data)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
