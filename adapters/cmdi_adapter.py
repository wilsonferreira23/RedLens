#!/usr/bin/env python3
"""Commix adapter: curated command, evidence and findings for command injection.

Runs Commix inside the Kali container with a fixed, allowlisted argument list.
The agent chooses the target URL; the adapter decides the flags and parses output.
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


def parse_commix_output(stdout: str) -> list[dict]:
    findings = []
    # Look for confirmation lines like:
    # [x] Critical: The parameter 'X' seems to be injectable via (results-based) command injection.
    for line in stdout.splitlines():
        if "seems to be injectable" in line.lower():
            match = re.search(r"parameter '([^']+)'", line)
            findings.append({
                "parameter": match.group(1) if match else "unknown",
                "line": line.strip(),
            })
    return findings


def run_commix(
    run_id: str,
    url: str,
    method: str,
    data: str | None,
    parameter: str | None,
) -> dict:
    directory = redlensctl.run_dir(run_id)
    redlensctl.scoped_url(directory, url)

    if not redlensctl.valid_risk_approval(directory, "intrusive-scan", url):
        raise redlensctl.RedLensError("Commix exige aprovação intrusive-scan.")

    command = [
        "commix",
        "--url", url,
        "--batch",
        "--timeout", "10",
        "--level", "1",
        "--risk", "1",
    ]
    if method == "POST":
        command.extend(["--data", data or ""])
    if parameter:
        command.extend(["-p", parameter])

    result = exec_kali(command, timeout=900)

    timestamp = _iso()
    raw_dir = directory / "evidence" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{timestamp}-commix.txt"
    raw_path.write_text(
        f"$ {' '.join(command)}\n\nSTDOUT\n{result.stdout}\n\nSTDERR\n{result.stderr}",
        encoding="utf-8",
    )

    findings = parse_commix_output(result.stdout)
    summary = {
        "tool": "commix",
        "url": url,
        "method": method,
        "parameter": parameter,
        "returncode": result.returncode,
        "findings": findings,
        "raw": str(raw_path.relative_to(directory)),
    }
    sanitized_dir = directory / "evidence" / "sanitized"
    summary_path = sanitized_dir / f"{timestamp}-commix-summary.json"
    redlensctl.write_json(summary_path, summary)

    for idx, item in enumerate(findings):
        finding_id = redlensctl.safe_id("finding", "cmdi", url, item.get("parameter", "?"), str(idx))
        redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
            "id": finding_id,
            "title": f"Command injection: {item.get('parameter', '?')}",
            "severity": "critical",
            "status": "observation",
            "asset": url,
            "evidence": [str(summary_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
        })

    redlensctl.append_event(directory, "commix.completed", {
        "url": url,
        "findings": len(findings),
    })

    return {
        "ok": True,
        "summary": str(summary_path.relative_to(directory)),
        "findings": len(findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="cmdi-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--data")
    parser.add_argument("--parameter")
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = run_commix(args.run, args.url, args.method, args.data, args.parameter)
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
