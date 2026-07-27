#!/usr/bin/env python3
"""SQLMap adapter: curated command, JSON parsing, evidence and findings.

Runs SQLMap inside the Kali container with a fixed, allowlisted argument list.
The agent chooses the target URL and parameter; the adapter decides the flags.
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


def build_command(
    url: str,
    method: str,
    data: str | None,
    parameter: str | None,
    level: int,
    risk: int,
) -> list[str]:
    if level not in {1, 2, 3}:
        raise redlensctl.RedLensError("Level SQLMap deve ser 1, 2 ou 3.")
    if risk not in {1, 2}:
        raise redlensctl.RedLensError("Risk SQLMap deve ser 1 ou 2.")
    command = [
        "sqlmap",
        "--batch",
        "--disable-coloring",
        "--level", str(level),
        "--risk", str(risk),
        "--timeout", "10",
        "--retries", "1",
        "--threads", "1",
        "--answers", "crack=N,dict=N",
        "--flush-session",
    ]
    if method == "GET":
        command.extend(["-u", url])
    else:
        command.extend(["-u", url, "--data", data or ""])
        if method != "POST":
            command.extend(["--method", method])
    if parameter:
        command.extend(["-p", parameter])
    return command


def parse_sqlmap_output(stdout: str) -> list[dict]:
    findings = []
    # SQLMap reports injection in stdout lines like:
    # parameter 'id' is vulnerable. Do you want to keep testing ...
    # title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    current = None
    for line in stdout.splitlines():
        line = line.strip()
        match = re.search(r"parameter '([^']+)' is vulnerable", line, re.IGNORECASE)
        if match:
            current = {"parameter": match.group(1), "title": None, "type": "error"}
        if current and "title:" in line.lower():
            current["title"] = line.split("title:", 1)[1].strip()
            findings.append(current)
            current = None
    return findings


def run_sqlmap(
    run_id: str,
    url: str,
    method: str,
    data: str | None,
    parameter: str | None,
    level: int,
    risk: int,
) -> dict:
    directory = redlensctl.run_dir(run_id)
    redlensctl.scoped_url(directory, url)

    if not redlensctl.valid_risk_approval(directory, "intrusive-scan", url):
        raise redlensctl.RedLensError("SQLMap exige aprovação intrusive-scan.")

    scope = redlensctl.read_json(directory / "scope" / "scope.json")
    authorization = redlensctl.read_json(directory / "authorization" / "authorization.json")
    if authorization["environment"] == "production" and (level > 1 or risk > 1):
        raise redlensctl.RedLensError("Level/risk elevados não permitidos em produção.")

    command = build_command(url, method, data, parameter, level, risk)
    result = exec_kali(command, timeout=900)

    timestamp = _iso()
    raw_dir = directory / "evidence" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{timestamp}-sqlmap.txt"
    raw_path.write_text(
        f"$ {' '.join(command)}\n\nSTDOUT\n{result.stdout}\n\nSTDERR\n{result.stderr}",
        encoding="utf-8",
    )

    findings = parse_sqlmap_output(result.stdout)
    summary = {
        "tool": "sqlmap",
        "url": url,
        "method": method,
        "parameter": parameter,
        "level": level,
        "risk": risk,
        "returncode": result.returncode,
        "vulnerable_parameters": findings,
        "raw": str(raw_path.relative_to(directory)),
    }
    sanitized_dir = directory / "evidence" / "sanitized"
    summary_path = sanitized_dir / f"{timestamp}-sqlmap-summary.json"
    redlensctl.write_json(summary_path, summary)

    for item in findings:
        finding_id = redlensctl.safe_id(
            "finding", "sqli", url, item.get("parameter", "?"), item.get("title", "") or ""
        )
        redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
            "id": finding_id,
            "title": f"SQL injection: {item.get('parameter', '?')} — {item.get('title', 'detectado')}",
            "severity": "critical" if risk == 2 else "high",
            "status": "observation",
            "asset": url,
            "evidence": [str(summary_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
        })

    redlensctl.append_event(directory, "sqlmap.completed", {
        "url": url,
        "parameter": parameter,
        "findings": len(findings),
    })

    return {
        "ok": True,
        "summary": str(summary_path.relative_to(directory)),
        "findings": len(findings),
        "vulnerable_parameters": [f["parameter"] for f in findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="sqlmap-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", choices=("GET", "POST", "PUT"), default="GET")
    parser.add_argument("--data")
    parser.add_argument("--parameter")
    parser.add_argument("--level", type=int, default=1)
    parser.add_argument("--risk", type=int, default=1)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = run_sqlmap(args.run, args.url, args.method, args.data, args.parameter, args.level, args.risk)
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
