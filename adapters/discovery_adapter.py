#!/usr/bin/env python3
"""Scoped content-discovery adapter that turns scanner output into inventory."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "adapters"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402

from kali_adapter import build_command  # noqa: E402


SUPPORTED_TOOLS = {"ffuf", "feroxbuster"}
DISCOVERY_CATEGORY = "surface"


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _update_coverage(
    directory: Path, category: str, status: str, summary: str, evidence: Path
) -> None:
    coverage_path = directory / "state" / "coverage.json"
    coverage = redlensctl.read_json(coverage_path)
    coverage["categories"][category] = {
        "status": status,
        "summary": summary,
        "evidence": [str(evidence.relative_to(directory))],
        "updated_at": redlensctl.iso(),
    }
    redlensctl.write_json(coverage_path, coverage)


def parse_feroxbuster(raw_output: str) -> list[str]:
    urls = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("{") is False:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if isinstance(url, str) and url.startswith("http"):
            urls.append(url)
    return urls


def parse_ffuf(raw_output: str) -> list[str]:
    urls = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if isinstance(url, str) and url.startswith("http"):
            urls.append(url)
    return urls


PARSERS = {
    "feroxbuster": parse_feroxbuster,
    "ffuf": parse_ffuf,
}


def _sanitize_output(raw_output: str) -> str:
    """Remove lines that look like secrets from public evidence."""
    redacted = []
    for line in raw_output.splitlines():
        if any(
            label in line.lower()
            for label in ("authorization:", "cookie:", "set-cookie:", "x-api-key")
        ):
            redacted.append("[REDACTED]")
        else:
            redacted.append(line)
    return "\n".join(redacted)


def discover(
    run_id: str, url: str, tool: str, timeout: int = 900
) -> dict:
    if tool not in SUPPORTED_TOOLS:
        raise redlensctl.RedLensError(f"Ferramenta de descoberta nao suportada: {tool}")

    directory = redlensctl.run_dir(run_id)
    redlensctl.scoped_url(directory, url)

    approval = argparse.Namespace(
        run=run_id, action="intrusive-scan", target=url
    )
    if not redlensctl.valid_risk_approval(directory, "intrusive-scan", url):
        raise redlensctl.RedLensError(
            "Descoberta de conteudo exige aprovacao intrusive-scan explicita."
        )

    scope = redlensctl.read_json(directory / "scope" / "scope.json")
    command = build_command(tool, url, scope["max_rps"])
    result = exec_kali(command, timeout=timeout)

    timestamp = _iso()
    safe_tool = re.sub(r"[^a-z0-9-]", "-", tool)
    raw_dir = directory / "evidence" / "raw"
    raw_path = raw_dir / f"{timestamp}-{safe_tool}.txt"
    raw_path.write_text(
        f"$ {' '.join(command)}\n\nSTDOUT\n{result.stdout}\n\nSTDERR\n{result.stderr}",
        encoding="utf-8",
    )

    sanitized_dir = directory / "evidence" / "sanitized"
    sanitized_path = sanitized_dir / f"{timestamp}-{safe_tool}.txt"
    sanitized_path.write_text(_sanitize_output(result.stdout), encoding="utf-8")

    discovered = PARSERS[tool](result.stdout)
    endpoints = []
    skipped = 0
    for raw_url in discovered:
        normalized = raw_url.split("?")[0].split("#")[0]
        full_url = urljoin(url, normalized) if not normalized.startswith("http") else normalized
        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https"):
            skipped += 1
            continue
        try:
            item_id, _, _ = redlensctl.record_inventory(
                directory, "endpoint", full_url, "tool", method="GET"
            )
            endpoints.append(item_id)
        except redlensctl.RedLensError:
            skipped += 1

    summary = {
        "tool": tool,
        "target": url,
        "command": command,
        "returncode": result.returncode,
        "discovered_total": len(discovered),
        "in_scope": len(endpoints),
        "skipped": skipped,
        "endpoints": sorted(set(endpoints)),
    }
    summary_path = sanitized_dir / f"{timestamp}-{safe_tool}-summary.json"
    redlensctl.write_json(summary_path, summary)

    _update_coverage(
        directory,
        DISCOVERY_CATEGORY,
        "confirmed",
        f"{tool} encontrou {len(endpoints)} endpoints no escopo",
        summary_path,
    )

    redlensctl.append_event(directory, "discovery.completed", {
        "tool": tool,
        "target": url,
        "endpoints": len(endpoints),
    })

    return {
        "ok": True,
        "tool": tool,
        "url": url,
        "endpoints": len(endpoints),
        "summary": str(summary_path.relative_to(directory)),
        "raw": str(raw_path.relative_to(directory)),
        "sanitized": str(sanitized_path.relative_to(directory)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="discovery-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--tool", choices=sorted(SUPPORTED_TOOLS), default="feroxbuster")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    try:
        result = discover(args.run, args.url, args.tool, args.timeout)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (redlensctl.RedLensError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
