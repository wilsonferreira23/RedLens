#!/usr/bin/env python3
"""Coverage planner: emit pending tasks needed to cover every inventory endpoint.

For each endpoint not yet covered by a recorded task, the planner suggests:
  - headers/CORS/methods check (web-safe)
  - one authz cell per role (authz-safe)
  - mutation probe per parameter (mutate-safe)
  - SQLi and XSS scans if the endpoint accepts parameters

This module is the autonomy core: instead of relying on the LLM to remember
what to test, the planner emits a deterministic backlog.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


COVERED_TASK_TITLES = {
    "headers",
    "cors",
    "authz",
    "sqli",
    "xss",
    "cmdi",
    "ssti",
    "traversal",
    "ssrf",
    "csrf",
    "mass-assignment",
    "mutation",
}


def list_endpoints(directory: Path) -> list[dict]:
    items = []
    for path in (directory / "inventory").glob("*.json"):
        item = redlensctl.read_json(path)
        if item.get("kind") in {"endpoint", "api"}:
            items.append(item)
    return items


def list_tasks(directory: Path) -> list[dict]:
    items = []
    for path in (directory / "tasks").glob("*.json"):
        items.append(redlensctl.read_json(path))
    return items


def existing_coverage(directory: Path) -> dict[str, set[str]]:
    coverage: dict[str, set[str]] = {}
    for task in list_tasks(directory):
        title = (task.get("title") or "").lower()
        target = task.get("target")
        if not target:
            continue
        for key in COVERED_TASK_TITLES:
            if key in title:
                coverage.setdefault(target, set()).add(key)
    return coverage


def plan_next(run_id: str, limit: int = 10) -> dict:
    directory = redlensctl.run_dir(run_id)
    endpoints = list_endpoints(directory)
    coverage = existing_coverage(directory)
    identities = [redlensctl.read_json(p) for p in (directory / "identities").glob("*.json")]

    pending = []
    for endpoint in endpoints:
        target = endpoint["value"]
        method = endpoint.get("method", "GET")
        covered = coverage.get(target, set())
        for key, title, kind in [
            ("headers", f"Verify headers/CORS on {target}", "validation"),
            ("csrf", f"CSRF check on {target}", "validation"),
            ("authz", f"Authorization cell on {target}", "authorization"),
        ]:
            if key not in covered:
                pending.append({"kind": kind, "title": title, "target": target, "category": key})
                if len(pending) >= limit:
                    break
        if method in {"GET", "POST", "PUT", "PATCH"}:
            if "sqli" not in covered:
                pending.append({"kind": "validation", "title": f"SQLMap probe on {target}", "target": target, "category": "sqli"})
            if "xss" not in covered:
                pending.append({"kind": "validation", "title": f"Dalfox probe on {target}", "target": target, "category": "xss"})
        if identities and "authz" not in covered:
            for ident in identities:
                role = ident.get("role")
                pending.append({
                    "kind": "authorization",
                    "title": f"Authorization cell for role {role} on {target}",
                    "target": target,
                    "category": "authz",
                    "role": role,
                })
        if len(pending) >= limit:
            break

    return {
        "ok": True,
        "endpoints_total": len(endpoints),
        "tasks_suggested": len(pending),
        "pending": pending[:limit],
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="plan-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--limit", type=int, default=10)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = plan_next(args.run, args.limit)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except redlensctl.RedLensError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())