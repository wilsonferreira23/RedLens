#!/usr/bin/env python3
"""Mass assignment probe: append privileged fields to a request body and compare.

Uses the replay engine to execute both the original and the mutated request,
and records evidence when the server returns a different response.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import subprocess
from shutil import which
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPLAY_SAFE = which("redlens-replay-safe") or "redlens-replay-safe"
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


PRIVILEGED_FIELDS = {
    "role", "admin", "is_admin", "is_staff", "superuser",
    "verified", "email_verified", "active", "is_active",
    "tenant", "tenant_id", "organization_id", "org_id",
    "balance", "credit", "quota", "limit",
    "created_at", "updated_at", "deleted_at",
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


def inject_privileged_fields(body: str, content_type: str) -> str:
    if "json" in (content_type or "").lower():
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            raise redlensctl.RedLensError("Body não é JSON válido.") from exc
        if not isinstance(data, dict):
            raise redlensctl.RedLensError("Mass assignment exige objeto JSON no body.")
        # Apply only fields that are not already present
        for field, value in {
            "role": "admin",
            "is_admin": True,
            "verified": True,
        }.items():
            if field not in data:
                data[field] = value
        return json.dumps(data, ensure_ascii=False)
    raise redlensctl.RedLensError("Mass assignment requer content-type JSON.")


def run_replay(run_id: str, spec_path: str, role: str) -> dict:
    result = subprocess.run(
        [REPLAY_SAFE, "--run", run_id, "--spec", spec_path, "--role", role],
        text=True,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise redlensctl.RedLensError(result.stderr.strip() or "Falha no replay.")
    return json.loads(result.stdout)


def write_spec(directory: Path, spec: dict) -> Path:
    spec_dir = directory / "evidence" / "private" / "mass-assignment"
    spec_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _iso()
    path = spec_dir / f"{timestamp}.json"
    path.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def analyze(run_id: str, spec_path_raw: str, role: str) -> dict:
    directory = redlensctl.run_dir(run_id)
    spec = load_spec(directory, spec_path_raw)
    method = str(spec.get("method", "GET")).upper()
    if method not in {"POST", "PUT", "PATCH"}:
        raise redlensctl.RedLensError("Mass assignment requer método POST/PUT/PATCH.")

    content_type = spec.get("content_type") or spec.get("headers", {}).get("Content-Type", "application/json")
    mutated = dict(spec)
    mutated["body"] = inject_privileged_fields(spec.get("body", ""), content_type)
    if "content_type" not in mutated and not spec.get("headers", {}).get("Content-Type"):
        mutated["content_type"] = "application/json"

    mutated_path = write_spec(directory, mutated)

    baseline = run_replay(run_id, spec_path_raw, role)
    mutated_response = run_replay(run_id, str(mutated_path.relative_to(directory)), role)

    comparison = {
        "baseline_status": baseline["status"],
        "baseline_size": baseline["size"],
        "mutated_status": mutated_response["status"],
        "mutated_size": mutated_response["size"],
        "differs": baseline["status"] != mutated_response["status"] or baseline["size"] != mutated_response["size"],
    }

    summary = {
        "tool": "mass-assignment",
        "target": spec["url"],
        "method": method,
        "privileged_fields_added": ["role", "is_admin", "verified"],
        "baseline": baseline,
        "mutated": mutated_response,
        "comparison": comparison,
    }

    sanitized_dir = directory / "evidence" / "sanitized"
    timestamp = _iso()
    summary_path = sanitized_dir / f"{timestamp}-mass-assignment.json"
    redlensctl.write_json(summary_path, summary)

    if comparison["differs"]:
        finding_id = redlensctl.safe_id("finding", "mass-assignment", spec["url"], method)
        redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
            "id": finding_id,
            "title": f"Mass assignment detected on {method} {spec['url']}",
            "severity": "high",
            "status": "observation",
            "asset": spec["url"],
            "evidence": [str(summary_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
        })

    redlensctl.append_event(directory, "mass-assignment.tested", {
        "url": spec["url"],
        "method": method,
        "differs": comparison["differs"],
    })

    return {"ok": True, "summary": str(summary_path.relative_to(directory)), **summary}


def main() -> int:
    parser = argparse.ArgumentParser(prog="massassign-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--role", required=True)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = analyze(args.run, args.spec, args.role)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
