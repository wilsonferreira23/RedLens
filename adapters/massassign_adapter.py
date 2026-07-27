#!/usr/bin/env python3
"""Mass assignment adapter: re-send a request with privileged fields added.

Uses the mutation engine to inject privilege-escalation fields into a JSON or
form body, then compares responses. The set of privileged fields is fixed; the
agent chooses the request-spec.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "adapters"))

import redlensctl  # noqa: E402
import mutate_adapter  # noqa: E402


PRIVILEGED_FIELDS = [
    ("role", "admin"),
    ("is_admin", True),
    ("admin", True),
    ("is_staff", True),
    ("privilege", "admin"),
    ("tenant_id", "1"),
    ("organization_id", "1"),
    ("group", "admins"),
]


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


def _inject_field(body: str, content_type: str, field: str, value) -> str:
    if content_type and "json" in content_type.lower():
        data = json.loads(body) if body else {}
        if not isinstance(data, dict):
            raise redlensctl.RedLensError("Body não é objeto JSON.")
        data[field] = value
        return json.dumps(data, ensure_ascii=False)
    if content_type and "x-www-form-urlencoded" in content_type.lower():
        pairs = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
        pairs.append((field, str(value)))
        return urllib.parse.urlencode(pairs)
    raise redlensctl.RedLensError("Content-Type não suportado.")


def analyze(
    run_id: str,
    spec_path_raw: str,
    role: str,
    fields: list[str],
) -> dict:
    directory = redlensctl.run_dir(run_id)
    spec = load_spec(directory, spec_path_raw)
    url = spec["url"]
    redlensctl.scoped_url(directory, url)
    method = str(spec.get("method", "GET")).upper()
    if method not in {"POST", "PUT", "PATCH"}:
        raise redlensctl.RedLensError("Mass assignment aplica-se a POST/PUT/PATCH.")

    # Requires data-mutation approval because we are mutating data on the server.
    if not redlensctl.valid_risk_approval(directory, "data-mutation", url):
        raise redlensctl.RedLensError("Mass assignment exige aprovação data-mutation.")

    content_type = spec.get("content_type") or spec.get("headers", {}).get("Content-Type", "application/json")
    body = spec.get("body", "")

    baseline_size = None
    comparisons = []
    findings = []

    # Execute baseline once.
    baseline = mutate_adapter.run_replay(run_id, spec_path_raw, role)
    baseline_size = baseline["size"]
    baseline_status = baseline["status"]

    for field, value in PRIVILEGED_FIELDS:
        if field in fields:
            continue
        try:
            mutated_body = _inject_field(body, content_type, field, value)
        except redlensctl.RedLensError:
            continue
        mutated_spec = dict(spec)
        mutated_spec["body"] = mutated_body
        mutated_spec["_mutation_payload_id"] = f"massassign-{field}"
        mutated_path = mutate_adapter.write_spec(directory, mutated_spec)

        try:
            mutated = mutate_adapter.run_replay(run_id, str(mutated_path.relative_to(directory)), role)
        except redlensctl.RedLensError:
            continue
        differs = mutated["status"] != baseline_status or mutated["size"] != baseline_size
        comparisons.append({
            "field": field,
            "value": value,
            "baseline_status": baseline_status,
            "baseline_size": baseline_size,
            "mutated_status": mutated["status"],
            "mutated_size": mutated["size"],
            "differs": differs,
        })
        if differs:
            findings.append({
                "field": field,
                "value": value,
                "status_change": mutated["status"] != baseline_status,
            })

    timestamp = _iso()
    summary = {
        "tool": "mass-assignment",
        "url": url,
        "method": method,
        "baseline_status": baseline_status,
        "baseline_size": baseline_size,
        "fields_tested": [c["field"] for c in comparisons],
        "differs": [c["field"] for c in comparisons if c["differs"]],
        "comparisons": comparisons,
    }
    sanitized_dir = directory / "evidence" / "sanitized"
    summary_path = sanitized_dir / f"{timestamp}-mass-assignment.json"
    redlensctl.write_json(summary_path, summary)

    for item in findings:
        finding_id = redlensctl.safe_id("finding", "mass-assignment", url, item["field"])
        redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
            "id": finding_id,
            "title": f"Possível mass assignment via campo '{item['field']}' em {url}",
            "severity": "high",
            "status": "observation",
            "asset": url,
            "evidence": [str(summary_path.relative_to(directory))],
            "reproduced": False,
            "negative_control": False,
            "created_at": redlensctl.iso(),
            "metadata": item,
        })

    redlensctl.append_event(directory, "massassignment.tested", {
        "url": url,
        "fields": len(comparisons),
        "differences": len(findings),
    })

    return {
        "ok": True,
        "summary": str(summary_path.relative_to(directory)),
        "differences": [c["field"] for c in comparisons if c["differs"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="massassign-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--skip-field", action="append", default=[])
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = analyze(args.run, args.spec, args.role, args.skip_field)
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