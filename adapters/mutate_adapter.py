#!/usr/bin/env python3
"""Request mutation engine: apply curated payloads to a request and compare responses.

This is the core offensive primitive. It receives a request-spec, mutates one
position with a curated payload, replays both the baseline and the mutated
requests, and records the difference as evidence. The LLM selects the intention
(payload class); the adapter decides the safe execution.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
from shutil import which
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPLAY_SAFE = which("redlens-replay-safe") or "redlens-replay-safe"
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


# Curated payload library. Never accept arbitrary payloads from the LLM.
PAYLOAD_LIBRARY = {
    "sqli-error": "' OR '1'='1",
    "sqli-time": "' OR SLEEP(5) --",
    "xss-html": "<script>alert(1)</script>",
    "xss-attr": "\" onmouseover=alert(1) \"",
    "ssti": "{{7*7}}",
    "cmdi": "; echo redlenscmdi ;",
    "traversal": "../../../etc/passwd",
    "generic": "redlens-mutation-marker",
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
    spec = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or not spec.get("url"):
        raise redlensctl.RedLensError("Request-spec inválido.")
    return spec


def mutate_query(url: str, field: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append((field, payload))
    new_query = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def mutate_body_field(body: str, content_type: str, field: str, payload: str) -> str:
    if content_type and "json" in content_type.lower():
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            raise redlensctl.RedLensError("Body não é JSON válido.") from exc
        if not isinstance(data, dict):
            raise redlensctl.RedLensError("Mutation de body_field exige objeto JSON.")
        data[field] = payload
        return json.dumps(data, ensure_ascii=False)
    if content_type and "x-www-form-urlencoded" in content_type.lower():
        pairs = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
        pairs.append((field, payload))
        return urllib.parse.urlencode(pairs)
    raise redlensctl.RedLensError("Content-Type não suportado para mutation de body_field.")


def mutate_header(spec: dict, field: str, payload: str) -> dict:
    headers = dict(spec.get("headers", {}))
    headers[field] = payload
    return headers


def mutate_path(url: str, segment: str, payload: str) -> str:
    if segment not in url:
        raise redlensctl.RedLensError("Segmento de path não encontrado na URL.")
    return url.replace(segment, payload, 1)


def apply_mutation(spec: dict, position: str, field: str, payload: str) -> dict:
    mutated = dict(spec)
    method = str(spec.get("method", "GET")).upper()
    url = spec["url"]

    if position == "query":
        mutated["url"] = mutate_query(url, field, payload)
    elif position == "body_field":
        content_type = spec.get("content_type") or spec.get("headers", {}).get("Content-Type", "application/json")
        mutated["body"] = mutate_body_field(spec.get("body", ""), content_type, field, payload)
        if "content_type" not in mutated and "Content-Type" not in mutated.get("headers", {}):
            mutated["content_type"] = content_type
    elif position == "header":
        mutated["headers"] = mutate_header(spec, field, payload)
    elif position == "path":
        mutated["url"] = mutate_path(url, field, payload)
    else:
        raise redlensctl.RedLensError(f"Posição de mutation não suportada: {position}")

    return mutated


def write_spec(directory: Path, spec: dict) -> Path:
    spec_dir = directory / "evidence" / "private" / "mutations"
    spec_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _iso()
    safe_payload = re.sub(r"[^a-z0-9-]", "-", spec.get("_mutation_payload_id", "mutation"))
    path = spec_dir / f"{timestamp}-{safe_payload}.json"
    path.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


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


def compare_responses(baseline: dict, mutated: dict) -> dict:
    return {
        "baseline_status": baseline["status"],
        "baseline_size": baseline["size"],
        "mutated_status": mutated["status"],
        "mutated_size": mutated["size"],
        "status_changed": baseline["status"] != mutated["status"],
        "size_changed": baseline["size"] != mutated["size"],
        "differs": baseline["status"] != mutated["status"] or baseline["size"] != mutated["size"],
    }


def _record_finding(
    directory: Path,
    payload_id: str,
    position: str,
    field: str,
    url: str,
    comparison: dict,
    evidence: Path,
) -> None:
    finding_id = redlensctl.safe_id("finding", payload_id, position, field, url)
    redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
        "id": finding_id,
        "title": f"Resposta alterada por mutation ({payload_id}) em {position}/{field}",
        "severity": "medium",
        "status": "observation",
        "asset": url,
        "evidence": [str(evidence.relative_to(directory))],
        "reproduced": False,
        "negative_control": False,
        "created_at": redlensctl.iso(),
        "metadata": {
            "payload_id": payload_id,
            "position": position,
            "field": field,
            "comparison": comparison,
        },
    })


def mutate(
    run_id: str,
    spec_path_raw: str,
    role: str,
    position: str,
    field: str,
    payload_id: str,
    baseline_spec_path: str | None = None,
) -> dict:
    directory = redlensctl.run_dir(run_id)
    redlensctl.safe_name(role, "Papel")

    if payload_id not in PAYLOAD_LIBRARY:
        raise redlensctl.RedLensError(f"Payload não permitido: {payload_id}")
    payload = PAYLOAD_LIBRARY[payload_id]

    original_spec = load_spec(directory, spec_path_raw)
    original_spec["_mutation_payload_id"] = payload_id
    mutated_spec = apply_mutation(original_spec, position, field, payload)

    # The mutated spec will be replayed with a mutating method if applicable.
    # Replay already enforces the data-mutation gate for POST/PUT/PATCH/DELETE.
    mutated_spec_path = write_spec(directory, mutated_spec)

    baseline = run_replay(run_id, spec_path_raw, role)
    mutated = run_replay(run_id, str(mutated_spec_path.relative_to(directory)), role)
    comparison = compare_responses(baseline, mutated)

    summary = {
        "tool": "mutate",
        "target": original_spec["url"],
        "method": original_spec.get("method", "GET"),
        "position": position,
        "field": field,
        "payload_id": payload_id,
        "payload": payload,
        "baseline": {
            "status": baseline["status"],
            "size": baseline["size"],
            "sha256": baseline["sha256"],
            "evidence": baseline["sanitized_evidence"],
        },
        "mutated": {
            "status": mutated["status"],
            "size": mutated["size"],
            "sha256": mutated["sha256"],
            "evidence": mutated["sanitized_evidence"],
        },
        "comparison": comparison,
    }

    sanitized_dir = directory / "evidence" / "sanitized"
    timestamp = _iso()
    summary_path = sanitized_dir / f"{timestamp}-mutate-{payload_id}-{position}.json"
    redlensctl.write_json(summary_path, summary)

    if comparison["differs"]:
        _record_finding(
            directory, payload_id, position, field, original_spec["url"],
            comparison, summary_path,
        )

    redlensctl.append_event(directory, "mutation.tested", {
        "target": original_spec["url"],
        "position": position,
        "field": field,
        "payload_id": payload_id,
        "differs": comparison["differs"],
    })

    return {
        "ok": True,
        "summary": str(summary_path.relative_to(directory)),
        **summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="mutate-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--position", choices=("query", "body_field", "header", "path"), required=True)
    parser.add_argument("--field", required=True)
    parser.add_argument("--payload-id", choices=sorted(PAYLOAD_LIBRARY.keys()), required=True)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = mutate(args.run, args.spec, args.role, args.position, args.field, args.payload_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
