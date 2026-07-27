#!/usr/bin/env python3
"""Authorization-matrix testing adapter: replay per role with negative control."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from shutil import which
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPLAY_SAFE = which("redlens-replay-safe") or "redlens-replay-safe"
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


def classify_access_status(status: int, response_headers: dict | None = None) -> str:
    """Classify HTTP status for the authorization matrix.

    Blocked (rate-limit) and errors are never reported as 'safe'.
    """
    if 200 <= status < 400:
        return "allowed"
    if status in (401, 403):
        return "denied"
    if status == 404:
        return "error"
    if status == 429:
        return "blocked"
    if response_headers:
        if response_headers.get("retry-after") or response_headers.get("Retry-After"):
            return "blocked"
    return "error"


def build_spec(directory: Path, endpoint: str, method: str, tenant: str | None, object_id: str | None) -> Path:
    method = method.upper()
    if method not in ALLOWED_METHODS:
        raise redlensctl.RedLensError(f"Método não permitido para teste de autorização: {method}")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    spec_dir = directory / "evidence" / "private" / "authz-specs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    spec = {
        "method": method,
        "url": endpoint,
        "object_tenant": tenant,
        "object_owner_role": None,
        "object_id": object_id,
    }
    path = spec_dir / f"{timestamp}-{method}.json"
    redlensctl.write_json(path, spec)
    return path


def run_replay(run_id: str, spec_path: str, role: str) -> dict:
    result = subprocess.run(
        [REPLAY_SAFE, "--run", run_id, "--spec", spec_path, "--role", role, "--skip-data-extraction-check"],
        text=True,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise redlensctl.RedLensError(result.stderr.strip() or f"Falha no replay para papel {role}.")
    return json.loads(result.stdout)


def read_sanitized_status(directory: Path, sanitized_relative: str) -> tuple[int, dict]:
    data = redlensctl.read_json(directory / sanitized_relative)
    return int(data["status"]), data.get("response_headers", {})


def ensure_negative_role(directory: Path, run_id: str, role: str) -> None:
    try:
        redlensctl.role_identities(directory, role)
    except redlensctl.RedLensError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(prog="authz-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--role", required=True)
    parser.add_argument("--tenant")
    parser.add_argument("--object-id")
    parser.add_argument("--negative-role", default="none")
    parser.add_argument("--spec")
    parser.add_argument("--skip-data-extraction-check", action="store_true")
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        endpoint = redlensctl.scoped_url(directory, args.endpoint)
        role = redlensctl.safe_name(args.role, "Papel")
        negative_role = redlensctl.safe_name(args.negative_role, "Papel")
        tenant = args.tenant or None
        object_id = args.object_id or None

        if args.spec:
            spec_path = redlensctl.evidence_paths(directory, [args.spec])[0]
            if "evidence/private" not in str(directory / spec_path):
                raise redlensctl.RedLensError("Spec de autorização deve ficar em evidence/private.")
            spec_absolute = directory / spec_path
        else:
            spec_absolute = build_spec(directory, endpoint, args.method, tenant, object_id)
        spec_relative = str(spec_absolute.relative_to(directory))

        # Data-extraction approval is checked against the positive role and the target object.
        spec_data = redlensctl.read_json(spec_absolute)
        object_tenant = spec_data.get("object_tenant") or tenant
        object_owner_role = spec_data.get("object_owner_role")
        if not args.skip_data_extraction_check:
            redlensctl.check_data_extraction(
                directory, args.run, endpoint, role, object_tenant, object_owner_role
            )

        positive = run_replay(args.run, spec_relative, role)
        ensure_negative_role(directory, args.run, negative_role)
        negative = run_replay(args.run, spec_relative, negative_role)

        pos_status, pos_headers = read_sanitized_status(directory, positive["sanitized_evidence"])
        neg_status, neg_headers = read_sanitized_status(directory, negative["sanitized_evidence"])

        pos_classification = classify_access_status(pos_status, pos_headers)
        neg_classification = classify_access_status(neg_status, neg_headers)

        pos_cell = redlensctl.record_access(
            directory, endpoint, args.method.upper(), role, pos_classification,
            [positive["sanitized_evidence"]], tenant=tenant, object_id=object_id,
        )
        neg_cell = redlensctl.record_access(
            directory, endpoint, args.method.upper(), negative_role, neg_classification,
            [negative["sanitized_evidence"]], tenant=tenant, object_id=object_id,
        )

        redlensctl.append_event(directory, "authorization.tested", {
            "endpoint": endpoint,
            "method": args.method.upper(),
            "role": role,
            "negative_role": negative_role,
            "positive_status": pos_classification,
            "negative_status": neg_classification,
        })

        print(json.dumps({
            "ok": True,
            "endpoint": endpoint,
            "method": args.method.upper(),
            "role": role,
            "negative_role": negative_role,
            "positive": {"status": pos_status, "classification": pos_classification, "evidence": positive["sanitized_evidence"]},
            "negative": {"status": neg_status, "classification": neg_classification, "evidence": negative["sanitized_evidence"]},
            "cells": {"positive": pos_cell, "negative": neg_cell},
            "consistent": pos_classification != neg_classification,
        }, ensure_ascii=False, indent=2))
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
