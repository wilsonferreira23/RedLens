#!/usr/bin/env python3
"""Scoped, authenticated request replay per role without arbitrary shell."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "runtime" / "kali-workspace"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ALLOWED_METHODS = SAFE_METHODS | MUTATING_METHODS
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402


def private_spec_path(directory: Path, raw: str) -> Path:
    path = Path(raw)
    path = path.resolve() if path.is_absolute() else (directory / path).resolve()
    if directory.resolve() not in path.parents:
        raise redlensctl.RedLensError("Especificação fora da operação.")
    if not path.is_file():
        raise redlensctl.RedLensError("Especificação de replay ausente.")
    if "evidence/private" not in str(path):
        raise redlensctl.RedLensError("Request-spec deve ficar em evidence/private.")
    return path


def load_spec(path: Path) -> dict:
    spec = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(spec, dict):
        raise redlensctl.RedLensError("Request-spec deve ser um objeto JSON.")
    method = str(spec.get("method", "")).upper()
    if method not in ALLOWED_METHODS:
        raise redlensctl.RedLensError(f"Método não permitido para replay: {method}")
    if not spec.get("url"):
        raise redlensctl.RedLensError("URL é obrigatória na request-spec.")
    if "body" in spec and not isinstance(spec["body"], (str, type(None))):
        raise redlensctl.RedLensError("Body deve ser uma string.")
    if "content_type" in spec and not isinstance(spec["content_type"], (str, type(None))):
        raise redlensctl.RedLensError("Content-Type deve ser uma string.")
    return spec


def classify_access_status(status: int, response_headers: dict | None = None) -> str:
    """Classify an HTTP status for authorization matrix recording.

    Blocked (e.g. rate-limit) and errors are never recorded as 'safe'.
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
        retry_after = response_headers.get("retry-after") or response_headers.get("Retry-After")
        if retry_after:
            return "blocked"
    return "error"


def check_data_extraction(directory: Path, run_id: str, url: str, role: str,
                          object_tenant: str | None, object_owner_role: str | None) -> None:
    try:
        redlensctl.check_data_extraction_approval(
            directory, run_id, url, role, object_tenant, object_owner_role
        )
    except redlensctl.RedLensError as exc:
        raise redlensctl.RedLensError(
            f"Replay de objeto de outro usuário/tenant exige aprovação data-extraction: {exc}"
        ) from exc


def execute_replay(directory: Path, spec: dict, role: str) -> tuple[dict, Path, Path]:
    """Execute replay via Kali worker and copy evidence into the run directory.

    Returns (worker metadata, private_evidence_path, sanitized_evidence_path).
    """
    role = redlensctl.safe_name(role, "Papel")
    url = redlensctl.scoped_url(directory, spec["url"])
    method = spec["method"].upper()
    session_private = directory / "evidence" / "private" / "sessions" / f"{role}.json"
    scope = redlensctl.read_json(directory / "scope" / "scope.json")

    token = uuid.uuid4().hex
    temp = WORKSPACE / ".redlens" / token
    temp.mkdir(parents=True, mode=0o700)
    try:
        temp_session = temp / "session.json"
        if session_private.is_file():
            shutil.copy2(session_private, temp_session)

        config = {
            "method": method,
            "url": url,
            "headers": spec.get("headers", {}),
            "body": spec.get("body"),
            "content_type": spec.get("content_type"),
            "session_path": f"/workspace/.redlens/{token}/session.json",
            "allowed_schemes": scope["allowed_schemes"],
            "allowed_domains": scope["allowed_domains"],
            "allowed_ports": scope["allowed_ports"],
        }
        config_path = temp / "config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        output = temp / "output"

        result = exec_kali(
            [
                "python3", "/workspace/redlens-replay-worker.py",
                "--config", f"/workspace/.redlens/{token}/config.json",
                "--output", f"/workspace/.redlens/{token}/output",
            ],
            timeout=60,
        )
        if result.returncode != 0:
            raise redlensctl.RedLensError(result.stderr.strip() or "Falha no replay.")

        metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_role = "".join(c if c.isalnum() else "-" for c in role)
        suffix = f"{timestamp}-replay-{safe_role}-{metadata['sha256'][:8]}"

        private_dest = directory / "evidence" / "private" / f"{suffix}.json"
        shutil.copy2(output / "private" / "response.json", private_dest)
        sanitized_dest = directory / "evidence" / "sanitized" / f"{suffix}.json"
        shutil.copy2(output / "sanitized" / "meta.json", sanitized_dest)

        return metadata, private_dest, sanitized_dest
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def record_replay_results(
    directory: Path, url: str, method: str, role: str,
    tenant: str | None, object_id: str | None,
    metadata: dict, sanitized_dest: Path,
) -> dict | None:
    """Record access matrix cell and inventory for a replay."""
    cell = None
    if tenant or object_id:
        response_headers = metadata.get("response_headers", {})
        status = classify_access_status(metadata["status"], response_headers)
        cell = redlensctl.record_access(
            directory, url, method, role, status,
            [str(sanitized_dest.relative_to(directory))],
            tenant=tenant, object_id=object_id,
        )
    try:
        redlensctl.record_inventory(
            directory, "endpoint", url, "replay", method=method
        )
    except redlensctl.RedLensError:
        pass
    return cell


def replay_spec(
    run_id: str, spec_path_raw: str, role: str,
    skip_data_extraction_check: bool = False,
) -> dict:
    """High-level replay entry point used by the CLI and by other adapters."""
    directory = redlensctl.run_dir(run_id)
    role = redlensctl.safe_name(role, "Papel")
    spec_path = private_spec_path(directory, spec_path_raw)
    spec = load_spec(spec_path)
    url = redlensctl.scoped_url(directory, spec["url"])

    object_tenant = spec.get("object_tenant")
    object_owner_role = spec.get("object_owner_role")
    if not skip_data_extraction_check:
        check_data_extraction(
            directory, run_id, url, role, object_tenant, object_owner_role
        )

    method = spec["method"].upper()
    if method in MUTATING_METHODS:
        if not redlensctl.valid_risk_approval(directory, "data-mutation", url):
            raise redlensctl.RedLensError(
                f"Método {method} exige aprovação data-mutation."
            )

    metadata, private_dest, sanitized_dest = execute_replay(directory, spec, role)
    tenant = object_tenant
    object_id = spec.get("object_id")
    cell = record_replay_results(
        directory, url, spec["method"].upper(), role,
        tenant, object_id, metadata, sanitized_dest,
    )

    redlensctl.append_event(directory, "replay.executed", {
        "role": role,
        "url": url,
        "method": spec["method"].upper(),
        "status": metadata["status"],
        "private": str(private_dest.relative_to(directory)),
        "sanitized": str(sanitized_dest.relative_to(directory)),
    })

    return {
        "ok": True,
        "role": role,
        "url": url,
        "method": spec["method"].upper(),
        "status": metadata["status"],
        "size": metadata["size"],
        "sha256": metadata["sha256"],
        "truncated": metadata.get("truncated", False),
        "private_evidence": str(private_dest.relative_to(directory)),
        "sanitized_evidence": str(sanitized_dest.relative_to(directory)),
        "access_cell": cell,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="replay-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--skip-data-extraction-check", action="store_true")
    args = parser.parse_args()

    try:
        result = replay_spec(args.run, args.spec, args.role, args.skip_data_extraction_check)
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
