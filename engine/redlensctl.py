#!/usr/bin/env python3
"""Persistent coverage, and quality gates for RedLens."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from redlens_config import load_config  # noqa: E402

CONFIG = load_config()
ROOT = CONFIG.home
RUNS = CONFIG.runs_dir
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_executor import exec_kali  # noqa: E402
from run_store import RunStore, RunStoreError  # noqa: E402
COVERAGE = (
    "surface",
    "authentication",
    "session",
    "authorization",
    "injection",
    "server_side",
    "client_side",
    "files_storage",
    "business_logic",
    "api",
    "configuration",
    "dependencies",
)
COVERAGE_STATUSES = {"pending", "tested-negative", "confirmed", "blocked", "not-applicable"}
INVENTORY_KINDS = {
    "asset", "endpoint", "parameter", "form", "api", "object", "flow", "trust-boundary",
}
TASK_KINDS = {
    "inventory", "browser", "discovery", "authentication", "authorization", "validation",
    "api", "business-logic", "reporting", "cleanup",
}
TASK_STATUSES = {"pending", "running", "completed", "blocked", "failed", "deferred"}
TASK_TRANSITIONS = {
    "pending": {"running", "blocked", "deferred"},
    "running": {"completed", "blocked", "failed", "deferred"},
    "blocked": {"pending", "deferred"},
    "failed": {"pending", "deferred"},
    "completed": set(),
    "deferred": set(),
}
HYPOTHESIS_STATUSES = {"open", "confirmed", "rejected", "inconclusive", "deferred"}
ACCESS_STATUSES = {"allowed", "denied", "error", "blocked"}
RESOURCE_STATUSES = {"created", "cleaned", "blocked"}
RUN_ID_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
STATE_TRANSITIONS = {
    "authorized": {"running", "stopped"},
    "running": {"paused", "stopped", "completed"},
    "paused": {"running", "stopped"},
    "stopped": set(),
    "completed": set(),
}
HEARTBEAT_STALE_SECONDS = 300
MAX_TASK_ATTEMPTS = 3
DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
DESTRUCTIVE_ACTIONS = {"intrusive-scan", "data-mutation", "destructive", "exploit"}


class RedLensError(ValueError):
    pass


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


def emit(data: dict) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def write_raw(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def append_event(directory: Path, event_type: str, payload: dict) -> None:
    """Append an auditable event without accepting arbitrary command output."""
    path = directory / "logs" / "events.jsonl"
    event = {"at": iso(), "type": event_type, "payload": payload}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    os.chmod(path, 0o600)


def safe_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def safe_name(value: str, label: str) -> str:
    result = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")
    if not result:
        raise RedLensError(f"{label} inválido.")
    return result


def _parsed_url(raw: str) -> tuple:
    try:
        parsed = urlparse(raw)
    except ValueError as exc:
        raise RedLensError(f"URL inválida: {raw}") from exc
    scheme = parsed.scheme.lower()
    if not scheme:
        raise RedLensError(f"URL sem protocolo: {raw}")
    host = parsed.hostname
    if not host:
        raise RedLensError(f"URL sem host: {raw}")
    host = host.lower()
    if parsed.username or parsed.password:
        raise RedLensError("URL não deve conter credenciais em linha.")
    port = parsed.port or DEFAULT_SCHEME_PORTS.get(scheme)
    path = parsed.path or "/"
    return parsed, scheme, host, port, path


def _domain_allowed(host: str, target_domain: str, allowed_domains: list[str]) -> bool:
    target_domain = target_domain.lower()
    if host == target_domain or host.endswith("." + target_domain):
        return True
    for domain in allowed_domains:
        domain = domain.lower().strip()
        if domain == "*":
            return True
        if domain.startswith("*."):
            suffix = domain[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        if host == domain:
            return True
    return False


def _load_scope(directory: Path) -> tuple[dict, str, int]:
    scope = read_json(directory / "scope" / "scope.json")
    target_url = scope.get("target", "")
    try:
        _, _, target_domain, target_port, _ = _parsed_url(target_url)
    except RedLensError:
        target_domain = ""
        target_port = None
    return scope, target_domain, target_port


def browser_url_in_scope(directory: Path, url: str) -> bool:
    """Return True if the given URL (e.g. a final browser URL) is in scope."""
    try:
        scope, target_domain, _ = _load_scope(directory)
        parsed, scheme, host, port, _ = _parsed_url(url)
    except RedLensError:
        return False
    allowed_schemes = {s.lower() for s in scope.get("allowed_schemes", ["http", "https"])}
    if scheme not in allowed_schemes:
        return False
    allowed_domains = scope.get("allowed_domains", [])
    if not _domain_allowed(host, target_domain, allowed_domains):
        return False
    allowed_ports = set(scope.get("allowed_ports", [80, 443]))
    if port not in allowed_ports:
        return False
    return True


def redirect_in_scope(directory: Path, url: str) -> bool:
    """Return only True/False whether a redirect target is in scope; do not follow."""
    return browser_url_in_scope(directory, url)


def scoped_url(directory: Path, raw: str) -> str:
    """Validate and return a normalized URL that is within the operation scope.

    Raises RedLensError for out-of-scope protocol, domain, port, or URL shape.
    """
    scope, target_domain, _ = _load_scope(directory)
    parsed, scheme, host, port, path = _parsed_url(raw)

    allowed_schemes = {s.lower() for s in scope.get("allowed_schemes", ["http", "https"])}
    if scheme not in allowed_schemes:
        raise RedLensError(
            f"Protocolo {scheme!r} fora do escopo. Permitidos: {sorted(allowed_schemes)}"
        )

    allowed_domains = scope.get("allowed_domains", [])
    if not _domain_allowed(host, target_domain, allowed_domains):
        raise RedLensError(
            f"Domínio {host!r} fora do escopo autorizado (alvo: {target_domain})."
        )

    allowed_ports = set(scope.get("allowed_ports", [80, 443]))
    if port not in allowed_ports:
        raise RedLensError(
            f"Porta {port} fora do escopo. Permitidas: {sorted(allowed_ports)}"
        )

    netloc = host
    if parsed.port is not None:
        netloc += f":{parsed.port}"
    normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))
    return normalized


def run_dir(run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise RedLensError("Identificador de operação inválido.")
    directory = (RUNS / run_id).resolve()
    if not directory.is_dir():
        raise RedLensError(f"Operação não encontrada: {run_id}")
    return directory


def lock_path(directory: Path) -> Path:
    return directory / "state" / ".lock"


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, ValueError):
        return False
    except PermissionError:
        return True
    return True


def acquire_run_lock(directory: Path) -> None:
    path = lock_path(directory)
    current_pid = os.getpid()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            pid = int(data.get("pid", 0))
            locked_at = datetime.fromisoformat(data.get("locked_at", ""))
        except (json.JSONDecodeError, ValueError, KeyError):
            pid = 0
            locked_at = datetime.min.replace(tzinfo=timezone.utc)
        if pid == current_pid:
            path.write_text(json.dumps({"pid": current_pid, "locked_at": iso()}), encoding="utf-8")
            os.chmod(path, 0o600)
            return
        age = (now() - locked_at).total_seconds()
        if age < HEARTBEAT_STALE_SECONDS and _process_alive(pid):
            raise RedLensError(f"Operação bloqueada pelo processo {pid}.")
    path.write_text(json.dumps({"pid": current_pid, "locked_at": iso()}), encoding="utf-8")
    os.chmod(path, 0o600)


def release_run_lock(directory: Path) -> None:
    path = lock_path(directory)
    if path.is_file():
        path.unlink()


def role_identities(directory: Path, role: str) -> list[dict]:
    role = safe_name(role, "Papel")
    result = []
    for path in (directory / "identities").glob("*.json"):
        item = read_json(path)
        if item.get("role") == role:
            result.append(item)
    return result


def valid_risk_approval(directory: Path, action: str, target: str) -> str:
    """Return a deterministic approval token if the action/target is authorized.

    Raises RedLensError if the operation is unauthorized, the target is out of
    scope, or a destructive action is requested without explicit authorization.
    """
    auth = read_json(directory / "authorization" / "authorization.json")
    state = read_json(directory / "state" / "state.json")
    if not auth.get("authorized"):
        raise RedLensError("Operação não autorizada.")

    scoped_url(directory, target)

    destructive = action in DESTRUCTIVE_ACTIONS
    if destructive and not auth.get("destructive_authorized"):
        raise RedLensError(f"Ação destrutiva {action!r} não autorizada.")

    token_input = f"{state.get('run_id', '')}:{action}:{target}"
    token = "risk-approval-" + hashlib.sha256(token_input.encode("utf-8")).hexdigest()[:16]
    return token


def require_risk_approval(directory: Path, action: str, target: str) -> str:
    """Convenience wrapper that always raises on missing risk approval."""
    return valid_risk_approval(directory, action, target)


def check_data_extraction_approval(
    directory: Path, run_id: str, target: str, role: str,
    object_tenant: str | None, object_owner_role: str | None
) -> str:
    """Return an approval token for data extraction, or raise RedLensError."""
    auth = read_json(directory / "authorization" / "authorization.json")
    scope = read_json(directory / "scope" / "scope.json")
    state = read_json(directory / "state" / "state.json")

    if not auth.get("authorized"):
        raise RedLensError("Operação não autorizada.")
    if state.get("run_id") != run_id:
        raise RedLensError("run_id não corresponde à operação.")

    impact_level = auth.get("impact_level") or scope.get("impact_level") or "medium"
    if impact_level == "low":
        raise RedLensError("Nível de impacto low não permite extração de dados.")

    allowed_roles = (
        set(scope.get("accounts", []))
        | set(auth.get("accounts", []))
        | set(scope.get("role_allowlist", []))
    )
    role_clean = safe_name(role, "Papel")
    if allowed_roles and role_clean not in allowed_roles:
        raise RedLensError(f"Papel {role_clean!r} não está na lista de contas autorizadas.")

    scoped_url(directory, target)

    cross_tenant = bool(object_tenant) or bool(object_owner_role)
    if cross_tenant:
        append_event(directory, "data-extraction.cross-tenant", {
            "run_id": run_id,
            "role": role_clean,
            "target": target,
            "object_tenant": object_tenant,
            "object_owner_role": object_owner_role,
        })
        mode = auth.get("mode") or scope.get("mode") or "standard"
        if mode == "quick":
            raise RedLensError("Acesso cross-tenant/object-owner não permitido em modo quick.")

    token_input = (
        f"{run_id}:data-extraction:{target}:{role_clean}:"
        f"{object_tenant or ''}:{object_owner_role or ''}"
    )
    token = "data-extraction-" + hashlib.sha256(token_input.encode("utf-8")).hexdigest()[:16]
    return token


def refresh_heartbeat(directory: Path, next_action: str | None = None) -> None:
    state_path = directory / "state" / "state.json"
    state = read_json(state_path)
    state["heartbeat_at"] = iso()
    state["updated_at"] = iso()
    if next_action:
        state["next_action"] = next_action
    write_json(state_path, state)


def is_heartbeat_stale(directory: Path) -> bool:
    state = read_json(directory / "state" / "state.json")
    heartbeat_at = state.get("heartbeat_at")
    if not heartbeat_at:
        return True
    return (now() - datetime.fromisoformat(heartbeat_at)).total_seconds() > HEARTBEAT_STALE_SECONDS


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RedLensError(f"Arquivo obrigatório ausente: {path}") from exc


def _target_scope_parts(target: str) -> tuple[str, int, list[str], list[int]]:
    """Derive domain, port, schemes and ports allowed for a target URL."""
    _, scheme, host, port, _ = _parsed_url(target)
    allowed_schemes = sorted({scheme, "http", "https"})
    allowed_ports = sorted({port, 80, 443})
    return host, port, allowed_schemes, allowed_ports


def command_init(args: argparse.Namespace) -> None:
    if not args.authorized:
        raise RedLensError("Autorização explícita é obrigatória antes de criar a operação.")
    if not args.target.startswith("http"):
        raise RedLensError("O alvo deve ser uma URL HTTP ou HTTPS completa.")

    target_domain, target_port, allowed_schemes, allowed_ports = _target_scope_parts(args.target)

    categories = []
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",") if c.strip()]
        invalid = [c for c in categories if c not in COVERAGE]
        if invalid:
            raise RedLensError(f"Categorias inválidas: {', '.join(invalid)}")
    else:
        categories = list(COVERAGE)

    accounts = [a.strip() for a in args.accounts.split(",") if a.strip()] if args.accounts else []
    prohibited_techniques = [
        item.strip() for item in args.prohibited_techniques.split(",") if item.strip()
    ]
    credentials = "available" if args.credentials_available == "yes" else "none"

    run_id = f"run-{now():%Y%m%dT%H%M%SZ}"
    directory = RUNS / run_id
    directory.mkdir(parents=True, mode=0o700)
    for name in (
        "authorization", "scope", "state", "plan", "inventory", "tasks", "hypotheses",
        "identities", "resources", "evidence/raw", "evidence/private", "evidence/sanitized",
        "findings", "attack-graph", "logs", "reports",
    ):
        (directory / name).mkdir(parents=True, exist_ok=True)
    write_json(directory / "authorization" / "authorization.json", {
        "authorized": True,
        "confirmed_at": iso(),
        "environment": args.environment,
        "mode": args.mode,
        "destructive_authorized": args.destructive_authorized,
        "max_rps": args.max_rps,
        "rate_window": args.rate_window,
        "categories": categories,
        "impact_level": args.impact_level,
        "accounts": accounts,
        "credentials": credentials,
        "prohibited_techniques": prohibited_techniques,
        "report_format": args.report_format,
    })
    write_json(directory / "scope" / "scope.json", {
        "target": args.target,
        "allowed_schemes": allowed_schemes,
        "allowed_domains": [target_domain],
        "allowed_ports": allowed_ports,
        "environment": args.environment,
        "mode": args.mode,
        "max_rps": args.max_rps,
        "rate_window": args.rate_window,
        "categories": categories,
        "impact_level": args.impact_level,
        "accounts": accounts,
        "credentials": credentials,
        "prohibited_techniques": prohibited_techniques,
        "report_format": args.report_format,
    })
    write_json(directory / "state" / "state.json", {
        "schema_version": 2,
        "run_id": run_id,
        "status": "authorized",
        "created_at": iso(),
        "updated_at": iso(),
        "heartbeat_at": None,
        "next_action": "Inventariar o alvo autorizado.",
        "last_error": None,
    })
    write_json(directory / "state" / "coverage.json", {
        "schema_version": 2,
        "categories": {category: {"status": "pending", "summary": "", "evidence": []}
                       for category in COVERAGE}
    })
    write_json(directory / "state" / "access-matrix.json", {"schema_version": 2, "cells": {}})
    write_json(directory / "state" / "resources.json", {"schema_version": 2, "items": {}})
    write_json(directory / "state" / "schema.json", {
        "schema_version": 2,
        "documents": [
            "authorization/authorization.json",
            "scope/scope.json",
            "state/state.json",
            "state/coverage.json",
            "state/access-matrix.json",
            "state/resources.json",
        ],
    })
    append_event(directory, "operation.created", {"run_id": run_id})
    emit({"ok": True, "run_id": run_id, "directory": str(directory)})


def command_migrate(args: argparse.Namespace) -> None:
    try:
        result = RunStore().migrate(args.run, dry_run=args.dry_run)
    except RunStoreError as exc:
        raise RedLensError(str(exc)) from exc
    emit(result)


SECRET_PATTERNS = {
    "bearer_token": re.compile(r"(?i)bearer\s+[a-z0-9_\-\.]{20,}"),
    "api_key": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-z0-9_\-\.]{16,}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "session_cookie": re.compile(r"(?i)(session|token)=[a-z0-9]{16,}"),
    "password_in_url": re.compile(r"[a-z]+://[^:/@]+:[^/@]+@"),
}
SENSITIVE_PATHS = {"evidence/private", "evidence/raw"}


def scan_for_secrets(directory: Path) -> list[dict]:
    matches = []
    for root_str, _, files in os.walk(directory):
        root_path = Path(root_str)
        rel = root_path.relative_to(directory)
        if any(str(rel).startswith(private) for private in SENSITIVE_PATHS):
            continue
        for name in files:
            file_path = root_path / name
            if not file_path.is_file():
                continue
            try:
                file_text = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            for label, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(file_text):
                    matches.append({
                        "file": str(file_path.relative_to(directory)),
                        "type": label,
                        "position": match.start(),
                    })
    return matches


def _docker_version(tool: list[str]) -> str:
    try:
        result = exec_kali(tool, timeout=10)
        return (result.stdout.strip() or result.stderr.strip() or "unknown").splitlines()[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return "unavailable"


TOOL_MANIFEST_COMMANDS = {
    "cloakbrowser": ["python3", "-c", "import cloakbrowser; print(cloakbrowser.__version__)"],
    "python": ["python3", "--version"],
    "whatweb": ["whatweb", "--version"],
    "wafw00f": ["wafw00f", "--version"],
    "httpx": ["httpx-toolkit", "-version"],
    "katana": ["katana", "-version"],
    "nuclei": ["nuclei", "-version"],
    "sslscan": ["sslscan", "--version"],
    "ffuf": ["ffuf", "-V"],
    "feroxbuster": ["feroxbuster", "--version"],
    "arjun": ["arjun", "-h"],
    "nikto": ["nikto", "-Version"],
}


def collect_tool_manifest(directory: Path) -> dict:
    manifest = {"collected_at": iso(), "tools": {}}
    for name, command in TOOL_MANIFEST_COMMANDS.items():
        manifest["tools"][name] = _docker_version(command)
    try:
        result = subprocess.run(["docker", "--version"], text=True, capture_output=True, timeout=10)
        manifest["tools"]["docker"] = (result.stdout.strip() or result.stderr.strip() or "unknown").splitlines()[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        manifest["tools"]["docker"] = "unavailable"
    manifest["tools"]["redlensctl"] = "redlensctl schema-v2"
    path = directory / "evidence" / "sanitized" / "tool-manifest.json"
    write_json(path, manifest)
    return manifest


def artifact_hashes(directory: Path) -> dict:
    hashes = {"generated_at": iso(), "files": {}}
    for subdir in ("evidence/raw", "evidence/sanitized"):
        for file_path in sorted((directory / subdir).rglob("*")):
            if not file_path.is_file():
                continue
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            hashes["files"][str(file_path.relative_to(directory))] = digest
    path = directory / "evidence" / "sanitized" / "artifact-hashes.json"
    write_json(path, hashes)
    return hashes


def event_timeline(directory: Path) -> list[dict]:
    path = directory / "logs" / "events.jsonl"
    if not path.is_file():
        return []
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def browser_degraded_status(directory: Path) -> dict:
    degraded = False
    reasons = []
    for path in (directory / "evidence" / "raw").rglob("metadata.json"):
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        backend = meta.get("backend", "")
        if backend and backend != "cloakbrowser":
            degraded = True
            reasons.append(f"{path.relative_to(directory)}: backend={backend}")
        if meta.get("requires_human_intervention"):
            reasons.append(f"{path.relative_to(directory)}: human_intervention")
    return {"degraded": degraded, "reasons": reasons}


def command_transition(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    state_path = directory / "state" / "state.json"
    state = read_json(state_path)
    if args.status not in STATE_TRANSITIONS.get(state["status"], set()):
        raise RedLensError(f"Transição inválida: {state['status']} → {args.status}")
    if args.status == "running":
        acquire_run_lock(directory)
        state["heartbeat_at"] = iso()
    if args.status in {"completed", "stopped"}:
        release_run_lock(directory)
    if args.status == "completed":
        import coverage_cells
        coverage_cells.assert_no_open_cells(directory)
        assert_quality(directory)
    state["status"] = args.status
    state["updated_at"] = iso()
    write_json(state_path, state)
    emit({"ok": True, "run_id": args.run, "status": args.status})


def command_heartbeat(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    acquire_run_lock(directory)
    refresh_heartbeat(directory, args.next_action)
    emit({"ok": True, "run_id": args.run, "heartbeat_at": iso()})


def command_resume(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    state_path = directory / "state" / "state.json"
    state = read_json(state_path)
    if state["status"] not in {"running", "paused"} and not is_heartbeat_stale(directory):
        raise RedLensError("A operação não está interrompida ou stale.")
    acquire_run_lock(directory)
    reset = []
    for path in (directory / "tasks").glob("*.json"):
        item = read_json(path)
        if item["status"] in {"running", "failed"} and item["attempt"] < MAX_TASK_ATTEMPTS:
            item["status"] = "pending"
            item["summary"] = "Reativada após interrupção."
            item["updated_at"] = iso()
            write_json(path, item)
            reset.append(item["id"])
    state["status"] = "running"
    state["heartbeat_at"] = iso()
    state["updated_at"] = iso()
    state["last_error"] = None
    write_json(state_path, state)
    append_event(directory, "operation.resumed", {"reset_tasks": reset})
    emit({"ok": True, "run_id": args.run, "reset_tasks": reset, "status": "running"})





def evidence_paths(directory: Path, values: list[str]) -> list[str]:
    result = []
    for value in values:
        path = Path(value)
        path = path.resolve() if path.is_absolute() else (directory / path).resolve()
        if directory.resolve() not in path.parents or not path.is_file():
            raise RedLensError(f"Evidência ausente ou fora da operação: {value}")
        result.append(str(path.relative_to(directory)))
    return result


def command_record_coverage(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    coverage_path = directory / "state" / "coverage.json"
    coverage = read_json(coverage_path)
    evidence = evidence_paths(directory, args.evidence or [])
    if args.status == "confirmed" and not evidence:
        raise RedLensError("Cobertura confirmada precisa de evidência.")
    coverage["categories"][args.category] = {
        "status": args.status,
        "summary": args.summary,
        "evidence": evidence,
        "updated_at": iso(),
    }
    write_json(coverage_path, coverage)
    emit({"ok": True, "category": args.category, "status": args.status})


def command_add_finding(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    evidence = evidence_paths(directory, args.evidence)
    if args.status == "confirmed" and not evidence:
        raise RedLensError("Achado confirmado precisa de evidência.")
    if args.status == "confirmed" and args.severity in {"high", "critical"}:
        if not args.reproduced or not args.negative_control:
            raise RedLensError("Achado alto/crítico exige reprodução e controle negativo.")
    finding_id = re.sub(r"[^A-Za-z0-9._-]+", "-", args.id).strip("-")
    if not finding_id:
        raise RedLensError("Identificador de achado inválido.")
    write_json(directory / "findings" / f"{finding_id}.json", {
        "id": finding_id,
        "title": args.title,
        "severity": args.severity,
        "status": args.status,
        "asset": args.asset,
        "evidence": evidence,
        "reproduced": bool(args.reproduced),
        "negative_control": bool(args.negative_control),
        "created_at": iso(),
    })
    emit({"ok": True, "finding_id": finding_id, "status": args.status})


def record_inventory(
    directory: Path, kind: str, value: str, source: str, method: str | None = None,
    parent: str | None = None,
    reachability: str | None = None,
    metadata: dict | None = None,
) -> tuple[str, bool, dict]:
    value = value.strip()
    if not value:
        raise RedLensError("Valor do inventário não pode ser vazio.")
    if source in ("browser", "tool") and value.startswith(("http", "ws")):
        require_risk_approval(directory, "inventory", value)
    item_id = safe_id(kind, method or "", value)
    path = directory / "inventory" / f"{item_id}.json"
    existed = path.is_file()
    item = read_json(path) if existed else {
        "id": item_id,
        "kind": kind,
        "value": value,
        "method": method or None,
        "parent": parent or None,
        "sources": [],
        "reachability": reachability or "unknown",
        "metadata": metadata or {},
        "created_at": iso(),
    }
    if source not in item["sources"]:
        item["sources"].append(source)
    if reachability and item.get("reachability") in {"unknown", None} and reachability != "unknown":
        item["reachability"] = reachability
    if metadata:
        item.setdefault("metadata", {}).update(metadata)
    item["updated_at"] = iso()
    write_json(path, item)
    return item_id, existed, item


def command_add_inventory(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    item_id, existed, item = record_inventory(
        directory, args.kind, args.value, args.source, args.method, args.parent
    )
    append_event(directory, "inventory.recorded", {"id": item_id, "kind": args.kind})
    emit({"ok": True, "item_id": item_id, "deduplicated": existed, "item": item})


def command_add_identity(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    role = safe_name(args.role, "Papel")
    identity_id = safe_id("identity", role, args.tenant or "", args.label)
    item = {
        "id": identity_id,
        "role": role,
        "tenant": args.tenant or None,
        "label": args.label,
        "created_at": iso(),
    }
    write_json(directory / "identities" / f"{identity_id}.json", item)
    append_event(directory, "identity.recorded", {"id": identity_id, "role": role})
    emit({"ok": True, "identity": item})


def command_add_hypothesis(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    hypothesis_id = safe_id("hypothesis", args.assumption, args.target or "")
    item = {
        "id": hypothesis_id,
        "assumption": args.assumption,
        "impact": args.impact,
        "evidence_needed": args.evidence_needed,
        "safe_test": args.safe_test,
        "risk_gate": args.risk_gate or None,
        "target": args.target or None,
        "status": "open",
        "created_at": iso(),
        "updated_at": iso(),
    }
    write_json(directory / "hypotheses" / f"{hypothesis_id}.json", item)
    append_event(directory, "hypothesis.recorded", {"id": hypothesis_id})
    emit({"ok": True, "hypothesis": item})


def command_update_hypothesis(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    hypothesis_id = safe_name(args.hypothesis, "Hipótese")
    path = directory / "hypotheses" / f"{hypothesis_id}.json"
    item = read_json(path)
    if args.status not in HYPOTHESIS_STATUSES:
        raise RedLensError("Estado da hipótese inválido.")
    item["status"] = args.status
    item["summary"] = args.summary
    item["updated_at"] = iso()
    write_json(path, item)
    append_event(directory, "hypothesis.updated", {"id": hypothesis_id, "status": args.status})
    emit({"ok": True, "hypothesis": item})


def command_add_task(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    task_id = safe_id("task", args.kind, args.title, args.target or "")
    path = directory / "tasks" / f"{task_id}.json"
    if path.is_file():
        item = read_json(path)
    else:
        item = {
            "id": task_id,
            "kind": args.kind,
            "title": args.title,
            "target": args.target or None,
            "inventory_id": args.inventory_id or None,
            "hypothesis_id": args.hypothesis_id or None,
            "status": "pending",
            "attempt": 0,
            "created_at": iso(),
        }
    item["updated_at"] = iso()
    write_json(path, item)
    append_event(directory, "task.recorded", {"id": task_id, "kind": args.kind})
    emit({"ok": True, "task": item})


def command_update_task(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    task_id = safe_name(args.task, "Tarefa")
    path = directory / "tasks" / f"{task_id}.json"
    item = read_json(path)
    if args.status not in TASK_TRANSITIONS[item["status"]]:
        raise RedLensError(f"Transição inválida da tarefa: {item['status']} → {args.status}")
    if args.status == "running":
        if item["attempt"] >= MAX_TASK_ATTEMPTS:
            raise RedLensError(
                f"Tarefa {task_id} atingiu o limite de {MAX_TASK_ATTEMPTS} tentativas; "
                "registre como blocked ou deferred."
            )
        item["attempt"] += 1
        item["started_at"] = iso()
    item["status"] = args.status
    item["summary"] = args.summary
    item["next_action"] = args.next_action or None
    item["updated_at"] = iso()
    write_json(path, item)
    state_path = directory / "state" / "state.json"
    state = read_json(state_path)
    state["heartbeat_at"] = iso()
    state["next_action"] = item["next_action"] or args.summary
    state["last_error"] = args.summary if args.status == "failed" else None
    state["updated_at"] = iso()
    write_json(state_path, state)
    append_event(directory, "task.updated", {"id": task_id, "status": args.status})
    emit({"ok": True, "task": item})


def record_access(
    directory: Path, endpoint: str, method: str, role: str, status: str,
    evidence_values: list[str], tenant: str | None = None, object_id: str | None = None,
) -> dict:
    require_risk_approval(directory, "access-test", endpoint)
    role = safe_name(role, "Papel")
    evidence = evidence_paths(directory, evidence_values)
    if status == "allowed" and not evidence:
        raise RedLensError("Acesso permitido precisa de evidência.")
    key = "|".join((endpoint, method.upper(), role, tenant or "", object_id or ""))
    path = directory / "state" / "access-matrix.json"
    matrix = read_json(path)
    matrix["cells"][key] = {
        "endpoint": endpoint,
        "method": method.upper(),
        "role": role,
        "tenant": tenant or None,
        "object_id": object_id or None,
        "status": status,
        "evidence": evidence,
        "updated_at": iso(),
    }
    write_json(path, matrix)
    return matrix["cells"][key]


def command_record_access(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    cell = record_access(
        directory, args.endpoint, args.method, args.role, args.status, args.evidence or [],
        args.tenant, args.object_id,
    )
    append_event(directory, "access.recorded", {"status": args.status, "role": cell["role"]})
    emit({"ok": True, "cell": cell})


def record_session(directory: Path, role: str, backend: str, state_path: Path) -> dict:
    role = safe_name(role, "Papel")
    path = directory / "state" / "sessions.json"
    sessions = read_json(path) if path.is_file() else {"roles": {}}
    item = {
        "role": role,
        "backend": backend,
        "private_state": str(state_path.relative_to(directory)),
        "updated_at": iso(),
    }
    sessions["roles"][role] = item
    write_json(path, sessions)
    return item


def command_record_resource(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    resource_id = safe_id("resource", args.kind, args.label)
    path = directory / "resources" / f"{resource_id}.json"
    item = {
        "id": resource_id,
        "kind": args.kind,
        "label": args.label,
        "cleanup": args.cleanup,
        "status": "created",
        "created_at": iso(),
        "updated_at": iso(),
    }
    write_json(path, item)
    resources_path = directory / "state" / "resources.json"
    resources = read_json(resources_path)
    resources["items"][resource_id] = {"status": "created", "updated_at": iso()}
    write_json(resources_path, resources)
    append_event(directory, "resource.recorded", {"id": resource_id, "kind": args.kind})
    emit({"ok": True, "resource": item})


def command_cleanup_resource(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    resource_id = safe_name(args.resource, "Recurso")
    path = directory / "resources" / f"{resource_id}.json"
    item = read_json(path)
    if item["status"] != "created":
        raise RedLensError("Recurso já foi finalizado.")
    item["status"] = args.status
    item["summary"] = args.summary
    item["updated_at"] = iso()
    write_json(path, item)
    resources_path = directory / "state" / "resources.json"
    resources = read_json(resources_path)
    resources["items"][resource_id] = {"status": args.status, "updated_at": iso()}
    write_json(resources_path, resources)
    append_event(directory, "resource.cleaned", {"id": resource_id, "status": args.status})
    emit({"ok": True, "resource": item})


def command_status(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    tasks = [read_json(path) for path in (directory / "tasks").glob("*.json")]
    hypotheses = [read_json(path) for path in (directory / "hypotheses").glob("*.json")]
    resources = [read_json(path) for path in (directory / "resources").glob("*.json")]
    matrix = read_json(directory / "state" / "access-matrix.json")
    emit({
        "ok": True,
        "state": read_json(directory / "state" / "state.json"),
        "scope": read_json(directory / "scope" / "scope.json"),
        "coverage": read_json(directory / "state" / "coverage.json"),
        "findings": len(list((directory / "findings").glob("*.json"))),
        "inventory": len(list((directory / "inventory").glob("*.json"))),
        "tasks": {status: sum(item["status"] == status for item in tasks) for status in TASK_STATUSES},
        "hypotheses": {status: sum(item["status"] == status for item in hypotheses)
                       for status in HYPOTHESIS_STATUSES},
        "access_matrix_cells": len(matrix["cells"]),
        "resources": {status: sum(item["status"] == status for item in resources)
                      for status in RESOURCE_STATUSES},
    })


def command_quality_gate(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    assert_quality(directory)
    emit({"ok": True, "quality_gate": "passed", "run_id": args.run})


def command_score(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    from score import score_run
    result = score_run(args.run)
    emit({"ok": True, "score": result})


def command_plan(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    from coverage_cells import plan_next
    result = plan_next(args.run, args.limit)
    emit({"ok": True, **result})


def command_capabilities(args: argparse.Namespace) -> None:
    sys.path.insert(0, str(ROOT / "adapters"))
    import capability_registry
    emit({"ok": True, "capabilities": capability_registry.capabilities_metadata()})


def command_report(args: argparse.Namespace) -> None:
    directory = run_dir(args.run)
    assert_quality(directory)
    scope = read_json(directory / "scope" / "scope.json")
    coverage = read_json(directory / "state" / "coverage.json")["categories"]
    matrix = read_json(directory / "state" / "access-matrix.json")["cells"]
    tasks = [read_json(path) for path in sorted((directory / "tasks").glob("*.json"))]
    findings = [read_json(path) for path in sorted((directory / "findings").glob("*.json"))]
    confirmed = [item for item in findings if item["status"] == "confirmed"]
    manifest = collect_tool_manifest(directory)
    hashes = artifact_hashes(directory)
    timeline = event_timeline(directory)
    browser_status = browser_degraded_status(directory)
    gaps = {
        "pending_coverage": [name for name, item in coverage.items() if item["status"] == "pending"],
        "blocked_tasks": [item["title"] for item in tasks if item["status"] == "blocked"],
        "deferred_tasks": [item["title"] for item in tasks if item["status"] == "deferred"],
        "browser_degraded": browser_status["degraded"],
        "browser_reasons": browser_status["reasons"],
    }
    executive = [
        "# Relatorio executivo RedLens",
        "",
        f"- Operacao: `{args.run}`",
        f"- Alvo autorizado: `{scope.get('target', 'N/A')}`",
        f"- Achados confirmados: {len(confirmed)}",
        f"- Cobertura concluida: {len(coverage) - len(gaps['pending_coverage'])}/{len(COVERAGE)} categorias",
        f"- Celulas de autorizacao registradas: {len(matrix)}",
        f"- Browser degradado: {'sim' if gaps['browser_degraded'] else 'nao'}",
        "",
        "## Achados confirmados",
        "",
    ]
    if confirmed:
        executive.extend(
            f"- **{item['severity'].upper()}** — {item['title']} (`{item['asset']}`)"
            for item in confirmed
        )
    else:
        executive.append("- Nenhum achado confirmado.")
    if gaps["browser_degraded"]:
        executive.extend(["", "## Modo degradado", ""])
        executive.extend(f"- {reason}" for reason in gaps["browser_reasons"])
    if gaps["blocked_tasks"] or gaps["deferred_tasks"] or gaps["pending_coverage"]:
        executive.extend(["", "## Lacunas explícitas", ""])
        if gaps["pending_coverage"]:
            executive.append(f"- Cobertura pendente: {', '.join(gaps['pending_coverage'])}")
        if gaps["blocked_tasks"]:
            executive.append(f"- Tarefas bloqueadas: {', '.join(gaps['blocked_tasks'])}")
        if gaps["deferred_tasks"]:
            executive.append(f"- Tarefas adiadas: {', '.join(gaps['deferred_tasks'])}")

    technical = [
        "# Relatório técnico RedLens",
        "",
        f"## Escopo",
        "",
        f"- Alvo: `{scope.get('target', 'N/A')}`",
        "",
        "## Cobertura",
        "",
        "| Categoria | Estado | Resumo |",
        "|---|---|---|",
    ]
    for category, item in coverage.items():
        summary = item["summary"].replace("|", "\\|")
        technical.append(f"| {category} | {item['status']} | {summary} |")
    technical.extend(["", "## Achados", ""])
    if findings:
        for item in findings:
            technical.extend([
                f"### {item['id']} — {item['title']}",
                "",
                f"- Severidade: `{item['severity']}`",
                f"- Estado: `{item['status']}`",
                f"- Ativo: `{item['asset']}`",
                f"- Reproduzido: {'sim' if item.get('reproduced') else 'não'}",
                f"- Controle negativo: {'sim' if item.get('negative_control') else 'não'}",
                f"- Evidências: {', '.join(f'`{path}`' for path in item['evidence']) or 'nenhuma'}",
                "",
            ])
    else:
        technical.append("Nenhum achado registrado.")
    technical.extend(["", "## Tarefas", ""])
    if tasks:
        technical.extend(f"- `{item['status']}` — {item['title']}" for item in tasks)
    else:
        technical.append("Nenhuma tarefa registrada.")
    technical.extend(["", "## Matriz de autorização", ""])
    if matrix:
        technical.extend([
            "| Endpoint | Método | Papel | Tenant | Objeto | Resultado |",
            "|---|---|---|---|---|---|",
        ])
        for item in matrix.values():
            technical.append(
                f"| {item['endpoint']} | {item['method']} | {item['role']} | "
                f"{item.get('tenant') or '-'} | {item.get('object_id') or '-'} | {item['status']} |"
            )
    else:
        technical.append("Nenhuma célula de autorização registrada.")
    technical.extend(["", "## Manifesto de ferramentas", ""])
    for name, version in manifest["tools"].items():
        technical.append(f"- `{name}`: {version}")
    technical.extend(["", "## Hashes de artefatos", ""])
    technical.append(f"Arquivos indexados: {len(hashes['files'])}")
    technical.extend(["", "## Timeline de eventos", ""])
    if timeline:
        for event in timeline[:100]:
            technical.append(f"- `{event['at']}` — {event['type']}")
    else:
        technical.append("Nenhum evento registrado.")
    if gaps["browser_degraded"]:
        technical.extend(["", "## Browser degradado", ""])
        technical.extend(f"- {reason}" for reason in gaps["browser_reasons"])
    technical.extend(["", "## Lacunas", ""])
    if gaps["pending_coverage"]:
        technical.append(f"- Cobertura pendente: {', '.join(gaps['pending_coverage'])}")
    if gaps["blocked_tasks"]:
        technical.append(f"- Tarefas bloqueadas: {', '.join(gaps['blocked_tasks'])}")
    if gaps["deferred_tasks"]:
        technical.append(f"- Tarefas adiadas: {', '.join(gaps['deferred_tasks'])}")
    if not any((gaps["pending_coverage"], gaps["blocked_tasks"], gaps["deferred_tasks"])):
        technical.append("- Nenhuma lacuna registrada.")
    executive_path = directory / "reports" / "executive.md"
    technical_path = directory / "reports" / "technical.md"
    executive_path.write_text("\n".join(executive) + "\n", encoding="utf-8")
    technical_path.write_text("\n".join(technical) + "\n", encoding="utf-8")
    os.chmod(executive_path, 0o600)
    os.chmod(technical_path, 0o600)
    emit({
        "ok": True,
        "executive": str(executive_path),
        "technical": str(technical_path),
        "manifest": str(directory / "evidence" / "sanitized" / "tool-manifest.json"),
        "hashes": str(directory / "evidence" / "sanitized" / "artifact-hashes.json"),
    })


def assert_quality(directory: Path) -> None:
    import coverage_cells
    coverage_cells.assert_no_open_cells(directory)
    coverage = read_json(directory / "state" / "coverage.json")["categories"]
    pending = [name for name, item in coverage.items() if item["status"] == "pending"]
    if pending:
        raise RedLensError("Cobertura pendente: " + ", ".join(pending))
    invalid = []
    for path in (directory / "findings").glob("*.json"):
        finding = read_json(path)
        if finding["status"] == "confirmed" and finding["severity"] in {"high", "critical"}:
            if not finding["reproduced"] or not finding["negative_control"] or not finding["evidence"]:
                invalid.append(finding["id"])
    if invalid:
        raise RedLensError("Achados altos/críticos sem validação completa: " + ", ".join(invalid))
    unfinished = []
    for path in (directory / "tasks").glob("*.json"):
        item = read_json(path)
        if item["status"] in {"pending", "running"}:
            unfinished.append(item["id"])
    if unfinished:
        raise RedLensError("Tarefas ainda abertas: " + ", ".join(unfinished))
    pending_cleanup = [
        item["id"] for path in (directory / "resources").glob("*.json")
        if (item := read_json(path))["status"] == "created"
    ]
    if pending_cleanup:
        raise RedLensError("Recursos sem cleanup: " + ", ".join(pending_cleanup))
    matches = scan_for_secrets(directory)
    if matches:
        locations = ", ".join(f"{m['file']} ({m['type']})" for m in matches)
        raise RedLensError("Possível vazamento de segredo detectado: " + locations)


def command_preflight(args: argparse.Namespace) -> None:
    """Executa preflight (diagnostico + auto-heal opcional)."""
    from adapters.preflight import preflight as run_preflight
    result = run_preflight(check_only=args.check_only)
    if not result["ok"]:
        raise RedLensError("Preflight falhou. Corrija os problemas pendentes antes de iniciar.")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="redlensctl")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--target", required=True)
    init.add_argument("--authorized", action="store_true")
    init.add_argument("--environment", choices=("lab", "staging", "production"), default="production")
    init.add_argument("--mode", choices=("quick", "standard", "deep"), default="standard")
    init.add_argument("--max-rps", type=float, default=2.0)
    init.add_argument("--rate-window", type=int, default=60)
    init.add_argument("--categories")
    init.add_argument("--impact-level", choices=("low", "medium", "high", "critical"), default="medium")
    init.add_argument("--accounts")
    init.add_argument("--credentials-available", choices=("yes", "no"), default="no")
    init.add_argument("--destructive-authorized", action="store_true")
    init.add_argument("--prohibited-techniques", default="")
    init.add_argument("--report-format", choices=("executive", "technical", "both"), default="both")
    init.set_defaults(func=command_init)

    migrate = commands.add_parser("migrate")
    migrate.add_argument("--run", required=True)
    migrate.add_argument("--dry-run", action="store_true")
    migrate.set_defaults(func=command_migrate)

    transition = commands.add_parser("transition")
    transition.add_argument("--run", required=True)
    transition.add_argument("--status", choices=("authorized", "running", "paused", "stopped", "completed"),
                            required=True)
    transition.set_defaults(func=command_transition)

    heartbeat = commands.add_parser("heartbeat")
    heartbeat.add_argument("--run", required=True)
    heartbeat.add_argument("--next-action")
    heartbeat.set_defaults(func=command_heartbeat)

    resume = commands.add_parser("resume")
    resume.add_argument("--run", required=True)
    resume.set_defaults(func=command_resume)

    record = commands.add_parser("record-coverage")
    record.add_argument("--run", required=True)
    record.add_argument("--category", choices=COVERAGE, required=True)
    record.add_argument("--status", choices=sorted(COVERAGE_STATUSES - {"pending"}), required=True)
    record.add_argument("--summary", required=True)
    record.add_argument("--evidence", action="append")
    record.set_defaults(func=command_record_coverage)

    finding = commands.add_parser("add-finding")
    finding.add_argument("--run", required=True)
    finding.add_argument("--id", required=True)
    finding.add_argument("--title", required=True)
    finding.add_argument("--severity", choices=("info", "low", "medium", "high", "critical"), required=True)
    finding.add_argument("--status", choices=("observation", "confirmed"), required=True)
    finding.add_argument("--asset", required=True)
    finding.add_argument("--evidence", action="append", default=[])
    finding.add_argument("--reproduced", action="store_true")
    finding.add_argument("--negative-control", action="store_true")
    finding.set_defaults(func=command_add_finding)

    inventory = commands.add_parser("add-inventory")
    inventory.add_argument("--run", required=True)
    inventory.add_argument("--kind", choices=sorted(INVENTORY_KINDS), required=True)
    inventory.add_argument("--value", required=True)
    inventory.add_argument("--method")
    inventory.add_argument("--parent")
    inventory.add_argument("--source", choices=("manual", "browser", "crawler", "tool", "documentation"),
                           required=True)
    inventory.set_defaults(func=command_add_inventory)

    identity = commands.add_parser("add-identity")
    identity.add_argument("--run", required=True)
    identity.add_argument("--role", required=True)
    identity.add_argument("--tenant")
    identity.add_argument("--label", required=True)
    identity.set_defaults(func=command_add_identity)

    hypothesis = commands.add_parser("add-hypothesis")
    hypothesis.add_argument("--run", required=True)
    hypothesis.add_argument("--assumption", required=True)
    hypothesis.add_argument("--impact", required=True)
    hypothesis.add_argument("--evidence-needed", required=True)
    hypothesis.add_argument("--safe-test", required=True)
    hypothesis.add_argument("--risk-gate")
    hypothesis.add_argument("--target")
    hypothesis.set_defaults(func=command_add_hypothesis)

    update_hypothesis = commands.add_parser("update-hypothesis")
    update_hypothesis.add_argument("--run", required=True)
    update_hypothesis.add_argument("--hypothesis", required=True)
    update_hypothesis.add_argument("--status", choices=sorted(HYPOTHESIS_STATUSES), required=True)
    update_hypothesis.add_argument("--summary", required=True)
    update_hypothesis.set_defaults(func=command_update_hypothesis)

    task = commands.add_parser("add-task")
    task.add_argument("--run", required=True)
    task.add_argument("--kind", choices=sorted(TASK_KINDS), required=True)
    task.add_argument("--title", required=True)
    task.add_argument("--target")
    task.add_argument("--inventory-id")
    task.add_argument("--hypothesis-id")
    task.set_defaults(func=command_add_task)

    update_task = commands.add_parser("update-task")
    update_task.add_argument("--run", required=True)
    update_task.add_argument("--task", required=True)
    update_task.add_argument("--status", choices=sorted(TASK_STATUSES), required=True)
    update_task.add_argument("--summary", required=True)
    update_task.add_argument("--next-action")
    update_task.set_defaults(func=command_update_task)

    access = commands.add_parser("record-access")
    access.add_argument("--run", required=True)
    access.add_argument("--endpoint", required=True)
    access.add_argument("--method", required=True)
    access.add_argument("--role", required=True)
    access.add_argument("--tenant")
    access.add_argument("--object-id")
    access.add_argument("--status", choices=sorted(ACCESS_STATUSES), required=True)
    access.add_argument("--evidence", action="append")
    access.set_defaults(func=command_record_access)

    resource = commands.add_parser("record-resource")
    resource.add_argument("--run", required=True)
    resource.add_argument("--kind", choices=("test-data", "session", "upload", "workflow"), required=True)
    resource.add_argument("--label", required=True)
    resource.add_argument("--cleanup", required=True)
    resource.set_defaults(func=command_record_resource)

    cleanup = commands.add_parser("cleanup-resource")
    cleanup.add_argument("--run", required=True)
    cleanup.add_argument("--resource", required=True)
    cleanup.add_argument("--status", choices=("cleaned", "blocked"), required=True)
    cleanup.add_argument("--summary", required=True)
    cleanup.set_defaults(func=command_cleanup_resource)

    status = commands.add_parser("status")
    status.add_argument("--run", required=True)
    status.set_defaults(func=command_status)

    gate = commands.add_parser("quality-gate")
    gate.add_argument("--run", required=True)
    gate.set_defaults(func=command_quality_gate)

    report = commands.add_parser("report")
    report.add_argument("--run", required=True)
    report.set_defaults(func=command_report)

    score = commands.add_parser("score")
    score.add_argument("--run", required=True)
    score.set_defaults(func=command_score)

    plan = commands.add_parser("plan")
    plan.add_argument("--run", required=True)
    plan.add_argument("--limit", type=int, default=20)
    plan.set_defaults(func=command_plan)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--check-only", action="store_true",
                           help="Apenas diagnostico, sem correcao")
    preflight.set_defaults(func=command_preflight)

    caps = commands.add_parser("capabilities")
    caps.set_defaults(func=command_capabilities)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.func(args)
        return 0
    except RedLensError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
