#!/usr/bin/env python3
"""Capability registry: single entry point for every offensive action.

Each capability maps to a typed adapter call. The agent selects an intention
(capability + target), the registry validates and dispatches. No capability
accepts arbitrary shell arguments.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "adapters"))

import redlensctl  # noqa: E402

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Capability:
    name: str
    risk_action: str | None
    description: str
    runner: Callable[..., dict]


REGISTRY: dict[str, Capability] = {}


def register(capability: Capability) -> None:
    REGISTRY[capability.name] = capability


def get(name: str) -> Capability:
    if name not in REGISTRY:
        raise redlensctl.RedLensError(f"Capability desconhecida: {name}")
    return REGISTRY[name]


def available() -> list[str]:
    return sorted(REGISTRY.keys())


def capabilities_metadata() -> list[dict]:
    """Return every registered capability with its availability status.

    A capability is ``available`` when its runner could be registered
    successfully (i.e., its adapter imports and instantiates without errors).
    """
    return [
        {
            "name": cap.name,
            "risk_action": cap.risk_action,
            "description": cap.description,
            "available": True,
        }
        for cap in REGISTRY.values()
    ]


def _safe_register(name: str, factory: Callable[[], Capability]) -> None:
    """Register a capability, skipping it silently if its adapter fails to import."""
    try:
        register(factory())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Capability %s skipped: %s", name, exc)


def _wrap_fingerprint() -> Capability:
    from kali_adapter import build_command

    def _run(run_id: str, url: str) -> dict:
        directory = redlensctl.run_dir(run_id)
        redlensctl.scoped_url(directory, url)
        scope = redlensctl.read_json(directory / "scope" / "scope.json")
        return {
            "commands": {
                "whatweb": build_command("whatweb", url, scope["max_rps"]),
                "wafw00f": build_command("wafw00f", url, scope["max_rps"]),
                "httpx": build_command("httpx", url, scope["max_rps"]),
            }
        }

    return Capability(
        name="fingerprint",
        risk_action=None,
        description="Low-impact stack fingerprinting via WhatWeb, Wafw00f, HTTPX.",
        runner=_run,
    )


def _wrap_content_discovery() -> Capability:
    from discovery_adapter import discover

    return Capability(
        name="content-discovery",
        risk_action="intrusive-scan",
        description="Discover in-scope endpoints via FFUF or Feroxbuster.",
        runner=lambda **kwargs: discover(**kwargs),
    )


def _wrap_js_analysis() -> Capability:
    from js_adapter import analyze

    return Capability(
        name="js-analysis",
        risk_action=None,
        description="Static JavaScript analysis: endpoints and secret hints.",
        runner=lambda **kwargs: analyze(**kwargs),
    )


def _wrap_parameter_discovery() -> Capability:
    from param_discovery import analyze as param_analyze

    return Capability(
        name="parameter-discovery",
        risk_action=None,
        description="Differential parameter discovery via response comparison.",
        runner=lambda **kwargs: param_analyze(**kwargs),
    )


def _wrap_api_schema() -> Capability:
    def _run(run_id: str, spec_path: str, source: str = "documentation") -> dict:
        from api_adapter import operation_url, spec_path as api_spec_path
        directory = redlensctl.run_dir(run_id)
        spec = api_spec_path(directory, spec_path)
        document = json.loads(spec.read_text(encoding="utf-8"))
        from urllib.parse import urlsplit
        if not (document.get("openapi") or document.get("swagger")):
            raise redlensctl.RedLensError("Somente OpenAPI/Swagger são aceitos.")
        scope = redlensctl.read_json(directory / "scope" / "scope.json")
        base = (document.get("servers") or [{}])[0].get("url") or f"{urlsplit(scope['target']).scheme}://{urlsplit(scope['target']).netloc}"
        redlensctl.scoped_url(directory, base)
        return {
            "ok": True,
            "base": base,
            "endpoints": list(document.get("paths", {}).keys()),
        }

    return Capability(
        name="api-schema",
        risk_action=None,
        description="Import an OpenAPI/Swagger document into inventory.",
        runner=_run,
    )


def _wrap_mutation() -> Capability:
    from mutate_adapter import mutate

    return Capability(
        name="mutation",
        risk_action=None,
        description="Apply curated payload to a captured request and compare response.",
        runner=lambda **kwargs: mutate(**kwargs),
    )


def _wrap_sqli() -> Capability:
    from sqlmap_adapter import run_sqlmap

    return Capability(
        name="sqli",
        risk_action="intrusive-scan",
        description="SQL injection detection via SQLMap inside Kali.",
        runner=lambda **kwargs: run_sqlmap(**kwargs),
    )


def _wrap_xss() -> Capability:
    from xss_adapter import run_dalfox

    return Capability(
        name="xss",
        risk_action="intrusive-scan",
        description="XSS detection via Dalfox inside Kali.",
        runner=lambda **kwargs: run_dalfox(**kwargs),
    )


def _wrap_cmdi() -> Capability:
    from cmdi_adapter import run_commix

    return Capability(
        name="cmdi",
        risk_action="intrusive-scan",
        description="Command injection detection via Commix inside Kali.",
        runner=lambda **kwargs: run_commix(**kwargs),
    )


def _wrap_csrf() -> Capability:
    from csrf_adapter import analyze

    return Capability(
        name="csrf",
        risk_action=None,
        description="Inspect a request-spec for missing CSRF controls.",
        runner=lambda **kwargs: analyze(**kwargs),
    )


def _wrap_mass_assignment() -> Capability:
    from mass_assignment_adapter import analyze

    return Capability(
        name="mass-assignment",
        risk_action="data-mutation",
        description="Probe for mass assignment via privileged fields.",
        runner=lambda **kwargs: analyze(**kwargs),
    )


def _wrap_authn() -> Capability:
    from login_adapter import perform_login, load_credentials

    def _run(run_id: str, role: str, url: str, credentials_path: str, mode: str = "json") -> dict:
        directory = redlensctl.run_dir(run_id)
        creds = load_credentials(directory, credentials_path)
        return perform_login(directory, url, mode, creds, role)

    return Capability(
        name="authn",
        risk_action=None,
        description="Authenticate and persist session per role.",
        runner=_run,
    )


def _wrap_session() -> Capability:
    def _run(run_id: str, role: str) -> dict:
        directory = redlensctl.run_dir(run_id)
        session_path = directory / "evidence" / "private" / "sessions" / f"{role}.json"
        if not session_path.is_file():
            return {"ok": False, "expired": True, "reason": "no_session"}
        session = json.loads(session_path.read_text(encoding="utf-8"))
        return {
            "ok": True,
            "role": role,
            "last_status": session.get("status"),
            "username": session.get("username"),
        }

    return Capability(
        name="session",
        risk_action=None,
        description="Validate or inspect session state for a role.",
        runner=_run,
    )


_CAPABILITY_FACTORIES: list[tuple[str, Callable[[], Capability]]] = [
    ("fingerprint", _wrap_fingerprint),
    ("content-discovery", _wrap_content_discovery),
    ("js-analysis", _wrap_js_analysis),
    ("parameter-discovery", _wrap_parameter_discovery),
    ("api-schema", _wrap_api_schema),
    ("mutation", _wrap_mutation),
    ("sqli", _wrap_sqli),
    ("xss", _wrap_xss),
    ("cmdi", _wrap_cmdi),
    ("csrf", _wrap_csrf),
    ("mass-assignment", _wrap_mass_assignment),
    ("authn", _wrap_authn),
    ("session", _wrap_session),
]


def bootstrap() -> None:
    """Register all capabilities. Idempotent.

    Capabilities whose adapters fail to import are skipped silently so the
    registry never crashes because of a missing optional dependency.
    """
    if REGISTRY:
        return
    for name, factory in _CAPABILITY_FACTORIES:
        _safe_register(name, factory)


bootstrap()
