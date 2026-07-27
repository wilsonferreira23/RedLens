"""Console entry points for source and installed RedLens layouts."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


COMMANDS = {
    "redlensctl": ("engine.redlensctl", None),
    "redlens-health": ("adapters.health", None),
    "redlens-kali-safe": ("adapters.kali_adapter", None),
    "redlens-decepticon-analyze": ("adapters.decepticon_analysis", None),
    "redlens-api-safe": ("adapters.api_adapter", None),
    "redlens-web-safe": ("adapters.web_validator", None),
    "redlens-browser-safe": ("adapters.browser_adapter", None),
    "redlens-mutate-safe": ("adapters.mutate_adapter", None),
    "redlens-sqlmap-safe": ("adapters.sqlmap_adapter", None),
    "redlens-xss-safe": ("adapters.xss_adapter", None),
    "redlens-cmdi-safe": ("adapters.cmdi_adapter", None),
    "redlens-csrf-safe": ("adapters.csrf_adapter", None),
    "redlens-massassign-safe": ("adapters.mass_assignment_adapter", None),
    "redlens-login-safe": ("adapters.login_adapter", None),
    "redlens-plan-safe": ("adapters.planner_adapter", None),
    "redlens-replay-safe": ("adapters.replay_adapter", None),
    "redlens-authz-safe": ("adapters.authz_adapter", None),
    "redlens-nosqli-safe": ("adapters.nosqli_validator", "nosqli-safe"),
    "redlens-ssrf-safe": ("adapters.ssrf_callback_validator", "ssrf-safe"),
    "redlens-xxe-safe": ("adapters.xxe_validator", "xxe-safe"),
    "redlens-ssti-safe": ("adapters.class_mutation_adapter", "ssti-safe"),
    "redlens-traversal-safe": ("adapters.class_mutation_adapter", "traversal-safe"),
    "redlens-race-workflow-safe": ("adapters.race_workflow", "race-workflow-safe"),
    "redlens-semantic-authz-safe": ("adapters.semantic_authz", "semantic-authz-safe"),
    "redlens-email-safe": ("adapters.email_adapter", None),
    "redlens-jwt-safe": ("adapters.jwt_adapter", None),
    "redlens-subdomain-safe": ("adapters.subdomain_adapter", None),
    "redlens-preflight": ("adapters.preflight", None),
}


def _dispatch(name: str) -> int:
    module_name, tool_name = COMMANDS[name]
    if tool_name:
        os.environ["REDLENS_TOOL"] = tool_name
    module = importlib.import_module(module_name)
    return int(module.main())


def main() -> int:
    name = Path(sys.argv[0]).name
    if name == "redlens":
        if len(sys.argv) < 2:
            print("usage: redlens {doctor|health|runtime|migrate} [...]")
            return 2
        command = sys.argv[1]
        sys.argv = [f"redlens-{command}", *sys.argv[2:]]
        if command == "health":
            return _dispatch("redlens-health")
        if command == "doctor":
            from runtime.doctor import main as doctor_main
            return int(doctor_main())
        if command == "runtime":
            from runtime.doctor import runtime_main
            return int(runtime_main())
        if command == "migrate":
            sys.argv = ["redlens-migrate", "migrate", *sys.argv[1:]]
            return _dispatch("redlensctl")
        print(f"comando RedLens desconhecido: {command}", file=sys.stderr)
        return 2
    if name not in COMMANDS:
        print(f"entry point RedLens desconhecido: {name}", file=sys.stderr)
        return 2
    return _dispatch(name)
