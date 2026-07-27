"""Portable runtime bootstrap and diagnostics."""

from __future__ import annotations

import argparse
import json
import shutil
import sys

from redlens_config import load_config
from engine.runtime_executor import docker_compose


def _result(result) -> int:
    output = (result.stdout or "").strip()
    error = (result.stderr or "").strip()
    if output:
        print(output)
    if error:
        print(error, file=sys.stderr)
    return result.returncode


def runtime_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redlens runtime")
    parser.add_argument("action", choices=("build", "up", "down", "status", "preflight", "adopt", "rollback"))
    parser.add_argument("--image")
    parser.add_argument("--skip-health", action="store_true")
    args = parser.parse_args(argv)
    if args.action in {"preflight", "adopt", "rollback"}:
        from runtime.migrate_container import main as migration_main
        forwarded = [args.action]
        if args.image:
            forwarded.extend(["--image", args.image])
        if args.skip_health:
            forwarded.append("--skip-health")
        return migration_main(forwarded)
    if not shutil.which("docker"):
        print(json.dumps({"ok": False, "error": "docker não encontrado"}), file=sys.stderr)
        return 2
    if args.action == "build":
        return _result(docker_compose("build", "kali-pentest", timeout=1800))
    if args.action == "up":
        return _result(docker_compose("--profile", "web", "up", "-d", "--build", timeout=1800))
    if args.action == "down":
        return _result(docker_compose("--profile", "web", "down", timeout=120))
    return _result(docker_compose("--profile", "web", "ps", timeout=30))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redlens doctor")
    parser.parse_args(argv)
    config = load_config()
    checks = {
        "home": config.home.is_dir(),
        "runs": config.runs_dir.is_dir(),
        "compose": config.compose_file.is_file(),
        "docker": shutil.which("docker") is not None,
        "python": sys.version_info >= (3, 12),
    }
    print(json.dumps({"ok": all(checks.values()), "checks": checks}, indent=2))
    return 0 if all(checks.values()) else 2


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "doctor"
    raise SystemExit(
        runtime_main(sys.argv[1:]) if command in {
            "build", "up", "down", "status", "preflight", "adopt", "rollback"
        }
        else main([])
    )
