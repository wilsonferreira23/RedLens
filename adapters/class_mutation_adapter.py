#!/usr/bin/env python3
"""Class-specific mutation scanners built on top of redlens-mutate-safe.

This adapter is invoked through symlinks named ssti-safe, traversal-safe, or
ssrf-safe. It delegates to the curated mutation engine and adds class-specific
metadata and finding titles.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "adapters"))

import redlensctl  # noqa: E402
import mutate_adapter  # noqa: E402


CLASS_CONFIG = {
    "ssti-safe": {
        "payload_id": "ssti",
        "title": "SSTI detectada por mutation",
        "severity": "high",
    },
    "traversal-safe": {
        "payload_id": "traversal",
        "title": "Path traversal detectado por mutation",
        "severity": "high",
    },
    "ssrf-safe": {
        "payload_id": "generic",
        "title": "Possível SSRF detectado por mutation",
        "severity": "medium",
    },
}


def main() -> int:
    prog = os.environ.get("REDLENS_TOOL") or os.path.basename(sys.argv[0])
    if prog not in CLASS_CONFIG:
        print(json.dumps({"ok": False, "error": f"Scanner desconhecido: {prog}"}, ensure_ascii=False))
        return 2

    config = CLASS_CONFIG[prog]
    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--position", choices=("query", "body_field", "header", "path"), required=True)
    parser.add_argument("--field", required=True)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = mutate_adapter.mutate(
            args.run, args.spec, args.role, args.position, args.field, config["payload_id"]
        )
        # Rewrite finding title/severity to match the scanner class if a finding was created.
        if result.get("comparison", {}).get("differs"):
            directory = redlensctl.run_dir(args.run)
            target = result["target"]
            finding_id = redlensctl.safe_id("finding", config["payload_id"], args.position, args.field, target)
            path = directory / "findings" / f"{finding_id}.json"
            if path.is_file():
                finding = redlensctl.read_json(path)
                finding["title"] = config["title"]
                finding["severity"] = config["severity"]
                finding["metadata"]["scanner_class"] = prog
                redlensctl.write_json(path, finding)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
