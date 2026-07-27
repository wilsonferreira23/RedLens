#!/usr/bin/env python3
"""Offline adapters for Decepticon's JWT, cookie, and OAuth analyzers."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import types
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECEPTICON_WEB = (
    ROOT.parent / "decepticon" / "packages" / "decepticon" / "decepticon" / "tools" / "web"
)
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Não foi possível carregar {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def analyzers():
    for package in ("decepticon", "decepticon.tools", "decepticon.tools.web"):
        sys.modules.setdefault(package, types.ModuleType(package))
    session = load_module(
        "decepticon.tools.web.session", DECEPTICON_WEB / "session.py"
    )
    jwt = load_module("decepticon.tools.web.jwt", DECEPTICON_WEB / "jwt.py")
    oauth = load_module("decepticon.tools.web.oauth", DECEPTICON_WEB / "oauth.py")
    return jwt, session, oauth


def private_input(directory: Path, raw: str, allow_copy: bool = False) -> Path:
    """Resolve input file. Must be inside operation, ideally under evidence/private/.

    Se allow_copy=True e o arquivo estiver fora, copia para evidence/private/inputs/.
    """
    path = Path(raw)
    path = path.resolve() if path.is_absolute() else (directory / path).resolve()
    if directory.resolve() in path.parents and path.is_file():
        return path
    if allow_copy and path.is_file():
        inputs_dir = directory / "evidence" / "private" / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        dest = inputs_dir / path.name
        dest.write_bytes(path.read_bytes())
        os.chmod(dest, 0o600)
        return dest
    raise redlensctl.RedLensError(
        f"Entrada '{raw}' nao esta dentro da operacao ({directory}). "
        "Copie o arquivo para evidence/private/inputs/ ou passe --copy."
    )


def _record_jwt_finding(directory: Path, source: Path, input_path: str) -> None:
    finding_id = redlensctl.safe_id("finding", "jwt-weak-secret", input_path)
    redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
        "id": finding_id,
        "title": "JWT HS secret quebrado offline",
        "severity": "critical",
        "status": "observation",
        "asset": str(source.relative_to(directory)),
        "evidence": [str(source.relative_to(directory))],
        "reproduced": False,
        "negative_control": False,
        "created_at": redlensctl.iso(),
    })


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="decepticon-analyze",
        description="Offline JWT/cookie/OAuth analyzer. Input must be inside operation or use --copy.",
    )
    parser.add_argument("--run", required=True)
    parser.add_argument("--kind", choices=("jwt", "cookie", "oauth"), required=True)
    parser.add_argument("--input", required=True, help="Path to file (relative to run, or absolute under evidence/private/)")
    parser.add_argument("--copy", action="store_true", help="Auto-copy file into evidence/private/inputs/ if outside operation")
    args = parser.parse_args()
    try:
        directory = redlensctl.run_dir(args.run)
        source = private_input(directory, args.input, allow_copy=args.copy)
        jwt, session, oauth = analyzers()
        if args.kind == "jwt":
            parsed = jwt.parse_token(source.read_text(encoding="utf-8").strip())
            cracked = jwt.crack_hs_secret(parsed, list(jwt.DEFAULT_WEAK_SECRETS))
            result = {
                "header": parsed.header.to_dict(),
                "claims": parsed.claims.to_dict(),
                "expired": parsed.claims.expired,
                "findings": list(parsed.findings),
                "cracked": cracked is not None,
                "cracked_secret_length": len(cracked) if cracked else None,
            }
            if cracked is not None:
                _record_jwt_finding(directory, source, args.input)
        elif args.kind == "cookie":
            data = json.loads(source.read_text(encoding="utf-8"))
            parsed = session.analyze_cookie(
                str(data["name"]),
                str(data["value"]),
                secure=bool(data.get("secure")),
                http_only=bool(data.get("http_only")),
                same_site=data.get("same_site"),
            )
            result = parsed.to_dict()
            result.pop("value", None)
        else:
            data = json.loads(source.read_text(encoding="utf-8"))
            redlensctl.scoped_url(directory, data["callback_url"])
            findings = oauth.analyze_oauth_callback(
                data["callback_url"],
                initial_request_url=data.get("initial_request_url"),
                public_client=bool(data.get("public_client")),
            )
            result = {"findings": [asdict(item) for item in findings]}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_kind = re.sub(r"[^a-z0-9-]", "-", args.kind)
        output = directory / "evidence" / "sanitized" / f"{timestamp}-{safe_kind}.json"
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "ok": True,
            "kind": args.kind,
            "evidence": str(output.relative_to(directory)),
            "result": result,
        }, ensure_ascii=False, indent=2))
        return 0
    except (redlensctl.RedLensError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
