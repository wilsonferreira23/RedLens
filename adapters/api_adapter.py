#!/usr/bin/env python3
"""Import an authorized local OpenAPI document into the RedLens inventory."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def operation_url(base: str, path: str) -> str:
    if not path.startswith("/"):
        raise redlensctl.RedLensError("Path OpenAPI inválido.")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def spec_path(directory: Path, raw: str) -> Path:
    path = Path(raw)
    path = path.resolve() if path.is_absolute() else (directory / path).resolve()
    if directory.resolve() not in path.parents or not path.is_file():
        raise redlensctl.RedLensError("Especificação ausente ou fora da operação.")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(prog="api-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--source", choices=("documentation", "browser"), default="documentation")
    args = parser.parse_args()
    try:
        directory = redlensctl.run_dir(args.run)
        source = spec_path(directory, args.spec)
        document = json.loads(source.read_text(encoding="utf-8"))
        if not (document.get("openapi") or document.get("swagger")):
            raise redlensctl.RedLensError("Somente documentos OpenAPI ou Swagger são aceitos.")
        scope = redlensctl.read_json(directory / "scope" / "scope.json")
        base = (document.get("servers") or [{}])[0].get("url")
        if not base:
            target = urlsplit(scope["target"])
            base = f"{target.scheme}://{target.netloc}"
        if "{" in base or "}" in base:
            raise redlensctl.RedLensError("Servidor OpenAPI com variável não resolvida.")
        redlensctl.scoped_url(directory, base)
        endpoints, parameters = [], []
        for route, methods in document.get("paths", {}).items():
            if not isinstance(methods, dict):
                continue
            url = operation_url(base, route)
            redlensctl.scoped_url(directory, url)
            for method, operation in methods.items():
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue
                item_id, _, _ = redlensctl.record_inventory(
                    directory, "api", url, args.source, method.upper()
                )
                endpoints.append(item_id)
                for parameter in operation.get("parameters", []):
                    if isinstance(parameter, dict) and parameter.get("name"):
                        value = f"{method.upper()} {url}#{parameter.get('in', 'unknown')}:{parameter['name']}"
                        parameter_id, _, _ = redlensctl.record_inventory(
                            directory, "parameter", value, args.source, parent=item_id
                        )
                        parameters.append(parameter_id)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        summary = {
            "source": str(source.relative_to(directory)),
            "base": base,
            "endpoints": sorted(set(endpoints)),
            "parameters": sorted(set(parameters)),
        }
        output = directory / "evidence" / "sanitized" / f"{timestamp}-openapi-summary.json"
        redlensctl.write_json(output, summary)
        redlensctl.append_event(directory, "api.openapi.imported", {
            "endpoints": len(summary["endpoints"]), "parameters": len(summary["parameters"]),
        })
        print(json.dumps({"ok": True, "evidence": str(output.relative_to(directory)), **summary},
                         ensure_ascii=False, indent=2))
        return 0
    except (redlensctl.RedLensError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
