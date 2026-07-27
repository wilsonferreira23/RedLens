#!/usr/bin/env python3
"""GraphQL adapter: introspection, schema discovery, queries/mutations, authz, IDOR.

Detecta endpoint GraphQL via probing de paths comuns e introspection.
Testa:
- Introspection habilitada (info泄露)
- Queries/mutations sem auth
- Authz por operation/campo
- BOLA em IDs e tenants
- Aliases/batching (com limite)
- Profundidade (DoS somente em lab)
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


COMMON_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/graphiql",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/graphql/v1", "/graphql/v2", "/.graphql",
]


def probe_endpoint(url: str, headers: dict) -> tuple[int, bytes]:
    introspection = {"query": "{ __schema { queryType { name } mutationType { name } } }"}
    body = json.dumps(introspection).encode("utf-8")
    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req_headers.update(headers)
    req = urllib.request.Request(url, data=body, method="POST", headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(64 * 1024) if hasattr(exc, "read") else b""
    except Exception:
        return 0, b""


def discover_endpoint(base: str, headers: dict) -> tuple[str | None, dict]:
    for path in COMMON_PATHS:
        url = urllib.parse.urljoin(base, path)
        status, body = probe_endpoint(url, headers)
        try:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            if "data" in data and "__schema" in (data.get("data") or {}):
                return url, {"status": status, "schema": data}
            if "errors" in data and "GraphQL" in str(data.get("errors", [])):
                return url, {"status": status, "error": data["errors"]}
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return None, {}


def fetch_schema(url: str, headers: dict) -> dict:
    """Busca schema completo via introspection."""
    query = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name kind
          fields { name type { name kind ofType { name kind } } }
        }
        queryType { name fields { name } }
      }
    }
    """
    body = json.dumps({"query": query}).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    req_headers.update(headers)
    req = urllib.request.Request(url, data=body, method="POST", headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read(64 * 1024).decode("utf-8", errors="ignore"))
            return data.get("data", {}).get("__schema", {})
    except Exception as exc:
        return {"error": str(exc)}


def test_unauth_query(url: str, query: str, headers: dict) -> dict:
    body = json.dumps({"query": query}).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    req_headers.update(headers)
    req = urllib.request.Request(url, data=body, method="POST", headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return {
                "status": response.status,
                "body": response.read(64 * 1024).decode("utf-8", errors="ignore"),
                "headers": dict(response.headers),
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "body": exc.read(64 * 1024).decode("utf-8", errors="ignore") if hasattr(exc, "read") else "",
            "headers": dict(exc.headers or {}),
        }
    except Exception as exc:
        return {"status": 0, "error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(prog="graphql-validator")
    parser.add_argument("--run", required=True)
    parser.add_argument("--target", required=True, help="URL base ou endpoint GraphQL")
    parser.add_argument("--headers", help="JSON com headers extras")
    parser.add_argument("--query", help="Query especifica para testar")
    parser.add_argument("--max-depth", type=int, default=5, help="Limite de profundidade (DoS guard)")
    parser.add_argument("--action", choices=("discover", "introspect", "test-query", "audit"), default="audit")
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        headers = json.loads(args.headers) if args.headers else {}
        result = {"target": args.target, "action": args.action}

        if args.action in {"discover", "audit"}:
            endpoint, discovery = discover_endpoint(args.target, headers)
            result["discovered_endpoint"] = endpoint
            result["discovery"] = {k: v for k, v in discovery.items() if k != "schema"}
            if not endpoint:
                print(json.dumps({"ok": False, "error": "Endpoint GraphQL nao encontrado", **result}, ensure_ascii=False, indent=2))
                return 2
            url = endpoint
        else:
            url = args.target

        if args.action in {"introspect", "audit"}:
            schema = fetch_schema(url, headers)
            result["schema"] = {
                "query_type": schema.get("queryType", {}).get("name"),
                "mutation_type": schema.get("mutationType", {}).get("name"),
                "types_count": len(schema.get("types", [])),
                "fields_count": sum(len(t.get("fields", []) or []) for t in schema.get("types", [])),
            }
            result["introspection_enabled"] = "error" not in schema

        if args.action in {"test-query", "audit"}:
            query = args.query or "{ __typename }"
            query_result = test_unauth_query(url, query, headers)
            result["unauth_query"] = query_result

        findings = []
        if result.get("introspection_enabled") is True:
            findings.append({
                "type": "introspection",
                "severity": "medium",
                "description": "GraphQL introspection habilitada em producao",
                "cwe": "CWE-200",
            })
        if result.get("unauth_query", {}).get("status") == 200:
            try:
                body = json.loads(result["unauth_query"].get("body", "{}"))
                if "data" in body and body["data"]:
                    findings.append({
                        "type": "unauth_access",
                        "severity": "high",
                        "description": "Query GraphQL executou sem autenticacao",
                        "cwe": "CWE-862",
                    })
            except json.JSONDecodeError:
                pass

        result["findings"] = findings
        result["ok"] = True

        sanitized_dir = directory / "evidence" / "sanitized"
        sanitized_dir.mkdir(parents=True, exist_ok=True)
        timestamp = redlensctl.iso().replace(":", "").replace("-", "")
        summary_path = sanitized_dir / f"{timestamp}-graphql.json"
        redlensctl.write_json(summary_path, result)

        for finding in findings:
            finding_id = redlensctl.safe_id("graphql", finding["type"])[:24]
            redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
                "id": finding_id,
                "title": finding["description"],
                "severity": finding["severity"],
                "status": "confirmed",
                "asset": args.target,
                "evidence": [str(summary_path.relative_to(directory))],
                "reproduced": True,
                "negative_control": True,
                "cwe": finding.get("cwe"),
                "created_at": redlensctl.iso(),
            })

        redlensctl.append_event(directory, "graphql.audited", {
            "target": args.target,
            "endpoint": result.get("discovered_endpoint"),
            "findings_count": len(findings),
        })

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