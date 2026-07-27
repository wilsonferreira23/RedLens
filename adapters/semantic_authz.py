#!/usr/bin/env python3
"""Semantic authz validation: not just status/size, but content comparison.

Compara respostas por:
- schema (estrutura JSON)
- campos sensiveis (PII, tokens, ids internos)
- proprietario (id do dono do recurso)
- tenant (tenant_id, organization_id, workspace_id)
- permissoes (role, scopes, abilities)
- IDs presentes
- conteudo normalizado (canonico)
- efeito persistido (antes/depois)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


def normalize_body(body: Any) -> Any:
    """Canonicaliza um body para comparacao semantica.

    - Remove campos nao deterministicos (timestamps, request IDs, tokens)
    - Ordena chaves para comparacao estavel
    """
    if isinstance(body, dict):
        drop = {
            "request_id", "requestId", "trace_id", "traceId", "ts", "timestamp",
            "nonce", "_id", "etag", "ETag", "last_modified", "lastModified",
            "session_id", "sessionId", "csrf_token", "csrfToken",
            "server_time", "serverTime", "Date", "date",
            "X-Request-Id", "x-request-id", "X-Trace-Id",
        }
        return {
            k: normalize_body(v)
            for k, v in sorted(body.items())
            if k not in drop and not re.search(r"token|secret|password|credential", k, re.I)
        }
    if isinstance(body, list):
        return [normalize_body(item) for item in body]
    if isinstance(body, str):
        return None
    return body


def extract_schema(body: Any) -> dict:
    """Extrai schema (estrutura de chaves e tipos) sem valores."""
    if isinstance(body, dict):
        return {k: extract_schema(v) for k, v in sorted(body.items())}
    if isinstance(body, list):
        if not body:
            return []
        return [extract_schema(body[0])]
    return type(body).__name__


def extract_ids(body: Any, prefix: str = "") -> list[str]:
    """Extrai todos os IDs presentes (uuid, numeric, custom)."""
    ids = []
    if isinstance(body, dict):
        for k, v in body.items():
            if re.search(r"^.*_id$|^id$|^uuid$|^guid$", k, re.I):
                if isinstance(v, (str, int)):
                    ids.append(f"{prefix}.{k}={v}")
            ids.extend(extract_ids(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(body, list):
        for i, item in enumerate(body):
            ids.extend(extract_ids(item, f"{prefix}[{i}]"))
    return ids


def extract_owner(body: Any) -> str | None:
    """Extrai o proprietario do recurso."""
    if not isinstance(body, dict):
        return None
    for key in ("owner_id", "ownerId", "owner", "user_id", "userId", "created_by", "createdBy", "author_id", "authorId"):
        if key in body:
            val = body[key]
            if isinstance(val, (str, int)):
                return f"{key}={val}"
    return None


def extract_tenant(body: Any) -> str | None:
    """Extrai o tenant do recurso."""
    if not isinstance(body, dict):
        return None
    for key in ("tenant_id", "tenantId", "tenant", "organization_id", "organizationId",
                "organization", "workspace_id", "workspaceId", "workspace",
                "account_id", "accountId", "company_id", "companyId"):
        if key in body:
            val = body[key]
            if isinstance(val, (str, int)):
                return f"{key}={val}"
    return None


def extract_permissions(body: Any) -> list[str]:
    """Extrai informacoes de permissao (roles, scopes, abilities)."""
    perms = []
    if not isinstance(body, dict):
        return perms
    for key in ("role", "roles", "scope", "scopes", "abilities", "permissions", "is_admin", "isAdmin", "is_owner", "isOwner"):
        if key in body:
            val = body[key]
            if isinstance(val, list):
                perms.extend(f"{key}={v}" for v in val if isinstance(v, (str, int)))
            elif isinstance(val, bool):
                perms.append(f"{key}={val}")
            elif isinstance(val, (str, int)):
                perms.append(f"{key}={val}")
    return perms


def extract_sensitive_fields(body: Any, prefix: str = "") -> list[str]:
    """Detecta campos sensiveis que vazaram na resposta."""
    sensitive = []
    if isinstance(body, dict):
        for k, v in body.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if re.search(r"password|secret|api[_-]?key|token|credential|ssn|cpf|cnpj|credit[_-]?card", k, re.I):
                sensitive.append(full_key)
            if isinstance(v, (dict, list)):
                sensitive.extend(extract_sensitive_fields(v, full_key))
    elif isinstance(body, list):
        for i, item in enumerate(body):
            sensitive.extend(extract_sensitive_fields(item, f"{prefix}[{i}]"))
    return sensitive


def compare_bodies(positive_body: Any, negative_body: Any) -> dict:
    """Compara dois bodies semanticamente e retorna o delta estruturado."""
    pos_norm = normalize_body(positive_body)
    neg_norm = normalize_body(negative_body)
    pos_schema = extract_schema(positive_body)
    neg_schema = extract_schema(negative_body)
    pos_ids = sorted(set(extract_ids(positive_body)))
    neg_ids = sorted(set(extract_ids(negative_body)))
    pos_owner = extract_owner(positive_body)
    neg_owner = extract_owner(negative_body)
    pos_tenant = extract_tenant(positive_body)
    neg_tenant = extract_tenant(negative_body)
    pos_perms = sorted(set(extract_permissions(positive_body)))
    neg_perms = sorted(set(extract_permissions(negative_body)))
    pos_sensitive = extract_sensitive_fields(positive_body)
    neg_sensitive = extract_sensitive_fields(negative_body)

    ids_only_in_pos = [i for i in pos_ids if i not in neg_ids]
    ids_only_in_neg = [i for i in neg_ids if i not in pos_ids]
    perms_only_in_pos = [p for p in pos_perms if p not in neg_perms]
    perms_only_in_neg = [p for p in neg_perms if p not in pos_perms]

    schema_match = pos_schema == neg_schema
    owner_match = pos_owner == neg_owner
    tenant_match = pos_tenant == neg_tenant
    permissions_match = pos_perms == neg_perms
    content_match = pos_norm == neg_norm

    semantic_leak = False
    leak_indicators = []
    if not owner_match and pos_owner is not None and neg_owner is not None:
        semantic_leak = True
        leak_indicators.append(f"owner differs: pos={pos_owner} neg={neg_owner}")
    if not tenant_match and pos_tenant is not None and neg_tenant is not None:
        semantic_leak = True
        leak_indicators.append(f"tenant differs: pos={pos_tenant} neg={neg_tenant}")
    if ids_only_in_pos:
        semantic_leak = True
        leak_indicators.append(f"ids only in positive: {ids_only_in_pos[:5]}")
    if perms_only_in_neg:
        semantic_leak = True
        leak_indicators.append(f"ids only in negative: {ids_only_in_neg[:5]}")
    if perms_only_in_pos or perms_only_in_neg:
        semantic_leak = True
        leak_indicators.append(f"permissions differ: pos={perms_only_in_pos} neg={perms_only_in_neg}")
    if not schema_match and pos_schema and neg_schema:
        semantic_leak = True
        leak_indicators.append(f"schema differs: pos_keys={list(pos_schema.keys())[:5]} neg_keys={list(neg_schema.keys())[:5]}")

    measurable_difference = bool(
        not schema_match or not owner_match or not tenant_match or
        not permissions_match or ids_only_in_pos or ids_only_in_neg or
        perms_only_in_pos or perms_only_in_neg
    )
    verdict = "confirmed" if measurable_difference else "tested-negative"
    confidence = "high" if measurable_difference else "medium"

    return {
        "schema_match": schema_match,
        "owner_match": owner_match,
        "tenant_match": tenant_match,
        "permissions_match": permissions_match,
        "content_match": content_match,
        "owner_positive": pos_owner,
        "owner_negative": neg_owner,
        "tenant_positive": pos_tenant,
        "tenant_negative": neg_tenant,
        "ids_only_in_positive": ids_only_in_pos,
        "ids_only_in_negative": ids_only_in_neg,
        "permissions_only_in_positive": perms_only_in_pos,
        "permissions_only_in_negative": perms_only_in_neg,
        "sensitive_fields_positive": pos_sensitive,
        "sensitive_fields_negative": neg_sensitive,
        "semantic_leak": semantic_leak,
        "leak_indicators": leak_indicators,
        "measurable_difference": measurable_difference,
        "verdict": verdict,
        "confidence": confidence,
    }


def compare_persisted(before: Any, after: Any) -> dict:
    """Compara estado antes/depois de mutacao."""
    before_ids = sorted(set(extract_ids(before)))
    after_ids = sorted(set(extract_ids(after)))
    new_ids = [i for i in after_ids if i not in before_ids]
    removed_ids = [i for i in before_ids if i not in after_ids]
    schema_before = extract_schema(before)
    schema_after = extract_schema(after)
    new_fields = []
    if isinstance(before, dict) and isinstance(after, dict):
        for k in after.keys():
            if k not in before:
                new_fields.append(k)
        for k in before.keys():
            if k not in after:
                new_fields.append(f"-{k}")
    return {
        "new_ids": new_ids,
        "removed_ids": removed_ids,
        "new_fields": new_fields,
        "schema_changed": schema_before != schema_after,
        "persisted_change": bool(new_ids or new_fields or schema_before != schema_after),
    }


def classify_authz(positive_classification: str, negative_classification: str, semantic: dict) -> dict:
    """Classificacao final considerando status + semantica."""
    if positive_classification == "blocked" or negative_classification == "blocked":
        return {
            "verdict": "blocked",
            "confidence": "low",
            "reason": "Rate limit ou bloqueio impede conclusao.",
        }
    if positive_classification == "denied" and negative_classification == "denied":
        return {
            "verdict": "safe",
            "confidence": "high",
            "reason": "Ambos papeis negados.",
        }
    if positive_classification == "allowed" and negative_classification == "denied":
        if semantic["semantic_leak"]:
            return {
                "verdict": "bola_confirmed",
                "confidence": "high",
                "reason": f"Positive permitido, negative negado, mas conteudo semanticamente diferente: {semantic['leak_indicators']}",
            }
        return {
            "verdict": "authorized",
            "confidence": "medium",
            "reason": "Positive permitido, negative negado, sem leak semantico.",
        }
    if positive_classification == "allowed" and negative_classification == "allowed":
        if semantic["semantic_leak"]:
            return {
                "verdict": "bola_confirmed",
                "confidence": "high",
                "reason": f"Ambos permitidos com conteudo diferente: {semantic['leak_indicators']}",
            }
        if semantic["content_match"]:
            return {
                "verdict": "unauthorized",
                "confidence": "high",
                "reason": "Negative tambem conseguiu acessar mesmo recurso (BFLA).",
            }
        return {
            "verdict": "needs_review",
            "confidence": "low",
            "reason": "Ambos permitidos, schemas iguais mas conteudo difere.",
        }
    if positive_classification == "denied" and negative_classification == "allowed":
        return {
            "verdict": "configuration_error",
            "confidence": "low",
            "reason": "Papel positivo negado mas controle negativo permitido. Inverter papeis.",
        }
    return {
        "verdict": "inconclusive",
        "confidence": "low",
        "reason": f"Combinacao nao coberta: pos={positive_classification}, neg={negative_classification}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="semantic-authz")
    sub = parser.add_subparsers(dest="action", required=True)

    compare_p = sub.add_parser("compare")
    compare_p.add_argument("--run")
    compare_p.add_argument("--positive", required=True, help="Arquivo JSON com body positivo")
    compare_p.add_argument("--negative", required=True, help="Arquivo JSON com body negativo")

    persist_p = sub.add_parser("persisted-diff")
    persist_p.add_argument("--run")
    persist_p.add_argument("--before", required=True, help="Body antes da mutacao")
    persist_p.add_argument("--after", required=True, help="Body depois da mutacao")

    args = parser.parse_args()
    try:
        directory = None
        if args.run:
            directory = redlensctl.run_dir(args.run)
            timestamp = redlensctl.iso().replace(":", "").replace("-", "")
            raw_dir = directory / "evidence" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            sanitized_dir = directory / "evidence" / "sanitized"
            sanitized_dir.mkdir(parents=True, exist_ok=True)

        if args.action == "compare":
            pos = json.loads(Path(args.positive).read_text(encoding="utf-8"))
            neg = json.loads(Path(args.negative).read_text(encoding="utf-8"))
            result = compare_bodies(pos, neg)

            if directory:
                raw_pos = raw_dir / f"{timestamp}-semantic-authz-positive.json"
                raw_neg = raw_dir / f"{timestamp}-semantic-authz-negative.json"
                redlensctl.write_json(raw_pos, pos)
                redlensctl.write_json(raw_neg, neg)

                summary_path = sanitized_dir / f"{timestamp}-semantic-authz-compare.json"
                summary = {
                    "capability": "semantic-authz",
                    "verdict": result["verdict"],
                    "confidence": result["confidence"],
                    "measurable_difference": result["measurable_difference"],
                    "diff": result,
                    "raw_positive": str(raw_pos.relative_to(directory)),
                    "raw_negative": str(raw_neg.relative_to(directory)),
                }
                redlensctl.write_json(summary_path, summary)

                redlensctl.append_event(directory, "semantic_authz.compared", {
                    "verdict": result["verdict"],
                    "measurable_difference": result["measurable_difference"],
                })
                redlensctl.append_event(directory, "validator.finished", {
                    "capability": "semantic-authz",
                    "verdict": result["verdict"],
                })

            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        elif args.action == "persisted-diff":
            before = json.loads(Path(args.before).read_text(encoding="utf-8"))
            after = json.loads(Path(args.after).read_text(encoding="utf-8"))
            result = compare_persisted(before, after)

            if directory:
                raw_before = raw_dir / f"{timestamp}-semantic-authz-before.json"
                raw_after = raw_dir / f"{timestamp}-semantic-authz-after.json"
                redlensctl.write_json(raw_before, before)
                redlensctl.write_json(raw_after, after)

                verdict = "confirmed" if result.get("persisted_change") else "tested-negative"
                summary_path = sanitized_dir / f"{timestamp}-semantic-authz-persisted.json"
                redlensctl.write_json(summary_path, {
                    "capability": "semantic-authz",
                    "verdict": verdict,
                    "diff": result,
                    "raw_before": str(raw_before.relative_to(directory)),
                    "raw_after": str(raw_after.relative_to(directory)),
                })

                redlensctl.append_event(directory, "semantic_authz.persisted_diff", {
                    "verdict": verdict,
                    "persisted_change": result.get("persisted_change"),
                })
                redlensctl.append_event(directory, "validator.finished", {
                    "capability": "semantic-authz",
                    "verdict": verdict,
                })

            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
    except (
        redlensctl.RedLensError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())