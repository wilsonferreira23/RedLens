#!/usr/bin/env python3
"""Login generico: autenticacao, refresh, MFA, OAuth/OIDC.

Modos suportados:
  - json: POST JSON com username/password
  - form: POST x-www-form-urlencoded
  - bearer: header Authorization: Bearer <token>
  - apikey: header X-Api-Key: <key>
  - cookie: Set-Cookie persistido
  - refresh: usa refresh_token para obter novo access_token
  - oauth: authorization_code com PKCE
  - mfa: requer intervencao humana apos primeiro fator

Credenciais em evidence/private/credentials/<role>.json.
Sessao em evidence/private/sessions/<role>.json com
{role, mode, token, refresh_token, cookies, expires_at, ...}.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


SUPPORTED_MODES = {"json", "form", "bearer", "apikey", "cookie", "refresh", "oauth", "mfa"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat()


def load_credentials(directory: Path, raw: str) -> dict:
    path = Path(raw)
    path = path.resolve() if path.is_absolute() else (directory / path).resolve()
    if directory.resolve() not in path.parents or not path.is_file():
        raise redlensctl.RedLensError("Credenciais ausentes ou fora da operacao.")
    if "evidence/private" not in str(path):
        raise redlensctl.RedLensError("Credenciais devem ficar em evidence/private.")
    creds = json.loads(path.read_text(encoding="utf-8"))
    if not creds:
        raise redlensctl.RedLensError("Credenciais vazias.")
    return creds


def http_request(url: str, method: str, headers: dict, body: bytes, timeout: int = 30) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, data=body if body else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            resp_headers = dict(response.headers)
            resp_body = response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        status = exc.code
        resp_headers = dict(exc.headers or {})
        resp_body = exc.read(64 * 1024) if hasattr(exc, "read") else b""
    except Exception as exc:
        raise redlensctl.RedLensError(f"Falha na requisicao: {exc}") from exc
    return status, resp_headers, resp_body


def extract_token_from_response(mode: str, status: int, headers: dict, body: bytes) -> tuple[str | None, str | None, list[str]]:
    """Extrai token, refresh_token, cookies. Suporta JWT, OAuth, cookies."""
    token_value = None
    token_location = None
    refresh_value = None
    cookies = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else []
    if not cookies:
        sc = headers.get("Set-Cookie")
        if sc:
            cookies = [sc]

    if mode in {"json", "form", "oauth", "refresh"}:
        try:
            payload = json.loads(body.decode("utf-8", errors="ignore"))
            if isinstance(payload, dict):
                for key in ("access_token", "token", "jwt", "auth_token", "id_token"):
                    if key in payload and isinstance(payload[key], str):
                        token_value = payload[key]
                        token_location = f"json:{key}"
                        break
                for key in ("refresh_token", "refreshToken"):
                    if key in payload and isinstance(payload[key], str):
                        refresh_value = payload[key]
                        break
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    if mode == "bearer":
        auth = headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token_value = auth[7:]
            token_location = "header:Authorization"

    return token_value, refresh_value, cookies


def jwt_decode(jwt: str) -> dict:
    """Decodifica payload de JWT sem verificar assinatura."""
    try:
        parts = jwt.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded.decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def jwt_expiry(jwt: str) -> datetime | None:
    payload = jwt_decode(jwt)
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        return datetime.fromtimestamp(exp, tz=timezone.utc)
    return None


def _mask_credentials(data: dict) -> dict:
    """Retorna copia do dict sem valores de senha."""
    return {k: v for k, v in data.items() if "password" not in k.lower()}


def perform_login(directory: Path, url: str, mode: str, creds: dict, role: str) -> dict:
    headers = {}
    body = b""

    if mode == "json":
        body = json.dumps({
            "username": creds.get("username"),
            "password": creds.get("password"),
            **{k: v for k, v in creds.items() if k not in {"username", "password"}},
        }).encode("utf-8")
        headers["Content-Type"] = "application/json"

    elif mode == "form":
        body = urllib.parse.urlencode({
            k: v for k, v in creds.items() if v
        }).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    elif mode == "bearer":
        token = creds.get("token") or creds.get("api_key")
        if not token:
            raise redlensctl.RedLensError("Modo bearer exige campo token ou api_key.")
        headers["Authorization"] = f"Bearer {token}"
        body = b""

    elif mode == "apikey":
        key = creds.get("api_key")
        if not key:
            raise redlensctl.RedLensError("Modo apikey exige campo api_key.")
        headers["X-Api-Key"] = key
        body = b""

    elif mode == "cookie":
        cookie = creds.get("cookie")
        if not cookie:
            raise redlensctl.RedLensError("Modo cookie exige campo cookie.")
        headers["Cookie"] = cookie
        body = b""

    elif mode == "refresh":
        refresh = creds.get("refresh_token")
        if not refresh:
            raise redlensctl.RedLensError("Modo refresh exige refresh_token.")
        body = json.dumps({"refresh_token": refresh, "grant_type": "refresh_token"}).encode("utf-8")
        headers["Content-Type"] = "application/json"

    elif mode == "oauth":
        grant = creds.get("grant_type", "authorization_code")
        body = json.dumps({
            "grant_type": grant,
            "client_id": creds.get("client_id"),
            "client_secret": creds.get("client_secret"),
            "code": creds.get("code"),
            "code_verifier": creds.get("code_verifier"),
            "redirect_uri": creds.get("redirect_uri"),
        }).encode("utf-8")
        headers["Content-Type"] = "application/json"

    elif mode == "mfa":
        body = json.dumps({
            "username": creds.get("username"),
            "password": creds.get("password"),
            "mfa_token": creds.get("mfa_token"),
        }).encode("utf-8")
        headers["Content-Type"] = "application/json"

    else:
        raise redlensctl.RedLensError(f"Modo nao suportado: {mode}")

    status, resp_headers, resp_body = http_request(url, "POST" if body else "GET", headers, body)
    token_value, refresh_value, cookies = extract_token_response(mode, status, resp_headers, resp_body)

    expires_at = None
    if token_value and "." in token_value and len(token_value) > 50:
        jwt_exp = jwt_expiry(token_value)
        if jwt_exp:
            expires_at = jwt_exp.isoformat()

    session = {
        "role": role,
        "mode": mode,
        "username": creds.get("username"),
        "status": status,
        "cookies": cookies,
        "token": token_value,
        "token_location": None,
        "refresh_token": refresh_value,
        "expires_at": expires_at,
        "created_at": _iso(),
        "login_url": url,
        "requires_human_intervention": mode == "mfa" and not creds.get("mfa_token"),
    }

    session_dir = directory / "evidence" / "private" / "sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_path = session_dir / f"{role}.json"
    session_path.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(session_path, 0o600)

    redlensctl.record_session(directory, role, "login-helper", session_path)

    timestamp = _iso().replace(":", "").replace("-", "")
    raw_dir = directory / "evidence" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{timestamp}-login-{role}-response.bin"
    redlensctl.write_raw(raw_path, resp_body)

    sanitized_dir = directory / "evidence" / "sanitized"
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "tool": "login-helper",
        "role": role,
        "url": url,
        "mode": mode,
        "status": status,
        "token_extracted": bool(token_value),
        "refresh_extracted": bool(refresh_value),
        "cookies_set": len(cookies),
        "expires_at": expires_at,
        "requires_human_intervention": session["requires_human_intervention"],
        "raw_response": str(raw_path.relative_to(directory)),
    }
    summary_path = sanitized_dir / f"{timestamp}-login-{role}.json"
    redlensctl.write_json(summary_path, summary)

    redlensctl.append_event(directory, "login.completed", {
        "role": role,
        "url": url,
        "mode": mode,
        "status": status,
        "token_extracted": bool(token_value),
        "requires_human_intervention": session["requires_human_intervention"],
    })

    return {
        "ok": True,
        "role": role,
        "status": status,
        "token_extracted": bool(token_value),
        "refresh_extracted": bool(refresh_value),
        "cookies_set": len(cookies),
        "expires_at": expires_at,
        "session": str(session_path.relative_to(directory)),
        "requires_human_intervention": session["requires_human_intervention"],
    }


def extract_token_response(mode: str, status: int, headers: dict, body: bytes) -> tuple[str | None, str | None, list[str]]:
    return extract_token_from_response(mode, status, headers, body)


def refresh_session(directory: Path, role: str, url: str | None = None) -> dict:
    """Tenta refresh do token usando refresh_token salvo."""
    session_path = directory / "evidence" / "private" / "sessions" / f"{role}.json"
    if not session_path.is_file():
        raise redlensctl.RedLensError(f"Sessao nao encontrada: {role}")
    session = json.loads(session_path.read_text(encoding="utf-8"))
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        raise redlensctl.RedLensError(f"Sessao {role} nao tem refresh_token.")
    refresh_url = url or session.get("login_url")
    if not refresh_url:
        raise redlensctl.RedLensError("URL de refresh nao definida.")
    body = json.dumps({"refresh_token": refresh_token, "grant_type": "refresh_token"}).encode("utf-8")
    status, headers, resp_body = http_request(refresh_url, "POST", {"Content-Type": "application/json"}, body)
    new_token, new_refresh, cookies = extract_token_response("refresh", status, headers, resp_body)
    if new_token:
        session["token"] = new_token
    if new_refresh:
        session["refresh_token"] = new_refresh
    if cookies:
        session["cookies"] = cookies
    session["status"] = status
    session["refreshed_at"] = _iso()
    if new_token and "." in new_token and len(new_token) > 50:
        jwt_exp = jwt_expiry(new_token)
        if jwt_exp:
            session["expires_at"] = jwt_exp.isoformat()
    session_path.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    redlensctl.append_event(directory, "session.refreshed", {"role": role, "status": status})
    return {"ok": True, "role": role, "status": status, "expires_at": session.get("expires_at")}


def detect_expiry(directory: Path, role: str) -> dict:
    """Verifica se o token da sessao esta expirado."""
    session_path = directory / "evidence" / "private" / "sessions" / f"{role}.json"
    if not session_path.is_file():
        raise redlensctl.RedLensError(f"Sessao nao encontrada: {role}")
    session = json.loads(session_path.read_text(encoding="utf-8"))
    expires_at = session.get("expires_at")
    if not expires_at:
        return {"role": role, "expired": False, "expires_at": None, "reason": "no_exp_claim"}
    try:
        exp_dt = datetime.fromisoformat(expires_at)
        now = _now()
        return {
            "role": role,
            "expired": exp_dt < now,
            "expires_at": expires_at,
            "seconds_until_expiry": (exp_dt - now).total_seconds() if exp_dt > now else None,
        }
    except ValueError:
        return {"role": role, "expired": None, "expires_at": expires_at, "reason": "invalid_format"}


def main() -> int:
    parser = argparse.ArgumentParser(prog="login-safe")
    sub = parser.add_subparsers(dest="action", required=True)

    login_p = sub.add_parser("login")
    login_p.add_argument("--run", required=True)
    login_p.add_argument("--role", required=True)
    login_p.add_argument("--url", required=True)
    login_p.add_argument("--mode", choices=sorted(SUPPORTED_MODES), default="json")
    login_p.add_argument("--credentials", required=True)

    refresh_p = sub.add_parser("refresh")
    refresh_p.add_argument("--run", required=True)
    refresh_p.add_argument("--role", required=True)
    refresh_p.add_argument("--url")

    detect_p = sub.add_parser("detect-expiry")
    detect_p.add_argument("--run", required=True)
    detect_p.add_argument("--role", required=True)

    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        directory = redlensctl.run_dir(args.run)
        if args.action == "login":
            redlensctl.scoped_url(directory, args.url)
            creds = load_credentials(directory, args.credentials)
            result = perform_login(directory, args.url, args.mode, creds, args.role)
            redlensctl.append_event(directory, "validator.finished", {
                "capability": "authn",
                "verdict": "success" if result.get("token_extracted") else "completed",
                "url": args.url,
                "role": args.role,
            })
        elif args.action == "refresh":
            session_path = directory / "evidence" / "private" / "sessions" / f"{args.role}.json"
            session = json.loads(session_path.read_text(encoding="utf-8")) if session_path.is_file() else {}
            refresh_url = args.url or session.get("login_url")
            if refresh_url:
                redlensctl.scoped_url(directory, refresh_url)
            result = refresh_session(directory, args.role, args.url)
            redlensctl.append_event(directory, "validator.finished", {
                "capability": "authn-refresh",
                "verdict": "success" if 200 <= result.get("status", 0) < 300 else "completed",
                "url": refresh_url or args.url,
                "role": args.role,
            })
        elif args.action == "detect-expiry":
            result = detect_expiry(directory, args.role)
        else:
            print(json.dumps({"ok": False, "error": f"Acao desconhecida: {args.action}"}, ensure_ascii=False), file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        json.JSONDecodeError,
        KeyError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())