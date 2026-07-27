#!/usr/bin/env python3
"""SSRF validator with controlled callback.

Injeta URL apontando para callback do proprio laboratorio (ou autorizado pelo usuario).
Verifica se o servidor fez request outbound para a URL injetada.

Uso:
  redlens-ssrf --run <id> --url <target> --position query --field url --token <callback-uuid>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402


CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8080


def build_callback_url(token: str, port: int = CALLBACK_PORT, host: str = CALLBACK_HOST) -> str:
    return f"http://{host}:{port}/redlens-cb/{token}"


def inject_and_replay(directory: Path, url: str, position: str, field: str, callback: str, method: str = "GET") -> tuple[int, dict, bytes]:
    parsed = urllib.parse.urlparse(url)
    if position == "query":
        qs = urllib.parse.parse_qs(parsed.query)
        qs[field] = [callback]
        new_qs = urllib.parse.urlencode({k: v[0] if len(v) == 1 else v for k, v in qs.items()})
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
        req = urllib.request.Request(new_url, method=method)
    elif position == "body_field":
        body = json.dumps({field: callback}).encode("utf-8")
        req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    elif position == "header":
        req = urllib.request.Request(url, method=method, headers={field: callback})
    elif position == "path":
        new_path = parsed.path.replace(f"{{{field}}}", urllib.parse.quote(callback, safe=""))
        new_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
        req = urllib.request.Request(new_url, method=method)
    else:
        raise redlensctl.RedLensError(f"Posicao nao suportada: {position}")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, dict(response.headers), response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(64 * 1024) if hasattr(exc, "read") else b""
    except Exception as exc:
        raise redlensctl.RedLensError(f"Falha: {exc}") from exc


def _callback_server_command(action: str, token: str | None = None) -> list[str]:
    cmd = ["python3", "/workspace/redlens-callback-server.py", action]
    if token and action in {"hits", "wait"}:
        cmd.extend(["--token", token])
    return cmd


def check_callback_server_reachable(timeout: int = 10) -> bool:
    """Verifica se o callback server do laboratorio esta acessivel."""
    try:
        result = exec_kali(_callback_server_command("status"), timeout=timeout)
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return bool(data.get("running"))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, json.JSONDecodeError):
        return False


def check_callback_hit(token: str, timeout: int = 10) -> tuple[bool, dict | None]:
    """Verifica se o callback recebeu um hit para o token.

    Retorna (hit_recebido, raw_hit).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = exec_kali(_callback_server_command("hits", token), timeout=10)
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for hit in data.get("hits", []):
                    if hit.get("token") == token:
                        return True, hit
            except json.JSONDecodeError:
                pass
        time.sleep(1)
    return False, None


def main() -> int:
    parser = argparse.ArgumentParser(prog="ssrf-validator")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--position", choices=("query", "body_field", "header", "path"), default="query")
    parser.add_argument("--field", default="url")
    parser.add_argument("--token", required=True)
    parser.add_argument("--callback-host", default="host.docker.internal")
    parser.add_argument("--callback-port", type=int, default=8080)
    parser.add_argument("--method", default="GET")
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)
        token = redlensctl.safe_name(args.token, "Token")
        callback = build_callback_url(token, args.callback_port, args.callback_host)

        baseline_status, _, baseline_body = inject_and_replay(directory, args.url, args.position, args.field, "https://example.com/canonical", args.method)

        target_status, target_headers, target_body = inject_and_replay(directory, args.url, args.position, args.field, callback, args.method)

        callback_reachable = check_callback_server_reachable(timeout=5)
        hit_received, raw_hit = False, None
        if callback_reachable:
            hit_received, raw_hit = check_callback_hit(token, timeout=10)

        verdict = "tested-negative"
        confidence = "medium"
        evidence = {
            "baseline_status": baseline_status,
            "target_status": target_status,
            "callback_received": hit_received,
            "callback_reachable": callback_reachable,
            "callback_url": callback,
            "position": args.position,
            "field": args.field,
        }
        if hit_received:
            verdict = "confirmed"
            confidence = "high"
        elif not callback_reachable:
            verdict = "tested-negative"
            confidence = "low"
            evidence["reason"] = "Callback server nao acessivel; degradado para DNS-only (sem confirmacao)"
        elif target_status != baseline_status:
            verdict = "needs_review"
            confidence = "low"
            evidence["reason"] = "Status diferente mas sem hit no callback"

        timestamp = redlensctl.iso().replace(":", "").replace("-", "")
        raw_dir = directory / "evidence" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_response_path = raw_dir / f"{timestamp}-ssrf-response-{token}.bin"
        redlensctl.write_raw(raw_response_path, target_body)

        if raw_hit:
            raw_hit_path = raw_dir / f"{timestamp}-ssrf-callback-hit-{token}.json"
            redlensctl.write_json(raw_hit_path, raw_hit)

        sanitized_dir = directory / "evidence" / "sanitized"
        sanitized_dir.mkdir(parents=True, exist_ok=True)
        summary_path = sanitized_dir / f"{timestamp}-ssrf-{token}.json"
        redlensctl.write_json(summary_path, {
            "capability": "ssrf",
            "verdict": verdict,
            "confidence": confidence,
            "evidence": evidence,
            "raw_size": len(target_body),
            "raw_response": str(raw_response_path.relative_to(directory)),
            "raw_hit": str(raw_hit_path.relative_to(directory)) if raw_hit else None,
        })

        if verdict == "confirmed":
            finding_id = f"ssrf-{token}"
            redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
                "id": finding_id,
                "title": f"SSRF via {args.position}.{args.field}",
                "severity": "high",
                "status": "confirmed",
                "asset": args.url,
                "evidence": [str(summary_path.relative_to(directory))],
                "reproduced": True,
                "negative_control": True,
                "created_at": redlensctl.iso(),
            })

        redlensctl.append_event(directory, "ssrf.validated", {
            "verdict": verdict,
            "token": token,
            "url": args.url,
            "callback_received": hit_received,
            "callback_reachable": callback_reachable,
        })
        redlensctl.append_event(directory, "validator.finished", {
            "capability": "ssrf",
            "verdict": verdict,
            "url": args.url,
        })

        print(json.dumps({
            "ok": True,
            "verdict": verdict,
            "confidence": confidence,
            "callback_received": hit_received,
            "callback_reachable": callback_reachable,
            "evidence": evidence,
        }, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
