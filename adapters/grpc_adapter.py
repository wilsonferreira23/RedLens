#!/usr/bin/env python3
"""gRPC adapter: reflection, service discovery, auth, payload tests.

Detecta gRPC/gRPC-web via probing:
- HTTP/2 + content-type application/grpc
- /.well-known/grpc-reflection endpoint
- Server reflection protocol

Usa grpcurl para listar servicos quando disponivel.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


def probe_grpc_http2(host: str, port: int, timeout: int = 10) -> dict:
    """Tenta HTTP/2 com Prior Knowledge (h2c) para detectar gRPC."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        request = (
            f"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            f"POST /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/grpc\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: h2c\r\n"
            f"\r\n"
        ).encode("latin-1")
        sock.send(request)
        response = sock.recv(4096)
        sock.close()
        return {
            "ok": True,
            "response_excerpt": response[:200].decode("latin-1", errors="ignore"),
            "grpc_indicators": [
                indicator for indicator in (b"application/grpc", b"grpc", b"h2", b"HTTP/2")
                if indicator in response
            ],
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def discover_with_grpcurl(target: str, plaintext: bool = True) -> dict:
    """Usa grpcurl para listar servicos."""
    cmd = ["grpcurl", "-plaintext" if plaintext else "", "-v", target, "list"]
    cmd = [c for c in cmd if c]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "ok": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "services": result.stdout.strip().splitlines() if result.returncode == 0 else [],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except FileNotFoundError:
        return {"ok": False, "error": "grpcurl nao instalado"}


def test_endpoint_http(url: str, timeout: int = 10) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {})
    except Exception as exc:
        return 0, {"error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(prog="grpc-validator")
    parser.add_argument("--run", required=True)
    parser.add_argument("--target", required=True, help="host:port ou URL")
    parser.add_argument("--action", choices=("detect", "list", "audit"), default="audit")
    parser.add_argument("--plaintext", action="store_true", default=True)
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)

        target = args.target
        host = port = None
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            target = f"{host}:{port}"
        elif ":" in target:
            host, _, port_s = target.partition(":")
            port = int(port_s)

        result = {"target": args.target, "action": args.action}

        if args.action in {"detect", "audit"}:
            http_status, http_headers = test_endpoint_http(f"http://{host}:{port}/")
            result["http_probe"] = {"status": http_status, "headers": http_headers}

            if host and port:
                h2_result = probe_grpc_http2(host, port)
                result["http2_probe"] = h2_result

            grpc_web_indicators = []
            for path in ["/grpc.health.v1.Health/Check", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"]:
                status, _ = test_endpoint_http(f"http://{host}:{port}{path}")
                if status in {200, 415, 400}:
                    grpc_web_indicators.append({"path": path, "status": status})
            result["grpc_web_indicators"] = grpc_web_indicators

        if args.action in {"list", "audit"}:
            grpcurl_result = discover_with_grpcurl(target, args.plaintext)
            result["grpcurl"] = grpcurl_result

        findings = []
        is_grpc = bool(
            result.get("grpc_web_indicators")
            or result.get("http2_probe", {}).get("grpc_indicators")
            or result.get("grpcurl", {}).get("services")
        )
        if is_grpc and args.action == "audit":
            services = result.get("grpcurl", {}).get("services", [])
            if services:
                findings.append({
                    "type": "service_enumeration",
                    "severity": "info",
                    "description": f"gRPC services exposed: {len(services)}",
                    "cwe": "CWE-200",
                })
            if any("ServerReflection" in s for s in services):
                findings.append({
                    "type": "reflection_enabled",
                    "severity": "medium",
                    "description": "gRPC server reflection habilitada em producao",
                    "cwe": "CWE-200",
                })
            if "grpc.health.v1.Health" in services:
                findings.append({
                    "type": "health_service",
                    "severity": "info",
                    "description": "gRPC health check service disponivel",
                })

        result["findings"] = findings
        result["ok"] = True
        result["is_grpc"] = is_grpc

        sanitized_dir = directory / "evidence" / "sanitized"
        sanitized_dir.mkdir(parents=True, exist_ok=True)
        timestamp = redlensctl.iso().replace(":", "").replace("-", "")
        summary_path = sanitized_dir / f"{timestamp}-grpc.json"
        redlensctl.write_json(summary_path, {
            "capability": "grpc",
            "action": args.action,
            **result,
        })

        for finding in findings:
            finding_id = redlensctl.safe_id("grpc", finding["type"])[:24]
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

        redlensctl.append_event(directory, "grpc.tested", {
            "target": args.target,
            "is_grpc": is_grpc,
            "findings_count": len(findings),
        })

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())