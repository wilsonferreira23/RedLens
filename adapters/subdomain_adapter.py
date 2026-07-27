#!/usr/bin/env python3
"""Subdomain enumeration adapter.

Fontes:
  - crt.sh: Certificate Transparency logs (passivo, sem ferramenta externa)
  - subfinder: Se disponivel no PATH ou container
  - assetfinder: Se disponivel no PATH ou container
  - dnsx: Resolucao DNS para verificar quais subdominios estao vivos

Fluxo:
  1. Enumera subdominios de um dominio alvo
  2. Resolve DNS para verificar quais estao ativos
  3. Registra no inventory da run
  4. Opcional: dispara discovery FFUF em cada subdominio encontrado

Uso:
  redlens-subdomain-safe enum --domain cubeinvest.app
  redlens-subdomain-safe enum --domain cubeinvest.app --run <id> [--resolve] [--depth <n>]
  redlens-subdomain-safe resolve --domain cubeinvest.app --subdomains <file>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


CRTSH_API = "https://crt.sh/?q={query}&output=json"


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _warn(msg: str) -> None:
    print(f"[subdomain-safe] WARN: {msg}", file=sys.stderr)


def _debug(msg: str) -> None:
    print(f"[subdomain-safe] DEBUG: {msg}", file=sys.stderr)


# ─── crt.sh ──────────────────────────────────────────────────────────────────


def crtsh_enum(domain: str, wildcard: bool = True) -> set[str]:
    """Consulta crt.sh por subdominios via Certificate Transparency logs."""
    query = f"%25.{domain}" if wildcard else domain
    url = CRTSH_API.format(query=query)
    subdomains: set[str] = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RedLens/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        _warn(f"crt.sh query failed: {exc}")
        return subdomains

    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lower()
            if sub.endswith(f".{domain}") or sub == domain:
                # Remove leading *. (wildcard)
                sub = sub.lstrip("*.")
                if sub.count(".") >= 1:  # pelo menos subdominio.tld
                    subdomains.add(sub)

    return subdomains


# ─── Subfinder (via container) ──────────────────────────────────────────────


def subfinder_enum(domain: str) -> set[str]:
    """Enumera subdominios usando subfinder (dentro do container Kali)."""
    subdomains: set[str] = set()
    try:
        from engine.runtime_executor import exec_kali
        result = exec_kali(["subfinder", "-d", domain, "-silent"], timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                sub = line.strip().lower()
                if sub and sub.endswith(f".{domain}"):
                    subdomains.add(sub)
    except Exception as exc:
        _warn(f"subfinder failed: {exc}")
    return subdomains


# ─── Assetfinder (via container) ────────────────────────────────────────────


def assetfinder_enum(domain: str) -> set[str]:
    """Enumera subdominios usando assetfinder."""
    subdomains: set[str] = set()
    try:
        from engine.runtime_executor import exec_kali
        result = exec_kali(["assetfinder", "--subs-only", domain], timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                sub = line.strip().lower()
                if sub and sub.endswith(f".{domain}"):
                    subdomains.add(sub)
    except Exception as exc:
        _warn(f"assetfinder failed: {exc}")
    return subdomains


# ─── DNS Resolution ─────────────────────────────────────────────────────────


def resolve_subdomain(subdomain: str, record_type: str = "A", timeout: float = 3.0) -> dict:
    """Resolve um subdominio para IP.

    Returns:
        {"subdomain": ..., "resolved": bool, "ips": [...], "record_type": ...}
    """
    ips: list[str] = []
    try:
        if record_type == "A":
            info = socket.getaddrinfo(subdomain, 80, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set(item[4][0] for item in info))
        elif record_type == "AAAA":
            info = socket.getaddrinfo(subdomain, 80, socket.AF_INET6, socket.SOCK_STREAM)
            ips = list(set(item[4][0] for item in info))
        elif record_type == "CNAME":
            # DNS lookup nativo
            result = subprocess.run(
                ["nslookup", "-type=CNAME", subdomain],
                capture_output=True, text=True, timeout=timeout,
            )
            for line in result.stdout.splitlines():
                m = re.search(r"canonical name = (\S+)", line)
                if m:
                    ips.append(m.group(1))
    except (socket.gaierror, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except Exception as exc:
        _debug(f"resolve {subdomain}: {exc}")

    return {
        "subdomain": subdomain,
        "resolved": len(ips) > 0,
        "ips": ips,
        "record_type": record_type,
    }


def resolve_all(subdomains: list[str], record_type: str = "A", concurrency: int = 10) -> list[dict]:
    """Resolve lista de subdominios."""
    results = []
    for sub in subdomains:
        results.append(resolve_subdomain(sub, record_type))
    return results


# ─── Enumeração completa ─────────────────────────────────────────────────────


def enum_domain(
    domain: str,
    sources: list[str] | None = None,
    resolve: bool = True,
    depth: int = 1,
) -> dict:
    """Enumera subdominios de um dominio de todas as fontes disponiveis."""
    if sources is None:
        sources = ["crtsh", "subfinder", "assetfinder"]

    all_subdomains: set[str] = set()

    # Fase 1: Coleta
    for source in sources:
        try:
            if source == "crtsh":
                result = crtsh_enum(domain)
                _debug(f"crt.sh: {len(result)} subdominios")
                all_subdomains.update(result)
            elif source == "subfinder":
                result = subfinder_enum(domain)
                _debug(f"subfinder: {len(result)} subdominios")
                all_subdomains.update(result)
            elif source == "assetfinder":
                result = assetfinder_enum(domain)
                _debug(f"assetfinder: {len(result)} subdominios")
                all_subdomains.update(result)
        except Exception as exc:
            _warn(f"Source {source} failed: {exc}")

    # Dedup e ordena
    sorted_subs = sorted(all_subdomains)

    # Fase 2: Resolucao DNS
    resolution: list[dict] = []
    if resolve and sorted_subs:
        resolution = resolve_all(sorted_subs)
        resolved_count = sum(1 for r in resolution if r["resolved"])
    else:
        resolved_count = 0

    # Fase 3: Profundidade adicional (se depth > 1)
    if depth > 1:
        # Para cada subdominio resolvido, tenta enum recursiva
        deeper: set[str] = set()
        for r in resolution:
            if r["resolved"]:
                deeper_subs = crtsh_enum(r["subdomain"])
                for ds in deeper_subs:
                    if ds not in all_subdomains and ds.endswith(f".{domain}"):
                        deeper.add(ds)
        if deeper:
            sorted_deeper = sorted(deeper)
            if resolve:
                deeper_resolution = resolve_all(sorted_deeper)
                resolved_deeper = sum(1 for r in deeper_resolution if r["resolved"])
            else:
                deeper_resolution = []
                resolved_deeper = 0
            resolution.extend(deeper_resolution)
            sorted_subs.extend(sorted_deeper)
            resolved_count += resolved_deeper
            all_subdomains.update(deeper)

    return {
        "ok": True,
        "domain": domain,
        "sources": sources,
        "total": len(sorted_subs),
        "resolved": resolved_count,
        "subdomains": sorted_subs,
        "resolution": resolution,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────


def cmd_enum(args: argparse.Namespace) -> dict:
    """Enumera subdominios."""
    sources = []
    if args.source_all:
        sources = ["crtsh", "subfinder", "assetfinder"]
    elif args.source_crtsh:
        sources.append("crtsh")
    if args.source_subfinder:
        sources.append("subfinder")
    if args.source_assetfinder:
        sources.append("assetfinder")
    if not sources:
        sources = ["crtsh"]  # default: passivo apenas

    result = enum_domain(
        domain=args.domain,
        sources=sources,
        resolve=args.resolve,
        depth=args.depth,
    )
    return result


def cmd_resolve(args: argparse.Namespace) -> dict:
    """Resolve subdominios de um arquivo."""
    if not args.subdomains:
        raise redlensctl.RedLensError("--subdomains (arquivo) obrigatorio")
    try:
        subs = [
            line.strip() for line in
            Path(args.subdomains).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception as exc:
        raise redlensctl.RedLensError(f"Erro lendo {args.subdomains}: {exc}") from exc

    results = resolve_all(subs, args.record_type)
    resolved = sum(1 for r in results if r["resolved"])
    return {
        "ok": True,
        "total": len(subs),
        "resolved": resolved,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="subdomain-safe", description="Subdomain enumeration toolkit")
    parser.add_argument("--run", help="Run ID para registrar inventory")
    sub = parser.add_subparsers(dest="action", required=True)

    # enum
    e = sub.add_parser("enum", help="Enumera subdominios")
    e.add_argument("--domain", required=True)
    e.add_argument("--resolve", action="store_true", default=True, help="Resolve DNS")
    e.add_argument("--depth", type=int, default=1, help="Profundidade de enum recursiva")
    e.add_argument("--source-all", action="store_true", help="Usar todas as fontes")
    e.add_argument("--source-crtsh", action="store_true", help="Usar crt.sh")
    e.add_argument("--source-subfinder", action="store_true", help="Usar subfinder")
    e.add_argument("--source-assetfinder", action="store_true", help="Usar assetfinder")

    # resolve
    r = sub.add_parser("resolve", help="Resolve subdominios de arquivo")
    r.add_argument("--domain", required=True)
    r.add_argument("--subdomains", help="Arquivo com lista de subdominios")
    r.add_argument("--record-type", choices=["A", "AAAA", "CNAME"], default="A")

    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        if args.action == "enum":
            result = cmd_enum(args)
        elif args.action == "resolve":
            result = cmd_resolve(args)
        else:
            raise redlensctl.RedLensError(f"Unknown action: {args.action}")

        # Registra no inventory se run foi fornecido
        if args.run and result.get("ok") and result.get("subdomains"):
            try:
                directory = redlensctl.run_dir(args.run)
                timestamp = _iso()

                # Registra cada subdominio resolvido no inventory
                resolution_map = {}
                if result.get("resolution"):
                    for res in result["resolution"]:
                        if res.get("resolved"):
                            resolution_map[res["subdomain"]] = res.get("ips", [])

                for sub in result["subdomains"]:
                    ips = resolution_map.get(sub, [])
                    method = "dns" if ips else "passive"
                    try:
                        redlensctl.record_inventory(
                            directory, "subdomain",
                            f"https://{sub}" if ips else sub,
                            source=method,
                            method="GET",
                        )
                    except Exception:
                        pass  # dedup silencioso

                # Salva evidencia
                raw_dir = directory / "evidence" / "raw"
                raw_dir.mkdir(parents=True, exist_ok=True)
                evidence_path = raw_dir / f"{timestamp}-subdomain-{args.domain}.json"
                # Evidencia inclui tudo
                redlensctl.write_json(evidence_path, result)

                sanitized_dir = directory / "evidence" / "sanitized"
                sanitized_dir.mkdir(parents=True, exist_ok=True)
                summary_path = sanitized_dir / f"{timestamp}-subdomain-{args.domain}-summary.json"
                # Resumo sanitizado (sem IPs internos)
                summary = {
                    "domain": args.domain,
                    "total": result["total"],
                    "resolved": result["resolved"],
                    "subdomains": result["subdomains"],
                }
                redlensctl.write_json(summary_path, summary)

                # Atualiza coverage surface
                coverage = redlensctl.read_json(directory / "state" / "coverage.json")
                if "surface" in coverage.get("categories", {}):
                    existing = coverage["categories"]["surface"].get("evidence", [])
                    existing.append(str(evidence_path.relative_to(directory)))
                    coverage["categories"]["surface"] = {
                        "status": "confirmed",
                        "summary": f"Subdomain enumeration: {result['total']} subdominios encontrados, {result['resolved']} resolvidos",
                        "evidence": existing,
                    }
                    redlensctl.write_json(directory / "state" / "coverage.json", coverage)

                redlensctl.append_event(directory, "subdomain.enum", {
                    "domain": args.domain,
                    "total": result["total"],
                    "resolved": result["resolved"],
                })
            except Exception as exc:
                _warn(f"Erro registrando inventory: {exc}")

        # Output (sem os dados brutos de resolucao, a menos que rich)
        output = {k: v for k, v in result.items() if k != "resolution"}
        print(json.dumps(output, ensure_ascii=False, indent=2, default=str))
        return 0

    except (redlensctl.RedLensError, json.JSONDecodeError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
