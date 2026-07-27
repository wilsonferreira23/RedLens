#!/usr/bin/env python3
"""RedLens Preflight — health check + auto-heal do runtime.

Modos:
  --check-only   Apenas diagnostico, sem correcao
  --heal         (padrao) Tenta corrigir problemas detectados
  --report-json  Saida em JSON via stdout (para consumo por redlensctl)

Fluxo:
  1. Diagnostico (health check completo)
  2. Auto-healing dos problemas corrigiveis
  3. Verificacao (health check pos-correcao)
  4. Relatorio consolidado
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "engine"))

from redlens_config import load_config  # noqa: E402

# ─── Mapeamento bin -> adapter (para correcao dos wrappers) ──────────────

BIN_TO_ADAPTER = {
    "login-safe": "login_adapter.py",
    "preflight": "preflight.py",
    "redlensctl": "redlensctl.py",
    "web-safe": "web_validator.py",
    "api-safe": "api_adapter.py",
    "mutate-safe": "mutate_adapter.py",
    "sqlmap-safe": "sqlmap_adapter.py",
    "xss-safe": "xss_adapter.py",
    "cmdi-safe": "cmdi_adapter.py",
    "csrf-safe": "csrf_adapter.py",
    "massassign-safe": "mass_assignment_adapter.py",
    "plan-safe": "planner_adapter.py",
    "browser-safe": "browser_adapter.py",
    "authz-safe": "authz_adapter.py",
    "decepticon-analyze": "decepticon_analysis.py",
    "ssrf-safe": "ssrf_callback_validator.py",
    "ssti-safe": ("class_mutation_adapter.py", "ssti-safe"),
    "traversal-safe": ("class_mutation_adapter.py", "traversal-safe"),
    "nosqli-safe": "nosqli_validator.py",
    "race-workflow-safe": "race_workflow.py",
    "semantic-authz-safe": "semantic_authz.py",
    "xxe-safe": "xxe_validator.py",
    "login-v2-safe": "login_adapter.py",
    "replay-safe": "replay_adapter.py",
    "kali-safe": "kali_adapter.py",
    "redlens-health": "health.py",
}

WRAPPER_TEMPLATE = r"""#!/bin/sh
set -eu

SOURCE=$0
while [ -L "$SOURCE" ]; do
  LINK=$(readlink "$SOURCE")
  case "$LINK" in
    /*) SOURCE=$LINK ;;
    *) SOURCE=$(dirname "$SOURCE")/$LINK ;;
  esac
done
BIN_DIR=$(CDPATH= cd -- "$(dirname "$SOURCE")" && pwd)
REDLENS_HOME=${REDLENS_HOME:-$(CDPATH= cd -- "$BIN_DIR/.." && pwd)}
REDLENS_PYTHON=${REDLENS_PYTHON:-$REDLENS_HOME/.venv/bin/python}
[ -x "$REDLENS_PYTHON" ] || REDLENS_PYTHON=python3
export REDLENS_HOME
_ADAPTER="$REDLENS_HOME/adapters/ADAPTER_FILE"
if [ -n "${REDLENS_TOOL_OVERRIDE:-}" ]; then
  export REDLENS_TOOL="$REDLENS_TOOL_OVERRIDE"
fi
exec "$REDLENS_PYTHON" "$_ADAPTER" "$@"
"""

LOCAL_BIN = Path("~/.local/bin").expanduser()
HEAL_LOG: list[dict] = []


# ─── Helpers ─────────────────────────────────────────────────────────────

def _log(level: str, scope: str, action: str, detail: str = "") -> None:
    entry = {"level": level, "scope": scope, "action": action, "detail": detail}
    HEAL_LOG.append(entry)
    icon = {"ok": "✅", "fixed": "🔧", "skipped": "⏭️", "error": "❌", "info": "ℹ️"}.get(level, "•")
    print(f"  {icon} [{scope}] {action}" + (f" — {detail}" if detail else ""))


def _run(cmd: list[str], timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=check)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, "", "TIMEOUT")


def _container_running(name: str) -> bool:
    r = _run(["docker", "inspect", name, "--format", "{{.State.Status}}"])
    return r.returncode == 0 and r.stdout.strip() == "running"


# ─── Etapa 1: Diagnostico ────────────────────────────────────────────────

def diagnose() -> dict:
    """Roda os mesmos checks do health.py + detecta wrappers quebrados."""
    config = load_config()
    issues: list[dict] = []
    summary = {"ok": True, "checks": 0, "passed": 0, "failed": 0, "healed": 0, "issues": issues}

    # 1. ADATA
    adata_ok = str(config.data_dir).startswith("/Volumes/ADATA SC735/")
    writable = os.access(config.data_dir, os.W_OK) if config.data_dir.exists() else False
    if not adata_ok:
        issues.append({"id": "adata-mount", "severity": "critical", "check": "ADATA montado", "ok": False})
    elif not writable:
        issues.append({"id": "adata-writable", "severity": "critical", "check": "ADATA gravavel", "ok": False})
    else:
        summary["passed"] += 1
    summary["checks"] += 1

    # 2. Docker + Kali container
    docker_ok = _run(["docker", "info"]).returncode == 0
    if not docker_ok:
        issues.append({"id": "docker", "severity": "critical", "check": "Docker rodando", "ok": False})
    else:
        summary["passed"] += 1
    summary["checks"] += 1

    kali_ok = _container_running(config.container_name) if docker_ok else False
    if not kali_ok:
        issues.append({"id": "kali-container", "severity": "high", "check": "Kali container running", "ok": False,
                       "healable": docker_ok})
    else:
        summary["passed"] += 1
    summary["checks"] += 1

    # 3. Wrappers em bin/
    bin_dir = config.home / "bin"
    broken_wrappers = []
    for script_name in BIN_TO_ADAPTER:
        sp = bin_dir / script_name
        if not sp.is_file():
            broken_wrappers.append({"script": script_name, "reason": "ausente"})
            continue
        content = sp.read_text()
        # Verifica se usa /usr/bin/python3 (antigo, quebrado)
        if "/usr/bin/python3" in content and ".venv/bin/python" not in content:
            broken_wrappers.append({"script": script_name, "reason": "python3 errado (system python)"})
            continue
        # Verifica se tem shebang
        if not content.startswith("#!/bin/sh"):
            broken_wrappers.append({"script": script_name, "reason": "shebang invalido"})
            continue

    if broken_wrappers:
        issues.append({"id": "broken-wrappers", "severity": "medium",
                       "check": f"{len(broken_wrappers)} wrappers quebrados",
                       "healable": True, "details": broken_wrappers})
    else:
        summary["passed"] += 1
    summary["checks"] += 1

    # 4. Symlinks em ~/.local/bin/
    broken_links = []
    if LOCAL_BIN.is_dir():
        for link in LOCAL_BIN.glob("redlens-*"):
            if link.is_symlink():
                target = link.resolve()
                if not target.exists():
                    broken_links.append({"link": str(link), "target": str(target), "reason": "quebrado"})
                elif not str(target).startswith("/Volumes/ADATA SC735/"):
                    broken_links.append({"link": str(link), "target": str(target), "reason": "fora da ADATA"})

    if broken_links:
        issues.append({"id": "broken-symlinks", "severity": "low",
                       "check": f"{len(broken_links)} symlinks problematicos",
                       "healable": True, "details": broken_links})
    else:
        summary["passed"] += 1
    summary["checks"] += 1

    # 5. CloakBrowser
    try:
        from adapters.health import cloakbrowser_navigation_check
        cloak = cloakbrowser_navigation_check()
        if not cloak.get("available"):
            issues.append({"id": "cloakbrowser", "severity": "high",
                           "check": "CloakBrowser navegacao",
                           "ok": False, "reason": cloak.get("reason", "falha")})
        else:
            summary["passed"] += 1
    except Exception as exc:
        issues.append({"id": "cloakbrowser", "severity": "high",
                       "check": "CloakBrowser", "ok": False, "reason": str(exc)[:100]})
    summary["checks"] += 1

    # 6. .venv existe
    venv_python = config.home / ".venv" / "bin" / "python3"
    if not venv_python.is_file():
        issues.append({"id": "venv-missing", "severity": "critical",
                       "check": ".venv/bin/python3", "ok": False,
                       "healable": False})
    else:
        summary["passed"] += 1
    summary["checks"] += 1

    summary["ok"] = len([i for i in issues if i.get("severity") in ("critical", "high")]) == 0
    return summary


# ─── Etapa 2: Auto-healing ──────────────────────────────────────────────

def heal_wrappers() -> int:
    """Corrige wrappers em bin/ que usam Python errado."""
    config = load_config()
    bin_dir = config.home / "bin"
    healed = 0

    for script_name, adapter_ref in BIN_TO_ADAPTER.items():
        sp = bin_dir / script_name
        if not sp.is_file():
            _log("skipped", script_name, "Nao encontrado em bin/")
            continue

        content = sp.read_text()

        # Determina adapter file e REDLENS_TOOL
        env_override = ""
        if isinstance(adapter_ref, tuple):
            adapter_file, tool_name = adapter_ref
            env_override = f'\nexport REDLENS_TOOL_OVERRIDE="{tool_name}"'
        else:
            adapter_file = adapter_ref

        # Gera o wrapper correto
        new_content = WRAPPER_TEMPLATE.replace("ADAPTER_FILE", adapter_file)
        if env_override:
            new_content = new_content.replace(
                'export REDLENS_HOME',
                f'export REDLENS_HOME{env_override}'
            )

        if content == new_content:
            continue

        sp.write_text(new_content)
        os.chmod(sp, sp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        _log("fixed", script_name, "Wrapper corrigido",
             f"-> {adapter_file}" + (f" (tool={tool_name})" if isinstance(adapter_ref, tuple) else ""))
        healed += 1

    return healed


def heal_symlinks() -> int:
    """Corrige/recria symlinks em ~/.local/bin/ apenas para wrappers conhecidos."""
    config = load_config()
    bin_dir = config.home / "bin"
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    healed = 0

    # Passo 1: Remove symlinks orfaos (quebrados ou que nao estao no mapa)
    def _link_name(script_name: str) -> str:
        return script_name if script_name.startswith("redlens-") else f"redlens-{script_name}"
    valid_link_names = {_link_name(s) for s in BIN_TO_ADAPTER}
    if LOCAL_BIN.is_dir():
        for entry in LOCAL_BIN.iterdir():
            if not entry.name.startswith("redlens-"):
                continue
            # Remove duplicatas do tipo redlens-redlens-* (prefixo duplicado)
            if entry.name.startswith("redlens-redlens-"):
                entry.unlink()
                _log("fixed", entry.name, "Symlink duplicado removido")
                healed += 1
                continue
            if entry.name in valid_link_names:
                continue
            # Link que nao esta no mapeamento -> remove
            if entry.is_symlink() or entry.is_file():
                entry.unlink()
                _log("fixed", entry.name, "Symlink orfao removido")
                healed += 1

    # So cria symlinks para os wrappers mapeados (evita lixo como .backup, etc.)
    for script_name in BIN_TO_ADAPTER:
        target = bin_dir / script_name
        if not target.is_file():
            continue

        link_name = _link_name(script_name)
        link_path = LOCAL_BIN / link_name

        # Se ja existe e esta correto, pula
        if link_path.is_symlink() and link_path.resolve() == target:
            continue
        # Se existe mas errado (outro destino ou arquivo solto), remove
        if link_path.exists() or link_path.is_symlink():
            link_path.unlink()

        link_path.symlink_to(target)
        _log("fixed", link_name, "Symlink recriado", str(target))
        healed += 1

    return healed


def heal_kali_container() -> bool:
    """Tenta iniciar o container Kali se ele existe mas nao esta rodando."""
    config = load_config()
    name = config.container_name

    # Verifica se o container existe (mas parado)
    r = _run(["docker", "inspect", name, "--format", "{{.State.Status}}"])
    if r.returncode != 0:
        # Container nem existe — tenta docker compose
        compose = config.compose_file
        if compose.is_file():
            _log("info", "kali", "Container nao existe, tentando docker compose up")
            r2 = _run(["docker", "compose", "-f", str(compose), "up", "-d"], timeout=120)
            if r2.returncode == 0:
                time.sleep(3)
                if _container_running(name):
                    _log("fixed", "kali", "Container criado e iniciado via compose")
                    return True
            _log("error", "kali", "Falha ao subir container via compose", r2.stderr[:200])
            return False

        _log("error", "kali", "Container nao encontrado e sem compose", "Execute: docker compose up -d")
        return False

    status = r.stdout.strip()
    if status == "running":
        _log("ok", "kali", "Container ja esta rodando")
        return True

    if status in ("exited", "paused", "created"):
        r2 = _run(["docker", "start", name], timeout=30)
        if r2.returncode == 0:
            time.sleep(2)
            if _container_running(name):
                _log("fixed", "kali", "Container iniciado")
                return True
        _log("error", "kali", "Falha ao iniciar container", r2.stderr[:200])
        return False

    _log("skipped", "kali", f"Container em estado inesperado: {status}")
    return False


def heal_pythonpath_in_scripts() -> int:
    """Garante que scripts no ~/.local/bin usam o python do .venv."""
    config = load_config()
    venv_python = config.home / ".venv" / "bin" / "python3"
    if not venv_python.is_file():
        return 0

    patched = 0
    for f in LOCAL_BIN.glob("redlens-*"):
        if not f.is_file() or f.is_symlink():
            continue
        try:
            content = f.read_text()
        except (OSError, PermissionError):
            continue
        # Se usa python3 direto e NAO usa o .venv
        if "exec /usr/bin/python3" in content or "exec python3" in content:
            if ".venv" not in content:
                new_content = content.replace(
                    "exec /usr/bin/python3",
                    f'REDLENS_PYTHON=$(dirname "$0")/../../.venv/bin/python3\nexec "$REDLENS_PYTHON"'
                )
                if new_content != content:
                    f.write_text(new_content)
                    os.chmod(f, f.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    _log("fixed", f.name, "Python path corrigido", "-> .venv/bin/python3")
                    patched += 1
    return patched


def heal() -> dict:
    """Executa todas as correcoes e retorna sumario."""
    results = {"healed": 0, "failed": 0, "details": []}

    n = heal_wrappers()
    results["healed"] += n
    if n:
        results["details"].append(f"{n} wrappers corrigidos")

    n = heal_symlinks()
    results["healed"] += n
    if n:
        results["details"].append(f"{n} symlinks recriados")

    n = heal_pythonpath_in_scripts()
    results["healed"] += n
    if n:
        results["details"].append(f"{n} scripts com PYTHONPATH ajustados")

    if heal_kali_container():
        results["healed"] += 1

    return results


# ─── Etapa 3: Verificacao pos-correcao ───────────────────────────────────

def verify() -> dict:
    """Re-executa o diagnostico apos correcoes e retorna estado final."""
    return diagnose()


# ─── Main ─────────────────────────────────────────────────────────────────

def preflight(check_only: bool = False, report_json: bool = False) -> dict:
    """Roda o preflight completo."""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     RedLens Preflight — Diagnostico do Runtime             ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # Etapa 1: Diagnostico
    print("📋 Etapa 1/3: Diagnosticando...")
    print()
    diag = diagnose()
    ok_count = diag.get("passed", 0)
    total = diag.get("checks", 0)
    print(f"\n   Resultado: {ok_count}/{total} checks OK")
    if diag.get("issues"):
        sev_count = {}
        for iss in diag["issues"]:
            sev = iss.get("severity", "unknown")
            sev_count[sev] = sev_count.get(sev, 0) + 1
        print(f"   Problemas: {', '.join(f'{n} {s}' for s, n in sev_count.items())}")
    print()

    # Se tem problemas e nao e check-only, tenta corrigir
    heal_result = {"healed": 0, "failed": 0, "details": []}
    if diag.get("issues") and not check_only:
        print("🔧 Etapa 2/3: Aplicando correcoes...")
        print()
        heal_result = heal()
        print(f"\n   {heal_result['healed']} correcoes aplicadas")
        if heal_result["failed"]:
            print(f"   {heal_result['failed']} falhas")
        print()

        # Etapa 3: Verificacao
        print("📋 Etapa 3/3: Verificando correcoes...")
        print()
        diag = verify()
        ok_count = diag.get("passed", 0)
        total = diag.get("checks", 0)
        print(f"\n   Resultado: {ok_count}/{total} checks OK")
    elif diag.get("issues") and check_only:
        print("⏭️  Modo --check-only, correcoes nao aplicadas")
        print()

    # Relatorio final
    final_issues = diag.get("issues", [])
    remaining = [i for i in final_issues if not i.get("ok", True)]
    all_ok = len(remaining) == 0

    print("━" * 56)
    if all_ok:
        print("✅  PREFLIGHT: AMBIENTE PRONTO PARA PENTEST")
    else:
        print(f"⚠️   PREFLIGHT: {len(remaining)} problema(s) pendente(s)")
        for iss in remaining:
            print(f"   ❌ [{iss.get('severity','?').upper()}] {iss['check']}")
            if iss.get("reason"):
                print(f"      Motivo: {iss['reason']}")
            if iss.get("details"):
                for d in iss["details"]:
                    if isinstance(d, dict):
                        print(f"      - {d.get('script','')} {d.get('reason','')}")
                    else:
                        print(f"      - {d}")

    print("━" * 56)
    print()

    result = {
        "ok": all_ok,
        "check_only": check_only,
        "checks": {"passed": ok_count, "total": total, "issues": remaining},
        "healing": heal_result,
        "log": HEAL_LOG,
    }

    if report_json:
        print(json.dumps(result, indent=2, ensure_ascii=False), file=sys.stderr)

    return result


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="redlens-preflight")
    parser.add_argument("--check-only", action="store_true", help="Apenas diagnostico, sem correcao")
    parser.add_argument("--report-json", action="store_true", help="Saida JSON em stderr")
    args = parser.parse_args()

    result = preflight(check_only=args.check_only, report_json=args.report_json)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
