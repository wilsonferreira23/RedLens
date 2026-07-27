"""Safely adopt the current Kali container into the Compose runtime."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from redlens_config import load_config


class MigrationError(RuntimeError):
    """Raised when container adoption cannot continue safely."""


def _run(args: list[str], *, env: dict[str, str] | None = None, timeout: int = 120):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)


def inspect_container(name: str) -> dict | None:
    result = _run(["docker", "inspect", name])
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)[0]
    except (IndexError, json.JSONDecodeError) as exc:
        raise MigrationError(f"Resposta inválida do Docker ao inspecionar {name}.") from exc


def preflight() -> dict:
    config = load_config()
    info = {
        "container": config.container_name,
        "workspace": str(config.workspace_dir),
        "compose": str(config.compose_file),
        "exists": False,
        "running": False,
        "workspace_mounted": False,
        "image": None,
        "privileged": None,
        "network_mode": None,
        "ok": False,
    }
    if not config.compose_file.is_file():
        info["error"] = f"Compose ausente: {config.compose_file}"
        return info
    current = inspect_container(config.container_name)
    if current is None:
        info["error"] = f"Container ausente: {config.container_name}"
        return info
    info.update({
        "exists": True,
        "running": current.get("State", {}).get("Running", False),
        "image": current.get("Config", {}).get("Image"),
        "privileged": current.get("HostConfig", {}).get("Privileged"),
        "network_mode": current.get("HostConfig", {}).get("NetworkMode"),
    })
    expected = str(config.workspace_dir.resolve())
    info["workspace_mounted"] = any(
        mount.get("Type") == "bind"
        and str(Path(mount.get("Source", "")).resolve()) == expected
        and mount.get("Destination") == "/workspace"
        and mount.get("RW") is True
        for mount in current.get("Mounts", [])
    )
    info["ok"] = bool(
        info["running"]
        and info["workspace_mounted"]
        and info["privileged"] is True
        and info["network_mode"] == "host"
    )
    if not info["ok"]:
        info["error"] = "Container atual não corresponde ao baseline esperado."
    return info


def _compose(args: list[str], image: str, config) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({
        "REDLENS_IMAGE": image,
        "REDLENS_CONTAINER": config.container_name,
        "REDLENS_WORKSPACE_DIR": str(config.workspace_dir),
    })
    return _run(
        ["docker", "compose", "-f", str(config.compose_file), *args],
        env=env,
        timeout=1800,
    )


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", *args], timeout=timeout)


def _legacy_name(container: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{container}-legacy-{stamp}"[:63]


def _state_path(config) -> Path:
    return config.data_dir / "runtime" / "migration-state.json"


def _write_state(config, value: dict) -> None:
    path = _state_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def adopt(image: str, skip_health: bool = False) -> dict:
    config = load_config()
    baseline = preflight()
    if not baseline["ok"]:
        raise MigrationError(baseline.get("error", "Preflight falhou."))
    if inspect_container(config.container_name) is None:
        raise MigrationError("O container desapareceu durante o preflight.")
    image_info = _docker("image", "inspect", image)
    if image_info.returncode != 0:
        raise MigrationError(f"Imagem não encontrada localmente: {image}")
    legacy = _legacy_name(config.container_name)
    rename = _docker("rename", config.container_name, legacy)
    if rename.returncode != 0:
        raise MigrationError(rename.stderr.strip() or "Não foi possível preservar o container legado.")
    stopped = _docker("stop", legacy)
    if stopped.returncode != 0:
        _docker("rename", legacy, config.container_name)
        raise MigrationError(stopped.stderr.strip() or "Não foi possível parar o container legado.")
    state = {
        "legacy_container": legacy,
        "container": config.container_name,
        "old_image": baseline["image"],
        "new_image": image,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_state(config, state)
    started = _compose(["--profile", "web", "up", "-d"], image, config)
    if started.returncode != 0:
        rollback(config)
        raise MigrationError(started.stderr.strip() or "Compose não iniciou o runtime.")
    adopted = inspect_container(config.container_name)
    valid = bool(adopted and adopted.get("State", {}).get("Running"))
    if not skip_health:
        health = _run([sys.executable, "-m", "adapters.health"], timeout=180)
        valid = valid and health.returncode == 0
    if not valid:
        rollback(config)
        raise MigrationError("Health ou validação do container adotado falhou; rollback executado.")
    state["status"] = "adopted"
    _write_state(config, state)
    return {"ok": True, "state": state, "health_checked": not skip_health}


def rollback(config=None) -> dict:
    config = config or load_config()
    state_path = _state_path(config)
    if not state_path.is_file():
        raise MigrationError(f"Estado de migração ausente: {state_path}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    legacy = state["legacy_container"]
    current = config.container_name
    down = _compose(["--profile", "web", "down"], state.get("new_image", config.container_name), config)
    if down.returncode != 0 and inspect_container(current) is not None:
        _docker("stop", current)
        _docker("rm", current)
    if inspect_container(legacy) is None:
        raise MigrationError(f"Container legado não encontrado: {legacy}")
    if inspect_container(current) is not None:
        raise MigrationError(f"Nome do container ainda ocupado: {current}")
    renamed = _docker("rename", legacy, current)
    if renamed.returncode != 0:
        raise MigrationError(renamed.stderr.strip() or "Não foi possível restaurar o container legado.")
    started = _docker("start", current)
    if started.returncode != 0:
        raise MigrationError(started.stderr.strip() or "Não foi possível iniciar o container legado.")
    state["status"] = "rolled-back"
    _write_state(config, state)
    return {"ok": True, "state": state}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redlens runtime migration")
    parser.add_argument("action", choices=("preflight", "adopt", "rollback"))
    parser.add_argument("--image", help="Imagem imutável a adotar durante adopt.")
    parser.add_argument("--skip-health", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "preflight":
            result = preflight()
        elif args.action == "adopt":
            if not args.image:
                raise MigrationError("--image é obrigatório para adopt.")
            result = adopt(args.image, skip_health=args.skip_health)
        else:
            result = rollback()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (MigrationError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
