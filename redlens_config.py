"""Portable RedLens configuration with environment overrides."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


def _path(value: str | None, default: Path) -> Path:
    candidate = Path(value).expanduser() if value else default
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate


def _config_file() -> Path:
    explicit = os.environ.get("REDLENS_CONFIG")
    if explicit:
        return Path(explicit).expanduser().resolve()
    home_override = os.environ.get("REDLENS_HOME")
    if home_override:
        return Path(home_override).expanduser().resolve() / "redlens.toml"
    current = Path.cwd() / "redlens.toml"
    if current.is_file():
        return current.resolve()
    return Path(__file__).resolve().parent / "redlens.toml"


def _default_data_dir() -> Path:
    """Keep operational data outside a portable source checkout."""
    if data_home := os.environ.get("XDG_DATA_HOME"):
        return Path(data_home).expanduser() / "redlens"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "redlens"
    return Path.home() / ".local" / "share" / "redlens"


def _read_file() -> dict:
    path = _config_file()
    if not path.is_file():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


@dataclass(frozen=True)
class Config:
    home: Path
    data_dir: Path
    backups_dir: Path
    runtime_dir: Path
    workspace_dir: Path
    runs_dir: Path
    container_name: str
    compose_file: Path
    cloak_python: Path
    cloak_cache: Path
    require_adata: bool
    min_free_gb: float


def load_config() -> Config:
    """Load configuration without requiring a fixed checkout location."""
    document = _read_file()
    paths = document.get("paths", {})
    runtime = document.get("runtime", {})
    source_root = Path(__file__).resolve().parent
    home = _path(os.environ.get("REDLENS_HOME") or paths.get("home"), source_root)
    data_default = home / "data" if os.environ.get("REDLENS_HOME") else _default_data_dir()
    data_dir = _path(
        os.environ.get("REDLENS_DATA_DIR") or paths.get("data_dir"),
        data_default,
    )
    backups_dir = _path(
        os.environ.get("REDLENS_BACKUPS_DIR") or paths.get("backups_dir"),
        data_dir / "backups",
    )
    runtime_dir = _path(
        os.environ.get("REDLENS_RUNTIME_DIR") or paths.get("runtime_dir"),
        home / "runtime",
    )
    workspace_dir = _path(
        os.environ.get("REDLENS_WORKSPACE_DIR") or paths.get("workspace_dir"),
        runtime_dir / "kali-workspace",
    )
    runs_dir = _path(
        os.environ.get("REDLENS_RUNS_DIR") or paths.get("runs_dir"),
        data_dir / "runs",
    )
    compose_file = _path(
        os.environ.get("REDLENS_COMPOSE_FILE") or runtime.get("compose_file"),
        runtime_dir / "compose.yaml",
    )
    cloak_python = _path(
        os.environ.get("REDLENS_CLOAK_PYTHON") or runtime.get("cloak_python"),
        runtime_dir / "cloakbrowser-venv" / "bin" / "python",
    )
    cloak_cache = _path(
        os.environ.get("REDLENS_CLOAK_CACHE") or runtime.get("cloak_cache"),
        runtime_dir / "cloakbrowser-cache",
    )
    container_name = os.environ.get("REDLENS_CONTAINER") or runtime.get(
        "container_name", "kali-pentest"
    )
    require_adata = os.environ.get("REDLENS_REQUIRE_ADATA", "0").lower() in {
        "1", "true", "yes"
    }
    min_free_gb = float(os.environ.get("REDLENS_MIN_FREE_GB", "5"))
    return Config(
        home=home,
        data_dir=data_dir,
        backups_dir=backups_dir,
        runtime_dir=runtime_dir,
        workspace_dir=workspace_dir,
        runs_dir=runs_dir,
        container_name=container_name,
        compose_file=compose_file,
        cloak_python=cloak_python,
        cloak_cache=cloak_cache,
        require_adata=require_adata,
        min_free_gb=min_free_gb,
    )


def config_path(value: Path) -> Path:
    """Resolve a configured path while keeping callers independent of layout."""
    return value.expanduser().resolve()
