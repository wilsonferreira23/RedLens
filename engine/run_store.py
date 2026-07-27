"""Durable run storage primitives and schema migrations."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from redlens_config import load_config


CURRENT_SCHEMA_VERSION = 2


class RunStoreError(ValueError):
    """Raised when a run cannot be opened or migrated safely."""


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class RunStore:
    """Own run discovery, atomic JSON writes, backups, and migrations."""

    def __init__(self, runs_dir: Path | None = None, backups_dir: Path | None = None):
        config = load_config()
        self.runs_dir = Path(runs_dir or config.runs_dir)
        self.backups_dir = Path(backups_dir or config.backups_dir)

    def open(self, run_id: str) -> Path:
        if not run_id or Path(run_id).name != run_id or run_id in {".", ".."}:
            raise RunStoreError("Identificador de operação inválido.")
        directory = self.runs_dir / run_id
        if not directory.is_dir():
            raise RunStoreError(f"Operação não encontrada: {run_id}")
        return directory

    @staticmethod
    def read_json(path: Path) -> dict:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise RunStoreError(f"JSON inválido ou ausente: {path}") from exc
        if not isinstance(value, dict):
            raise RunStoreError(f"JSON deve ser um objeto: {path}")
        return value

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(path)

    def backup(self, run_id: str) -> Path:
        source = self.open(run_id)
        destination = self.backups_dir / f"{run_id}-{_timestamp()}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
        return destination

    def migration_plan(self, run_id: str) -> dict:
        directory = self.open(run_id)
        state = self.read_json(directory / "state" / "state.json")
        current = int(state.get("schema_version", 1))
        actions: list[str] = []
        if current < CURRENT_SCHEMA_VERSION:
            actions.append(f"state.json: schema_version {current} -> {CURRENT_SCHEMA_VERSION}")
        elif current > CURRENT_SCHEMA_VERSION:
            raise RunStoreError(
                f"Schema {current} é mais novo que o suportado ({CURRENT_SCHEMA_VERSION})."
            )
        for relative in (
            "state/coverage.json",
            "state/access-matrix.json",
            "state/resources.json",
        ):
            path = directory / relative
            if path.is_file() and "schema_version" not in self.read_json(path):
                actions.append(f"{relative}: adicionar schema_version {CURRENT_SCHEMA_VERSION}")
        if not (directory / "state" / "schema.json").is_file():
            actions.append("state/schema.json: criar manifesto de schema")
        return {
            "run_id": run_id,
            "current": current,
            "target": CURRENT_SCHEMA_VERSION,
            "actions": actions,
        }

    def migrate(self, run_id: str, dry_run: bool = False) -> dict:
        plan = self.migration_plan(run_id)
        if dry_run or not plan["actions"]:
            return {"ok": True, "dry_run": dry_run, "backup": None, **plan}

        backup = self.backup(run_id)
        directory = self.open(run_id)
        state_path = directory / "state" / "state.json"
        state = self.read_json(state_path)
        state["schema_version"] = CURRENT_SCHEMA_VERSION
        self.write_json(state_path, state)
        for relative in (
            "state/coverage.json",
            "state/access-matrix.json",
            "state/resources.json",
        ):
            path = directory / relative
            if path.is_file():
                document = self.read_json(path)
                document.setdefault("schema_version", CURRENT_SCHEMA_VERSION)
                self.write_json(path, document)
        self.write_json(directory / "state" / "schema.json", {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "documents": [
                "authorization/authorization.json",
                "scope/scope.json",
                "state/state.json",
                "state/coverage.json",
                "state/access-matrix.json",
                "state/resources.json",
            ],
        })
        return {"ok": True, "dry_run": False, "backup": str(backup), **plan}
