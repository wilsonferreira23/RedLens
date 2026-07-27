#!/usr/bin/env python3
"""Scoped browser flows through Kali, preferring CloakBrowser."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "runtime"))

import redlensctl  # noqa: E402
from browser_runner import BrowserRunner, BrowserRunnerError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(prog="browser-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--form-spec")
    parser.add_argument("--role", default="default")
    args = parser.parse_args()
    runner = BrowserRunner()
    workspace = runner.worker.parent
    temp = None
    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)
        role = redlensctl.safe_name(args.role, "Papel")
        scope = redlensctl.read_json(directory / "scope" / "scope.json")
        action = "snapshot"
        fields = []
        submit_selector = ""
        wait_ms = 1000
        if args.form_spec:
            if scope["credentials"] == "none":
                raise redlensctl.RedLensError(
                    "A operação não possui credenciais de teste autorizadas."
                )
            spec_path = Path(args.form_spec)
            spec_path = (
                spec_path.resolve()
                if spec_path.is_absolute()
                else (directory / spec_path).resolve()
            )
            if directory.resolve() not in spec_path.parents or not spec_path.is_file():
                raise redlensctl.RedLensError("Especificação de formulário fora da operação.")
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            if spec.get("url", args.url) != args.url:
                raise redlensctl.RedLensError("A URL da especificação não corresponde ao alvo.")
            fields = spec["fields"]
            if not fields or any(set(item) != {"selector", "value"} for item in fields):
                raise redlensctl.RedLensError("Campos de formulário inválidos.")
            submit_selector = spec["submit_selector"]
            wait_ms = spec.get("wait_ms", 1000)
            action = "form"
        token = uuid.uuid4().hex
        temp = workspace / ".redlens" / token
        temp.mkdir(parents=True, mode=0o700)
        output = temp / "output"
        state_private = directory / "evidence" / "private" / "sessions" / f"{role}.json"
        state_private.parent.mkdir(parents=True, exist_ok=True)
        temp_state = temp / "browser-state.json"
        if state_private.is_file():
            shutil.copy2(state_private, temp_state)
        config = {
            "action": action,
            "url": args.url,
            "allowed_schemes": scope["allowed_schemes"],
            "allowed_domains": scope["allowed_domains"],
            "allowed_ports": scope["allowed_ports"],
            "fields": fields,
            "submit_selector": submit_selector,
            "wait_ms": wait_ms,
            "role": role,
            "state": str(temp_state),
        }
        (temp / "config.json").write_text(
            json.dumps(config, ensure_ascii=False), encoding="utf-8"
        )
        result = runner.navigate(temp / "config.json", output)
        if result.returncode != 0:
            raise redlensctl.RedLensError(result.stderr.strip() or "Falha no navegador.")
        metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
        redlensctl.scoped_url(directory, metadata["final_url"])
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        evidence_dir = directory / "evidence" / "raw" / f"{timestamp}-browser"
        shutil.copytree(output, evidence_dir)
        if temp_state.is_file():
            shutil.copy2(temp_state, state_private)
            session = redlensctl.record_session(
                directory, role, metadata["backend"], state_private
            )
        else:
            session = None
        inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
        recorded = []
        for url in inventory.get("urls", []):
            try:
                item_id, _, _ = redlensctl.record_inventory(
                    directory, "endpoint", url, "browser"
                )
                recorded.append(item_id)
            except redlensctl.RedLensError:
                continue
        redlensctl.append_event(directory, "browser.captured", {
            "backend": metadata["backend"],
            "role": role,
            "evidence": str(evidence_dir.relative_to(directory)),
            "inventory_count": len(recorded),
        })
        print(json.dumps({
            "ok": True,
            "action": action,
            "metadata": metadata,
            "evidence": str(evidence_dir.relative_to(directory)),
            "inventory_items": recorded,
            "session": session,
        }, ensure_ascii=False, indent=2))
        return 0
    except (
        redlensctl.RedLensError,
        BrowserRunnerError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
        OSError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        if temp and temp.exists():
            shutil.rmtree(temp)


if __name__ == "__main__":
    raise SystemExit(main())
