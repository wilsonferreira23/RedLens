"""Validate the tool lock and emit a small, portable SBOM document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_manifest(lock_path: Path) -> dict:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    components = []
    for name, version in sorted(lock.get("apt_packages", {}).items()):
        components.append({"type": "library", "name": name, "version": version, "source": "apt"})
    for name, version in sorted(lock.get("python_packages", {}).items()):
        components.append({"type": "library", "name": name, "version": version, "source": "pypi"})
    for name, checksum in sorted(lock.get("vendored_binaries", {}).items()):
        components.append({"type": "file", "name": name, "checksum": checksum, "source": "vendor"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"base_image": lock["base_image"], "lock_schema": lock["schema_version"]},
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path(__file__).parent / "kali-image" / "tools.lock.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = build_manifest(args.lock)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "components": len(manifest["components"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
