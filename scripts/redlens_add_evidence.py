#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Append an artifact to RedLens evidence_manifest.jsonl")
    parser.add_argument("--state", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--finding-id", default="")
    parser.add_argument("--type", required=True, dest="artifact_type")
    parser.add_argument("--path", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--redaction-status", default="unreviewed")
    args = parser.parse_args()

    artifact_path = Path(args.path)
    record = {
        "id": args.id,
        "finding_id": args.finding_id,
        "artifact_type": args.artifact_type,
        "path": str(artifact_path),
        "source_environment": args.source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sha256": sha256(artifact_path) if artifact_path.exists() and artifact_path.is_file() else "",
        "redaction_status": args.redaction_status,
    }
    with (Path(args.state) / "evidence_manifest.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"Recorded evidence {args.id}")


if __name__ == "__main__":
    main()
