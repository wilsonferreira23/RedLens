#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize RedLens structured engagement state")
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", required=True, choices=["quick", "standard", "deep"])
    parser.add_argument("--type", required=True, dest="target_type")
    parser.add_argument("--authorization", required=True, choices=["confirmed"])
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report").mkdir(exist_ok=True)

    timestamp = now()
    write_json(
        out / "engagement.json",
        {
            "target_name": args.target,
            "assessment_mode": args.mode,
            "target_type": args.target_type,
            "authorization_status": args.authorization,
            "scope": [],
            "constraints": [],
            "risk_gates": [],
            "created_at": timestamp,
            "updated_at": timestamp,
        },
    )
    write_json(out / "target_model.json", {"assets": [], "entry_points": [], "trust_boundaries": [], "data_stores": []})
    write_json(out / "coverage.json", {"required": [], "completed": [], "gaps": []})
    for name in ("hypotheses.jsonl", "findings.jsonl", "evidence_manifest.jsonl", "command_log.jsonl", "decisions.jsonl"):
        (out / name).touch()

    print(f"Initialized RedLens state at {out}")


if __name__ == "__main__":
    main()
