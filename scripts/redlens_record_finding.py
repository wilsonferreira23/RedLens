#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


REQUIRED = ["id", "title", "severity", "confidence", "affected_assets", "business_impact", "remediation"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Append a RedLens finding to findings.jsonl")
    parser.add_argument("--state", required=True)
    parser.add_argument("--finding", required=True, help="Path to finding JSON")
    args = parser.parse_args()

    state = Path(args.state)
    finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    missing = [key for key in REQUIRED if key not in finding]
    if missing:
        raise SystemExit(f"missing required fields: {', '.join(missing)}")
    finding.setdefault("recorded_at", datetime.now(timezone.utc).isoformat())
    with (state / "findings.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(finding, sort_keys=True) + "\n")
    print(f"Recorded finding {finding['id']}")


if __name__ == "__main__":
    main()
