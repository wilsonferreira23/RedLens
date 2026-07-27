"""Run score: gap/confidence report instead of an automatic security score.

Produces a deterministic, regenerable score object that is only allowed to
make claims when a valid benchmark file exists.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402

from coverage_cells import load_cells  # noqa: E402


RUBRIC = {
    "discovery_and_reachability": 15,
    "input_coverage": 10,
    "detection_critical_high": 20,
    "detection_medium": 5,
    "authorization_tenancy": 15,
    "business_logic": 10,
    "precision_validation": 10,
    "autonomy_resilience": 5,
    "evidence_report": 5,
    "operational_safety": 5,
}

BENCHMARK_INVALID_CAP = 70


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_benchmark(directory: Path) -> tuple[bool, dict | None]:
    path = directory / "benchmarks" / "ground-truth.json"
    if not path.is_file():
        return False, None
    try:
        data = redlensctl.read_json(path)
    except redlensctl.RedLensError:
        return False, None
    required = {"benchmark_run_id", "target", "verified_findings"}
    if not required.issubset(data.keys()):
        return False, None
    if not isinstance(data.get("verified_findings"), list):
        return False, None
    return True, data


def _load_inventory(directory: Path) -> list[dict]:
    items = []
    for path in (directory / "inventory").glob("*.json"):
        try:
            items.append(redlensctl.read_json(path))
        except redlensctl.RedLensError:
            continue
    return items


def _load_access_matrix(directory: Path) -> dict:
    path = directory / "state" / "access-matrix.json"
    if not path.is_file():
        return {"cells": {}}
    try:
        return redlensctl.read_json(path)
    except redlensctl.RedLensError:
        return {"cells": {}}


def _load_artifact_hashes(directory: Path) -> dict:
    path = directory / "evidence" / "sanitized" / "artifact-hashes.json"
    if not path.is_file():
        return {"files": {}}
    try:
        return redlensctl.read_json(path)
    except redlensctl.RedLensError:
        return {"files": {}}


def _dimension(name: str, score: float, reason: str) -> dict:
    return {
        "score": round(score, 2),
        "max": RUBRIC[name],
        "reason": reason,
    }


def score_run(run_id: str) -> dict:
    directory = redlensctl.run_dir(run_id)
    cells = load_cells(directory)
    total_cells = max(len(cells), 1)

    confirmed = sum(1 for c in cells.values() if c.get("status") == "confirmed")
    tested_negative = sum(1 for c in cells.values() if c.get("status") == "tested-negative")
    blocked = sum(1 for c in cells.values() if c.get("status") == "blocked")
    failed = sum(1 for c in cells.values() if c.get("status") == "failed")
    failed_without_blocker = sum(
        1 for c in cells.values()
        if c.get("status") == "failed" and not c.get("blocker")
    )
    pending = sum(1 for c in cells.values() if c.get("status") == "pending")
    running = sum(1 for c in cells.values() if c.get("status") == "running")
    not_applicable = sum(1 for c in cells.values() if c.get("status") == "not-applicable")
    out_of_scope = sum(1 for c in cells.values() if c.get("status") == "out-of-scope")

    valid_negative = tested_negative  # cells reaching tested-negative already enforce evidence+reachability

    inventory = _load_inventory(directory)
    reachable = sum(
        1 for item in inventory if item.get("reachability") in {"reachable", "proven"}
    )
    inventory_total = max(len(inventory), 1)

    matrix = _load_access_matrix(directory)
    access_cells = len(matrix.get("cells", {}))

    hashes = _load_artifact_hashes(directory)
    artifact_count = len(hashes.get("files", {}))

    objects_and_flows = [item for item in inventory if item.get("kind") in {"object", "flow"}]
    covered_object_flow_ids = set()
    for c in cells.values():
        if c.get("status") in {"confirmed", "tested-negative"}:
            if c.get("object_id"):
                covered_object_flow_ids.add(c.get("object_id"))
            if c.get("flow_id"):
                covered_object_flow_ids.add(c.get("flow_id"))
    object_flow_total = max(len(objects_and_flows), 1)
    object_flow_covered = sum(
        1 for item in objects_and_flows if item.get("id") in covered_object_flow_ids
    )

    findings = []
    if (directory / "findings").is_dir():
        findings = [redlensctl.read_json(p) for p in (directory / "findings").glob("*.json")]
    high_critical = 0
    high_critical_unconfirmed = 0
    high_critical_confirmed = 0
    confirmed_findings = 0
    for finding in findings:
        if finding.get("status") == "confirmed":
            confirmed_findings += 1
        if finding.get("severity") in {"high", "critical"}:
            high_critical += 1
            if (
                finding.get("status") != "confirmed"
                or not finding.get("reproduced")
                or not finding.get("negative_control")
            ):
                high_critical_unconfirmed += 1
            else:
                high_critical_confirmed += 1

    benchmark_valid, benchmark = _load_benchmark(directory)

    # Dimension scores with distinct, specific reasons.
    dimension_scores = {
        "discovery_and_reachability": _dimension(
            "discovery_and_reachability",
            (reachable / inventory_total) * RUBRIC["discovery_and_reachability"],
            f"{reachable}/{len(inventory)} inventory items with proven reachability",
        ),
        "input_coverage": _dimension(
            "input_coverage",
            ((confirmed + valid_negative) / total_cells) * RUBRIC["input_coverage"],
            f"{confirmed + valid_negative}/{len(cells)} cells closed with evidence",
        ),
        "detection_critical_high": _dimension(
            "detection_critical_high",
            (high_critical_confirmed / max(high_critical, 1)) * RUBRIC["detection_critical_high"]
            if high_critical else 0.0,
            f"{high_critical_confirmed} of {high_critical} high/critical findings confirmed and validated"
            if high_critical else "no high/critical findings observed",
        ),
        "detection_medium": _dimension(
            "detection_medium",
            RUBRIC["detection_medium"]
            if confirmed_findings and high_critical_unconfirmed == 0 else 0.0,
            f"{confirmed_findings} confirmed finding(s) support medium detection"
            if confirmed_findings and high_critical_unconfirmed == 0
            else "medium detection unsupported by confirmed findings or blocked by unconfirmed high/critical findings",
        ),
        "authorization_tenancy": _dimension(
            "authorization_tenancy",
            (access_cells / total_cells) * RUBRIC["authorization_tenancy"],
            f"{access_cells} access-matrix cells recorded across {len(cells)} coverage cells",
        ),
        "business_logic": _dimension(
            "business_logic",
            (object_flow_covered / object_flow_total) * RUBRIC["business_logic"]
            if objects_and_flows else 0.0,
            f"{object_flow_covered}/{len(objects_and_flows)} object/flow inventory items covered"
            if objects_and_flows else "no objects or flows inventoried",
        ),
        "precision_validation": _dimension(
            "precision_validation",
            RUBRIC["precision_validation"] if high_critical_unconfirmed == 0 else 0.0,
            "all high/critical findings have reproduction and negative control"
            if high_critical_unconfirmed == 0
            else f"{high_critical_unconfirmed} high/critical finding(s) lack reproduction or negative control",
        ),
        "autonomy_resilience": _dimension(
            "autonomy_resilience",
            (1 - (pending + running) / total_cells) * RUBRIC["autonomy_resilience"],
            f"{pending + running}/{len(cells)} cells still pending or running",
        ),
        "evidence_report": _dimension(
            "evidence_report",
            RUBRIC["evidence_report"] if artifact_count else 0.0,
            f"{artifact_count} artifact hash(es) recorded"
            if artifact_count else "no artifact hashes recorded",
        ),
        "operational_safety": _dimension(
            "operational_safety",
            RUBRIC["operational_safety"] if failed_without_blocker == 0 else 0.0,
            "no failed cells without blocker explanation"
            if failed_without_blocker == 0
            else f"{failed_without_blocker} failed cell(s) lack a blocker explanation",
        ),
    }

    raw_total = sum(d["score"] for d in dimension_scores.values())
    cap = 100 if benchmark_valid else BENCHMARK_INVALID_CAP
    total_score = round(min(raw_total, cap), 2)

    open_cells = pending + running
    if (
        benchmark_valid
        and total_score >= 90
        and high_critical_unconfirmed == 0
        and open_cells == 0
        and failed_without_blocker == 0
    ):
        confidence = "high"
        claim_allowed = True
    elif total_score >= 70:
        confidence = "medium"
        claim_allowed = False
    elif total_score >= 40:
        confidence = "low"
        claim_allowed = False
    else:
        confidence = "experimental"
        claim_allowed = False

    gaps: list[str] = []
    if open_cells:
        gaps.append(f"{open_cells} cells open (pending/running)")
    if failed:
        gaps.append(f"{failed} cells failed")
    if failed_without_blocker:
        gaps.append(f"{failed_without_blocker} failed cells without blocker explanation")
    if blocked:
        gaps.append(f"{blocked} cells blocked")
    if high_critical_unconfirmed:
        gaps.append(f"{high_critical_unconfirmed} high/critical findings unconfirmed")
    if not benchmark_valid:
        gaps.append("benchmark missing or invalid")

    score = {
        "generated_at": _iso(),
        "run_id": run_id,
        "rubric": RUBRIC,
        "dimensions": dimension_scores,
        "total": total_score,
        "max": 100,
        "confidence": confidence,
        "claim_allowed": claim_allowed,
        "gaps": gaps,
        "benchmark_valid": benchmark_valid,
        "benchmark": benchmark,
        "cells_total": len(cells),
        "cells_confirmed": confirmed,
        "cells_tested_negative": tested_negative,
        "cells_blocked": blocked,
        "cells_failed": failed,
        "cells_pending": pending,
        "cells_running": running,
        "cells_not_applicable": not_applicable,
        "cells_out_of_scope": out_of_scope,
        "findings_total": len(findings),
        "findings_confirmed": confirmed_findings,
        "findings_high_critical": high_critical,
        "findings_high_critical_unconfirmed": high_critical_unconfirmed,
        "findings_high_critical_confirmed": high_critical_confirmed,
        "failed_without_blocker": failed_without_blocker,
    }

    path = directory / "state" / "score.json"
    redlensctl.write_json(path, score)
    return score


def assert_cell_quality(directory: Path) -> None:
    """Strict cell-level gate: all cells must reach a terminal status."""
    import coverage_cells
    coverage_cells.assert_no_open_cells(directory)
