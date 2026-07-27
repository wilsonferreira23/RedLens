"""Coverage cell model and planner: deterministic, ID-structured coverage.

A coverage cell is the smallest unit of test the RedLens must perform:

  endpoint × method × parameter × role × tenant × object × flow × capability

Every applicable cell must end in one of:
  confirmed, tested-negative, blocked, failed, not-applicable, out-of-scope

`failed`, `blocked`, and `inconclusive` never count as tested-negative.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


CELL_STATUSES = {
    "pending", "running", "confirmed", "tested-negative",
    "blocked", "not-applicable", "out-of-scope", "failed",
}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CoverageCell:
    id: str
    asset_id: str | None
    endpoint_id: str | None
    method: str
    parameter_id: str | None
    role: str
    tenant: str | None
    object_id: str | None
    flow_id: str | None
    capability: str
    applicable: bool = True
    status: str = "pending"
    reachability_proven: bool = False
    executions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    negative_controls: list[str] = field(default_factory=list)
    blocker: str | None = None
    updated_at: str = field(default_factory=_iso)

    def to_dict(self) -> dict:
        return asdict(self)


def cell_id(
    endpoint_id: str | None,
    method: str | None,
    parameter_id: str | None,
    role: str,
    tenant: str | None,
    object_id: str | None,
    capability: str,
    flow_id: str | None = None,
) -> str:
    parts = [
        endpoint_id or "*",
        (method or "GET").upper(),
        parameter_id or "*",
        role,
        tenant or "*",
        object_id or "*",
        capability,
        flow_id or "*",
    ]
    raw = "|".join(parts)
    return redlensctl.safe_id("cell", raw)


def load_cells(directory: Path) -> dict[str, dict]:
    path = directory / "state" / "coverage-cells.json"
    if not path.is_file():
        return {}
    data = redlensctl.read_json(path)
    return data.get("cells", {})


def save_cells(directory: Path, cells: dict[str, dict]) -> None:
    path = directory / "state" / "coverage-cells.json"
    redlensctl.write_json(path, {"version": 1, "cells": cells})


def upsert_cell(directory: Path, cell: CoverageCell) -> CoverageCell:
    cells = load_cells(directory)
    cell.updated_at = _iso()
    cells[cell.id] = cell.to_dict()
    save_cells(directory, cells)
    return cell


def update_cell_status(directory: Path, cell_id_value: str, status: str, **fields: Any) -> dict | None:
    if status not in CELL_STATUSES:
        raise redlensctl.RedLensError(f"Status de célula inválido: {status}")
    cells = load_cells(directory)
    if cell_id_value not in cells:
        return None
    cell = cells[cell_id_value]
    for key, value in fields.items():
        cell[key] = value
    cell["status"] = status
    if status == "tested-negative":
        if not cell.get("evidence"):
            raise redlensctl.RedLensError(
                f"Célula {cell_id_value} tested-negative requer evidência."
            )
        if not cell.get("reachability_proven"):
            raise redlensctl.RedLensError(
                f"Célula {cell_id_value} tested-negative requer reachability_proven."
            )
    cell["updated_at"] = _iso()
    cells[cell_id_value] = cell
    save_cells(directory, cells)
    return cell


def list_endpoints(directory: Path) -> list[dict]:
    items = []
    for path in (directory / "inventory").glob("*.json"):
        item = redlensctl.read_json(path)
        if item.get("kind") in {"endpoint", "api"}:
            items.append(item)
    return items


def list_parameters(directory: Path, endpoint_id: str) -> list[dict]:
    items = []
    for path in (directory / "inventory").glob("*.json"):
        item = redlensctl.read_json(path)
        if item.get("kind") == "parameter" and item.get("parent") == endpoint_id:
            items.append(item)
    return items


def list_identities(directory: Path) -> list[dict]:
    return [redlensctl.read_json(p) for p in (directory / "identities").glob("*.json")]


def list_objects(directory: Path) -> list[dict]:
    items = []
    for path in (directory / "inventory").glob("*.json"):
        item = redlensctl.read_json(path)
        if item.get("kind") == "object":
            items.append(item)
    return items


def list_flows(directory: Path) -> list[dict]:
    items = []
    for path in (directory / "inventory").glob("*.json"):
        item = redlensctl.read_json(path)
        if item.get("kind") == "flow":
            items.append(item)
    return items


def applicable_capabilities(method: str | None) -> list[str]:
    caps = ["headers", "csrf", "authz"]
    method_upper = (method or "GET").upper()
    if method_upper in {"GET", "POST", "PUT", "PATCH"}:
        caps.extend(["sqli", "xss", "cmdi", "ssti", "traversal", "ssrf", "mutation"])
    if method_upper in {"POST", "PUT", "PATCH"}:
        caps.append("mass-assignment")
    return caps


def plan_next(run_id: str, limit: int = 20) -> dict:
    directory = redlensctl.run_dir(run_id)
    cells = load_cells(directory)
    identities = list_identities(directory)
    if not identities:
        identities = [{"role": "default", "tenant": None, "id": "identity-default"}]

    objects = list_objects(directory)
    flows = list_flows(directory)
    if not objects:
        objects = [None]
    if not flows:
        flows = [None]

    pending = []
    stop = False
    for endpoint in list_endpoints(directory):
        endpoint_id = endpoint["id"]
        method = endpoint.get("method", "GET")
        params = list_parameters(directory, endpoint_id)
        if not params:
            params = [None]
        for capability in applicable_capabilities(method):
            for identity in identities:
                role = identity.get("role", "default")
                tenant = identity.get("tenant")
                for parameter in params:
                    parameter_id = parameter["id"] if parameter else None
                    for obj in objects:
                        object_id = obj["id"] if obj else None
                        for flow in flows:
                            flow_id = flow["id"] if flow else None
                            cid = cell_id(
                                endpoint_id,
                                method,
                                parameter_id,
                                role,
                                tenant,
                                object_id,
                                capability,
                                flow_id=flow_id,
                            )
                            if cid not in cells or cells[cid].get("status") == "pending":
                                cell = CoverageCell(
                                    id=cid,
                                    asset_id=None,
                                    endpoint_id=endpoint_id,
                                    method=method,
                                    parameter_id=parameter_id,
                                    role=role,
                                    tenant=tenant,
                                    object_id=object_id,
                                    flow_id=flow_id,
                                    capability=capability,
                                    applicable=True,
                                    status="pending",
                                )
                                cells[cid] = cell.to_dict()
                                pending.append({
                                    "id": cid,
                                    "endpoint": endpoint_id,
                                    "method": method,
                                    "parameter": parameter_id,
                                    "role": role,
                                    "capability": capability,
                                })
                            if len(pending) >= limit:
                                stop = True
                                break
                        if stop:
                            break
                    if stop:
                        break
                if stop:
                    break
            if stop:
                break
        if stop:
            break

    save_cells(directory, cells)
    return {
        "ok": True,
        "new_cells": len(pending),
        "total_cells": len(cells),
        "pending": pending[:limit],
    }


def coverage_stats(directory: Path) -> dict:
    cells = load_cells(directory)
    by_status: dict[str, int] = {s: 0 for s in CELL_STATUSES}
    by_capability: dict[str, int] = {}
    for cell in cells.values():
        by_status[cell.get("status", "pending")] = by_status.get(cell.get("status", "pending"), 0) + 1
        cap = cell.get("capability", "unknown")
        by_capability[cap] = by_capability.get(cap, 0) + 1
    total = max(len(cells), 1)
    # Only confirmed and tested-negative count as negative coverage.
    negative_ratio = (by_status.get("tested-negative", 0) + by_status.get("confirmed", 0)) / total
    return {
        "total_cells": len(cells),
        "by_status": by_status,
        "by_capability": by_capability,
        "negative_coverage_ratio": round(negative_ratio, 3),
    }


def assert_no_open_cells(directory: Path) -> None:
    """Raise RedLensError if coverage is not terminal or has unexplained failures."""
    cells = load_cells(directory)
    open_cells: list[str] = []
    unexplained_failures: list[str] = []
    for cid, cell in cells.items():
        status = cell.get("status")
        if status in {"pending", "running"}:
            open_cells.append(f"{cid}:{status}")
        if status == "failed" and not cell.get("blocker"):
            unexplained_failures.append(cid)
    messages: list[str] = []
    if open_cells:
        messages.append(
            "Células de cobertura ainda abertas: " + ", ".join(open_cells[:20])
        )
    if unexplained_failures:
        messages.append(
            "Falhas sem explicação de blocker: " + ", ".join(unexplained_failures[:20])
        )
    if messages:
        raise redlensctl.RedLensError(" | ".join(messages))


def main_cli() -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="planner-cells")
    sub = parser.add_subparsers(dest="cmd", required=True)

    plan_p = sub.add_parser("plan")
    plan_p.add_argument("--run", required=True)
    plan_p.add_argument("--limit", type=int, default=20)

    stats_p = sub.add_parser("stats")
    stats_p.add_argument("--run", required=True)

    args = parser.parse_args()
    try:
        if args.cmd == "plan":
            result = plan_next(args.run, args.limit)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.cmd == "stats":
            directory = redlensctl.run_dir(args.run)
            stats = coverage_stats(directory)
            print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0
    except redlensctl.RedLensError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main_cli())
