#!/usr/bin/env python3
"""Benchmark runner: executa RedLens contra alvos conhecidos.

Uso:
  redlens-benchmark reset --target juice-shop
  redlens-benchmark health --target juice-shop
  redlens-benchmark run --target juice-shop --mode quick
  redlens-benchmark score --target juice-shop
  redlens-benchmark destroy

Targets suportados:
  juice-shop: http://localhost:13000 (OWASP Juice Shop)
  webgoat: http://localhost:8081 (WebGoat 8)
  dvwa: http://localhost:8082 (Damn Vulnerable Web App)
  vampi: http://localhost:15000 (VAmPI)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


TARGETS = {
    "juice-shop": {
        "url": "http://localhost:13000",
        "ground_truth_file": "ground_truth_juice_shop.json",
    },
    "webgoat": {
        "url": "http://localhost:8081/WebGoat",
        "ground_truth_file": "ground_truth_webgoat.json",
    },
    "dvwa": {
        "url": "http://localhost:8082",
        "ground_truth_file": "ground_truth_dvwa.json",
    },
    "vampi": {
        "url": "http://localhost:15000",
        "ground_truth_file": "ground_truth_vampi.json",
    },
}

GROUND_TRUTH_DIR = ROOT / "benchmarks" / "ground_truth"
GROUND_TRUTH_DIR.mkdir(parents=True, exist_ok=True)


def health_check(target: str) -> dict:
    info = TARGETS.get(target)
    if not info:
        return {"ok": False, "error": f"target desconhecido: {target}"}
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", info["url"]],
            capture_output=True, text=True, timeout=10,
        )
        status = int(result.stdout.strip() or "0")
        return {
            "ok": True,
            "target": target,
            "url": info["url"],
            "status": status,
            "reachable": 200 <= status < 400,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def run_redlens(target: str, mode: str = "standard") -> dict:
    info = TARGETS.get(target)
    if not info:
        return {"ok": False, "error": f"target desconhecido: {target}"}

    env = {**__import__("os").environ, "REDLENS_HOME": str(ROOT)}
    run_id = f"benchmark-{target}-{int(time.time())}"

    init_result = subprocess.run(
        [sys.executable, str(ROOT / "engine" / "redlensctl.py"), "init",
         "--target", info["url"], "--authorized"],
        capture_output=True, text=True, timeout=30, env=env,
    )
    if init_result.returncode != 0:
        return {"ok": False, "error": f"init falhou: {init_result.stderr}", "stage": "init"}

    try:
        init_data = json.loads(init_result.stdout)
        run_id = init_data["run_id"]
        directory = init_data["directory"]
    except (json.JSONDecodeError, KeyError) as exc:
        return {"ok": False, "error": f"init invalido: {exc}", "stage": "init"}

    return {
        "ok": True,
        "target": target,
        "url": info["url"],
        "mode": mode,
        "run_id": run_id,
        "directory": directory,
        "next_steps": [
            "Use run_id em add-inventory, add-identity, plan, score, etc.",
        ],
    }


def score_run(target: str, run_id: str) -> dict:
    env = {**__import__("os").environ, "REDLENS_HOME": str(ROOT)}
    score_result = subprocess.run(
        [sys.executable, str(ROOT / "engine" / "redlensctl.py"), "score", "--run", run_id],
        capture_output=True, text=True, timeout=60, env=env,
    )
    if score_result.returncode != 0:
        return {"ok": False, "error": score_result.stderr}
    return json.loads(score_result.stdout)


def load_ground_truth(target: str) -> dict:
    path = GROUND_TRUTH_DIR / TARGETS[target]["ground_truth_file"]
    if not path.is_file():
        return {"target": target, "vulnerabilities": [], "note": "ground truth nao definido"}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(prog="redlens-benchmark")
    sub = parser.add_subparsers(dest="action", required=True)

    health = sub.add_parser("health")
    health.add_argument("--target", required=True, choices=list(TARGETS.keys()))

    run = sub.add_parser("run")
    run.add_argument("--target", required=True, choices=list(TARGETS.keys()))
    run.add_argument("--mode", default="standard")

    score = sub.add_parser("score")
    score.add_argument("--target", required=True, choices=list(TARGETS.keys()))
    score.add_argument("--run", required=True)

    gt = sub.add_parser("ground-truth")
    gt.add_argument("--target", required=True, choices=list(TARGETS.keys()))

    args = parser.parse_args()
    try:
        if args.action == "health":
            print(json.dumps(health_check(args.target), ensure_ascii=False, indent=2))
        elif args.action == "run":
            print(json.dumps(run_redlens(args.target, args.mode), ensure_ascii=False, indent=2))
        elif args.action == "score":
            print(json.dumps(score_run(args.target, args.run), ensure_ascii=False, indent=2))
        elif args.action == "ground-truth":
            print(json.dumps(load_ground_truth(args.target), ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())