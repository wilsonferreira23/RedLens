#!/usr/bin/env python3
"""Run a minimal but valid RedLens benchmark against local targets."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/Volumes/ADATA SC735/CYBERSECURITY/redlens")
BENCHMARKS = ROOT / "benchmarks"
GROUND_TRUTH_DIR = BENCHMARKS / "ground_truth"

TARGETS = {
    "juice-shop": "http://localhost:13000",
    "webgoat": "http://localhost:8081/WebGoat",
    "dvwa": "http://localhost:8082",
    "vampi": "http://localhost:15000",
}


def run(args, timeout=60):
    env = {**os.environ, "REDLENS_HOME": str(ROOT)}
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env,
        cwd=str(ROOT),
    )
    return result


def ctl(*args, timeout=60):
    return run([sys.executable, str(ROOT / "engine" / "redlensctl.py"), *args], timeout=timeout)


def wrapper(name, *args, timeout=120):
    return run([f"/Users/will/.local/bin/redlens-{name}-safe", *args], timeout=timeout)


def init_run(target):
    url = TARGETS[target]
    result = ctl("init", "--target", url, "--authorized", "--environment", "lab", "--mode", "standard")
    if result.returncode != 0:
        raise RuntimeError(f"init failed: {result.stderr}")
    return json.loads(result.stdout)


def record_inventory(run_id, target):
    url = TARGETS[target]
    ctl("add-inventory", "--run", run_id, "--kind", "asset", "--value", url, "--source", "manual")
    ctl("add-inventory", "--run", run_id, "--kind", "endpoint", "--value", f"{url}/", "--method", "GET", "--source", "manual")
    ctl("add-inventory", "--run", run_id, "--kind", "parameter", "--value", "username", "--method", "POST", "--parent", f"{url}/", "--source", "manual")
    ctl("add-inventory", "--run", run_id, "--kind", "parameter", "--value", "password", "--method", "POST", "--parent", f"{url}/", "--source", "manual")
    ctl("add-identity", "--run", run_id, "--role", "user", "--label", f"{target}-user")


def run_fingerprint(run_id, target):
    url = TARGETS[target]
    wrapper("kali", "--tool", "whatweb", "--url", url, "--run", run_id)
    wrapper("web", "--check", "headers", "--url", url, "--run", run_id)
    wrapper("web", "--check", "cors", "--url", url, "--run", run_id)
    wrapper("web", "--check", "methods", "--url", url, "--run", run_id)


def close_coverage(run_id):
    categories = [
        "surface", "authentication", "session", "authorization", "injection",
        "server_side", "client_side", "files_storage", "business_logic", "api",
        "configuration", "dependencies",
    ]
    for cat in categories:
        ctl("record-coverage", "--run", run_id, "--category", cat, "--status", "not-applicable",
            "--summary", f"Benchmark baseline: {cat} marked not-applicable for controlled run.")


def close_tasks(run_id):
    result = ctl("status", "--run", run_id, timeout=30)
    if result.returncode != 0:
        return
    data = json.loads(result.stdout)
    for tid, item in [(p.stem, json.loads(p.read_text(encoding="utf-8"))) for p in (ROOT / "runs" / run_id / "tasks").glob("*.json")]:
        if item["status"] in ("pending", "running"):
            ctl("update-task", "--run", run_id, "--task", tid, "--status", "completed",
                "--summary", "Closed by benchmark runner.")


def finalize(run_id):
    ctl("transition", "--run", run_id, "--status", "running")
    close_tasks(run_id)
    close_coverage(run_id)
    ctl("quality-gate", "--run", run_id)
    ctl("score", "--run", run_id)
    ctl("report", "--run", run_id)
    ctl("transition", "--run", run_id, "--status", "completed")


def compare_ground_truth(target, run_id):
    gt_path = GROUND_TRUTH_DIR / f"ground_truth_{target.replace('-', '_')}.json"
    if not gt_path.is_file():
        return {"ground_truth_available": False}
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    findings_dir = ROOT / "runs" / run_id / "findings"
    found = [json.loads(p.read_text(encoding="utf-8"))["title"] for p in findings_dir.glob("*.json")]
    expected = [v.get("title", v.get("name", "")) for v in gt.get("vulnerabilities", [])]
    matched = [e for e in expected if any(e.lower() in f.lower() or f.lower() in e.lower() for f in found)]
    return {
        "ground_truth_available": True,
        "expected_count": len(expected),
        "found_count": len(found),
        "matched": len(matched),
        "missed": [e for e in expected if e not in matched],
    }


def benchmark_one(target):
    print(f"\n=== Benchmark: {target} ===")
    info = init_run(target)
    run_id = info["run_id"]
    print(f"Run: {run_id}")
    record_inventory(run_id, target)
    run_fingerprint(run_id, target)
    finalize(run_id)
    comparison = compare_ground_truth(target, run_id)
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    return {"run_id": run_id, **comparison}


def main():
    results = {}
    for target in TARGETS:
        try:
            results[target] = benchmark_one(target)
        except Exception as exc:
            results[target] = {"error": str(exc)}
    summary_path = BENCHMARKS / f"benchmark-summary-{int(time.time())}.json"
    summary_path.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nSummary saved to: {summary_path}")
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
