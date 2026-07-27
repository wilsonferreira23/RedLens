import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "engine" / "redlensctl.py"
sys.path.insert(0, str(ROOT / "engine"))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class BaseRunTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ["REDLENS_HOME"] = self.temp.name
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        result = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized")
        self.run_id = result["run_id"]
        self.directory = Path(result["directory"])

    def tearDown(self):
        self.temp.cleanup()

    def run_ctl(self, *args):
        result = subprocess.run(
            [sys.executable, str(CTL), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )
        if result.returncode:
            self.fail(result.stderr)
        return json.loads(result.stdout)


class CapabilityRegistryTest(BaseRunTest):
    def test_registry_exposes_known_capabilities(self):
        reg = load_module("capability_registry", ROOT / "adapters" / "capability_registry.py")
        names = reg.available()
        for required in [
            "fingerprint", "content-discovery", "parameter-discovery", "js-analysis",
            "api-schema", "mutation", "sqli", "xss", "cmdi",
            "csrf", "mass-assignment", "authn", "session",
        ]:
            self.assertIn(required, names, f"missing capability: {required}")

    def test_unknown_capability_raises(self):
        reg = load_module("capability_registry", ROOT / "adapters" / "capability_registry.py")
        with self.assertRaises(Exception):
            reg.get("nope")


class CoverageCellsTest(BaseRunTest):
    def test_plan_creates_cells_per_endpoint_role_capability(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        result = cells_mod.plan_next(self.run_id, limit=50)
        self.assertGreater(result["total_cells"], 0)
        self.assertGreaterEqual(result["new_cells"], 7)

    def test_plan_creates_cells_for_all_parameters(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        endpoint = self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/users",
            "--source", "browser",
        )
        for value in ("id", "name"):
            self.run_ctl(
                "add-inventory", "--run", self.run_id,
                "--kind", "parameter",
                "--value", value,
                "--source", "manual",
                "--parent", endpoint["item_id"],
            )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        result = cells_mod.plan_next(self.run_id, limit=100)
        # GET endpoint yields 10 capabilities; 1 identity x 2 parameters = 20 cells
        self.assertEqual(result["new_cells"], 20)
        self.assertEqual(result["total_cells"], 20)
        cells = cells_mod.load_cells(self.directory)
        param_items = [
            json.loads(p.read_text(encoding="utf-8"))
            for p in (self.directory / "inventory").glob("*.json")
            if json.loads(p.read_text(encoding="utf-8")).get("kind") == "parameter"
        ]
        expected_param_ids = {p["id"] for p in param_items}
        cell_param_ids = {c["parameter_id"] for c in cells.values()}
        self.assertEqual(cell_param_ids, expected_param_ids)
        self.assertEqual({p["value"] for p in param_items}, {"id", "name"})

    def test_tested_negative_requires_evidence_and_reachability(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        result = cells_mod.plan_next(self.run_id, limit=10)
        cid = result["pending"][0]["id"]

        # Missing evidence should fail.
        with self.assertRaises(Exception):
            cells_mod.update_cell_status(
                self.directory, cid, "tested-negative",
                reachability_proven=True,
            )

        # Missing reachability should fail even with evidence.
        with self.assertRaises(Exception):
            cells_mod.update_cell_status(
                self.directory, cid, "tested-negative",
                evidence=["evidence/sanitized/x.json"],
            )

        # Both evidence and reachability allow the transition.
        updated = cells_mod.update_cell_status(
            self.directory, cid, "tested-negative",
            evidence=["evidence/sanitized/x.json"],
            reachability_proven=True,
        )
        self.assertEqual(updated["status"], "tested-negative")

    def test_blocked_failed_not_counted_as_negative_coverage(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        cells_mod.plan_next(self.run_id, limit=10)
        cells = cells_mod.load_cells(self.directory)
        cids = list(cells.keys())
        cells_mod.update_cell_status(self.directory, cids[0], "blocked", blocker="waf")
        cells_mod.update_cell_status(self.directory, cids[1], "failed", blocker="tool error")
        cells_mod.update_cell_status(
            self.directory, cids[2], "tested-negative",
            evidence=["evidence/sanitized/x.json"],
            reachability_proven=True,
        )
        stats = cells_mod.coverage_stats(self.directory)
        self.assertEqual(stats["by_status"]["blocked"], 1)
        self.assertEqual(stats["by_status"]["failed"], 1)
        self.assertEqual(stats["by_status"]["tested-negative"], 1)
        self.assertEqual(
            stats["negative_coverage_ratio"],
            round(1 / len(cells), 3),
        )

    def test_cell_id_is_deterministic(self):
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        cid1 = cells_mod.cell_id("endpoint-a", "GET", None, "admin", "tenant-a", None, "authz")
        cid2 = cells_mod.cell_id("endpoint-a", "GET", None, "admin", "tenant-a", None, "authz")
        self.assertEqual(cid1, cid2)

    def test_invalid_status_rejected(self):
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        with self.assertRaises(Exception):
            cells_mod.update_cell_status(self.directory, "cell-x", "nope")


class ScoreTest(BaseRunTest):
    def test_score_run_generates_score_without_claim(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        score_mod = load_module("score", ROOT / "engine" / "score.py")
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        cells_mod.plan_next(self.run_id, limit=50)

        result = score_mod.score_run(self.run_id)
        self.assertIn("total", result)
        self.assertIn("claim_allowed", result)
        self.assertIn("confidence", result)
        self.assertIn("benchmark_valid", result)
        self.assertFalse(result["claim_allowed"], "Empty cells cannot yield claim_allowed=true.")
        self.assertFalse(result["benchmark_valid"])
        self.assertIn("benchmark missing or invalid", result["gaps"])

    def test_score_dimensions_have_distinct_reasons(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        score_mod = load_module("score", ROOT / "engine" / "score.py")
        result = score_mod.score_run(self.run_id)
        reasons = [d["reason"] for d in result["dimensions"].values()]
        self.assertEqual(len(reasons), len(set(reasons)), "dimension reasons must be distinct")
        for dim in result["dimensions"].values():
            self.assertIn("score", dim)
            self.assertIn("max", dim)
            self.assertIn("reason", dim)

    def test_score_with_high_critical_unconfirmed_is_zero(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        score_mod = load_module("score", ROOT / "engine" / "score.py")
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        cells_mod.plan_next(self.run_id, limit=50)
        cells = cells_mod.load_cells(self.directory)
        for cid, cell in cells.items():
            cell["status"] = "tested-negative"
            cell["evidence"] = ["evidence/sanitized/x.json"]
            cell["reachability_proven"] = True
            cells[cid] = cell
        cells_mod.save_cells(self.directory, cells)

        findings_dir = self.directory / "findings"
        findings_dir.mkdir(exist_ok=True)
        bad_finding = {
            "id": "finding-bad",
            "title": "test",
            "severity": "critical",
            "status": "confirmed",
            "asset": "https://app.example.test",
            "evidence": ["evidence/sanitized/x.json"],
            "reproduced": False,
            "negative_control": False,
            "created_at": "2026-07-27T00:00:00Z",
        }
        (findings_dir / "finding-bad.json").write_text(json.dumps(bad_finding), encoding="utf-8")

        result = score_mod.score_run(self.run_id)
        self.assertFalse(result["claim_allowed"])
        self.assertEqual(result["dimensions"]["precision_validation"]["score"], 0.0)


class CellLevelQualityGateTest(BaseRunTest):
    def test_cell_gate_rejects_open_cells(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        score_mod = load_module("score", ROOT / "engine" / "score.py")
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        cells_mod.plan_next(self.run_id, limit=10)
        with self.assertRaises(Exception) as ctx:
            score_mod.assert_cell_quality(self.directory)
        self.assertIn("cobertura", str(ctx.exception).lower())

    def test_completion_blocked_with_open_cells(self):
        os.environ["REDLENS_HOME"] = self.temp.name
        if "redlensctl" in sys.modules:
            importlib.reload(sys.modules["redlensctl"])
        cells_mod = load_module("coverage_cells", ROOT / "engine" / "coverage_cells.py")
        ctl_mod = load_module("redlensctl", CTL)
        endpoint = self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        cells_mod.plan_next(self.run_id, limit=10)

        # Provide coverage for every category so the gate fails specifically on cells.
        evidence = self.directory / "evidence" / "sanitized" / "x.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text("{}", encoding="utf-8")
        for category in ctl_mod.COVERAGE:
            self.run_ctl(
                "record-coverage", "--run", self.run_id,
                "--category", category,
                "--status", "tested-negative",
                "--summary", "covered",
                "--evidence", str(evidence.relative_to(self.directory)),
            )

        self.run_ctl("transition", "--run", self.run_id, "--status", "running")
        result = subprocess.run(
            [sys.executable, str(CTL), "transition", "--run", self.run_id, "--status", "completed"],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cobertura", result.stderr.lower())


class RedLensctlPlanCommandTest(BaseRunTest):
    def test_plan_command_emits_cells(self):
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin",
            "--label", "admin-test",
        )
        result = self.run_ctl("plan", "--run", self.run_id, "--limit", "10")
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["new_cells"], 1)

    def test_score_command_runs(self):
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        result = self.run_ctl("score", "--run", self.run_id)
        self.assertTrue(result["ok"])
        self.assertIn("total", result["score"])

    def test_capabilities_command_lists_caps(self):
        result = self.run_ctl("capabilities")
        self.assertTrue(result["ok"])
        names = [c["name"] for c in result["capabilities"]]
        self.assertIn("sqli", names)
        self.assertIn("authn", names)


class ReachabilityTest(BaseRunTest):
    def test_inventory_records_reachability(self):
        result = self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api/me",
            "--source", "browser",
        )
        inv_path = self.directory / "inventory" / f"{result['item_id']}.json"
        item = json.loads(inv_path.read_text(encoding="utf-8"))
        self.assertIn("reachability", item)
        self.assertIn("metadata", item)


if __name__ == "__main__":
    unittest.main()
