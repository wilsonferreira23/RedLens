import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "engine" / "redlensctl.py"


class RedLensCtlTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        self._old_redlens_home = os.environ.get("REDLENS_HOME")
        os.environ["REDLENS_HOME"] = self.temp.name
        self.ctl = self._import_ctl()

    def tearDown(self):
        if self._old_redlens_home is None:
            os.environ.pop("REDLENS_HOME", None)
        else:
            os.environ["REDLENS_HOME"] = self._old_redlens_home
        self.temp.cleanup()

    def _import_ctl(self):
        spec = importlib.util.spec_from_file_location("redlensctl", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules["redlensctl"] = module
        spec.loader.exec_module(module)
        return module

    def run_ctl(self, *args, ok=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )
        if ok and result.returncode != 0:
            self.fail(result.stderr)
        if not ok:
            self.assertNotEqual(result.returncode, 0)
            return json.loads(result.stderr)
        return json.loads(result.stdout)

    def init_run(self, *extra):
        return self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized",
        )

    def test_requires_explicit_authorization(self):
        error = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            ok=False,
        )
        self.assertIn("Autorização explícita", error["error"])
        self.assertFalse((Path(self.temp.name) / "runs").exists())



    def test_high_finding_requires_reproduction_and_negative_control(self):
        run = self.init_run()
        run_id = run["run_id"]
        evidence = Path(run["directory"]) / "evidence" / "raw" / "proof.txt"
        evidence.write_text("synthetic proof", encoding="utf-8")
        error = self.run_ctl(
            "add-finding",
            "--run", run_id,
            "--id", "F-001",
            "--title", "Authorization bypass",
            "--severity", "high",
            "--status", "confirmed",
            "--asset", "https://app.example.test/account",
            "--evidence", str(evidence),
            ok=False,
        )
        self.assertIn("reprodução e controle negativo", error["error"])


    def test_completion_requires_closed_coverage(self):
        run_id = self.init_run()["run_id"]
        self.run_ctl("transition", "--run", run_id, "--status", "running")
        error = self.run_ctl(
            "transition", "--run", run_id, "--status", "completed", ok=False
        )
        self.assertIn("Cobertura pendente", error["error"])

    def test_report_is_generated_only_after_quality_gate(self):
        run = self.init_run()
        run_id = run["run_id"]
        status = self.run_ctl("status", "--run", run_id)
        for category in status["coverage"]["categories"]:
            self.run_ctl(
                "record-coverage",
                "--run", run_id,
                "--category", category,
                "--status", "not-applicable",
                "--summary", "Laboratory unit test",
            )
        report = self.run_ctl("report", "--run", run_id)
        self.assertTrue(Path(report["executive"]).is_file())
        self.assertTrue(Path(report["technical"]).is_file())

    def test_inventory_is_deduplicated_and_tracks_sources(self):
        run_id = self.init_run()["run_id"]
        first = self.run_ctl(
            "add-inventory", "--run", run_id, "--kind", "endpoint",
            "--value", "https://app.example.test/api/me", "--method", "GET",
            "--source", "browser",
        )
        second = self.run_ctl(
            "add-inventory", "--run", run_id, "--kind", "endpoint",
            "--value", "https://app.example.test/api/me", "--method", "GET",
            "--source", "crawler",
        )
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(set(second["item"]["sources"]), {"browser", "crawler"})

    def test_task_must_close_before_quality_gate(self):
        run = self.init_run()
        run_id = run["run_id"]
        task = self.run_ctl(
            "add-task", "--run", run_id, "--kind", "inventory",
            "--title", "Map authorized endpoints",
        )["task"]
        status = self.run_ctl("status", "--run", run_id)
        for category in status["coverage"]["categories"]:
            self.run_ctl(
                "record-coverage", "--run", run_id, "--category", category,
                "--status", "not-applicable", "--summary", "Laboratory unit test",
            )
        error = self.run_ctl("quality-gate", "--run", run_id, ok=False)
        self.assertIn("Tarefas ainda abertas", error["error"])
        self.run_ctl(
            "update-task", "--run", run_id, "--task", task["id"],
            "--status", "running", "--summary", "Inventory started",
        )
        self.run_ctl(
            "update-task", "--run", run_id, "--task", task["id"],
            "--status", "completed", "--summary", "Inventory stored",
        )
        self.assertTrue(self.run_ctl("quality-gate", "--run", run_id)["ok"])

    def test_access_matrix_allowed_requires_evidence(self):
        run = self.init_run()
        run_id = run["run_id"]
        error = self.run_ctl(
            "record-access", "--run", run_id,
            "--endpoint", "https://app.example.test/api/me", "--method", "GET",
            "--role", "viewer", "--status", "allowed", ok=False,
        )
        self.assertIn("precisa de evidência", error["error"])
        evidence = Path(run["directory"]) / "evidence" / "sanitized" / "access.json"
        evidence.write_text("{}", encoding="utf-8")
        result = self.run_ctl(
            "record-access", "--run", run_id,
            "--endpoint", "https://app.example.test/api/me", "--method", "GET",
            "--role", "viewer", "--status", "allowed", "--evidence", str(evidence),
        )
        self.assertEqual(result["cell"]["status"], "allowed")

    def test_quality_gate_requires_resource_cleanup(self):
        run = self.init_run()
        run_id = run["run_id"]
        status = self.run_ctl("status", "--run", run_id)
        for category in status["coverage"]["categories"]:
            self.run_ctl(
                "record-coverage", "--run", run_id, "--category", category,
                "--status", "not-applicable", "--summary", "Laboratory unit test",
            )
        resource = self.run_ctl(
            "record-resource", "--run", run_id, "--kind", "test-data",
            "--label", "synthetic-account", "--cleanup", "Delete after test",
        )["resource"]
        error = self.run_ctl("quality-gate", "--run", run_id, ok=False)
        self.assertIn("Recursos sem cleanup", error["error"])
        self.run_ctl(
            "cleanup-resource", "--run", run_id, "--resource", resource["id"],
            "--status", "cleaned", "--summary", "Synthetic account removed",
        )
        self.assertTrue(self.run_ctl("quality-gate", "--run", run_id)["ok"])


    def test_scoped_url_accepts_target_and_subdomain(self):
        run = self.init_run()
        directory = Path(run["directory"])
        url = self.ctl.scoped_url(directory, "https://app.example.test/api/me")
        self.assertEqual(url, "https://app.example.test/api/me")
        subdomain = self.ctl.scoped_url(directory, "https://sub.app.example.test/x")
        self.assertEqual(subdomain, "https://sub.app.example.test/x")

    def test_scoped_url_rejects_wrong_domain(self):
        run = self.init_run()
        directory = Path(run["directory"])
        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.scoped_url(directory, "https://evil.test/")
        self.assertIn("Domínio", str(ctx.exception))

    def test_scoped_url_rejects_wrong_port(self):
        run = self.init_run()
        directory = Path(run["directory"])
        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.scoped_url(directory, "http://app.example.test:8080/")
        self.assertIn("Porta", str(ctx.exception))

    def test_browser_url_in_scope_returns_boolean(self):
        run = self.init_run()
        directory = Path(run["directory"])
        self.assertTrue(self.ctl.browser_url_in_scope(directory, "https://app.example.test/"))
        self.assertFalse(self.ctl.browser_url_in_scope(directory, "https://evil.test/"))

    def test_init_stores_new_fields(self):
        run = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized",
            "--environment", "lab",
            "--mode", "quick",
            "--max-rps", "5",
            "--rate-window", "30",
            "--categories", "surface,authentication",
            "--impact-level", "high",
            "--accounts", "admin,user",
            "--credentials-available", "yes",
            "--destructive-authorized",
            "--prohibited-techniques", "dos,phishing",
            "--report-format", "technical",
        )
        directory = Path(run["directory"])
        auth = self.ctl.read_json(directory / "authorization" / "authorization.json")
        scope = self.ctl.read_json(directory / "scope" / "scope.json")
        self.assertEqual(auth["environment"], "lab")
        self.assertEqual(auth["mode"], "quick")
        self.assertEqual(auth["max_rps"], 5.0)
        self.assertEqual(auth["rate_window"], 30)
        self.assertEqual(auth["categories"], ["surface", "authentication"])
        self.assertEqual(auth["impact_level"], "high")
        self.assertEqual(auth["accounts"], ["admin", "user"])
        self.assertEqual(auth["credentials"], "available")
        self.assertTrue(auth["destructive_authorized"])
        self.assertEqual(auth["prohibited_techniques"], ["dos", "phishing"])
        self.assertEqual(auth["report_format"], "technical")
        self.assertEqual(scope["allowed_domains"], ["app.example.test"])
        self.assertIn(443, scope["allowed_ports"])
        self.assertEqual(scope["mode"], "quick")
        self.assertEqual(scope["credentials"], "available")
        self.assertEqual(scope["prohibited_techniques"], ["dos", "phishing"])
        self.assertEqual(scope["report_format"], "technical")

    def test_valid_risk_approval_requires_destructive_flag(self):
        run = self.init_run()
        directory = Path(run["directory"])
        target = "https://app.example.test/api/me"
        token = self.ctl.valid_risk_approval(directory, "inventory", target)
        self.assertTrue(token.startswith("risk-approval-"))
        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.valid_risk_approval(directory, "data-mutation", target)
        self.assertIn("destrutiva", str(ctx.exception).lower())
        auth_path = directory / "authorization" / "authorization.json"
        auth = self.ctl.read_json(auth_path)
        auth["destructive_authorized"] = True
        self.ctl.write_json(auth_path, auth)
        token2 = self.ctl.valid_risk_approval(directory, "data-mutation", target)
        self.assertTrue(token2.startswith("risk-approval-"))

    def test_check_data_extraction_approval_behavior(self):
        run = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized",
            "--impact-level", "medium",
            "--accounts", "viewer",
            "--mode", "standard",
        )
        directory = Path(run["directory"])
        run_id = run["run_id"]
        target = "https://app.example.test/api/me"
        token = self.ctl.check_data_extraction_approval(
            directory, run_id, target, "viewer", None, None
        )
        self.assertTrue(token.startswith("data-extraction-"))

        with self.assertRaises(self.ctl.RedLensError):
            self.ctl.check_data_extraction_approval(
                directory, run_id, target, "attacker", None, None
            )

        cross_token = self.ctl.check_data_extraction_approval(
            directory, run_id, target, "viewer", "other-tenant", None
        )
        self.assertTrue(cross_token.startswith("data-extraction-"))
        events = list((directory / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines())
        self.assertTrue(any("data-extraction.cross-tenant" in line for line in events))

    def test_check_data_extraction_rejects_low_impact(self):
        run = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized",
            "--impact-level", "low",
            "--accounts", "viewer",
        )
        directory = Path(run["directory"])
        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.check_data_extraction_approval(
                directory, run["run_id"], "https://app.example.test/api/me",
                "viewer", None, None
            )
        self.assertIn("impacto", str(ctx.exception).lower())

    def test_check_data_extraction_rejects_quick_mode_for_cross_tenant(self):
        run = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized",
            "--impact-level", "medium",
            "--accounts", "viewer",
            "--mode", "quick",
        )
        directory = Path(run["directory"])
        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.check_data_extraction_approval(
                directory, run["run_id"], "https://app.example.test/api/me",
                "viewer", "other-tenant", None
            )
        self.assertIn("quick", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
