#!/usr/bin/env python3
"""Regression tests for section 8 of PLANO_REDLENS_AJUSTES_ATUAIS.md.

All tests use local fixtures, mocks, or the https://example.test/ style.
No real external network traffic is generated.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "engine" / "redlensctl.py"
ROOT = Path(__file__).resolve().parents[1]


class RegressionPlanTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        self._old_redlens_home = os.environ.get("REDLENS_HOME")
        os.environ["REDLENS_HOME"] = self.temp.name

        # Reload redlensctl and dependent modules so each test uses a fresh
        # REDLENS_HOME pointing at the temporary directory.
        for key in list(sys.modules):
            if key in (
                "redlensctl",
                "coverage_cells",
                "score",
                "adapters.health",
                "adapters.nosqli_validator",
                "adapters.semantic_authz",
                "adapters.race_workflow",
                "adapters.capability_registry",
            ):
                del sys.modules[key]

        self.ctl = self._import_ctl()
        self._import_adapters()

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

    def _import_adapters(self):
        # Engine modules are imported by their basenames; adapters form a
        # namespace package under the project root.
        sys.path.insert(0, str(ROOT / "engine"))
        sys.path.insert(0, str(ROOT))
        import adapters.health as health
        import adapters.nosqli_validator as nosqli_validator
        import adapters.race_workflow as race_workflow
        import adapters.capability_registry as capability_registry
        import coverage_cells
        import score

        self.health = health
        self.nosqli_validator = nosqli_validator
        self.race_workflow = race_workflow
        self.capability_registry = capability_registry
        self.coverage_cells = coverage_cells
        self.score = score

    def run_ctl(self, *args, ok=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )
        if ok and result.returncode != 0:
            self.fail(f"redlensctl {' '.join(args)} failed: {result.stderr}")
        if not ok:
            self.assertNotEqual(result.returncode, 0)
            return json.loads(result.stderr)
        return json.loads(result.stdout)

    def init_run(self, target="https://app.example.test"):
        return self.run_ctl("init", "--target", target, "--authorized")

    # 1. Scope and redirects
    def test_scope_and_redirects(self):
        run = self.init_run()
        directory = Path(run["directory"])

        same = self.ctl.scoped_url(directory, "https://app.example.test/api/me")
        self.assertEqual(same, "https://app.example.test/api/me")

        subdomain = self.ctl.scoped_url(directory, "https://sub.app.example.test/x")
        self.assertEqual(subdomain, "https://sub.app.example.test/x")

        self.assertTrue(self.ctl.redirect_in_scope(directory, "https://app.example.test/redirect"))
        self.assertFalse(self.ctl.redirect_in_scope(directory, "https://evil.test/"))

        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.scoped_url(directory, "https://evil.test/")
        self.assertIn("Domínio", str(ctx.exception))

    # 2. Credential out of scope
    def test_scoped_url_rejects_inline_credentials(self):
        run = self.init_run()
        directory = Path(run["directory"])
        with self.assertRaises(self.ctl.RedLensError) as ctx:
            self.ctl.scoped_url(directory, "https://user:pass@app.example.test/")
        self.assertIn("credenciais", str(ctx.exception).lower())

    # 3. Envelope without repeated prompts
    def test_init_authorized_creates_operation_and_unauthorized_fails(self):
        run = self.init_run()
        self.assertTrue(Path(run["directory"]).is_dir())
        self.assertEqual(run["ok"], True)

        error = self.run_ctl("init", "--target", "https://app.example.test", ok=False)
        self.assertIn("Autorização", error["error"])

    # 4. Agent/skill/CLI contract
    def _parser_subcommand_choices(self, parser):
        action = next(
            (a for a in parser._subparsers._actions if hasattr(a, "choices") and a.choices),
            None,
        )
        self.assertIsNotNone(action)
        return set(action.choices.keys())

    def test_agent_skill_cli_only_list_existing_subcommands(self):
        parser = self.ctl.parser()
        choices = self._parser_subcommand_choices(parser)
        forbidden = {"operation", "inventory", "coverage", "evidence"}
        self.assertTrue(forbidden.isdisjoint(choices))
        self.assertNotIn("report generate", " ".join(choices))

        agent_path = Path("/Users/will/.config/opencode/agents/redlens.md")
        skill_path = ROOT / "opencode" / "skills" / "redlens" / "SKILL.md"
        for path in (agent_path, skill_path):
            text = path.read_text(encoding="utf-8")
            # Exclude the explicit prohibition line in the skill.
            check_text = re.sub(r"Do not use .*", "", text)
            for forbidden_cmd in forbidden:
                self.assertNotIn(
                    f"redlensctl {forbidden_cmd}",
                    check_text,
                    f"{path} mentions redlensctl {forbidden_cmd}",
                )
            self.assertNotIn("report generate", check_text, f"{path} mentions report generate")

            # Every `redlensctl <subcommand>` reference must exist in the parser.
            prose_words = {"commands", "subcommands"}
            for match in re.finditer(r"redlensctl\s+([a-z][a-z0-9-]*)", text):
                sub = match.group(1)
                if sub in {"--target", "--run", "--authorized"} | prose_words:
                    continue
                self.assertIn(
                    sub,
                    choices,
                    f"{path} references unknown subcommand {sub!r}",
                )

        # CLI help itself only lists existing subcommands.
        help_text = parser.format_help()
        for sub in choices:
            self.assertIn(sub, help_text)

    # 5. Real capabilities
    def test_capabilities_have_callable_runners_and_no_delegated_placeholders(self):
        metadata = self.capability_registry.capabilities_metadata()
        self.assertTrue(metadata)
        for entry in metadata:
            cap = self.capability_registry.REGISTRY[entry["name"]]
            self.assertTrue(callable(cap.runner))
            self.assertIsNotNone(cap.runner)
            self.assertNotIn("delegated", cap.description.lower())
            self.assertNotIn("delegated", entry.get("description", "").lower())
            self.assertTrue(entry.get("available"))

    # 6. NoSQLi rejected with 400
    def test_nosqli_400_is_tested_negative_not_confirmed(self):
        run = self.init_run()
        run_id = run["run_id"]

        class FakeResponse:
            status = 400
            headers = {}

            def read(self, size=-1):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        argv = [
            "nosqli-validator",
            "--run",
            run_id,
            "--url",
            "https://app.example.test/login",
            "--negative-control-only",
        ]
        with patch.object(
            self.nosqli_validator.urllib.request, "urlopen", return_value=FakeResponse()
        ):
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                old_argv = sys.argv
                sys.argv = argv
                try:
                    exit_code = self.nosqli_validator.main()
                finally:
                    sys.argv = old_argv
            self.assertEqual(exit_code, 0)

        output = json.loads(captured.getvalue())
        self.assertIn(output["verdict"], {"tested-negative", "observation"})
        self.assertNotEqual(output["verdict"], "confirmed")

        findings = list((Path(run["directory"]) / "findings").glob("*.json"))
        self.assertFalse(findings)

    # 7. Concurrent login is normal
    def test_race_workflow_login_returns_not_applicable(self):
        run = self.init_run()
        run_id = run["run_id"]

        argv = [
            "race-workflow",
            "race",
            "--run",
            run_id,
            "--url",
            "https://app.example.test/login",
        ]
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            old_argv = sys.argv
            sys.argv = argv
            try:
                exit_code = self.race_workflow.main()
            finally:
                sys.argv = old_argv
        self.assertEqual(exit_code, 0)

        output = json.loads(captured.getvalue())
        self.assertEqual(output["verdict"], "not-applicable")

        findings = list((Path(run["directory"]) / "findings").glob("*.json"))
        self.assertFalse(findings)

    # 8. Health with broken tool
    def test_broken_tool_is_reported_unavailable(self):
        with patch.object(self.health.subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="Traceback (most recent call last):\nSomething broke\n",
            )
            result = self.health.tool_version("ffuf", container="kali-pentest")
        self.assertFalse(result["available"])
        self.assertIsNotNone(result["reason"])

    # 9. CloakBrowser local
    def test_cloakbrowser_navigation_returns_structured_result(self):
        fake_stdout = json.dumps({"available": True, "reason": "navigation ok"})
        with patch.object(self.health.subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=fake_stdout,
                stderr="",
            )
            result = self.health.cloakbrowser_navigation_check(container="kali-pentest")

        self.assertIn("available", result)
        self.assertIn("degraded", result)
        self.assertIn("missing", result)
        self.assertTrue(result["available"])
        self.assertFalse(result["degraded"])
        self.assertFalse(result["missing"])

    # 10. Coverage for every parameter
    def test_plan_next_creates_cells_for_every_parameter(self):
        run = self.init_run()
        run_id = run["run_id"]

        endpoint = self.run_ctl(
            "add-inventory",
            "--run",
            run_id,
            "--kind",
            "endpoint",
            "--value",
            "https://app.example.test/api/users",
            "--method",
            "GET",
            "--source",
            "manual",
        )
        endpoint_id = endpoint["item_id"]

        param_ids = []
        for name in ("username", "email"):
            item = self.run_ctl(
                "add-inventory",
                "--run",
                run_id,
                "--kind",
                "parameter",
                "--value",
                name,
                "--parent",
                endpoint_id,
                "--source",
                "manual",
            )
            param_ids.append(item["item_id"])

        self.run_ctl(
            "add-identity",
            "--run",
            run_id,
            "--role",
            "user",
            "--label",
            "test-user",
        )

        result = self.coverage_cells.plan_next(run_id)
        self.assertGreaterEqual(result["new_cells"], len(param_ids))

        directory = Path(run["directory"])
        cells = self.coverage_cells.load_cells(directory)
        covered_params = {cell["parameter_id"] for cell in cells.values()}
        for pid in param_ids:
            self.assertIn(pid, covered_params)

    # 11. Score without benchmark
    def test_score_without_benchmark_denies_high_confidence(self):
        run = self.init_run()
        run_id = run["run_id"]
        result = self.score.score_run(run_id)
        self.assertFalse(result["claim_allowed"])
        self.assertNotEqual(result["confidence"], "high")
        self.assertFalse(result["benchmark_valid"])

    # 12. Operation resume
    def test_resume_resets_running_and_failed_tasks_below_max_attempts(self):
        run = self.init_run()
        run_id = run["run_id"]

        tasks = []
        for title in ("task-a", "task-b", "task-c"):
            t = self.run_ctl(
                "add-task",
                "--run",
                run_id,
                "--kind",
                "inventory",
                "--title",
                title,
            )["task"]
            tasks.append(t)

        directory = Path(run["directory"])
        # task-a: running, below limit -> should be reset to pending.
        a_path = directory / "tasks" / f"{tasks[0]['id']}.json"
        a = json.loads(a_path.read_text(encoding="utf-8"))
        a["status"] = "running"
        a["attempt"] = 0
        a_path.write_text(json.dumps(a), encoding="utf-8")

        # task-b: failed, below limit -> should be reset to pending.
        b_path = directory / "tasks" / f"{tasks[1]['id']}.json"
        b = json.loads(b_path.read_text(encoding="utf-8"))
        b["status"] = "failed"
        b["attempt"] = 1
        b_path.write_text(json.dumps(b), encoding="utf-8")

        # task-c: failed, at max attempts -> must stay failed.
        c_path = directory / "tasks" / f"{tasks[2]['id']}.json"
        c = json.loads(c_path.read_text(encoding="utf-8"))
        c["status"] = "failed"
        c["attempt"] = self.ctl.MAX_TASK_ATTEMPTS
        c_path.write_text(json.dumps(c), encoding="utf-8")

        result = self.run_ctl("resume", "--run", run_id)
        self.assertEqual(result["status"], "running")
        self.assertIn(tasks[0]["id"], result["reset_tasks"])
        self.assertIn(tasks[1]["id"], result["reset_tasks"])
        self.assertNotIn(tasks[2]["id"], result["reset_tasks"])

        self.assertEqual(
            json.loads(a_path.read_text(encoding="utf-8"))["status"],
            "pending",
        )
        self.assertEqual(
            json.loads(b_path.read_text(encoding="utf-8"))["status"],
            "pending",
        )
        self.assertEqual(
            json.loads(c_path.read_text(encoding="utf-8"))["status"],
            "failed",
        )

        state = self.ctl.read_json(directory / "state" / "state.json")
        self.assertEqual(state["status"], "running")

    # 13. /pentest URL to report on local fixture
    def test_pentest_url_local_fixture_end_to_end(self):
        run = self.run_ctl(
            "init",
            "--target",
            "https://example.test/",
            "--authorized",
        )
        run_id = run["run_id"]
        directory = Path(run["directory"])

        self.run_ctl("transition", "--run", run_id, "--status", "running")

        endpoint = self.run_ctl(
            "add-inventory",
            "--run",
            run_id,
            "--kind",
            "endpoint",
            "--value",
            "https://example.test/api/users",
            "--method",
            "GET",
            "--source",
            "manual",
        )
        endpoint_id = endpoint["item_id"]

        for name in ("username", "email"):
            self.run_ctl(
                "add-inventory",
                "--run",
                run_id,
                "--kind",
                "parameter",
                "--value",
                name,
                "--parent",
                endpoint_id,
                "--source",
                "manual",
            )

        self.run_ctl(
            "add-identity",
            "--run",
            run_id,
            "--role",
            "user",
            "--label",
            "fixture-user",
        )

        status = self.run_ctl("status", "--run", run_id)
        for category in status["coverage"]["categories"]:
            self.run_ctl(
                "record-coverage",
                "--run",
                run_id,
                "--category",
                category,
                "--status",
                "not-applicable",
                "--summary",
                "Local fixture: category not applicable.",
            )

        evidence = directory / "evidence" / "raw" / "observation.txt"
        evidence.write_text("synthetic observation evidence", encoding="utf-8")
        self.run_ctl(
            "add-finding",
            "--run",
            run_id,
            "--id",
            "OBS-001",
            "--title",
            "Low observation",
            "--severity",
            "low",
            "--status",
            "observation",
            "--asset",
            "https://example.test/api/users",
            "--evidence",
            str(evidence),
        )

        task = self.run_ctl(
            "add-task",
            "--run",
            run_id,
            "--kind",
            "inventory",
            "--title",
            "Map fixture endpoints",
        )["task"]
        self.run_ctl(
            "update-task",
            "--run",
            run_id,
            "--task",
            task["id"],
            "--status",
            "running",
            "--summary",
            "Started",
        )
        self.run_ctl(
            "update-task",
            "--run",
            run_id,
            "--task",
            task["id"],
            "--status",
            "completed",
            "--summary",
            "Done",
        )

        self.run_ctl("quality-gate", "--run", run_id)
        report = self.run_ctl("report", "--run", run_id)
        self.run_ctl("transition", "--run", run_id, "--status", "completed")

        self.assertTrue(Path(report["executive"]).is_file())
        self.assertTrue(Path(report["technical"]).is_file())

        final = self.run_ctl("status", "--run", run_id)
        self.assertEqual(final["state"]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
