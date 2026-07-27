import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "engine" / "redlensctl.py"


def load_adapter(name: str, home: str):
    os.environ["REDLENS_HOME"] = home
    if "redlensctl" in sys.modules:
        importlib.reload(sys.modules["redlensctl"])
    path = ROOT / "adapters" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


class BaseAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        result = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized")
        self.run_id = result["run_id"]
        self.directory = Path(result["directory"])
        # Lab tests may exercise intrusive scanners.
        auth = json.loads((self.directory / "authorization" / "authorization.json").read_text(encoding="utf-8"))
        auth["destructive_authorized"] = True
        (self.directory / "authorization" / "authorization.json").write_text(
            json.dumps(auth, ensure_ascii=False, indent=2), encoding="utf-8")

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


class SqlmapAdapterTest(BaseAdapterTest):

    def test_rejects_invalid_level(self):
        adapter = load_adapter("sqlmap_adapter", self.temp.name)
        with patch.object(sys, "argv", [
            "sqlmap-safe", "--run", self.run_id,
            "--url", "https://app.example.test/api",
            "--level", "5",
        ]):
            self.assertEqual(adapter.main(), 2)

    def test_parses_findings_and_records_observation(self):
        adapter = load_adapter("sqlmap_adapter", self.temp.name)
        self.run_ctl(
            "add-inventory", "--run", self.run_id,
            "--kind", "endpoint",
            "--value", "https://app.example.test/api",
            "--method", "GET",
            "--source", "tool",
        )

        def fake_docker_exec(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 0,
                "[*] starting @ 00:00:00 /2026-07-27/\n"
                "parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]\n"
                "title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)\n"
                "back-end DBMS: MySQL >= 5.0\n",
                "",
            )

        with patch.object(adapter.subprocess, "run", side_effect=fake_docker_exec):
            with patch.object(sys, "argv", [
                "sqlmap-safe", "--run", self.run_id,
                "--url", "https://app.example.test/api",
                "--parameter", "id",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["status"], "observation")


class XssAdapterTest(BaseAdapterTest):

    def test_records_finding_on_poc_line(self):
        adapter = load_adapter("xss_adapter", self.temp.name)

        def fake_docker_exec(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 0,
                "[*] dalfox scanner version 2.9.4\n"
                "[POC][G][GET] https://app.example.test/?q=<script>alert(1)</script>\n",
                "",
            )

        with patch.object(adapter.subprocess, "run", side_effect=fake_docker_exec):
            with patch.object(sys, "argv", [
                "xss-safe", "--run", self.run_id,
                "--url", "https://app.example.test/",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)


class CmdiAdapterTest(BaseAdapterTest):

    def test_records_finding_on_injectable_line(self):
        adapter = load_adapter("cmdi_adapter", self.temp.name)

        def fake_docker_exec(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 0,
                "[+] Testing parameter 'cmd'\n"
                "[x] Critical: The parameter 'cmd' seems to be injectable via (results-based) command injection.\n",
                "",
            )

        with patch.object(adapter.subprocess, "run", side_effect=fake_docker_exec):
            with patch.object(sys, "argv", [
                "cmdi-safe", "--run", self.run_id,
                "--url", "https://app.example.test/api",
                "--parameter", "cmd",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["severity"], "critical")


class CsrfAdapterTest(BaseAdapterTest):
    def write_spec(self, spec: dict) -> Path:
        spec_dir = self.directory / "evidence" / "private" / "replay-specs"
        spec_dir.mkdir(parents=True, exist_ok=True)
        path = spec_dir / "test.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def test_missing_csrf_token_creates_finding(self):
        adapter = load_adapter("csrf_adapter", self.temp.name)
        spec = self.write_spec({
            "method": "POST",
            "url": "https://app.example.test/api/submit",
            "content_type": "application/json",
            "body": json.dumps({"name": "alice"}),
        })
        with patch.object(sys, "argv", [
            "csrf-safe", "--run", self.run_id,
            "--spec", str(spec),
        ]):
            self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertIn("csrf_token", f["metadata"]["missing"])

    def test_csrf_token_present_no_finding(self):
        adapter = load_adapter("csrf_adapter", self.temp.name)
        spec = self.write_spec({
            "method": "POST",
            "url": "https://app.example.test/api/submit",
            "content_type": "application/json",
            "body": json.dumps({"name": "alice", "_token": "xyz"}),
            "headers": {"Origin": "https://app.example.test"},
        })
        with patch.object(sys, "argv", [
            "csrf-safe", "--run", self.run_id,
            "--spec", str(spec),
        ]):
            self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertFalse(findings)

    def test_rejects_spec_outside_private(self):
        adapter = load_adapter("csrf_adapter", self.temp.name)
        bad = self.directory / "leak.json"
        bad.write_text(json.dumps({"method": "POST", "url": "https://app.example.test"}), encoding="utf-8")
        with patch.object(sys, "argv", [
            "csrf-safe", "--run", self.run_id,
            "--spec", str(bad),
        ]):
            self.assertEqual(adapter.main(), 2)


class MassAssignmentAdapterTest(BaseAdapterTest):
    def write_spec(self, spec: dict) -> Path:
        spec_dir = self.directory / "evidence" / "private" / "replay-specs"
        spec_dir.mkdir(parents=True, exist_ok=True)
        path = spec_dir / "test.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def write_identity(self, role: str):
        self.run_ctl(
            "add-identity",
            "--run", self.run_id,
            "--role", role,
            "--label", f"{role}-test",
        )


    def test_records_finding_when_response_differs(self):
        adapter = load_adapter("mass_assignment_adapter", self.temp.name)
        self.write_identity("admin")
        spec = self.write_spec({
            "method": "PUT",
            "url": "https://app.example.test/api/users",
            "content_type": "application/json",
            "body": json.dumps({"name": "alice"}),
        })

        call_count = {"n": 0}

        def fake_replay(cmd, **kwargs):
            call_count["n"] += 1
            status = 200 if call_count["n"] == 1 else 200
            size = 12 if call_count["n"] == 1 else 500
            sha = "a" * 64 if call_count["n"] == 1 else "b" * 64
            timestamp = "20260727T000000Z"
            output = json.dumps({
                "ok": True,
                "role": "admin",
                "url": "https://app.example.test/api/users",
                "method": "PUT",
                "status": status,
                "size": size,
                "sha256": sha,
                "truncated": False,
                "private_evidence": f"evidence/private/{timestamp}.json",
                "sanitized_evidence": f"evidence/sanitized/{timestamp}.json",
            })
            return subprocess.CompletedProcess(cmd, 0, output, "")

        with patch.object(adapter.subprocess, "run", side_effect=fake_replay):
            with patch.object(sys, "argv", [
                "massassign-safe", "--run", self.run_id,
                "--spec", str(spec),
                "--role", "admin",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)


class PlannerAdapterTest(BaseAdapterTest):
    def test_emits_pending_tasks_for_endpoint(self):
        adapter = load_adapter("planner_adapter", self.temp.name)
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
        with patch.object(sys, "argv", [
            "plan-safe", "--run", self.run_id, "--limit", "5",
        ]):
            self.assertEqual(adapter.main(), 0)


class AddFindingQualityTest(BaseAdapterTest):
    def _write_evidence(self, path: str):
        full = self.directory / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(json.dumps({"ok": True}), encoding="utf-8")

    def test_observation_accepted_without_reproduction(self):
        self._write_evidence("evidence/sanitized/obs.json")
        self.run_ctl(
            "add-finding", "--run", self.run_id,
            "--id", "F-OBS-1",
            "--title", "Possible information leak",
            "--severity", "medium",
            "--status", "observation",
            "--asset", "https://app.example.test/api",
            "--evidence", "evidence/sanitized/obs.json",
        )
        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["status"], "observation")
        self.assertFalse(f["reproduced"])
        self.assertFalse(f["negative_control"])

    def test_confirmed_high_requires_reproduction_and_negative_control(self):
        self._write_evidence("evidence/sanitized/sql.json")
        result = subprocess.run(
            [sys.executable, str(CTL),
             "add-finding", "--run", self.run_id,
             "--id", "F-HIGH-1",
             "--title", "SQL injection",
             "--severity", "high",
             "--status", "confirmed",
             "--asset", "https://app.example.test/api",
             "--evidence", "evidence/sanitized/sql.json"],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reprodução", result.stderr.lower())

    def test_confirmed_high_with_reproduction_and_negative_control_accepted(self):
        self._write_evidence("evidence/sanitized/sql.json")
        self.run_ctl(
            "add-finding", "--run", self.run_id,
            "--id", "F-HIGH-2",
            "--title", "Confirmed SQL injection",
            "--severity", "high",
            "--status", "confirmed",
            "--asset", "https://app.example.test/api",
            "--evidence", "evidence/sanitized/sql.json",
            "--reproduced",
            "--negative-control",
        )
        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["status"], "confirmed")
        self.assertTrue(f["reproduced"])
        self.assertTrue(f["negative_control"])


if __name__ == "__main__":
    unittest.main()
