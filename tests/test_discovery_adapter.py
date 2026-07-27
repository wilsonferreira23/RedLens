import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "engine" / "redlensctl.py"
ADAPTER_PATH = ROOT / "adapters" / "discovery_adapter.py"
SPEC = importlib.util.spec_from_file_location("discovery_adapter", ADAPTER_PATH)
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


class DiscoveryAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        created = self._call_ctl("init", "--target", "https://app.example.test",
            "--authorized")
        self.run_id = created["run_id"]
        self.directory = Path(created["directory"])
        auth = json.loads((self.directory / "authorization" / "authorization.json").read_text(encoding="utf-8"))
        auth["destructive_authorized"] = True
        (self.directory / "authorization" / "authorization.json").write_text(
            json.dumps(auth, ensure_ascii=False, indent=2), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def _call_ctl(self, *args):
        result = subprocess.run([sys.executable, str(CTL), *args],
                                env=self.env, text=True, capture_output=True)
        if result.returncode:
            self.fail(result.stderr)
        return json.loads(result.stdout)

    def _feroxbuster_stdout(self, urls):
        lines = []
        for url in urls:
            lines.append(json.dumps({"url": url, "status": 200, "content_length": 42}))
        return "\n".join(lines)

    def test_discovers_in_scope_endpoints_and_records_coverage(self):
        urls = [
            "https://app.example.test/admin",
            "https://app.example.test/api/users",
            "https://evil.test/should-be-skipped",
        ]
        fake_result = subprocess.CompletedProcess(
            args=["docker", "exec"],
            returncode=0,
            stdout=self._feroxbuster_stdout(urls),
            stderr="",
        )
        with mock.patch.object(ADAPTER.redlensctl, "RUNS", self.directory.parent):
            with mock.patch.object(ADAPTER.subprocess, "run", return_value=fake_result):
                result = ADAPTER.discover(self.run_id, "https://app.example.test", "feroxbuster")

        self.assertTrue(result["ok"])
        self.assertEqual(result["endpoints"], 2)
        self.assertTrue((self.directory / result["summary"]).is_file())
        self.assertTrue((self.directory / result["raw"]).is_file())

        summary = json.loads((self.directory / result["summary"]).read_text(encoding="utf-8"))
        self.assertEqual(summary["discovered_total"], 3)
        self.assertEqual(summary["in_scope"], 2)
        self.assertEqual(summary["skipped"], 1)

        inventory = list((self.directory / "inventory").glob("*.json"))
        endpoint_values = {
            json.loads(path.read_text(encoding="utf-8"))["value"]
            for path in inventory
        }
        self.assertIn("https://app.example.test/admin", endpoint_values)
        self.assertIn("https://app.example.test/api/users", endpoint_values)
        self.assertNotIn("https://evil.test/should-be-skipped", endpoint_values)

        coverage = json.loads((self.directory / "state" / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(coverage["categories"]["surface"]["status"], "confirmed")
