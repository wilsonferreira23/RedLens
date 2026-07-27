import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "engine" / "redlensctl.py"


class ReportsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        created = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized")
        self.run_id = created["run_id"]
        self.directory = Path(created["directory"])

    def tearDown(self):
        self.temp.cleanup()

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

    def close_coverage(self):
        status = self.run_ctl("status", "--run", self.run_id)
        for category in status["coverage"]["categories"]:
            self.run_ctl(
                "record-coverage",
                "--run", self.run_id,
                "--category", category,
                "--status", "not-applicable",
                "--summary", "Laboratory unit test",
            )

    def test_report_includes_manifest_hashes_timeline(self):
        self.close_coverage()
        report = self.run_ctl("report", "--run", self.run_id)
        self.assertTrue((self.directory / report["manifest"]).is_file())
        self.assertTrue((self.directory / report["hashes"]).is_file())
        technical = (self.directory / report["technical"]).read_text(encoding="utf-8")
        self.assertIn("Manifesto de ferramentas", technical)
        self.assertIn("Hashes de artefatos", technical)
        self.assertIn("Timeline de eventos", technical)

    def test_secret_scan_blocks_report(self):
        self.close_coverage()
        leak = self.directory / "evidence" / "sanitized" / "leak.txt"
        leak.write_text("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", encoding="utf-8")
        error = self.run_ctl("report", "--run", self.run_id, ok=False)
        self.assertIn("vazamento", error["error"])

    def test_browser_degraded_detected(self):
        self.close_coverage()
        raw = self.directory / "evidence" / "raw" / "20260727T000000Z-browser" / "metadata.json"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps({"backend": "playwright-fallback"}), encoding="utf-8")
        report = self.run_ctl("report", "--run", self.run_id)
        executive = (self.directory / report["executive"]).read_text(encoding="utf-8")
        technical = (self.directory / report["technical"]).read_text(encoding="utf-8")
        self.assertIn("Browser degradado", executive)
        self.assertIn("Browser degradado", technical)

    def test_report_matrix_includes_tenant_object(self):
        self.close_coverage()
        evidence = self.directory / "evidence" / "sanitized" / "access.json"
        evidence.write_text("{}", encoding="utf-8")
        self.run_ctl(
            "record-access",
            "--run", self.run_id,
            "--endpoint", "https://app.example.test/api/me",
            "--method", "GET",
            "--role", "admin",
            "--tenant", "tenant-a",
            "--object-id", "me",
            "--status", "allowed",
            "--evidence", str(evidence),
        )
        report = self.run_ctl("report", "--run", self.run_id)
        technical = (self.directory / report["technical"]).read_text(encoding="utf-8")
        self.assertIn("tenant-a", technical)
        self.assertIn("me", technical)


if __name__ == "__main__":
    unittest.main()
