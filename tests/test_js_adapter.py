import importlib.util
import io
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
ADAPTER_PATH = ROOT / "adapters" / "js_adapter.py"
SPEC = importlib.util.spec_from_file_location("js_adapter", ADAPTER_PATH)
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


class JsAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        created = self._call_ctl("init", "--target", "https://app.example.test",
            "--authorized")
        self.run_id = created["run_id"]
        self.directory = Path(created["directory"])

    def tearDown(self):
        self.temp.cleanup()

    def _call_ctl(self, *args):
        result = subprocess.run([sys.executable, str(CTL), *args],
                                env=self.env, text=True, capture_output=True)
        if result.returncode:
            self.fail(result.stderr)
        return json.loads(result.stdout)

    def _urlopen_side_effect(self, request, *args, **kwargs):
        url = request.full_url
        if url == "https://app.example.test/":
            body = (
                '<html><script src="/app.js"></script>'
                '<script src="/vendor.js"></script>'
                '<script src="https://evil.test/tracker.js"></script></html>'
            )
        elif url == "https://app.example.test/app.js":
            body = 'const API = "/api/secret"; const api_key = "supersecret123456";'
        elif url == "https://app.example.test/vendor.js":
            body = 'var config = {version: "1.0"};'
        else:
            raise IOError(f"unexpected URL: {url}")
        mock_response = mock.MagicMock()
        mock_response.read.return_value = body.encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        return mock_response

    def test_extracts_endpoints_and_secrets_from_js(self):
        with mock.patch.object(ADAPTER.redlensctl, "RUNS", self.directory.parent):
            with mock.patch.object(ADAPTER.urllib.request, "urlopen", side_effect=self._urlopen_side_effect):
                result = ADAPTER.analyze(self.run_id, "https://app.example.test/")

        self.assertTrue(result["ok"])
        self.assertEqual(result["js_files"], 2)
        self.assertEqual(result["endpoints"], 1)
        self.assertEqual(result["secret_hints"], 1)

        inventory = {
            json.loads(p.read_text(encoding="utf-8"))["value"]
            for p in (self.directory / "inventory").glob("*.json")
        }
        self.assertIn("https://app.example.test/api/secret", inventory)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        finding = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["status"], "observation")
        secrets_path = self.directory / finding["evidence"][0]
        self.assertTrue(secrets_path.is_file())
        secrets = json.loads(secrets_path.read_text(encoding="utf-8"))
        self.assertTrue(all("<redacted>" in s["snippet"] for s in secrets))

        coverage = json.loads((self.directory / "state" / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(coverage["categories"]["client_side"]["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
