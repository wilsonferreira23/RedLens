import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "engine" / "redlensctl.py"
ADAPTER = ROOT / "adapters" / "api_adapter.py"


class ApiAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        created = self.call_script(CTL, "init", "--target", "https://app.example.test",
            "--authorized")
        self.run_id = created["run_id"]
        self.directory = Path(created["directory"])

    def tearDown(self):
        self.temp.cleanup()

    def call_script(self, script, *args):
        result = subprocess.run([sys.executable, str(script), *args], env=self.env,
                                text=True, capture_output=True)
        if result.returncode:
            self.fail(result.stderr)
        return json.loads(result.stdout)

    def test_imports_scoped_openapi_endpoints_and_parameters(self):
        spec = self.directory / "evidence" / "private" / "openapi.json"
        spec.write_text(json.dumps({
            "openapi": "3.0.0",
            "servers": [{"url": "https://app.example.test"}],
            "paths": {
                "/users/{id}": {
                    "get": {"parameters": [{"name": "id", "in": "path"}]},
                    "post": {"parameters": [{"name": "verbose", "in": "query"}]},
                }
            },
        }), encoding="utf-8")
        result = self.call_script(ADAPTER, "--run", self.run_id,
                                  "--spec", "evidence/private/openapi.json")
        self.assertEqual(len(result["endpoints"]), 2)
        self.assertEqual(len(result["parameters"]), 2)
        self.assertTrue((self.directory / result["evidence"]).is_file())


if __name__ == "__main__":
    unittest.main()
