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
ADAPTER_PATH = ROOT / "adapters" / "authz_adapter.py"
CTL = ROOT / "engine" / "redlensctl.py"


def load_authz(home: str):
    os.environ["REDLENS_HOME"] = home
    if "redlensctl" in sys.modules:
        importlib.reload(sys.modules["redlensctl"])
    spec = importlib.util.spec_from_file_location("authz_adapter", ADAPTER_PATH)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


class AuthzAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        self.ADAPTER = load_authz(self.temp.name)
        result = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized")
        self.run_id = result["run_id"]
        self.directory = Path(result["directory"])
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "admin", "--tenant", "tenant-a", "--label", "admin-test"
        )
        self.run_ctl(
            "add-identity", "--run", self.run_id,
            "--role", "viewer", "--tenant", "tenant-a", "--label", "viewer-test"
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_ctl(self, *args):
        result = subprocess.run(
            [sys.executable, str(CTL), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            self.fail(result.stderr)
        return json.loads(result.stdout)

    def fake_replay(self, positive_status: int, negative_status: int):
        def run(cmd, **kwargs):
            role = None
            for idx, part in enumerate(cmd):
                if part == "--role" and idx + 1 < len(cmd):
                    role = cmd[idx + 1]
                    break
            status = positive_status if role == "admin" else negative_status
            spec_relative = None
            for idx, part in enumerate(cmd):
                if part == "--spec" and idx + 1 < len(cmd):
                    spec_relative = cmd[idx + 1]
                    break
            run_dir = Path(self.temp.name) / "runs" / self.run_id
            spec_path = run_dir / spec_relative
            sanitized = run_dir / "evidence" / "sanitized" / f"replay-{role}-{status}.json"
            private = run_dir / "evidence" / "private" / f"replay-{role}-{status}.json"
            sanitized.parent.mkdir(parents=True, exist_ok=True)
            private.parent.mkdir(parents=True, exist_ok=True)
            redlensctl_spec = importlib.util.spec_from_file_location("redlensctl", str(CTL))
            redlensctl = importlib.util.module_from_spec(redlensctl_spec)
            redlensctl_spec.loader.exec_module(redlensctl)
            redlensctl.write_json(sanitized, {
                "status": status,
                "size": 0,
                "sha256": "a" * 64,
                "response_headers": {},
            })
            private.write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, json.dumps({
                "ok": True,
                "role": role,
                "url": "https://app.example.test/api/me",
                "method": "GET",
                "status": status,
                "size": 0,
                "sha256": "a" * 64,
                "private_evidence": str(private.relative_to(run_dir)),
                "sanitized_evidence": str(sanitized.relative_to(run_dir)),
            }), "")
        return run

    def test_classify_status(self):
        self.assertEqual(self.ADAPTER.classify_access_status(200), "allowed")
        self.assertEqual(self.ADAPTER.classify_access_status(401), "denied")
        self.assertEqual(self.ADAPTER.classify_access_status(403), "denied")
        self.assertEqual(self.ADAPTER.classify_access_status(404), "error")
        self.assertEqual(self.ADAPTER.classify_access_status(429), "blocked")
        self.assertEqual(self.ADAPTER.classify_access_status(500), "error")
        self.assertEqual(
            self.ADAPTER.classify_access_status(503, {"retry-after": "120"}),
            "blocked"
        )

    def test_rejects_forbidden_method(self):
        with patch.object(self.ADAPTER.subprocess, "run", self.fake_replay(200, 401)):
            with patch.object(sys, "argv", [
                "authz-safe", "--run", self.run_id,
                "--endpoint", "https://app.example.test/api/me",
                "--method", "POST", "--role", "admin", "--object-id", "me",
            ]):
                self.assertEqual(self.ADAPTER.main(), 2)


    def test_records_positive_and_negative_cells(self):
        with patch.object(self.ADAPTER.subprocess, "run", self.fake_replay(200, 401)):
            with patch.object(sys, "argv", [
                "authz-safe", "--run", self.run_id,
                "--endpoint", "https://app.example.test/api/me",
                "--role", "admin", "--negative-role", "viewer",
                "--tenant", "tenant-a", "--object-id", "me",
                "--skip-data-extraction-check",
            ]):
                self.assertEqual(self.ADAPTER.main(), 0)
        matrix = json.loads((self.directory / "state" / "access-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(len(matrix["cells"]), 2)
        statuses = {cell["role"]: cell["status"] for cell in matrix["cells"].values()}
        self.assertEqual(statuses["admin"], "allowed")
        self.assertEqual(statuses["viewer"], "denied")

    def test_rate_limited_is_blocked_not_safe(self):
        with patch.object(self.ADAPTER.subprocess, "run", self.fake_replay(429, 429)):
            with patch.object(sys, "argv", [
                "authz-safe", "--run", self.run_id,
                "--endpoint", "https://app.example.test/api/me",
                "--role", "admin", "--negative-role", "viewer",
                "--tenant", "tenant-a", "--object-id", "me",
                "--skip-data-extraction-check",
            ]):
                self.assertEqual(self.ADAPTER.main(), 0)
        matrix = json.loads((self.directory / "state" / "access-matrix.json").read_text(encoding="utf-8"))
        for cell in matrix["cells"].values():
            self.assertEqual(cell["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
