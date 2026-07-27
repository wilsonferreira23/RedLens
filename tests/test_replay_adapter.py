import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "runtime" / "kali-workspace"
ADAPTER_PATH = ROOT / "adapters" / "replay_adapter.py"
WORKER_PATH = ROOT / "runtime" / "kali-workspace" / "redlens-replay-worker.py"
CTL = ROOT / "engine" / "redlensctl.py"

SPEC_WORKER = importlib.util.spec_from_file_location("replay_worker", WORKER_PATH)
WORKER = importlib.util.module_from_spec(SPEC_WORKER)
SPEC_WORKER.loader.exec_module(WORKER)


def load_adapter(home: str):
    os.environ["REDLENS_HOME"] = home
    # Force redlensctl to recompute ROOT/RUNS from the current environment.
    if "redlensctl" in sys.modules:
        importlib.reload(sys.modules["redlensctl"])
    spec = importlib.util.spec_from_file_location("replay_adapter", ADAPTER_PATH)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


class ReplayWorkerTest(unittest.TestCase):
    def test_redacts_sensitive_headers(self):
        headers = {
            "Accept": "application/json",
            "Cookie": "session=secret",
            "Authorization": "Bearer secret",
            "X-Api-Key": "secret",
        }
        parsed = WORKER.redact_headers(headers)
        self.assertEqual(parsed["Accept"], "application/json")
        self.assertEqual(parsed["Cookie"], "<redacted>")
        self.assertEqual(parsed["Authorization"], "<redacted>")
        self.assertEqual(parsed["X-Api-Key"], "<redacted>")

    def test_cookie_filter_matches_domain_and_path(self):
        session = {
            "cookies": [
                {
                    "name": "session",
                    "value": "abc",
                    "domain": ".example.test",
                    "path": "/",
                },
                {
                    "name": "other",
                    "value": "xyz",
                    "domain": "other.test",
                    "path": "/",
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text(json.dumps(session), encoding="utf-8")
            cookies = WORKER.load_cookies(path, "https://app.example.test/login")
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]["name"], "session")


class ReplayAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        self.ADAPTER = load_adapter(self.temp.name)
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
        if result.returncode != 0:
            self.fail(result.stderr)
        return json.loads(result.stdout)

    def write_spec(self, spec: dict) -> Path:
        spec_dir = self.directory / "evidence" / "private" / "replay-specs"
        spec_dir.mkdir(parents=True, exist_ok=True)
        path = spec_dir / "test.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def write_identity(self, role: str, tenant: Optional[str] = None):
        self.run_ctl(
            "add-identity",
            "--run", self.run_id,
            "--role", role,
            "--tenant", tenant or "",
            "--label", f"{role}-test",
        )

    def fake_docker_exec(self):
        def run(cmd, **kwargs):
            output_dir = None
            for idx, part in enumerate(cmd):
                if part == "--output" and idx + 1 < len(cmd):
                    container_path = cmd[idx + 1]
                    relative = container_path.replace("/workspace/", "")
                    output_dir = WORKSPACE / relative
                    break
            if output_dir is None:
                raise RuntimeError("Mock could not find --output in command")
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "private").mkdir(exist_ok=True)
            (output_dir / "sanitized").mkdir(exist_ok=True)
            meta = {
                "ok": True,
                "method": "GET",
                "url": "https://app.example.test/api/me",
                "status": 200,
                "size": 12,
                "sha256": "a" * 64,
                "truncated": False,
                "private": str(output_dir / "private" / "response.json"),
                "sanitized": str(output_dir / "sanitized" / "meta.json"),
            }
            (output_dir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
            (output_dir / "private" / "response.json").write_text(
                json.dumps({"body_base64": "SGVsbG8gV29ybGQ="}), encoding="utf-8"
            )
            (output_dir / "sanitized" / "meta.json").write_text(
                json.dumps({"status": 200, "size": 12}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return run

    def test_rejects_spec_outside_private(self):
        bad = self.directory / "evidence" / "sanitized" / "leak.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text(json.dumps({"method": "GET", "url": "https://app.example.test"}), encoding="utf-8")
        with patch.object(self.ADAPTER.subprocess, "run", self.fake_docker_exec()):
            with patch.object(sys, "argv", ["replay-safe", "--run", self.run_id, "--spec", str(bad), "--role", "viewer"]):
                self.assertEqual(self.ADAPTER.main(), 2)


    def test_successful_replay_records_evidence_and_access(self):
        self.write_identity("admin", tenant="tenant-a")
        self.write_spec({
            "method": "GET",
            "url": "https://app.example.test/api/me",
            "object_tenant": "tenant-a",
            "object_id": "me",
        })
        temp = Path(self.temp.name) / "replay-output"
        with patch.object(self.ADAPTER.subprocess, "run", self.fake_docker_exec()):
            with patch.object(sys, "argv", ["replay-safe", "--run", self.run_id, "--spec", "evidence/private/replay-specs/test.json", "--role", "admin"]):
                self.assertEqual(self.ADAPTER.main(), 0)
        private_files = list((self.directory / "evidence" / "private").glob("*replay*"))
        sanitized_files = list((self.directory / "evidence" / "sanitized").glob("*replay*"))
        self.assertTrue(private_files)
        self.assertTrue(sanitized_files)
        matrix = json.loads((self.directory / "state" / "access-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(len(matrix["cells"]), 1)
        cell = list(matrix["cells"].values())[0]
        self.assertEqual(cell["status"], "allowed")
        self.assertEqual(cell["role"], "admin")


import subprocess


if __name__ == "__main__":
    unittest.main()
