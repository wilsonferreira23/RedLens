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
ADAPTER_PATH = ROOT / "adapters" / "mutate_adapter.py"
CTL = ROOT / "engine" / "redlensctl.py"


def load_adapter(home: str):
    os.environ["REDLENS_HOME"] = home
    if "redlensctl" in sys.modules:
        importlib.reload(sys.modules["redlensctl"])
    spec = importlib.util.spec_from_file_location("mutate_adapter", ADAPTER_PATH)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


class MutateAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        result = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized")
        self.run_id = result["run_id"]
        self.directory = Path(result["directory"])
        self.ADAPTER = load_adapter(self.temp.name)

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

    def write_identity(self, role: str, tenant: str = ""):
        self.run_ctl(
            "add-identity",
            "--run", self.run_id,
            "--role", role,
            "--tenant", tenant,
            "--label", f"{role}-test",
        )

    def fake_replay(self, baseline_status=200, baseline_size=12, mutated_status=200, mutated_size=500):
        call_count = {"n": 0}

        def run_replay(run_id: str, spec_path: str, role: str) -> dict:
            call_count["n"] += 1
            status = mutated_status if call_count["n"] > 1 else baseline_status
            size = mutated_size if call_count["n"] > 1 else baseline_size
            sha = "a" * 64 if call_count["n"] == 1 else "b" * 64
            timestamp = "20260727T000000Z"
            return {
                "ok": True,
                "role": role,
                "url": "https://app.example.test/api/me",
                "method": "GET",
                "status": status,
                "size": size,
                "sha256": sha,
                "truncated": False,
                "private_evidence": f"evidence/private/{timestamp}-replay-{role}-{sha[:8]}.json",
                "sanitized_evidence": f"evidence/sanitized/{timestamp}-replay-{role}-{sha[:8]}.json",
            }
        return run_replay

    def test_rejects_unknown_payload(self):
        spec = self.write_spec({"method": "GET", "url": "https://app.example.test/api/me"})
        with patch.object(self.ADAPTER, "run_replay", side_effect=self.fake_replay()):
            with patch.object(sys, "argv", [
                "mutate-safe", "--run", self.run_id, "--spec", str(spec),
                "--role", "admin", "--position", "query", "--field", "q",
                "--payload-id", "nuclear"
            ]):
                self.assertEqual(self.ADAPTER.main(), 2)

    def test_query_mutation_detects_difference(self):
        self.write_identity("admin")
        spec = self.write_spec({"method": "GET", "url": "https://app.example.test/api/me?q=base"})
        with patch.object(self.ADAPTER, "run_replay", side_effect=self.fake_replay(mutated_size=500)):
            with patch.object(sys, "argv", [
                "mutate-safe", "--run", self.run_id, "--spec", str(spec),
                "--role", "admin", "--position", "query", "--field", "q",
                "--payload-id", "generic"
            ]):
                self.assertEqual(self.ADAPTER.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertTrue(findings, "Mutation que altera resposta deve gerar finding.")
        finding = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(finding["metadata"]["payload_id"], "generic")
        self.assertEqual(finding["metadata"]["position"], "query")

    def test_body_field_json_mutation(self):
        self.write_identity("admin")
        spec = self.write_spec({
            "method": "POST",
            "url": "https://app.example.test/api/me",
            "content_type": "application/json",
            "body": json.dumps({"name": "alice"}),
        })
        with patch.object(self.ADAPTER, "run_replay", side_effect=self.fake_replay()):
            with patch.object(sys, "argv", [
                "mutate-safe", "--run", self.run_id, "--spec", str(spec),
                "--role", "admin", "--position", "body_field", "--field", "name",
                "--payload-id", "generic"
            ]):
                self.assertEqual(self.ADAPTER.main(), 0)

        mutated_specs = list((self.directory / "evidence" / "private" / "mutations").glob("*.json"))
        self.assertEqual(len(mutated_specs), 1)
        mutated = json.loads(mutated_specs[0].read_text(encoding="utf-8"))
        self.assertEqual(json.loads(mutated["body"])["name"], "redlens-mutation-marker")

    def test_header_mutation(self):
        self.write_identity("admin")
        spec = self.write_spec({
            "method": "GET",
            "url": "https://app.example.test/api/me",
            "headers": {"X-Test": "base"},
        })
        with patch.object(self.ADAPTER, "run_replay", side_effect=self.fake_replay()):
            with patch.object(sys, "argv", [
                "mutate-safe", "--run", self.run_id, "--spec", str(spec),
                "--role", "admin", "--position", "header", "--field", "X-Test",
                "--payload-id", "generic"
            ]):
                self.assertEqual(self.ADAPTER.main(), 0)

        mutated_specs = list((self.directory / "evidence" / "private" / "mutations").glob("*.json"))
        self.assertEqual(len(mutated_specs), 1)
        mutated = json.loads(mutated_specs[0].read_text(encoding="utf-8"))
        self.assertEqual(mutated["headers"]["X-Test"], "redlens-mutation-marker")

    def test_no_difference_does_not_create_finding(self):
        self.write_identity("admin")
        spec = self.write_spec({"method": "GET", "url": "https://app.example.test/api/me?q=base"})
        with patch.object(self.ADAPTER, "run_replay", side_effect=self.fake_replay(mutated_size=12)):
            with patch.object(sys, "argv", [
                "mutate-safe", "--run", self.run_id, "--spec", str(spec),
                "--role", "admin", "--position", "query", "--field", "q",
                "--payload-id", "generic"
            ]):
                self.assertEqual(self.ADAPTER.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertFalse(findings, "Mutation sem alteração não deve gerar finding.")


if __name__ == "__main__":
    unittest.main()
