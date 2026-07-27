import importlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "engine" / "redlensctl.py"


class FakeResponse:
    def __init__(self, status: int, body: dict | bytes, headers: dict | None = None):
        self.status = status
        self.headers = headers or {}
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def read(self, n: int = -1) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def make_response(status: int, body: dict | bytes, headers: dict | None = None):
    body_bytes = body if isinstance(body, bytes) else json.dumps(body).encode()
    if 200 <= status < 400:
        return FakeResponse(status, body_bytes, headers or {})
    raise urllib.error.HTTPError(
        "http://example.test", status, "", headers or {}, io.BytesIO(body_bytes)
    )


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


class NoSQLiFalsePositiveTest(BaseAdapterTest):

    def _build_urlopen(self, baseline_status=401, payload_status=400, payload_body=None,
                       protected_status=401, follow_url=None):
        baseline = {"username": "redlens_test_user", "password": "redlens_test_pass"}
        invalid = {"username": "redlens_invalid_user", "password": "redlens_invalid_pass"}
        payload_body = payload_body or {"error": "invalid"}

        def urlopen(req, timeout=None):
            url = req.full_url
            method = req.get_method()
            data = json.loads(req.data.decode()) if req.data else None

            if method == "POST" and url == "https://app.example.test/api/login":
                if data == invalid:
                    return make_response(baseline_status, {"error": "rejected"})
                if data == baseline:
                    return make_response(baseline_status, {"error": "rejected"})
                return make_response(payload_status, payload_body)

            if method == "GET" and url == follow_url:
                return make_response(protected_status, {"ok": True})

            raise ConnectionError(f"Unexpected request {method} {url}")

        return urlopen

    def test_400_payload_is_not_confirmed(self):
        adapter = load_adapter("nosqli_validator", self.temp.name)
        urlopen = self._build_urlopen(payload_status=400)

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "nosqli-validator", "--run", self.run_id,
                "--url", "https://app.example.test/api/login",
                "--protected-url", "https://app.example.test/api/me",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 0)

        summaries = list((self.directory / "evidence" / "sanitized").glob("*nosqli*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "tested-negative")
        self.assertIn("negative_control", summary)
        self.assertTrue(summary["negative_control"]["rejected"])

    def test_token_without_followup_success_is_not_confirmed(self):
        adapter = load_adapter("nosqli_validator", self.temp.name)
        urlopen = self._build_urlopen(
            baseline_status=401,
            payload_status=200,
            payload_body={"access_token": "hacked", "user_id": "admin"},
            protected_status=401,
            follow_url="https://app.example.test/api/me",
        )

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "nosqli-validator", "--run", self.run_id,
                "--url", "https://app.example.test/api/login",
                "--protected-url", "https://app.example.test/api/me",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 0)

        summaries = list((self.directory / "evidence" / "sanitized").glob("*nosqli*"))
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "observation")

    def test_bypass_confirmed_when_token_and_followup_succeed(self):
        adapter = load_adapter("nosqli_validator", self.temp.name)
        urlopen = self._build_urlopen(
            baseline_status=401,
            payload_status=200,
            payload_body={"access_token": "hacked", "user_id": "admin"},
            protected_status=200,
            follow_url="https://app.example.test/api/me",
        )

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "nosqli-validator", "--run", self.run_id,
                "--url", "https://app.example.test/api/login",
                "--protected-url", "https://app.example.test/api/me",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(f["severity"], "high")
        self.assertTrue(f["reproduced"])
        self.assertTrue(f["negative_control"])

    def test_negative_control_only_flag(self):
        adapter = load_adapter("nosqli_validator", self.temp.name)

        def urlopen(req, timeout=None):
            data = json.loads(req.data.decode()) if req.data else None
            if data and data.get("username") == "redlens_invalid_user":
                return make_response(401, {"error": "rejected"})
            raise ConnectionError("Unexpected request")

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "nosqli-validator", "--run", self.run_id,
                "--url", "https://app.example.test/api/login",
                "--negative-control-only",
            ]):
                self.assertEqual(adapter.main(), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*nosqli-negative*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["mode"], "negative-control-only")
        self.assertEqual(summary["verdict"], "tested-negative")


class RaceWorkflowTest(BaseAdapterTest):

    def _build_server(self, scenario: str):
        state = {"balance": 100.0}
        lock = {"n": 0}

        def urlopen(req, timeout=None):
            url = req.full_url
            method = req.get_method()

            if method == "GET" and url == "https://app.example.test/api/state":
                return make_response(200, state)

            if method == "POST" and url == "https://app.example.test/api/redeem":
                lock["n"] += 1
                if scenario == "safe":
                    # Atomic: each request sees the current balance.
                    state["balance"] -= 10
                elif scenario == "vulnerable":
                    # Race: all concurrent requests see the same balance.
                    # Only the first deducts in the final state.
                    if lock["n"] == 1:
                        state["balance"] -= 10
                return make_response(200, {"ok": True})

            if method == "POST" and url == "https://app.example.test/api/cleanup":
                return make_response(200, {"ok": True})

            raise ConnectionError(f"Unexpected request {method} {url}")

        return urlopen

    def _run_race(self, scenario: str):
        adapter = load_adapter("race_workflow", self.temp.name)
        urlopen = self._build_server(scenario)
        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "race-workflow", "race", "--run", self.run_id,
                "--url", "https://app.example.test/api/redeem",
                "--method", "POST",
                "--n", "3",
                "--state-url", "https://app.example.test/api/state",
                "--state-check", "balance",
                "--cleanup-url", "https://app.example.test/api/cleanup",
            ]):
                self.assertEqual(adapter.main(), 0)

        summaries = list((self.directory / "evidence" / "sanitized").glob("*race*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        return summary

    def test_login_race_returns_not_applicable(self):
        adapter = load_adapter("race_workflow", self.temp.name)
        with patch.object(sys, "argv", [
            "race-workflow", "race", "--run", self.run_id,
            "--url", "https://app.example.test/api/login",
            "--method", "POST",
            "--n", "3",
        ]):
            self.assertEqual(adapter.main(), 0)

        summaries = list((self.directory / "evidence" / "sanitized").glob("*race*"))
        self.assertFalse(summaries)
        events_path = self.directory / "logs" / "events.jsonl"
        self.assertTrue(events_path.is_file())
        events = events_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertTrue(any(json.loads(line).get("type") == "race.tested" for line in events))

    def test_race_without_invariant_violation_returns_tested_negative(self):
        summary = self._run_race("safe")
        self.assertEqual(summary["verdict"], "tested-negative")
        self.assertEqual(summary["success_count"], 3)
        self.assertEqual(summary["final_state"]["value"], 60)
        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 0)
        self.assertIn("negative_control", summary)
        self.assertEqual(summary["negative_control"]["baseline_state"]["value"], 90)

    def test_race_with_invariant_violation_returns_confirmed(self):
        summary = self._run_race("vulnerable")
        self.assertEqual(summary["verdict"], "confirmed")
        self.assertEqual(summary["success_count"], 3)
        self.assertEqual(summary["final_state"]["value"], 90)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(f["severity"], "high")
        self.assertTrue(f["reproduced"])
        self.assertTrue(f["negative_control"])


if __name__ == "__main__":
    unittest.main()
