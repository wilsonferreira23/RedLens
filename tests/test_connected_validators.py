#!/usr/bin/env python3
"""Connected validator tests: positive, negative and blocked cases."""

from __future__ import annotations

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


def load_adapter(name: str, home: str):
    os.environ["REDLENS_HOME"] = home
    if "redlensctl" in sys.modules:
        importlib.reload(sys.modules["redlensctl"])
    path = ROOT / "adapters" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


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

    def events(self):
        path = self.directory / "logs" / "events.jsonl"
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").strip().splitlines() if line.strip()]


class SSRFValidatorTest(BaseAdapterTest):
    def _mock_subprocess(self, hit: dict | None = None, reachable: bool = True):
        def run(cmd, **kwargs):
            class Result:
                pass
            r = Result()
            if "status" in cmd:
                r.returncode = 0
                r.stdout = json.dumps({"running": reachable})
                r.stderr = ""
            elif "hits" in cmd:
                r.returncode = 0
                r.stdout = json.dumps({"hits": [hit] if hit else []})
                r.stderr = ""
            else:
                r.returncode = 0
                r.stdout = "{}"
                r.stderr = ""
            return r
        return run

    def _run_ssrf(self, hit: dict | None = None, reachable: bool = True):
        adapter = load_adapter("ssrf_callback_validator", self.temp.name)

        def urlopen(req, timeout=None):
            return make_response(200, {"ok": True})

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(adapter.subprocess, "run", side_effect=self._mock_subprocess(hit, reachable)):
                with patch.object(sys, "argv", [
                    "ssrf-validator", "--run", self.run_id,
                    "--url", "https://app.example.test/api/fetch",
                    "--position", "query",
                    "--field", "url",
                    "--token", "testtoken",
                ]):
                    return adapter.main()

    def test_positive_callback_hit_confirms_ssrf(self):
        hit = {"token": "testtoken", "path": "/redlens-cb/testtoken"}
        self.assertEqual(self._run_ssrf(hit=hit), 0)

        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        f = json.loads(findings[0].read_text(encoding="utf-8"))
        self.assertEqual(f["status"], "confirmed")

        summaries = list((self.directory / "evidence" / "sanitized").glob("*ssrf*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "confirmed")

        raw = list((self.directory / "evidence" / "raw").glob("*ssrf*"))
        self.assertTrue(raw)

        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_negative_no_hit_returns_tested_negative(self):
        self.assertEqual(self._run_ssrf(hit=None, reachable=True), 0)
        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*ssrf*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "tested-negative")
        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_blocked_out_of_scope_url(self):
        adapter = load_adapter("ssrf_callback_validator", self.temp.name)
        with patch.object(sys, "argv", [
            "ssrf-validator", "--run", self.run_id,
            "--url", "http://evil.example.com/api/fetch",
            "--token", "tok",
        ]):
            self.assertEqual(adapter.main(), 2)
        self.assertFalse(list((self.directory / "findings").glob("*.json")))


class XXEValidatorTest(BaseAdapterTest):
    def _mock_subprocess(self, hit: dict | None = None, reachable: bool = True):
        def run(cmd, **kwargs):
            class Result:
                pass
            r = Result()
            if "status" in cmd:
                r.returncode = 0
                r.stdout = json.dumps({"running": reachable})
            elif "hits" in cmd:
                r.returncode = 0
                r.stdout = json.dumps({"hits": [hit] if hit else []})
            else:
                r.returncode = 0
                r.stdout = "{}"
            r.stderr = ""
            return r
        return run

    def _run_xxe(self, hit: dict | None = None, reachable: bool = True):
        adapter = load_adapter("xxe_validator", self.temp.name)

        def urlopen(req, timeout=None):
            return make_response(200, {"ok": True})

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(adapter.subprocess, "run", side_effect=self._mock_subprocess(hit, reachable)):
                with patch.object(sys, "argv", [
                    "xxe-validator", "--run", self.run_id,
                    "--url", "https://app.example.test/api/xml",
                    "--token", "xxetok",
                ]):
                    return adapter.main()

    def test_positive_callback_hit_confirms_xxe(self):
        hit = {"token": "xxetok", "path": "/redlens-cb/xxetok"}
        self.assertEqual(self._run_xxe(hit=hit), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*xxe*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "confirmed")
        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_negative_no_callback_returns_tested_negative(self):
        self.assertEqual(self._run_xxe(hit=None, reachable=True), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*xxe*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "tested-negative")
        raw = list((self.directory / "evidence" / "raw").glob("*xxe*"))
        self.assertTrue(raw)
        self.assertFalse(list((self.directory / "findings").glob("*.json")))

    def test_blocked_out_of_scope_url(self):
        adapter = load_adapter("xxe_validator", self.temp.name)
        with patch.object(sys, "argv", [
            "xxe-validator", "--run", self.run_id,
            "--url", "http://evil.example.com/api/xml",
        ]):
            self.assertEqual(adapter.main(), 2)


class NoSQLiValidatorTest(BaseAdapterTest):
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

    def test_positive_bypass_confirmed(self):
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
        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_negative_400_rejected(self):
        adapter = load_adapter("nosqli_validator", self.temp.name)
        urlopen = self._build_urlopen(payload_status=400)
        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "nosqli-validator", "--run", self.run_id,
                "--url", "https://app.example.test/api/login",
                "--protected-url", "https://app.example.test/api/me",
            ]):
                self.assertEqual(adapter.main(), 0)

        self.assertEqual(len(list((self.directory / "findings").glob("*.json"))), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*nosqli*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "tested-negative")
        raw = list((self.directory / "evidence" / "raw").glob("*nosqli*"))
        self.assertTrue(raw)

    def test_blocked_out_of_scope_url(self):
        adapter = load_adapter("nosqli_validator", self.temp.name)
        with patch.object(sys, "argv", [
            "nosqli-validator", "--run", self.run_id,
            "--url", "http://evil.example.com/api/login",
        ]):
            self.assertEqual(adapter.main(), 2)


class RaceWorkflowValidatorTest(BaseAdapterTest):
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
                    state["balance"] -= 10
                elif scenario == "vulnerable":
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
                return adapter.main()

    def test_positive_invariant_violation_confirmed(self):
        self.assertEqual(self._run_race("vulnerable"), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*race*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "confirmed")
        findings = list((self.directory / "findings").glob("*.json"))
        self.assertEqual(len(findings), 1)
        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_negative_safe_returns_tested_negative(self):
        self.assertEqual(self._run_race("safe"), 0)
        summaries = list((self.directory / "evidence" / "sanitized").glob("*race*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "tested-negative")
        self.assertIn("negative_control", summary)
        self.assertEqual(len(list((self.directory / "findings").glob("*.json"))), 0)

    def test_blocked_out_of_scope_url(self):
        adapter = load_adapter("race_workflow", self.temp.name)
        with patch.object(sys, "argv", [
            "race-workflow", "race", "--run", self.run_id,
            "--url", "http://evil.example.com/api/redeem",
        ]):
            self.assertEqual(adapter.main(), 2)


class LoginValidatorTest(BaseAdapterTest):
    def _write_creds(self, role: str, username: str, password: str):
        creds_dir = self.directory / "evidence" / "private" / "credentials"
        creds_dir.mkdir(parents=True, exist_ok=True)
        path = creds_dir / f"{role}.json"
        path.write_text(json.dumps({"username": username, "password": password}, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def test_positive_login_extracts_token_and_saves_session(self):
        adapter = load_adapter("login_adapter", self.temp.name)
        creds_path = self._write_creds("admin", "admin", "secret123")

        def urlopen(req, timeout=None):
            self.assertEqual(req.full_url, "https://app.example.test/api/login")
            return make_response(200, {"access_token": "jwt-token-value", "user_id": "u1"})

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "login-safe", "login", "--run", self.run_id,
                "--role", "admin",
                "--url", "https://app.example.test/api/login",
                "--mode", "json",
                "--credentials", str(creds_path.relative_to(self.directory)),
            ]):
                self.assertEqual(adapter.main(), 0)

        session_path = self.directory / "evidence" / "private" / "sessions" / "admin.json"
        self.assertTrue(session_path.is_file())
        session = json.loads(session_path.read_text(encoding="utf-8"))
        self.assertEqual(session["token"], "jwt-token-value")
        self.assertNotIn("password", session)

        summaries = list((self.directory / "evidence" / "sanitized").glob("*login*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertTrue(summary["token_extracted"])
        self.assertNotIn("password", json.dumps(summary))

        raw = list((self.directory / "evidence" / "raw").glob("*login*"))
        self.assertTrue(raw)
        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_negative_invalid_credentials_no_token(self):
        adapter = load_adapter("login_adapter", self.temp.name)
        creds_path = self._write_creds("user", "user", "wrong")

        def urlopen(req, timeout=None):
            return make_response(401, {"error": "unauthorized"})

        with patch.object(adapter.urllib.request, "urlopen", side_effect=urlopen):
            with patch.object(sys, "argv", [
                "login-safe", "login", "--run", self.run_id,
                "--role", "user",
                "--url", "https://app.example.test/api/login",
                "--mode", "json",
                "--credentials", str(creds_path.relative_to(self.directory)),
            ]):
                self.assertEqual(adapter.main(), 0)

        summary = json.loads(list((self.directory / "evidence" / "sanitized").glob("*login*"))[0].read_text(encoding="utf-8"))
        self.assertFalse(summary["token_extracted"])

    def test_blocked_out_of_scope_url(self):
        adapter = load_adapter("login_adapter", self.temp.name)
        creds_path = self._write_creds("user", "user", "wrong")
        with patch.object(sys, "argv", [
            "login-safe", "login", "--run", self.run_id,
            "--role", "user",
            "--url", "http://evil.example.com/api/login",
            "--mode", "json",
            "--credentials", str(creds_path.relative_to(self.directory)),
        ]):
            self.assertEqual(adapter.main(), 2)


class SemanticAuthzValidatorTest(BaseAdapterTest):
    def _write_bodies(self, positive: dict, negative: dict):
        pos_path = self.directory / "evidence" / "private" / "positive.json"
        neg_path = self.directory / "evidence" / "private" / "negative.json"
        pos_path.write_text(json.dumps(positive, ensure_ascii=False, indent=2), encoding="utf-8")
        neg_path.write_text(json.dumps(negative, ensure_ascii=False, indent=2), encoding="utf-8")
        return pos_path, neg_path

    def test_positive_different_owner_returns_confirmed(self):
        adapter = load_adapter("semantic_authz", self.temp.name)
        pos_path, neg_path = self._write_bodies(
            {"id": "1", "owner_id": "a", "tenant_id": "t1", "role": "admin"},
            {"id": "1", "owner_id": "b", "tenant_id": "t1", "role": "user"},
        )
        with patch.object(sys, "argv", [
            "semantic-authz", "compare", "--run", self.run_id,
            "--positive", str(pos_path),
            "--negative", str(neg_path),
        ]):
            self.assertEqual(adapter.main(), 0)

        summaries = list((self.directory / "evidence" / "sanitized").glob("*semantic-authz*"))
        self.assertTrue(summaries)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "confirmed")
        self.assertTrue(summary["diff"]["measurable_difference"])
        raw = list((self.directory / "evidence" / "raw").glob("*semantic-authz*"))
        self.assertTrue(raw)
        self.assertTrue(any(e.get("type") == "validator.finished" for e in self.events()))

    def test_negative_identical_returns_tested_negative(self):
        adapter = load_adapter("semantic_authz", self.temp.name)
        body = {"id": "1", "owner_id": "a", "tenant_id": "t1", "role": "user"}
        pos_path, neg_path = self._write_bodies(body, body)
        with patch.object(sys, "argv", [
            "semantic-authz", "compare", "--run", self.run_id,
            "--positive", str(pos_path),
            "--negative", str(neg_path),
        ]):
            self.assertEqual(adapter.main(), 0)

        summary = json.loads(list((self.directory / "evidence" / "sanitized").glob("*semantic-authz*"))[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["verdict"], "tested-negative")
        self.assertFalse(summary["diff"]["measurable_difference"])

    def test_blocked_missing_run(self):
        adapter = load_adapter("semantic_authz", self.temp.name)
        pos_path, neg_path = self._write_bodies({"a": 1}, {"a": 1})
        with patch.object(sys, "argv", [
            "semantic-authz", "compare", "--run", "run-nonexistent",
            "--positive", str(pos_path),
            "--negative", str(neg_path),
        ]):
            self.assertEqual(adapter.main(), 2)


class BinWrappersTest(unittest.TestCase):
    def _wrapper(self, name: str, adapter: str):
        path = ROOT / "bin" / name
        self.assertTrue(path.is_file(), f"wrapper missing: {path}")
        content = path.read_text()
        self.assertIn("REDLENS_HOME", content)
        self.assertIn(adapter, content)

    def test_ssrf_safe_wrapper(self):
        self._wrapper("ssrf-safe", "ssrf_callback_validator.py")

    def test_xxe_safe_wrapper(self):
        self._wrapper("xxe-safe", "xxe_validator.py")

    def test_nosqli_safe_wrapper(self):
        self._wrapper("nosqli-safe", "nosqli_validator.py")

    def test_race_workflow_safe_wrapper(self):
        self._wrapper("race-workflow-safe", "race_workflow.py")

    def test_semantic_authz_safe_wrapper(self):
        self._wrapper("semantic-authz-safe", "semantic_authz.py")

    def test_login_v2_safe_wrapper(self):
        self._wrapper("login-v2-safe", "login_adapter.py")


if __name__ == "__main__":
    unittest.main()
