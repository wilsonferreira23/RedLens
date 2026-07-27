import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class SemanticAuthzTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.positive = Path(self.temp.name) / "positive.json"
        self.negative = Path(self.temp.name) / "negative.json"
        self.before = Path(self.temp.name) / "before.json"
        self.after = Path(self.temp.name) / "after.json"

    def tearDown(self):
        self.temp.cleanup()

    def run_semantic(self, action, *args):
        result = subprocess.run(
            [sys.executable, str(ROOT / "adapters" / "semantic_authz.py"),
             action, *args],
            capture_output=True, text=True, timeout=30,
        )
        return json.loads(result.stdout)

    def test_detects_bola_with_different_owner(self):
        self.positive.write_text(json.dumps({
            "id": 1, "username": "victim", "owner_id": "victim-uuid", "email": "v@test.com", "is_admin": False
        }))
        self.negative.write_text(json.dumps({
            "id": 2, "username": "attacker", "owner_id": "attacker-uuid", "email": "a@test.com", "is_admin": True
        }))
        result = self.run_semantic("compare", "--positive", str(self.positive), "--negative", str(self.negative))
        self.assertTrue(result["semantic_leak"])
        self.assertFalse(result["owner_match"])
        self.assertFalse(result["permissions_match"])

    def test_same_resource_no_leak(self):
        body = {
            "id": 1, "username": "user1", "email": "u@test.com", "is_admin": False
        }
        self.positive.write_text(json.dumps(body))
        self.negative.write_text(json.dumps(body))
        result = self.run_semantic("compare", "--positive", str(self.positive), "--negative", str(self.negative))
        self.assertFalse(result["semantic_leak"])
        self.assertTrue(result["content_match"])

    def test_detects_sensitive_field_leak(self):
        self.positive.write_text(json.dumps({
            "id": 1, "username": "u", "password": "secret123", "api_key": "abc"
        }))
        self.negative.write_text(json.dumps({
            "id": 2, "username": "u2", "password": "secret456", "api_key": "xyz"
        }))
        result = self.run_semantic("compare", "--positive", str(self.positive), "--negative", str(self.negative))
        self.assertIn("password", result["sensitive_fields_positive"])
        self.assertIn("api_key", result["sensitive_fields_positive"])

    def test_persisted_diff_detects_new_fields(self):
        self.before.write_text(json.dumps({"id": 1, "username": "u"}))
        self.after.write_text(json.dumps({"id": 1, "username": "u", "is_admin": True}))
        result = self.run_semantic("persisted-diff", "--before", str(self.before), "--after", str(self.after))
        self.assertTrue(result["persisted_change"])
        self.assertIn("is_admin", result["new_fields"])
        self.assertTrue(result["schema_changed"])


class CallbackServerTest(unittest.TestCase):
    def test_callback_handler_methods_exist(self):
        spec = importlib.util.spec_from_file_location(
            "redlens_callback_server",
            ROOT / "runtime" / "redlens-callback-server.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertTrue(hasattr(mod.CallbackHandler, "do_GET"))
        self.assertTrue(hasattr(mod.CallbackHandler, "do_POST"))


class LoginAdapterTest(unittest.TestCase):
    def test_login_module_supports_all_modes(self):
        from adapters.login_adapter import SUPPORTED_MODES, jwt_decode
        self.assertIn("json", SUPPORTED_MODES)
        self.assertIn("form", SUPPORTED_MODES)
        self.assertIn("bearer", SUPPORTED_MODES)
        self.assertIn("apikey", SUPPORTED_MODES)
        self.assertIn("refresh", SUPPORTED_MODES)
        self.assertIn("oauth", SUPPORTED_MODES)
        self.assertIn("mfa", SUPPORTED_MODES)
        payload = jwt_decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        self.assertEqual(payload.get("sub"), "1234567890")


class RaceWorkflowTest(unittest.TestCase):
    def test_workflow_templates_defined(self):
        from adapters.race_workflow import WORKFLOW_TEMPLATES
        for name in ["skip-step", "replay-once", "change-tenant", "change-quantity", "coupon-reuse", "token-reuse"]:
            self.assertIn(name, WORKFLOW_TEMPLATES)


class ValidatorsCompileTest(unittest.TestCase):
    def test_all_validators_compile(self):
        validators = [
            "ssrf_callback_validator.py",
            "nosqli_validator.py",
            "xxe_validator.py",
            "race_workflow.py",
            "semantic_authz.py",
        ]
        for v in validators:
            path = ROOT / "adapters" / v
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, f"{v} nao compila: {result.stderr}")


class BenchmarkTest(unittest.TestCase):
    def test_targets_defined(self):
        from benchmarks.benchmark_runner import TARGETS
        self.assertIn("juice-shop", TARGETS)
        self.assertIn("vampi", TARGETS)
        self.assertIn("webgoat", TARGETS)
        self.assertIn("dvwa", TARGETS)

    def test_vampi_ground_truth_exists(self):
        from benchmarks.benchmark_runner import load_ground_truth, GROUND_TRUTH_DIR, TARGETS
        gt_file = GROUND_TRUTH_DIR / TARGETS["vampi"]["ground_truth_file"]
        self.assertTrue(gt_file.is_file())


class CapabilityRegistryTest(unittest.TestCase):
    def setUp(self):
        import adapters.capability_registry as reg
        reg.bootstrap()
        self.registry = reg.REGISTRY

    def test_no_placeholder_capabilities_remain(self):
        """Capabilities that only delegated to an external runner must be gone."""
        placeholders = {"browser", "replay", "authz", "ssti", "traversal", "ssrf"}
        for name in placeholders:
            self.assertNotIn(name, self.registry)

    def test_every_kept_capability_has_callable_runner(self):
        """Every kept capability must be registered with a callable runner."""
        kept = [
            "fingerprint",
            "content-discovery",
            "js-analysis",
            "parameter-discovery",
            "api-schema",
            "mutation",
            "sqli",
            "xss",
            "cmdi",
            "csrf",
            "mass-assignment",
            "authn",
            "session",
        ]
        for name in kept:
            self.assertIn(name, self.registry, f"capability {name} is not registered")
            cap = self.registry[name]
            self.assertTrue(callable(cap.runner), f"runner of {name} is not callable")

    def test_capabilities_metadata_includes_availability(self):
        from adapters.capability_registry import capabilities_metadata
        for meta in capabilities_metadata():
            self.assertIn("available", meta)
            self.assertTrue(meta["available"])


if __name__ == "__main__":
    unittest.main()