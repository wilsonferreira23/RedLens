import base64
import importlib.util
import json
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "adapters" / "decepticon_analysis.py"
SPEC = importlib.util.spec_from_file_location("decepticon_analysis", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class DecepticonAnalysisTest(unittest.TestCase):
    def test_jwt_analysis_is_offline_and_flags_missing_expiry(self):
        jwt, _, _ = MODULE.analyzers()
        token = f"{segment({'alg': 'HS256', 'typ': 'JWT'})}.{segment({'sub': 'test-user'})}.AA"
        parsed = jwt.parse_token(token)
        self.assertEqual(parsed.claims.sub, "test-user")
        self.assertIn("no exp claim", " ".join(parsed.findings))

    def test_cookie_output_can_be_sanitized(self):
        _, session, _ = MODULE.analyzers()
        parsed = session.analyze_cookie("sessionid", "short")
        output = parsed.to_dict()
        output.pop("value", None)
        self.assertNotIn("value", output)
        self.assertEqual(output["framework"], "Django")

    def test_jwt_weak_secret_is_cracked_offline(self):
        jwt, _, _ = MODULE.analyzers()
        token = jwt.forge_token({"sub": "test-user"}, alg="HS256", secret="secret")
        parsed = jwt.parse_token(token)
        cracked = jwt.crack_hs_secret(parsed, list(jwt.DEFAULT_WEAK_SECRETS))
        self.assertEqual(cracked, "secret")


if __name__ == "__main__":
    unittest.main()
