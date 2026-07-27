import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GraphQLTest(unittest.TestCase):
    def setUp(self):
        self.gql = load_module("graphql_adapter", ROOT / "adapters" / "graphql_adapter.py")
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**__import__("os").environ, "REDLENS_HOME": self.temp.name}

    def tearDown(self):
        self.temp.cleanup()

    def test_common_paths_defined(self):
        self.assertIn("/graphql", self.gql.COMMON_PATHS)
        self.assertIn("/api/graphql", self.gql.COMMON_PATHS)

    def test_probe_endpoint_returns_tuple(self):
        status, body = self.gql.probe_endpoint("http://localhost:9999/graphql", {})
        self.assertIsInstance(status, int)
        self.assertIsInstance(body, bytes)


class WebSocketTest(unittest.TestCase):
    def setUp(self):
        self.ws = load_module("websocket_adapter", ROOT / "adapters" / "websocket_adapter.py")

    def test_encode_decode_roundtrip(self):
        original = b"hello world"
        frame = self.ws.encode_ws_frame(original, masked=True)
        opcode, decoded = self.ws.decode_ws_frame(frame)
        self.assertEqual(decoded, original)
        self.assertEqual(opcode, 1)

    def test_encode_frame_unmasked(self):
        original = b"test"
        frame = self.ws.encode_ws_frame(original, masked=False, opcode=2)
        opcode, decoded = self.ws.decode_ws_frame(frame)
        self.assertEqual(decoded, original)


class GrpcTest(unittest.TestCase):
    def setUp(self):
        self.grpc_mod = load_module("grpc_adapter", ROOT / "adapters" / "grpc_adapter.py")

    def test_probe_grpc_http2_handles_connection_failure(self):
        result = self.grpc_mod.probe_grpc_http2("127.0.0.1", 65535, timeout=2)
        self.assertIn("ok", result)

    def test_test_endpoint_http(self):
        status, headers = self.grpc_mod.test_endpoint_http("http://127.0.0.1:65535/")
        self.assertIsInstance(status, int)
        self.assertIsInstance(headers, dict)


class FindingsManagerTest(unittest.TestCase):
    def setUp(self):
        self.fm = load_module("findings_manager", ROOT / "adapters" / "findings_manager.py")
        self.temp = tempfile.TemporaryDirectory()
        (Path(self.temp.name) / "findings").mkdir(parents=True)
        (Path(self.temp.name) / "logs").mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_required_fields_list(self):
        self.assertIn("cvss_score", self.fm.REQUIRED_FIELDS)
        self.assertIn("cwe", self.fm.REQUIRED_FIELDS)
        self.assertIn("owasp", self.fm.REQUIRED_FIELDS)
        self.assertIn("reproduction_steps", self.fm.REQUIRED_FIELDS)
        self.assertIn("retest_checklist", self.fm.REQUIRED_FIELDS)
        self.assertIn("chain_relations", self.fm.REQUIRED_FIELDS)

    def test_cwe_owasp_catalogs_complete(self):
        for cwe in ["CWE-79", "CWE-89", "CWE-78", "CWE-862", "CWE-918"]:
            self.assertIn(cwe, self.fm.CWE_CATALOG)
        for owasp in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
            self.assertIn(owasp, self.fm.OWASP_TOP_10)

    def test_category_to_cwe_owasp_mapping(self):
        self.assertEqual(self.fm.get_cwe_owasp_for_category("sqli"), ("CWE-89", "A03"))
        self.assertEqual(self.fm.get_cwe_owasp_for_category("xss"), ("CWE-79", "A03"))
        self.assertEqual(self.fm.get_cwe_owasp_for_category("ssrf"), ("CWE-918", "A10"))
        self.assertEqual(self.fm.get_cwe_owasp_for_category("bola"), ("CWE-639", "A01"))

    def test_compute_cvss_for_severity(self):
        score, vector = self.fm.compute_cvss_from_severity("critical")
        self.assertGreaterEqual(score, 9.0)
        self.assertLessEqual(score, 10.0)
        self.assertIn("CVSS", vector)

    def test_build_finding_observation_no_validation_required(self):
        finding = self.fm.build_finding(
            category="xss",
            title="Test XSS",
            severity="medium",
            asset="https://example.com",
            technical_impact="XSS allows script execution",
            business_impact="Session hijack risk",
            root_cause="No sanitization",
            reproduction_steps=["Step 1: Visit URL", "Step 2: See alert"],
            evidence=["evidence/sanitized/test.json"],
            remediation="Sanitize input",
            status="observation",
        )
        self.assertEqual(finding["category"], "xss")
        self.assertEqual(finding["cwe"], "CWE-79")
        self.assertEqual(finding["owasp"], "A03")
        self.assertGreater(finding["cvss_score"], 4.0)
        self.assertIn("cwe_name", finding)
        self.assertIn("retest_checklist", finding)

    def test_build_finding_high_requires_reproduction(self):
        with self.assertRaises(Exception):
            self.fm.build_finding(
                category="sqli",
                title="Critical SQLi",
                severity="critical",
                asset="https://example.com",
                technical_impact="Full DB compromise",
                business_impact="All user data exposed",
                root_cause="Concatenated SQL",
                reproduction_steps=[],
                evidence=["evidence/sanitized/test.json"],
                remediation="Use parameterized queries",
                status="confirmed",
                negative_control="Verified same query returns error on safe input",
                independent_validation="Verified with sqlmap",
            )

    def test_validate_finding_detects_missing_fields(self):
        finding = {"id": "test", "title": "x"}
        errors = self.fm.validate_finding(finding)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("severidade" in e.lower() or "severity" in e.lower() for e in errors))

    def test_validate_finding_critical_requires_validation(self):
        finding = self.fm.build_finding(
            category="bola",
            title="Test BOLA",
            severity="high",
            asset="https://example.com",
            technical_impact="Cross-user access",
            business_impact="Privacy violation",
            root_cause="Missing ownership check",
            reproduction_steps=["Step 1"],
            evidence=["evidence.json"],
            remediation="Add owner check",
            status="observation",
        )
        finding["status"] = "confirmed"
        finding["negative_control"] = ""
        finding["independent_validation"] = ""
        errors = self.fm.validate_finding(finding)
        self.assertGreater(len(errors), 0)

    def test_save_and_link_chain(self):
        finding1 = self.fm.build_finding(
            category="sqli",
            title="SQLi leads to user dump",
            severity="high",
            asset="https://example.com",
            technical_impact="DB compromise",
            business_impact="Data breach",
            root_cause="Input not sanitized",
            reproduction_steps=["Step 1"],
            evidence=["evidence/sanitized/sqli.json"],
            remediation="Use parameterized queries",
            negative_control="Tested safe input returns empty",
            independent_validation="Verified with sqlmap",
            status="confirmed",
        )
        finding2 = self.fm.build_finding(
            category="bola",
            title="BOLA via stolen user_id",
            severity="high",
            asset="https://example.com",
            technical_impact="Cross-user access",
            business_impact="Account takeover",
            root_cause="Weak session",
            reproduction_steps=["Step 1"],
            evidence=["evidence/sanitized/bola.json"],
            remediation="Rotate sessions",
            negative_control="Tested without stolen id denied",
            independent_validation="Manual reproduction",
            status="confirmed",
        )
        directory = Path(self.temp.name)
        self.fm.save_finding(directory, finding1)
        self.fm.save_finding(directory, finding2)
        self.fm.link_chain(directory, finding1["id"], finding2["id"])

        path1 = directory / "findings" / f"{finding1['id']}.json"
        saved = json.loads(path1.read_text(encoding="utf-8"))
        self.assertIn(finding2["id"], saved["chain_relations"])

    def test_generate_findings_report_groups_correctly(self):
        directory = Path(self.temp.name)
        for sev in ["low", "medium", "high"]:
            finding = self.fm.build_finding(
                category="xss",
                title=f"Test {sev}",
                severity=sev,
                asset="https://example.com",
                technical_impact="x",
                business_impact="x",
                root_cause="x",
                reproduction_steps=["x"],
                evidence=["x"],
                remediation="x",
            )
            self.fm.save_finding(directory, finding)

        report = self.fm.generate_findings_report(directory)
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["by_severity"]["low"], 1)
        self.assertEqual(report["by_severity"]["medium"], 1)
        self.assertEqual(report["by_severity"]["high"], 1)
        self.assertEqual(report["high_critical_count"], 1)
        self.assertIn("CWE-79", report["by_cwe"])
        self.assertIn("A03", report["by_owasp"])


class NewAdaptersCompileTest(unittest.TestCase):
    def test_all_new_adapters_compile(self):
        adapters = [
            "graphql_adapter.py",
            "websocket_adapter.py",
            "grpc_adapter.py",
            "findings_manager.py",
        ]
        for a in adapters:
            path = ROOT / "adapters" / a
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, f"{a} nao compila: {result.stderr}")


if __name__ == "__main__":
    unittest.main()