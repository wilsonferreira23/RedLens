import json
import subprocess
import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import health


class ToolVersionTest(unittest.TestCase):
    def _run(self, returncode, stdout, stderr):
        with patch("adapters.health.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=returncode, stdout=stdout, stderr=stderr
            )
            return health.tool_version("ffuf", container="kali-pentest")

    def test_broken_tool_returns_available_false(self):
        result = self._run(returncode=1, stdout="", stderr="not found")
        self.assertFalse(result["available"])
        self.assertIsNotNone(result["reason"])

    def test_traceback_in_output_is_marked_missing(self):
        result = self._run(returncode=0, stdout="Traceback (most recent call last):\n", stderr="")
        self.assertFalse(result["available"])
        self.assertIsNotNone(result["reason"])

    def test_clean_version_is_available(self):
        result = self._run(returncode=0, stdout="v1.0.0", stderr="")
        self.assertTrue(result["available"])
        self.assertEqual(result["version"], "v1.0.0")

    def test_tools_use_supported_smoke_commands(self):
        self.assertEqual(health.TOOL_VERSION_COMMANDS["arjun"], ["arjun", "-h"])
        self.assertEqual(health.TOOL_VERSION_COMMANDS["dalfox"], ["dalfox", "version"])
        self.assertEqual(health.TOOL_VERSION_COMMANDS["tplmap"], ["tplmap", "-h"])
        self.assertEqual(
            health.TOOL_VERSION_COMMANDS["schemathesis"],
            ["schemathesis", "--version"],
        )


class HealthMainTest(unittest.TestCase):
    def test_ok_false_when_mandatory_check_fails(self):
        with patch("adapters.health.docker_running", return_value=False):
            with patch("adapters.health.adata_status", return_value={"on_adata": True, "writable": True, "free_gb": 10.0}):
                with patch("adapters.health.container", return_value={"name": "kali-pentest", "ok": True, "status": "running"}):
                    with patch("adapters.health.cloakbrowser_navigation_check", return_value={"available": True, "degraded": False, "missing": False, "reason": "ok"}):
                        with patch("adapters.health.wrapper_check", return_value={"ok": True, "on_adata": True, "executable": True, "target": "/tmp/x"}):
                            captured = StringIO()
                            sys.stdout = captured
                            exit_code = health.main()
                            sys.stdout = sys.__stdout__
        output = json.loads(captured.getvalue())
        self.assertFalse(output["ok"])
        self.assertFalse(output["mandatory_ok"])
        self.assertEqual(exit_code, 2)
        self.assertIn("docker", output["buckets"]["missing"])

    def test_ok_false_when_required_tool_is_missing(self):
        def tool_result(name, container=None):
            return {
                "available": name != "tplmap",
                "version": "ok" if name != "tplmap" else None,
                "reason": None if name != "tplmap" else "missing",
            }

        with patch("adapters.health.docker_running", return_value=True):
            with patch("adapters.health.adata_status", return_value={"on_adata": True, "writable": True, "free_gb": 10.0}):
                with patch("adapters.health.container", return_value={"name": "kali-pentest", "ok": True, "status": "running"}):
                    with patch("adapters.health.tool_version", side_effect=tool_result):
                        with patch("adapters.health.cloakbrowser_navigation_check", return_value={"available": True, "degraded": False, "missing": False, "reason": "ok"}):
                            with patch("adapters.health.wrapper_check", return_value={"ok": True, "on_adata": True, "executable": True, "target": "/tmp/x"}):
                                captured = StringIO()
                                with patch("sys.stdout", captured):
                                    exit_code = health.main()

        output = json.loads(captured.getvalue())
        self.assertFalse(output["ok"])
        self.assertFalse(output["mandatory_ok"])
        self.assertEqual(exit_code, 2)
        self.assertIn("tplmap", output["buckets"]["missing"])


if __name__ == "__main__":
    unittest.main()
