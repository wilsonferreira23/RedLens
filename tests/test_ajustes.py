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


class DecepticonCopyTest(unittest.TestCase):
    def setUp(self):
        self.da = load_module("decepticon_analysis", ROOT / "adapters" / "decepticon_analysis.py")
        self.temp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temp.name) / "run-test"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "findings").mkdir()
        (self.run_dir / "evidence" / "private" / "inputs").mkdir(parents=True)
        (self.run_dir / "evidence" / "sanitized").mkdir(parents=True)
        (self.run_dir / "state").mkdir()
        (self.run_dir / "scope").mkdir()
        (self.run_dir / "authorization").mkdir()
        import os
        os.environ["REDLENS_HOME"] = str(self.run_dir.parent)

    def tearDown(self):
        self.temp.cleanup()

    def test_copy_outside_input_to_private(self):
        external = Path(self.temp.name) / "external.txt"
        external.write_text("data")
        result = self.da.private_input(self.run_dir, str(external), allow_copy=True)
        self.assertTrue(result.is_file())
        self.assertIn("evidence/private/inputs", str(result))
        self.assertEqual(result.read_text(), "data")

    def test_input_already_in_private_works(self):
        internal = self.run_dir / "evidence" / "private" / "inputs" / "internal.txt"
        internal.write_text("data")
        result = self.da.private_input(self.run_dir, str(internal))
        self.assertEqual(result.resolve(), internal.resolve())

    def test_input_outside_without_copy_raises_with_help(self):
        external = Path(self.temp.name) / "external.txt"
        external.write_text("data")
        with self.assertRaises(Exception) as ctx:
            self.da.private_input(self.run_dir, str(external), allow_copy=False)
        self.assertIn("--copy", str(ctx.exception))


class KaliAdapterFixTest(unittest.TestCase):
    def test_kali_adapter_handles_missing_command_check_risk(self):
        spec = importlib.util.spec_from_file_location("kali_adapter", ROOT / "adapters" / "kali_adapter.py")
        mod = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(ROOT / "engine"))
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:
            self.fail(f"import fail: {exc}")

    def test_build_command_includes_user_agent(self):
        k = load_module("kali_adapter", ROOT / "adapters" / "kali_adapter.py")
        for tool in ["whatweb", "nuclei"]:
            cmd = k.build_command(tool, "https://example.com", 2.0)
            cmd_str = " ".join(cmd)
            self.assertTrue("User-Agent" in cmd_str or "RedLens" in cmd_str, f"{tool} missing User-Agent/RedLens")

    def test_nuclei_command_uses_local_templates(self):
        k = load_module("kali_adapter", ROOT / "adapters" / "kali_adapter.py")
        cmd = k.build_command("nuclei", "https://example.com", 2.0)
        self.assertIn("/root/.local/nuclei-templates", " ".join(cmd))
        self.assertIn("-duc", " ".join(cmd))


class WebSafeFixTest(unittest.TestCase):
    def setUp(self):
        self.wv = load_module("web_validator", ROOT / "adapters" / "web_validator.py")

    def test_command_includes_user_agent(self):
        cmd = self.wv.command("headers", "https://example.com")
        cmd_str = " ".join(cmd)
        self.assertIn("RedLens", cmd_str)
        self.assertIn("Accept", cmd_str)

    def test_command_cors_keeps_origin(self):
        cmd = self.wv.command("cors", "https://example.com")
        self.assertIn("redlens.invalid", " ".join(cmd))


class WordlistsTest(unittest.TestCase):
    def test_local_wordlist_exists(self):
        path = ROOT / "wordlists" / "common.txt"
        self.assertTrue(path.is_file(), f"wordlist missing: {path}")
        content = path.read_text()
        self.assertIn("admin", content)
        self.assertIn("api", content)


class HttpxLocalTest(unittest.TestCase):
    def test_httpx_installed(self):
        result = subprocess.run(
            ["httpx", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, f"httpx not working: {result.stderr}")
        self.assertTrue("Usage" in (result.stdout + result.stderr) or len(result.stdout) > 50)


class BinWrappersTest(unittest.TestCase):
    def test_bin_kali_safe_wrapper(self):
        path = ROOT / "bin" / "kali-safe"
        self.assertTrue(path.is_file())
        content = path.read_text()
        self.assertIn("REDLENS_HOME", content)
        self.assertIn("kali_adapter.py", content)

    def test_bin_web_safe_wrapper_uses_absolute_path(self):
        path = ROOT / "bin" / "web-safe"
        content = path.read_text()
        self.assertIn("REDLENS_HOME", content)
        self.assertIn("web_validator.py", content)

    def test_bin_api_safe_wrapper_uses_absolute_path(self):
        path = ROOT / "bin" / "api-safe"
        content = path.read_text()
        self.assertIn("REDLENS_HOME", content)
        self.assertIn("api_adapter.py", content)


if __name__ == "__main__":
    unittest.main()
