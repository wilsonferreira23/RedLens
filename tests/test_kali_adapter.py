import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "adapters" / "kali_adapter.py"
SPEC = importlib.util.spec_from_file_location("kali_adapter", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class KaliAdapterTest(unittest.TestCase):
    def test_commands_are_fixed_argument_lists(self):
        command = MODULE.build_command("katana", "https://example.test", 2)
        self.assertEqual(command[0], "katana")
        self.assertIn("https://example.test", command)
        self.assertNotIn("sh", command)
        self.assertNotIn("-c", command)

    def test_nuclei_has_rate_and_concurrency_limits(self):
        command = MODULE.build_command("nuclei", "https://example.test", 3)
        self.assertEqual(command[0], "nuclei")
        self.assertEqual(command[command.index("-rl") + 1], "3")
        self.assertEqual(command[command.index("-c") + 1], "2")

    def test_content_discovery_uses_fixed_wordlist_and_rate(self):
        command = MODULE.build_command("ffuf", "https://example.test", 4)
        self.assertEqual(command[0], "ffuf")
        self.assertTrue(command[command.index("-w") + 1].startswith("/usr/share/"))
        self.assertEqual(command[command.index("-rate") + 1], "4")
        self.assertNotIn("sh", command)


if __name__ == "__main__":
    unittest.main()
