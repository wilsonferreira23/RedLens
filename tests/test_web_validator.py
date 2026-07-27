import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "adapters" / "web_validator.py"
SPEC = importlib.util.spec_from_file_location("web_validator", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WebValidatorTest(unittest.TestCase):
    def test_commands_are_fixed_and_do_not_use_shell(self):
        command = MODULE.command("cors", "https://example.test")
        self.assertEqual(command[0], "curl")
        self.assertIn("Origin: https://redlens.invalid", command)
        self.assertNotIn("sh", command)
        self.assertNotIn("-c", command)

    def test_cookie_value_is_redacted(self):
        parsed = MODULE.parse_headers(
            "HTTP/1.1 200 OK\r\nSet-Cookie: session=secret-value; HttpOnly\r\n"
        )
        self.assertEqual(parsed["set-cookie"], ["session=<redacted>; HttpOnly"])


if __name__ == "__main__":
    unittest.main()
