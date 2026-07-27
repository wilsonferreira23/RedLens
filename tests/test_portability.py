import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from redlens_config import load_config
from engine import runtime_executor
from engine.run_store import CURRENT_SCHEMA_VERSION, RunStore
from runtime.browser_runner import BrowserRunner
from runtime.manifest import build_manifest


class PortabilityTest(unittest.TestCase):
    def test_paths_and_container_are_environment_configurable(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            env = {
                "REDLENS_HOME": str(root / "home"),
                "REDLENS_DATA_DIR": str(root / "data"),
                "REDLENS_RUNTIME_DIR": str(root / "runtime"),
                "REDLENS_CONTAINER": "kali-test",
            }
            with patch.dict(os.environ, env, clear=False):
                config = load_config()
            self.assertEqual(config.home, root / "home")
            self.assertEqual(config.data_dir, root / "data")
            self.assertEqual(config.runtime_dir, root / "runtime")
            self.assertEqual(config.container_name, "kali-test")
            self.assertEqual(config.backups_dir, root / "data" / "backups")

    def test_executor_owns_container_name(self):
        completed = subprocess.CompletedProcess([], 0, "ok", "")
        with patch.dict(os.environ, {"REDLENS_CONTAINER": "kali-test"}, clear=False):
            with patch("engine.runtime_executor.subprocess.run", return_value=completed) as run:
                result = runtime_executor.exec_kali(["whatweb", "--version"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(run.call_args.args[0][:3], ["docker", "exec", "kali-test"])

    def test_run_store_dry_run_does_not_modify_legacy_run(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run_dir = root / "runs" / "legacy"
            (run_dir / "state").mkdir(parents=True)
            (run_dir / "state" / "state.json").write_text('{"run_id":"legacy"}', encoding="utf-8")
            store = RunStore(root / "runs", root / "backups")
            result = store.migrate("legacy", dry_run=True)
            self.assertTrue(result["actions"])
            self.assertFalse((run_dir / "state" / "schema.json").exists())

            migrated = store.migrate("legacy")
            self.assertTrue(Path(migrated["backup"]).is_dir())
            state = store.read_json(run_dir / "state" / "state.json")
            self.assertEqual(state["schema_version"], CURRENT_SCHEMA_VERSION)
            self.assertTrue((run_dir / "state" / "schema.json").is_file())

    def test_browser_runner_uses_configured_backend(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            python = root / "python"
            worker = root / "worker.py"
            python.touch()
            worker.touch()
            runner = BrowserRunner(python=python, cache=root / "cache", worker=worker)
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch("runtime.browser_runner.subprocess.run", return_value=completed) as run:
                result = runner.navigate(root / "config.json", root / "output")
            self.assertEqual(result.returncode, 0)
            command = run.call_args.args[0]
            self.assertEqual(command[0], str(python))
            self.assertEqual(run.call_args.kwargs["env"]["CLOAKBROWSER_CACHE_DIR"], str(root / "cache"))

    def test_tool_lock_can_generate_manifest(self):
        lock = Path(__file__).parents[1] / "runtime" / "kali-image" / "tools.lock.json"
        manifest = build_manifest(lock)
        self.assertEqual(manifest["bomFormat"], "CycloneDX")
        self.assertGreaterEqual(len(manifest["components"]), 15)


if __name__ == "__main__":
    unittest.main()
