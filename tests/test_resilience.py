import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "engine" / "redlensctl.py"


class ResilienceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "REDLENS_HOME": self.temp.name}
        created = self.run_ctl(
            "init",
            "--target", "https://app.example.test",
            "--authorized")
        self.run_id = created["run_id"]
        self.directory = Path(created["directory"])

    def tearDown(self):
        self.temp.cleanup()

    def run_ctl(self, *args, ok=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )
        if ok and result.returncode != 0:
            self.fail(result.stderr)
        if not ok:
            self.assertNotEqual(result.returncode, 0)
            return json.loads(result.stderr)
        return json.loads(result.stdout)

    def test_transition_running_acquires_lock(self):
        self.run_ctl("transition", "--run", self.run_id, "--status", "running")
        lock = self.directory / "state" / ".lock"
        self.assertTrue(lock.is_file())
        data = json.loads(lock.read_text(encoding="utf-8"))
        self.assertIn("pid", data)

    def test_second_running_blocked_while_lock_valid(self):
        self.run_ctl("transition", "--run", self.run_id, "--status", "running")
        self.run_ctl("transition", "--run", self.run_id, "--status", "paused")
        # Simulate another live process holding the lock
        holder = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            lock = self.directory / "state" / ".lock"
            lock.write_text(
                json.dumps({"pid": holder.pid, "locked_at": self.run_ctl("status", "--run", self.run_id)["state"]["updated_at"]}),
                encoding="utf-8",
            )
            error = self.run_ctl(
                "transition", "--run", self.run_id, "--status", "running", ok=False
            )
            self.assertIn("bloqueada", error["error"])
        finally:
            holder.terminate()
            try:
                holder.wait(timeout=2)
            except subprocess.TimeoutExpired:
                holder.kill()

    def test_heartbeat_refreshes_state(self):
        self.run_ctl("transition", "--run", self.run_id, "--status", "running")
        before = self.run_ctl("status", "--run", self.run_id)["state"]["heartbeat_at"]
        time.sleep(0.1)
        self.run_ctl("heartbeat", "--run", self.run_id, "--next-action", "still alive")
        after = self.run_ctl("status", "--run", self.run_id)["state"]["heartbeat_at"]
        self.assertNotEqual(before, after)

    def test_resume_reactivates_interrupted_tasks(self):
        self.run_ctl("transition", "--run", self.run_id, "--status", "running")
        task = self.run_ctl(
            "add-task", "--run", self.run_id, "--kind", "inventory",
            "--title", "Map endpoints"
        )["task"]
        self.run_ctl(
            "update-task", "--run", self.run_id, "--task", task["id"],
            "--status", "running", "--summary", "started"
        )
        # Simulate crash: remove lock manually and keep task running
        (self.directory / "state" / ".lock").unlink()
        resumed = self.run_ctl("resume", "--run", self.run_id)
        self.assertEqual(resumed["status"], "running")
        self.assertIn(task["id"], resumed["reset_tasks"])
        task_after = json.loads(
            (self.directory / "tasks" / f"{task['id']}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(task_after["status"], "pending")

    def test_retry_limit_blocks_after_max_attempts(self):
        self.run_ctl("transition", "--run", self.run_id, "--status", "running")
        task = self.run_ctl(
            "add-task", "--run", self.run_id, "--kind", "inventory",
            "--title", "Flaky task"
        )["task"]
        for _ in range(3):
            self.run_ctl(
                "update-task", "--run", self.run_id, "--task", task["id"],
                "--status", "running", "--summary", "try"
            )
            self.run_ctl(
                "update-task", "--run", self.run_id, "--task", task["id"],
                "--status", "failed", "--summary", "fail"
            )
            self.run_ctl(
                "update-task", "--run", self.run_id, "--task", task["id"],
                "--status", "pending", "--summary", "retry"
            )
        error = self.run_ctl(
            "update-task", "--run", self.run_id, "--task", task["id"],
            "--status", "running", "--summary", "exceed", ok=False
        )
        self.assertIn("limite", error["error"])


if __name__ == "__main__":
    unittest.main()
