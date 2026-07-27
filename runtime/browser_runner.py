"""Browser execution seam used by the scoped browser adapter."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from redlens_config import load_config


class BrowserRunnerError(RuntimeError):
    """Raised when the configured browser runtime cannot execute."""


class BrowserRunner:
    def __init__(
        self,
        python: Path | None = None,
        cache: Path | None = None,
        worker: Path | None = None,
    ):
        config = load_config()
        self.python = Path(python or config.cloak_python)
        self.cache = Path(cache or config.cloak_cache)
        self.worker = Path(worker or config.workspace_dir / "redlens-browser-worker.py")

    def navigate(
        self,
        config_path: Path,
        output_dir: Path,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        if not self.python.is_file():
            raise BrowserRunnerError(f"CloakBrowser não encontrado: {self.python}")
        if not self.worker.is_file():
            raise BrowserRunnerError(f"Worker do navegador não encontrado: {self.worker}")
        env = os.environ.copy()
        env["CLOAKBROWSER_CACHE_DIR"] = str(self.cache)
        return subprocess.run(
            [
                str(self.python),
                str(self.worker),
                "--config",
                str(config_path),
                "--output",
                str(output_dir),
            ],
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
