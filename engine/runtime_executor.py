"""Single execution seam for commands inside the Kali runtime."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

from redlens_config import load_config


def exec_kali(
    args: Sequence[str],
    *,
    timeout: float = 900,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Run a vector command in the configured container.

    Callers provide already-validated argv tokens. The executor owns the
    container name and Docker invocation so adapters do not duplicate it.
    """
    command = ["docker", "exec", load_config().container_name, *map(str, args)]
    return subprocess.run(
        command,
        text=text,
        capture_output=capture_output,
        timeout=timeout,
    )


def container_status() -> subprocess.CompletedProcess:
    config = load_config()
    return subprocess.run(
        ["docker", "inspect", config.container_name, "--format", "{{.State.Status}}"],
        text=True,
        capture_output=True,
        timeout=10,
    )


def docker_compose(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    config = load_config()
    return subprocess.run(
        ["docker", "compose", "-f", str(config.compose_file), *args],
        text=True,
        capture_output=True,
        timeout=timeout,
    )
