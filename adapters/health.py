#!/usr/bin/env python3
"""Read-only health check for the external RedLens runtime.

Verifies:
- ADATA root + writability + minimum free space
- Docker engine reachable
- All required containers running
- All required Kali tools present and returning a clean version string
- CloakBrowser can import, launch, navigate to a local probe, and close
- All wrappers resolvable and ADATA-bound
- Capability registry availability

Returns three buckets (available / degraded / missing) and fails closed
(exit 2) when any mandatory capability is missing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redlens_config import load_config  # noqa: E402


CONFIG = load_config()
CLOAK_PYTHON = CONFIG.cloak_python
CLOAK_CACHE = CONFIG.cloak_cache

REQUIRED_TOOLS = [
    "whatweb", "wafw00f", "httpx", "katana", "nuclei", "sslscan",
    "ffuf", "feroxbuster", "arjun", "nikto", "sqlmap", "commix",
    "dalfox", "tplmap", "schemathesis",
]

TOOL_VERSION_COMMANDS: dict[str, list[str]] = {
    "whatweb": ["whatweb", "--version"],
    "wafw00f": ["wafw00f", "--version"],
    "httpx": ["httpx", "-version"],
    "katana": ["katana", "-version"],
    "nuclei": ["nuclei", "-version"],
    "sslscan": ["sslscan", "--version"],
    "ffuf": ["ffuf", "-V"],
    "feroxbuster": ["feroxbuster", "--version"],
    "arjun": ["arjun", "-h"],
    "nikto": ["nikto", "-Version"],
    "sqlmap": ["sqlmap", "--version"],
    "commix": ["commix", "--version"],
    "dalfox": ["dalfox", "version"],
    "tplmap": ["tplmap", "-h"],
    "schemathesis": ["schemathesis", "--version"],
}

REQUIRED_WRAPPERS = [
    "redlensctl", "redlens-health", "redlens-preflight",
    "redlens-kali-safe", "redlens-decepticon-analyze",
    "redlens-api-safe", "redlens-web-safe",
    "redlens-mutate-safe",
    "redlens-sqlmap-safe", "redlens-xss-safe", "redlens-cmdi-safe",
    "redlens-csrf-safe", "redlens-massassign-safe",
    "redlens-login-safe", "redlens-plan-safe",
]

BROKEN_MARKERS = ("Traceback", "command not found", "No such file or directory")


def docker_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            text=True, capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def container(name: str | None = None) -> dict:
    name = name or load_config().container_name
    result = subprocess.run(
        ["docker", "inspect", name, "--format", "{{.State.Status}}"],
        text=True, capture_output=True, timeout=10,
    )
    return {
        "name": name,
        "ok": result.returncode == 0 and result.stdout.strip() == "running",
        "status": result.stdout.strip() or result.stderr.strip(),
    }


def _run_command(args: list[str], container: str | None = None) -> subprocess.CompletedProcess:
    if container:
        cmd = ["docker", "exec", container, *args]
    else:
        cmd = args
    return subprocess.run(
        cmd,
        text=True, capture_output=True, timeout=30,
    )


def _clean_version_output(text: str) -> str:
    """Return the first non-empty line of output, or empty string."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _is_clean(output: str) -> bool:
    return all(marker not in output for marker in BROKEN_MARKERS)


def tool_version(tool: str, container: str | None = None) -> dict:
    """Run the correct version command for a tool and verify it is usable.

    A tool is available only when it exits 0 and its combined stdout/stderr
    does not contain ``Traceback`` or ``Error``.
    """
    try:
        args = TOOL_VERSION_COMMANDS.get(tool)
        if not args:
            return {"available": False, "version": None, "reason": "unknown tool"}

        result = _run_command(args, container=container)

        # Kali sometimes ships the httpx binary as httpx-toolkit.
        if (result.returncode != 0 or not _is_clean(result.stdout + result.stderr)) and tool == "httpx":
            alt_args = ["httpx-toolkit" if a == "httpx" else a for a in args]
            result = _run_command(alt_args, container=container)

        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 and _is_clean(output):
            return {"available": True, "version": _clean_version_output(output), "reason": None}
        return {
            "available": False,
            "version": _clean_version_output(output) or None,
            "reason": f"exit {result.returncode}",
        }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return {"available": False, "version": None, "reason": str(exc)}


def wrapper_check(name: str) -> dict:
    configured = os.environ.get("REDLENS_WRAPPER_DIR")
    path = Path(configured).expanduser() / name if configured else None
    if path is None or not path.exists():
        resolved = shutil.which(name)
        path = Path(resolved) if resolved else Path(name)
    info = {"name": name, "ok": False, "on_adata": False, "executable": False, "target": None}
    if not path.exists():
        return info
    if not path.is_symlink():
        if path.is_file():
            info["target"] = str(path)
            info["executable"] = path.stat().st_mode & 0o111 != 0
            info["ok"] = info["executable"]
        return info
    target = str(path.resolve())
    info["target"] = target
    info["on_adata"] = target.startswith("/Volumes/ADATA SC735/")
    info["executable"] = path.stat().st_mode & 0o111 != 0
    info["ok"] = info["executable"] and (
        info["on_adata"] or not load_config().require_adata
    )
    return info


def adata_status() -> dict:
    config = load_config()
    info = {"on_adata": False, "root_exists": False, "writable": False, "free_gb": None}
    info["on_adata"] = str(config.data_dir).startswith("/Volumes/ADATA SC735/")
    info["root_exists"] = config.data_dir.exists()
    runs_dir = config.runs_dir
    runs_dir.mkdir(parents=True, exist_ok=True)
    if runs_dir.exists():
        info["writable"] = runs_dir.stat().st_mode & 0o200 != 0 or runs_dir.exists()
        try:
            test_file = runs_dir / ".health-write-test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()
            info["writable"] = True
        except OSError:
            info["writable"] = False
    try:
        usage = shutil.disk_usage(str(config.data_dir))
        info["free_gb"] = round(usage.free / (1024 ** 3), 2)
    except FileNotFoundError:
        info["free_gb"] = 0.0
    return info


_CLOAKBROWSER_PROBE_SCRIPT = r'''
import json, socket, threading, socketserver, http.server
try:
    from cloakbrowser import launch as launch_cloakbrowser
except Exception as exc:
    print(json.dumps({"missing": True, "reason": "cloakbrowser import failed: " + str(exc)[:120]}))
    raise SystemExit(0)

class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redlens-probe":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args):
        pass

def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

port = free_port()
server = socketserver.ThreadingTCPServer(("127.0.0.1", port), ProbeHandler)
thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
result = {"status": None, "available": False, "reason": None, "missing": False}
try:
    browser = launch_cloakbrowser(headless=True, humanize=False)
    try:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(10000)
        resp = page.goto("http://127.0.0.1:%d/redlens-probe" % port, wait_until='commit')
        page.wait_for_function('document.readyState == "complete"')
        result["status"] = resp.status if resp else None
        result["available"] = result["status"] == 200
        if not result["available"]:
            result["reason"] = "status %s" % result["status"]
        context.close()
    finally:
        browser.close()
except Exception as exc:
    result["reason"] = str(exc)[:120]
finally:
    server.shutdown()
    server.server_close()
print(json.dumps(result))
'''


def cloakbrowser_navigation_check(container: str | None = None) -> dict:
    """Verify CloakBrowser can import, launch, navigate to a local probe, and close."""
    if not container and not CLOAK_PYTHON.is_file():
        return {
            "available": False,
            "degraded": False,
            "missing": True,
            "reason": f"native CloakBrowser runtime missing: {CLOAK_PYTHON}",
        }
    try:
        command = (
            ["docker", "exec", container, "python3", "-c", _CLOAKBROWSER_PROBE_SCRIPT]
            if container
            else [str(CLOAK_PYTHON), "-c", _CLOAKBROWSER_PROBE_SCRIPT]
        )
        env = os.environ.copy()
        env["CLOAKBROWSER_CACHE_DIR"] = str(CLOAK_CACHE)
        result = subprocess.run(
            command, text=True, capture_output=True, timeout=90, env=env,
        )
        if result.returncode != 0:
            return {
                "available": False,
                "degraded": False,
                "missing": True,
                "reason": result.stderr.strip() or "browser probe exited non-zero",
            }
        last_line = (result.stdout or "").strip().splitlines()[-1]
        data = json.loads(last_line)
        if data.get("missing"):
            return {
                "available": False,
                "degraded": False,
                "missing": True,
                "reason": data.get("reason", "cloakbrowser missing"),
            }
        if data.get("available"):
            return {
                "available": True,
                "degraded": False,
                "missing": False,
                "reason": "navigation ok",
            }
        return {
            "available": False,
            "degraded": True,
            "missing": False,
            "reason": data.get("reason", "navigation failed"),
        }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "degraded": False,
            "missing": True,
            "reason": str(exc)[:120],
        }


def main() -> int:
    checks = {}
    config = load_config()

    adata = adata_status()
    checks["adata_root"] = adata.get("root_exists", adata["on_adata"])
    checks["adata_writable"] = adata["writable"]
    checks["adata_min_space_5gb"] = bool(adata["free_gb"] is not None and adata["free_gb"] >= 5.0)

    checks["docker_running"] = docker_running()

    kali_running = False
    kali_info = container(config.container_name)
    checks["kali_pentest_running"] = kali_info["ok"]
    kali_running = kali_info["ok"]

    tools: dict[str, dict] = {}
    for tool in REQUIRED_TOOLS:
        if kali_running:
            tools[tool] = tool_version(tool, container=config.container_name)
        else:
            tools[tool] = {"available": False, "version": "skipped", "reason": "kali not running"}
    checks["tools"] = tools

    cloak = cloakbrowser_navigation_check()
    checks["cloakbrowser_navigation"] = cloak

    wrappers: dict[str, dict] = {}
    for name in REQUIRED_WRAPPERS:
        wrappers[name] = wrapper_check(name)
    checks["wrappers"] = wrappers

    capability_registry = (config.home / "adapters" / "capability_registry.py").is_file()
    checks["capability_registry_present"] = capability_registry

    # Build the three health buckets.
    available: list[str] = []
    degraded: list[str] = []
    missing: list[str] = []

    if checks["docker_running"]:
        available.append("docker")
    else:
        missing.append("docker")

    if checks["adata_writable"]:
        available.append("adata-writable")
    else:
        missing.append("adata-writable")

    if checks["kali_pentest_running"]:
        available.append("kali-pentest")
    else:
        missing.append("kali-pentest")

    for tool, info in tools.items():
        if info.get("available"):
            available.append(tool)
        else:
            missing.append(tool)

    for wrapper, info in wrappers.items():
        if info["ok"]:
            available.append(wrapper)
        else:
            missing.append(wrapper)

    if cloak["available"]:
        available.append("cloakbrowser-navigation")
    elif cloak["degraded"]:
        degraded.append("cloakbrowser-navigation")
    else:
        missing.append("cloakbrowser-navigation")

    if capability_registry:
        available.append("capability-registry")
    else:
        missing.append("capability-registry")

    mandatory_ok = all([
        checks["adata_root"],
        (not config.require_adata or adata["on_adata"]),
        checks["docker_running"],
        checks["adata_writable"],
        bool(adata["free_gb"] is not None and adata["free_gb"] >= config.min_free_gb),
        checks["kali_pentest_running"],
        cloak["available"],
        all(info.get("available") for info in tools.values()),
        all(info["ok"] for info in wrappers.values()),
        capability_registry,
    ])

    ok = mandatory_ok

    output = {
        "ok": ok,
        "fail_closed": True,
        "mandatory_ok": mandatory_ok,
        "adata": adata,
        "containers": [kali_info],
        "checks": {
            "docker_running": checks["docker_running"],
            "kali_pentest_running": checks["kali_pentest_running"],
            "cloakbrowser_navigation": cloak,
            "capability_registry_present": capability_registry,
        },
        "tools": tools,
        "wrappers": {name: info["ok"] for name, info in wrappers.items()},
        "buckets": {
            "available": available,
            "degraded": degraded,
            "missing": missing,
        },
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
