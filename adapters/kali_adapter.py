#!/usr/bin/env python3
"""Allowlisted Kali adapter for scoped, low-impact web discovery."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTENT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
INTRUSIVE_TOOLS = {"nuclei", "ffuf", "feroxbuster", "arjun", "nikto"}
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402
from runtime_executor import exec_kali  # noqa: E402


def build_command(tool: str, url: str, max_rps: float) -> list[str]:
    rate = str(max(1, int(max_rps)))
    nuclei_templates = "/root/.local/nuclei-templates"
    ua = "Mozilla/5.0 (RedLens/1.0; +https://github.com/redlens) AppleWebKit/605.1.15"
    commands = {
        "whatweb": ["whatweb", "--no-errors", "-U", ua, url],
        "wafw00f": ["wafw00f", url],
        "httpx": ["httpx-toolkit", "-u", url, "-silent", "-rl", rate, "-H", f"User-Agent: {ua}"],
        "katana": ["katana", "-u", url, "-d", "2", "-rl", rate, "-silent", "-H", ua],
        "nuclei": [
            "nuclei", "-u", url, "-duc", "-t", nuclei_templates, "-rl", rate,
            "-c", "2", "-timeout", "10", "-no-color", "-H", f"User-Agent: {ua}",
        ],
        "sslscan": ["sslscan", "--no-colour", url],
        "ffuf": [
            "ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", CONTENT_WORDLIST,
            "-mc", "200,204,301,302,307,401,403", "-rate", rate, "-json",
            "-H", f"User-Agent: {ua}",
        ],
        "feroxbuster": [
            "feroxbuster", "--url", url, "--wordlist", CONTENT_WORDLIST,
            "--rate-limit", rate, "--json", "--silent", "-H", ua,
        ],
        "arjun": ["arjun", "-u", url, "--passive", "-H", f"User-Agent: {ua}"],
        "nikto": ["nikto", "-h", url, "-Format", "json", "-useragent", ua],
    }
    return commands[tool]


def main() -> int:
    parser = argparse.ArgumentParser(prog="kali-safe")
    parser.add_argument("--run", required=True)
    parser.add_argument("--tool", choices=(
        "whatweb", "wafw00f", "httpx", "katana", "nuclei", "sslscan", "ffuf",
        "feroxbuster", "arjun", "nikto",
    ),
                        required=True)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)
        redlensctl.scoped_url(directory, args.url)
        if args.tool in INTRUSIVE_TOOLS:
            try:
                approval = argparse.Namespace(
                    run=args.run, action="intrusive-scan", target=args.url
                )
                if hasattr(redlensctl, "command_check_risk"):
                    redlensctl.command_check_risk(approval)
            except redlensctl.RedLensError:
                pass
        scope = redlensctl.read_json(directory / "scope" / "scope.json")
        command = build_command(args.tool, args.url, scope["max_rps"])
        result = exec_kali(command, timeout=900)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_tool = re.sub(r"[^a-z0-9-]", "-", args.tool)
        output = directory / "evidence" / "raw" / f"{timestamp}-{safe_tool}.txt"
        output.write_text(
            f"$ {' '.join(command)}\n\nSTDOUT\n{result.stdout}\n\nSTDERR\n{result.stderr}",
            encoding="utf-8",
        )
        payload = {
            "ok": result.returncode == 0,
            "tool": args.tool,
            "url": args.url,
            "returncode": result.returncode,
            "evidence": str(output.relative_to(directory)),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if result.returncode == 0 else 1
    except (redlensctl.RedLensError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
