#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "redlens" / "SKILL.md"
AGENT = ROOT / "opencode" / "agents" / "redlens.md"
ASSESSMENT_MODES = ROOT / "skills" / "redlens" / "references" / "playbooks" / "assessment-modes.md"
PRO_REPORT = ROOT / "skills" / "redlens" / "references" / "reporting" / "professional-report-standard.md"
REQUIRED_FILES = [
    ROOT / "skills" / "redlens" / "references" / "strategy" / "operator-brain.md",
    ROOT / "skills" / "redlens" / "references" / "strategy" / "attack-chain-analysis.md",
    ROOT / "skills" / "redlens" / "references" / "strategy" / "coverage-gates.md",
    ROOT / "skills" / "redlens" / "references" / "environment" / "state-schema.md",
    PRO_REPORT,
    ROOT / "skills" / "redlens" / "references" / "reporting" / "finding-schema.md",
    ROOT / "scripts" / "redlens_init_state.py",
    ROOT / "scripts" / "redlens_record_finding.py",
    ROOT / "scripts" / "redlens_add_evidence.py",
    ROOT / "scripts" / "redlens_report_skeleton.py",
]
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
LINK_RE = re.compile(r"`(references/[^`]+)`|\((references/[^)]+)\)")
FORBIDDEN_DEFAULTS = [
    "apt-get upgrade -y",
    "always exploit",
    "scan everything",
    "ignore scope",
    "no authorization",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        fail(f"{path} must start with YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end == -1:
        fail(f"{path} must close YAML frontmatter")
    raw = text[4:end]
    data: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or line.startswith(" ") or line.startswith("  "):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip().strip("'\"")
    return data, text[end + 5 :]


def validate_skill() -> None:
    if not SKILL.exists():
        fail(f"missing {SKILL}")
    meta, body = frontmatter(SKILL)
    name = meta.get("name", "")
    description = meta.get("description", "")
    if name != "redlens":
        fail("skill name must be redlens")
    if not NAME_RE.match(name):
        fail("skill name must match lowercase hyphen format")
    if not (1 <= len(description) <= 1024):
        fail("skill description must be 1-1024 characters")
    if "RedLens" not in description:
        fail("skill description must include the public display name RedLens")
    if len(body.splitlines()) > 500:
        fail("SKILL.md body must stay under 500 lines")
    text = SKILL.read_text(encoding="utf-8")
    text_lower = text.lower()
    if "references/playbooks/assessment-modes.md" not in text:
        fail("SKILL.md must link to assessment-modes.md")
    if "references/web/tools/cloakbrowser.md" not in text:
        fail("SKILL.md must link to cloakbrowser.md")
    if "CloakBrowser" not in text:
        fail("SKILL.md must mention CloakBrowser")
    for required_ref in (
        "operator-brain.md",
        "attack-chain-analysis.md",
        "coverage-gates.md",
        "professional-report-standard.md",
    ):
        if required_ref not in text:
            fail(f"SKILL.md must link to {required_ref}")
    for mode in ("quick", "standard", "deep"):
        if mode not in text_lower:
            fail(f"SKILL.md must mention assessment mode: {mode}")
    for phrase in FORBIDDEN_DEFAULTS:
        if phrase in text_lower:
            fail(f"forbidden unsafe default phrase: {phrase}")
    for match in LINK_RE.finditer(text):
        rel = match.group(1) or match.group(2)
        linked = SKILL.parent / rel
        if not linked.exists():
            fail(f"broken reference link: {rel}")


def validate_assessment_modes() -> None:
    if not ASSESSMENT_MODES.exists():
        fail(f"missing {ASSESSMENT_MODES}")
    text = ASSESSMENT_MODES.read_text(encoding="utf-8")
    text_lower = text.lower()
    required_phrases = [
        "`quick`",
        "`standard`",
        "`deep`",
        "mandatory coverage",
        "escalation triggers",
        "do not say \"secure\"",
    ]
    for phrase in required_phrases:
        if phrase not in text_lower:
            fail(f"assessment-modes.md missing required phrase: {phrase}")


def validate_required_files() -> None:
    for path in REQUIRED_FILES:
        if not path.exists():
            fail(f"missing required RedLens professional file: {path}")


def validate_professional_report_standard() -> None:
    text = PRO_REPORT.read_text(encoding="utf-8").lower()
    for phrase in ("artifact", "redaction", "retest", "executive summary", "attack chain"):
        if phrase not in text:
            fail(f"professional-report-standard.md missing required phrase: {phrase}")


def validate_agent() -> None:
    if not AGENT.exists():
        fail(f"missing {AGENT}")
    meta, body = frontmatter(AGENT)
    if meta.get("mode") != "subagent":
        fail("OpenCode agent mode must be subagent")
    if "redlens" not in body:
        fail("OpenCode agent must instruct usage of redlens skill")
    if "RedLens" not in body:
        fail("OpenCode agent must include the public display name RedLens")
    body_lower = body.lower()
    for mode in ("quick", "standard", "deep"):
        if mode not in body_lower:
            fail(f"OpenCode agent must mention assessment mode: {mode}")
    if "standard" not in body_lower or "default" not in body_lower:
        fail("OpenCode agent must define standard as the default mode")


def main() -> None:
    validate_required_files()
    validate_skill()
    validate_assessment_modes()
    validate_professional_report_standard()
    validate_agent()
    print("OK: RedLens skill package is valid")


if __name__ == "__main__":
    main()
