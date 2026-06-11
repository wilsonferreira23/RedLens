# RedLens Open Source Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the existing `kali-pentest` OpenCode agent/skill as the open source `RedLens` cross-agent skill that installs cleanly into Codex, Claude Code, and OpenCode, then publish it to the user's GitHub.

**Architecture:** Keep one canonical Agent Skills-compatible skill at `skills/redlens/SKILL.md`, with detailed workflows in `skills/redlens/references/`. Add adapter artifacts only where needed: `opencode/agents/redlens.md` for OpenCode subagent behavior and `scripts/install.sh` to copy the canonical skill into each supported tool's global skill directory. Validate the package with deterministic Python checks instead of relying on manual review.

**Tech Stack:** Markdown Agent Skills format, POSIX shell install script, Python 3 stdlib validation, Git/GitHub CLI.

---

## Current Inputs

- Existing OpenCode agent source: `/Users/will/.config/opencode/agents/kali-pentest.md`
- Existing OpenCode skill source: `/Users/will/.config/opencode/skills/kali-pentest/SKILL.md`
- Existing references source: `/Users/will/.config/opencode/skills/kali-pentest/references/`
- Target repository: `/Users/will/Documents/RedLens`
- Current branch: `main`
- Current remote: none configured at planning time

## Compatibility Targets

- Codex: install canonical folder to `~/.codex/skills/redlens/`.
- Claude Code: install canonical folder to `~/.claude/skills/redlens/`; Claude Code invokes it as `/redlens` because the directory name defines the command.
- OpenCode skill: install canonical folder to `~/.config/opencode/skills/redlens/`; OpenCode also discovers `.claude/skills` and `.agents/skills`, but use its native path for clarity.
- OpenCode agent: install `opencode/agents/redlens.md` to `~/.config/opencode/agents/redlens.md`.

## File Structure

- Create `skills/redlens/SKILL.md`: canonical concise skill, under 500 lines, with strict authorization, scope, risk-gate, environment selection, playbook routing, and reporting rules.
- Copy `skills/redlens/references/`: existing reference tree from OpenCode, preserving environment, playbook, and tool-specific docs.
- Create `opencode/agents/redlens.md`: OpenCode subagent wrapper with frontmatter and a short prompt that instructs the agent to load/use `redlens` skill.
- Create `scripts/install.sh`: copies/syncs skill and OpenCode agent to Codex, Claude Code, and OpenCode global directories.
- Create `scripts/validate_skill.py`: validates frontmatter, name regex, description length, required files, internal links, and dangerous default language.
- Create `README.md`: public installation and usage guide.
- Create `LICENSE`: MIT license unless the user asks for another license before execution.
- Create `.gitignore`: ignore OS files, Python caches, temporary validation output, and local pentest state.

---

### Task 1: Create Release Branch and Inventory Source Files

**Files:**
- Read: `/Users/will/.config/opencode/agents/kali-pentest.md`
- Read: `/Users/will/.config/opencode/skills/kali-pentest/SKILL.md`
- Read: `/Users/will/.config/opencode/skills/kali-pentest/references/`

- [ ] **Step 1: Create a working branch**

Run:

```bash
git switch -c codex/package-redlens-skill
```

Expected: branch `codex/package-redlens-skill` is active.

- [ ] **Step 2: Inventory source sizes**

Run:

```bash
wc -l /Users/will/.config/opencode/agents/kali-pentest.md /Users/will/.config/opencode/skills/kali-pentest/SKILL.md
find /Users/will/.config/opencode/skills/kali-pentest/references -type f | sort > /tmp/redlens-reference-files.txt
wc -l /tmp/redlens-reference-files.txt
```

Expected: confirms the source agent, source skill, and reference file count before copying.

- [ ] **Step 3: Commit no files yet**

Run:

```bash
git status --short
```

Expected: only the plan file is currently untracked or modified if this plan has not yet been committed.

---

### Task 2: Build the Canonical Skill Package

**Files:**
- Create: `skills/redlens/SKILL.md`
- Create/Copy: `skills/redlens/references/**`

- [ ] **Step 1: Copy existing reference tree**

Run:

```bash
mkdir -p skills/redlens
cp -R /Users/will/.config/opencode/skills/redlens/references skills/redlens/
```

Expected: `skills/redlens/references/` contains the current reference files.

- [ ] **Step 2: Write canonical `SKILL.md`**

Create `skills/redlens/SKILL.md` with this structure:

```markdown
---
name: redlens
description: Execute authorized Kali Linux penetration testing workflows with strict scope, risk gates, evidence capture, and reporting. Use for approved security assessments involving recon, web/API testing, network enumeration, vulnerability validation, password audits, cloud-native checks, wireless, forensics, or post-exploitation planning.
license: MIT
compatibility: codex, claude-code, opencode, agent-skills
metadata:
  category: security
  audience: authorized-security-testers
  risk: high
---

# RedLens

## Non-Negotiable Safety Rules

1. Confirm explicit authorization before scanning, probing, exploitation, brute forcing, credential testing, or post-exploitation.
2. Treat scope as binding: hosts, domains, ports, accounts, time windows, and allowed techniques are limits, not suggestions.
3. Ask for a second explicit approval before high-risk actions: exploitation, brute forcing, credential spraying, phishing, NTLM relay, wireless attacks, persistence, data exfiltration, destructive checks, DoS-like checks, or intrusive scanners.
4. Do not attack third-party, critical infrastructure, production systems, or accounts outside the authorized scope.
5. Prefer evidence-preserving, minimally invasive validation. Stop when impact is proven enough to report.

## Start Every Assessment

1. Identify target type: URL, domain, IP, CIDR, repository, mobile app, wireless SSID, artifact, or account set.
2. Confirm authorization, scope, constraints, test type, rate limits, lockout policy, and reporting format.
3. Select execution environment:
   - Local Kali: use direct commands.
   - SSH Kali: use `ssh` and `scp`.
   - Docker Kali: use persistent `redlens` container.
4. Create state directory: `/tmp/redlens-state/<safe-target-name>/`.
5. Record scope, approvals, commands, evidence paths, findings, and deferred actions in state files.

## Environment References

- Local mode: `references/environment/local-mode.md`
- SSH/server mode: `references/environment/server-mode.md`
- Docker mode: `references/environment/docker-mode.md`
- Persistent Docker container: `references/environment/docker-mode-persistent-container.md`
- Docker networking: `references/environment/docker-mode-networking.md`
- State files: `references/environment/state-files.md`

## Playbook Routing

Read `references/playbooks/README.md`, then load only the relevant playbook:

- Web application: `references/playbooks/web-application.md`
- API security: `references/playbooks/api-security.md`
- External attack surface: `references/playbooks/external-attack-surface.md`
- Internal network: `references/playbooks/internal-network.md`
- Active Directory: `references/playbooks/active-directory.md`
- Cloud-native: `references/playbooks/cloud-native-assessment.md`
- Mobile app: `references/playbooks/mobile-application.md`
- Wireless: `references/playbooks/wireless-assessment.md`
- Source code audit: `references/playbooks/source-code-audit.md`
- Forensics triage: `references/playbooks/forensics-triage.md`
- Password audit: `references/playbooks/password-audit.md`
- Post-exploitation: `references/playbooks/post-exploitation.md`
- Reporting: `references/playbooks/reporting-workflow.md`

## Operating Loop

1. Plan the next safe action from the selected playbook.
2. Run the minimum command needed for that step in the selected environment.
3. Save raw output to a file instead of flooding context.
4. Extract only relevant evidence into the state directory.
5. Update findings with severity, affected asset, reproduction steps, impact, evidence, and remediation.
6. Reassess risk before escalating technique or intensity.

## Reporting

Produce an executive summary and technical report with:

- Scope and authorization summary.
- Methodology and constraints.
- Confirmed findings only, separated from observations.
- Evidence references and reproduction steps.
- Business impact.
- Remediation guidance.
- Retest checklist.

Use `references/playbooks/reporting-workflow.md` for structure.
```

Expected: the canonical skill uses only frontmatter fields understood by OpenCode and compatible with Agent Skills-style consumers.

- [ ] **Step 3: Remove unsafe defaults from copied references**

Run:

```bash
rg -n "apt-get upgrade -y|NUNCA|hydra|brute|DoS|dos|phishing|exfiltration|persistence" skills/redlens
```

Expected: high-risk terms are present only as gated actions or references, never as automatic default execution.

- [ ] **Step 4: Commit canonical skill**

Run:

```bash
git add skills/redlens
git commit -m "feat: add portable redlens skill"
```

Expected: first implementation commit created.

---

### Task 3: Add OpenCode Agent Adapter

**Files:**
- Create: `opencode/agents/redlens.md`

- [ ] **Step 1: Create OpenCode agent file**

Write `opencode/agents/redlens.md`:

```markdown
---
description: Authorized Kali Linux penetration testing subagent. Use for approved black-box, gray-box, network, web, API, cloud, wireless, forensics, and reporting tasks that need the redlens skill.
mode: subagent
color: '#FF0000'
permission:
  bash: allow
  edit: allow
  read: allow
  glob: allow
  grep: allow
  task: allow
  webfetch: allow
  websearch: allow
---

You are a senior penetration testing operator working only on explicitly authorized scopes.

Before taking action, load and follow the `redlens` skill. Treat its authorization, scope, risk-gate, environment, evidence, and reporting rules as controlling instructions.

If the user's target, authorization, or allowed techniques are unclear, ask for clarification before scanning or probing.
```

Expected: OpenCode can install this as `~/.config/opencode/agents/redlens.md`; the file name defines the agent name.

- [ ] **Step 2: Commit OpenCode adapter**

Run:

```bash
git add opencode/agents/redlens.md
git commit -m "feat: add opencode redlens agent"
```

Expected: adapter commit created.

---

### Task 4: Add Installer

**Files:**
- Create: `scripts/install.sh`

- [ ] **Step 1: Write installer script**

Create `scripts/install.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="$ROOT_DIR/skills/redlens"
AGENT_SRC="$ROOT_DIR/opencode/agents/redlens.md"

install_skill() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  rm -rf "$dest"
  cp -R "$SKILL_SRC" "$dest"
  echo "installed skill: $dest"
}

install_file() {
  local src="$1"
  local dest="$2"
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  echo "installed file: $dest"
}

if [[ ! -f "$SKILL_SRC/SKILL.md" ]]; then
  echo "missing skill source: $SKILL_SRC/SKILL.md" >&2
  exit 1
fi

install_skill "${CODEX_HOME:-$HOME/.codex}/skills/redlens"
install_skill "$HOME/.claude/skills/redlens"
install_skill "$HOME/.config/opencode/skills/redlens"

if [[ -f "$AGENT_SRC" ]]; then
  install_file "$AGENT_SRC" "$HOME/.config/opencode/agents/redlens.md"
fi

echo "redlens installed for Codex, Claude Code, and OpenCode"
```

Expected: a single command installs the skill into all supported local tools.

- [ ] **Step 2: Make script executable**

Run:

```bash
chmod +x scripts/install.sh
```

Expected: `scripts/install.sh` is executable.

- [ ] **Step 3: Commit installer**

Run:

```bash
git add scripts/install.sh
git commit -m "feat: add cross-agent installer"
```

Expected: installer commit created.

---

### Task 5: Add Deterministic Validation

**Files:**
- Create: `scripts/validate_skill.py`

- [ ] **Step 1: Write validator**

Create `scripts/validate_skill.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "redlens" / "SKILL.md"
AGENT = ROOT / "opencode" / "agents" / "redlens.md"
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\((references/[^)]+)\)")
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
    if len(body.splitlines()) > 500:
        fail("SKILL.md body must stay under 500 lines")
    text_lower = SKILL.read_text(encoding="utf-8").lower()
    for phrase in FORBIDDEN_DEFAULTS:
        if phrase in text_lower:
            fail(f"forbidden unsafe default phrase: {phrase}")
    for match in LINK_RE.finditer(SKILL.read_text(encoding="utf-8")):
        linked = SKILL.parent / match.group(1)
        if not linked.exists():
            fail(f"broken reference link: {match.group(1)}")


def validate_agent() -> None:
    if not AGENT.exists():
        fail(f"missing {AGENT}")
    meta, body = frontmatter(AGENT)
    if meta.get("mode") != "subagent":
        fail("OpenCode agent mode must be subagent")
    if "redlens" not in body:
        fail("OpenCode agent must instruct usage of redlens skill")


def main() -> None:
    validate_skill()
    validate_agent()
    print("OK: redlens skill package is valid")


if __name__ == "__main__":
    main()
```

Expected: validator is stdlib-only and can run on a clean machine.

- [ ] **Step 2: Run validator**

Run:

```bash
python3 scripts/validate_skill.py
```

Expected: `OK: redlens skill package is valid`.

- [ ] **Step 3: Commit validator**

Run:

```bash
git add scripts/validate_skill.py
git commit -m "test: validate redlens skill package"
```

Expected: validation commit created.

---

### Task 6: Add Open Source Repository Metadata

**Files:**
- Create: `README.md`
- Create: `LICENSE`
- Create: `.gitignore`

- [ ] **Step 1: Write README**

Create `README.md`:

```markdown
# redlens

RedLens portable Agent Skill for authorized Kali Linux penetration testing workflows across Codex, Claude Code, and OpenCode.

## What it does

- Guides authorized security assessments with explicit scope and risk gates.
- Supports Kali via local shell, SSH, or persistent Docker container.
- Routes work to focused playbooks for web, API, network, cloud-native, wireless, forensics, password audits, post-exploitation planning, and reporting.
- Keeps detailed tool notes in references so agents load only what they need.

## Safety

Use this skill only for systems you are authorized to test. High-risk actions require explicit approval before execution.

## Install

```bash
git clone https://github.com/<your-github-user>/redlens.git
cd redlens
./scripts/install.sh
```

The installer copies the skill to:

- `~/.codex/skills/redlens`
- `~/.claude/skills/redlens`
- `~/.config/opencode/skills/redlens`
- `~/.config/opencode/agents/redlens.md`

## Use

Codex and Claude Code:

```text
Use the redlens skill for an authorized assessment of <target>.
```

Claude Code direct command:

```text
/redlens authorized assessment of <target>
```

OpenCode:

```text
@redlens authorized assessment of <target>
```

## Validate

```bash
python3 scripts/validate_skill.py
```

## License

MIT
```

After repository creation, replace `<your-github-user>` with the detected GitHub login from `gh api user --jq .login`.

- [ ] **Step 2: Write MIT license**

Run:

```bash
YEAR="$(date +%Y)"
OWNER="$(gh api user --jq .name 2>/dev/null || gh api user --jq .login 2>/dev/null || printf 'Will')"
cat > LICENSE <<EOF
MIT License

Copyright (c) $YEAR $OWNER

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
```

Expected: `LICENSE` has current year and GitHub account name/login when available.

- [ ] **Step 3: Write `.gitignore`**

Create `.gitignore`:

```gitignore
.DS_Store
__pycache__/
*.pyc
.pytest_cache/
.mypy_cache/
/tmp/
/dist/
/redlens-state/
```

- [ ] **Step 4: Update README clone URL**

Run:

```bash
LOGIN="$(gh api user --jq .login)"
python3 - <<PY
from pathlib import Path
path = Path("README.md")
text = path.read_text()
text = text.replace("https://github.com/<your-github-user>/redlens.git", f"https://github.com/$LOGIN/redlens.git")
path.write_text(text)
PY
```

Expected: README clone URL uses the authenticated GitHub login.

- [ ] **Step 5: Commit repository metadata**

Run:

```bash
git add README.md LICENSE .gitignore
git commit -m "docs: add open source project metadata"
```

Expected: metadata commit created.

---

### Task 7: Verify Local Installation

**Files:**
- Read/Write via installer:
  - `~/.codex/skills/redlens/`
  - `~/.claude/skills/redlens/`
  - `~/.config/opencode/skills/redlens/`
  - `~/.config/opencode/agents/redlens.md`

- [ ] **Step 1: Run package validation**

Run:

```bash
python3 scripts/validate_skill.py
```

Expected: `OK: redlens skill package is valid`.

- [ ] **Step 2: Run installer**

Run:

```bash
./scripts/install.sh
```

Expected: installer reports all Codex, Claude Code, OpenCode skill paths and OpenCode agent path.

- [ ] **Step 3: Verify installed files**

Run:

```bash
test -f "${CODEX_HOME:-$HOME/.codex}/skills/redlens/SKILL.md"
test -f "$HOME/.claude/skills/redlens/SKILL.md"
test -f "$HOME/.config/opencode/skills/redlens/SKILL.md"
test -f "$HOME/.config/opencode/agents/redlens.md"
```

Expected: all `test -f` commands exit successfully.

- [ ] **Step 4: Commit installer verification note if any docs changed**

Run:

```bash
git status --short
```

Expected: no uncommitted changes unless validation revealed a needed doc or script fix.

---

### Task 8: Publish to GitHub

**Files:**
- Git repository metadata only.

- [ ] **Step 1: Confirm GitHub CLI authentication**

Run:

```bash
gh auth status
```

Expected: authenticated account is available. If not authenticated, run `gh auth login` interactively before continuing.

- [ ] **Step 2: Create GitHub repository if no remote exists**

Run:

```bash
if ! git remote get-url origin >/dev/null 2>&1; then
  gh repo create redlens --public --source=. --remote=origin --description "RedLens portable Agent Skill for authorized Kali Linux penetration testing workflows across Codex, Claude Code, and OpenCode"
fi
```

Expected: `origin` points to the new public GitHub repository.

- [ ] **Step 3: Push branch**

Run:

```bash
git push -u origin codex/package-redlens-skill
```

Expected: branch is available on GitHub.

- [ ] **Step 4: Open pull request**

Run:

```bash
gh pr create \
  --title "Package redlens as a portable Agent Skill" \
  --body "Packages the existing redlens OpenCode setup as a portable open source skill for Codex, Claude Code, and OpenCode. Adds installer, validator, OpenCode agent adapter, README, and MIT license." \
  --draft
```

Expected: draft PR URL is returned.

---

## Verification Checklist

- [ ] `python3 scripts/validate_skill.py` passes.
- [ ] `./scripts/install.sh` installs into Codex, Claude Code, and OpenCode paths.
- [ ] `~/.codex/skills/redlens/SKILL.md` exists.
- [ ] `~/.claude/skills/redlens/SKILL.md` exists.
- [ ] `~/.config/opencode/skills/redlens/SKILL.md` exists.
- [ ] `~/.config/opencode/agents/redlens.md` exists.
- [ ] `git log --oneline` shows focused commits.
- [ ] GitHub repo exists and branch is pushed.
- [ ] Draft PR exists or `main` is pushed directly if the user asks for direct publish.

## Self-Review

- Spec coverage: The plan covers Codex, Claude Code, OpenCode skill usage, OpenCode agent usage, open source packaging, local installation, validation, and GitHub publication.
- Placeholder scan: The only angle-bracket value appears inside README content before an explicit replacement step; execution replaces it with the authenticated GitHub login before commit.
- Risk review: The plan intentionally removes automatic intrusive behavior and requires authorization plus second approval for high-risk operations.
