# RedLens

**Turn Codex, Claude Code, and OpenCode into a serious Kali-powered security assessment operator.**

RedLens is a portable Agent Skill for authorized penetration testing. It gives your AI agent a professional assessment loop: confirm scope, choose depth, run Kali workflows, preserve evidence, validate findings, and produce reports an engineer can actually fix from.

[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-RedLens-red)](#install)
[![Works with](https://img.shields.io/badge/Codex%20%7C%20Claude%20Code%20%7C%20OpenCode-ready-black)](#use)
[![Kali](https://img.shields.io/badge/Kali-local%20%7C%20SSH%20%7C%20Docker-557C94)](#how-it-runs)
[![CloakBrowser](https://img.shields.io/badge/CloakBrowser-stealth%20automation-purple)](#cloakbrowser-built-in)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

If you have ever watched an AI "pentest" by running one scanner, dumping noisy output, and calling it done, RedLens is built to fix that.

## Why People Try RedLens

- **It gives agents a real pentest brain.** Not just tool names. RedLens defines scope, coverage, evidence, escalation, and reporting behavior.
- **Quick and standard modes are not watered down.** They keep mandatory coverage and explicit gaps, while deep mode adds exhaustive chaining and cross-validation.
- **It works where you already work.** Install once and use it from Codex, Claude Code, or OpenCode.
- **It is Kali-native.** Run through local Kali, SSH to a Kali box, or a persistent Docker container.
- **It uses CloakBrowser when normal headless browsers fail.** RedLens knows when to switch from CLI tooling to stealth browser automation for JS challenges and anti-bot protected pages.
- **It ships with a serious reference pack.** 300+ files covering recon, web, API, network, cloud, wireless, password audits, forensics, post-exploitation planning, and reporting.

## What Makes It Different

| Typical AI Pentest Prompt | RedLens |
| --- | --- |
| "Run some tools" | Selects a mode, playbook, environment, and evidence plan |
| One scanner dump | Multi-step coverage with required gaps and next actions |
| Vague "looks secure" output | Precise tested/untested coverage and confirmed findings |
| No depth control | `quick`, `standard`, and `deep` contracts |
| Random commands | Kali workflows with state, artifacts, and reporting |
| Headless browser gets blocked | CloakBrowser workflow for authorized browser-dependent testing |

## Assessment Modes

RedLens has depth modes that control runtime, not quality.

| Mode | Use It When | What You Get |
| --- | --- | --- |
| `quick` | You need fast signal now | Mandatory triage coverage, top risks, evidence, gaps, and next recommended mode |
| `standard` | You want the professional default | Broad inventory, validated findings, reproduction steps, remediation, and retest checklist |
| `deep` | You need the strongest assessment | Expanded enumeration, cross-tool validation, chained findings, artifacts, attack paths, and full reporting |

Default mode is `standard`.

## What RedLens Covers

- **Recon:** DNS, subdomains, ports, technologies, exposed services, screenshots, historical URLs.
- **Web apps:** auth, sessions, IDOR/BOLA, XSS, SQLi, SSTI, uploads, headers, CORS, business logic.
- **APIs:** OpenAPI, GraphQL, gRPC, token handling, object authorization, fuzzing, rate-limit abuse.
- **Networks:** external attack surface, internal enumeration, protocol checks, service validation.
- **Cloud-native:** Kubernetes, containers, AWS, Azure, GCP, benchmark-driven review.
- **Password audits:** hash identification, cracking strategy, lockout-aware online testing.
- **Wireless, RFID, VoIP, ICS:** specialized playbooks with explicit risk boundaries.
- **Reporting:** executive summaries, technical findings, evidence references, retest steps.

## CloakBrowser Built In

Modern targets often do not give scanners the real app. They give them a JS challenge, a bot wall, or a fake "Checking your browser" page.

RedLens includes a CloakBrowser workflow for authorized web assessments:

- Detect CDN and anti-bot challenge pages before wasting time with blocked CLI tools.
- Use CloakBrowser instead of regular Playwright, Puppeteer, or vanilla headless Chromium when browser realism matters.
- Extract rendered content and cookies, then feed that evidence back into CLI tooling.
- Keep browser use tied to scope, authorization, evidence, and reporting.

CloakBrowser reference: `skills/redlens/references/web/tools/cloakbrowser.md`

## Install

```bash
git clone https://github.com/wilsonferreira23/RedLens.git
cd RedLens
./scripts/install.sh
```

The installer copies RedLens to:

```text
~/.codex/skills/redlens
~/.claude/skills/redlens
~/.config/opencode/skills/redlens
~/.config/opencode/agents/redlens.md
```

## Use

Codex or Claude Code:

```text
Use RedLens in standard mode for an authorized assessment of https://example.com.
```

Claude Code command:

```text
/redlens run a quick authorized assessment of https://example.com and list gaps
```

OpenCode:

```text
@redlens run a deep authorized assessment of https://example.com within this scope: ...
```

## How It Runs

RedLens can operate through:

- **Local Kali:** direct shell commands on a Kali machine.
- **SSH Kali:** agent drives a full Kali VM/server over SSH.
- **Docker Kali:** persistent `kali-pentest` container for CLI automation.

It records work under `/tmp/kali-pentest-state/<target>/` so evidence, raw output, findings, and gaps are not lost between steps.

## The RedLens Loop

```text
Authorize -> Scope -> Choose mode -> Select playbook -> Run focused checks
          -> Save evidence -> Validate findings -> Report fixes -> Recommend next depth
```

## Validate The Package

```bash
python3 scripts/validate_skill.py
```

Expected:

```text
OK: RedLens skill package is valid
```

## Repository Layout

```text
skills/redlens/SKILL.md                       # Canonical cross-agent skill
skills/redlens/references/playbooks/          # Mode contracts and assessment playbooks
skills/redlens/references/**/tools/           # Kali tool references
opencode/agents/redlens.md                    # OpenCode subagent adapter
scripts/install.sh                            # Installer for Codex, Claude Code, OpenCode
scripts/validate_skill.py                     # Package validator
```

## Safety

RedLens is for authorized security work only.

- No scanning or probing without explicit authorization.
- Scope is binding: hosts, ports, accounts, time windows, and techniques matter.
- High-risk actions require a second explicit approval.
- RedLens should report what was tested, what was not tested, and what should happen next.

## Give It A Star

If you want AI agents that behave less like toy scanners and more like disciplined security operators, star the repo and try RedLens on a lab or authorized target.

## License

MIT
