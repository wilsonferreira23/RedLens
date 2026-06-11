# RedLens

**A portable AI skill for authorized Kali Linux penetration testing.**

RedLens turns Codex, Claude Code, and OpenCode into a structured security-assessment assistant: scoped, evidence-driven, risk-gated, and ready to work with Kali through local shell, SSH, or Docker.

[![Skill](https://img.shields.io/badge/Agent%20Skill-RedLens-red)](#install)
[![Platforms](https://img.shields.io/badge/Codex%20%7C%20Claude%20Code%20%7C%20OpenCode-supported-black)](#use)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> Built for authorized security work. RedLens helps organize recon, testing, evidence, and reporting without skipping scope confirmation or high-risk approvals.

## Why Star This

- One skill works across **Codex**, **Claude Code**, and **OpenCode**.
- Includes **300+ Kali-oriented references** for web, API, network, cloud, wireless, forensics, password audits, reporting, and post-exploitation planning.
- Uses a clear operating loop: scope -> plan -> run minimal command -> save evidence -> report.
- Keeps dangerous actions behind explicit authorization and risk gates.
- Ships with a local installer and deterministic validator.

## What RedLens Covers

| Area | Examples |
| --- | --- |
| Recon | subdomains, DNS, ports, technologies, exposed services |
| Web/API | crawling, endpoints, auth, IDOR/BOLA, injection, GraphQL, JWT, CORS |
| Network | internal/external enumeration, service validation, protocol playbooks |
| Cloud-native | Kubernetes, containers, AWS/Azure/GCP assessment references |
| Password audits | offline cracking, spraying gates, lockout-aware workflows |
| Wireless/RFID/VoIP/ICS | specialized playbooks with explicit risk boundaries |
| Reporting | evidence handling, executive summaries, technical reports |

## Install

```bash
git clone https://github.com/wilsonferreira23/RedLens.git
cd RedLens
./scripts/install.sh
```

The installer copies RedLens to:

- `~/.codex/skills/redlens`
- `~/.claude/skills/redlens`
- `~/.config/opencode/skills/redlens`
- `~/.config/opencode/agents/redlens.md`

## Use

Codex or Claude Code:

```text
Use the RedLens skill for an authorized assessment of https://example.com.
```

Claude Code direct command:

```text
/redlens authorized assessment of https://example.com
```

OpenCode:

```text
@redlens authorized assessment of https://example.com
```

## Workflow

```text
Confirm authorization
Define scope and constraints
Select Kali environment: local, SSH, or Docker
Choose the right playbook
Run minimal evidence-producing commands
Record findings and artifacts
Generate a clear report
```

## Safety Model

RedLens is intentionally strict:

- No scanning or probing without explicit authorization.
- Scope is binding: hosts, ports, accounts, windows, and techniques matter.
- Exploitation, brute forcing, phishing, persistence, exfiltration, intrusive scanners, and DoS-like checks require a second explicit approval.
- Evidence should be minimally invasive and enough to prove impact.

## Validate

```bash
python3 scripts/validate_skill.py
```

Expected output:

```text
OK: RedLens skill package is valid
```

## Repository Layout

```text
skills/redlens/SKILL.md          # Canonical cross-agent skill
skills/redlens/references/       # Kali playbooks and tool references
opencode/agents/redlens.md       # OpenCode subagent adapter
scripts/install.sh               # Local installer
scripts/validate_skill.py        # Package validator
```

## Disclaimer

RedLens is for authorized security testing, internal labs, owned systems, and approved assessments only. You are responsible for ensuring you have permission and for following applicable laws, contracts, and rules of engagement.

## License

MIT
