# RedLens

Portable Agent Skill for authorized Kali Linux penetration testing workflows across Codex, Claude Code, and OpenCode.

## What It Does

- Guides authorized security assessments with explicit scope and risk gates.
- Supports Kali through local shell, SSH, or a persistent Docker container.
- Routes work to focused playbooks for web, API, network, cloud-native, wireless, forensics, password audits, post-exploitation planning, and reporting.
- Keeps detailed tool notes in references so agents load only what they need.

## Safety

Use RedLens only for systems you are authorized to test. High-risk actions require explicit approval before execution.

## Install

```bash
git clone https://github.com/wilsonferreira23/RedLens.git
cd RedLens
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
Use the RedLens skill for an authorized assessment of <target>.
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
