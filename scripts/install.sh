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

echo "RedLens installed for Codex, Claude Code, and OpenCode"
