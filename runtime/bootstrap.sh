#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export REDLENS_HOME=${REDLENS_HOME:-$SCRIPT_DIR}
export REDLENS_RUNTIME_DIR=${REDLENS_RUNTIME_DIR:-$REDLENS_HOME/runtime}
export REDLENS_WORKSPACE_DIR=${REDLENS_WORKSPACE_DIR:-$REDLENS_RUNTIME_DIR/kali-workspace}

mkdir -p "$REDLENS_WORKSPACE_DIR"

PYTHON_BIN=${REDLENS_PYTHON:-python3}
VENV_DIR=${REDLENS_VENV_DIR:-$REDLENS_HOME/.venv}
if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --editable "$REDLENS_HOME"
"$VENV_DIR/bin/python" - <<'PY'
from redlens_config import load_config

config = load_config()
for path in (config.data_dir, config.runs_dir, config.backups_dir, config.cloak_cache):
    path.mkdir(parents=True, exist_ok=True)
PY

install -m 755 "$REDLENS_RUNTIME_DIR/redlens-callback-server.py" \
  "$REDLENS_WORKSPACE_DIR/redlens-callback-server.py"

if [ "${REDLENS_BUILD_RUNTIME:-0}" = "1" ]; then
  exec "$VENV_DIR/bin/python" -m runtime.doctor up
fi

exec "$VENV_DIR/bin/python" -m runtime.doctor doctor
