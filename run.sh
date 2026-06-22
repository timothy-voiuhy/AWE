#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
REQUIREMENTS="$SCRIPT_DIR/requirements.txt"

# ── Virtual environment ────────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "[AWE] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# ── Dependencies ───────────────────────────────────────────────────────────────
# Re-install only when requirements.txt is newer than the last install marker.
MARKER="$VENV_DIR/.installed"
if [ ! -f "$MARKER" ] || [ "$REQUIREMENTS" -nt "$MARKER" ]; then
    echo "[AWE] Installing dependencies..."
    pip install --quiet -r "$REQUIREMENTS"
    touch "$MARKER"
fi

# ── Launch ─────────────────────────────────────────────────────────────────────
echo "[AWE] Starting..."
cd "$SCRIPT_DIR/src"
exec python awe.py "$@"
