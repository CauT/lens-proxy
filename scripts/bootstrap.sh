#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v uv >/dev/null || { echo "Install uv before preparing the app dependencies." >&2; exit 1; }
uv python install 3.13.12 --install-dir "$ROOT/.python" --no-bin
RUNTIME="$(find "$ROOT/.python" -maxdepth 1 -type d -name 'cpython-3.13.12-macos-*-none' | head -1)"
if [[ ! -x "$ROOT/.runtime/bin/python" ]]; then
  uv venv --python "$RUNTIME/bin/python3" "$ROOT/.runtime"
fi
if [[ -f "$ROOT/engine/requirements.lock" ]]; then
  uv pip sync --python "$ROOT/.runtime/bin/python" "$ROOT/engine/requirements.lock"
else
  uv pip install --python "$ROOT/.runtime/bin/python" -r "$ROOT/engine/requirements.txt"
fi
echo "Dependencies ready. Run scripts/build-app.sh."
