#!/usr/bin/env bash
# One-command launcher: sets up the Python venv, builds the React UI, and serves everything on http://127.0.0.1:8000
# Safe to run from any location (the folder can be moved or renamed): a virtual environment that no longer works is rebuilt automatically.
set -e
cd "$(dirname "$0")"

command -v tshark >/dev/null 2>&1 || { echo "ERROR: tshark not found. Install it first:  brew install wireshark   |   sudo apt install tshark"; exit 1; }
command -v npm    >/dev/null 2>&1 || { echo "ERROR: Node.js/npm not found (need Node 18+). Install from https://nodejs.org"; exit 1; }
PY=$(command -v python3 || command -v python) || { echo "ERROR: Python 3 not found."; exit 1; }

VENV=backend/.venv
if [ -d "$VENV" ] && ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
  echo "Python environment is broken (project moved?) - rebuilding it ..."
  rm -rf "$VENV"
fi
[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install -q -r backend/requirements.txt

( cd frontend && npm install --no-audit --no-fund --silent && npm run build --silent )

echo
echo "  PCAP Analyzer running at  http://127.0.0.1:${PORT:-8000}   (Ctrl+C to stop)"
echo
cd backend && exec .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port "${PORT:-8000}"
