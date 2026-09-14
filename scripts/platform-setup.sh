#!/usr/bin/env bash
# Sentinel Guardian - one-click platform setup for macOS/Linux/WSL
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[Sentinel Guardian] $1 not found. Install it and retry."
        exit 1
    fi
}

need python
need git
need npm

echo "[1/5] Installing Sentinel Python deps ..."
python -m pip install -e ".[product,dev]"

if [ ! -d "ageval-security/ageval" ]; then
    echo "[2/5] Cloning ZJU-REAL ageval ..."
    git clone https://github.com/ZJU-REAL/ageval.git ageval-security/ageval
else
    echo "[2/5] ageval checkout already exists."
fi

echo "[3/5] Installing ageval CLI ..."
python -m pip install -e ageval-security/ageval

echo "[4/5] Installing Sentinel ageval plugin ..."
(cd ageval-security && ageval plugin install plugins/sentinel-agent)

echo "[5/5] Installing console deps ..."
(cd ageval-security/platform_api/web && npm install)

echo
echo "Setup complete."
echo "Run: bash scripts/platform-start.sh"
echo "Open: http://127.0.0.1:5174/"
