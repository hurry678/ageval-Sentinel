#!/usr/bin/env bash
# Sentinel Guardian - platform backend launcher (ageval-security/platform_api + web console)
# Backend : FastAPI via uvicorn @ 127.0.0.1:8010
# Console : Vite dev server @ 127.0.0.1:5174 (proxies /api -> :8010)
#
# Prerequisite: this interpreter's environment has redsentinel, ageval-cli, and the
# sentinel-agent plugin installed. See README platform setup steps.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d "ageval-security/ageval" ]; then
    echo "[Sentinel Guardian] ageval-security/ageval not found."
    echo "This is the ZJU-REAL/ageval checkout the platform runs on top of. It is not"
    echo "tracked by this repo's git history and must be cloned separately:"
    echo
    echo "    git clone https://github.com/ZJU-REAL/ageval.git ageval-security/ageval"
    echo
    echo "See README platform setup steps."
    exit 1
fi

echo "[Sentinel Guardian] Starting platform backend on http://127.0.0.1:8010 ..."
(cd ageval-security && python -m uvicorn platform_api.app:app --host 127.0.0.1 --port 8010) &

echo "[Sentinel Guardian] Starting console on http://127.0.0.1:5174 ..."
(cd ageval-security/platform_api/web && npm run dev) &

echo
echo "Backend : http://127.0.0.1:8010"
echo "Console : http://127.0.0.1:5174  (open this in your browser)"
echo
echo "Ctrl+C, then kill the two background jobs to stop the servers."
wait
