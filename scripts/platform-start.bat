@echo off
REM Sentinel Guardian - platform backend launcher (ageval-security/platform_api + web console)
REM Backend : FastAPI via uvicorn @ 127.0.0.1:8010
REM Console : Vite dev server @ 127.0.0.1:5174 (proxies /api -> :8010)
REM
REM Prerequisite: this interpreter's environment has redsentinel, ageval-cli, and the
REM sentinel-agent plugin installed. See README platform setup steps.

setlocal
cd /d "%~dp0.."

if not exist "ageval-security\ageval" (
    echo [Sentinel Guardian] ageval-security\ageval not found.
    echo This is the ZJU-REAL/ageval checkout the platform runs on top of. It is not
    echo tracked by this repo's git history and must be cloned separately:
    echo.
    echo     git clone https://github.com/ZJU-REAL/ageval.git ageval-security\ageval
    echo.
    echo See README platform setup steps.
    endlocal
    exit /b 1
)

echo [Sentinel Guardian] Starting platform backend on http://127.0.0.1:8010 ...
start "Sentinel Platform API" cmd /k "cd /d %CD%\ageval-security && python -m uvicorn platform_api.app:app --host 127.0.0.1 --port 8010"

echo [Sentinel Guardian] Starting console on http://127.0.0.1:5174 ...
start "Sentinel Platform Console" cmd /k "cd /d %CD%\ageval-security\platform_api\web && npm run dev"

echo.
echo Backend : http://127.0.0.1:8010
echo Console : http://127.0.0.1:5174  (open this in your browser)
echo.
echo Close the two spawned windows to stop the servers.
endlocal
