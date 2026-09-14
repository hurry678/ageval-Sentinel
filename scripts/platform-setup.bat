@echo off
REM Sentinel Guardian - one-click platform setup for Windows

setlocal
cd /d "%~dp0.."

where python >nul 2>nul
if errorlevel 1 (
    echo [Sentinel Guardian] Python not found. Install Python 3.12 and retry.
    endlocal
    exit /b 1
)

where git >nul 2>nul
if errorlevel 1 (
    echo [Sentinel Guardian] Git not found. Install Git and retry.
    endlocal
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [Sentinel Guardian] npm not found. Install Node.js LTS and retry.
    endlocal
    exit /b 1
)

echo [1/5] Installing Sentinel Python deps ...
python -m pip install -e ".[product,dev]"
if errorlevel 1 goto :error

if not exist "ageval-security\ageval" (
    echo [2/5] Cloning ZJU-REAL ageval ...
    git clone https://github.com/ZJU-REAL/ageval.git ageval-security\ageval
    if errorlevel 1 goto :error
) else (
    echo [2/5] ageval checkout already exists.
)

echo [3/5] Installing ageval CLI ...
python -m pip install -e ageval-security\ageval
if errorlevel 1 goto :error

echo [4/5] Installing Sentinel ageval plugin ...
cd ageval-security
ageval plugin install plugins/sentinel-agent
if errorlevel 1 goto :error
cd ..

echo [5/5] Installing console deps ...
cd ageval-security\platform_api\web
call npm install
if errorlevel 1 goto :error
cd ..\..\..

echo.
echo Setup complete.
echo Run scripts\platform-start.bat to start backend and console.
echo Open http://127.0.0.1:5174/
endlocal
exit /b 0

:error
echo.
echo Setup failed. See errors above.
endlocal
exit /b 1
