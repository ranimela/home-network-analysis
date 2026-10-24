@echo off
setlocal
title Home Network Monitor

echo ===================================================
echo   Home Network Analysis ^& Device Monitor
echo ===================================================

cd /d "%~dp0"

:: Check if virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [!] Virtual environment not found. Initializing with uv...
    uv venv
    uv pip install -e ".[dev]"
)

:: Wait 2 seconds and open browser in background
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8000"

:: Start the Python server
echo [*] Starting Home Network Monitor on http://localhost:8000 ...
echo [*] Press Ctrl+C in this terminal to stop the monitor.
echo.

".venv\Scripts\python.exe" -m home_network_analysis.main --port 8000

pause
