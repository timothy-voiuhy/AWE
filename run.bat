@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "REQUIREMENTS=%SCRIPT_DIR%requirements.txt"
set "MARKER=%VENV_DIR%\.installed"

:: ── Virtual environment ───────────────────────────────────────────────────────
if not exist "%VENV_DIR%\" (
    echo [AWE] Creating virtual environment...
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [AWE] ERROR: Failed to create virtual environment.
        echo        Make sure Python 3 is installed and on PATH.
        pause
        exit /b 1
    )
)

call "%VENV_DIR%\Scripts\activate.bat"

:: ── Dependencies ──────────────────────────────────────────────────────────────
:: Re-install only when requirements.txt is newer than the last install marker.
set "DO_INSTALL=0"
if not exist "%MARKER%" set "DO_INSTALL=1"
if "%DO_INSTALL%"=="0" (
    for /f %%A in ('forfiles /p "%SCRIPT_DIR%" /m requirements.txt /c "cmd /c echo @ftime"') do set "REQ_TIME=%%A"
    for /f %%A in ('forfiles /p "%VENV_DIR%" /m .installed /c "cmd /c echo @ftime"') do set "MRK_TIME=%%A"
    if "!REQ_TIME!" gtr "!MRK_TIME!" set "DO_INSTALL=1"
)

if "%DO_INSTALL%"=="1" (
    echo [AWE] Installing dependencies...
    pip install --quiet -r "%REQUIREMENTS%"
    if errorlevel 1 (
        echo [AWE] ERROR: Dependency installation failed.
        pause
        exit /b 1
    )
    type nul > "%MARKER%"
)

:: ── Launch ────────────────────────────────────────────────────────────────────
echo [AWE] Starting...
python "%SCRIPT_DIR%main.py" %*
