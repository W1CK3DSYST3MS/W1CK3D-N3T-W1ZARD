@echo off
title W1CK3D_NET_WIZARD - Environment Reset
echo.
echo ============================================================
echo   W1CK3D_NET_WIZARD -- Environment Reset
echo ============================================================
echo.
echo This will:
echo   1. Find your Python installation
echo   2. Uninstall all non-core packages (clean slate)
echo   3. Remove any cached pyc files from this folder
echo   4. Reinstall only what W1CK3D_NET_WIZARD needs
echo.
echo Press any key to continue or close this window to cancel.
pause >nul

REM ── Find Python ─────────────────────────────────────────────────────────────
set PYTHON=
where python >nul 2>&1 && set PYTHON=python
if "%PYTHON%"=="" where py >nul 2>&1 && set PYTHON=py
if "%PYTHON%"=="" (
    echo ERROR: Python not found on PATH.
    echo Install from https://www.python.org/downloads/
    pause & exit /b 1
)
echo [OK] Using: %PYTHON% (%PYTHON% --version)
%PYTHON% --version

REM ── Step 1: Remove cached .pyc files from this folder ───────────────────────
echo.
echo [1/4] Removing cached Python files from app folder...
cd /d "%~dp0"
for /r %%f in (*.pyc) do del /q "%%f" 2>nul
for /d /r %%d in (__pycache__) do rd /s /q "%%d" 2>nul
echo [OK] Cache cleared.

REM ── Step 2: Uninstall ALL third-party packages ───────────────────────────────
echo.
echo [2/4] Uninstalling all pip packages (clean slate)...
echo       This may take a moment...
%PYTHON% -m pip freeze > "%TEMP%\pip_packages.txt"
%PYTHON% -m pip uninstall -r "%TEMP%\pip_packages.txt" -y >nul 2>&1
echo [OK] All packages removed.

REM ── Step 3: Upgrade pip itself ───────────────────────────────────────────────
echo.
echo [3/4] Upgrading pip...
%PYTHON% -m pip install --upgrade pip --quiet
echo [OK] pip upgraded.

REM ── Step 4: Fresh install of required packages ───────────────────────────────
echo.
echo [4/4] Installing W1CK3D_NET_WIZARD dependencies...
%PYTHON% -m pip install pyshark manuf
echo.

REM ── Verify ───────────────────────────────────────────────────────────────────
echo Verifying installs...
%PYTHON% -c "import pyshark; print('[OK] pyshark')" 2>&1
%PYTHON% -c "import manuf;   print('[OK] manuf')"   2>&1
%PYTHON% -c "import tkinter; print('[OK] tkinter Tk', tkinter.TkVersion)" 2>&1

echo.
echo ============================================================
echo   Reset complete. Launch with: double-click launch.pyw
echo ============================================================
echo.
pause
