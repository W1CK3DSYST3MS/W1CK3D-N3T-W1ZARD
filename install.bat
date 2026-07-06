@echo off
title W1CK3D_NET_WIZARD - Installer
echo.
echo ============================================================
echo   W1CK3D_NET_WIZARD -- Windows Installer
echo ============================================================
echo.

REM ── Find Python ────────────────────────────────────────────────────────
set PYTHON=
set PYTHONW=
where python >nul 2>&1
if %errorlevel%==0 set PYTHON=python
if "%PYTHON%"=="" (
    where py >nul 2>&1
    if %errorlevel%==0 set PYTHON=py
)
if "%PYTHON%"=="" (
    echo ERROR: Python not found.
    echo   Install from https://www.python.org/downloads/
    echo   Tick "Add Python to PATH" on the first screen.
    echo.
    pause
    exit /b 1
)
echo [OK] Found:
%PYTHON% --version

REM ── Locate pythonw.exe (needed for the shortcut) ───────────────────────
for /f "tokens=*" %%i in ('%PYTHON% -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))"') do set PYTHONW=%%i
if not exist "%PYTHONW%" (
    REM fallback: pythonw in same folder as python
    for /f "tokens=*" %%i in ('where python') do set PYTHONW=%%~dpi pythonw.exe
)
echo [INFO] pythonw: %PYTHONW%

REM ── Check tkinter ──────────────────────────────────────────────────────
echo.
echo Checking tkinter...
%PYTHON% -c "import tkinter; print('[OK] tkinter', tkinter.TkVersion)"
if %errorlevel% neq 0 (
    echo.
    echo [FAIL] tkinter is missing.
    echo   Fix: Start - Add or Remove Programs - Python - Modify
    echo        Tick "tcl/tk and IDLE", click Modify, then re-run this.
    echo.
    pause
    exit /b 1
)

REM ── Install pip packages ───────────────────────────────────────────────
echo.
echo Installing Python dependencies...
%PYTHON% -m pip install --quiet pyshark manuf
echo [OK] Dependencies ready.

REM ── Unblock all script files ───────────────────────────────────────────
echo.
echo Unblocking script files...
powershell -NoProfile -Command "Get-ChildItem '%~dp0' -Recurse -Include *.py,*.pyw,*.ps1,*.bat | Unblock-File"
echo [OK] Scripts unblocked.

REM ── Check launch.pyw exists ────────────────────────────────────────────
echo.
if not exist "%~dp0launch.pyw" (
    echo [FAIL] launch.pyw is missing from this folder.
    echo        Download it separately and place it here:
    echo        %~dp0
    echo.
    pause
    exit /b 1
)
echo [OK] launch.pyw found.

REM ── Check optional tools ───────────────────────────────────────────────
set TSHARK_FOUND=0
if exist "%ProgramFiles%\Wireshark\tshark.exe"      set TSHARK_FOUND=1
if exist "%ProgramFiles(x86)%\Wireshark\tshark.exe" set TSHARK_FOUND=1
where tshark >nul 2>&1 && set TSHARK_FOUND=1
if %TSHARK_FOUND%==1 (echo [OK] Wireshark/tshark found.) else (
    echo [NOTE] Wireshark not found - https://www.wireshark.org/ (tick Npcap)
)

set NMAP_FOUND=0
if exist "%ProgramFiles%\Nmap\nmap.exe"      set NMAP_FOUND=1
if exist "%ProgramFiles(x86)%\Nmap\nmap.exe" set NMAP_FOUND=1
where nmap >nul 2>&1 && set NMAP_FOUND=1
if %NMAP_FOUND%==1 (echo [OK] nmap found.) else (
    echo [NOTE] nmap not found - https://nmap.org/
)

REM ── Create desktop shortcut ────────────────────────────────────────────
echo.
echo Creating desktop shortcut...
set SCRIPT_DIR=%~dp0
set SHORTCUT=%USERPROFILE%\Desktop\W1CK3D_NET_WIZARD.lnk
set ICON=%SCRIPT_DIR%assets\icon.ico
set LAUNCH=%SCRIPT_DIR%launch.pyw
REM Shortcut calls pythonw.exe directly - more reliable than .pyw file association
powershell -NoProfile -Command "
  $ws = New-Object -COM WScript.Shell;
  $s = $ws.CreateShortcut('%SHORTCUT%');
  $s.TargetPath = '%PYTHONW%';
  $s.Arguments = '\"%LAUNCH%\"';
  $s.WorkingDirectory = '%SCRIPT_DIR%';
  $s.IconLocation = '%ICON%';
  $s.Description = 'W1CK3D_NET_WIZARD';
  $s.Save()
" 2>nul
if exist "%SHORTCUT%" (
    echo [OK] Desktop shortcut created.
) else (
    echo [NOTE] Shortcut not created automatically.
    echo        Double-click launch.pyw in the app folder to launch.
)

echo.
echo ============================================================
echo   Done!
echo.
echo   TO LAUNCH:   double-click launch.pyw in this folder
echo                or use the desktop shortcut
echo   DIAGNOSTIC:  double-click diagnose.pyw
echo ============================================================
echo.
pause
