@echo off
REM diagnose.bat — W1CK3D_NET_WIZARD launch diagnostics
REM Run this in the same folder as app.py.
REM The window stays open so you can read every result.
REM Send a screenshot of this output when reporting issues.

title W1CK3D_NET_WIZARD — Diagnostics
color 0A

echo.
echo ============================================================
echo   W1CK3D_NET_WIZARD — Launch Diagnostics
echo ============================================================
echo.

set PASS=0
set FAIL=0
set SCRIPT_DIR=%~dp0

REM ── 1. Python ─────────────────────────────────────────────────────────────
echo [CHECK 1] Looking for Python...
set PYTHON=

where python >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PY_VER=%%i
    set PYTHON=python
    echo   [OK] python found: %PY_VER%
    set /a PASS+=1
    goto :check_py_found
)

where py >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=*" %%i in ('py --version 2^>^&1') do set PY_VER=%%i
    set PYTHON=py
    echo   [OK] py launcher found: %PY_VER%
    set /a PASS+=1
    goto :check_py_found
)

echo   [FAIL] Python not found on PATH.
echo          Install from https://www.python.org/downloads/
echo          On the first screen, tick "Add Python to PATH"
set /a FAIL+=1
goto :check_tkinter

:check_py_found

REM ── 2. Python version (need 3.10+) ────────────────────────────────────────
echo.
echo [CHECK 2] Checking Python version...
%PYTHON% -c "import sys; v=sys.version_info; ok=v>=(3,10); print('  [OK] Python %d.%d.%d — meets requirement (3.10+)' % (v.major,v.minor,v.micro) if ok else '  [FAIL] Python %d.%d.%d — need 3.10 or newer' % (v.major,v.minor,v.micro)); sys.exit(0 if ok else 1)" 2>&1
if %errorlevel%==0 (set /a PASS+=1) else (set /a FAIL+=1)

REM ── 3. tkinter ────────────────────────────────────────────────────────────
:check_tkinter
echo.
echo [CHECK 3] Checking tkinter (GUI framework)...
if "%PYTHON%"=="" (
    echo   [SKIP] Python not found — cannot check tkinter.
    goto :check_pip
)
%PYTHON% -c "import tkinter; print('  [OK] tkinter version', tkinter.TkVersion)" 2>&1
if %errorlevel%==0 (
    set /a PASS+=1
) else (
    echo   [FAIL] tkinter is not installed.
    echo          This usually means Python was installed without the Tcl/Tk component.
    echo          Fix: Re-run the Python installer, choose 'Modify', and make sure
    echo               'tcl/tk and IDLE' is ticked.
    echo          Or install a fresh Python from https://www.python.org/downloads/
    set /a FAIL+=1
)

REM ── 4. pip / pyshark ──────────────────────────────────────────────────────
:check_pip
echo.
echo [CHECK 4] Checking pyshark...
if "%PYTHON%"=="" goto :check_manuf
%PYTHON% -c "import pyshark; print('  [OK] pyshark', pyshark.__version__ if hasattr(pyshark,'__version__') else 'installed')" 2>&1
if %errorlevel%==0 (
    set /a PASS+=1
) else (
    echo   [WARN] pyshark not installed. Running pip install...
    %PYTHON% -m pip install pyshark
    %PYTHON% -c "import pyshark" 2>&1 && (
        echo   [OK] pyshark installed successfully.
        set /a PASS+=1
    ) || (
        echo   [FAIL] pyshark install failed.
        set /a FAIL+=1
    )
)

:check_manuf
echo.
echo [CHECK 5] Checking manuf...
if "%PYTHON%"=="" goto :check_tshark
%PYTHON% -c "import manuf; print('  [OK] manuf installed')" 2>&1
if %errorlevel%==0 (
    set /a PASS+=1
) else (
    echo   [WARN] manuf not installed. Running pip install...
    %PYTHON% -m pip install manuf
    set /a PASS+=1
)

REM ── 5. tshark ─────────────────────────────────────────────────────────────
:check_tshark
echo.
echo [CHECK 6] Looking for tshark (Wireshark)...
set TSHARK_OK=0

where tshark >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=*" %%i in ('tshark --version 2^>^&1') do (
        echo   [OK] tshark on PATH: %%i
        set TSHARK_OK=1
        goto :tshark_found
    )
)

if exist "%ProgramFiles%\Wireshark\tshark.exe" (
    echo   [OK] tshark found: %ProgramFiles%\Wireshark\tshark.exe
    set TSHARK_OK=1
    goto :tshark_found
)
if exist "%ProgramFiles(x86)%\Wireshark\tshark.exe" (
    echo   [OK] tshark found: %ProgramFiles(x86)%\Wireshark\tshark.exe
    set TSHARK_OK=1
    goto :tshark_found
)

echo   [WARN] tshark not found. pcap analysis and live capture will not work.
echo          Install Wireshark from https://www.wireshark.org/download.html
echo          (Install Npcap when prompted for live capture support.)

:tshark_found
if %TSHARK_OK%==1 (set /a PASS+=1) else (set /a FAIL+=1)

REM ── 6. nmap ───────────────────────────────────────────────────────────────
echo.
echo [CHECK 7] Looking for nmap...
set NMAP_OK=0
where nmap >nul 2>&1 && set NMAP_OK=1
if exist "%ProgramFiles%\Nmap\nmap.exe"      set NMAP_OK=1
if exist "%ProgramFiles(x86)%\Nmap\nmap.exe" set NMAP_OK=1
if %NMAP_OK%==1 (
    echo   [OK] nmap found.
    set /a PASS+=1
) else (
    echo   [WARN] nmap not found. Network scanning will not work.
    echo          Install from https://nmap.org/download.html
)

REM ── 7. Required files ─────────────────────────────────────────────────────
echo.
echo [CHECK 8] Checking required application files...
set FILES_OK=1
for %%f in (app.py analyze.py cli.py scheduler.py live_capture.py admin_panel.py) do (
    if exist "%SCRIPT_DIR%%%f" (
        echo   [OK] %%f
    ) else (
        echo   [FAIL] MISSING: %%f
        set FILES_OK=0
        set /a FAIL+=1
    )
)
for %%f in (analyzer\__init__.py tools\__init__.py assets\icon.ico) do (
    if exist "%SCRIPT_DIR%%%f" (
        echo   [OK] %%f
    ) else (
        echo   [FAIL] MISSING: %%f
        set FILES_OK=0
        set /a FAIL+=1
    )
)
if %FILES_OK%==1 set /a PASS+=1

REM ── 8. App import test ────────────────────────────────────────────────────
echo.
echo [CHECK 9] Testing Python imports (this is where most failures occur)...
if "%PYTHON%"=="" goto :summary

cd /d "%SCRIPT_DIR%"
%PYTHON% -c "
import sys, os
sys.path.insert(0, os.getcwd())
errors = []

mods = [
    ('tkinter',              'tkinter'),
    ('analyzer.storage',     'ReportStore'),
    ('analyze',              'run_analysis'),
    ('tools.ip_investigate', 'lookup_ip'),
    ('tools.protocol_library','load_library'),
    ('tools.scan_profiles',  'SCAN_PROFILES'),
    ('tools.wireless_analyzer','analyze_80211_pcap'),
    ('admin_panel',          'AdminSettingsPanel'),
    ('cli',                  'analyze_file'),
    ('scheduler',            'effective_config'),
    ('live_capture',         'CaptureSession'),
]

for mod, attr in mods:
    try:
        m = __import__(mod, fromlist=[attr])
        getattr(m, attr)
        print('  [OK]', mod)
    except Exception as e:
        print('  [FAIL]', mod, '-->', type(e).__name__ + ':', str(e)[:120])
        errors.append(mod)

if errors:
    print()
    print('  FAILED IMPORTS:', ', '.join(errors))
    sys.exit(1)
else:
    print()
    print('  All imports OK.')
" 2>&1

if %errorlevel%==0 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
)

REM ── Summary ───────────────────────────────────────────────────────────────
:summary
echo.
echo ============================================================
echo   Results:  %PASS% passed   %FAIL% failed / warned
echo ============================================================
echo.

if %FAIL%==0 (
    echo   Everything looks good. Trying to launch the app now...
    echo   If the app does not appear, check launch.log in this folder.
    echo.
    if "%PYTHON%"=="" goto :end
    cd /d "%SCRIPT_DIR%"
    %PYTHON% app.py > "%SCRIPT_DIR%launch.log" 2>&1
    if %errorlevel% neq 0 (
        echo   App exited with an error. Contents of launch.log:
        echo   ----------------------------------------------------
        type "%SCRIPT_DIR%launch.log"
    )
) else (
    echo   Fix the FAIL items above and re-run this diagnostic.
    echo   Screenshot this window if you need help.
)

:end
echo.
pause
