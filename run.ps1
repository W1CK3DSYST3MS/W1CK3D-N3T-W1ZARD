# run.ps1 — W1CK3D_NET_WIZARD launcher for Windows
#
# Right-click → Run with PowerShell   (or double-click the desktop shortcut)
#
# If PowerShell blocks this script, run once as your normal user:
#     Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

$ErrorActionPreference = 'Continue'

Set-Location -Path $PSScriptRoot
$AppDir  = $PSScriptRoot
$LogFile = Join-Path $AppDir 'launch.log'

function Show-Error {
    param([string]$Title, [string]$Message)
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        $Message, $Title,
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
}

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts  $Msg" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Write-Log "=== Launch started ==="

# ── Find Python ───────────────────────────────────────────────────────────────
$python = $null
foreach ($cmd in @('py', 'python', 'python3')) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) { $python = $cmd; break }
}

if (-not $python) {
    $candidates = @(
        "$Env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$Env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$Env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$Env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $python = $c; break }
    }
}

if (-not $python) {
    $msg = "Python was not found on this computer.`n`n" +
           "Fix:`n" +
           "1. Download Python 3.10+ from https://www.python.org/downloads/`n" +
           "2. On the first installer screen, tick 'Add Python to PATH'`n" +
           "3. Click Install Now, then re-run this launcher.`n`n" +
           "Log saved to: $LogFile"
    Write-Log "FAIL: Python not found"
    Show-Error "W1CK3D_NET_WIZARD — Python Not Found" $msg
    exit 1
}

$pyVersion = & $python --version 2>&1
Write-Log "Python: $python  ($pyVersion)"

# ── Check tkinter ─────────────────────────────────────────────────────────────
& $python -c "import tkinter" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    $msg = "tkinter (the GUI framework) is not available in your Python installation.`n`n" +
           "This usually means Python was installed without the Tcl/Tk option.`n`n" +
           "Fix:`n" +
           "1. Open 'Add or Remove Programs' and find Python`n" +
           "2. Click Modify`n" +
           "3. Make sure 'tcl/tk and IDLE' is ticked`n" +
           "4. Click Modify to repair, then re-run this launcher.`n`n" +
           "Or reinstall Python from https://www.python.org/downloads/`n`n" +
           "Log: $LogFile"
    Write-Log "FAIL: tkinter not available"
    Show-Error "W1CK3D_NET_WIZARD — tkinter Missing" $msg
    exit 1
}
Write-Log "tkinter: OK"

# ── Install Python dependencies ────────────────────────────────────────────────
Write-Log "Verifying dependencies..."
& $python -m pip install --quiet --disable-pip-version-check pyshark manuf 2>&1 |
    ForEach-Object { Write-Log "pip: $_" }

# ── Warn only (do not block launch) ───────────────────────────────────────────
$tsharkFound = (Get-Command tshark -ErrorAction SilentlyContinue) -or
               (Test-Path "$Env:ProgramFiles\Wireshark\tshark.exe") -or
               (Test-Path "${Env:ProgramFiles(x86)}\Wireshark\tshark.exe")
if (-not $tsharkFound) { Write-Log "WARN: tshark not found" }

$nmapFound = (Get-Command nmap -ErrorAction SilentlyContinue) -or
             (Test-Path "$Env:ProgramFiles\Nmap\nmap.exe") -or
             (Test-Path "${Env:ProgramFiles(x86)}\Nmap\nmap.exe")
if (-not $nmapFound) { Write-Log "WARN: nmap not found" }

# ── Verify app.py exists ──────────────────────────────────────────────────────
$appPath = Join-Path $AppDir 'app.py'
if (-not (Test-Path $appPath)) {
    $msg = "app.py not found in:`n$AppDir`n`n" +
           "Make sure you are running this script from inside the W1CK3D_NET_WIZARD folder."
    Write-Log "FAIL: app.py not found"
    Show-Error "W1CK3D_NET_WIZARD — File Missing" $msg
    exit 1
}

# ── Launch with pythonw.exe (no console) or python.exe (hidden window) ────────
Write-Log "Launching app.py..."

$pythonExe = $python
if ($python -notmatch '\\') {
    $resolved = (Get-Command $python -ErrorAction SilentlyContinue)
    if ($resolved) { $pythonExe = $resolved.Source }
}
$pythonW = $pythonExe -replace 'python\.exe$', 'pythonw.exe'
if (-not (Test-Path $pythonW)) { $pythonW = $null }

try {
    if ($pythonW) {
        Write-Log "Using pythonw: $pythonW"
        $proc = Start-Process -FilePath $pythonW `
                    -ArgumentList "`"$appPath`"" `
                    -WorkingDirectory $AppDir `
                    -RedirectStandardError $LogFile `
                    -PassThru -NoNewWindow
    } else {
        Write-Log "Using python (hidden window): $pythonExe"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName         = $pythonExe
        $psi.Arguments        = "`"$appPath`""
        $psi.WorkingDirectory = $AppDir
        $psi.UseShellExecute  = $false
        $psi.CreateNoWindow   = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardOutput = $false
        $proc = [System.Diagnostics.Process]::Start($psi)
    }

    # Wait up to 10 seconds — if it exits before the GUI appears, it crashed
    $exited = $proc.WaitForExit(10000)

    if ($exited -and $proc.ExitCode -ne 0) {
        $errLines = @()
        if (Test-Path $LogFile) {
            $errLines = Get-Content $LogFile -ErrorAction SilentlyContinue |
                        Select-Object -Last 25
        }
        $errText = if ($errLines) { $errLines -join "`n" } else { '(no output captured)' }

        $msg = "W1CK3D_NET_WIZARD failed to start (exit code $($proc.ExitCode)).`n`n" +
               "Last log entries:`n" +
               "──────────────────────────────────`n" +
               $errText +
               "`n──────────────────────────────────`n`n" +
               "Full log: $LogFile`n" +
               "Run diagnose.bat for a detailed diagnostic report."
        Write-Log "FAIL: app exited with code $($proc.ExitCode)"
        Show-Error "W1CK3D_NET_WIZARD — Launch Failed" $msg
        exit $proc.ExitCode
    }

    Write-Log "App running (PID $($proc.Id))"

} catch {
    $msg = "Unexpected error launching the app:`n`n$_`n`n" +
           "Run diagnose.bat for a detailed diagnostic report.`n" +
           "Log: $LogFile"
    Write-Log "EXCEPTION: $_"
    Show-Error "W1CK3D_NET_WIZARD — Unexpected Error" $msg
    exit 1
}
