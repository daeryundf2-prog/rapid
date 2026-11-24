[CmdletBinding()]
param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8765,
    [switch]$Reinstall,
    [switch]$DoctorOnly,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$WebUrl = "http://${HostName}:${Port}"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Python children write UTF-8 and the console decodes it as UTF-8; otherwise Korean
# paths and messages piped through Out-Host are shown as CP949 mojibake.
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# The python.org per-user installer leaves py.exe/python.exe off PATH unless the
# PATH box is ticked, and %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe is the
# Microsoft Store alias that only prints "Python was not found" (exit 9009).
function Find-SystemPython {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if (-not $py) {
        $py = Get-Item (Join-Path $env:LOCALAPPDATA "Programs\Python\Launcher\py.exe") -ErrorAction SilentlyContinue
    }
    if ($py) {
        return @{ Exe = $(if ($py -is [System.IO.FileInfo]) { $py.FullName } else { $py.Source }); Args = @("-3") }
    }
    $python = Get-Command python -All -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -notlike "*\WindowsApps\*" } |
        Select-Object -First 1
    if ($python) {
        return @{ Exe = $python.Source; Args = @() }
    }
    # Python312, Python312-32, Python313-arm64: order by the minor version, not every digit
    # in the folder name, and skip interpreters older than the 3.10 floor.
    $installed = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs\Python\Python3*\python.exe") -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -match "^Python3(\d+)" -and [int]$Matches[1] -ge 10 } |
        Sort-Object { [int]($_.Directory.Name -replace "^Python3(\d+).*$", '$1') } -Descending |
        Select-Object -First 1
    if ($installed) {
        return @{ Exe = $installed.FullName; Args = @() }
    }
    throw "Python was not found. Install Python 3.10+ from https://www.python.org/downloads/windows/ and enable 'Add python.exe to PATH'."
}

# Native command output is sent to the host (Out-Host), never to the
# function's output stream: a PowerShell function returns everything its
# body writes, so a child that prints a line would otherwise turn the
# returned exit code into an array and every caller check into a failure.
function Invoke-SystemPython {
    param([string[]]$PythonArgs)
    $python = Find-SystemPython
    $allArgs = @($python.Args) + $PythonArgs
    & $python.Exe @allArgs | Out-Host
    return [int]$LASTEXITCODE
}

function Invoke-VenvPython {
    param([string[]]$PythonArgs)
    & $VenvPython @PythonArgs | Out-Host
    return [int]$LASTEXITCODE
}

Set-Location $RepoRoot

if ($Reinstall -and (Test-Path $VenvPython)) {
    Write-Step "Removing existing virtual environment"
    Remove-Item -Recurse -Force (Join-Path $RepoRoot ".venv")
}

if (!(Test-Path $VenvPython)) {
    Write-Step "Creating Python virtual environment"
    $code = Invoke-SystemPython @("-m", "venv", ".venv")
    if ($code -ne 0) {
        exit $code
    }
}

Write-Step "Installing rapidtriage web dependencies"
$code = Invoke-VenvPython @("-m", "pip", "install", "-U", "pip")
if ($code -ne 0) {
    exit $code
}
$code = Invoke-VenvPython @("-m", "pip", "install", "-e", ".[web]")
if ($code -ne 0) {
    exit $code
}

Write-Step "Running rapidtriage doctor"
$code = Invoke-VenvPython @("-m", "rapidtriage", "doctor", "--host", $HostName, "--port", "$Port")
if ($code -ne 0) {
    Write-Host "Doctor reported a fatal error. Fix the issue above, then rerun this script." -ForegroundColor Red
    exit $code
}

if ($DoctorOnly) {
    exit 0
}

# The server opens the browser itself with a one-time token URL
# (http://host:port/#token=...). Opening $WebUrl here would race the
# token handoff and land the analyst on a token wall.
if ($NoBrowser) {
    $env:RAPIDTRIAGE_NO_BROWSER = "1"
} else {
    Remove-Item Env:RAPIDTRIAGE_NO_BROWSER -ErrorAction SilentlyContinue
}

Write-Step "Starting rapidtriage web UI"
Write-Host "The browser opens automatically with the API token. Press Ctrl+C in this window to stop the server."
# The server stays attached to this console (no pipe) so its output is live.
& $VenvPython @("-m", "rapidtriage", "web", "--host", $HostName, "--port", "$Port")
exit $LASTEXITCODE
