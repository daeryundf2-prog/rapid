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

function Invoke-SystemPython {
    param([string[]]$PythonArgs)
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 @PythonArgs
        return $LASTEXITCODE
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        & python @PythonArgs
        return $LASTEXITCODE
    }
    throw "Python was not found. Install Python 3.9+ from https://www.python.org/downloads/windows/ and enable 'Add python.exe to PATH'."
}

function Invoke-VenvPython {
    param([string[]]$PythonArgs)
    & $VenvPython @PythonArgs
    return $LASTEXITCODE
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

if (!$NoBrowser) {
    Write-Step "Opening $WebUrl"
    Start-Process $WebUrl
}

Write-Step "Starting rapidtriage web UI"
Write-Host "Press Ctrl+C in this window to stop the server."
Invoke-VenvPython @("-m", "rapidtriage", "web", "--host", $HostName, "--port", "$Port")
exit $LASTEXITCODE
