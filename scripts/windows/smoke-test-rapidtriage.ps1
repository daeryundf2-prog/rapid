[CmdletBinding()]
param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8877,
    [string]$OutputDir = "rapidtriage-windows-smoke",
    [string]$VenvDir = ".rapidtriage-smoke-venv",
    [switch]$Reinstall,
    [switch]$SkipWeb
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$VenvRoot = if ([System.IO.Path]::IsPathRooted($VenvDir)) { $VenvDir } else { Join-Path $RepoRoot $VenvDir }
$VenvPython = Join-Path $VenvRoot "Scripts\python.exe"
$SmokeDir = if ([System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir } else { Join-Path $RepoRoot $OutputDir }
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
    $installed = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs\Python\Python3*\python.exe") -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.Directory.Name -replace "\D", "") } -Descending |
        Select-Object -First 1
    if ($installed) {
        return @{ Exe = $installed.FullName; Args = @() }
    }
    throw "Python was not found. Install Python 3.10+ and enable 'Add python.exe to PATH'."
}

# Child output goes to the host so the function returns only the exit code.
function Invoke-SystemPython {
    param([string[]]$PythonArgs)
    $python = Find-SystemPython
    $allArgs = @($python.Args) + $PythonArgs
    & $python.Exe @allArgs | Out-Host
    return [int]$LASTEXITCODE
}

function Invoke-CheckedPython {
    param(
        [string]$StepName,
        [string[]]$PythonArgs,
        [string]$OutputFile = ""
    )
    Write-Step $StepName
    if ($OutputFile) {
        & $VenvPython @PythonArgs | Tee-Object -FilePath $OutputFile
    } else {
        & $VenvPython @PythonArgs
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$StepName failed with exit code $LASTEXITCODE."
    }
}

Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $SmokeDir | Out-Null

if ($Reinstall -and (Test-Path $VenvRoot)) {
    Write-Step "Removing existing smoke-test virtual environment"
    Remove-Item -Recurse -Force $VenvRoot
}

if (!(Test-Path $VenvPython)) {
    Write-Step "Creating smoke-test Python virtual environment"
    $code = Invoke-SystemPython @("-m", "venv", $VenvRoot)
    if ($code -ne 0) {
        exit $code
    }
}

Invoke-CheckedPython "Installing RapidTriage web/test dependencies" @("-m", "pip", "install", "-U", "pip")
Invoke-CheckedPython "Installing editable package" @("-m", "pip", "install", "-e", ".[web,test]")
Invoke-CheckedPython "Checking CLI entrypoint" @("-m", "rapidtriage", "--help") (Join-Path $SmokeDir "rapidtriage-help.txt")
Invoke-CheckedPython "Running runtime doctor" @("-m", "rapidtriage", "doctor", "--host", $HostName, "--port", "$Port", "--json") (Join-Path $SmokeDir "doctor.json")
Invoke-CheckedPython "Running synthetic sample case" @("-m", "rapidtriage", "sample", "--output-dir", (Join-Path $SmokeDir "sample"), "--run", "--overwrite", "--read-only", "--json") (Join-Path $SmokeDir "sample.json")
Invoke-CheckedPython "Searching sample case for password" @("-m", "rapidtriage", "search", (Join-Path $SmokeDir "sample\run-output"), "-k", "password", "--output", (Join-Path $SmokeDir "sample-search.json"))
Invoke-CheckedPython "Running small benchmark" @("-m", "rapidtriage", "benchmark", "--output-dir", (Join-Path $SmokeDir "benchmark"), "--file-count", "100", "--search-iterations", "1", "--overwrite", "--json") (Join-Path $SmokeDir "benchmark.json")
Invoke-CheckedPython "Building validation package" @("-m", "rapidtriage", "validation", "--output-dir", (Join-Path $SmokeDir "validation"), "--overwrite", "--json") (Join-Path $SmokeDir "validation.json")

$DummyVhdx = Join-Path $SmokeDir "dummy.vhdx"
if (!(Test-Path $DummyVhdx)) {
    New-Item -ItemType File -Path $DummyVhdx | Out-Null
}
Invoke-CheckedPython "Checking evidence support guidance" @("-m", "rapidtriage", "evidence", $DummyVhdx, "--json") (Join-Path $SmokeDir "evidence-vhdx.json")

if (!$SkipWeb) {
    Write-Step "Starting web server smoke check at $WebUrl"
    # The API requires a token by default since auth hardening; use a fixed
    # smoke-only token so the contract request can authenticate.
    $SmokeToken = "rapidtriage-smoke-token"
    $job = Start-Job -ScriptBlock {
        param($PythonExe, $Repo, $HostArg, $PortArg, $TokenArg)
        Set-Location $Repo
        & $PythonExe -m rapidtriage web --host $HostArg --port $PortArg --auth-token $TokenArg
    } -ArgumentList $VenvPython, $RepoRoot, $HostName, $Port, $SmokeToken

    try {
        $ready = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Milliseconds 500
            try {
                $response = Invoke-WebRequest -Uri $WebUrl -UseBasicParsing -TimeoutSec 2
                if ($response.StatusCode -eq 200) {
                    $ready = $true
                    $response.Content | Out-File -FilePath (Join-Path $SmokeDir "web-index.html") -Encoding utf8
                    $contract = Invoke-WebRequest -Uri "$WebUrl/api/workbench/smoke-contract" -UseBasicParsing -TimeoutSec 5 -Headers @{ "X-RapidTriage-Token" = $SmokeToken }
                    if ($contract.StatusCode -ne 200) {
                        throw "Workbench smoke contract did not respond with HTTP 200."
                    }
                    $contract.Content | Out-File -FilePath (Join-Path $SmokeDir "workbench-smoke-contract.json") -Encoding utf8
                    break
                }
            } catch {
                # Keep polling until the server is ready or the timeout expires.
            }
        }
        if (!$ready) {
            throw "Web UI did not respond with HTTP 200 at $WebUrl."
        }
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue | Out-Null
        Receive-Job $job -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $SmokeDir "web-server.log") -Encoding utf8
        Remove-Job $job -Force -ErrorAction SilentlyContinue | Out-Null
    }
} else {
    Invoke-CheckedPython "Writing workbench smoke contract artifact" @("-c", "import json; from rapidtriage.api.app import build_workbench_smoke_contract; print(json.dumps(build_workbench_smoke_contract(), ensure_ascii=False, indent=2))") (Join-Path $SmokeDir "workbench-smoke-contract.json")
}

if ($SkipWeb) {
    Invoke-CheckedPython "Summarizing smoke outputs" @((Join-Path $RepoRoot "scripts\summarize-smoke.py"), $SmokeDir, "--platform", "windows", "--allow-missing-web")
} else {
    Invoke-CheckedPython "Summarizing smoke outputs" @((Join-Path $RepoRoot "scripts\summarize-smoke.py"), $SmokeDir, "--platform", "windows")
}

Write-Step "Windows smoke test completed"
Write-Host "Smoke outputs: $SmokeDir" -ForegroundColor Green
