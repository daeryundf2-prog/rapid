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
$SmokeDir = Join-Path $RepoRoot $OutputDir
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
    throw "Python was not found. Install Python 3.9+ and enable 'Add python.exe to PATH'."
}

function Invoke-VenvPython {
    param([string[]]$PythonArgs)
    & $VenvPython @PythonArgs
    return $LASTEXITCODE
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
    $job = Start-Job -ScriptBlock {
        param($PythonExe, $Repo, $HostArg, $PortArg)
        Set-Location $Repo
        & $PythonExe -m rapidtriage web --host $HostArg --port $PortArg
    } -ArgumentList $VenvPython, $RepoRoot, $HostName, $Port

    try {
        $ready = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Milliseconds 500
            try {
                $response = Invoke-WebRequest -Uri $WebUrl -UseBasicParsing -TimeoutSec 2
                if ($response.StatusCode -eq 200) {
                    $ready = $true
                    $response.Content | Out-File -FilePath (Join-Path $SmokeDir "web-index.html") -Encoding utf8
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
}

if ($SkipWeb) {
    Invoke-CheckedPython "Summarizing smoke outputs" @((Join-Path $RepoRoot "scripts\summarize-smoke.py"), $SmokeDir, "--platform", "windows", "--allow-missing-web")
} else {
    Invoke-CheckedPython "Summarizing smoke outputs" @((Join-Path $RepoRoot "scripts\summarize-smoke.py"), $SmokeDir, "--platform", "windows")
}

Write-Step "Windows smoke test completed"
Write-Host "Smoke outputs: $SmokeDir" -ForegroundColor Green
