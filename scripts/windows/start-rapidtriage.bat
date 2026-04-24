@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "POWERSHELL_SCRIPT=%SCRIPT_DIR%start-rapidtriage.ps1"

where powershell >nul 2>nul
if errorlevel 1 (
  echo PowerShell was not found. Please run scripts\windows\start-rapidtriage.ps1 from PowerShell.
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%POWERSHELL_SCRIPT%" %*
exit /b %ERRORLEVEL%
