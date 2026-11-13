# Run the Windows Event Log collector for the Security channel (must be elevated).
$ErrorActionPreference = "Continue"

$backend = Split-Path $PSScriptRoot -Parent
Set-Location $backend

$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "Python virtualenv not found at $python"
    Write-Host "Create it first: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
    Read-Host "Press Enter to close"
    exit 1
}

Write-Host "Aegis collector - Security channel (Ctrl+C to stop)"
& $python "tools\windows_event_collector.py" --channel Security --since-minutes 1440 --interval 20

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Collector exited with code $LASTEXITCODE. See the message above."
    Read-Host "Press Enter to close"
}
