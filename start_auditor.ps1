<#
.SYNOPSIS
    SystemAuditor Enterprise — Skrypt Uruchomieniowy PowerShell (Windows)
.DESCRIPTION
    Uruchamia kompletny system (Weryfikacja PKI/E2E + Serwer Centralny FastAPI +
    Lokalny Agent Endpoint + Otwarcie Dashboardu GUI w przeglądarce).
#>

param(
    [string]$HostIp = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$NoBrowser,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$cmdArgs = @("run_system.py", "--host", $HostIp, "--port", $Port)
if ($NoBrowser) { $cmdArgs += "--no-browser" }
if ($SkipTests) { $cmdArgs += "--skip-tests" }

Write-Host "[*] Uruchamianie SystemAuditor Enterprise..." -ForegroundColor Cyan
python @cmdArgs
