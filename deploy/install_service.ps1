<# Installs the helpdesk as a Windows service (auto-start, auto-restart) using NSSM.
   Run in an elevated PowerShell:  .\deploy\install_service.ps1 #>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$nssm = (Get-Command nssm -ErrorAction SilentlyContinue).Source
if (-not $nssm) { throw 'nssm.exe not found. Install it (winget install NSSM.NSSM) and reopen PowerShell.' }
$svc = 'GlobalHelpdesk'
New-Item -ItemType Directory -Force "$root\logs" | Out-Null
if (Get-Service $svc -ErrorAction SilentlyContinue) { nssm stop $svc | Out-Null; nssm remove $svc confirm | Out-Null }
nssm install $svc "$root\.venv\Scripts\python.exe" "-m waitress --host=0.0.0.0 --port=5008 --threads=8 --connection-limit=1000 wsgi:app"
nssm set $svc AppDirectory $root
nssm set $svc DisplayName "Global Helpdesk (port 5008)"
nssm set $svc Start SERVICE_AUTO_START
nssm set $svc AppStdout "$root\logs\service.out.log"
nssm set $svc AppStderr "$root\logs\service.err.log"
nssm set $svc AppRotateFiles 1
nssm set $svc AppRotateBytes 10485760
nssm set $svc AppExit Default Restart
if (-not (Get-NetFirewallRule -DisplayName 'Global Helpdesk 5008' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Global Helpdesk 5008' -Direction Inbound -Protocol TCP -LocalPort 5008 -Action Allow | Out-Null
}
nssm start $svc
Write-Host "Service '$svc' installed and started on http://localhost:5008"
