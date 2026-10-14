<# Pull the latest code from GitHub, update dependencies, run tests, back up the DB and restart the service.
   Run in an elevated PowerShell:  .\deploy\update.ps1 [-Branch main] [-SkipTests] #>
param([string]$Branch = 'main', [switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$svc = 'GlobalHelpdesk'

# 1. back up the database first (pg_dump uses DATABASE_URL from .env)
$envLine = (Get-Content .env | Where-Object { $_ -like 'DATABASE_URL=*' }) -replace '^DATABASE_URL=', ''
if ($envLine -match 'postgresql(\+\w+)?://([^:]+):([^@]+)@([^:/]+):(\d+)/(\w+)') {
    $pgdump = (Get-ChildItem 'C:\Program Files\PostgreSQL\*\bin\pg_dump.exe' | Sort-Object FullName -Descending | Select-Object -First 1).FullName
    New-Item -ItemType Directory -Force "$root\backups" | Out-Null
    $file = "$root\backups\globalhelpdesk_$(Get-Date -Format yyyyMMdd_HHmmss).dump"
    $env:PGPASSWORD = $Matches[3]
    & $pgdump -h $Matches[4] -p $Matches[5] -U $Matches[2] -F c -f $file $Matches[6]
    Write-Host "Backup written: $file"
    Get-ChildItem "$root\backups\*.dump" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 14 | Remove-Item -Force
}

# 2. get the new code
git fetch origin
$before = git rev-parse HEAD
git checkout $Branch
git pull --ff-only origin $Branch
$after = git rev-parse HEAD
Write-Host "Updated $before -> $after"

# 3. dependencies + tests (tests use a temporary SQLite DB, never the live one)
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
if (-not $SkipTests) {
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    & .\.venv\Scripts\python.exe -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Tests failed - service NOT restarted. Fix or roll back with: git reset --hard $before" }
}

# 4. restart (the app upgrades its own schema on start)
Restart-Service $svc
Start-Sleep 6
try { $r = Invoke-WebRequest http://localhost:5008/login -UseBasicParsing -TimeoutSec 15; Write-Host "Health check: HTTP $($r.StatusCode)" }
catch { throw "Service did not come back healthy: $_" }
