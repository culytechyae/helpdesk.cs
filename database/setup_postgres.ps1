<#
 Creates the PostgreSQL role + database "globalhelpdesk", applies the schema and writes .env for production (port 5008).
 Usage (PowerShell):  .\database\setup_postgres.ps1 [-PgHost localhost] [-PgPort 5432]
#>
param([string]$PgHost = 'localhost', [int]$PgPort = 5432, [string]$SuperUser = 'postgres')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$psql = (Get-Command psql -ErrorAction SilentlyContinue).Source
if (-not $psql) { $psql = (Get-ChildItem 'C:\Program Files\PostgreSQL\*\bin\psql.exe' | Sort-Object FullName -Descending | Select-Object -First 1).FullName }
if (-not $psql) { throw 'psql not found. Install PostgreSQL client tools or add them to PATH.' }

$superPw = Read-Host "Password of PostgreSQL user '$SuperUser'" -AsSecureString
$appPw   = Read-Host "Password to set for the new application role 'helpdesk_app'" -AsSecureString
function Plain($s) { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)) }
$env:PGPASSWORD = Plain $superPw
$app = Plain $appPw
if ($app.Length -lt 8 -or $app -match "['\s]") { throw "Application password must be 8+ chars with no spaces or single quotes." }

$exists = & $psql -h $PgHost -p $PgPort -U $SuperUser -tAc "SELECT 1 FROM pg_roles WHERE rolname='helpdesk_app'"
if ($exists -eq '1') { & $psql -h $PgHost -p $PgPort -U $SuperUser -c "ALTER ROLE helpdesk_app LOGIN PASSWORD '$app'" }
else { & $psql -h $PgHost -p $PgPort -U $SuperUser -c "CREATE ROLE helpdesk_app LOGIN PASSWORD '$app'" }
$db = & $psql -h $PgHost -p $PgPort -U $SuperUser -tAc "SELECT 1 FROM pg_database WHERE datname='globalhelpdesk'"
if ($db -ne '1') { & $psql -h $PgHost -p $PgPort -U $SuperUser -c "CREATE DATABASE globalhelpdesk OWNER helpdesk_app ENCODING 'UTF8'" }

$env:PGPASSWORD = $app
& $psql -h $PgHost -p $PgPort -U helpdesk_app -d globalhelpdesk -v ON_ERROR_STOP=1 -q -f (Join-Path $root 'database\globalhelpdesk_schema.sql')

$envFile = Join-Path $root '.env'
if (Test-Path $envFile) { Copy-Item $envFile "$envFile.bak" -Force }
$secret = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$adminPw = -join ((1..14) | ForEach-Object { 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[(Get-Random -Maximum 56)] })
@"
FLASK_ENV=production
PORT=5008
SECRET_KEY=$secret
DATABASE_URL=postgresql+psycopg2://helpdesk_app:$app@${PgHost}:${PgPort}/globalhelpdesk
SESSION_COOKIE_SECURE=0
INITIAL_ADMIN_EMAIL=admin@helpdesk.local
INITIAL_ADMIN_PASSWORD=$adminPw
"@ | Set-Content -Encoding UTF8 $envFile
Write-Host "`nDone. Database 'globalhelpdesk' is ready and .env written."
Write-Host "First super admin -> username: admin   password: $adminPw   (change it after first sign-in)"
Write-Host "Start production on port 5008:  .\start_waitress_production.bat"
