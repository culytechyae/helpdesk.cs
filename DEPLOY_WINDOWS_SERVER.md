# Deploy Global Helpdesk to a Windows Server (via GitHub)

Result: the app runs as a Windows service on **port 5008**, backed by PostgreSQL database **`globalhelpdesk`**,
updated with one command from GitHub.

```
Browser ──► (optional IIS/HTTPS :443) ──► Waitress :5008 ──► Flask app ──► PostgreSQL :5432 (globalhelpdesk)
```

Run every PowerShell command below **as Administrator** on the server, unless noted.

---

## 0. Before you start

| Item | Notes |
|---|---|
| Windows Server 2019/2022 | 4 GB RAM minimum |
| GitHub repo | https://github.com/culytechyae/helpdesk.cs |
| Access | RDP to the server, and a GitHub account/token with read access to the repo |

## 1. Prepare the repository on GitHub (on your PC, once)

1. Make sure no secrets or live data are committed. `.env` and `backups/` are already in `.gitignore`.
   The repo currently contains SQLite files in `instance/` and `__pycache__`; remove them from Git (files stay on your disk):
   ```powershell
   cd D:\helpdesk.cs
   git rm -r --cached instance/*.db __pycache__ logs 2>$null
   Add-Content .gitignore "`ninstance/*.db`nlogs/"
   git add -A
   git commit -m "Multi-tenant helpdesk: PostgreSQL, port 5008, deployment scripts"
   git push origin main
   ```
2. Keep the repository **private**. On the server you will use a *read-only deploy key* or a *fine-grained token*
   (GitHub → Settings → Developer settings → Fine-grained tokens → repo `helpdesk.cs` → **Contents: Read-only**).

## 2. Install the software on the server

```powershell
winget install -e --id Git.Git
winget install -e --id Python.Python.3.13
winget install -e --id PostgreSQL.PostgreSQL.17      # remember the 'postgres' password you set
winget install -e --id NSSM.NSSM                      # runs the app as a service
```
Close and reopen PowerShell so `git`, `python` and `nssm` are on PATH. Check:
```powershell
git --version; python --version; nssm version
```

## 3. Get the code from GitHub

```powershell
New-Item -ItemType Directory -Force C:\apps | Out-Null
cd C:\apps
# HTTPS with a token (paste the token when asked for the password; user name = your GitHub user)
git clone https://github.com/culytechyae/helpdesk.cs.git globalhelpdesk
cd globalhelpdesk
git config credential.helper manager      # remember the token for later updates
```

## 4. Python environment

```powershell
cd C:\apps\globalhelpdesk
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 5. Create the PostgreSQL database `globalhelpdesk`

The script creates the role `helpdesk_app`, the database, applies the schema and writes `.env`
(random `SECRET_KEY`, `DATABASE_URL`, `PORT=5008`):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\database\setup_postgres.ps1
```
It asks for the `postgres` password and a new password for `helpdesk_app`, then prints the **first super admin**
login (`admin` / generated password). Write it down; you must change it at first sign-in.

<details><summary>Manual alternative (psql)</summary>

```powershell
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -c "CREATE ROLE helpdesk_app LOGIN PASSWORD 'STRONG_PASSWORD';"
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -c "CREATE DATABASE globalhelpdesk OWNER helpdesk_app ENCODING 'UTF8';"
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U helpdesk_app -d globalhelpdesk -f database\globalhelpdesk_schema.sql
Copy-Item .env.production.example .env     # then edit DATABASE_URL, SECRET_KEY, INITIAL_ADMIN_PASSWORD
```
</details>

Review `.env` (never commit it). For HTTPS set `SESSION_COOKIE_SECURE=1`; for error e-mails set `ERROR_NOTIFICATION_EMAIL`.

## 6. Test run (foreground)

```powershell
.\deploy\run_production.bat
```
Open `http://localhost:5008` on the server → sign in page loads. Press `Ctrl+C` to stop.

## 7. Install as a Windows service (auto-start, auto-restart)

```powershell
.\deploy\install_service.ps1
```
This registers service **GlobalHelpdesk**, opens firewall port **5008**, writes logs to `logs\service.*.log`, and starts it.
```powershell
Get-Service GlobalHelpdesk              # Running
Invoke-WebRequest http://localhost:5008/login -UseBasicParsing | Select StatusCode
```
Users on your network can now reach `http://<server-ip>:5008`. If the server is behind a cloud firewall, open TCP 5008 there too.

## 8. First-time application setup

1. Sign in at `http://<server>:5008/login` as `admin` and set a new password.
2. **Schools → Add School**: name, logo, colours, first school admin e-mail. Share the school's sign-in link `/s/<slug>`.
3. **Admin Tools → Import Users** and **Import Previous Tickets** (templates are on those pages).
4. **Admin Tools → Email Settings**: SMTP account for notifications.

## 9. Optional: HTTPS with IIS reverse proxy (recommended for the internet)

1. Install IIS, **URL Rewrite** and **Application Request Routing (ARR)**; in ARR → *Server Proxy Settings* tick **Enable proxy**.
2. Create an IIS site bound to `https://helpdesk.yourdomain.com` (install your certificate; free option: win-acme).
3. Add this `web.config` in the site's folder:
   ```xml
   <configuration><system.webServer><rewrite><rules>
     <rule name="proxy" stopProcessing="true">
       <match url="(.*)" />
       <action type="Rewrite" url="http://localhost:5008/{R:1}" />
       <serverVariables>
         <set name="HTTP_X_FORWARDED_PROTO" value="https" />
       </serverVariables>
     </rule>
   </rules></rewrite></system.webServer></configuration>
   ```
   (Allow the server variable `HTTP_X_FORWARDED_PROTO` under URL Rewrite → *View Server Variables*.)
4. Set `SESSION_COOKIE_SECURE=1` in `.env`, restart the service, and close the public firewall rule for 5008
   (`Remove-NetFirewallRule -DisplayName 'Global Helpdesk 5008'`) so only IIS can reach it.

## 10. Updating from GitHub (every release)

On your PC: `git push origin main`. On the server:
```powershell
cd C:\apps\globalhelpdesk
.\deploy\update.ps1
```
It backs up the database (`backups\*.dump`, last 14 kept), pulls the branch, installs dependencies, runs the tests on a
temporary database, restarts the service and checks `/login`. The app upgrades its own database schema on start.

Roll back: `git reset --hard <previous-commit>; Restart-Service GlobalHelpdesk`
(restore data if needed: `pg_restore -U helpdesk_app -d globalhelpdesk --clean backups\<file>.dump`).

## 11. Optional: deploy automatically on every push (GitHub Actions)

Install a **self-hosted runner** on the server (repo → Settings → Actions → Runners → *New self-hosted runner* → Windows;
install it as a service). Then add `.github/workflows/deploy.yml`:

```yaml
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: [self-hosted, windows]
    steps:
      - name: Update production
        shell: powershell
        run: |
          cd C:\apps\globalhelpdesk
          .\deploy\update.ps1
```
The runner service account must be allowed to restart the `GlobalHelpdesk` service
(run the runner service as an administrator account, or grant it `sc sdset`/service control rights).

## 12. Operations

| Task | Command |
|---|---|
| Status / restart / stop | `Get-Service GlobalHelpdesk` / `Restart-Service GlobalHelpdesk` / `Stop-Service GlobalHelpdesk` |
| Application log | `Get-Content C:\apps\globalhelpdesk\logs\helpdesk_production.log -Tail 100 -Wait` |
| Service log | `logs\service.err.log` |
| Manual backup | `pg_dump -U helpdesk_app -F c -f backups\manual.dump globalhelpdesk` |
| Nightly backup | `schtasks /Create /TN "Helpdesk backup" /SC DAILY /ST 02:00 /RU SYSTEM /TR "powershell -NoProfile -Command \"$env:PGPASSWORD='<helpdesk_app password>'; & 'C:\Program Files\PostgreSQL\17\bin\pg_dump.exe' -U helpdesk_app -F c -f C:\apps\globalhelpdesk\backups\nightly.dump globalhelpdesk\""` (copy the file off the server) |
| New super admin / reset | `.\.venv\Scripts\flask.exe --app app create-superadmin` |
| Uploaded logos | `static\uploads\schools\` - include in file backups |

## 13. Troubleshooting

| Symptom | Fix |
|---|---|
| Browser can't reach `:5008` | `Get-Service GlobalHelpdesk`; check firewall rule; `netstat -ano | findstr 5008` |
| Service stops immediately | read `logs\service.err.log`; usually a wrong `DATABASE_URL` in `.env` |
| `password authentication failed` | re-run `database\setup_postgres.ps1` (it resets the role password and rewrites `.env`) |
| Login form says "form expired" | cookies blocked, or behind a proxy that changes the host; use the same URL consistently |
| Users logged out after restart | set a fixed `SECRET_KEY` in `.env` (the setup script does) |
| `git pull` asks for a password | create a fine-grained token (Contents: read) and sign in once with `git config credential.helper manager` |

## Security checklist

- [ ] `.env` is not in Git; `SECRET_KEY` is long and random
- [ ] Default/first super-admin password changed
- [ ] HTTPS enabled and `SESSION_COOKIE_SECURE=1`
- [ ] Port 5432 (PostgreSQL) not exposed to the internet
- [ ] Nightly database backups copied off the server
- [ ] Windows updates enabled
