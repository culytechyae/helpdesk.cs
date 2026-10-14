@echo off
REM Starts the helpdesk on port 5008 using the project's virtual environment.
cd /d "%~dp0.."
if not exist ".env" (echo Missing .env - run database\setup_postgres.ps1 first & exit /b 1)
".venv\Scripts\python.exe" -m waitress --host=0.0.0.0 --port=5008 --threads=8 --connection-limit=1000 --ident="Global Helpdesk" wsgi:app
