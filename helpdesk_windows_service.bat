@echo off
echo ========================================
echo Helpdesk Application - Windows Service
echo ========================================
echo.
echo This script will install the Helpdesk application as a Windows service.
echo.
echo Prerequisites:
echo 1. Download NSSM from https://nssm.cc/
echo 2. Extract nssm.exe to this directory
echo 3. Run this script as Administrator
echo.
echo Press any key to continue...
pause

echo.
echo Installing Helpdesk as Windows Service...
echo.

REM Check if NSSM exists
if not exist "nssm.exe" (
    echo ERROR: nssm.exe not found in current directory
    echo Please download NSSM from https://nssm.cc/ and extract nssm.exe here
    pause
    exit /b 1
)

REM Get current directory
set "APP_DIR=%CD%"
set "PYTHON_PATH=python.exe"
set "APP_ARGS=-m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident=Helpdesk Application wsgi:app"

echo Installing service...
nssm install Helpdesk "%PYTHON_PATH%" "%APP_ARGS%"
if errorlevel 1 (
    echo ERROR: Failed to install service
    pause
    exit /b 1
)

echo Configuring service...
nssm set Helpdesk AppDirectory "%APP_DIR%"
nssm set Helpdesk Description "Helpdesk Application - Production Server"
nssm set Helpdesk Start SERVICE_AUTO_START
nssm set Helpdesk AppStdout "%APP_DIR%\logs\helpdesk.log"
nssm set Helpdesk AppStderr "%APP_DIR%\logs\helpdesk_error.log"

echo Creating logs directory...
if not exist "logs" mkdir logs

echo.
echo Service installed successfully!
echo.
echo To manage the service:
echo - Start:   nssm start Helpdesk
echo - Stop:    nssm stop Helpdesk
echo - Status:  nssm status Helpdesk
echo - Remove:  nssm remove Helpdesk confirm
echo.
echo The service will start automatically on system boot.
echo.
echo Press any key to start the service now...
pause

echo Starting service...
nssm start Helpdesk

echo.
echo Service started! Check status with: nssm status Helpdesk
echo.
pause 