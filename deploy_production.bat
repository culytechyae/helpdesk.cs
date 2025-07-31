@echo off
echo ========================================
echo Helpdesk Application - Production Deployment
echo ========================================
echo.
echo This script will deploy the Helpdesk application for production.
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

echo ✅ Python found
echo.

REM Check if required packages are installed
echo Checking required packages...
python -c "import flask, waitress, openpyxl, reportlab" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install required packages
        pause
        exit /b 1
    )
    echo ✅ Packages installed successfully
) else (
    echo ✅ Required packages are already installed
)

echo.

REM Run production initialization
echo Running production initialization...
python production_start.py
if errorlevel 1 (
    echo ERROR: Production initialization failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo Production Deployment Complete!
echo ========================================
echo.
echo The application is now ready for production.
echo.
echo To start the production server:
echo 1. Run: start_waitress_production.bat
echo 2. Or manually: python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 wsgi:app
echo.
echo Access URLs:
echo - Local: http://localhost:5000
echo - Network: http://YOUR_IP:5000
echo.
echo Admin Login:
echo - Username: admin
echo - Password: admin123
echo.
echo Press any key to start the production server now...
pause

echo.
echo Starting production server...
start_waitress_production.bat 