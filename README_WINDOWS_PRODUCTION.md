# Helpdesk Application - Windows Production Deployment Guide

## Overview
This guide explains how to deploy the Helpdesk application in production mode on Windows using either Gunicorn or Waitress WSGI servers.

## Production Setup for Windows

### Method 1: Using Gunicorn (Recommended for Production)

#### 1. Install Dependencies
```cmd
pip install -r requirements.txt
```

#### 2. Start Production Server
```cmd
# Option 1: Use the batch file
start_production.bat

# Option 2: Manual start
python -m gunicorn -c gunicorn.conf.py wsgi:app

# Option 3: Direct command
python -m gunicorn --bind 0.0.0.0:5000 --workers 4 wsgi:app
```

### Method 2: Using Waitress (Windows-Native)

#### 1. Install Dependencies
```cmd
pip install -r requirements_windows.txt
```

#### 2. Start Production Server
```cmd
# Option 1: Use the batch file
start_waitress.bat

# Option 2: Manual start
python -m waitress --host=0.0.0.0 --port=5000 wsgi:app

# Option 3: With more options
python -m waitress --host=0.0.0.0 --port=5000 --threads=4 wsgi:app
```

### Method 3: Using Flask Development Server (Not Recommended for Production)

```cmd
python app.py
```

## Configuration Files

### Gunicorn Configuration (`gunicorn.conf.py`)
```python
bind = "0.0.0.0:5000"
workers = 4
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2
preload_app = True
reload = False
accesslog = "-"
errorlog = "-"
loglevel = "info"
```

### WSGI Entry Point (`wsgi.py`)
```python
from app import app

if __name__ == "__main__":
    app.run()
```

## Access URLs

### Local Access
- http://localhost:5000
- http://127.0.0.1:5000

### Network Access
- http://YOUR_WINDOWS_IP:5000
- http://YOUR_DOMAIN:5000 (if configured)

## Windows Service Setup (Optional)

### Using NSSM (Non-Sucking Service Manager)

1. Download NSSM from: https://nssm.cc/
2. Install as Windows Service:

```cmd
# Install the service
nssm install Helpdesk "python.exe" "-m gunicorn -c gunicorn.conf.py wsgi:app"
nssm set Helpdesk AppDirectory "C:\path\to\helpdesk"
nssm set Helpdesk Description "Helpdesk Application"
nssm set Helpdesk Start SERVICE_AUTO_START

# Start the service
nssm start Helpdesk

# Check status
nssm status Helpdesk
```

### Using Windows Task Scheduler

1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (at startup)
4. Action: Start a program
5. Program: `python.exe`
6. Arguments: `-m gunicorn -c gunicorn.conf.py wsgi:app`
7. Start in: `C:\path\to\helpdesk`

## Production Features

### Security
- Debug mode disabled in production
- Production-ready WSGI server
- Multiple worker processes for load handling

### Performance
- 4 worker processes (Gunicorn) or threads (Waitress)
- Request limits to prevent memory leaks
- Connection pooling

### Monitoring
- Access logs enabled
- Error logs enabled
- Process monitoring

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```cmd
   # Find process using port 5000
   netstat -ano | findstr :5000
   # Kill the process
   taskkill /PID <PID> /F
   ```

2. **Gunicorn Not Found**
   ```cmd
   # Use python -m gunicorn instead
   python -m gunicorn -c gunicorn.conf.py wsgi:app
   ```

3. **Permission Issues**
   ```cmd
   # Run as Administrator if needed
   # Or check Windows Defender/Firewall settings
   ```

4. **Database Issues**
   ```cmd
   # Check database files
   dir helpdesk*.db
   # Verify database integrity
   sqlite3 helpdesk.db "PRAGMA integrity_check;"
   ```

### Performance Optimization

1. **Increase Workers** (if you have more CPU cores):
   ```cmd
   python -m gunicorn --workers 8 --bind 0.0.0.0:5000 wsgi:app
   ```

2. **Use Waitress for Better Windows Performance**:
   ```cmd
   python -m waitress --host=0.0.0.0 --port=5000 --threads=8 wsgi:app
   ```

3. **Memory Optimization**:
   ```cmd
   python -m gunicorn --max-requests 1000 --max-requests-jitter 50 --bind 0.0.0.0:5000 wsgi:app
   ```

## Firewall Configuration

### Windows Firewall
1. Open Windows Defender Firewall
2. Click "Allow an app or feature through Windows Defender Firewall"
3. Click "Change settings"
4. Click "Allow another app"
5. Browse to your Python executable
6. Make sure both Private and Public are checked

### Command Line (Administrator)
```cmd
netsh advfirewall firewall add rule name="Helpdesk" dir=in action=allow protocol=TCP localport=5000
```

## Backup Strategy

### Database Backup
```cmd
# Backup all database files
copy helpdesk*.db C:\backup\helpdesk\

# Or use SQLite backup command
sqlite3 helpdesk.db ".backup 'C:\backup\helpdesk_%date%.db'"
```

### Application Backup
```cmd
# Backup application files
xcopy /E /I /H . C:\backup\helpdesk_app\
```

## Monitoring and Maintenance

### Health Check
- Access http://localhost:5000/login
- Verify all features are working

### Log Monitoring
- Monitor console output for errors
- Check Windows Event Viewer for system issues
- Monitor database size and switching

### Performance Monitoring
- Use Task Manager to monitor CPU and memory usage
- Monitor response times
- Check for memory leaks

## Security Considerations

1. **Change Default Passwords**
   - Admin password: admin123
   - Agent passwords: password123

2. **Network Security**
   - Configure Windows Firewall
   - Use HTTPS in production
   - Regular security updates

3. **File Permissions**
   - Ensure proper file permissions
   - Regular backups
   - Access control

## Quick Start Commands

### Development Mode
```cmd
python app.py
```

### Production Mode (Gunicorn)
```cmd
python -m gunicorn -c gunicorn.conf.py wsgi:app
```

### Production Mode (Waitress)
```cmd
python -m waitress --host=0.0.0.0 --port=5000 wsgi:app
```

### Production Mode (Batch File)
```cmd
start_production.bat
```

## Support

For issues or questions:
1. Check the console output for errors
2. Verify configuration files
3. Test database connectivity
4. Check network connectivity
5. Review Windows Event Viewer logs 