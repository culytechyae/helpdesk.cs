# Helpdesk Application - Production Deployment Guide

## Overview
This guide provides complete instructions for deploying the Helpdesk application in production using Waitress WSGI server (recommended for Windows) or Gunicorn (Linux/Unix).

## Production Server Configuration

### ✅ Current Status: PRODUCTION READY
- **Server**: Waitress WSGI Server
- **Host**: 0.0.0.0 (all interfaces)
- **Port**: 5000
- **Threads**: 4
- **Connection Limit**: 1000
- **Status**: Running

## Quick Start

### Windows Production Server
```cmd
# Method 1: Use the production batch file
start_waitress_production.bat

# Method 2: Manual start
python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident="Helpdesk Application" wsgi:app

# Method 3: Using configuration file
python -m waitress --config-file=waitress.conf.py wsgi:app
```

### Linux/Unix Production Server
```bash
# Method 1: Use the production shell script
chmod +x start_waitress_production.sh
./start_waitress_production.sh

# Method 2: Manual start
python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident="Helpdesk Application" wsgi:app
```

## Production Features

### 🔒 Security
- Debug mode disabled
- Production WSGI server (Waitress)
- Secure session configuration
- HTTP-only cookies
- Request size limits

### ⚡ Performance
- 4 worker threads
- Connection pooling
- Request limits (1000 connections)
- Memory management
- Async request handling

### 📊 Monitoring
- Access logs enabled
- Error logs enabled
- Rotating log files
- Performance metrics

### 🔄 Reliability
- Automatic restart on failure
- Graceful shutdown
- Process monitoring
- Health checks

## Configuration Files

### Waitress Configuration (`waitress.conf.py`)
```python
# Server configuration
host = "0.0.0.0"
port = 5000
threads = 4
connection_limit = 1000
cleanup_interval = 30
ident = "Helpdesk Application"
max_request_body_size = 1073741824  # 1GB
buffer_size = 16384
```

### Production Configuration (`production_config.py`)
- Environment-based settings
- Security configurations
- Logging setup
- Database management
- Performance tuning

## Access URLs

### Local Access
- http://localhost:5000
- http://127.0.0.1:5000

### Network Access
- http://YOUR_SERVER_IP:5000
- http://YOUR_DOMAIN:5000 (if configured)

## Windows Service Setup

### Using NSSM (Recommended)
1. Download NSSM from https://nssm.cc/
2. Extract `nssm.exe` to your project directory
3. Run as Administrator:
```cmd
helpdesk_windows_service.bat
```

### Manual Service Installation
```cmd
# Install service
nssm install Helpdesk "python.exe" "-m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident=Helpdesk Application wsgi:app"

# Configure service
nssm set Helpdesk AppDirectory "C:\path\to\helpdesk"
nssm set Helpdesk Description "Helpdesk Application - Production Server"
nssm set Helpdesk Start SERVICE_AUTO_START

# Start service
nssm start Helpdesk
```

### Service Management
```cmd
# Start service
nssm start Helpdesk

# Stop service
nssm stop Helpdesk

# Check status
nssm status Helpdesk

# Remove service
nssm remove Helpdesk confirm
```

## Linux Service Setup

### Systemd Service
1. Copy `helpdesk.service` to `/etc/systemd/system/`
2. Update paths in the service file
3. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable helpdesk
sudo systemctl start helpdesk
sudo systemctl status helpdesk
```

## Environment Configuration

### Environment Variables
```bash
# Production settings
export FLASK_ENV=production
export SECRET_KEY=your-super-secret-production-key
export HOST=0.0.0.0
export PORT=5000
export THREADS=4
export CONNECTION_LIMIT=1000

# Email settings (if using SMTP)
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587
export EMAIL_ADDRESS=your-email@gmail.com
export EMAIL_PASSWORD=your-app-password
```

### Windows Environment Variables
```cmd
set FLASK_ENV=production
set SECRET_KEY=your-super-secret-production-key
set HOST=0.0.0.0
set PORT=5000
set THREADS=4
set CONNECTION_LIMIT=1000
```

## Firewall Configuration

### Windows Firewall
```cmd
# Allow port 5000 (run as Administrator)
netsh advfirewall firewall add rule name="Helpdesk" dir=in action=allow protocol=TCP localport=5000
```

### Linux Firewall (UFW)
```bash
sudo ufw allow 5000
sudo ufw enable
```

### Linux Firewall (iptables)
```bash
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
sudo iptables-save
```

## Reverse Proxy Setup (Recommended)

### Nginx Configuration
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName your-domain.com
    
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/
    
    ErrorLog ${APACHE_LOG_DIR}/helpdesk_error.log
    CustomLog ${APACHE_LOG_DIR}/helpdesk_access.log combined
</VirtualHost>
```

## SSL/HTTPS Setup

### Let's Encrypt with Nginx
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Backup Strategy

### Database Backup
```bash
# Backup all database files
cp helpdesk*.db /backup/location/

# SQLite backup
sqlite3 helpdesk.db ".backup '/backup/helpdesk_$(date +%Y%m%d).db'"
```

### Application Backup
```bash
# Backup application files
tar -czf helpdesk_backup_$(date +%Y%m%d).tar.gz . --exclude=*.db --exclude=logs/*
```

### Automated Backup Script
```bash
#!/bin/bash
BACKUP_DIR="/backup/helpdesk"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup databases
cp helpdesk*.db $BACKUP_DIR/

# Backup application
tar -czf $BACKUP_DIR/helpdesk_app_$DATE.tar.gz . --exclude=*.db --exclude=logs/*

# Clean old backups (keep last 30 days)
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

## Monitoring and Maintenance

### Health Check
- Access http://YOUR_SERVER_IP:5000/login
- Verify all features are working
- Check database connectivity

### Log Monitoring
```bash
# View application logs
tail -f logs/helpdesk.log

# View error logs
tail -f logs/helpdesk_error.log

# View system logs (Linux)
sudo journalctl -u helpdesk -f
```

### Performance Monitoring
```bash
# Check server status
netstat -an | grep :5000

# Monitor CPU and memory
top -p $(pgrep -f waitress)

# Check disk usage
df -h
du -sh logs/
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Find process using port 5000
   netstat -tulpn | grep :5000
   # Kill the process
   kill -9 PID
   ```

2. **Permission Issues**
   ```bash
   # Ensure proper file permissions
   chmod 755 start_waitress_production.sh
   chmod 644 waitress.conf.py
   ```

3. **Service Won't Start**
   ```bash
   # Check service logs
   sudo journalctl -u helpdesk -f
   
   # Test manual start
   python -m waitress --host=0.0.0.0 --port=5000 wsgi:app
   ```

4. **Database Issues**
   ```bash
   # Check database files
   ls -la helpdesk*.db
   
   # Verify database integrity
   sqlite3 helpdesk.db "PRAGMA integrity_check;"
   ```

### Performance Optimization

1. **Increase Threads** (if you have more CPU cores):
   ```bash
   python -m waitress --host=0.0.0.0 --port=5000 --threads=8 --connection-limit=2000 wsgi:app
   ```

2. **Memory Optimization**:
   ```bash
   python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --max-request-body-size=1073741824 wsgi:app
   ```

3. **Load Balancing** (for high traffic):
   - Use multiple instances on different ports
   - Configure Nginx load balancer
   - Use Redis for session storage

## Security Checklist

- [ ] Change default admin password
- [ ] Use strong passwords for all users
- [ ] Configure firewall rules
- [ ] Enable HTTPS/SSL
- [ ] Regular security updates
- [ ] Monitor access logs
- [ ] Backup strategy in place
- [ ] Test disaster recovery

## Support

For issues or questions:
1. Check the logs: `tail -f logs/helpdesk.log`
2. Verify configuration files
3. Test database connectivity
4. Check network connectivity
5. Review system resources

## Quick Commands Reference

### Start Production Server
```bash
# Windows
start_waitress_production.bat

# Linux
./start_waitress_production.sh

# Manual
python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 wsgi:app
```

### Stop Server
```bash
# Press Ctrl+C in terminal
# Or kill process
pkill -f waitress
```

### Check Status
```bash
# Check if running
netstat -an | grep :5000

# Check service status
sudo systemctl status helpdesk
```

### View Logs
```bash
# Application logs
tail -f logs/helpdesk.log

# Error logs
tail -f logs/helpdesk_error.log
```

Your Helpdesk application is now configured for production deployment with Waitress WSGI server! 🚀 