# Helpdesk Application - Production Deployment Guide

## Overview
This guide explains how to deploy the Helpdesk application in production mode using Gunicorn WSGI server.

## Production Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Production Configuration Files

#### Gunicorn Configuration (`gunicorn.conf.py`)
- **Workers**: 4 worker processes
- **Bind**: 0.0.0.0:5000 (accessible from any IP)
- **Timeout**: 30 seconds
- **Max Requests**: 1000 per worker
- **Logging**: Info level

#### WSGI Entry Point (`wsgi.py`)
- Provides the application object to Gunicorn

### 3. Starting the Application

#### Windows
```bash
# Option 1: Use the batch file
start_production.bat

# Option 2: Manual start
gunicorn -c gunicorn.conf.py wsgi:app
```

#### Linux/Unix
```bash
# Option 1: Use the shell script
chmod +x start_production.sh
./start_production.sh

# Option 2: Manual start
gunicorn -c gunicorn.conf.py wsgi:app
```

### 4. System Service (Linux)

#### Install as System Service
1. Copy `helpdesk.service` to `/etc/systemd/system/`
2. Update the paths in the service file
3. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable helpdesk
sudo systemctl start helpdesk
sudo systemctl status helpdesk
```

#### Service Management
```bash
# Start service
sudo systemctl start helpdesk

# Stop service
sudo systemctl stop helpdesk

# Restart service
sudo systemctl restart helpdesk

# View logs
sudo journalctl -u helpdesk -f
```

### 5. Production Features

#### Security
- Debug mode disabled
- Production-ready WSGI server
- Multiple worker processes for load handling

#### Performance
- 4 worker processes for concurrent requests
- Request limits to prevent memory leaks
- Connection pooling

#### Monitoring
- Access logs enabled
- Error logs enabled
- Process monitoring

### 6. Access URLs

#### Local Access
- http://localhost:5000
- http://127.0.0.1:5000

#### Network Access
- http://YOUR_SERVER_IP:5000
- http://YOUR_DOMAIN:5000 (if configured)

### 7. Environment Variables (Optional)

Create a `.env` file for environment-specific settings:
```
FLASK_ENV=production
SECRET_KEY=your-production-secret-key
DATABASE_URL=sqlite:///helpdesk.db
```

### 8. Reverse Proxy (Recommended)

For production, use a reverse proxy like Nginx:

#### Nginx Configuration Example
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
    }
}
```

### 9. SSL/HTTPS (Recommended)

Use Let's Encrypt or your SSL certificate with Nginx for HTTPS.

### 10. Database Management

The application uses SQLite with automatic database switching:
- Multiple database files (helpdesk.db, helpdesk2.db, etc.)
- Automatic switching when database size reaches 1GB
- Data aggregation across all databases

### 11. Backup Strategy

#### Database Backup
```bash
# Backup all database files
cp helpdesk*.db /backup/location/

# Or use SQLite backup command
sqlite3 helpdesk.db ".backup '/backup/helpdesk_$(date +%Y%m%d).db'"
```

#### Application Backup
```bash
# Backup application files
tar -czf helpdesk_backup_$(date +%Y%m%d).tar.gz . --exclude=*.db
```

### 12. Monitoring and Maintenance

#### Health Check
- Access http://YOUR_SERVER_IP:5000/login
- Verify all features are working

#### Log Monitoring
- Monitor Gunicorn logs for errors
- Check application logs for issues
- Monitor database size and switching

#### Performance Monitoring
- Monitor worker process health
- Check memory usage
- Monitor response times

### 13. Troubleshooting

#### Common Issues

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
   chmod 755 start_production.sh
   chmod 644 gunicorn.conf.py
   ```

3. **Database Issues**
   ```bash
   # Check database files
   ls -la helpdesk*.db
   # Verify database integrity
   sqlite3 helpdesk.db "PRAGMA integrity_check;"
   ```

### 14. Updates and Maintenance

#### Application Updates
1. Stop the service
2. Backup current version
3. Update code
4. Install new dependencies
5. Restart the service

#### Database Maintenance
- Regular backups
- Monitor database sizes
- Check for data integrity

### 15. Security Considerations

- Change default admin password
- Use strong passwords
- Regular security updates
- Firewall configuration
- SSL/TLS encryption
- Regular backups

## Support

For issues or questions:
1. Check the logs: `sudo journalctl -u helpdesk -f`
2. Verify configuration files
3. Test database connectivity
4. Check network connectivity 