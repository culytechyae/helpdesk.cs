# 🚀 Windows Server Production Deployment Guide

## 📋 Step-by-Step Windows Server Deployment

### **Prerequisites**
- Windows Server 2016/2019/2022
- Python 3.7+ installed
- Administrator access
- Internet connection for package installation

---

## **Step 1: Prepare the Server Environment**

### 1.1 **Install Python (if not already installed)**
```cmd
# Download Python from https://www.python.org/downloads/
# Install with "Add Python to PATH" checked
# Verify installation
python --version
```

### 1.2 **Create Application Directory**
```cmd
# Create directory for the application
mkdir C:\HelpdeskApp
cd C:\HelpdeskApp

# Copy your application files to this directory
# (Copy all files from your development machine)
```

### 1.3 **Set Environment Variables**
```cmd
# Open Command Prompt as Administrator
setx FLASK_ENV "production"
setx SECRET_KEY "your-super-secret-production-key-change-this"
setx HOST "0.0.0.0"
setx PORT "5000"
setx THREADS "4"
setx CONNECTION_LIMIT "1000"

# Verify environment variables
echo %FLASK_ENV%
echo %SECRET_KEY%
```

---

## **Step 2: Install Dependencies**

### 2.1 **Install Required Packages**
```cmd
# Navigate to application directory
cd C:\HelpdeskApp

# Install all dependencies
pip install -r requirements.txt

# Verify installations
python -c "import flask, waitress, openpyxl, reportlab, requests"
echo "✅ All packages installed successfully"
```

### 2.2 **Verify Python Path**
```cmd
# Check if Python is in PATH
where python
where pip

# If not found, add Python Scripts to PATH
setx PATH "%PATH%;C:\Users\%USERNAME%\AppData\Roaming\Python\Python313\Scripts"
```

---

## **Step 3: Initialize Production Environment**

### 3.1 **Run Production Initialization**
```cmd
# Navigate to application directory
cd C:\HelpdeskApp

# Run production initialization
python production_start.py
```

**Expected Output:**
```
============================================================
Helpdesk Application - Production Startup
============================================================
Startup time: 2025-07-30 16:25:49

✅ Production initialization completed!

Next steps:
1. Start the production server:
   python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 wsgi:app

2. Or use the batch file:
   start_waitress_production.bat

3. Access the application:
   Local: http://localhost:5000
   Network: http://YOUR_IP:5000

4. Login with admin credentials:
   Username: admin
   Password: admin123
```

### 3.2 **Verify Database Creation**
```cmd
# Check if databases were created
dir *.db

# Expected files:
# helpdesk.db
# helpdesk2.db
# helpdesk3.db
# helpdesk4.db
# helpdesk5.db
```

---

## **Step 4: Configure Windows Firewall**

### 4.1 **Allow Port 5000**
```cmd
# Open Command Prompt as Administrator

# Add firewall rule for port 5000
netsh advfirewall firewall add rule name="Helpdesk Application" dir=in action=allow protocol=TCP localport=5000

# Verify rule was added
netsh advfirewall firewall show rule name="Helpdesk Application"
```

### 4.2 **Allow Application Through Firewall**
```cmd
# Allow Python through firewall
netsh advfirewall firewall add rule name="Python Helpdesk" dir=in action=allow program="C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python313\python.exe"
```

---

## **Step 5: Start Production Server**

### 5.1 **Method 1: Using Batch File (Recommended)**
```cmd
# Navigate to application directory
cd C:\HelpdeskApp

# Start production server
start_waitress_production.bat
```

### 5.2 **Method 2: Manual Start**
```cmd
# Navigate to application directory
cd C:\HelpdeskApp

# Start production server manually
python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident="Helpdesk Application" wsgi:app
```

### 5.3 **Method 3: Using Configuration File**
```cmd
# Navigate to application directory
cd C:\HelpdeskApp

# Start using configuration file
python -m waitress --config-file=waitress.conf.py wsgi:app
```

**Expected Output:**
```
INFO:waitress:Serving on http://0.0.0.0:5000
```

---

## **Step 6: Verify Application is Running**

### 6.1 **Check Server Status**
```cmd
# Check if port 5000 is listening
netstat -an | findstr :5000

# Expected output:
# TCP    0.0.0.0:5000           0.0.0.0:0              LISTENING
```

### 6.2 **Test Local Access**
```cmd
# Test local connectivity
curl http://localhost:5000

# Or open browser and navigate to:
# http://localhost:5000
```

### 6.3 **Test Network Access**
```cmd
# Get server IP address
ipconfig

# Test from another machine:
# http://YOUR_SERVER_IP:5000
```

---

## **Step 7: Configure as Windows Service (Optional)**

### 7.1 **Install NSSM (Non-Sucking Service Manager)**
```cmd
# Download NSSM from https://nssm.cc/
# Extract nssm.exe to C:\HelpdeskApp\

# Install as Windows service
nssm install Helpdesk "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python313\python.exe" "-m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 --ident=\"Helpdesk Application\" wsgi:app"

# Set service directory
nssm set Helpdesk AppDirectory "C:\HelpdeskApp"

# Set service description
nssm set Helpdesk Description "Helpdesk Application - Production Server"

# Set startup type to automatic
nssm set Helpdesk Start SERVICE_AUTO_START

# Start the service
nssm start Helpdesk

# Check service status
nssm status Helpdesk
```

### 7.2 **Service Management Commands**
```cmd
# Start service
nssm start Helpdesk

# Stop service
nssm stop Helpdesk

# Restart service
nssm restart Helpdesk

# Remove service
nssm remove Helpdesk confirm
```

---

## **Step 8: Health Check and Monitoring**

### 8.1 **Run Health Check**
```cmd
# Navigate to application directory
cd C:\HelpdeskApp

# Run health check
python health_check.py
```

**Expected Output:**
```
============================================================
Helpdesk Application - Health Check Report
============================================================
Check time: 2025-07-30 16:30:00

Checking Server Connectivity...
✅ Server is running and accessible

Checking Database Connectivity...
✅ Main database accessible (Users: 8)

Checking File Permissions...
✅ Directory 'logs' is writable
✅ Directory 'uploads' is writable

Checking Port Availability...
✅ Port 5000 is in use (server is running)

Checking Email Configuration...
⚠️  No email settings configured (email notifications will not work)

============================================================
HEALTH CHECK SUMMARY
============================================================
Server Connectivity: ✅ PASS
Database Connectivity: ✅ PASS
File Permissions: ✅ PASS
Port Availability: ✅ PASS
Email Configuration: ⚠️  FAIL

Overall Status: 4/5 checks passed
⚠️  Most health checks passed. Application is mostly healthy.
```

### 8.2 **Monitor Logs**
```cmd
# View application logs
type logs\helpdesk.log

# View error logs
type logs\helpdesk_error.log

# Monitor logs in real-time (if available)
# tail -f logs\helpdesk.log
```

---

## **Step 9: Configure Email (Optional but Recommended)**

### 9.1 **Access Email Settings**
1. Open browser and go to: `http://YOUR_SERVER_IP:5000`
2. Login with: `admin` / `admin123`
3. Go to: **Admin Dashboard** → **Email Settings**

### 9.2 **Configure Email Provider**
1. **Select Provider**: Choose your email provider (Gmail, Outlook, etc.)
2. **Enter Credentials**: 
   - Email address
   - Password (use App Password for Gmail with 2FA)
3. **Test Connection**: Use the "Test Connection" button
4. **Save Settings**: Click "Save Email Settings"

### 9.3 **Test Email Functionality**
1. Go to: **Admin Dashboard** → **Email Settings**
2. Enter a test email address
3. Click "Send Test Email"
4. Check if email is received

---

## **Step 10: Security Configuration**

### 10.1 **Change Default Passwords**
```cmd
# Access the application
# Login as admin: admin / admin123
# Go to: Admin Dashboard → Users
# Change admin password and other user passwords
```

### 10.2 **Configure SSL/HTTPS (Recommended for Production)**
```cmd
# Install reverse proxy (IIS or Nginx)
# Configure SSL certificate
# Set up HTTPS redirection
```

### 10.3 **Regular Backups**
```cmd
# Create backup directory
mkdir C:\HelpdeskApp\backup

# Create backup script
echo @echo off > backup.bat
echo set DATE=%%date:~-4%%-%%date:~3,2%%-%%date:~0,2%% >> backup.bat
echo copy *.db backup\ >> backup.bat
echo copy logs\*.log backup\ >> backup.bat

# Run backup
backup.bat
```

---

## **Step 11: Performance Optimization**

### 11.1 **Adjust Server Settings**
```cmd
# Edit waitress.conf.py for your server specs
# Adjust threads based on CPU cores
# Adjust connection_limit based on memory
```

### 11.2 **Database Optimization**
```cmd
# Monitor database sizes
dir *.db

# Check database usage in admin panel
# Admin Dashboard → Database Management
```

---

## **Step 12: Troubleshooting**

### 12.1 **Common Issues**

#### **Server Won't Start**
```cmd
# Check if port is in use
netstat -an | findstr :5000

# Kill existing processes
taskkill /f /im python.exe

# Check Python installation
python --version
```

#### **Database Errors**
```cmd
# Check database files
dir *.db

# Run health check
python health_check.py

# Reinitialize if needed
python production_start.py
```

#### **Firewall Issues**
```cmd
# Check firewall rules
netsh advfirewall firewall show rule name="Helpdesk Application"

# Add firewall rule if missing
netsh advfirewall firewall add rule name="Helpdesk Application" dir=in action=allow protocol=TCP localport=5000
```

### 12.2 **Log Analysis**
```cmd
# View recent errors
type logs\helpdesk_error.log

# View application logs
type logs\helpdesk.log

# Check Windows Event Log
eventvwr.msc
```

---

## **Step 13: Maintenance and Monitoring**

### 13.1 **Daily Tasks**
```cmd
# Check application health
python health_check.py

# Review logs for errors
type logs\helpdesk_error.log

# Monitor server resources
tasklist | findstr python
```

### 13.2 **Weekly Tasks**
```cmd
# Backup databases
copy *.db backup\

# Clean old logs
del logs\*.log.old

# Check disk space
dir /s C:\HelpdeskApp
```

### 13.3 **Monthly Tasks**
```cmd
# Update Python packages
pip install --upgrade -r requirements.txt

# Test backup restoration
# Review security logs
# Performance analysis
```

---

## **🎉 Success Indicators**

### ✅ **Application Running Successfully**
- ✅ Server accessible at `http://YOUR_SERVER_IP:5000`
- ✅ Admin login works: `admin` / `admin123`
- ✅ Health check passes: `python health_check.py`
- ✅ No critical errors in logs
- ✅ Port 5000 listening: `netstat -an | findstr :5000`

### ✅ **Production Ready**
- ✅ Windows Firewall configured
- ✅ Environment variables set
- ✅ Dependencies installed
- ✅ Database initialized
- ✅ Logs being written
- ✅ Email configured (optional)

---

## **📞 Quick Reference Commands**

### **Start Application**
```cmd
cd C:\HelpdeskApp
start_waitress_production.bat
```

### **Check Status**
```cmd
netstat -an | findstr :5000
python health_check.py
```

### **View Logs**
```cmd
type logs\helpdesk.log
type logs\helpdesk_error.log
```

### **Backup**
```cmd
copy *.db backup\
copy logs\*.log backup\
```

### **Restart**
```cmd
taskkill /f /im python.exe
start_waitress_production.bat
```

---

## **🎯 Final Checklist**

- [ ] **Python 3.7+ installed**
- [ ] **All dependencies installed**
- [ ] **Application files copied to server**
- [ ] **Environment variables set**
- [ ] **Production initialization completed**
- [ ] **Windows Firewall configured**
- [ ] **Server started successfully**
- [ ] **Health check passes**
- [ ] **Local access working**
- [ ] **Network access working**
- [ ] **Admin login working**
- [ ] **Email configured (optional)**
- [ ] **Backup strategy in place**
- [ ] **Monitoring setup**

---

## **🚀 Your Helpdesk Application is Now Production Ready!**

**Access URLs:**
- **Local**: http://localhost:5000
- **Network**: http://YOUR_SERVER_IP:5000
- **Admin Login**: admin / admin123

**Next Steps:**
1. Configure email settings in admin panel
2. Change default passwords
3. Set up regular backups
4. Monitor application health
5. Configure SSL/HTTPS for production use

**🎉 Congratulations! Your Helpdesk application is now running in production on Windows Server with enterprise-grade features and monitoring.** 