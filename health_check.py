#!/usr/bin/env python3
"""
Health Check Script for Helpdesk Application
This script checks the health of the production application.
"""

import requests
import sqlite3
import os
import sys
import time
from datetime import datetime

def check_server_connectivity():
    """Check if the server is running and accessible"""
    try:
        response = requests.get('http://localhost:5000/', timeout=5)
        if response.status_code == 200:
            print("✅ Server is running and accessible")
            return True
        else:
            print(f"❌ Server returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Server is not running or not accessible")
        return False
    except requests.exceptions.Timeout:
        print("❌ Server connection timeout")
        return False
    except Exception as e:
        print(f"❌ Server check failed: {str(e)}")
        return False

def check_database_connectivity():
    """Check if databases are accessible"""
    try:
        # Check main database in instance directory
        db_path = 'instance/helpdesk.db'
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM user")
            user_count = cursor.fetchone()[0]
            conn.close()
            print(f"✅ Main database accessible (Users: {user_count})")
        else:
            print("❌ Main database file not found")
            return False
        
        # Check additional databases in instance directory
        for i in range(2, 6):
            db_file = f'instance/helpdesk{i}.db'
            if os.path.exists(db_file):
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM user")
                user_count = cursor.fetchone()[0]
                conn.close()
                print(f"✅ Database {i} accessible (Users: {user_count})")
            else:
                print(f"⚠️  Database {i} not found (this is normal if not used)")
        
        return True
    except Exception as e:
        print(f"❌ Database check failed: {str(e)}")
        return False

def check_file_permissions():
    """Check if required directories and files are accessible"""
    try:
        # Check directories
        required_dirs = ['logs', 'uploads']
        for directory in required_dirs:
            if os.path.exists(directory):
                # Test write permission
                test_file = os.path.join(directory, 'test_write.tmp')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                print(f"✅ Directory '{directory}' is writable")
            else:
                print(f"❌ Directory '{directory}' not found")
                return False
        
        # Check log files
        log_files = ['logs/helpdesk.log', 'logs/helpdesk_error.log']
        for log_file in log_files:
            if os.path.exists(log_file):
                file_size = os.path.getsize(log_file)
                print(f"✅ Log file '{log_file}' exists ({file_size} bytes)")
            else:
                print(f"⚠️  Log file '{log_file}' not found (will be created when needed)")
        
        return True
    except Exception as e:
        print(f"❌ File permission check failed: {str(e)}")
        return False

def check_port_availability():
    """Check if port 5000 is in use"""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 5000))
        sock.close()
        
        if result == 0:
            print("✅ Port 5000 is in use (server is running)")
            return True
        else:
            print("❌ Port 5000 is not in use (server may not be running)")
            return False
    except Exception as e:
        print(f"❌ Port check failed: {str(e)}")
        return False

def check_email_configuration():
    """Check if email settings are configured"""
    try:
        # Import app and create context
        from app import app, EmailSettings
        
        with app.app_context():
            email_settings = EmailSettings.query.filter_by(is_active=True).first()
            if email_settings:
                print(f"✅ Email settings configured (SMTP: {email_settings.smtp_server}:{email_settings.smtp_port})")
                return True
            else:
                print("⚠️  No email settings configured (email notifications will not work)")
                return False
    except Exception as e:
        print(f"❌ Email configuration check failed: {str(e)}")
        return False

def generate_health_report():
    """Generate a comprehensive health report"""
    print("=" * 60)
    print("Helpdesk Application - Health Check Report")
    print("=" * 60)
    print(f"Check time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    checks = [
        ("Server Connectivity", check_server_connectivity),
        ("Database Connectivity", check_database_connectivity),
        ("File Permissions", check_file_permissions),
        ("Port Availability", check_port_availability),
        ("Email Configuration", check_email_configuration)
    ]
    
    results = []
    for check_name, check_function in checks:
        print(f"Checking {check_name}...")
        try:
            result = check_function()
            results.append((check_name, result))
        except Exception as e:
            print(f"❌ {check_name} check failed with exception: {str(e)}")
            results.append((check_name, False))
        print()
    
    # Summary
    print("=" * 60)
    print("HEALTH CHECK SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for check_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{check_name}: {status}")
    
    print()
    print(f"Overall Status: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 All health checks passed! Application is healthy.")
        return True
    elif passed >= total * 0.8:
        print("⚠️  Most health checks passed. Application is mostly healthy.")
        return True
    else:
        print("❌ Multiple health checks failed. Application needs attention.")
        return False

def main():
    """Main health check function"""
    try:
        success = generate_health_report()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nHealth check interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Health check failed with error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 