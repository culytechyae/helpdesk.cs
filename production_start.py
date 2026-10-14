#!/usr/bin/env python3
"""
Production Startup Script for Helpdesk Application
This script initializes the application for production deployment.
"""

import os
import sys
import logging
from datetime import datetime

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def setup_logging():
    """Setup production logging"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
        handlers=[
            logging.FileHandler('logs/helpdesk_production.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def initialize_databases():
    """Create/upgrade the schema. Importing ``app`` runs the idempotent tenancy migration and, on a
    brand-new database, creates the first super admin (see INITIAL_ADMIN_PASSWORD in the docs).
    No sample users or default passwords are created."""
    logger = logging.getLogger(__name__)
    try:
        from app import app, db  # noqa: F401  (import performs the bootstrap)
        logger.info("Database schema is up to date")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

def initialize_email_templates():
    """Initialize email templates"""
    logger = logging.getLogger(__name__)
    
    try:
        from init_email_templates import init_email_templates
        
        logger.info("Initializing email templates...")
        init_email_templates()
        logger.info("Email templates initialized successfully")
        
    except Exception as e:
        logger.error(f"Email template initialization failed: {str(e)}")
        # Don't raise here as this is not critical for startup

def check_production_requirements():
    """Check production requirements"""
    logger = logging.getLogger(__name__)
    
    # Check required directories
    required_dirs = ['logs', 'uploads']
    for directory in required_dirs:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}")
    
    # Check required files
    required_files = ['app.py', 'wsgi.py']
    for file in required_files:
        if not os.path.exists(file):
            logger.error(f"Required file missing: {file}")
            return False
    
    logger.info("Production requirements check passed")
    return True

def main():
    """Main production startup function"""
    print("=" * 60)
    print("Helpdesk Application - Production Startup")
    print("=" * 60)
    print(f"Startup time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Setup logging
    logger = setup_logging()
    logger.info("Starting production initialization...")
    
    try:
        # Check requirements
        if not check_production_requirements():
            logger.error("Production requirements check failed")
            sys.exit(1)
        
        # Initialize databases
        initialize_databases()
        
        # Initialize email templates
        initialize_email_templates()
        
        logger.info("Production initialization completed successfully!")
        print()
        print("✅ Production initialization completed!")
        print()
        print("Next steps:")
        print("1. Start the production server:")
        print("   python -m waitress --host=0.0.0.0 --port=5000 --threads=4 --connection-limit=1000 wsgi:app")
        print()
        print("2. Or use the batch file:")
        print("   start_waitress_production.bat")
        print()
        print("3. Access the application:")
        print("   Local: http://localhost:5000")
        print("   Network: http://YOUR_IP:5000")
        print()
        print("4. Login with admin credentials:")
        print("   Username: admin")
        print("   Password: admin123")
        print()
        
    except Exception as e:
        logger.error(f"Production initialization failed: {str(e)}")
        print(f"❌ Production initialization failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 