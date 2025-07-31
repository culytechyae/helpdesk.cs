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
    """Initialize all databases safely"""
    logger = logging.getLogger(__name__)
    
    try:
        from app import app, db, DATABASES, User, generate_password_hash
        
        logger.info("Starting database initialization...")
        
        # Initialize main database
        with app.app_context():
            db.create_all()
            logger.info("Main database initialized successfully")
            
            # Create admin user if it doesn't exist
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@school.com',
                    password_hash=generate_password_hash('admin123'),
                    role='admin'
                )
                db.session.add(admin)
                logger.info("Admin user created")
            
            # Create sample IT agents
            it_agents = User.query.filter_by(role='it_agent').all()
            if len(it_agents) < 3:
                for i in range(3 - len(it_agents)):
                    agent = User(
                        username=f'it_agent_{i+1}',
                        email=f'it_agent_{i+1}@school.com',
                        password_hash=generate_password_hash('password123'),
                        role='it_agent',
                        department='IT'
                    )
                    db.session.add(agent)
                logger.info(f"Created {3 - len(it_agents)} IT agents")
            
            # Create sample FM agents
            fm_agents = User.query.filter_by(role='fm_agent').all()
            if len(fm_agents) < 4:
                for i in range(4 - len(fm_agents)):
                    agent = User(
                        username=f'fm_agent_{i+1}',
                        email=f'fm_agent_{i+1}@school.com',
                        password_hash=generate_password_hash('password123'),
                        role='fm_agent',
                        department='FM'
                    )
                    db.session.add(agent)
                logger.info(f"Created {4 - len(fm_agents)} FM agents")
            
            db.session.commit()
            logger.info("Database initialization completed successfully")
            
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