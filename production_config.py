# Production Configuration for Helpdesk Application

import os
import logging
from logging.handlers import RotatingFileHandler

class ProductionConfig:
    """Production configuration settings"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-super-secret-production-key-change-this')
    DEBUG = False
    TESTING = False
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///helpdesk.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Server Configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    THREADS = int(os.environ.get('THREADS', 4))
    CONNECTION_LIMIT = int(os.environ.get('CONNECTION_LIMIT', 1000))
    
    # Security Configuration
    SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/helpdesk.log')
    ERROR_LOG_FILE = os.environ.get('ERROR_LOG_FILE', 'logs/helpdesk_error.log')
    
    # Database Management
    MAX_DB_SIZE = int(os.environ.get('MAX_DB_SIZE', 1073741824))  # 1GB
    DB_SWITCH_THRESHOLD = float(os.environ.get('DB_SWITCH_THRESHOLD', 0.8))
    
    # Application Settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    
    # Performance Settings
    WORKER_TIMEOUT = 30
    MAX_REQUESTS = 1000
    MAX_REQUESTS_JITTER = 50
    
    # Production-specific settings
    PREFERRED_URL_SCHEME = 'http'  # Change to 'https' if using SSL
    SERVER_NAME = None  # Set to your domain if using a reverse proxy
    
    @staticmethod
    def init_app(app):
        """Initialize production-specific app configuration"""
        # Create necessary directories
        os.makedirs('logs', exist_ok=True)
        os.makedirs('uploads', exist_ok=True)
        
        # Configure logging
        if not app.debug and not app.testing:
            # File handler for general logs
            file_handler = RotatingFileHandler(
                ProductionConfig.LOG_FILE,
                maxBytes=10240000,
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            
            # Error file handler
            error_handler = RotatingFileHandler(
                ProductionConfig.ERROR_LOG_FILE,
                maxBytes=10240000,
                backupCount=10
            )
            error_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            error_handler.setLevel(logging.ERROR)
            app.logger.addHandler(error_handler)
            
            app.logger.setLevel(logging.INFO)
            app.logger.info('Helpdesk production startup')

class DevelopmentConfig:
    """Development configuration settings"""
    
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'dev-secret-key'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///helpdesk.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    
    # Server Configuration
    HOST = '127.0.0.1'
    PORT = 5000
    
    # Logging Configuration
    LOG_LEVEL = 'DEBUG'
    
    @staticmethod
    def init_app(app):
        """Initialize development-specific app configuration"""
        pass

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
} 