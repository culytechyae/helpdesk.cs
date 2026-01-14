from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import csv
import io
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import sqlite3
import threading
import time
import psutil
from dotenv import load_dotenv
from database_config_postgresql import PostgreSQLConfig, DatabaseManager
import json
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import sys
import traceback
from config import get_config

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    try:
        os.makedirs('logs')
    except PermissionError:
        print("Warning: Could not create logs directory due to permissions")

# Set up file handler for logging
try:
    file_handler = RotatingFileHandler('logs/helpdesk_production.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)
except (PermissionError, OSError) as e:
    print(f"Warning: Could not set up file logging: {e}")
    # Fall back to console logging only
    pass

app = Flask(__name__)

# Add tojson filter for templates
@app.template_filter('tojson')
def tojson_filter(obj):
    """Convert Python object to JSON string for use in JavaScript"""
    return json.dumps(obj)

# Load configuration from config file
config_class = get_config()
app.config.from_object(config_class)

# Additional configuration for production
if app.config['FLASK_ENV'] == 'production':
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_PATH'] = '/'
    app.config['SESSION_REFRESH_EACH_REQUEST'] = False

# Session configuration to prevent logout issues
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # 24 hour session

# Helper function for UTC datetime
def utc_now():
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)

def prevent_redirect_loop(f):
    """Decorator to prevent redirect loops by tracking redirect history"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if we're in a redirect loop
        redirect_count = session.get('redirect_count', 0)
        if redirect_count > 3:
            # Clear session and redirect to login to break the loop
            session.clear()
            logout_user()
            flash('Redirect loop detected. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        # Increment redirect counter
        session['redirect_count'] = redirect_count + 1
        
        # Call the original function
        result = f(*args, **kwargs)
        
        # Reset redirect counter on successful page load
        if isinstance(result, str) or not hasattr(result, 'status_code'):
            session['redirect_count'] = 0
        
        return result
    return decorated_function

# Module permissions configuration
MODULE_PERMISSIONS = {
    'system_management': ['super_admin', 'admin'],
    'database_management': ['super_admin', 'admin'],
    'backup_restore': ['super_admin', 'admin'],
    'user_management': ['super_admin', 'admin'],
    'agent_management': ['super_admin', 'admin'],
    'bulk_user_creation': ['super_admin', 'admin'],
    'email_settings': ['super_admin', 'admin'],
    'email_templates': ['super_admin', 'admin'],
    'summary_reports': ['super_admin', 'admin', 'it_agent', 'fm_agent'],
    'ticket_management': ['super_admin', 'admin', 'it_agent', 'fm_agent'],
    'search_tickets': ['super_admin', 'admin', 'it_agent', 'fm_agent'],
    'search_users': ['super_admin', 'admin'],
    'settings': ['super_admin', 'admin']
}

def check_module_access(module_name):
    """Check if current user has access to a specific module"""
    if not current_user.is_authenticated:
        print(f"DEBUG: User not authenticated for module {module_name}")
        return False
    
    print(f"DEBUG: Checking access for user {current_user.username} (role: {current_user.role}) to module {module_name}")
    print(f"DEBUG: User ID: {current_user.id}, Email: {current_user.email}")
    print(f"DEBUG: User role type: {type(current_user.role)}")
    print(f"DEBUG: User role value: '{current_user.role}'")
    
    # Super admin has access to everything - check both 'super_admin' and 'admin' roles
    if current_user.role in ['super_admin', 'admin']:
        print(f"DEBUG: Super admin/Admin access granted to {module_name}")
        return True
    
    # Check if user's role is allowed for this module
    allowed_roles = MODULE_PERMISSIONS.get(module_name, [])
    print(f"DEBUG: Allowed roles for {module_name}: {allowed_roles}")
    print(f"DEBUG: User role '{current_user.role}' in allowed roles: {current_user.role in allowed_roles}")
    
    base_access = current_user.role in allowed_roles
    
    print(f"DEBUG: Base access: {base_access}")
    
    # For admin users, also check user-specific permissions
    if base_access and current_user.role == 'admin':
        try:
            if current_user.department:
                user_permissions = json.loads(current_user.department)
                if module_name in user_permissions and not user_permissions[module_name]:
                    print(f"DEBUG: Admin user denied access to {module_name} by user-specific permissions")
                    return False
        except (json.JSONDecodeError, KeyError):
            pass
    
    print(f"DEBUG: Final access result: {base_access}")
    return base_access

def require_module_access(module_name):
    """Decorator to require module access"""
    def decorator(f):
        @login_required
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_module_access(module_name):
                flash('Access denied. You do not have permission to access this module.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def handle_route_errors(f):
    """Decorator to handle errors in route functions and send notifications"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            # Log and notify about the error
            log_and_notify_error(e, {
                'route_function': f.__name__,
                'route_args': str(args),
                'route_kwargs': str(kwargs)
            })
            
            # Re-raise the exception to let Flask handle it
            raise
    return decorated_function

def send_error_notification(error_info):
    """Send error notification email to admin"""
    try:
        # Get email settings
        email_settings = EmailSettings.query.filter_by(is_active=True).first()
        if not email_settings:
            logger.error("No email settings configured for error notifications")
            return False
        
        # Create error notification email
        subject = f"🚨 Helpdesk System Error - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <h2 style="color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 10px;">
                    🚨 Helpdesk System Error Alert
                </h2>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #856404;">Error Details</h3>
                    <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Error Type:</strong> {error_info.get('error_type', 'Unknown')}</p>
                    <p><strong>Error Message:</strong> {error_info.get('error_message', 'No message')}</p>
                </div>
                
                <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #495057;">Request Information</h3>
                    <p><strong>URL:</strong> {error_info.get('url', 'Unknown')}</p>
                    <p><strong>Method:</strong> {error_info.get('method', 'Unknown')}</p>
                    <p><strong>User Agent:</strong> {error_info.get('user_agent', 'Unknown')}</p>
                    <p><strong>User:</strong> {error_info.get('user', 'Not logged in')}</p>
                    <p><strong>IP Address:</strong> {error_info.get('ip_address', 'Unknown')}</p>
                </div>
                
                <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #495057;">System Information</h3>
                    <p><strong>Python Version:</strong> {sys.version}</p>
                    <p><strong>Flask Version:</strong> {app.config.get('FLASK_VERSION', 'Unknown')}</p>
                    <p><strong>Database:</strong> PostgreSQL</p>
                </div>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #856404;">Stack Trace</h3>
                    <pre style="background-color: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px;">{error_info.get('traceback', 'No traceback available')}</pre>
                </div>
                
                <div style="background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; padding: 15px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #155724;">Action Required</h3>
                    <p>Please review this error and take appropriate action to resolve the issue. The system may need immediate attention.</p>
                    <ul>
                        <li>Check the application logs for more details</li>
                        <li>Verify database connectivity</li>
                        <li>Check system resources</li>
                        <li>Review recent code changes</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #6c757d; font-size: 12px;">
                    <p>This is an automated error notification from the Helpdesk System.</p>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_settings.email_address
        msg['To'] = ERROR_NOTIFICATION_EMAIL
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP(email_settings.smtp_server, email_settings.smtp_port)
        server.starttls()
        server.login(email_settings.email_address, email_settings.email_password)
        text = msg.as_string()
        server.sendmail(email_settings.email_address, ERROR_NOTIFICATION_EMAIL, text)
        server.quit()
        
        logger.info(f"Error notification email sent to {ERROR_NOTIFICATION_EMAIL}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send error notification email: {str(e)}")
        return False

def log_and_notify_error(error, context=None):
    """Log error and send notification email"""
    try:
        # Get error information
        error_info = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now().isoformat(),
            'url': request.url if request else 'Unknown',
            'method': request.method if request else 'Unknown',
            'user_agent': request.headers.get('User-Agent', 'Unknown') if request else 'Unknown',
            'ip_address': request.remote_addr if request else 'Unknown',
            'user': current_user.username if current_user.is_authenticated else 'Not logged in'
        }
        
        # Add context if provided
        if context:
            error_info.update(context)
        
        # Log the error
        logger.error(f"Application Error: {error_info['error_type']}: {error_info['error_message']}")
        logger.error(f"URL: {error_info['url']}, User: {error_info['user']}, IP: {error_info['ip_address']}")
        logger.error(f"Traceback: {error_info['traceback']}")
        
        # Send notification email
        send_error_notification(error_info)
        
    except Exception as e:
        logger.error(f"Error in error handling: {str(e)}")

# Initialize database manager
db_manager = DatabaseManager()

# Configure Flask-SQLAlchemy with current database
app.config['SQLALCHEMY_DATABASE_URI'] = db_manager.get_current_db_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'  # Better session protection

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'super_admin', 'admin', 'user', 'it_agent', 'fm_agent'
    department = db.Column(db.Text, nullable=True)  # Store module permissions as JSON string - changed to TEXT for larger storage
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    
    def set_password(self, password):
        """Set password hash for user"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password hash for user"""
        return check_password_hash(self.password_hash, password)

class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # 'IT', 'FM'
    priority = db.Column(db.String(20), default='Medium')  # 'Low', 'Medium', 'High', 'Critical'
    status = db.Column(db.String(20), default='Open')  # 'Open', 'Assigned', 'In Progress', 'Resolved', 'Closed'
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)
    
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')

class UserActivityLog(db.Model):
    """User activity logging model"""
    __tablename__ = 'user_activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # 'login', 'logout', 'create_ticket', 'update_ticket', etc.
    details = db.Column(db.Text, nullable=True)  # Additional details about the action
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.Text, nullable=True)  # Browser/device info
    timestamp = db.Column(db.DateTime, default=utc_now)
    
    user = db.relationship('User', backref='activity_logs')

class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)
    
    ticket = db.relationship('Ticket', backref='comments')
    user = db.relationship('User', backref='comments')

class EmailSettings(db.Model):
    __tablename__ = 'email_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(100), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    email_address = db.Column(db.String(120), nullable=False)
    email_password = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

class EmailTemplate(db.Model):
    __tablename__ = 'email_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    template_type = db.Column(db.String(50), nullable=False, unique=True)  # 'ticket_created', 'comment_added', 'status_updated'
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_email_notification(to_email, subject, body):
    """Send email notification using configured SMTP settings"""
    try:
        # Get email settings
        email_settings = EmailSettings.query.filter_by(is_active=True).first()
        if not email_settings:
            print("No email settings configured")
            return False
        
        print(f"Attempting to send email to: {to_email}")
        print(f"Using SMTP server: {email_settings.smtp_server}:{email_settings.smtp_port}")
        print(f"From email: {email_settings.email_address}")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_settings.email_address
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'html'))
        
        # Send email with better error handling
        print("Connecting to SMTP server...")
        server = smtplib.SMTP(email_settings.smtp_server, email_settings.smtp_port)
        print("Starting TLS...")
        server.starttls()
        print("Logging in...")
        server.login(email_settings.email_address, email_settings.email_password)
        print("Sending email...")
        text = msg.as_string()
        server.sendmail(email_settings.email_address, to_email, text)
        print("Email sent successfully!")
        server.quit()
        
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication failed: {str(e)}")
        print("Please check your email and password. For Gmail, you may need to use an App Password.")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"SMTP Connection failed: {str(e)}")
        print("Please check your SMTP server and port settings.")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"Recipient email rejected: {str(e)}")
        return False
    except Exception as e:
        print(f"Email sending failed: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        return False

def get_email_template(template_type):
    """Get email template by type"""
    template = EmailTemplate.query.filter_by(template_type=template_type, is_active=True).first()
    return template

def send_templated_email(to_email, template_type, **kwargs):
    """Send email using template with variable substitution"""
    template = get_email_template(template_type)
    if not template:
        print(f"No template found for type: {template_type}")
        return False
    
    # Replace placeholders in subject and body
    subject = template.subject
    body = template.body
    
    for key, value in kwargs.items():
        placeholder = f"{{{key}}}"
        subject = subject.replace(placeholder, str(value))
        body = body.replace(placeholder, str(value))
    
    return send_email_notification(to_email, subject, body)

def send_email_with_attachment(to_email, subject, body, attachment_file, filename):
    """Send email notification with attachment"""
    try:
        # Get email settings
        email_settings = EmailSettings.query.filter_by(is_active=True).first()
        if not email_settings:
            print("No email settings configured")
            return False
        
        print(f"Attempting to send email with attachment to: {to_email}")
        print(f"Using SMTP server: {email_settings.smtp_server}:{email_settings.smtp_port}")
        print(f"From email: {email_settings.email_address}")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_settings.email_address
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'html'))
        
        # Add attachment
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(attachment_file.read())
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', f'attachment; filename= {filename}')
        msg.attach(attachment)
        
        # Send email with better error handling
        print("Connecting to SMTP server...")
        server = smtplib.SMTP(email_settings.smtp_server, email_settings.smtp_port)
        print("Starting TLS...")
        server.starttls()
        print("Logging in...")
        server.login(email_settings.email_address, email_settings.email_password)
        print("Sending email with attachment...")
        text = msg.as_string()
        server.sendmail(email_settings.email_address, to_email, text)
        print("Email with attachment sent successfully!")
        server.quit()
        
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication failed: {str(e)}")
        print("Please check your email and password. For Gmail, you may need to use an App Password.")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"SMTP Connection failed: {str(e)}")
        print("Please check your SMTP server and port settings.")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"Recipient email rejected: {str(e)}")
        return False
    except Exception as e:
        print(f"Email sending failed: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        return False

def get_all_tickets_from_all_dbs():
    """Get all tickets from current database"""
    try:
        # Use the current database
        tickets = Ticket.query.all()
        return tickets
    except Exception as e:
        print(f"Error reading tickets from database: {str(e)}")
        return []

def send_comprehensive_notifications(ticket, action_type, **kwargs):
    """Send comprehensive notifications to all stakeholders: user, admin, and assigned agent"""
    try:
        # Get all admin users for notifications
        admin_users = User.query.filter(User.role.in_(['admin', 'super_admin'])).all()
        
        # Get ticket creator
        creator = User.query.get(ticket.created_by)
        
        # Get assigned agent
        assigned_agent = User.query.get(ticket.assigned_to) if ticket.assigned_to else None
        
        # Send notifications based on action type
        if action_type == 'ticket_created':
            # Notify all admins
            for admin in admin_users:
                if admin.email:
                    send_templated_email(
                        admin.email,
                        'admin_ticket_created',
                        ticket_id=ticket.id,
                        ticket_title=ticket.title,
                        ticket_category=ticket.category,
                        ticket_priority=ticket.priority,
                        ticket_description=ticket.description,
                        creator_name=creator.username if creator else 'Unknown User',
                        creator_email=creator.email if creator else 'No email',
                        created_date=ticket.created_at.strftime('%Y-%m-%d %H:%M'),
                        assigned_agent=assigned_agent.username if assigned_agent else 'Unassigned'
                    )
            
            # Notify assigned agent
            if assigned_agent and assigned_agent.email:
                send_templated_email(
                    assigned_agent.email,
                    'ticket_assigned_to_agent',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    ticket_description=ticket.description,
                    creator_name=creator.username if creator else 'Unknown User',
                    created_date=ticket.created_at.strftime('%Y-%m-%d %H:%M')
                )
            
            # Notify ticket creator
            if creator and creator.email:
                send_templated_email(
                    creator.email,
                    'ticket_created',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    ticket_status=ticket.status,
                    assigned_agent=assigned_agent.username if assigned_agent else 'Unassigned',
                    created_date=ticket.created_at.strftime('%Y-%m-%d %H:%M')
                )
        
        elif action_type == 'comment_added':
            comment_content = kwargs.get('comment_content', '')
            commenter_name = kwargs.get('commenter_name', 'Unknown User')
            
            # Notify all admins
            for admin in admin_users:
                if admin.email:
                    send_templated_email(
                        admin.email,
                        'admin_comment_added',
                        ticket_id=ticket.id,
                        ticket_title=ticket.title,
                        ticket_category=ticket.category,
                        ticket_priority=ticket.priority,
                        commenter_name=commenter_name,
                        comment_content=comment_content,
                        comment_date=kwargs.get('comment_date', ''),
                        creator_name=creator.username if creator else 'Unknown User',
                        assigned_agent=assigned_agent.username if assigned_agent else 'Unassigned'
                    )
            
            # Notify assigned agent (if different from commenter)
            if assigned_agent and assigned_agent.email and assigned_agent.id != kwargs.get('commenter_id'):
                send_templated_email(
                    assigned_agent.email,
                    'comment_added',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    commenter_name=commenter_name,
                    comment_content=comment_content,
                    comment_date=kwargs.get('comment_date', '')
                )
            
            # Notify ticket creator (if different from commenter)
            if creator and creator.email and creator.id != kwargs.get('commenter_id'):
                send_templated_email(
                    creator.email,
                    'comment_added',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    commenter_name=commenter_name,
                    comment_content=comment_content,
                    comment_date=kwargs.get('comment_date', '')
                )
        
        elif action_type == 'status_updated':
            old_status = kwargs.get('old_status', '')
            new_status = kwargs.get('new_status', '')
            updated_by = kwargs.get('updated_by', 'Unknown User')
            
            # Notify all admins
            for admin in admin_users:
                if admin.email:
                    send_templated_email(
                        admin.email,
                        'admin_status_updated',
                        ticket_id=ticket.id,
                        ticket_title=ticket.title,
                        ticket_category=ticket.category,
                        ticket_priority=ticket.priority,
                        old_status=old_status,
                        new_status=new_status,
                        updated_by=updated_by,
                        updated_date=kwargs.get('updated_date', ''),
                        creator_name=creator.username if creator else 'Unknown User',
                        assigned_agent=assigned_agent.username if assigned_agent else 'Unassigned'
                    )
            
            # Notify assigned agent
            if assigned_agent and assigned_agent.email:
                send_templated_email(
                    assigned_agent.email,
                    'status_updated',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    old_status=old_status,
                    new_status=new_status,
                    updated_by=updated_by,
                    updated_by_role=kwargs.get('updated_by_role', ''),
                    updated_date=kwargs.get('updated_date', '')
                )
            
            # Notify ticket creator
            if creator and creator.email:
                send_templated_email(
                    creator.email,
                    'status_updated',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    old_status=old_status,
                    new_status=new_status,
                    updated_by=updated_by,
                    updated_by_role=kwargs.get('updated_by_role', ''),
                    updated_date=kwargs.get('updated_date', '')
                )
        
        elif action_type == 'ticket_assigned':
            # Get the agent who was assigned (could be different from current assigned_to)
            assigned_agent_id = kwargs.get('assigned_agent_id', ticket.assigned_to)
            assigned_agent_user = User.query.get(assigned_agent_id) if assigned_agent_id else None
            
            # Notify all admins
            for admin in admin_users:
                if admin.email:
                    send_templated_email(
                        admin.email,
                        'admin_ticket_assigned',
                        ticket_id=ticket.id,
                        ticket_title=ticket.title,
                        ticket_category=ticket.category,
                        ticket_priority=ticket.priority,
                        assigned_agent=assigned_agent_user.username if assigned_agent_user else 'Unassigned',
                        assigned_by=kwargs.get('assigned_by', 'System'),
                        assigned_date=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M'),
                        creator_name=creator.username if creator else 'Unknown User'
                    )
            
            # Notify newly assigned agent
            if assigned_agent_user and assigned_agent_user.email:
                send_templated_email(
                    assigned_agent_user.email,
                    'ticket_assigned_to_agent',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    ticket_description=ticket.description,
                    creator_name=creator.username if creator else 'Unknown User',
                    created_date=ticket.created_at.strftime('%Y-%m-%d %H:%M'),
                    assigned_by=kwargs.get('assigned_by', 'System')
                )
            
            # Notify ticket creator
            if creator and creator.email:
                send_templated_email(
                    creator.email,
                    'ticket_assigned',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    assigned_agent=assigned_agent_user.username if assigned_agent_user else 'Unassigned',
                    assigned_date=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')
                )
        
        return True
        
    except Exception as e:
        print(f"Error sending comprehensive notifications: {str(e)}")
        return False

def assign_ticket_round_robin(category):
    """
    Enhanced Round Robin ticket assignment system
    - Supports IT, FM, and HSE categories
    - Skips inactive agents
    - Includes new agents automatically
    - Maintains proper rotation
    - Logs assignment decisions for debugging
    """
    try:
        # Get all active agents for the category
        if category == 'IT':
            agents = User.query.filter_by(role='it_agent', is_active=True).order_by(User.created_at).all()
        elif category == 'FM':
            agents = User.query.filter_by(role='fm_agent', is_active=True).order_by(User.created_at).all()
        elif category == 'HSE':
            agents = User.query.filter_by(role='hse_agent', is_active=True).order_by(User.created_at).all()
        else:
            logger.warning(f"Unknown category '{category}' for round-robin assignment")
            return None
        
        if not agents:
            logger.warning(f"No active agents found for category '{category}'")
            return None
        
        logger.info(f"Round-robin assignment for {category}: Found {len(agents)} active agents")
        
        # Get the last assigned ticket for this category
        last_assigned_ticket = Ticket.query.filter_by(category=category).order_by(Ticket.created_at.desc()).first()
        
        if not last_assigned_ticket or not last_assigned_ticket.assigned_to:
            # First ticket for this category, assign to first agent
            selected_agent = agents[0]
            logger.info(f"First {category} ticket: Assigning to {selected_agent.username}")
            return selected_agent
        
        # Find the last assigned agent in our active agents list
        last_agent_id = last_assigned_ticket.assigned_to
        last_agent_index = -1
        
        for i, agent in enumerate(agents):
            if agent.id == last_agent_id:
                last_agent_index = i
                break
        
        # If last agent is not in active list (inactive or removed), start from first
        if last_agent_index == -1:
            selected_agent = agents[0]
            logger.info(f"Last {category} agent not found in active list: Assigning to {selected_agent.username}")
            return selected_agent
        
        # Get next agent in round-robin order
        next_agent_index = (last_agent_index + 1) % len(agents)
        selected_agent = agents[next_agent_index]
        
        logger.info(f"Round-robin {category}: Last assigned to {agents[last_agent_index].username}, next assigned to {selected_agent.username}")
        
        return selected_agent
        
    except Exception as e:
        logger.error(f"Error in round robin assignment for category '{category}': {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None

def log_user_activity(user_id, username, action, details=None, ip_address=None, user_agent=None):
    """Log user activity to database"""
    try:
        log_entry = UserActivityLog(
            user_id=user_id,
            username=username,
            action=action,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Error logging user activity: {str(e)}")
        # Don't fail the main operation if logging fails
        pass

def get_all_users_from_all_dbs():
    """Get all users from current database"""
    try:
        # Use the current database
        users = User.query.all()
        return users
    except Exception as e:
        print(f"Error reading users from database: {str(e)}")
        return []

def search_tickets(query, category=None, status=None, priority=None):
    """Search tickets with filters"""
    all_tickets = get_all_tickets_from_all_dbs()
    filtered_tickets = []
    
    query = query.lower() if query else ""
    
    for ticket in all_tickets:
        # Text search
        matches_query = (
            query == "" or
            query in ticket.title.lower() or
            query in ticket.description.lower() or
            query in ticket.creator.username.lower() if ticket.creator else False
        )
        
        # Category filter
        matches_category = category is None or ticket.category == category
        
        # Status filter
        matches_status = status is None or ticket.status == status
        
        # Priority filter
        matches_priority = priority is None or ticket.priority == priority
        
        if matches_query and matches_category and matches_status and matches_priority:
            filtered_tickets.append(ticket)
    
    return filtered_tickets

def search_users(query, role=None, department=None, is_active=None):
    """Search users with filters"""
    all_users = get_all_users_from_all_dbs()
    filtered_users = []
    
    query = query.lower() if query else ""
    
    for user in all_users:
        # Text search
        matches_query = (
            query == "" or
            query in user.username.lower() or
            query in user.email.lower() or
            (user.department and query in user.department.lower())
        )
        
        # Role filter
        matches_role = role is None or user.role == role
        
        # Department filter
        matches_department = department is None or user.department == department
        
        # Active status filter
        matches_active = is_active is None or user.is_active == is_active
        
        if matches_query and matches_role and matches_department and matches_active:
            filtered_users.append(user)
    
    return filtered_users

# Routes
@app.route('/')
def index():
    # Prevent redirect loops by checking if user is already authenticated
    if current_user.is_authenticated:
        # Check if user is trying to access root while already logged in
        # This prevents the redirect loop issue
        user_role = current_user.role
        if user_role in ['super_admin', 'admin']:
            return redirect(url_for('admin_dashboard'))
        elif user_role in ['it_agent', 'fm_agent']:
            return redirect(url_for('agent_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    # User not authenticated, show login page
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password) and user.is_active:
            login_user(user, remember=True)  # Make session permanent
            session.permanent = True  # Ensure session is permanent
            
            # Log user login activity
            log_user_activity(
                user_id=user.id,
                username=user.username,
                action='login',
                details=f'User logged in successfully',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Log user logout activity
    log_user_activity(
        user_id=current_user.id,
        username=current_user.username,
        action='logout',
        details=f'User logged out',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'super_admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role in ['it_agent', 'fm_agent']:
        return redirect(url_for('agent_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    tickets = Ticket.query.filter_by(created_by=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('user_dashboard.html', tickets=tickets)

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard with comprehensive statistics"""
    try:
        # Get all tickets for admin view
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
        
        # Get agents for assignment
        it_agents = User.query.filter(
            db.or_(
                db.and_(User.department == 'IT', User.role == 'agent'),
                db.and_(User.role == 'it_agent', User.department.is_(None)),
                db.and_(User.role == 'it_agent', User.department == 'IT')
            )
        ).all()
        
        fm_agents = User.query.filter(
            db.or_(
                db.and_(User.department == 'FM', User.role == 'agent'),
                db.and_(User.role == 'fm_agent', User.department.is_(None)),
                db.and_(User.role == 'fm_agent', User.department == 'Handyman'),
                db.and_(User.role == 'fm_agent', User.department == 'FM')
            )
        ).all()
        
        hse_agents = User.query.filter(
            db.or_(
                db.and_(User.department == 'HSE', User.role == 'agent'),
                db.and_(User.role == 'hse_agent', User.department.is_(None)),
                db.and_(User.role == 'hse_agent', User.department == 'HSE')
            )
        ).all()
        
        return render_template('admin_dashboard.html', 
                             tickets=tickets, 
                             it_agents=it_agents, 
                             fm_agents=fm_agents,
                             hse_agents=hse_agents)
                             
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'error')
        return render_template('error.html', error=str(e))

@app.route('/agent/dashboard')
@login_required
def agent_dashboard():
    if current_user.role not in ['it_agent', 'fm_agent', 'admin', 'super_admin']:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    assigned_tickets = Ticket.query.filter_by(assigned_to=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('agent_dashboard.html', tickets=assigned_tickets)

@app.route('/ticket/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        priority = request.form['priority']
        
        ticket = Ticket(
            title=title,
            description=description,
            category=category,
            priority=priority,
            created_by=current_user.id
        )
        
        # Auto-assign ticket using round-robin
        assigned_agent = assign_ticket_round_robin(category)
        if assigned_agent:
            ticket.assigned_to = assigned_agent.id
        
        db.session.add(ticket)
        db.session.commit()
        
        # Send comprehensive email notifications to all stakeholders
        send_comprehensive_notifications(ticket, 'ticket_created')
        
        # Log ticket creation
        log_user_activity(
            user_id=current_user.id,
            username=current_user.username,
            action='create_ticket',
            details=f'Created ticket: {title}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        flash('Ticket created successfully')
        return redirect(url_for('user_dashboard'))
    
    return render_template('create_ticket.html')

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check if user has access to this ticket
        if current_user.role not in ['admin', 'super_admin', 'it_agent', 'fm_agent'] and ticket.created_by != current_user.id:
            flash('Access denied')
            return redirect(url_for('dashboard'))
        
        # Get agents for assignment (only for admin/super_admin)
        it_agents = []
        fm_agents = []
        hse_agents = []
        if current_user.role in ['admin', 'super_admin']:
            it_agents = User.query.filter_by(role='it_agent', is_active=True).all()
            fm_agents = User.query.filter_by(role='fm_agent', is_active=True).all()
            hse_agents = User.query.filter_by(role='hse_agent', is_active=True).all()
        
        # Debug logging
        logger.info(f"Viewing ticket {ticket_id} for user {current_user.username} (role: {current_user.role})")
        logger.info(f"Ticket creator: {ticket.created_by}, Assigned to: {ticket.assigned_to}")
        
        # Additional debug info
        logger.info(f"Ticket title: {ticket.title}")
        logger.info(f"Ticket status: {ticket.status}")
        logger.info(f"Ticket category: {ticket.category}")
        logger.info(f"Ticket priority: {ticket.priority}")
        logger.info(f"Agents available - IT: {len(it_agents)}, FM: {len(fm_agents)}, HSE: {len(hse_agents)}")
        
        # Ensure assignee is loaded if assigned_to exists but assignee is None
        if ticket.assigned_to and not ticket.assignee:
            try:
                ticket.assignee = User.query.get(ticket.assigned_to)
                if ticket.assignee:
                    logger.debug(f'Manually loaded assignee for ticket {ticket_id}: {ticket.assignee.username}')
            except Exception as assignee_error:
                logger.warning(f'Could not load assignee for ticket {ticket_id}: {str(assignee_error)}')
        
        # Check relationships
        if hasattr(ticket, 'creator') and ticket.creator:
            logger.info(f"Creator username: {ticket.creator.username}")
        else:
            logger.warning(f"Ticket {ticket_id} has no creator relationship")
            
        if hasattr(ticket, 'assignee') and ticket.assignee:
            logger.info(f"Assignee username: {ticket.assignee.username}")
        else:
            logger.info(f"Ticket {ticket_id} has no assignee")
        
        return render_template('view_ticket.html', ticket=ticket, it_agents=it_agents, fm_agents=fm_agents, hse_agents=hse_agents)
        
    except Exception as e:
        logger.error(f"Error viewing ticket {ticket_id}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading ticket: {str(e)}', 'error')
        return render_template('error.html', error=str(e))

@app.route('/ticket/<int:ticket_id>/assign', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    """Assign or reassign ticket to an agent"""
    try:
        if current_user.role not in ['admin', 'super_admin']:
            flash('Access denied. Only administrators can assign tickets.', 'error')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
        ticket = Ticket.query.get_or_404(ticket_id)
        agent_id = request.form.get('agent_id')
        
        if not agent_id:
            # Unassign ticket
            ticket.assigned_to = None
            ticket.status = 'Open'
            flash('Ticket unassigned successfully.', 'success')
        else:
            # Assign ticket to agent
            agent = User.query.get(agent_id)
            if not agent or agent.role not in ['it_agent', 'fm_agent', 'hse_agent']:
                flash('Invalid agent selected.', 'error')
                return redirect(url_for('view_ticket', ticket_id=ticket_id))
            
            # Check if agent is active
            if not agent.is_active:
                flash('Selected agent is inactive and cannot receive tickets.', 'error')
                return redirect(url_for('view_ticket', ticket_id=ticket_id))
            
            # Allow admin to assign HSE tickets to FM agents
            # Standard category-to-agent matching
            if ticket.category == 'IT' and agent.role != 'it_agent':
                flash('IT tickets can only be assigned to IT agents.', 'error')
                return redirect(url_for('view_ticket', ticket_id=ticket_id))
            elif ticket.category == 'FM' and agent.role != 'fm_agent':
                flash('FM tickets can only be assigned to FM agents.', 'error')
                return redirect(url_for('view_ticket', ticket_id=ticket_id))
            elif ticket.category == 'HSE':
                # HSE tickets can be assigned to HSE agents (normal) or FM agents (admin override)
                if agent.role not in ['hse_agent', 'fm_agent']:
                    flash('HSE tickets can only be assigned to HSE or FM agents.', 'error')
                    return redirect(url_for('view_ticket', ticket_id=ticket_id))
            
            ticket.assigned_to = agent.id
            ticket.status = 'Assigned'
            flash(f'Ticket assigned to {agent.username} successfully.', 'success')
        
        db.session.commit()
        
        # Log the assignment action
        log_user_activity(
            user_id=current_user.id,
            username=current_user.username,
            action='assign_ticket',
            details=f'{"Unassigned" if not agent_id else f"Assigned to {agent.username}"} ticket #{ticket_id}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Send notifications for ticket assignment
        if agent_id:
            send_comprehensive_notifications(ticket, 'ticket_assigned', assigned_agent_id=agent_id, assigned_by=current_user.username)
        
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
    except Exception as e:
        logger.error(f"Error assigning ticket {ticket_id}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error assigning ticket: {str(e)}', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/ticket/<int:ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check if user has access to this ticket
        if current_user.role not in ['admin', 'super_admin', 'it_agent', 'fm_agent'] and ticket.created_by != current_user.id:
            flash('Access denied')
            return redirect(url_for('dashboard'))
        
        content = request.form['content']
        comment = Comment(
            ticket_id=ticket_id,
            user_id=current_user.id,
            content=content
        )
        
        db.session.add(comment)
        db.session.commit()
        
        # Log comment addition
        log_user_activity(
            user_id=current_user.id,
            username=current_user.username,
            action='add_comment',
            details=f'Added comment to ticket #{ticket_id}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Send comprehensive email notifications for new comment
        send_comprehensive_notifications(
            ticket, 
            'comment_added',
            comment_content=content,
            commenter_name=current_user.username,
            commenter_id=current_user.id,
            comment_date=comment.created_at.strftime('%Y-%m-%d %H:%M')
        )
        
        flash('Comment added successfully!', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
    except Exception as e:
        logger.error(f"Error adding comment to ticket {ticket_id}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error adding comment: {str(e)}', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/ticket/<int:ticket_id>/status', methods=['POST'])
@login_required
def update_ticket_status(ticket_id):
    """Update ticket status (for agents and admin)"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check if user has access to update this ticket
        if current_user.role not in ['admin', 'super_admin', 'it_agent', 'fm_agent']:
            flash('Access denied. Only agents and administrators can update ticket status.', 'error')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
        # Check if user is assigned to this ticket or is admin
        if current_user.role not in ['admin', 'super_admin'] and ticket.assigned_to != current_user.id:
            flash('Access denied. You can only update tickets assigned to you.', 'error')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
        new_status = request.form.get('status')
        if not new_status:
            flash('Status is required.', 'error')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
        # Validate status transition
        valid_statuses = ['Open', 'In Progress', 'Resolved', 'Closed']
        if new_status not in valid_statuses:
            flash('Invalid status.', 'error')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
        # Update ticket status
        old_status = ticket.status
        ticket.status = new_status
        ticket.updated_at = utc_now()
        
        # If status is 'Closed', set resolved_at timestamp
        if new_status == 'Closed':
            if not hasattr(ticket, 'resolved_at'):
                ticket.resolved_at = utc_now()
        
        db.session.commit()
        
        # Log the status update
        log_user_activity(
            user_id=current_user.id,
            username=current_user.username,
            action='update_ticket_status',
            details=f'Updated ticket #{ticket_id} status from {old_status} to {new_status}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Send notifications for status update
        send_comprehensive_notifications(ticket, 'status_updated', 
                                       old_status=old_status, 
                                       new_status=new_status,
                                       updated_by=current_user.username)
        
        flash(f'Ticket status updated to {new_status} successfully!', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
        
    except Exception as e:
        logger.error(f"Error updating ticket {ticket_id} status: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error updating ticket status: {str(e)}', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/admin/users')
@require_module_access('user_management')
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/tickets')
@require_module_access('ticket_management')
def admin_tickets():
    """Admin tickets page with comprehensive filtering"""
    try:
        # Get filter parameters from request
        # Flask automatically decodes URL-encoded values, but let's be explicit
        status_filter = request.args.get('status', '').strip() if request.args else ''
        category_filter = request.args.get('category', '').strip() if request.args else ''
        priority_filter = request.args.get('priority', '').strip() if request.args else ''
        assigned_to_filter = request.args.get('assigned_to', '').strip() if request.args else ''
        created_by_filter = request.args.get('created_by', '').strip() if request.args else ''
        date_from_filter = request.args.get('date_from', '').strip() if request.args else ''
        date_to_filter = request.args.get('date_to', '').strip() if request.args else ''
        search_filter = request.args.get('search', '').strip() if request.args else ''
        
        # Debug logging
        logger.info(f'=== FILTER DEBUG ===')
        logger.info(f'All request.args: {dict(request.args)}')
        logger.info(f'Status filter (raw): "{status_filter}"')
        logger.info(f'Category filter: "{category_filter}", Priority: "{priority_filter}"')
        print(f'=== FILTER DEBUG ===')
        print(f'Status filter: "{status_filter}"')
        print(f'Category filter: "{category_filter}"')
        print(f'Priority filter: "{priority_filter}"')
        
        # Start with base query
        query = Ticket.query
        total_before_filter = query.count()
        logger.info(f'Total tickets before filter: {total_before_filter}')
        print(f'Total tickets before filter: {total_before_filter}')
        
        # Apply status filter - each filter is independent
        if status_filter:
            # Flask automatically decodes URL-encoded values, but ensure spaces are handled
            # The status_filter should already be decoded by Flask, but handle edge cases
            query = query.filter(Ticket.status == status_filter)
            logger.info(f'Applied status filter: "{status_filter}"')
            print(f'Applied status filter: "{status_filter}"')
            # Verify the filter by checking count
            count_after_status = query.count()
            logger.info(f'Count after status filter: {count_after_status}')
            print(f'Count after status filter: {count_after_status}')
        
        # Apply category filter
        if category_filter:
            query = query.filter(Ticket.category == category_filter)
        
        # Apply priority filter
        if priority_filter:
            query = query.filter(Ticket.priority == priority_filter)
        
        # Apply assigned_to filter
        if assigned_to_filter:
            if assigned_to_filter == 'unassigned':
                query = query.filter(Ticket.assigned_to.is_(None))
            else:
                try:
                    agent_id = int(assigned_to_filter)
                    query = query.filter(Ticket.assigned_to == agent_id)
                except ValueError:
                    pass  # Invalid ID, ignore filter
        
        # Apply created_by filter
        if created_by_filter:
            try:
                creator_id = int(created_by_filter)
                query = query.filter(Ticket.created_by == creator_id)
            except ValueError:
                pass  # Invalid ID, ignore filter
        
        # Apply date range filters
        if date_from_filter:
            try:
                date_from = datetime.strptime(date_from_filter, '%Y-%m-%d')
                query = query.filter(Ticket.created_at >= date_from)
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        if date_to_filter:
            try:
                date_to = datetime.strptime(date_to_filter, '%Y-%m-%d')
                # Include the entire end date
                date_to = date_to.replace(hour=23, minute=59, second=59)
                query = query.filter(Ticket.created_at <= date_to)
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        # Apply search filter (search in title and description)
        if search_filter:
            search_term = f'%{search_filter}%'
            # Try to search by ticket ID if query is numeric
            try:
                ticket_id = int(search_filter)
                # If it's a number, search by ID exactly or as string
                query = query.filter(
                    db.or_(
                        Ticket.title.ilike(search_term),
                        Ticket.description.ilike(search_term),
                        Ticket.id == ticket_id
                    )
                )
            except (ValueError, TypeError):
                # If not numeric, just search title and description
                query = query.filter(
                    db.or_(
                        Ticket.title.ilike(search_term),
                        Ticket.description.ilike(search_term)
                    )
                )
        
        # Order by creation date (newest first)
        query = query.order_by(Ticket.created_at.desc())
        
        # Get count before executing (for debugging)
        filtered_count = query.count()
        logger.info(f'Final filtered ticket count: {filtered_count}')
        print(f'Final filtered ticket count: {filtered_count}')
        
        # Get filtered tickets - execute query explicitly
        try:
            # Use joinedload to eagerly load relationships
            try:
                from sqlalchemy.orm import joinedload
                query = query.options(
                    joinedload(Ticket.creator),
                    joinedload(Ticket.assignee)
                )
            except ImportError:
                pass  # If joinedload not available, continue without it
            
            tickets = list(query.all())  # Convert to list to force evaluation
            
            # Ensure assignee is loaded for tickets that have assigned_to but assignee is None
            for ticket in tickets:
                if ticket.assigned_to and not ticket.assignee:
                    try:
                        ticket.assignee = User.query.get(ticket.assigned_to)
                        if ticket.assignee:
                            logger.debug(f'Manually loaded assignee for ticket {ticket.id}: {ticket.assignee.username}')
                    except Exception as assignee_error:
                        logger.warning(f'Could not load assignee for ticket {ticket.id}: {str(assignee_error)}')
            
            logger.info(f'Retrieved {len(tickets)} tickets after filtering')
            print(f'Retrieved {len(tickets)} tickets after filtering')
            
            # Verify first few ticket statuses if filtering
            if status_filter and tickets:
                first_few_statuses = [t.status for t in tickets[:5]]
                logger.info(f'First 5 ticket statuses: {first_few_statuses}')
                print(f'First 5 ticket statuses: {first_few_statuses}')
                # Compare with the status_filter (Flask already decoded it)
                wrong_statuses = [s for s in first_few_statuses if s != status_filter]
                if wrong_statuses:
                    logger.warning(f'WARNING: Some tickets have wrong status! Expected: "{status_filter}", Got: {wrong_statuses}')
                    print(f'WARNING: Some tickets have wrong status! Expected: "{status_filter}", Got: {wrong_statuses}')
                else:
                    logger.info(f'✓ All ticket statuses match filter: {status_filter}')
                    print(f'✓ All ticket statuses match filter: {status_filter}')
        except Exception as query_error:
            logger.error(f'Error executing query: {str(query_error)}')
            print(f'Error executing query: {str(query_error)}')
            import traceback
            logger.error(traceback.format_exc())
            print(traceback.format_exc())
            # Fallback to unfiltered query
            tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(50).all()
        
        # Get all users for filter dropdowns
        all_users = User.query.filter(User.is_active == True).order_by(User.username).all()
        
        # Get all agents (it_agent, fm_agent, hse_agent) for filter dropdowns
        all_agents = User.query.filter(
            User.role.in_(['it_agent', 'fm_agent', 'hse_agent', 'agent'])
        ).filter(User.is_active == True).order_by(User.username).all()
        
        return render_template('admin_tickets.html', 
                             tickets=tickets,
                             all_users=all_users,
                             all_agents=all_agents)
                             
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f'Error loading tickets: {str(e)}')
        logger.error(f'Traceback: {error_trace}')
        flash(f'Error loading tickets: {str(e)}', 'error')
        # Fallback to basic query with filters still applied if possible
        try:
            status_filter = request.args.get('status', '').strip()
            query = Ticket.query
            if status_filter:
                query = query.filter(Ticket.status == status_filter)
            tickets = query.order_by(Ticket.created_at.desc()).limit(50).all()
        except:
            tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(50).all()
        all_users = User.query.filter(User.is_active == True).order_by(User.username).all()
        all_agents = User.query.filter(
            User.role.in_(['it_agent', 'fm_agent', 'hse_agent', 'agent'])
        ).filter(User.is_active == True).order_by(User.username).all()
        return render_template('admin_tickets.html', 
                             tickets=tickets,
                             all_users=all_users,
                             all_agents=all_agents)

def _get_tickets_by_status(status_filters):
    """Utility to fetch tickets for specific statuses."""
    if isinstance(status_filters, str):
        status_filters = [status_filters]
    try:
        query = Ticket.query.filter(Ticket.status.in_(status_filters))
        query = query.order_by(Ticket.created_at.desc())
        try:
            from sqlalchemy.orm import joinedload
            query = query.options(
                joinedload(Ticket.creator),
                joinedload(Ticket.assignee)
            )
        except (ImportError, Exception) as load_error:
            logger.warning(f'Joinedload unavailable for status view: {str(load_error)}')
        tickets = list(query.all())
        
        # Ensure assignee is loaded for tickets that have assigned_to but assignee is None
        for ticket in tickets:
            if ticket.assigned_to and not ticket.assignee:
                try:
                    ticket.assignee = User.query.get(ticket.assigned_to)
                    if ticket.assignee:
                        logger.debug(f'Manually loaded assignee for ticket {ticket.id}: {ticket.assignee.username}')
                except Exception as assignee_error:
                    logger.warning(f'Could not load assignee for ticket {ticket.id}: {str(assignee_error)}')
        
        logger.info(f'Loaded {len(tickets)} tickets for statuses {status_filters}')
        return tickets
    except Exception as e:
        logger.error(f'Error fetching tickets for statuses {status_filters}: {str(e)}')
        logger.error(traceback.format_exc())
        return []

def _render_status_view(status_filters, page_title, description, empty_message=None):
    """Render common status-based ticket view."""
    status_list = status_filters if isinstance(status_filters, list) else [status_filters]
    tickets = _get_tickets_by_status(status_list)
    try:
        all_agents = User.query.filter(
            User.role.in_(['it_agent', 'fm_agent', 'hse_agent', 'agent'])
        ).filter(User.is_active == True).order_by(User.username).all()
    except Exception as agent_error:
        logger.error(f'Error loading agents for status view: {str(agent_error)}')
        all_agents = []
    if not empty_message:
        empty_message = "No tickets match the selected status."
    return render_template(
        'admin_ticket_status.html',
        page_title=page_title,
        status_filters=status_list,
        status_description=description,
        empty_message=empty_message,
        tickets=tickets,
        all_agents=all_agents
    )

@app.route('/admin/tickets/open')
@require_module_access('ticket_management')
def admin_open_tickets():
    """View of open tickets awaiting action."""
    return _render_status_view(
        status_filters=['Open'],
        page_title='Open Tickets',
        description='Tickets that have not yet been assigned or started.',
        empty_message='No open tickets found. Great job!'
    )

@app.route('/admin/tickets/pending')
@require_module_access('ticket_management')
def admin_pending_tickets():
    """View of tickets currently in progress or awaiting resolution."""
    pending_statuses = ['Assigned', 'In Progress']
    return _render_status_view(
        status_filters=pending_statuses,
        page_title='Pending Tickets',
        description='Tickets that are assigned or currently in progress.',
        empty_message='No pending tickets at the moment.'
    )

@app.route('/admin/tickets/closed')
@require_module_access('ticket_management')
def admin_closed_tickets():
    """View of tickets that have been resolved or closed."""
    closed_statuses = ['Resolved', 'Closed']
    return _render_status_view(
        status_filters=closed_statuses,
        page_title='Closed Tickets',
        description='Tickets that have been completed or closed out.',
        empty_message='No closed tickets recorded yet.'
    )

@app.route('/admin/system_management')
@require_module_access('system_management')
def admin_system_management():
    """System management page with comprehensive system information and monitoring"""
    try:
        import platform
        import psutil
        import os
        from datetime import datetime
        
        # Get system information
        try:
            uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
            uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h"
        except:
            uptime_str = "Unknown"
            
        # Get disk usage (handle Windows vs Unix paths)
        try:
            if platform.system() == 'Windows':
                disk_usage = psutil.disk_usage('C:\\')
            else:
                disk_usage = psutil.disk_usage('/')
            
            disk_total = disk_usage.total
            disk_used = disk_usage.used
            disk_free = disk_usage.free
            disk_percent = disk_usage.percent
        except:
            disk_total = disk_used = disk_free = disk_percent = 0
            
        system_info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'hostname': platform.node(),
            'uptime': uptime_str,
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'memory_percent': psutil.virtual_memory().percent,
            'disk_total': disk_total,
            'disk_used': disk_used,
            'disk_free': disk_free,
            'disk_percent': disk_percent
        }
        
        # Get application statistics
        app_stats = {
            'total_users': User.query.count(),
            'total_tickets': Ticket.query.count(),
            'active_tickets': Ticket.query.filter(Ticket.status.in_(['Open', 'Assigned', 'In Progress'])).count(),
            'resolved_tickets': Ticket.query.filter(Ticket.status.in_(['Resolved', 'Closed'])).count(),
            'total_comments': Comment.query.count() if hasattr(app, 'Comment') else 0,
            'database_size': 'N/A'  # Will be calculated if possible
        }
        
        # Get recent system activities
        recent_activities = []
        try:
            # Get recent user activities (last 10)
            recent_logs = UserActivityLog.query.order_by(UserActivityLog.created_at.desc()).limit(10).all()
            for log in recent_logs:
                recent_activities.append({
                    'type': 'user_activity',
                    'description': log.details,
                    'user': log.username,
                    'timestamp': log.created_at,
                    'ip_address': log.ip_address
                })
        except:
            pass
        
        # Get recent tickets (last 5)
        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(5).all()
        for ticket in recent_tickets:
            creator = User.query.get(ticket.created_by)
            recent_activities.append({
                'type': 'ticket_created',
                'description': f'Ticket #{ticket.id}: {ticket.title}',
                'user': creator.username if creator else 'Unknown',
                'timestamp': ticket.created_at,
                'status': ticket.status
            })
        
        # Sort activities by timestamp
        recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Get system health status
        system_health = {
            'cpu_healthy': system_info['cpu_percent'] < 80,
            'memory_healthy': system_info['memory_percent'] < 85,
            'disk_healthy': system_info['disk_percent'] < 90,
            'overall_status': 'Healthy'
        }
        
        # Determine overall status
        if not all([system_health['cpu_healthy'], system_health['memory_healthy'], system_health['disk_healthy']]):
            system_health['overall_status'] = 'Warning'
        if system_info['cpu_percent'] > 95 or system_info['memory_percent'] > 95 or system_info['disk_percent'] > 95:
            system_health['overall_status'] = 'Critical'
        
        return render_template('admin_system_management.html', 
                             system_info=system_info,
                             app_stats=app_stats,
                             recent_activities=recent_activities,
                             system_health=system_health)
                             
    except Exception as e:
        logger.error(f"Error in system management: {str(e)}")
        # Return basic template with error handling
        return render_template('admin_system_management.html', 
                             system_info={},
                             app_stats={},
                             recent_activities=[],
                             system_health={'overall_status': 'Error'})

@app.route('/admin/system_restart', methods=['POST'])
@require_module_access('system_management')
def system_restart():
    """Restart the system (placeholder for actual implementation)"""
    try:
        flash('System restart initiated. This is a placeholder function.', 'info')
        return jsonify({'success': True, 'message': 'System restart initiated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/system_troubleshoot', methods=['POST'])
@require_module_access('system_management')
def system_troubleshoot():
    """Run system troubleshooting (placeholder for actual implementation)"""
    try:
        flash('System troubleshooting completed. This is a placeholder function.', 'info')
        return jsonify({'success': True, 'message': 'Troubleshooting completed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/fix_database', methods=['POST'])
@require_module_access('system_management')
def fix_database():
    """Fix database issues (placeholder for actual implementation)"""
    try:
        flash('Database fix completed. This is a placeholder function.', 'info')
        return jsonify({'success': True, 'message': 'Database fix completed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/backup_database', methods=['POST'])
@require_module_access('system_management')
def backup_database():
    """Create database backup (placeholder for actual implementation)"""
    try:
        flash('Database backup initiated. This is a placeholder function.', 'info')
        return jsonify({'success': True, 'message': 'Database backup initiated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/clear_cache', methods=['POST'])
@require_module_access('system_management')
def clear_cache():
    """Clear system cache (placeholder for actual implementation)"""
    try:
        flash('System cache cleared. This is a placeholder function.', 'info')
        return jsonify({'success': True, 'message': 'Cache cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/refresh_stats', methods=['POST'])
@require_module_access('system_management')
def refresh_stats():
    """Refresh system statistics"""
    try:
        flash('System statistics refreshed.', 'success')
        return jsonify({'success': True, 'message': 'Statistics refreshed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/database_management')
@require_module_access('database_management')
def admin_database_management():
    db_info = db_manager.get_database_info()
    return render_template('admin_database_management.html', db_info=db_info)

@app.route('/admin/backup_restore')
@require_module_access('backup_restore')
def admin_backup_restore():
    return render_template('admin_backup_restore.html')

@app.route('/admin/agent_management')
@require_module_access('agent_management')
def admin_agent_management():
    """Enhanced agent management with comprehensive statistics and round-robin tracking"""
    try:
        # Get all agents by category
        it_agents = User.query.filter_by(role='it_agent', is_active=True).all()
        fm_agents = User.query.filter_by(role='fm_agent', is_active=True).all()
        hse_agents = User.query.filter_by(role='hse_agent', is_active=True).all()
        
        # Get inactive agents
        inactive_it_agents = User.query.filter_by(role='it_agent', is_active=False).all()
        inactive_fm_agents = User.query.filter_by(role='fm_agent', is_active=False).all()
        inactive_hse_agents = User.query.filter_by(role='hse_agent', is_active=False).all()
        
        # Enhance agents with statistics
        def enhance_agent_with_stats(agent):
            """Add statistics directly to agent object for template compatibility"""
            # Count assigned tickets
            agent.assigned_tickets_count = Ticket.query.filter_by(assigned_to=agent.id).count()
            
            # Get last assignment date
            last_assignment = Ticket.query.filter_by(assigned_to=agent.id).order_by(Ticket.created_at.desc()).first()
            agent.last_assignment = last_assignment.created_at if last_assignment else None
            
            # Count active tickets (Open, Assigned, In Progress)
            agent.active_tickets_count = Ticket.query.filter(
                Ticket.assigned_to == agent.id,
                Ticket.status.in_(['Open', 'Assigned', 'In Progress'])
            ).count()
            
            # Count resolved tickets
            agent.resolved_tickets_count = Ticket.query.filter(
                Ticket.assigned_to == agent.id,
                Ticket.status.in_(['Resolved', 'Closed'])
            ).count()
            
            # Calculate average resolution time
            resolved_tickets_with_time = Ticket.query.filter(
                Ticket.assigned_to == agent.id,
                Ticket.status.in_(['Resolved', 'Closed']),
                Ticket.updated_at.isnot(None)
            ).all()
            
            total_resolution_time = 0
            count_with_time = 0
            for ticket in resolved_tickets_with_time:
                if ticket.created_at and ticket.updated_at:
                    resolution_time = (ticket.updated_at - ticket.created_at).total_seconds() / 3600  # hours
                    total_resolution_time += resolution_time
                    count_with_time += 1
            
            agent.avg_resolution_time = total_resolution_time / count_with_time if count_with_time > 0 else 0
            
            return agent
        
        # Enhance all agents with statistics
        it_agents = [enhance_agent_with_stats(agent) for agent in it_agents]
        fm_agents = [enhance_agent_with_stats(agent) for agent in fm_agents]
        hse_agents = [enhance_agent_with_stats(agent) for agent in hse_agents]
        
        # Get round-robin assignment info
        def get_round_robin_info(category):
            """Get round-robin assignment information for a category"""
            if category == 'IT':
                agents = it_agents
            elif category == 'FM':
                agents = fm_agents
            elif category == 'HSE':
                agents = hse_agents
            else:
                return None
            
            if not agents:
                return None
            
            # Get the last assigned ticket for this category
            last_assigned_ticket = Ticket.query.filter_by(category=category).order_by(Ticket.created_at.desc()).first()
            
            if not last_assigned_ticket or not last_assigned_ticket.assigned_to:
                return {
                    'next_agent': agents[0].username if agents else 'None',
                    'last_assigned': 'None',
                    'rotation_order': [agent.username for agent in agents]
                }
            
            # Find the last assigned agent
            last_agent_id = last_assigned_ticket.assigned_to
            last_agent_index = -1
            
            for i, agent in enumerate(agents):
                if agent.id == last_agent_id:
                    last_agent_index = i
                    break
            
            # If last agent is not in active list, start from first
            if last_agent_index == -1:
                next_agent_index = 0
            else:
                next_agent_index = (last_agent_index + 1) % len(agents)
            
            return {
                'next_agent': agents[next_agent_index].username if agents else 'None',
                'last_assigned': agents[last_agent_index].username if last_agent_index >= 0 else 'None',
                'rotation_order': [agent.username for agent in agents]
            }
        
        round_robin_info = {
            'IT': get_round_robin_info('IT'),
            'FM': get_round_robin_info('FM'),
            'HSE': get_round_robin_info('HSE')
        }
        
        # Calculate totals for template
        total_agents = len(it_agents) + len(fm_agents) + len(hse_agents)
        total_active = len(it_agents) + len(fm_agents) + len(hse_agents)
        it_agents_active = len(it_agents)
        fm_agents_active = len(fm_agents)
        hse_agents_active = len(hse_agents)
        
        return render_template('admin_agent_management.html', 
                             it_agents=it_agents,
                             fm_agents=fm_agents,
                             hse_agents=hse_agents,
                             inactive_it_agents=inactive_it_agents,
                             inactive_fm_agents=inactive_fm_agents,
                             inactive_hse_agents=inactive_hse_agents,
                             round_robin_info=round_robin_info,
                             total_agents=total_agents,
                             total_active=total_active,
                             it_agents_active=it_agents_active,
                             fm_agents_active=fm_agents_active,
                             hse_agents_active=hse_agents_active)
                             
    except Exception as e:
        logger.error(f"Error loading agent management: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading agent management: {str(e)}', 'error')
        return render_template('error.html', error=str(e))
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading agent management: {str(e)}', 'error')
        return render_template('error.html', error=str(e))

@app.route('/admin/round_robin_status')
@require_module_access('agent_management')
def round_robin_status():
    """Get current round-robin assignment status for all categories"""
    try:
        # Get active agents by category
        it_agents = User.query.filter_by(role='it_agent', is_active=True).order_by(User.created_at).all()
        fm_agents = User.query.filter_by(role='fm_agent', is_active=True).order_by(User.created_at).all()
        hse_agents = User.query.filter_by(role='hse_agent', is_active=True).order_by(User.created_at).all()
        
        def get_category_status(category, agents):
            if not agents:
                return {
                    'category': category,
                    'active_agents': 0,
                    'next_agent': 'None',
                    'last_assigned': 'None',
                    'rotation_order': [],
                    'unassigned_tickets': 0
                }
            
            # Get unassigned tickets for this category
            unassigned_tickets = Ticket.query.filter_by(
                category=category, 
                assigned_to=None,
                status='Open'
            ).count()
            
            # Get the last assigned ticket for this category
            last_assigned_ticket = Ticket.query.filter_by(category=category).order_by(Ticket.created_at.desc()).first()
            
            if not last_assigned_ticket or not last_assigned_ticket.assigned_to:
                return {
                    'category': category,
                    'active_agents': len(agents),
                    'next_agent': agents[0].username if agents else 'None',
                    'last_assigned': 'None',
                    'rotation_order': [agent.username for agent in agents],
                    'unassigned_tickets': unassigned_tickets
                }
            
            # Find the last assigned agent
            last_agent_id = last_assigned_ticket.assigned_to
            last_agent_index = -1
            
            for i, agent in enumerate(agents):
                if agent.id == last_agent_id:
                    last_agent_index = i
                    break
            
            # If last agent is not in active list, start from first
            if last_agent_index == -1:
                next_agent_index = 0
            else:
                next_agent_index = (last_agent_index + 1) % len(agents)
            
            return {
                'category': category,
                'active_agents': len(agents),
                'next_agent': agents[next_agent_index].username if agents else 'None',
                'last_assigned': agents[last_agent_index].username if last_agent_index >= 0 else 'None',
                'rotation_order': [agent.username for agent in agents],
                'unassigned_tickets': unassigned_tickets
            }
        
        status = {
            'IT': get_category_status('IT', it_agents),
            'FM': get_category_status('FM', fm_agents),
            'HSE': get_category_status('HSE', hse_agents)
        }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting round-robin status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/force_round_robin/<category>', methods=['POST'])
@require_module_access('agent_management')
def force_round_robin_assignment(category):
    """Force round-robin assignment for unassigned tickets in a category"""
    try:
        if category not in ['IT', 'FM', 'HSE']:
            return jsonify({'success': False, 'error': 'Invalid category'})
        
        # Get unassigned tickets for this category
        unassigned_tickets = Ticket.query.filter_by(
            category=category, 
            assigned_to=None,
            status='Open'
        ).all()
        
        if not unassigned_tickets:
            return jsonify({'success': True, 'message': f'No unassigned {category} tickets found'})
        
        # Get next agent using round-robin
        next_agent = assign_ticket_round_robin(category)
        if not next_agent:
            return jsonify({'success': False, 'error': f'No active agents found for {category}'})
        
        # Assign all unassigned tickets to the next agent
        assigned_count = 0
        for ticket in unassigned_tickets:
            ticket.assigned_to = next_agent.id
            ticket.status = 'Assigned'
            ticket.updated_at = utc_now()
            assigned_count += 1
        
        db.session.commit()
        
        # Log the bulk assignment
        log_user_activity(
            user_id=current_user.id,
            username=current_user.username,
            action='force_round_robin',
            details=f'Force assigned {assigned_count} {category} tickets to {next_agent.username}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True, 
            'message': f'Assigned {assigned_count} {category} tickets to {next_agent.username}',
            'assigned_count': assigned_count,
            'assigned_to': next_agent.username
        })
        
    except Exception as e:
        logger.error(f"Error forcing round-robin assignment for {category}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/email_settings')
@require_module_access('email_settings')
def admin_email_settings():
    email_settings = EmailSettings.query.first()
    return render_template('admin_email_settings.html', email_settings=email_settings)

@app.route('/admin/update_email_settings', methods=['POST'])
@require_module_access('email_settings')
def update_email_settings():
    """Update email settings"""
    try:
        smtp_server = request.form.get('smtp_server')
        smtp_port = request.form.get('smtp_port')
        email_address = request.form.get('email_address')
        email_password = request.form.get('email_password')
        
        if not all([smtp_server, smtp_port, email_address, email_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('admin_email_settings'))
        
        # Check if email settings exist
        email_settings = EmailSettings.query.first()
        if email_settings:
            # Update existing settings
            email_settings.smtp_server = smtp_server
            email_settings.smtp_port = int(smtp_port)
            email_settings.email_address = email_address
            email_settings.email_password = email_password
            email_settings.updated_at = utc_now()
        else:
            # Create new settings
            email_settings = EmailSettings(
                smtp_server=smtp_server,
                smtp_port=int(smtp_port),
                email_address=email_address,
                email_password=email_password
            )
            db.session.add(email_settings)
        
        db.session.commit()
        flash('Email settings updated successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating email settings: {str(e)}', 'error')
    
    return redirect(url_for('admin_email_settings'))

@app.route('/admin/email_templates')
@require_module_access('email_templates')
def admin_email_templates():
    templates = EmailTemplate.query.all()
    return render_template('admin_email_templates.html', templates=templates)

@app.route('/admin/update_email_template', methods=['POST'])
@require_module_access('email_templates')
def update_email_template():
    """Update email template"""
    try:
        template_type = request.form.get('template_type')
        subject = request.form.get('subject')
        body = request.form.get('body')
        
        if not all([template_type, subject, body]):
            flash('All fields are required', 'error')
            return redirect(url_for('admin_email_templates'))
        
        # Check if template exists
        template = EmailTemplate.query.filter_by(template_type=template_type).first()
        if template:
            # Update existing template
            template.subject = subject
            template.body = body
            template.updated_at = utc_now()
        else:
            # Create new template
            template = EmailTemplate(
                template_type=template_type,
                subject=subject,
                body=body
            )
            db.session.add(template)
        
        db.session.commit()
        flash(f'Email template "{template_type}" updated successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating email template: {str(e)}', 'error')
    
    return redirect(url_for('admin_email_templates'))

@app.route('/admin/get_email_template/<template_type>')
@require_module_access('email_templates')
def get_email_template_route(template_type):
    """Get email template by type for AJAX requests"""
    try:
        template = EmailTemplate.query.filter_by(template_type=template_type).first()
        if template:
            return jsonify({
                'success': True,
                'template': {
                    'subject': template.subject,
                    'body': template.body
                }
            })
        else:
            # Return default template if none exists
            default_templates = {
                'ticket_created': {
                    'subject': 'New Ticket Created - #{ticket_id}',
                    'body': '''<h2>New Ticket Created</h2>
<p>A new ticket has been created in the helpdesk system.</p>
<p><strong>Ticket ID:</strong> #{ticket_id}</p>
<p><strong>Title:</strong> {ticket_title}</p>
<p><strong>Category:</strong> {ticket_category}</p>
<p><strong>Priority:</strong> {ticket_priority}</p>
<p><strong>Status:</strong> {ticket_status}</p>
<p><strong>Assigned Agent:</strong> {assigned_agent}</p>
<p><strong>Created Date:</strong> {created_date}</p>
<p>Please log in to the helpdesk system to view and manage this ticket.</p>'''
                },
                'ticket_assigned_to_agent': {
                    'subject': 'Ticket #{ticket_id} Assigned to You',
                    'body': '''<h2>Ticket Assigned</h2>
<p>A ticket has been assigned to you.</p>
<p><strong>Ticket ID:</strong> #{ticket_id}</p>
<p><strong>Title:</strong> {ticket_title}</p>
<p><strong>Category:</strong> {ticket_category}</p>
<p><strong>Priority:</strong> {ticket_priority}</p>
<p><strong>Status:</strong> {ticket_status}</p>
<p><strong>Assigned Date:</strong> {assigned_date}</p>
<p>Please log in to the helpdesk system to view and manage this ticket.</p>'''
                },
                'comment_added': {
                    'subject': 'New Comment on Ticket: #{ticket_id} - {ticket_title}',
                    'body': '''<h2>New Comment Added</h2>
<p>A new comment has been added to ticket #{ticket_id}.</p>
<p><strong>Commenter:</strong> {commenter_name}</p>
<p><strong>Comment:</strong> {comment_content}</p>
<p><strong>Date:</strong> {comment_date}</p>
<p>Please log in to the helpdesk system to view the full comment and ticket details.</p>'''
                },
                'status_updated': {
                    'subject': 'Ticket #{ticket_id} Status Updated',
                    'body': '''<h2>Ticket Status Updated</h2>
<p>The status of ticket #{ticket_id} has been updated.</p>
<p><strong>Old Status:</strong> {old_status}</p>
<p><strong>New Status:</strong> {new_status}</p>
<p><strong>Updated By:</strong> {updated_by} ({updated_by_role})</p>
<p><strong>Update Date:</strong> {updated_date}</p>
<p>Please log in to the helpdesk system to view the updated ticket details.</p>'''
                }
            }
            
            if template_type in default_templates:
                return jsonify({
                    'success': True,
                    'template': default_templates[template_type]
                })
            else:
                return jsonify({'success': False, 'error': 'Template type not found'})
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/test_email', methods=['POST'])
@require_module_access('email_settings')
def test_email():
    """Test email configuration"""
    try:
        # Get test email address
        test_email = request.form.get('test_email')
        if not test_email:
            flash('Test email address is required', 'error')
            return redirect(url_for('admin_email_settings'))
        
        # Get email settings
        email_settings = EmailSettings.query.filter_by(is_active=True).first()
        if not email_settings:
            flash('No email settings configured', 'error')
            return redirect(url_for('admin_email_settings'))
        
        # Send test email
        subject = 'Helpdesk Email Test'
        body = f'''<h2>Email Test Successful</h2>
<p>This is a test email from your helpdesk system.</p>
<p><strong>SMTP Server:</strong> {email_settings.smtp_server}</p>
<p><strong>Port:</strong> {email_settings.smtp_port}</p>
<p><strong>From Email:</strong> {email_settings.email_address}</p>
<p><strong>Test Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>If you received this email, your email configuration is working correctly!</p>'''
        
        if send_email_notification(test_email, subject, body):
            flash(f'Test email sent successfully to {test_email}', 'success')
        else:
            flash('Failed to send test email. Check your email settings.', 'error')
            
    except Exception as e:
        flash(f'Error testing email: {str(e)}', 'error')
    
    return redirect(url_for('admin_email_settings'))

@app.route('/admin/summary_reports')
@require_module_access('summary_reports')
def admin_summary_reports():
    """Admin summary reports page with comprehensive statistics and charts"""
    # Initialize all variables with defaults to prevent undefined errors
    total_users = 0
    total_tickets = 0
    all_tickets = []
    active_tickets = 0
    resolved_tickets_count = 0
    it_tickets = []
    fm_tickets = []
    hse_tickets = []
    critical_tickets = []
    high_tickets = []
    medium_tickets = []
    low_tickets = []
    open_tickets = []
    assigned_tickets = []
    in_progress_tickets = []
    resolved_tickets = []
    closed_tickets = []
    user_tickets = {}
    agent_tickets = {}
    users = []
    monthly_stats = []
    monthly_labels = []
    monthly_counts = []
    status_data = {}
    priority_data = {}
    category_data = {}
    
    try:
        from datetime import datetime, timedelta
        from collections import defaultdict
        
        # Get overall system statistics
        total_users = User.query.filter(User.is_active == True).count()
        total_tickets = Ticket.query.count()
        all_tickets = Ticket.query.all()
        active_tickets = Ticket.query.filter(Ticket.status.in_(['Open', 'Assigned', 'In Progress'])).count()
        resolved_tickets_count = Ticket.query.filter(Ticket.status.in_(['Resolved', 'Closed'])).count()
        
        # Get tickets by category
        it_tickets = Ticket.query.filter_by(category='IT').all()
        fm_tickets = Ticket.query.filter_by(category='FM').all()
        hse_tickets = Ticket.query.filter_by(category='HSE').all()
        
        # Get tickets by priority
        critical_tickets = Ticket.query.filter_by(priority='Critical').all()
        high_tickets = Ticket.query.filter_by(priority='High').all()
        medium_tickets = Ticket.query.filter_by(priority='Medium').all()
        low_tickets = Ticket.query.filter_by(priority='Low').all()
        
        # Get tickets by status
        open_tickets = Ticket.query.filter_by(status='Open').all()
        assigned_tickets = Ticket.query.filter_by(status='Assigned').all()
        in_progress_tickets = Ticket.query.filter_by(status='In Progress').all()
        resolved_tickets = Ticket.query.filter_by(status='Resolved').all()
        closed_tickets = Ticket.query.filter_by(status='Closed').all()
        
        # Calculate monthly trends (last 12 months)
        monthly_stats = []
        try:
            from dateutil.relativedelta import relativedelta
            use_relativedelta = True
        except ImportError:
            use_relativedelta = False
        
        current_date = datetime.now()
        for i in range(11, -1, -1):  # Last 12 months
            try:
                if use_relativedelta:
                    # More accurate month calculation
                    month_start = (current_date - relativedelta(months=i)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    month_end = (month_start + relativedelta(months=1)) - timedelta(seconds=1)
                else:
                    # Fallback method
                    if i == 0:
                        month_start = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    else:
                        # Calculate months back
                        months_back = i
                        year = current_date.year
                        month = current_date.month
                        for _ in range(months_back):
                            month -= 1
                            if month < 1:
                                month = 12
                                year -= 1
                        month_start = datetime(year, month, 1, 0, 0, 0)
                    
                    # Calculate month end
                    if month_start.month == 12:
                        month_end = datetime(month_start.year + 1, 1, 1, 0, 0, 0) - timedelta(seconds=1)
                    else:
                        month_end = datetime(month_start.year, month_start.month + 1, 1, 0, 0, 0) - timedelta(seconds=1)
                
                month_tickets = Ticket.query.filter(
                    Ticket.created_at >= month_start,
                    Ticket.created_at <= month_end
                ).count()
                
                monthly_stats.append({
                    'month': month_start.strftime('%b %Y'),
                    'count': month_tickets
                })
            except Exception as month_error:
                logger.warning(f'Error calculating month {i}: {str(month_error)}')
                monthly_stats.append({
                    'month': f'Month {i}',
                    'count': 0
                })
        
        # Get user-specific ticket statistics
        user_tickets = {}
        users = []
        try:
            users = User.query.filter(User.is_active == True).all()
            for user in users:
                try:
                    user_created = Ticket.query.filter_by(created_by=user.id).all()
                    if user_created:
                        user_tickets[user.username] = {
                            'total': len(user_created),
                            'assigned': len([t for t in user_created if t.status == 'Assigned']),
                            'in_progress': len([t for t in user_created if t.status == 'In Progress']),
                            'closed': len([t for t in user_created if t.status in ['Resolved', 'Closed']])
                        }
                except Exception as user_error:
                    logger.warning(f'Error processing user {user.id}: {str(user_error)}')
                    continue
        except Exception as users_error:
            logger.error(f'Error loading users: {str(users_error)}')
            users = []
        
        # Get agent-specific ticket statistics
        agent_tickets = {}
        try:
            agents = User.query.filter(
                User.role.in_(['it_agent', 'fm_agent', 'hse_agent', 'agent'])
            ).filter(User.is_active == True).all()
            
            for agent in agents:
                try:
                    agent_assigned = Ticket.query.filter_by(assigned_to=agent.id).all()
                    if agent_assigned:
                        agent_tickets[agent.username] = {
                            'total': len(agent_assigned),
                            'assigned': len([t for t in agent_assigned if t.status == 'Assigned']),
                            'in_progress': len([t for t in agent_assigned if t.status == 'In Progress']),
                            'closed': len([t for t in agent_assigned if t.status in ['Resolved', 'Closed']])
                        }
                except Exception as agent_error:
                    logger.warning(f'Error processing agent {agent.id}: {str(agent_error)}')
                    continue
        except Exception as agents_error:
            logger.error(f'Error loading agents: {str(agents_error)}')
            agent_tickets = {}
        
        # Prepare data for charts
        status_data = {
            'Open': len(open_tickets),
            'Assigned': len(assigned_tickets),
            'In Progress': len(in_progress_tickets),
            'Resolved': len(resolved_tickets),
            'Closed': len(closed_tickets)
        }
        
        priority_data = {
            'Critical': len(critical_tickets),
            'High': len(high_tickets),
            'Medium': len(medium_tickets),
            'Low': len(low_tickets)
        }
        
        category_data = {
            'IT': len(it_tickets),
            'FM': len(fm_tickets),
            'HSE': len(hse_tickets)
        }
        
        # Monthly trend data for chart
        monthly_labels = [stat['month'] for stat in monthly_stats]
        monthly_counts = [stat['count'] for stat in monthly_stats]
        
        return render_template('admin_summary_reports.html',
                             total_users=total_users,
                             total_tickets=total_tickets,
                             all_tickets=all_tickets,
                             active_tickets=active_tickets,
                             resolved_tickets_count=resolved_tickets_count,
                             it_tickets=it_tickets,
                             fm_tickets=fm_tickets,
                             hse_tickets=hse_tickets,
                             critical_tickets=critical_tickets,
                             high_tickets=high_tickets,
                             medium_tickets=medium_tickets,
                             low_tickets=low_tickets,
                             open_tickets=open_tickets,
                             assigned_tickets=assigned_tickets,
                             in_progress_tickets=in_progress_tickets,
                             resolved_tickets=resolved_tickets,
                             closed_tickets=closed_tickets,
                             user_tickets=user_tickets,
                             agent_tickets=agent_tickets,
                             users=users,
                             monthly_stats=monthly_stats,
                             monthly_labels=monthly_labels,
                             monthly_counts=monthly_counts,
                             status_data=status_data,
                             priority_data=priority_data,
                             category_data=category_data)
                             
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f'Error loading summary reports: {str(e)}')
        logger.error(error_trace)
        print(f'ERROR in summary_reports: {str(e)}')
        print(error_trace)
        flash(f'Error loading summary reports: {str(e)}', 'error')
        
        # Fallback with empty data - ensure all variables are defined
        try:
            return render_template('admin_summary_reports.html',
                                 total_users=0,
                                 total_tickets=0,
                                 all_tickets=[],
                                 active_tickets=0,
                                 resolved_tickets_count=0,
                                 it_tickets=[],
                                 fm_tickets=[],
                                 hse_tickets=[],
                                 critical_tickets=[],
                                 high_tickets=[],
                                 medium_tickets=[],
                                 low_tickets=[],
                                 open_tickets=[],
                                 assigned_tickets=[],
                                 in_progress_tickets=[],
                                 resolved_tickets=[],
                                 closed_tickets=[],
                                 user_tickets={},
                                 agent_tickets={},
                                 users=[],
                                 monthly_stats=[],
                                 monthly_labels=[],
                                 monthly_counts=[],
                                 status_data={},
                                 priority_data={},
                                 category_data={})
        except Exception as template_error:
            logger.error(f'Error rendering fallback template: {str(template_error)}')
            return f'<h1>Error Loading Summary Reports</h1><p>{str(e)}</p><p>Check server logs for details.</p>', 500

@app.route('/admin/search_tickets', methods=['GET', 'POST'])
@require_module_access('search_tickets')
def admin_search_tickets():
    """Search tickets page with comprehensive filtering"""
    # Initialize default values first
    tickets = []
    search_query = ''
    category_filter = ''
    status_filter = ''
    priority_filter = ''
    assigned_to_filter = ''
    all_agents = []
    
    # If POST request, redirect to GET with query parameters (RESTful pattern)
    if request.method == 'POST':
        try:
            # Build query string from form data
            params = {}
            if request.form:
                if request.form.get('query', '').strip():
                    params['query'] = request.form.get('query', '').strip()
                if request.form.get('category', '').strip():
                    params['category'] = request.form.get('category', '').strip()
                if request.form.get('status', '').strip():
                    params['status'] = request.form.get('status', '').strip()
                if request.form.get('priority', '').strip():
                    params['priority'] = request.form.get('priority', '').strip()
                if request.form.get('assigned_to', '').strip():
                    params['assigned_to'] = request.form.get('assigned_to', '').strip()
            
            # Redirect to GET with query parameters
            from urllib.parse import urlencode
            query_string = urlencode(params)
            redirect_url = url_for('admin_search_tickets')
            if query_string:
                redirect_url += '?' + query_string
            return redirect(redirect_url)
        except Exception as redirect_error:
            logger.error(f'Error in POST redirect: {str(redirect_error)}')
            # Fall through to GET handling
    
    try:
        # Get filter parameters from GET request
        search_query = request.args.get('query', '').strip() if request.args else ''
        category_filter = request.args.get('category', '').strip() if request.args else ''
        status_filter = request.args.get('status', '').strip() if request.args else ''
        priority_filter = request.args.get('priority', '').strip() if request.args else ''
        assigned_to_filter = request.args.get('assigned_to', '').strip() if request.args else ''
        
        logger.info(f'Search filters - query: "{search_query}", category: "{category_filter}", status: "{status_filter}", priority: "{priority_filter}", assigned_to: "{assigned_to_filter}"')
        
        # Start with base query
        query = Ticket.query
        
        # Apply search query filter (search in title, description, and ticket ID)
        if search_query:
            search_term = f'%{search_query}%'
            # Try to search by ticket ID if query is numeric
            try:
                ticket_id = int(search_query)
                # If it's a number, search by ID exactly or as string
                query = query.filter(
                    db.or_(
                        Ticket.title.ilike(search_term),
                        Ticket.description.ilike(search_term),
                        Ticket.id == ticket_id
                    )
                )
            except (ValueError, TypeError):
                # If not numeric, just search title and description
                query = query.filter(
                    db.or_(
                        Ticket.title.ilike(search_term),
                        Ticket.description.ilike(search_term)
                    )
                )
        
        # Apply category filter
        if category_filter:
            query = query.filter(Ticket.category == category_filter)
        
        # Apply status filter
        if status_filter:
            query = query.filter(Ticket.status == status_filter)
        
        # Apply priority filter
        if priority_filter:
            query = query.filter(Ticket.priority == priority_filter)
        
        # Apply assigned_to filter (agent filter)
        if assigned_to_filter:
            if assigned_to_filter == 'unassigned':
                query = query.filter(Ticket.assigned_to.is_(None))
            else:
                try:
                    agent_id = int(assigned_to_filter)
                    query = query.filter(Ticket.assigned_to == agent_id)
                except (ValueError, TypeError):
                    pass  # Invalid ID, ignore filter
        
        # Order by creation date (newest first)
        query = query.order_by(Ticket.created_at.desc())
        
        # Get filtered tickets - use joinedload to eagerly load relationships
        try:
            from sqlalchemy.orm import joinedload
            query = query.options(
                joinedload(Ticket.creator),
                joinedload(Ticket.assignee)
            )
        except (ImportError, Exception) as load_error:
            logger.warning(f'Could not use joinedload: {str(load_error)}')
            # Continue without joinedload - relationships will be lazy loaded
        
        logger.info(f'Executing query...')
        tickets = list(query.all())  # Convert to list to force evaluation
        
        # Ensure assignee is loaded for tickets that have assigned_to but assignee is None
        for ticket in tickets:
            if ticket.assigned_to and not ticket.assignee:
                try:
                    ticket.assignee = User.query.get(ticket.assigned_to)
                    if ticket.assignee:
                        logger.debug(f'Manually loaded assignee for ticket {ticket.id}: {ticket.assignee.username}')
                except Exception as assignee_error:
                    logger.warning(f'Could not load assignee for ticket {ticket.id}: {str(assignee_error)}')
        
        logger.info(f'Retrieved {len(tickets)} tickets')
        
    except Exception as query_error:
        logger.error(f'Error building query: {str(query_error)}')
        import traceback
        error_trace = traceback.format_exc()
        logger.error(error_trace)
        print(f'ERROR in query: {str(query_error)}')
        print(error_trace)
        tickets = []
    
    try:
        # Get all agents for filter dropdown
        all_agents = User.query.filter(
            User.role.in_(['it_agent', 'fm_agent', 'hse_agent', 'agent'])
        ).filter(User.is_active == True).order_by(User.username).all()
    except Exception as agent_error:
        logger.error(f'Error loading agents: {str(agent_error)}')
        all_agents = []
    
    # Ensure all variables are safe for template
    safe_tickets = tickets if tickets else []
    safe_query = search_query if search_query else ''
    safe_category = category_filter if category_filter else ''
    safe_status = status_filter if status_filter else ''
    safe_priority = priority_filter if priority_filter else ''
    safe_assigned_to = assigned_to_filter if assigned_to_filter else ''
    safe_agents = all_agents if all_agents else []
    
    try:
        logger.info(f'Rendering template with {len(safe_tickets)} tickets, {len(safe_agents)} agents')
        return render_template('admin_search_tickets.html',
                             tickets=safe_tickets,
                             query=safe_query,
                             category=safe_category,
                             status=safe_status,
                             priority=safe_priority,
                             assigned_to=safe_assigned_to,
                             all_agents=safe_agents)
    except Exception as template_error:
        logger.error(f'Error rendering template: {str(template_error)}')
        import traceback
        error_trace = traceback.format_exc()
        logger.error(error_trace)
        print(f'ERROR in template: {str(template_error)}')
        print(error_trace)
        flash(f'Error loading search page: {str(template_error)}', 'error')
        # Return minimal template with safe defaults
        try:
            return render_template('admin_search_tickets.html',
                                 tickets=[],
                                 query='',
                                 category='',
                                 status='',
                                 priority='',
                                 assigned_to='',
                                 all_agents=[])
        except Exception as fallback_error:
            logger.error(f'Error in fallback template: {str(fallback_error)}')
            # Last resort - return simple error page
            return f'''
            <html>
            <head><title>Error</title></head>
            <body>
                <h1>Error Loading Search Page</h1>
                <p>Template error: {str(template_error)}</p>
                <p>Fallback error: {str(fallback_error)}</p>
                <p><a href="{url_for('dashboard')}">Go to Dashboard</a></p>
            </body>
            </html>
            ''', 500

@app.route('/admin/search_users')
@require_module_access('search_users')
def admin_search_users():
    return render_template('admin_search_users.html')

@app.route('/admin/settings')
@require_module_access('settings')
def admin_settings():
    return render_template('admin_settings.html')

@app.route('/admin/module_permissions')
@login_required
def admin_module_permissions():
    """Super admin module permissions management page"""
    if current_user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users with admin role
    admin_users = User.query.filter_by(role='admin').all()
    
    return render_template('admin_module_permissions.html', 
                         module_permissions=MODULE_PERMISSIONS,
                         admin_users=admin_users)

@app.route('/admin/update_module_permissions', methods=['POST'])
@login_required
def update_module_permissions():
    """Update module permissions for admin users"""
    if current_user.role != 'super_admin':
        return jsonify({'success': False, 'error': 'Access denied. Super admin privileges required.'})
    
    try:
        # Get form data
        user_id = request.form.get('user_id')
        permissions_json = request.form.get('permissions')
        
        if not user_id or not permissions_json:
            return jsonify({'success': False, 'error': 'Missing required data'})
        
        # Update user's module permissions
        user = User.query.get(user_id)
        if user and user.role == 'admin':
            # Store permissions in user's department field as JSON
            permissions = json.loads(permissions_json)
            user.department = json.dumps(permissions)
            db.session.commit()
            
            return jsonify({'success': True, 'message': f'Module permissions updated for {user.username}'})
        else:
            return jsonify({'success': False, 'error': 'User not found or invalid role'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating permissions: {str(e)}'})

@app.route('/admin/system_settings')
@require_module_access('settings')
def admin_system_settings():
    """Super admin system settings page"""
    
    # Get system statistics
    total_users = User.query.count()
    total_tickets = Ticket.query.count()
    active_tickets = Ticket.query.filter(Ticket.status.in_(['Open', 'Assigned', 'In Progress'])).count()
    
    # Get role distribution
    role_stats = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
    
    return render_template('admin_system_settings.html',
                         total_users=total_users,
                         total_tickets=total_tickets,
                         active_tickets=active_tickets,
                         role_stats=role_stats)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@require_module_access('user_management')
def create_user():
    """Create a new user"""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            department = request.form.get('department')
            
            # Validate required fields
            if not all([username, email, password, role]):
                flash('All fields are required!', 'error')
                return render_template('create_user.html')
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'error')
                return render_template('create_user.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists!', 'error')
                return render_template('create_user.html')
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                role=role,
                department=department,
                is_active=True
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'User {username} created successfully!', 'success')
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return render_template('create_user.html')
    
    return render_template('create_user.html')

@app.route('/admin/bulk_create_users', methods=['GET', 'POST'])
@require_module_access('bulk_user_creation')
def bulk_create_users():
    """Bulk create users"""
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'csv_file' not in request.files:
                flash('No file selected!', 'error')
                return render_template('bulk_create_users.html')
            
            file = request.files['csv_file']
            if file.filename == '':
                flash('No file selected!', 'error')
                return render_template('bulk_create_users.html')
            
            if not file.filename.endswith('.csv'):
                flash('Please upload a CSV file!', 'error')
                return render_template('bulk_create_users.html')
            
            # Read and process CSV file
            csv_content = file.read().decode('utf-8').splitlines()
            csv_reader = csv.DictReader(csv_content)
            
            # Validate CSV headers
            required_headers = ['username', 'email', 'password', 'role']
            optional_headers = ['department']
            
            if not all(header in csv_reader.fieldnames for header in required_headers):
                missing_headers = [h for h in required_headers if h not in csv_reader.fieldnames]
                flash(f'Missing required columns: {", ".join(missing_headers)}', 'error')
                return render_template('bulk_create_users.html')
            
            # Process each row
            success_count = 0
            error_count = 0
            errors = []
            
            for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 because row 1 is headers
                try:
                    # Validate required fields
                    username = row['username'].strip()
                    email = row['email'].strip()
                    password = row['password'].strip()
                    role = row['role'].strip()
                    department = row.get('department', '').strip() if 'department' in row else ''
                    
                    if not all([username, email, password, role]):
                        errors.append(f'Row {row_num}: Missing required fields')
                        error_count += 1
                        continue
                    
                    # Validate role
                    valid_roles = ['user', 'admin', 'it_agent', 'fm_agent']
                    if role not in valid_roles:
                        errors.append(f'Row {row_num}: Invalid role "{role}". Must be one of: {", ".join(valid_roles)}')
                        error_count += 1
                        continue
                    
                    # Check if user already exists
                    if User.query.filter_by(username=username).first():
                        errors.append(f'Row {row_num}: Username "{username}" already exists')
                        error_count += 1
                        continue
                    
                    if User.query.filter_by(email=email).first():
                        errors.append(f'Row {row_num}: Email "{email}" already exists')
                        error_count += 1
                        continue
                    
                    # Create new user
                    new_user = User(
                        username=username,
                        email=email,
                        role=role,
                        department=department if department else None,
                        is_active=True
                    )
                    new_user.set_password(password)
                    
                    db.session.add(new_user)
                    success_count += 1
                    
                except Exception as e:
                    errors.append(f'Row {row_num}: {str(e)}')
                    error_count += 1
            
            # Commit all successful creations
            if success_count > 0:
                try:
                    db.session.commit()
                    flash(f'Successfully created {success_count} users!', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error committing users to database: {str(e)}', 'error')
                    return render_template('bulk_create_users.html')
            
            # Show errors if any
            if error_count > 0:
                if success_count > 0:
                    flash(f'Created {success_count} users, but {error_count} rows had errors.', 'warning')
                else:
                    flash(f'No users were created. {error_count} rows had errors.', 'error')
                
                # Log errors for debugging (first 5 errors to avoid overwhelming the user)
                error_summary = '; '.join(errors[:5])
                if len(errors) > 5:
                    error_summary += f'; and {len(errors) - 5} more errors'
                flash(f'Error details: {error_summary}', 'error')
            
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            flash(f'Error processing CSV file: {str(e)}', 'error')
            return render_template('bulk_create_users.html')
    
    return render_template('bulk_create_users.html')

@app.route('/user/ticket_summary')
@login_required
def my_ticket_summary():
    """User's own ticket summary page"""
    try:
        # Get user's tickets
        user_tickets = Ticket.query.filter_by(created_by=current_user.id).all()
        
        # Categorize tickets by status
        open_tickets = [t for t in user_tickets if t.status == 'Open']
        assigned_tickets = [t for t in user_tickets if t.status == 'Assigned']
        in_progress_tickets = [t for t in user_tickets if t.status == 'In Progress']
        closed_tickets = [t for t in user_tickets if t.status in ['Resolved', 'Closed']]
        
        # Categorize by category
        it_tickets = [t for t in user_tickets if t.category == 'IT']
        fm_tickets = [t for t in user_tickets if t.category == 'FM']
        hse_tickets = [t for t in user_tickets if t.category == 'HSE']
        
        # Categorize by priority
        critical_tickets = [t for t in user_tickets if t.priority == 'Critical']
        high_tickets = [t for t in user_tickets if t.priority == 'High']
        medium_tickets = [t for t in user_tickets if t.priority == 'Medium']
        low_tickets = [t for t in user_tickets if t.priority == 'Low']
        
        return render_template('user_ticket_summary.html',
                             user=current_user,
                             user_tickets=user_tickets,
                             open_tickets=open_tickets,
                             assigned_tickets=assigned_tickets,
                             in_progress_tickets=in_progress_tickets,
                             closed_tickets=closed_tickets,
                             it_tickets=it_tickets,
                             fm_tickets=fm_tickets,
                             hse_tickets=hse_tickets,
                             critical_tickets=critical_tickets,
                             high_tickets=high_tickets,
                             medium_tickets=medium_tickets,
                             low_tickets=low_tickets)
                             
    except Exception as e:
        flash(f'Error loading your ticket summary: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/test/module_access/<module_name>')
@login_required
def test_module_access(module_name):
    """Test route to check module access for current user"""
    try:
        print(f"DEBUG: Testing module access for {current_user.username} (role: {current_user.role})")
        print(f"DEBUG: Testing access to module: {module_name}")
        
        # Test the check_module_access function
        has_access = check_module_access(module_name)
        
        # Get module permissions
        allowed_roles = MODULE_PERMISSIONS.get(module_name, [])
        
        return f"""
        <h3>Module Access Test Results</h3>
        <p><strong>User:</strong> {current_user.username}</p>
        <p><strong>User Role:</strong> {current_user.role}</p>
        <p><strong>User ID:</strong> {current_user.id}</p>
        <p><strong>Module:</strong> {module_name}</p>
        <p><strong>Allowed Roles:</strong> {allowed_roles}</p>
        <p><strong>Has Access:</strong> {'✅ Yes' if has_access else '❌ No'}</p>
        <p><strong>User Role in Allowed Roles:</strong> {'✅ Yes' if current_user.role in allowed_roles else '❌ No'}</p>
        <p><strong>Is Super Admin:</strong> {'✅ Yes' if current_user.role == 'super_admin' else '❌ No'}</p>
        <p><strong>Is Admin:</strong> {'✅ Yes' if current_user.role == 'admin' else '❌ No'}</p>
        """
        
    except Exception as e:
        return f"Error testing module access: {str(e)}"

@app.route('/backup_success')
@login_required
def backup_success():
    return render_template('backup_success.html')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    log_and_notify_error(error, {'error_type': '404 Not Found'})
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    log_and_notify_error(error, {'error_type': '500 Internal Server Error'})
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    log_and_notify_error(error, {'error_type': '403 Forbidden'})
    return render_template('403.html'), 403

@app.errorhandler(401)
def unauthorized_error(error):
    """Handle 401 errors"""
    log_and_notify_error(error, {'error_type': '401 Unauthorized'})
    return render_template('401.html'), 401

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all unhandled exceptions"""
    log_and_notify_error(error, {'error_type': 'Unhandled Exception'})
    return render_template('500.html'), 500

# Before request handler to log requests
@app.before_request
def before_request():
    """Log all requests for debugging"""
    if request.endpoint:
        logger.info(f"Request: {request.method} {request.url} - User: {current_user.username if current_user.is_authenticated else 'Anonymous'} - IP: {request.remote_addr}")

# After request handler to log responses
@app.after_request
def after_request(response):
    """Log response status"""
    if response.status_code >= 400:
        logger.warning(f"Response: {response.status_code} for {request.method} {request.url}")
    return response


@app.route('/admin/reports')
@login_required
def admin_reports():
    """Admin Reports page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_reports'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_reports.html')
        
    except Exception as e:
        flash(f'Error loading admin_reports: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))




@app.route('/admin/user_activity')
@login_required
def admin_user_activity():
    """Admin User Activity page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_user_activity'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_user_activity.html')
        
    except Exception as e:
        flash(f'Error loading admin_user_activity: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/system_logs')
@login_required
def admin_system_logs():
    """Admin System Logs page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_system_logs'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_system_logs.html')
        
    except Exception as e:
        flash(f'Error loading admin_system_logs: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/permissions')
@login_required
def admin_permissions():
    """Admin Permissions page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_permissions'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_permissions.html')
        
    except Exception as e:
        flash(f'Error loading admin_permissions: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/roles')
@login_required
def admin_roles():
    """Admin Roles page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_roles'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_roles.html')
        
    except Exception as e:
        flash(f'Error loading admin_roles: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/departments')
@login_required
def admin_departments():
    """Admin Departments page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_departments'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_departments.html')
        
    except Exception as e:
        flash(f'Error loading admin_departments: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/categories')
@login_required
def admin_categories():
    """Admin Categories page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_categories'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_categories.html')
        
    except Exception as e:
        flash(f'Error loading admin_categories: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/priorities')
@login_required
def admin_priorities():
    """Admin Priorities page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_priorities'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_priorities.html')
        
    except Exception as e:
        flash(f'Error loading admin_priorities: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/statuses')
@login_required
def admin_statuses():
    """Admin Statuses page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_statuses'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_statuses.html')
        
    except Exception as e:
        flash(f'Error loading admin_statuses: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/notifications')
@login_required
def admin_notifications():
    """Admin Notifications page"""
    try:
        # Check if user has permission
        if not has_permission(current_user, 'admin_notifications'):
            flash('Access denied. You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('admin_notifications.html')
        
    except Exception as e:
        flash(f'Error loading admin_notifications: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))





if __name__ == '__main__':
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Create super admin user if it doesn't exist
        super_admin = User.query.filter_by(username='admin').first()
        if not super_admin:
            super_admin = User(
                username='admin',
                email='admin@helpdesk.local',
                password_hash=generate_password_hash('admin123'),
                role='super_admin',
                is_active=True
            )
            db.session.add(super_admin)
            db.session.commit()
            print("Super admin user created: admin / admin123")
        
        # Create default email templates if they don't exist
        default_templates = [
            {
                'template_type': 'ticket_created',
                'subject': 'New Ticket Created: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>New Ticket Created</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Created by:</strong> {created_by} ({created_by_role})</p>
                    <p><strong>Created:</strong> {created_date}</p>
                    <br>
                    <p>A new ticket has been created in the helpdesk system. Please log in to view and manage this ticket.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'ticket_assigned_to_agent',
                'subject': 'New Ticket Assigned: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>New Ticket Assigned</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Description:</strong> {ticket_description}</p>
                    <p><strong>Created by:</strong> {creator_name}</p>
                    <p><strong>Created:</strong> {created_date}</p>
                    <br>
                    <p>Please log in to the helpdesk system to view and update this ticket.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'comment_added',
                'subject': 'Comment Added to Ticket: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>Comment Added to Ticket</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Comment by:</strong> {comment_by} ({comment_by_role})</p>
                    <p><strong>Comment:</strong> {comment_content}</p>
                    <p><strong>Added:</strong> {comment_date}</p>
                    <br>
                    <p>A new comment has been added to this ticket. Please log in to the helpdesk system to view the full conversation.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'status_updated',
                'subject': 'Ticket Status Updated: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>Ticket Status Updated</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Previous Status:</strong> {old_status}</p>
                    <p><strong>New Status:</strong> {new_status}</p>
                    <p><strong>Updated by:</strong> {updated_by} ({updated_by_role})</p>
                    <p><strong>Updated:</strong> {updated_date}</p>
                    <br>
                    <p>Your ticket status has been updated. Please log in to the helpdesk system for more details.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'admin_ticket_created',
                'subject': 'ADMIN ALERT: New Ticket Created: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>🚨 ADMIN ALERT: New Ticket Created</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Description:</strong> {ticket_description}</p>
                    <p><strong>Created by:</strong> {creator_name} ({creator_email})</p>
                    <p><strong>Created:</strong> {created_date}</p>
                    <p><strong>Assigned to:</strong> {assigned_agent}</p>
                    <br>
                                    <p>This is an administrative notification. A new ticket has been created in the helpdesk system.</p>
                <p>Please monitor this ticket and ensure proper handling.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'admin_comment_added',
                'subject': 'ADMIN ALERT: Comment Added to Ticket: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>💬 ADMIN ALERT: New Comment Added</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Comment by:</strong> {commenter_name}</p>
                    <p><strong>Comment:</strong> {comment_content}</p>
                    <p><strong>Date:</strong> {comment_date}</p>
                    <p><strong>Ticket Creator:</strong> {creator_name}</p>
                    <p><strong>Assigned Agent:</strong> {assigned_agent}</p>
                    <br>
                                    <p>This is an administrative notification. A new comment has been added to an existing ticket.</p>
                <p>Please monitor the conversation and ensure proper resolution.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'admin_status_updated',
                'subject': 'ADMIN ALERT: Ticket Status Updated: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>🔄 ADMIN ALERT: Ticket Status Updated</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Previous Status:</strong> {old_status}</p>
                    <p><strong>New Status:</strong> {new_status}</p>
                    <p><strong>Updated by:</strong> {updated_by}</p>
                    <p><strong>Updated:</strong> {updated_date}</p>
                    <p><strong>Ticket Creator:</strong> {creator_name}</p>
                    <p><strong>Assigned Agent:</strong> {assigned_agent}</p>
                    <br>
                                    <p>This is an administrative notification. A ticket status has been updated.</p>
                <p>Please monitor the progress and ensure timely resolution.</p>
                <br>
                <hr>
                <p><em>Best regards,<br>Al Qeyam Helpdesk Team</em></p>
                </body>
                </html>
                '''
            }
        ]
        
        for template_data in default_templates:
            existing_template = EmailTemplate.query.filter_by(template_type=template_data['template_type']).first()
            if not existing_template:
                template = EmailTemplate(
                    template_type=template_data['template_type'],
                    subject=template_data['subject'],
                    body=template_data['body']
                )
                db.session.add(template)
        
        db.session.commit()

@app.route('/admin/download_tickets_excel')
@login_required
def download_tickets_excel():
    """Download tickets as Excel file"""
    try:
        # Get all tickets
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
        
        # Create Excel file
        import io
        import pandas as pd
        from datetime import datetime
        
        # Prepare data for Excel
        data = []
        for ticket in tickets:
            creator = User.query.get(ticket.created_by)
            assigned_agent = User.query.get(ticket.assigned_to) if ticket.assigned_to else None
            
            data.append({
                'Ticket ID': ticket.id,
                'Title': ticket.title,
                'Description': ticket.description,
                'Category': ticket.category,
                'Priority': ticket.priority,
                'Status': ticket.status,
                'Created By': creator.username if creator else 'Unknown',
                'Creator Email': creator.email if creator else 'Unknown',
                'Assigned To': assigned_agent.username if assigned_agent else 'Unassigned',
                'Created Date': ticket.created_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.created_at else '',
                'Updated Date': ticket.updated_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.updated_at else '',
                'Comments Count': len(ticket.comments) if hasattr(ticket, 'comments') else 0
            })
        
        # Create DataFrame and Excel file
        df = pd.DataFrame(data)
        
        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Tickets', index=False)
        
        output.seek(0)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'tickets_export_{timestamp}.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f'Error generating Excel file: {str(e)}', 'error')
        return redirect(url_for('admin_tickets'))

@app.route('/admin/download_summary_pdf')
@login_required
def download_summary_pdf():
    """Download summary report as PDF"""
    try:
        # Get summary statistics
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.filter_by(status='Open').count()
        in_progress_tickets = Ticket.query.filter_by(status='In Progress').count()
        resolved_tickets = Ticket.query.filter_by(status='Resolved').count()
        closed_tickets = Ticket.query.filter_by(status='Closed').count()
        
        # Get recent tickets
        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
        
        # Create PDF content
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from datetime import datetime
        import io
        
        # Create PDF in memory
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        # Add title
        story.append(Paragraph("Al Qeyam Helpdesk - Summary Report", title_style))
        story.append(Spacer(1, 12))
        
        # Add timestamp
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Add statistics
        story.append(Paragraph("System Statistics", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        stats_data = [
            ['Metric', 'Count'],
            ['Total Tickets', str(total_tickets)],
            ['Open Tickets', str(open_tickets)],
            ['In Progress', str(in_progress_tickets)],
            ['Resolved', str(resolved_tickets)],
            ['Closed', str(closed_tickets)]
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Add recent tickets
        story.append(Paragraph("Recent Tickets", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        if recent_tickets:
            ticket_data = [['ID', 'Title', 'Status', 'Priority', 'Created']]
            for ticket in recent_tickets:
                creator = User.query.get(ticket.created_by)
                ticket_data.append([
                    str(ticket.id),
                    ticket.title[:30] + '...' if len(ticket.title) > 30 else ticket.title,
                    ticket.status,
                    ticket.priority,
                    ticket.created_at.strftime('%Y-%m-%d') if ticket.created_at else 'N/A'
                ])
            
            ticket_table = Table(ticket_data, colWidths=[0.5*inch, 2.5*inch, 1*inch, 1*inch, 1*inch])
            ticket_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            
            story.append(ticket_table)
        else:
            story.append(Paragraph("No recent tickets found.", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'helpdesk_summary_{timestamp}.pdf'
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f'Error generating PDF report: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

# Missing routes to fix BuildError issues
@app.route('/admin/download_table_excel/<table_name>')
@login_required
def download_table_excel(table_name):
    """Download specific table as Excel file"""
    try:
        # Placeholder implementation
        flash(f'Excel download for {table_name} table is not implemented yet.', 'info')
        return redirect(url_for('admin_database_management'))
    except Exception as e:
        flash(f'Error downloading table: {str(e)}', 'error')
        return redirect(url_for('admin_database_management'))

@app.route('/admin/download_all_tables_excel')
@login_required
def download_all_tables_excel():
    """Download all tables as Excel file"""
    try:
        # Placeholder implementation
        flash('Download all tables Excel feature is not implemented yet.', 'info')
        return redirect(url_for('admin_database_management'))
    except Exception as e:
        flash(f'Error downloading all tables: {str(e)}', 'error')
        return redirect(url_for('admin_database_management'))

@app.route('/admin/switch_database/<int:db_index>', methods=['POST'])
@login_required
def switch_database(db_index):
    """Switch to different database"""
    try:
        # Placeholder implementation
        flash(f'Database switching to index {db_index} is not implemented yet.', 'info')
        return redirect(url_for('admin_database_management'))
    except Exception as e:
        flash(f'Error switching database: {str(e)}', 'error')
        return redirect(url_for('admin_database_management'))

@app.route('/admin/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    try:
        user = User.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()
        flash(f'User {user.username} status toggled successfully.', 'success')
    except Exception as e:
        flash(f'Error toggling user status: {str(e)}', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete user"""
    try:
        user = User.query.get_or_404(user_id)
        if user.username == 'admin':
            flash('Cannot delete admin user.', 'error')
        else:
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.username} deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/add_agent', methods=['GET', 'POST'])
@login_required
def add_agent():
    """Add new agent"""
    if request.method == 'GET':
        return render_template('add_agent.html')
    
    try:
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        agent_type = request.form.get('agent_type')
        department = request.form.get('department')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        notes = request.form.get('notes')
        
        # Validation
        if not all([username, email, password, confirm_password, agent_type]):
            flash('All required fields must be filled.', 'error')
            return redirect(url_for('add_agent'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('add_agent'))
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('add_agent'))
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please use a different email address.', 'error')
            return redirect(url_for('add_agent'))
        
        # Create new user/agent
        new_agent = User(
            username=username,
            email=email,
            role=agent_type,
            department=department,
            is_active=True
        )
        new_agent.set_password(password)
        
        # Store additional info in department field as JSON
        additional_info = {}
        if full_name:
            additional_info['full_name'] = full_name
        if phone:
            additional_info['phone'] = phone
        if notes:
            additional_info['notes'] = notes
        
        if additional_info:
            new_agent.department = json.dumps(additional_info)
        
        # Save to database
        db.session.add(new_agent)
        db.session.commit()
        
        flash(f'Agent {username} has been successfully created!', 'success')
        return redirect(url_for('admin_agent_management'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding agent: {str(e)}', 'error')
        return redirect(url_for('add_agent'))

@app.route('/admin/create_system_backup', methods=['POST'])
@login_required
def create_system_backup():
    """Create system backup"""
    try:
        # Placeholder implementation
        flash('System backup feature is not implemented yet.', 'info')
        return redirect(url_for('admin_backup_restore'))
    except Exception as e:
        flash(f'Error creating system backup: {str(e)}', 'error')
        return redirect(url_for('admin_backup_restore'))

@app.route('/admin/create_database_backup', methods=['POST'])
@login_required
def create_database_backup():
    """Create database backup"""
    try:
        # Placeholder implementation
        flash('Database backup feature is not implemented yet.', 'info')
        return redirect(url_for('admin_backup_restore'))
    except Exception as e:
        flash(f'Error creating database backup: {str(e)}', 'error')
        return redirect(url_for('admin_backup_restore'))

@app.route('/admin/restore_system_backup', methods=['POST'])
@login_required
def restore_system_backup():
    """Restore system backup"""
    try:
        # Placeholder implementation
        flash('System restore feature is not implemented yet.', 'info')
        return redirect(url_for('admin_backup_restore'))
    except Exception as e:
        flash(f'Error restoring system backup: {str(e)}', 'error')
        return redirect(url_for('admin_backup_restore'))

@app.route('/admin/send_daily_summary', methods=['POST'])
@login_required
def send_daily_summary():
    """Send daily summary email"""
    try:
        # Placeholder implementation
        flash('Daily summary email feature is not implemented yet.', 'info')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f'Error sending daily summary: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/view_user/<int:user_id>')
@login_required
def view_user(user_id):
    """View user details"""
    try:
        user = User.query.get_or_404(user_id)
        return render_template('view_user.html', user=user)
    except Exception as e:
        flash(f'Error viewing user: {str(e)}', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/download_user_tickets/<int:user_id>')
@login_required
def download_user_tickets(user_id):
    """Download user tickets as Excel"""
    try:
        # Placeholder implementation
        flash('Download user tickets feature is not implemented yet.', 'info')
        return redirect(url_for('admin_summary_reports'))
    except Exception as e:
        flash(f'Error downloading user tickets: {str(e)}', 'error')
        return redirect(url_for('admin_summary_reports'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """Edit user details"""
    try:
        user = User.query.get_or_404(user_id)
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'reset_password':
                # Handle password reset
                new_password = request.form.get('new_password')
                if new_password:
                    user.set_password(new_password)
                    db.session.commit()
                    flash(f'Password for user {user.username} has been reset successfully.', 'success')
                else:
                    flash('New password is required for password reset.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            # Handle regular user editing
            # Update user details
            user.username = request.form.get('username')
            user.email = request.form.get('email')
            user.role = request.form.get('role')
            user.department = request.form.get('department')
            user.is_active = request.form.get('is_active') == 'on'
            
            # Update password if provided
            new_password = request.form.get('password')
            if new_password:
                user.set_password(new_password)
            
            db.session.commit()
            flash(f'User {user.username} updated successfully.', 'success')
            return redirect(url_for('admin_users'))
        
        return render_template('edit_user.html', user=user)
        
    except Exception as e:
        flash(f'Error editing user: {str(e)}', 'error')
        return redirect(url_for('admin_users'))





@app.route('/favicon.ico')
def favicon():
    """Serve favicon to prevent 404 errors"""
    try:
        return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    except FileNotFoundError:
        # If favicon doesn't exist, return no content to prevent 404 errors
        return '', 204

@app.route('/static/manifest.json')
def manifest():
    """Serve PWA manifest.json"""
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route('/static/service-worker.js')
def service_worker():
    """Serve service worker for PWA"""
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
