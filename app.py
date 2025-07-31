from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Multiple database configuration
DATABASES = [
    'sqlite:///helpdesk.db',
    'sqlite:///helpdesk2.db',
    'sqlite:///helpdesk3.db',
    'sqlite:///helpdesk4.db',
    'sqlite:///helpdesk5.db'
]

# Database management
class DatabaseManager:
    def __init__(self):
        self.current_db_index = 0
        self.db_locks = [threading.Lock() for _ in range(len(DATABASES))]
        self.db_sizes = {}
        self.max_db_size = 1024 * 1024 * 1024  # 1GB limit per database (can store 5000+ tickets)
        
    def get_current_db_uri(self):
        return DATABASES[self.current_db_index]
    
    def get_db_size(self, db_path):
        """Get database file size in bytes"""
        try:
            if os.path.exists(db_path):
                return os.path.getsize(db_path)
            return 0
        except:
            return 0
    
    def check_and_switch_db(self):
        """Check if current database is full and switch if necessary"""
        current_db_path = f"helpdesk{self.current_db_index + 1 if self.current_db_index > 0 else ''}.db"
        current_size = self.get_db_size(current_db_path)
        
        if current_size > self.max_db_size:
            # Switch to next database
            self.current_db_index = (self.current_db_index + 1) % len(DATABASES)
            print(f"Database {current_db_path} is full ({current_size} bytes). Switching to database {self.current_db_index + 1}")
            return True
        return False
    
    def get_all_databases(self):
        """Get all database URIs"""
        return DATABASES
    
    def get_database_info(self):
        """Get information about all databases"""
        info = []
        for i, db_uri in enumerate(DATABASES):
            db_path = f"helpdesk{i + 1 if i > 0 else ''}.db"
            size = self.get_db_size(db_path)
            is_active = (i == self.current_db_index)
            info.append({
                'index': i,
                'name': f"helpdesk{i + 1 if i > 0 else ''}.db",
                'size': size,
                'size_mb': round(size / (1024 * 1024), 2),
                'is_active': is_active,
                'uri': db_uri
            })
        return info

# Initialize database manager
db_manager = DatabaseManager()

# Configure Flask-SQLAlchemy with current database
app.config['SQLALCHEMY_DATABASE_URI'] = db_manager.get_current_db_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin', 'user', 'it_agent', 'fm_agent'
    department = db.Column(db.String(50), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # 'IT', 'FM'
    priority = db.Column(db.String(20), default='Medium')  # 'Low', 'Medium', 'High', 'Critical'
    status = db.Column(db.String(20), default='Open')  # 'Open', 'Assigned', 'In Progress', 'Resolved', 'Closed'
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    ticket = db.relationship('Ticket', backref='comments')
    user = db.relationship('User', backref='comments')

class EmailSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(100), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    email_address = db.Column(db.String(120), nullable=False)
    email_password = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_type = db.Column(db.String(50), nullable=False, unique=True)  # 'ticket_created', 'comment_added', 'status_updated'
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    """Get all tickets from all databases"""
    all_tickets = []
    
    for db_uri in DATABASES:
        try:
            # Create temporary app context for this database
            temp_app = Flask(__name__)
            temp_app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
            temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
            temp_db = SQLAlchemy(temp_app)
            
            # Define models for this database - User must be defined first
            class TempUser(temp_db.Model):
                __tablename__ = 'user'
                id = temp_db.Column(temp_db.Integer, primary_key=True)
                username = temp_db.Column(temp_db.String(80), unique=True, nullable=False)
                email = temp_db.Column(temp_db.String(120), unique=True, nullable=False)
                password_hash = temp_db.Column(temp_db.String(120), nullable=False)
                role = temp_db.Column(temp_db.String(20), default='user')
                department = temp_db.Column(temp_db.String(50), nullable=True)
                is_active = temp_db.Column(temp_db.Boolean, default=True)
                created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
            
            class TempTicket(temp_db.Model):
                __tablename__ = 'ticket'
                id = temp_db.Column(temp_db.Integer, primary_key=True)
                title = temp_db.Column(temp_db.String(200), nullable=False)
                description = temp_db.Column(temp_db.Text, nullable=False)
                category = temp_db.Column(temp_db.String(50), nullable=False)
                priority = temp_db.Column(temp_db.String(20), default='Medium')
                status = temp_db.Column(temp_db.String(20), default='Open')
                created_by = temp_db.Column(temp_db.Integer, temp_db.ForeignKey('user.id'), nullable=False)
                assigned_to = temp_db.Column(temp_db.Integer, temp_db.ForeignKey('user.id'), nullable=True)
                created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
                updated_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
                
                creator = temp_db.relationship('TempUser', foreign_keys=[created_by], backref='created_tickets')
                assignee = temp_db.relationship('TempUser', foreign_keys=[assigned_to], backref='assigned_tickets')
            
            with temp_app.app_context():
                tickets = TempTicket.query.all()
                for ticket in tickets:
                    # Convert to regular Ticket object
                    ticket_obj = Ticket()
                    ticket_obj.id = ticket.id
                    ticket_obj.title = ticket.title
                    ticket_obj.description = ticket.description
                    ticket_obj.category = ticket.category
                    ticket_obj.priority = ticket.priority
                    ticket_obj.status = ticket.status
                    ticket_obj.created_by = ticket.created_by
                    ticket_obj.assigned_to = ticket.assigned_to
                    ticket_obj.created_at = ticket.created_at
                    ticket_obj.updated_at = ticket.updated_at
                    
                    # Add relationships
                    if ticket.creator:
                        user_obj = User()
                        user_obj.id = ticket.creator.id
                        user_obj.username = ticket.creator.username
                        user_obj.email = ticket.creator.email
                        user_obj.role = ticket.creator.role
                        user_obj.department = ticket.creator.department
                        user_obj.is_active = ticket.creator.is_active
                        user_obj.created_at = ticket.creator.created_at
                        ticket_obj.creator = user_obj
                    
                    if ticket.assignee:
                        assignee_obj = User()
                        assignee_obj.id = ticket.assignee.id
                        assignee_obj.username = ticket.assignee.username
                        assignee_obj.email = ticket.assignee.email
                        assignee_obj.role = ticket.assignee.role
                        assignee_obj.department = ticket.assignee.department
                        assignee_obj.is_active = ticket.assignee.is_active
                        assignee_obj.created_at = ticket.assignee.created_at
                        ticket_obj.assignee = assignee_obj
                    
                    all_tickets.append(ticket_obj)
                    
        except Exception as e:
            print(f"Error reading from database {db_uri}: {str(e)}")
            continue
    
    return all_tickets

def get_all_users_from_all_dbs():
    """Get all users from all databases"""
    all_users = []
    
    for db_uri in DATABASES:
        try:
            # Create temporary app context for this database
            temp_app = Flask(__name__)
            temp_app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
            temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
            temp_db = SQLAlchemy(temp_app)
            
            # Define User model for this database
            class TempUser(temp_db.Model):
                __tablename__ = 'user'
                id = temp_db.Column(temp_db.Integer, primary_key=True)
                username = temp_db.Column(temp_db.String(80), unique=True, nullable=False)
                email = temp_db.Column(temp_db.String(120), unique=True, nullable=False)
                password_hash = temp_db.Column(temp_db.String(120), nullable=False)
                role = temp_db.Column(temp_db.String(20), default='user')
                department = temp_db.Column(temp_db.String(50), nullable=True)
                is_active = temp_db.Column(temp_db.Boolean, default=True)
                created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
            
            with temp_app.app_context():
                users = TempUser.query.all()
                for user in users:
                    # Convert to regular User object
                    user_obj = User()
                    user_obj.id = user.id
                    user_obj.username = user.username
                    user_obj.email = user.email
                    user_obj.password_hash = user.password_hash
                    user_obj.role = user.role
                    user_obj.department = user.department
                    user_obj.is_active = user.is_active
                    user_obj.created_at = user.created_at
                    all_users.append(user_obj)
                    
        except Exception as e:
            print(f"Error reading users from database {db_uri}: {str(e)}")
            continue
    
    return all_users

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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password) and user.is_active:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        tickets = Ticket.query.all()
        users = User.query.all()
        it_agents = User.query.filter_by(role='it_agent').all()
        fm_agents = User.query.filter_by(role='fm_agent').all()
        return render_template('admin_dashboard.html', tickets=tickets, users=users, 
                            it_agents=it_agents, fm_agents=fm_agents)
    else:
        if current_user.role in ['it_agent', 'fm_agent']:
            assigned_tickets = Ticket.query.filter_by(assigned_to=current_user.id).all()
            return render_template('agent_dashboard.html', tickets=assigned_tickets)
        else:
            my_tickets = Ticket.query.filter_by(created_by=current_user.id).all()
            return render_template('user_dashboard.html', tickets=my_tickets)

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')
        
        ticket = Ticket(
            title=title,
            description=description,
            category=category,
            priority=priority,
            created_by=current_user.id
        )
        
        # Check if current database is full and switch if necessary
        db_manager.check_and_switch_db()
        
        db.session.add(ticket)
        db.session.commit()
        
        # Auto-assign ticket based on category and FIFO round-robin order
        if category == 'IT':
            it_agents = User.query.filter_by(role='it_agent').order_by(User.created_at).all()
            if it_agents:
                # Get the last assigned IT agent to implement round-robin (excluding current ticket)
                last_assigned_ticket = Ticket.query.filter_by(category='IT').filter(Ticket.id != ticket.id).order_by(Ticket.created_at.desc()).first()
                
                if last_assigned_ticket and last_assigned_ticket.assigned_to:
                    # Find the index of the last assigned agent
                    last_agent_index = -1
                    for i, agent in enumerate(it_agents):
                        if agent.id == last_assigned_ticket.assigned_to:
                            last_agent_index = i
                            break
                    
                    # Assign to next agent in round-robin order
                    next_agent_index = (last_agent_index + 1) % len(it_agents)
                    next_agent = it_agents[next_agent_index]
                else:
                    # First ticket, assign to first agent
                    next_agent = it_agents[0]
                
                ticket.assigned_to = next_agent.id
                ticket.status = 'Assigned'
                db.session.commit()
        
        elif category == 'FM':
            fm_agents = User.query.filter_by(role='fm_agent').order_by(User.created_at).all()
            if fm_agents:
                # Get the last assigned FM agent to implement round-robin (excluding current ticket)
                last_assigned_ticket = Ticket.query.filter_by(category='FM').filter(Ticket.id != ticket.id).order_by(Ticket.created_at.desc()).first()
                
                if last_assigned_ticket and last_assigned_ticket.assigned_to:
                    # Find the index of the last assigned agent
                    last_agent_index = -1
                    for i, agent in enumerate(fm_agents):
                        if agent.id == last_assigned_ticket.assigned_to:
                            last_agent_index = i
                            break
                    
                    # Assign to next agent in round-robin order
                    next_agent_index = (last_agent_index + 1) % len(fm_agents)
                    next_agent = fm_agents[next_agent_index]
                else:
                    # First ticket, assign to first agent
                    next_agent = fm_agents[0]
                
                ticket.assigned_to = next_agent.id
                ticket.status = 'Assigned'
                db.session.commit()
        
        # Send email notifications
        if ticket.assigned_to:
            # Email to assigned agent
            assigned_agent = User.query.get(ticket.assigned_to)
            if assigned_agent and assigned_agent.email:
                send_templated_email(
                    assigned_agent.email,
                    'ticket_assigned_to_agent',
                    ticket_id=ticket.id,
                    ticket_title=ticket.title,
                    ticket_category=ticket.category,
                    ticket_priority=ticket.priority,
                    ticket_description=ticket.description,
                    creator_name=ticket.creator.username,
                    created_date=ticket.created_at.strftime('%Y-%m-%d %H:%M')
                )
            
            # Email to ticket creator
            creator = User.query.get(ticket.created_by)
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
        
        flash('Ticket created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('create_ticket.html')

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != 'admin' and ticket.created_by != current_user.id and ticket.assigned_to != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get agents for assignment dropdown (admin only)
    it_agents = []
    fm_agents = []
    if current_user.role == 'admin':
        it_agents = User.query.filter_by(role='it_agent').all()
        fm_agents = User.query.filter_by(role='fm_agent').all()
    
    return render_template('view_ticket.html', ticket=ticket, it_agents=it_agents, fm_agents=fm_agents)

@app.route('/ticket/<int:ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != 'admin' and ticket.created_by != current_user.id and ticket.assigned_to != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    content = request.form.get('content')
    if content:
        comment = Comment(
            ticket_id=ticket_id,
            user_id=current_user.id,
            content=content
        )
        db.session.add(comment)
        db.session.commit()
        
        # Send email notification to ticket creator about new comment
        creator = User.query.get(ticket.created_by)
        if creator and creator.email and creator.id != current_user.id:  # Don't send email if creator is commenting
            send_templated_email(
                creator.email,
                'comment_added',
                ticket_id=ticket.id,
                ticket_title=ticket.title,
                commenter_name=current_user.username,
                comment_content=content,
                comment_date=comment.created_at.strftime('%Y-%m-%d %H:%M')
            )
        
        flash('Comment added successfully!', 'success')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/ticket/<int:ticket_id>/update_status', methods=['POST'])
@login_required
def update_ticket_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role not in ['admin', 'it_agent', 'fm_agent'] or ticket.assigned_to != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    new_status = request.form.get('status')
    if new_status in ['Open', 'In Progress', 'Resolved', 'Closed']:
        old_status = ticket.status
        ticket.status = new_status
        db.session.commit()
        
        # Send email notification to ticket creator about status update
        creator = User.query.get(ticket.created_by)
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
                updated_by=current_user.username,
                updated_by_role=current_user.role,
                updated_date=datetime.utcnow().strftime('%Y-%m-%d %H:%M')
            )
        
        flash('Ticket status updated successfully!', 'success')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        department = request.form.get('department')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('create_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('create_user.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            department=department
        )
        
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('create_user.html')

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        department = request.form.get('department')
        
        if User.query.filter_by(username=username).first() and User.query.filter_by(username=username).first().id != user.id:
            flash('Username already exists.', 'error')
            return render_template('edit_user.html', user=user)
        
        if User.query.filter_by(email=email).first() and User.query.filter_by(email=email).first().id != user.id:
            flash('Email already exists.', 'error')
            return render_template('edit_user.html', user=user)
        
        user.username = username
        user.email = email
        user.role = role
        user.department = department
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    
    if not new_password:
        flash('New password cannot be empty.', 'error')
        return redirect(url_for('edit_user', user_id=user.id))
    
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password reset successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/bulk_create_users', methods=['GET', 'POST'])
@login_required
def bulk_create_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        csv_file = request.files.get('csv_file')
        if not csv_file:
            flash('No CSV file selected.', 'error')
            return render_template('bulk_create_users.html')
        
        if not csv_file.filename.endswith('.csv'):
            flash('Please select a CSV file (with .csv extension).', 'error')
            return render_template('bulk_create_users.html')
        
        try:
            # Read the uploaded CSV file
            file_content = csv_file.read()
            csv_stream = io.StringIO(file_content.decode('utf-8'))
            csv_reader = csv.DictReader(csv_stream)
            
            for row in csv_reader:
                username = row.get('username')
                email = row.get('email')
                password = row.get('password')
                role = row.get('role')
                department = row.get('department')
                
                if not all([username, email, password, role]):
                    flash(f"Missing required fields in row: {row}", 'error')
                    continue
                
                if User.query.filter_by(username=username).first():
                    flash(f"Username '{username}' already exists.", 'error')
                    continue
                
                if User.query.filter_by(email=email).first():
                    flash(f"Email '{email}' already exists.", 'error')
                    continue
                
                user = User(
                    username=username,
                    email=email,
                    password_hash=generate_password_hash(password),
                    role=role,
                    department=department
                )
                db.session.add(user)
            
            db.session.commit()
            flash(f'Successfully created {len(csv_reader.fieldnames)} users from CSV!', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            print(f"Error reading CSV file: {e}")
            flash(f'Error reading CSV file: {e}', 'error')
            return render_template('bulk_create_users.html')
    
    return render_template('bulk_create_users.html')

@app.route('/admin/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'error')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/assign_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    agent_id = request.form.get('agent_id')
    
    if agent_id:
        agent = User.query.get(agent_id)
        if agent and agent.role in ['it_agent', 'fm_agent']:
            ticket.assigned_to = agent_id
            ticket.status = 'Assigned'
            db.session.commit()
            
            # Send email notifications for manual assignment
            if agent.email:
                agent_subject = f"Ticket Manually Assigned: #{ticket.id} - {ticket.title}"
                agent_body = f"""
                <html>
                <body>
                    <h2>Ticket Manually Assigned</h2>
                    <p><strong>Ticket ID:</strong> #{ticket.id}</p>
                    <p><strong>Title:</strong> {ticket.title}</p>
                    <p><strong>Category:</strong> {ticket.category}</p>
                    <p><strong>Priority:</strong> {ticket.priority}</p>
                    <p><strong>Description:</strong> {ticket.description}</p>
                    <p><strong>Created by:</strong> {ticket.creator.username}</p>
                    <p><strong>Assigned by:</strong> {current_user.username} (Admin)</p>
                    <p><strong>Created:</strong> {ticket.created_at.strftime('%Y-%m-%d %H:%M')}</p>
                    <br>
                    <p>This ticket has been manually assigned to you by an administrator.</p>
                    <p>Please log in to the helpdesk system to view and update this ticket.</p>
                </body>
                </html>
                """
                send_email_notification(agent.email, agent_subject, agent_body)
            
            # Email to ticket creator about manual assignment
            creator = User.query.get(ticket.created_by)
            if creator and creator.email:
                creator_subject = f"Ticket Reassigned: #{ticket.id} - {ticket.title}"
                creator_body = f"""
                <html>
                <body>
                    <h2>Ticket Reassigned</h2>
                    <p><strong>Ticket ID:</strong> #{ticket.id}</p>
                    <p><strong>Title:</strong> {ticket.title}</p>
                    <p><strong>Category:</strong> {ticket.category}</p>
                    <p><strong>Priority:</strong> {ticket.priority}</p>
                    <p><strong>Status:</strong> {ticket.status}</p>
                    <p><strong>New Assigned Agent:</strong> {agent.username}</p>
                    <p><strong>Reassigned by:</strong> {current_user.username} (Admin)</p>
                    <p><strong>Created:</strong> {ticket.created_at.strftime('%Y-%m-%d %H:%M')}</p>
                    <br>
                    <p>Your ticket has been reassigned to a different agent by an administrator.</p>
                </body>
                </html>
                """
                send_email_notification(creator.email, creator_subject, creator_body)
            
            flash('Ticket assigned successfully!', 'success')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        smtp_server = request.form.get('smtp_server')
        smtp_port = request.form.get('smtp_port')
        email_address = request.form.get('email_address')
        email_password = request.form.get('email_password')
        
        # Import email configuration for validation
        from email_config import EmailConfig
        
        # Validate inputs
        validation_errors = EmailConfig.validate_email_settings(smtp_server, smtp_port, email_address, email_password)
        if validation_errors:
            for error in validation_errors:
                flash(error, 'error')
            return render_template('admin_email_settings.html', email_settings=None)
        
        try:
            smtp_port = int(smtp_port)
        except ValueError:
            flash('SMTP port must be a number.', 'error')
            return render_template('admin_email_settings.html', email_settings=None)
        
        # Test connection before saving
        print("Testing email configuration before saving...")
        if not EmailConfig.test_smtp_connection(smtp_server, smtp_port):
            flash('Cannot connect to SMTP server. Please check server and port settings.', 'error')
            return render_template('admin_email_settings.html', email_settings=None)
        
        # Get existing settings or create new
        email_settings = EmailSettings.query.filter_by(is_active=True).first()
        if not email_settings:
            email_settings = EmailSettings()
            db.session.add(email_settings)
        
        # Update settings
        email_settings.smtp_server = smtp_server
        email_settings.smtp_port = smtp_port
        email_settings.email_address = email_address
        email_settings.email_password = email_password
        email_settings.is_active = True
        
        db.session.commit()
        flash('Email settings updated successfully!', 'success')
        return redirect(url_for('admin_settings'))
    
    # Get current settings
    email_settings = EmailSettings.query.filter_by(is_active=True).first()
    return render_template('admin_email_settings.html', email_settings=email_settings)

@app.route('/admin/test_email', methods=['POST'])
@login_required
def test_email():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    test_email = request.form.get('test_email')
    if not test_email:
        flash('Test email address is required.', 'error')
        return redirect(url_for('admin_settings'))
    
    # Check if email settings exist
    email_settings = EmailSettings.query.filter_by(is_active=True).first()
    if not email_settings:
        flash('No email settings configured. Please save email settings first.', 'error')
        return redirect(url_for('admin_settings'))
    
    # Import email configuration for testing
    from email_config import EmailConfig
    
    print(f"Testing email configuration...")
    print(f"SMTP Server: {email_settings.smtp_server}:{email_settings.smtp_port}")
    print(f"From Email: {email_settings.email_address}")
    print(f"To Email: {test_email}")
    
    # Test connection first
    if not EmailConfig.test_smtp_connection(email_settings.smtp_server, email_settings.smtp_port):
        flash('Cannot connect to SMTP server. Please check your email settings.', 'error')
        return redirect(url_for('admin_settings'))
    
    # Test authentication
    if not EmailConfig.test_smtp_authentication(
        email_settings.smtp_server, 
        email_settings.smtp_port, 
        email_settings.email_address, 
        email_settings.email_password
    ):
        flash('Authentication failed. Please check your email and password.', 'error')
        return redirect(url_for('admin_settings'))
    
    # Send test email
    if EmailConfig.send_test_email(
        email_settings.smtp_server,
        email_settings.smtp_port,
        email_settings.email_address,
        email_settings.email_password,
        test_email
    ):
        flash('Test email sent successfully! Check your email inbox.', 'success')
    else:
        flash('Failed to send test email. Please check the console for detailed error messages.', 'error')
    
    return redirect(url_for('admin_settings'))

@app.route('/admin/download_tickets_excel')
@login_required
def download_tickets_excel():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all tickets with related data
    tickets = Ticket.query.all()
    
    # Create a new workbook and select the active sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "Tickets"
    
    # Define headers
    headers = ['ID', 'Title', 'Description', 'Category', 'Priority', 'Status', 'Created By', 'Assigned To', 'Created At', 'Updated At']
    
    # Style for headers
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center")
    
    # Add headers
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
    
    # Add data
    for row, ticket in enumerate(tickets, 2):
        creator = User.query.get(ticket.created_by)
        assignee = User.query.get(ticket.assigned_to) if ticket.assigned_to else None
        
        ws.cell(row=row, column=1, value=ticket.id)
        ws.cell(row=row, column=2, value=ticket.title)
        ws.cell(row=row, column=3, value=ticket.description)
        ws.cell(row=row, column=4, value=ticket.category)
        ws.cell(row=row, column=5, value=ticket.priority)
        ws.cell(row=row, column=6, value=ticket.status)
        ws.cell(row=row, column=7, value=creator.username if creator else 'Unknown')
        ws.cell(row=row, column=8, value=assignee.username if assignee else 'Unassigned')
        ws.cell(row=row, column=9, value=ticket.created_at.strftime('%Y-%m-%d %H:%M:%S'))
        ws.cell(row=row, column=10, value=ticket.updated_at.strftime('%Y-%m-%d %H:%M:%S'))
    
    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width
    
    # Save to BytesIO
    excel_file = BytesIO()
    wb.save(excel_file)
    excel_file.seek(0)
    
    return send_file(
        excel_file,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'tickets_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    )

@app.route('/admin/download_summary_pdf')
@login_required
def download_summary_pdf():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get summary statistics
    total_tickets = Ticket.query.count()
    it_tickets = Ticket.query.filter_by(category='IT').count()
    fm_tickets = Ticket.query.filter_by(category='FM').count()
    
    # Status breakdown
    open_tickets = Ticket.query.filter_by(status='Open').count()
    assigned_tickets = Ticket.query.filter_by(status='Assigned').count()
    in_progress_tickets = Ticket.query.filter_by(status='In Progress').count()
    resolved_tickets = Ticket.query.filter_by(status='Resolved').count()
    closed_tickets = Ticket.query.filter_by(status='Closed').count()
    
    # Priority breakdown
    low_priority = Ticket.query.filter_by(priority='Low').count()
    medium_priority = Ticket.query.filter_by(priority='Medium').count()
    high_priority = Ticket.query.filter_by(priority='High').count()
    critical_priority = Ticket.query.filter_by(priority='Critical').count()
    
    # User statistics
    total_users = User.query.count()
    admin_users = User.query.filter_by(role='admin').count()
    regular_users = User.query.filter_by(role='user').count()
    it_agents = User.query.filter_by(role='it_agent').count()
    fm_agents = User.query.filter_by(role='fm_agent').count()
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=20
    )
    
    # Title
    elements.append(Paragraph("Helpdesk System Summary Report", title_style))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 30))
    
    # Ticket Statistics
    elements.append(Paragraph("Ticket Statistics", heading_style))
    
    ticket_data = [
        ['Metric', 'Count'],
        ['Total Tickets', total_tickets],
        ['IT Tickets', it_tickets],
        ['FM Tickets', fm_tickets],
        ['Open Tickets', open_tickets],
        ['Assigned Tickets', assigned_tickets],
        ['In Progress Tickets', in_progress_tickets],
        ['Resolved Tickets', resolved_tickets],
        ['Closed Tickets', closed_tickets]
    ]
    
    ticket_table = Table(ticket_data, colWidths=[3*inch, 1.5*inch])
    ticket_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(ticket_table)
    elements.append(Spacer(1, 20))
    
    # Priority Statistics
    elements.append(Paragraph("Priority Breakdown", heading_style))
    
    priority_data = [
        ['Priority', 'Count'],
        ['Low', low_priority],
        ['Medium', medium_priority],
        ['High', high_priority],
        ['Critical', critical_priority]
    ]
    
    priority_table = Table(priority_data, colWidths=[3*inch, 1.5*inch])
    priority_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(priority_table)
    elements.append(Spacer(1, 20))
    
    # User Statistics
    elements.append(Paragraph("User Statistics", heading_style))
    
    user_data = [
        ['User Type', 'Count'],
        ['Total Users', total_users],
        ['Administrators', admin_users],
        ['Regular Users', regular_users],
        ['IT Agents', it_agents],
        ['FM Agents', fm_agents]
    ]
    
    user_table = Table(user_data, colWidths=[3*inch, 1.5*inch])
    user_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(user_table)
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'helpdesk_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    )

@app.route('/admin/email_templates', methods=['GET', 'POST'])
@login_required
def admin_email_templates():
    """Manage email templates"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        template_type = request.form.get('template_type')
        subject = request.form.get('subject')
        body = request.form.get('body')
        
        # Check if template exists
        template = EmailTemplate.query.filter_by(template_type=template_type).first()
        if template:
            template.subject = subject
            template.body = body
            template.updated_at = datetime.utcnow()
        else:
            template = EmailTemplate(
                template_type=template_type,
                subject=subject,
                body=body
            )
            db.session.add(template)
        
        db.session.commit()
        flash('Email template updated successfully!', 'success')
        return redirect(url_for('admin_email_templates'))
    
    # Get all templates
    templates = EmailTemplate.query.all()
    return render_template('admin_email_templates.html', templates=templates)

@app.route('/admin/email_templates/<template_type>')
@login_required
def get_email_template_data(template_type):
    """Get email template data for AJAX requests"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    template = EmailTemplate.query.filter_by(template_type=template_type).first()
    if template:
        return jsonify({
            'subject': template.subject,
            'body': template.body
        })
    else:
        return jsonify({'error': 'Template not found'}), 404

# Initialize scheduler
scheduler = BackgroundScheduler()

def generate_daily_summary_email():
    """Generate and send daily summary email to admin with Excel attachment"""
    try:
        with app.app_context():
            # Get all tickets
            tickets = Ticket.query.all()
            
            # Create Excel file in memory
            wb = Workbook()
            ws = wb.active
            ws.title = "All Tickets"
            
            # Add headers
            headers = ['ID', 'Title', 'Description', 'Category', 'Status', 'Priority', 'Created By', 'Assigned To', 'Created At', 'Updated At']
            for col, header in enumerate(headers, 1):
                ws.cell(row=1, column=col, value=header)
            
            # Add ticket data
            for row, ticket in enumerate(tickets, 2):
                ws.cell(row=row, column=1, value=ticket.id)
                ws.cell(row=row, column=2, value=ticket.title)
                ws.cell(row=row, column=3, value=ticket.description)
                ws.cell(row=row, column=4, value=ticket.category)
                ws.cell(row=row, column=5, value=ticket.status)
                ws.cell(row=row, column=6, value=ticket.priority)
                ws.cell(row=row, column=7, value=ticket.created_by)
                ws.cell(row=row, column=8, value=ticket.assigned_to)
                ws.cell(row=row, column=9, value=ticket.created_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.created_at else '')
                ws.cell(row=row, column=10, value=ticket.updated_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.updated_at else '')
            
            # Auto-adjust column widths
            for column in ws.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                ws.column_dimensions[column_letter].width = adjusted_width
            
            # Save to BytesIO
            excel_file = BytesIO()
            wb.save(excel_file)
            excel_file.seek(0)
            
            # Create email body
            body = f"""
            <html>
            <body>
                <h2>Daily Helpdesk Data Backup</h2>
                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
                <p><strong>Total Tickets:</strong> {len(tickets)}</p>
                <p>Please find attached the complete ticket data in Excel format.</p>
            </body>
            </html>
            """
            
            # Send email with Excel attachment
            success = send_email_with_attachment('curlytechy27@gmail.com', 'Daily Helpdesk Data Backup', body, excel_file, f"tickets_backup_{datetime.now().strftime('%Y-%m-%d')}.xlsx")
            if success:
                print(f"Daily summary email with Excel attachment sent successfully to curlytechy27@gmail.com at {datetime.now()}")
            else:
                print(f"Failed to send daily summary email at {datetime.now()}")

    except Exception as e:
        print(f"Error in daily summary email generation: {str(e)}")

@app.route('/admin/send_daily_summary', methods=['POST'])
@login_required
def send_daily_summary():
    """Manual trigger for sending daily summary email"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        generate_daily_summary_email()
        flash('Daily summary email sent successfully!', 'success')
    except Exception as e:
        flash(f'Failed to send daily summary email: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

# Schedule daily summary email at 9:00 AM every day
scheduler.add_job(
    func=generate_daily_summary_email,
    trigger=CronTrigger(hour=9, minute=0),
    id='daily_summary_email',
    name='Send daily summary email',
    replace_existing=True
)

# Start the scheduler
scheduler.start()

@app.route('/admin/summary_reports')
@login_required
def admin_summary_reports():
    """Summary reports page with charts and tables"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all tickets for statistics from all databases
    all_tickets = get_all_tickets_from_all_dbs()
    users = get_all_users_from_all_dbs()
    
    # Category-wise summary
    it_tickets = [t for t in all_tickets if t.category == 'IT']
    fm_tickets = [t for t in all_tickets if t.category == 'FM']
    
    # Status-wise summary
    open_tickets = [t for t in all_tickets if t.status == 'Open']
    assigned_tickets = [t for t in all_tickets if t.status == 'Assigned']
    in_progress_tickets = [t for t in all_tickets if t.status == 'In Progress']
    resolved_tickets = [t for t in all_tickets if t.status == 'Resolved']
    closed_tickets = [t for t in all_tickets if t.status == 'Closed']
    
    # Priority-wise summary
    critical_tickets = [t for t in all_tickets if t.priority == 'Critical']
    high_tickets = [t for t in all_tickets if t.priority == 'High']
    medium_tickets = [t for t in all_tickets if t.priority == 'Medium']
    low_tickets = [t for t in all_tickets if t.priority == 'Low']
    
    # User-wise summary
    user_tickets = {}
    for user in users:
        if user.role == 'user':  # Only regular users
            user_tickets[user.username] = {
                'total': len([t for t in all_tickets if t.created_by == user.id]),
                'open': len([t for t in all_tickets if t.created_by == user.id and t.status == 'Open']),
                'pending': len([t for t in all_tickets if t.created_by == user.id and t.status in ['Assigned', 'In Progress']]),
                'closed': len([t for t in all_tickets if t.created_by == user.id and t.status in ['Resolved', 'Closed']])
            }
    
    # Agent-wise summary
    agent_tickets = {}
    for user in users:
        if user.role in ['it_agent', 'fm_agent']:
            agent_tickets[user.username] = {
                'total': len([t for t in all_tickets if t.assigned_to == user.id]),
                'open': len([t for t in all_tickets if t.assigned_to == user.id and t.status == 'Open']),
                'assigned': len([t for t in all_tickets if t.assigned_to == user.id and t.status == 'Assigned']),
                'in_progress': len([t for t in all_tickets if t.assigned_to == user.id and t.status == 'In Progress']),
                'resolved': len([t for t in all_tickets if t.assigned_to == user.id and t.status == 'Resolved']),
                'closed': len([t for t in all_tickets if t.assigned_to == user.id and t.status == 'Closed'])
            }
    
    return render_template('admin_summary_reports.html',
                         all_tickets=all_tickets,
                         it_tickets=it_tickets,
                         fm_tickets=fm_tickets,
                         open_tickets=open_tickets,
                         assigned_tickets=assigned_tickets,
                         in_progress_tickets=in_progress_tickets,
                         resolved_tickets=resolved_tickets,
                         closed_tickets=closed_tickets,
                         critical_tickets=critical_tickets,
                         high_tickets=high_tickets,
                         medium_tickets=medium_tickets,
                         low_tickets=low_tickets,
                         user_tickets=user_tickets,
                         agent_tickets=agent_tickets,
                         users=users)

@app.route('/admin/user_ticket_summary/<int:user_id>')
@login_required
def user_ticket_summary(user_id):
    """Individual user ticket summary"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user_tickets = Ticket.query.filter_by(created_by=user_id).all()
    
    # Categorize tickets by status
    open_tickets = [t for t in user_tickets if t.status == 'Open']
    pending_tickets = [t for t in user_tickets if t.status in ['Assigned', 'In Progress']]
    closed_tickets = [t for t in user_tickets if t.status in ['Resolved', 'Closed']]
    
    return render_template('user_ticket_summary.html',
                         user=user,
                         user_tickets=user_tickets,
                         open_tickets=open_tickets,
                         pending_tickets=pending_tickets,
                         closed_tickets=closed_tickets)

@app.route('/admin/download_user_tickets/<int:user_id>')
@login_required
def download_user_tickets(user_id):
    """Download user's tickets in Excel format"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user_tickets = Ticket.query.filter_by(created_by=user_id).all()
    
    # Create Excel file
    wb = Workbook()
    ws = wb.active
    ws.title = f"{user.username}_Tickets"
    
    # Add headers
    headers = ['ID', 'Title', 'Description', 'Category', 'Status', 'Priority', 'Assigned To', 'Created At', 'Updated At']
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = Font(bold=True)
        cell.fill = PatternFill(start_color="CCCCCC", end_color="CCCCCC", fill_type="solid")
    
    # Add ticket data
    for row, ticket in enumerate(user_tickets, 2):
        ws.cell(row=row, column=1, value=ticket.id)
        ws.cell(row=row, column=2, value=ticket.title)
        ws.cell(row=row, column=3, value=ticket.description)
        ws.cell(row=row, column=4, value=ticket.category)
        ws.cell(row=row, column=5, value=ticket.status)
        ws.cell(row=row, column=6, value=ticket.priority)
        ws.cell(row=row, column=7, value=ticket.assignee.username if ticket.assignee else 'Unassigned')
        ws.cell(row=row, column=8, value=ticket.created_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.created_at else '')
        ws.cell(row=row, column=9, value=ticket.updated_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.updated_at else '')
    
    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width
    
    # Save to BytesIO
    excel_file = BytesIO()
    wb.save(excel_file)
    excel_file.seek(0)
    
    return send_file(
        excel_file,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f"{user.username}_tickets_{datetime.now().strftime('%Y%m%d')}.xlsx"
    )

@app.route('/admin/database_management')
@login_required
def admin_database_management():
    """Database management page"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    db_info = db_manager.get_database_info()
    return render_template('admin_database_management.html', databases=db_info)

@app.route('/admin/search_tickets', methods=['GET', 'POST'])
@login_required
def admin_search_tickets():
    """Search tickets page"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        query = request.form.get('query', '')
        category = request.form.get('category', '')
        status = request.form.get('status', '')
        priority = request.form.get('priority', '')
        
        # Convert empty strings to None for filtering
        category = category if category else None
        status = status if status else None
        priority = priority if priority else None
        
        tickets = search_tickets(query, category, status, priority)
        return render_template('admin_search_tickets.html', tickets=tickets, 
                             query=query, category=category, status=status, priority=priority)
    
    return render_template('admin_search_tickets.html', tickets=[], 
                         query='', category='', status='', priority='')

@app.route('/admin/tickets')
@login_required
def admin_tickets():
    """All tickets page with advanced filtering"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all tickets from all databases
    all_tickets = get_all_tickets_from_all_dbs()
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    category_filter = request.args.get('category', '')
    priority_filter = request.args.get('priority', '')
    assigned_to_filter = request.args.get('assigned_to', '')
    created_by_filter = request.args.get('created_by', '')
    date_from_filter = request.args.get('date_from', '')
    date_to_filter = request.args.get('date_to', '')
    search_filter = request.args.get('search', '').lower()
    
    # Apply filters
    filtered_tickets = []
    for ticket in all_tickets:
        # Status filter
        if status_filter and ticket.status != status_filter:
            continue
            
        # Category filter
        if category_filter and ticket.category != category_filter:
            continue
            
        # Priority filter
        if priority_filter and ticket.priority != priority_filter:
            continue
            
        # Assigned to filter
        if assigned_to_filter:
            if assigned_to_filter == 'unassigned' and ticket.assigned_to is not None:
                continue
            elif assigned_to_filter != 'unassigned' and (ticket.assigned_to is None or str(ticket.assigned_to) != assigned_to_filter):
                continue
                
        # Created by filter
        if created_by_filter and str(ticket.created_by) != created_by_filter:
            continue
            
        # Date range filter
        if date_from_filter:
            try:
                from_date = datetime.strptime(date_from_filter, '%Y-%m-%d')
                if ticket.created_at.date() < from_date.date():
                    continue
            except:
                pass
                
        if date_to_filter:
            try:
                to_date = datetime.strptime(date_to_filter, '%Y-%m-%d')
                if ticket.created_at.date() > to_date.date():
                    continue
            except:
                pass
                
        # Search filter
        if search_filter:
            if (search_filter not in ticket.title.lower() and 
                search_filter not in ticket.description.lower()):
                continue
                
        filtered_tickets.append(ticket)
    
    # Sort by created date (newest first)
    filtered_tickets.sort(key=lambda x: x.created_at, reverse=True)
    
    # Get all users and agents for filter dropdowns
    all_users = get_all_users_from_all_dbs()
    all_agents = [user for user in all_users if user.role in ['it_agent', 'fm_agent']]
    
    return render_template('admin_tickets.html', 
                         filtered_tickets=filtered_tickets,
                         all_users=all_users,
                         all_agents=all_agents)

@app.route('/admin/search_users', methods=['GET', 'POST'])
@login_required
def admin_search_users():
    """Search users page"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        query = request.form.get('query', '')
        role = request.form.get('role', '')
        department = request.form.get('department', '')
        is_active = request.form.get('is_active', '')
        
        # Convert empty strings to None for filtering
        role = role if role else None
        department = department if department else None
        is_active = is_active if is_active else None
        
        # Convert is_active string to boolean
        if is_active == 'true':
            is_active = True
        elif is_active == 'false':
            is_active = False
        else:
            is_active = None
        
        users = search_users(query, role, department, is_active)
        return render_template('admin_search_users.html', users=users,
                             query=query, role=role, department=department, is_active=is_active)
    
    return render_template('admin_search_users.html', users=[],
                         query='', role='', department='', is_active='')

@app.route('/admin/switch_database/<int:db_index>', methods=['POST'])
@login_required
def switch_database(db_index):
    """Switch to a specific database"""
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if 0 <= db_index < len(DATABASES):
        db_manager.current_db_index = db_index
        app.config['SQLALCHEMY_DATABASE_URI'] = db_manager.get_current_db_uri()
        flash(f'Switched to database {db_index + 1}', 'success')
    else:
        flash('Invalid database index', 'error')
    
    return redirect(url_for('admin_database_management'))

if __name__ == '__main__':
    # Initialize all databases
    for db_uri in DATABASES:
        temp_app = Flask(__name__)
        temp_app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
        temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        temp_db = SQLAlchemy(temp_app)
        
        # Define models for this database with proper table names
        class TempUser(temp_db.Model):
            __tablename__ = 'user'
            id = temp_db.Column(temp_db.Integer, primary_key=True)
            username = temp_db.Column(temp_db.String(80), unique=True, nullable=False)
            email = temp_db.Column(temp_db.String(120), unique=True, nullable=False)
            password_hash = temp_db.Column(temp_db.String(120), nullable=False)
            role = temp_db.Column(temp_db.String(20), default='user')
            department = temp_db.Column(temp_db.String(50), nullable=True)
            is_active = temp_db.Column(temp_db.Boolean, default=True)
            created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
        
        class TempTicket(temp_db.Model):
            __tablename__ = 'ticket'
            id = temp_db.Column(temp_db.Integer, primary_key=True)
            title = temp_db.Column(temp_db.String(200), nullable=False)
            description = temp_db.Column(temp_db.Text, nullable=False)
            category = temp_db.Column(temp_db.String(50), nullable=False)
            priority = temp_db.Column(temp_db.String(20), default='Medium')
            status = temp_db.Column(temp_db.String(20), default='Open')
            created_by = temp_db.Column(temp_db.Integer, temp_db.ForeignKey('user.id'), nullable=False)
            assigned_to = temp_db.Column(temp_db.Integer, temp_db.ForeignKey('user.id'), nullable=True)
            created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
            updated_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        class TempComment(temp_db.Model):
            __tablename__ = 'comment'
            id = temp_db.Column(temp_db.Integer, primary_key=True)
            ticket_id = temp_db.Column(temp_db.Integer, temp_db.ForeignKey('ticket.id'), nullable=False)
            user_id = temp_db.Column(temp_db.Integer, temp_db.ForeignKey('user.id'), nullable=False)
            content = temp_db.Column(temp_db.Text, nullable=False)
            created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
        
        class TempEmailSettings(temp_db.Model):
            __tablename__ = 'email_settings'
            id = temp_db.Column(temp_db.Integer, primary_key=True)
            smtp_server = temp_db.Column(temp_db.String(100), nullable=False)
            smtp_port = temp_db.Column(temp_db.Integer, nullable=False)
            email_address = temp_db.Column(temp_db.String(120), nullable=False)
            email_password = temp_db.Column(temp_db.String(120), nullable=False)
            is_active = temp_db.Column(temp_db.Boolean, default=True)
            created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
            updated_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        class TempEmailTemplate(temp_db.Model):
            __tablename__ = 'email_template'
            id = temp_db.Column(temp_db.Integer, primary_key=True)
            template_type = temp_db.Column(temp_db.String(50), nullable=False, unique=True)
            subject = temp_db.Column(temp_db.String(200), nullable=False)
            body = temp_db.Column(temp_db.Text, nullable=False)
            is_active = temp_db.Column(temp_db.Boolean, default=True)
            created_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow)
            updated_at = temp_db.Column(temp_db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        with temp_app.app_context():
            temp_db.create_all()
            print(f"Database {db_uri} initialized successfully")
    
    # Initialize main database with default data
    with app.app_context():
        db.create_all()
        
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
        
        # Create sample FM agents
        fm_agents = User.query.filter_by(role='fm_agent').all()
        if len(fm_agents) < 4:
            for i in range(4 - len(fm_agents)):
                agent = User(
                    username=f'fm_agent_{i+1}',
                    email=f'fm_agent_{i+1}@school.com',
                    password_hash=generate_password_hash('password123'),
                    role='fm_agent',
                    department='Facilities Management'
                )
                db.session.add(agent)
        
        db.session.commit()
        
        # Create default email templates if they don't exist
        default_templates = [
            {
                'template_type': 'ticket_created',
                'subject': 'Ticket Created: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>Ticket Created Successfully</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Category:</strong> {ticket_category}</p>
                    <p><strong>Priority:</strong> {ticket_priority}</p>
                    <p><strong>Status:</strong> {ticket_status}</p>
                    <p><strong>Assigned to:</strong> {assigned_agent}</p>
                    <p><strong>Created:</strong> {created_date}</p>
                    <br>
                    <p>Your ticket has been created and assigned. You will receive updates on the progress.</p>
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
                </body>
                </html>
                '''
            },
            {
                'template_type': 'comment_added',
                'subject': 'New Comment on Ticket: #{ticket_id} - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>New Comment Added</h2>
                    <p><strong>Ticket ID:</strong> #{ticket_id}</p>
                    <p><strong>Title:</strong> {ticket_title}</p>
                    <p><strong>Comment by:</strong> {commenter_name}</p>
                    <p><strong>Comment:</strong> {comment_content}</p>
                    <p><strong>Date:</strong> {comment_date}</p>
                    <br>
                    <p>Please log in to the helpdesk system to view the full conversation.</p>
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
    
    app.run(host='0.0.0.0', port=5000, debug=False) 