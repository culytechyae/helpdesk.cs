"""Database models. Tenant-owned tables carry a ``school_id`` column; see tenancy.py
for how queries are automatically scoped to the current school."""
import re
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db

ROLE_SUPER_ADMIN = 'super_admin'
ROLE_ADMIN = 'admin'          # school administrator
ROLE_USER = 'user'
AGENT_ROLES = ('it_agent', 'fm_agent', 'hse_agent')
ADMIN_ROLES = (ROLE_ADMIN, ROLE_SUPER_ADMIN)
ALL_ROLES = (ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER) + AGENT_ROLES
CATEGORY_AGENT_ROLE = {'IT': 'it_agent', 'FM': 'fm_agent', 'HSE': 'hse_agent'}
CATEGORIES = tuple(CATEGORY_AGENT_ROLE)
PRIORITIES = ('Low', 'Medium', 'High', 'Critical')
STATUSES = ('Open', 'Assigned', 'In Progress', 'Resolved', 'Closed')


def utc_now():
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


HEX_COLOR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')


class School(db.Model):
    """A tenant. Branding (name, logo, colours) is configured by the super admin."""
    __tablename__ = 'schools'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    slug = db.Column(db.String(60), nullable=False, unique=True, index=True)
    display_name = db.Column(db.String(150), nullable=True)   # shown in the UI header; defaults to name
    logo_filename = db.Column(db.String(200), nullable=True)
    primary_color = db.Column(db.String(7), nullable=True)
    secondary_color = db.Column(db.String(7), nullable=True)
    contact_email = db.Column(db.String(120), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

    @property
    def system_name(self):
        """Name shown in the UI (templates read ``system_settings.system_name``)."""
        return self.display_name or self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # see ALL_ROLES
    department = db.Column(db.Text, nullable=True)  # free text / admin module permissions as JSON
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    # --- multi-tenancy -----------------------------------------------------
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True, index=True)
    full_name = db.Column(db.String(120), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

    school = db.relationship('School', foreign_keys=[school_id])

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_super_admin(self):
        return self.role == ROLE_SUPER_ADMIN

    @property
    def is_school_admin(self):
        return self.role == ROLE_ADMIN

    @property
    def is_admin_level(self):
        return self.role in ADMIN_ROLES

    @property
    def is_agent(self):
        return self.role in AGENT_ROLES

    @property
    def display_name(self):
        return self.full_name or self.username


class Ticket(db.Model):
    __tablename__ = 'tickets'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # 'IT', 'FM', 'HSE'
    priority = db.Column(db.String(20), default='Medium')
    status = db.Column(db.String(20), default='Open')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True, index=True)
    external_ref = db.Column(db.String(100), nullable=True, index=True)  # id in a legacy system (bulk import)

    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')


class UserActivityLog(db.Model):
    """User activity logging model"""
    __tablename__ = 'user_activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=utc_now)
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True, index=True)

    user = db.relationship('User', backref='activity_logs')


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True, index=True)

    ticket = db.relationship('Ticket', backref='comments')
    user = db.relationship('User', backref='comments')


# --- platform-level (not tenant scoped) -------------------------------------
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
    template_type = db.Column(db.String(50), nullable=False, unique=True)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)


class SystemSettings(db.Model):
    """Platform branding, used on pages shown outside any school (e.g. the main login)."""
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    system_name = db.Column(db.String(100), nullable=False, default='Al Qeyam Helpdesk')
    logo_filename = db.Column(db.String(200), nullable=True)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)


TENANT_MODELS = (User, Ticket, Comment, UserActivityLog)
