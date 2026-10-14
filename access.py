"""Role / module access control shared by the main app and the tenant blueprint."""
import json
from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user, login_required

from models import ROLE_SUPER_ADMIN, ROLE_ADMIN, AGENT_ROLES, ADMIN_ROLES

# Module permissions configuration.
# Platform modules are super-admin only; tenant modules are available to the school's admins.
_STAFF = ['super_admin', 'admin', 'it_agent', 'fm_agent', 'hse_agent']
MODULE_PERMISSIONS = {
    'system_management': ['super_admin'],
    'database_management': ['super_admin'],
    'backup_restore': ['super_admin'],
    'email_settings': ['super_admin'],
    'email_templates': ['super_admin'],
    'settings': ['super_admin'],
    'user_management': ['super_admin', 'admin'],
    'agent_management': ['super_admin', 'admin'],
    'bulk_user_creation': ['super_admin', 'admin'],
    'bulk_ticket_import': ['super_admin', 'admin'],
    'search_users': ['super_admin', 'admin'],
    'summary_reports': _STAFF,
    'ticket_management': _STAFF,
    'search_tickets': _STAFF,
}


def _admin_module_overrides(user):
    """Super admins may switch individual modules off for a school admin (stored in ``department``)."""
    try:
        if user.department:
            data = json.loads(user.department)
            return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        pass
    return {}


def check_module_access(module_name):
    """Check if current user has access to a specific module"""
    if not current_user.is_authenticated:
        return False
    if current_user.role == ROLE_SUPER_ADMIN:
        return True
    if current_user.role not in MODULE_PERMISSIONS.get(module_name, []):
        return False
    if current_user.role == ROLE_ADMIN:
        return _admin_module_overrides(current_user).get(module_name, True) is not False
    return True


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


def admin_required(f):
    """School admin / super admin only."""
    @login_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ADMIN_ROLES:
            flash('Access denied. Administrator privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def can_access_ticket(ticket):
    """Staff of the school may open any of its tickets; requesters only their own."""
    if current_user.role in ADMIN_ROLES or current_user.role in AGENT_ROLES:
        return True
    return ticket.created_by == current_user.id
