"""Multi-tenancy core.

Isolation model
---------------
One shared database; every tenant-owned row (users, tickets, comments, activity logs)
carries ``school_id``. A SQLAlchemy ``do_orm_execute`` hook appends a school filter to
*every* ORM SELECT (including lazy loads), so existing ``Ticket.query...`` code is tenant-safe
without having to remember a filter. The scope is:

* school users / school admins -> their own school
* super admin                  -> the school they have "entered" (session), otherwise nothing
* anonymous                    -> nothing (fail closed)

Platform code that legitimately needs all rows opts out explicitly with ``all_schools()``
or the ``tenant_bypass`` execution option.
"""
import logging
import os
import re
from contextlib import contextmanager
from functools import wraps

from flask import g, session, has_request_context, flash, redirect, url_for, request
from flask_login import current_user
from sqlalchemy import event, inspect, or_, false, text
from sqlalchemy.orm import Session, with_loader_criteria

from extensions import db
from models import (
    School, User, Ticket, Comment, UserActivityLog, SystemSettings,
    ROLE_SUPER_ADMIN, ROLE_ADMIN, HEX_COLOR_RE,
)

logger = logging.getLogger(__name__)

BYPASS = object()  # sentinel: no tenant filtering


class TenantError(Exception):
    """Raised when a tenant-owned row would be written without a school."""


# --------------------------------------------------------------------------- scope
def _identity():
    """(role, school_id) of the signed-in user, read with a plain column query.

    Deliberately avoids touching the ORM ``User`` instance: that may be expired after a commit, and
    reloading it would re-enter the tenant filter (infinite recursion).
    """
    cached = g.get('_tenant_identity')
    if cached is not None:
        return cached
    ident = (None, None)
    raw = session.get('_user_id')
    if raw:
        try:
            row = db.session.execute(
                db.select(User.role, User.school_id, User.is_active)
                .where(User.id == int(raw)).execution_options(tenant_bypass=True)).first()
        except (TypeError, ValueError):
            row = None
        if row is not None and row.is_active:
            ident = (row.role, row.school_id)
    g._tenant_identity = ident
    return ident


def reset_identity():
    """Call after login/logout so the cached identity is recomputed."""
    if has_request_context():
        g.pop('_tenant_identity', None)
        g.pop('_active_school', None)


def effective_school_id():
    """Return BYPASS, a school id (int), or None (= no school -> match nothing)."""
    if not has_request_context():
        return BYPASS  # CLI / scheduler / migrations: explicit, trusted code
    if g.get('tenant_bypass'):
        return BYPASS
    role, school_id = _identity()
    if role is None:
        return None
    if role == ROLE_SUPER_ADMIN:
        return session.get('active_school_id')
    return school_id


@contextmanager
def all_schools():
    """Temporarily disable tenant filtering (platform-level code only)."""
    if not has_request_context():
        yield
        return
    previous = g.get('tenant_bypass', False)
    g.tenant_bypass = True
    try:
        yield
    finally:
        g.tenant_bypass = previous


def unscoped_get(model, ident):
    """Primary-key lookup ignoring tenant scope."""
    return db.session.get(model, ident, execution_options={'tenant_bypass': True})


@event.listens_for(Session, 'do_orm_execute')
def _apply_tenant_filter(state):
    if not state.is_select or state.execution_options.get('tenant_bypass'):
        return
    sid = effective_school_id()
    if sid is BYPASS:
        return
    options = []
    if sid is None:
        for model in (User, Ticket, Comment, UserActivityLog):
            options.append(with_loader_criteria(
                model, lambda cls: false(), include_aliases=True, propagate_to_loaders=True))
    else:
        # super admins stay visible (comments/activity they authored must still render)
        options.append(with_loader_criteria(
            User, lambda cls: or_(cls.school_id == sid, cls.role == ROLE_SUPER_ADMIN),
            include_aliases=True, propagate_to_loaders=True))
        for model in (Ticket, Comment):
            options.append(with_loader_criteria(
                model, lambda cls: cls.school_id == sid,
                include_aliases=True, propagate_to_loaders=True))
        options.append(with_loader_criteria(
            UserActivityLog, lambda cls: or_(cls.school_id == sid, cls.school_id.is_(None)),
            include_aliases=True, propagate_to_loaders=True))
    state.statement = state.statement.options(*options)


@event.listens_for(Session, 'before_flush')
def _stamp_school_id(session_, flush_context, instances):
    """New tenant rows inherit the current school (or are derived from a related row)."""
    sid = effective_school_id()
    default = sid if isinstance(sid, int) else None
    with session_.no_autoflush:
        for obj in list(session_.new):
            if isinstance(obj, User):
                if obj.school_id is None and obj.role != ROLE_SUPER_ADMIN:
                    obj.school_id = default
                if obj.school_id is None and obj.role != ROLE_SUPER_ADMIN:
                    raise TenantError('A school is required for non-super-admin users')
            elif isinstance(obj, Ticket):
                if obj.school_id is None:
                    obj.school_id = default
                if obj.school_id is None and obj.created_by:
                    creator = unscoped_get(User, obj.created_by)
                    obj.school_id = creator.school_id if creator else None
                if obj.school_id is None:
                    raise TenantError('A school is required for tickets')
            elif isinstance(obj, Comment):
                if obj.school_id is None:
                    ticket = obj.ticket or (unscoped_get(Ticket, obj.ticket_id) if obj.ticket_id else None)
                    obj.school_id = ticket.school_id if ticket else default
                if obj.school_id is None:
                    raise TenantError('A school is required for comments')
            elif isinstance(obj, UserActivityLog):
                if obj.school_id is None:
                    user = unscoped_get(User, obj.user_id) if obj.user_id else None
                    obj.school_id = user.school_id if user else default


# --------------------------------------------------------------------------- helpers
def slugify(value):
    value = re.sub(r'[^a-z0-9]+', '-', (value or '').lower()).strip('-')
    return value[:60] or 'school'


def unique_slug(base, exclude_id=None):
    slug = slugify(base)
    candidate, n = slug, 2
    while True:
        q = School.query.filter(School.slug == candidate)
        if exclude_id:
            q = q.filter(School.id != exclude_id)
        if not q.first():
            return candidate
        candidate = f'{slug[:55]}-{n}'
        n += 1


def _mix(hex_color, other, ratio):
    """Blend ``hex_color`` toward ``other`` (0..255 triplet) by ``ratio``."""
    h = hex_color.lstrip('#')
    rgb = [int(h[i:i + 2], 16) for i in (0, 2, 4)]
    out = [round(c + (o - c) * ratio) for c, o in zip(rgb, other)]
    return '#%02x%02x%02x' % tuple(out)


DEFAULT_THEME = {
    'dark': '#2c5f5f', 'medium': '#4a9b9b', 'light': '#6bc4c4', 'lighter': '#8dd8d8',
    'custom': False,
}


def build_theme(primary=None, secondary=None):
    """CSS colour variables for a school (falls back to the platform teal theme)."""
    if not primary or not HEX_COLOR_RE.match(primary):
        return dict(DEFAULT_THEME)
    medium = secondary if secondary and HEX_COLOR_RE.match(secondary) else _mix(primary, (255, 255, 255), 0.3)
    return {
        'dark': primary,
        'medium': medium,
        'light': _mix(medium, (255, 255, 255), 0.3),
        'lighter': _mix(medium, (255, 255, 255), 0.5),
        'custom': True,
    }


def active_school():
    """School whose UI the current request should show (None -> platform branding)."""
    if not has_request_context():
        return None
    cached = g.get('_active_school', False)
    if cached is not False:
        return cached
    school = None
    try:
        if current_user.is_authenticated:
            sid = (session.get('active_school_id') if current_user.role == ROLE_SUPER_ADMIN
                   else current_user.school_id)
        else:
            sid = session.get('login_school_id')
        if sid:
            school = db.session.get(School, sid)
    except Exception:  # branding must never break a page
        logger.exception('Could not resolve active school')
    g._active_school = school
    return school


# --------------------------------------------------------------------------- guards
# Endpoints a super admin may use without having "entered" a school. Everything else
# touches tenant data and needs a school context (allow-list => safe by default).
PLATFORM_ENDPOINTS = {
    'static', 'index', 'login', 'logout', 'dashboard', 'favicon', 'manifest', 'service_worker',
    'change_password', 'school_login', 'school_home',
    'admin_users', 'create_user', 'bulk_create_users', 'edit_user', 'view_user',
    'toggle_user_status', 'delete_user', 'add_agent', 'admin_agent_management',
    'admin_settings', 'update_system_settings',
    'admin_system_management', 'system_restart', 'system_troubleshoot', 'fix_database',
    'backup_database', 'clear_cache', 'refresh_stats', 'admin_database_management',
    'admin_backup_restore', 'switch_database', 'create_system_backup', 'create_database_backup',
    'restore_system_backup', 'download_table_excel', 'download_all_tables_excel',
    'admin_email_settings', 'update_email_settings', 'admin_email_templates',
    'update_email_template', 'get_email_template_route', 'test_email',
    'admin_module_permissions', 'update_module_permissions', 'backup_success',
}


def super_admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.path))
        if current_user.role != ROLE_SUPER_ADMIN:
            flash('Access denied. Super admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper


def platform_scope(f):
    """Super admins use platform pages across all schools (apply *inside* the auth decorator)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == ROLE_SUPER_ADMIN:
            g.tenant_bypass = True
        return f(*args, **kwargs)
    return wrapper


def school_admin_required(f):
    """School admin or super admin (inside a school)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.path))
        if current_user.role not in (ROLE_ADMIN, ROLE_SUPER_ADMIN):
            flash('Access denied. Administrator privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------------------------------- migration
TENANT_TABLES = ('users', 'tickets', 'comments', 'user_activity_logs')


def _add_column(conn, inspector, table, column, ddl):
    existing = {c['name'] for c in inspector.get_columns(table)}
    if column in existing:
        return
    try:
        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}'))
        logger.info('migration: added %s.%s', table, column)
    except Exception as exc:  # another worker may have added it concurrently
        if column not in {c['name'] for c in inspect(conn).get_columns(table)}:
            raise
        logger.info('migration: %s.%s already added (%s)', table, column, exc)


def _create_index(conn, name, table, column):
    try:
        conn.execute(text(f'CREATE INDEX IF NOT EXISTS {name} ON {table} ({column})'))
    except Exception:
        logger.exception('migration: could not create index %s', name)


def run_migrations(app):
    """Idempotent schema upgrade + data backfill. Safe to run on every start."""
    with app.app_context():
        db.create_all()
        engine = db.engine
        dialect = engine.dialect.name
        with engine.begin() as conn:
            insp = inspect(conn)
            tables = set(insp.get_table_names())
            for table in TENANT_TABLES:
                if table in tables:
                    _add_column(conn, insp, table, 'school_id', 'INTEGER REFERENCES schools(id)')
                    _create_index(conn, f'ix_{table}_school_id', table, 'school_id')
            if 'users' in tables:
                _add_column(conn, insp, 'users', 'full_name', 'VARCHAR(120)')
                _add_column(conn, insp, 'users', 'must_change_password',
                            'BOOLEAN DEFAULT FALSE' if dialect == 'postgresql' else 'BOOLEAN DEFAULT 0')
                if dialect == 'postgresql':  # werkzeug scrypt hashes are longer than 120 chars
                    conn.execute(text('ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255)'))
            if 'tickets' in tables:
                _add_column(conn, insp, 'tickets', 'external_ref', 'VARCHAR(100)')
                _create_index(conn, 'ix_tickets_external_ref', 'tickets', 'external_ref')
                _create_index(conn, 'ix_tickets_status', 'tickets', 'status')

        _backfill_default_school()


def _backfill_default_school():
    """Pre-multi-tenant installs: move all existing data into a default school."""
    orphan_users = User.query.execution_options(tenant_bypass=True).filter(
        User.school_id.is_(None), User.role != ROLE_SUPER_ADMIN).count()
    orphan_tickets = Ticket.query.execution_options(tenant_bypass=True).filter(
        Ticket.school_id.is_(None)).count()
    if not orphan_users and not orphan_tickets:
        return
    school = School.query.order_by(School.id).first()
    if not school:
        settings = SystemSettings.query.first()
        name = (settings.system_name if settings else None) or 'Default School'
        school = School(name=name, slug=unique_slug(name), logo_filename=settings.logo_filename if settings else None)
        db.session.add(school)
        db.session.flush()
        logger.info('migration: created default school %r for existing data', school.name)
    sid = school.id
    db.session.execute(text('UPDATE users SET school_id=:s WHERE school_id IS NULL AND role != :r'),
                       {'s': sid, 'r': ROLE_SUPER_ADMIN})
    db.session.execute(text('UPDATE tickets SET school_id=:s WHERE school_id IS NULL'), {'s': sid})
    db.session.execute(text(
        'UPDATE comments SET school_id=(SELECT t.school_id FROM tickets t WHERE t.id=comments.ticket_id) '
        'WHERE school_id IS NULL'))
    db.session.execute(text(
        'UPDATE user_activity_logs SET school_id=(SELECT u.school_id FROM users u WHERE u.id=user_activity_logs.user_id) '
        'WHERE school_id IS NULL'))
    db.session.commit()
