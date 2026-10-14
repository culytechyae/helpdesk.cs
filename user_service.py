"""User creation rules shared by the single-user form, agent form and bulk import."""
import re
import secrets
import string

from extensions import db
from models import (
    User, School, ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER, AGENT_ROLES,
)

MIN_PASSWORD_LENGTH = 8
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9._@+-]{3,80}$')

SCHOOL_ASSIGNABLE_ROLES = (ROLE_USER,) + AGENT_ROLES + (ROLE_ADMIN,)


def assignable_roles(actor):
    """Roles the actor may hand out."""
    if actor.role == ROLE_SUPER_ADMIN:
        return SCHOOL_ASSIGNABLE_ROLES + (ROLE_SUPER_ADMIN,)
    return SCHOOL_ASSIGNABLE_ROLES


def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def normalize_email(email):
    return (email or '').strip().lower()


def global_user_exists(username=None, email=None):
    """Usernames and e-mails are unique platform-wide (users sign in with either)."""
    q = User.query.execution_options(tenant_bypass=True)
    if username and q.filter(db.func.lower(User.username) == username.lower()).first():
        return 'username'
    if email and q.filter(db.func.lower(User.email) == email.lower()).first():
        return 'email'
    return None


def make_unique_username(base, school=None, reserved=()):
    """Derive a free username from ``base`` (usually the e-mail local part)."""
    base = re.sub(r'[^A-Za-z0-9._+-]', '', base or '')[:60] or 'user'
    if len(base) < 3:
        base = (base + 'user')[:60]
    candidates = [base]
    if school is not None:
        candidates.append(f'{base}.{school.slug}'[:75])
    n = 2
    while True:
        for cand in candidates:
            if cand.lower() not in reserved and not global_user_exists(username=cand):
                return cand
        candidates = [f'{base}{n}'[:75]]
        n += 1


def validate_new_user(actor, *, username, email, password, role, school):
    """Return an error string or None."""
    if not username or not email or not role:
        return 'Username, email and role are required.'
    if not USERNAME_RE.match(username):
        return 'Username must be 3-80 characters (letters, digits and . _ @ + - only).'
    if not EMAIL_RE.match(email) or len(email) > 120:
        return f'"{email}" is not a valid email address.'
    if role not in assignable_roles(actor):
        return f'Role "{role}" is not allowed.'
    if role != ROLE_SUPER_ADMIN and school is None:
        return 'A school is required for this role.'
    if password is not None and len(password) < MIN_PASSWORD_LENGTH:
        return f'Password must be at least {MIN_PASSWORD_LENGTH} characters.'
    clash = global_user_exists(username=username, email=email)
    if clash:
        return f'A user with this {clash} already exists.'
    return None


def build_user(*, username, email, password, role, school, full_name=None, department=None,
               must_change_password=False):
    user = User(
        username=username, email=email, role=role, full_name=(full_name or None),
        department=(department or None), is_active=True,
        school_id=None if role == ROLE_SUPER_ADMIN else school.id,
        must_change_password=must_change_password,
    )
    user.set_password(password)
    return user


def resolve_school_for_actor(actor, school_id_value):
    """School a new user lands in: school admins are pinned to their own school."""
    if actor.role != ROLE_SUPER_ADMIN:
        return db.session.get(School, actor.school_id)
    try:
        return db.session.get(School, int(school_id_value))
    except (TypeError, ValueError):
        return None


def can_manage_user(actor, target):
    if actor.role == ROLE_SUPER_ADMIN:
        return True
    return (actor.role == ROLE_ADMIN and target.role != ROLE_SUPER_ADMIN
            and target.school_id is not None and target.school_id == actor.school_id)
