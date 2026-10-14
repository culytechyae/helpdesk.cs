"""Platform (super admin) pages: schools, branding, school switching - plus bulk import pages."""
import logging
import os
import re
import secrets

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session, current_app,
    send_file, Response, abort,
)
from flask_login import current_user, login_required
from sqlalchemy import func

from access import require_module_access
from extensions import db
from importers import (
    ImportFileError, import_users, import_tickets, template_csv, template_xlsx,
)
from models import (
    School, User, Ticket, ROLE_ADMIN, ROLE_SUPER_ADMIN, AGENT_ROLES, HEX_COLOR_RE, utc_now,
)
from tenancy import all_schools, super_admin_required, unique_slug
from user_service import (
    EMAIL_RE, build_user, generate_password, make_unique_username, normalize_email, global_user_exists,
)

logger = logging.getLogger(__name__)
bp = Blueprint('tenant', __name__)

LOGO_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_LOGO_BYTES = 2 * 1024 * 1024
_MAGIC = {
    'png': (b'\x89PNG\r\n\x1a\n',), 'jpg': (b'\xff\xd8\xff',), 'jpeg': (b'\xff\xd8\xff',),
    'gif': (b'GIF87a', b'GIF89a'), 'webp': (b'RIFF',),
}


def _logo_folder():
    return current_app.config.get('SCHOOL_LOGO_FOLDER') or os.path.join(
        current_app.static_folder, 'uploads', 'schools')


def _remove_logo_file(filename):
    if not filename:
        return
    path = os.path.join(_logo_folder(), os.path.basename(filename))
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        logger.warning('Could not remove logo %s', path)


def save_logo(file_storage, school):
    """Validate and store an uploaded logo; returns (filename, error)."""
    ext = file_storage.filename.rsplit('.', 1)[-1].lower() if '.' in file_storage.filename else ''
    if ext not in LOGO_EXTENSIONS:
        return None, 'Logo must be a PNG, JPG, GIF or WebP image.'
    data = file_storage.read(MAX_LOGO_BYTES + 1)
    if len(data) > MAX_LOGO_BYTES:
        return None, 'Logo is larger than 2 MB.'
    if not any(data.startswith(m) for m in _MAGIC[ext]) or (ext == 'webp' and data[8:12] != b'WEBP'):
        return None, 'The file content does not match its image type.'
    os.makedirs(_logo_folder(), exist_ok=True)
    filename = f'schools/school_{school.id}_{secrets.token_hex(4)}.{ext}'
    with open(os.path.join(_logo_folder(), os.path.basename(filename)), 'wb') as fh:
        fh.write(data)
    return filename, None


def _school_form_data():
    form = request.form
    return {
        'name': form.get('name', '').strip(),
        'display_name': form.get('display_name', '').strip(),
        'slug': form.get('slug', '').strip().lower(),
        'primary_color': form.get('primary_color', '').strip(),
        'secondary_color': form.get('secondary_color', '').strip(),
        'contact_email': form.get('contact_email', '').strip(),
    }


def _validate_school(data, school=None):
    name = data['name']
    if not name or len(name) > 150:
        return 'School name is required (max 150 characters).'
    if len(data['display_name']) > 150:
        return 'Display name is too long.'
    clash = School.query.filter(func.lower(School.name) == name.lower())
    if school:
        clash = clash.filter(School.id != school.id)
    if clash.first():
        return f'A school named "{name}" already exists.'
    if data['slug']:
        if not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', data['slug']) or len(data['slug']) > 60:
            return 'Web address may only contain lowercase letters, digits and single dashes.'
        slug_clash = School.query.filter(School.slug == data['slug'])
        if school:
            slug_clash = slug_clash.filter(School.id != school.id)
        if slug_clash.first():
            return f'The web address "{data["slug"]}" is already used by another school.'
    for key in ('primary_color', 'secondary_color'):
        if data[key] and not HEX_COLOR_RE.match(data[key]):
            return 'Colours must be hex values like #2c5f5f.'
    if data['contact_email'] and not EMAIL_RE.match(data['contact_email']):
        return 'Contact email is not valid.'
    return None


# --------------------------------------------------------------------------- platform pages
def _school_stats():
    """{school_id: {...counts}} computed with a handful of grouped queries."""
    stats = {}
    with all_schools():
        for sid, role, n in db.session.query(User.school_id, User.role, func.count(User.id)) \
                .group_by(User.school_id, User.role):
            if sid is None:
                continue
            d = stats.setdefault(sid, {'users': 0, 'agents': 0, 'admins': 0, 'tickets': 0, 'open': 0})
            d['users'] += n
            if role in AGENT_ROLES:
                d['agents'] += n
            if role == ROLE_ADMIN:
                d['admins'] += n
        for sid, status, n in db.session.query(Ticket.school_id, Ticket.status, func.count(Ticket.id)) \
                .group_by(Ticket.school_id, Ticket.status):
            if sid is None:
                continue
            d = stats.setdefault(sid, {'users': 0, 'agents': 0, 'admins': 0, 'tickets': 0, 'open': 0})
            d['tickets'] += n
            if status in ('Open', 'Assigned', 'In Progress'):
                d['open'] += n
    return stats


@bp.route('/platform')
@super_admin_required
def platform_dashboard():
    schools = School.query.order_by(School.name).all()
    stats = _school_stats()
    empty = {'users': 0, 'agents': 0, 'admins': 0, 'tickets': 0, 'open': 0}
    totals = {k: sum(stats.get(s.id, empty)[k] for s in schools) for k in empty}
    return render_template('platform_dashboard.html', schools=schools, stats=stats, empty=empty, totals=totals)


@bp.route('/platform/schools')
@super_admin_required
def schools():
    return redirect(url_for('tenant.platform_dashboard'))


@bp.route('/platform/schools/new', methods=['GET', 'POST'])
@super_admin_required
def school_new():
    if request.method == 'POST':
        data = _school_form_data()
        error = _validate_school(data)
        admin_email = normalize_email(request.form.get('admin_email'))
        admin_name = request.form.get('admin_name', '').strip()
        if not error and admin_email and not EMAIL_RE.match(admin_email):
            error = 'School admin email is not valid.'
        if not error and admin_email and global_user_exists(email=admin_email):
            error = f'A user with email {admin_email} already exists.'
        logo = request.files.get('logo_file')
        if error:
            flash(error, 'error')
            return render_template('school_form.html', school=None, form=data), 400
        school = School(
            name=data['name'], display_name=data['display_name'] or None,
            slug=data['slug'] or unique_slug(data['name']),
            primary_color=data['primary_color'] or None, secondary_color=data['secondary_color'] or None,
            contact_email=data['contact_email'] or None, is_active=True)
        db.session.add(school)
        try:
            db.session.flush()
            if logo and logo.filename:
                filename, logo_err = save_logo(logo, school)
                if logo_err:
                    db.session.rollback()
                    flash(logo_err, 'error')
                    return render_template('school_form.html', school=None, form=data), 400
                school.logo_filename = filename
            created_admin = None
            if admin_email:
                password = generate_password()
                username = make_unique_username(admin_email.split('@')[0], school)
                admin = build_user(username=username, email=admin_email, password=password, role=ROLE_ADMIN,
                                   school=school, full_name=admin_name, must_change_password=True)
                db.session.add(admin)
                created_admin = {'username': username, 'email': admin_email, 'password': password}
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception('Failed to create school')
            flash('Could not create the school. Please try again.', 'error')
            return render_template('school_form.html', school=None, form=data), 500
        logger.info('School %s created by %s', school.slug, current_user.username)
        return render_template('school_created.html', school=school, admin=created_admin)
    return render_template('school_form.html', school=None, form={})


@bp.route('/platform/schools/<int:school_id>/edit', methods=['GET', 'POST'])
@super_admin_required
def school_edit(school_id):
    school = db.session.get(School, school_id) or abort(404)
    if request.method == 'POST':
        data = _school_form_data()
        error = _validate_school(data, school)
        if error:
            flash(error, 'error')
            return render_template('school_form.html', school=school, form=data), 400
        logo = request.files.get('logo_file')
        new_logo = None
        if logo and logo.filename:
            new_logo, logo_err = save_logo(logo, school)
            if logo_err:
                flash(logo_err, 'error')
                return render_template('school_form.html', school=school, form=data), 400
        old_logo = school.logo_filename
        school.name = data['name']
        school.display_name = data['display_name'] or None
        if data['slug']:
            school.slug = data['slug']
        school.primary_color = data['primary_color'] or None
        school.secondary_color = data['secondary_color'] or None
        school.contact_email = data['contact_email'] or None
        if new_logo:
            school.logo_filename = new_logo
        elif request.form.get('remove_logo') == '1':
            school.logo_filename = None
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception('Failed to update school %s', school_id)
            flash('Could not save the school. Please try again.', 'error')
            return render_template('school_form.html', school=school, form=data), 500
        if school.logo_filename != old_logo:
            _remove_logo_file(old_logo)
        flash(f'"{school.name}" updated.', 'success')
        return redirect(url_for('tenant.platform_dashboard'))
    form = {
        'name': school.name, 'display_name': school.display_name or '', 'slug': school.slug,
        'primary_color': school.primary_color or '', 'secondary_color': school.secondary_color or '',
        'contact_email': school.contact_email or '',
    }
    return render_template('school_form.html', school=school, form=form)


@bp.route('/platform/schools/<int:school_id>/toggle', methods=['POST'])
@super_admin_required
def school_toggle(school_id):
    school = db.session.get(School, school_id) or abort(404)
    school.is_active = not school.is_active
    if not school.is_active and session.get('active_school_id') == school.id:
        session.pop('active_school_id', None)
    db.session.commit()
    flash(f'"{school.name}" {"activated" if school.is_active else "suspended - its users can no longer sign in"}.',
          'success' if school.is_active else 'warning')
    return redirect(url_for('tenant.platform_dashboard'))


@bp.route('/platform/schools/<int:school_id>/delete', methods=['POST'])
@super_admin_required
def school_delete(school_id):
    school = db.session.get(School, school_id) or abort(404)
    stats = _school_stats().get(school.id, {})
    if stats.get('users') or stats.get('tickets'):
        flash('Only schools without users or tickets can be deleted. Suspend the school instead.', 'error')
        return redirect(url_for('tenant.platform_dashboard'))
    name, logo = school.name, school.logo_filename
    db.session.delete(school)
    db.session.commit()
    _remove_logo_file(logo)
    flash(f'School "{name}" deleted.', 'success')
    return redirect(url_for('tenant.platform_dashboard'))


@bp.route('/platform/schools/<int:school_id>/enter', methods=['POST'])
@super_admin_required
def school_enter(school_id):
    school = db.session.get(School, school_id) or abort(404)
    session['active_school_id'] = school.id
    flash(f'You are now managing "{school.name}".', 'info')
    return redirect(url_for('admin_dashboard'))


@bp.route('/platform/leave', methods=['POST'])
@super_admin_required
def school_leave():
    session.pop('active_school_id', None)
    return redirect(url_for('tenant.platform_dashboard'))


# --------------------------------------------------------------------------- bulk import
def _import_schools_for_form():
    if current_user.role == ROLE_SUPER_ADMIN:
        return School.query.filter_by(is_active=True).order_by(School.name).all()
    return []


def _default_school_for_import():
    """Selected school (super admin) or own school (school admin)."""
    if current_user.role != ROLE_SUPER_ADMIN:
        return db.session.get(School, current_user.school_id)
    raw = request.form.get('school_id') or session.get('active_school_id')
    try:
        return db.session.get(School, int(raw)) if raw else None
    except (TypeError, ValueError):
        return None


def _run_import(kind, module_label):
    schools_ = _import_schools_for_form()
    template = f'import_{kind}.html'
    ctx = {'schools': schools_, 'selected_school_id': session.get('active_school_id')}
    if request.method == 'GET':
        return render_template(template, **ctx)
    default_school = _default_school_for_import()
    if default_school is None and current_user.role != ROLE_SUPER_ADMIN:
        flash('Your account is not assigned to a school.', 'error')
        return render_template(template, **ctx), 400
    dry_run = request.form.get('dry_run') == '1'
    try:
        if kind == 'users':
            result = import_users(current_user, request.files.get('import_file'), default_school,
                                  dry_run=dry_run,
                                  require_password_change=request.form.get('require_password_change', '1') == '1')
        else:
            result = import_tickets(current_user, request.files.get('import_file'), default_school,
                                    dry_run=dry_run,
                                    create_missing_requesters=request.form.get('create_missing_requesters') == '1',
                                    fallback_to_importer=request.form.get('fallback_to_importer') == '1')
    except ImportFileError as exc:
        flash(str(exc), 'error')
        ctx['selected_school_id'] = default_school.id if default_school else ctx['selected_school_id']
        return render_template(template, **ctx), 400
    except Exception:
        db.session.rollback()
        logger.exception('Bulk %s import failed', kind)
        flash('The import failed unexpectedly. Nothing was saved.', 'error')
        return render_template(template, **ctx), 500
    return render_template('import_result.html', result=result, kind=kind, module_label=module_label)


@bp.route('/admin/import/users', methods=['GET', 'POST'])
@require_module_access('bulk_user_creation')
def import_users_view():
    return _run_import('users', 'Users')


@bp.route('/admin/import/tickets', methods=['GET', 'POST'])
@require_module_access('bulk_ticket_import')
def import_tickets_view():
    return _run_import('tickets', 'Tickets')


@bp.route('/admin/import/template/<kind>.<fmt>')
@login_required
def import_template(kind, fmt):
    if kind not in ('users', 'tickets') or fmt not in ('csv', 'xlsx'):
        abort(404)
    if current_user.role not in (ROLE_ADMIN, ROLE_SUPER_ADMIN):
        abort(403)
    name = f'{kind}_import_template.{fmt}'
    if fmt == 'csv':
        return Response(template_csv(kind), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename={name}'})
    return send_file(template_xlsx(kind), as_attachment=True, download_name=name,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
