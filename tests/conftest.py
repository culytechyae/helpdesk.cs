import os
import re
import sys
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix='helpdesk_test_')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'test.db').replace('\\', '/')
os.environ['FLASK_ENV'] = 'development'
os.environ['CSRF_ENABLED'] = '0'
os.environ['INITIAL_ADMIN_PASSWORD'] = 'SuperAdmin#123'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402
from extensions import db  # noqa: E402
from models import User  # noqa: E402

PASSWORD = 'Passw0rd!!'


@pytest.fixture(scope='session')
def flask_app():
    app = app_module.app
    app.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False)
    return app


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


def login(client, ident, password=PASSWORD, path='/login'):
    return client.post(path, data={'username': ident, 'password': password}, follow_redirects=False)


@pytest.fixture()
def make_client(flask_app):
    def _make(ident, password=PASSWORD, path='/login'):
        c = flask_app.test_client()
        resp = login(c, ident, password, path)
        assert resp.status_code == 302, f'login failed for {ident}: {resp.status_code}'
        return c
    return _make


@pytest.fixture(scope='session')
def superadmin(flask_app):
    c = flask_app.test_client()
    resp = c.post('/login', data={'username': 'admin', 'password': 'SuperAdmin#123'})
    assert resp.status_code == 302
    with flask_app.app_context():
        u = User.query.execution_options(tenant_bypass=True).filter_by(username='admin').first()
        u.must_change_password = False
        db.session.commit()
    return c


def activate_all(flask_app):
    """Clear forced password change so tests can use accounts created through the UI."""
    with flask_app.app_context():
        User.query.execution_options(tenant_bypass=True).update({'must_change_password': False})
        db.session.commit()


def set_password(flask_app, username, password=PASSWORD):
    with flask_app.app_context():
        u = User.query.execution_options(tenant_bypass=True).filter_by(username=username).first()
        u.set_password(password)
        u.must_change_password = False
        db.session.commit()


PNG = (b'\x89PNG\r\n\x1a\n' + b'\x00' * 32)


def create_school(superadmin_client, flask_app, name, slug=None, admin_email=None, color='#8a1c3c', logo=True):
    import io
    data = {'name': name, 'display_name': f'{name} Helpdesk', 'slug': slug or '',
            'primary_color': color, 'secondary_color': '', 'contact_email': '',
            'admin_email': admin_email or '', 'admin_name': 'School Admin'}
    if logo:
        data['logo_file'] = (io.BytesIO(PNG), 'logo.png')
    resp = superadmin_client.post('/platform/schools/new', data=data, content_type='multipart/form-data')
    assert resp.status_code == 200, resp.get_data(as_text=True)[:500]
    html = resp.get_data(as_text=True)
    pw = None
    if admin_email:
        m = re.findall(r'<code>(.*?)</code>', html)
        pw, username = m[1], m[0]
        set_password(flask_app, username)
        return username
    return None


def create_user_via_ui(client, **fields):
    data = {'password': PASSWORD}
    data.update(fields)
    return client.post('/admin/create_user', data=data)
