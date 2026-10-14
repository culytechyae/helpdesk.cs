"""Upgrade of a pre-multi-tenant database (no school_id columns) must be automatic and lossless."""
import os
import sqlite3
import subprocess
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LEGACY_SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(80) NOT NULL UNIQUE, email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(120) NOT NULL, role VARCHAR(20), department TEXT, is_active BOOLEAN, created_at DATETIME);
CREATE TABLE tickets (id INTEGER PRIMARY KEY, title VARCHAR(200) NOT NULL, description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL, priority VARCHAR(20), status VARCHAR(20), created_by INTEGER NOT NULL,
    assigned_to INTEGER, created_at DATETIME, updated_at DATETIME);
CREATE TABLE comments (id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    content TEXT NOT NULL, created_at DATETIME);
CREATE TABLE user_activity_logs (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, username VARCHAR(80) NOT NULL,
    action VARCHAR(100) NOT NULL, details TEXT, ip_address VARCHAR(45), user_agent TEXT, timestamp DATETIME);
CREATE TABLE system_settings (id INTEGER PRIMARY KEY, system_name VARCHAR(100) NOT NULL, logo_filename VARCHAR(200),
    updated_at DATETIME);
INSERT INTO system_settings VALUES (1, 'Legacy Helpdesk', NULL, '2026-01-01 00:00:00');
INSERT INTO users VALUES (1, 'root', 'root@x.com', 'h', 'super_admin', NULL, 1, '2026-01-01 00:00:00');
INSERT INTO users VALUES (2, 'boss', 'boss@x.com', 'h', 'admin', NULL, 1, '2026-01-01 00:00:00');
INSERT INTO users VALUES (3, 'ann', 'ann@x.com', 'h', 'user', NULL, 1, '2026-01-01 00:00:00');
INSERT INTO users VALUES (4, 'ivy', 'ivy@x.com', 'h', 'it_agent', NULL, 1, '2026-01-01 00:00:00');
INSERT INTO tickets VALUES (1, 'Old ticket', 'desc', 'IT', 'High', 'Open', 3, 4, '2026-01-02 00:00:00', '2026-01-02 00:00:00');
INSERT INTO comments VALUES (1, 1, 4, 'old comment', '2026-01-02 01:00:00');
INSERT INTO user_activity_logs VALUES (1, 3, 'ann', 'login', 'x', '1.1.1.1', 'ua', '2026-01-02 00:00:00');
"""

CHECK = textwrap.dedent("""
    import os, sys
    sys.path.insert(0, r'%s')
    import app as m
    from models import School, User, Ticket, Comment, UserActivityLog
    with m.app.app_context():
        schools = School.query.all()
        assert len(schools) == 1, schools
        s = schools[0]
        assert s.name == 'Legacy Helpdesk', s.name
        bypass = dict(tenant_bypass=True)
        users = {u.username: u for u in User.query.execution_options(**bypass)}
        assert users['root'].school_id is None                       # super admin stays platform-level
        assert all(users[n].school_id == s.id for n in ('boss', 'ann', 'ivy'))
        assert Ticket.query.execution_options(**bypass).one().school_id == s.id
        assert Comment.query.execution_options(**bypass).one().school_id == s.id
        assert UserActivityLog.query.execution_options(**bypass).one().school_id == s.id
        m.run_migrations(m.app)                                       # idempotent
        assert School.query.count() == 1
    c = m.app.test_client()
    # boss (legacy school admin) can still sign in after resetting the stub hash
    with m.app.app_context():
        u = User.query.execution_options(tenant_bypass=True).filter_by(username='boss').one()
        u.set_password('Passw0rd!!'); m.db.session.commit()
    r = c.post('/login', data={'username': 'boss', 'password': 'Passw0rd!!'})
    assert r.status_code == 302, r.status_code
    html = c.get('/admin/tickets').get_data(as_text=True)
    assert 'Old ticket' in html and 'Legacy Helpdesk' in html
    print('MIGRATION-OK')
""" % ROOT)


def test_legacy_database_is_upgraded(tmp_path):
    db_path = tmp_path / 'legacy.db'
    conn = sqlite3.connect(db_path)
    conn.executescript(LEGACY_SCHEMA)
    conn.commit()
    conn.close()
    env = dict(os.environ, DATABASE_URL='sqlite:///' + str(db_path).replace('\\', '/'), FLASK_ENV='development',
               CSRF_ENABLED='0')
    out = subprocess.run([sys.executable, '-c', CHECK], env=env, capture_output=True, text=True, cwd=str(tmp_path))
    assert 'MIGRATION-OK' in out.stdout, out.stdout + out.stderr
    # columns really exist on disk
    conn = sqlite3.connect(db_path)
    for table in ('users', 'tickets', 'comments', 'user_activity_logs'):
        cols = [r[1] for r in conn.execute(f'pragma table_info({table})')]
        assert 'school_id' in cols, table
    conn.close()
