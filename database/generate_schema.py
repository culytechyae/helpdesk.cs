"""Regenerate database/globalhelpdesk_schema.sql from the SQLAlchemy models (PostgreSQL dialect)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('DATABASE_URL', 'sqlite://')

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable, CreateIndex

from extensions import db
import models  # noqa: F401

HEADER = """-- =====================================================================
-- Global Helpdesk - PostgreSQL schema (multi-tenant: schools)
-- Database : globalhelpdesk        Application port : 5008
--
-- 1) As a superuser create the role and database (see database/setup_postgres.bat):
--      CREATE ROLE helpdesk_app LOGIN PASSWORD '<strong password>';
--      CREATE DATABASE globalhelpdesk OWNER helpdesk_app ENCODING 'UTF8';
-- 2) Connect to globalhelpdesk and run this file:
--      psql -U helpdesk_app -d globalhelpdesk -f database/globalhelpdesk_schema.sql
-- The application also creates/upgrades these tables itself on start (idempotent),
-- so running this file is optional but recommended for DBAs who manage DDL.
-- =====================================================================

BEGIN;
"""

FOOTER = """
-- Tenant-isolation helper indexes (queries always filter by school_id)
CREATE INDEX IF NOT EXISTS ix_tickets_school_status  ON tickets (school_id, status);
CREATE INDEX IF NOT EXISTS ix_tickets_school_created ON tickets (school_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_tickets_assigned_to    ON tickets (assigned_to);
CREATE INDEX IF NOT EXISTS ix_tickets_created_by     ON tickets (created_by);
CREATE INDEX IF NOT EXISTS ix_comments_ticket_id     ON comments (ticket_id);
CREATE INDEX IF NOT EXISTS ix_logs_user_id           ON user_activity_logs (user_id);
CREATE INDEX IF NOT EXISTS ix_users_role             ON users (school_id, role);

COMMIT;
"""

dialect = postgresql.dialect()
out = [HEADER]
for table in db.metadata.sorted_tables:
    sql = str(CreateTable(table, if_not_exists=True).compile(dialect=dialect)).strip()
    out.append(f'\n{sql};\n')
    for index in sorted(table.indexes, key=lambda i: i.name):
        idx = str(CreateIndex(index, if_not_exists=True).compile(dialect=dialect)).strip()
        out.append(f'{idx};\n')
out.append(FOOTER)
target = os.path.join(ROOT, 'database', 'globalhelpdesk_schema.sql')
with open(target, 'w', encoding='utf-8', newline='\n') as fh:
    fh.write(''.join(out))
print('written', target)
