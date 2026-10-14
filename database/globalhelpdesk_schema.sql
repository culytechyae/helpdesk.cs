-- =====================================================================
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

CREATE TABLE IF NOT EXISTS email_settings (
	id SERIAL NOT NULL, 
	smtp_server VARCHAR(100) NOT NULL, 
	smtp_port INTEGER NOT NULL, 
	email_address VARCHAR(120) NOT NULL, 
	email_password VARCHAR(120) NOT NULL, 
	is_active BOOLEAN, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	updated_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS email_templates (
	id SERIAL NOT NULL, 
	template_type VARCHAR(50) NOT NULL, 
	subject VARCHAR(200) NOT NULL, 
	body TEXT NOT NULL, 
	is_active BOOLEAN, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	updated_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (template_type)
);

CREATE TABLE IF NOT EXISTS schools (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	slug VARCHAR(60) NOT NULL, 
	display_name VARCHAR(150), 
	logo_filename VARCHAR(200), 
	primary_color VARCHAR(7), 
	secondary_color VARCHAR(7), 
	contact_email VARCHAR(120), 
	is_active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	updated_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_schools_slug ON schools (slug);

CREATE TABLE IF NOT EXISTS system_settings (
	id SERIAL NOT NULL, 
	system_name VARCHAR(100) NOT NULL, 
	logo_filename VARCHAR(200), 
	updated_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS users (
	id SERIAL NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	email VARCHAR(120) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(20), 
	department TEXT, 
	is_active BOOLEAN, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	school_id INTEGER, 
	full_name VARCHAR(120), 
	must_change_password BOOLEAN, 
	PRIMARY KEY (id), 
	UNIQUE (username), 
	UNIQUE (email), 
	FOREIGN KEY(school_id) REFERENCES schools (id)
);
CREATE INDEX IF NOT EXISTS ix_users_school_id ON users (school_id);

CREATE TABLE IF NOT EXISTS tickets (
	id SERIAL NOT NULL, 
	title VARCHAR(200) NOT NULL, 
	description TEXT NOT NULL, 
	category VARCHAR(50) NOT NULL, 
	priority VARCHAR(20), 
	status VARCHAR(20), 
	created_by INTEGER NOT NULL, 
	assigned_to INTEGER, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	updated_at TIMESTAMP WITHOUT TIME ZONE, 
	school_id INTEGER, 
	external_ref VARCHAR(100), 
	PRIMARY KEY (id), 
	FOREIGN KEY(created_by) REFERENCES users (id), 
	FOREIGN KEY(assigned_to) REFERENCES users (id), 
	FOREIGN KEY(school_id) REFERENCES schools (id)
);
CREATE INDEX IF NOT EXISTS ix_tickets_external_ref ON tickets (external_ref);
CREATE INDEX IF NOT EXISTS ix_tickets_school_id ON tickets (school_id);

CREATE TABLE IF NOT EXISTS user_activity_logs (
	id SERIAL NOT NULL, 
	user_id INTEGER NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	action VARCHAR(100) NOT NULL, 
	details TEXT, 
	ip_address VARCHAR(45), 
	user_agent TEXT, 
	timestamp TIMESTAMP WITHOUT TIME ZONE, 
	school_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	FOREIGN KEY(school_id) REFERENCES schools (id)
);
CREATE INDEX IF NOT EXISTS ix_user_activity_logs_school_id ON user_activity_logs (school_id);

CREATE TABLE IF NOT EXISTS comments (
	id SERIAL NOT NULL, 
	ticket_id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	content TEXT NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE, 
	school_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(ticket_id) REFERENCES tickets (id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	FOREIGN KEY(school_id) REFERENCES schools (id)
);
CREATE INDEX IF NOT EXISTS ix_comments_school_id ON comments (school_id);

-- Tenant-isolation helper indexes (queries always filter by school_id)
CREATE INDEX IF NOT EXISTS ix_tickets_school_status  ON tickets (school_id, status);
CREATE INDEX IF NOT EXISTS ix_tickets_school_created ON tickets (school_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_tickets_assigned_to    ON tickets (assigned_to);
CREATE INDEX IF NOT EXISTS ix_tickets_created_by     ON tickets (created_by);
CREATE INDEX IF NOT EXISTS ix_comments_ticket_id     ON comments (ticket_id);
CREATE INDEX IF NOT EXISTS ix_logs_user_id           ON user_activity_logs (user_id);
CREATE INDEX IF NOT EXISTS ix_users_role             ON users (school_id, role);

COMMIT;
