# Multi-tenant (multi-school) helpdesk

One installation serves many schools. Each school has its own users, agents, tickets, name, logo and colours.

## Roles

| Role | Scope | Can do |
|---|---|---|
| `super_admin` | whole platform | add/suspend schools, set name/logo/colours, create users in any school (incl. school admins and IT/FM/HSE agents), bulk-import users and tickets for any school, "Manage" a school to see its tickets, platform settings, e-mail settings, system pages |
| `admin` (school admin) | own school only | manage the school's users, import users and previous tickets, assign tickets to the school's IT/FM/HSE agents, reports |
| `it_agent` / `fm_agent` / `hse_agent` | own school only | work tickets of the school; receive tickets round-robin per category |
| `user` | own school only | raise and follow own tickets |

## Isolation

Every user, ticket, comment and activity-log row has a `school_id`. A SQLAlchemy hook (`tenancy.py`) adds the school
filter to **every** query, including lazy loads, so a school can never read or modify another school's rows even
through a guessed URL (cross-school ids return 404). With no school context (anonymous, or a super admin who has
not entered a school) queries return nothing. Platform code opts out explicitly with `all_schools()`.

## Typical set-up

1. Sign in as super admin → **Schools → Add School**. Enter name, display name, colours, logo and (optionally) the
   first school admin's email. A temporary password is shown once.
2. Share the school's sign-in link `https://<host>/s/<slug>` (shows that school's branding). Users can also sign in
   on `/login`; they always land in their own school's UI.
3. **Admin Tools → Import Users** (CSV/XLSX, templates provided) to load staff, agents (`it_agent`, `fm_agent`,
   `hse_agent`) and requesters. Super admin may include a `school` column (slug/name) to load several schools at once.
4. **Admin Tools → Import Previous Tickets** to load history (original dates, status, requester, assigned agent,
   resolution comment). Imports are idempotent (`ticket_id` / title+requester+date), send no e-mails and do not
   affect round-robin.
5. New tickets are auto-assigned round-robin to active agents of the *same school and category*. School admins can
   reassign manually from the ticket page.

Tick **Validate only** on either import to preview errors without saving.

## Import formats

Users: `email` (required), `username`, `full_name`, `role` (`user` default, `it_agent`, `fm_agent`, `hse_agent`,
`admin`), `department`, `password` (generated if blank), `school` (super admin only).

Tickets: `title` (required), `description`, `category` (`IT`/`FM`/`HSE`), `priority`, `status`, `requester`
(username or email), `assigned_to`, `created_at`, `updated_at`, `ticket_id`, `comments`, `school`.
Text dates are read day-first (`31/12/2025`) or ISO (`2025-12-31 14:30`). Limits: 5,000 rows, 5 MB per file.

## Configuration

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | `sqlite:///helpdesk.db` (default) or `postgresql+psycopg2://user:pass@host/db` |
| `SECRET_KEY` | **set this in production**. If missing a random key is generated in `instance/secret_key` |
| `FLASK_ENV` | `production` for production settings |
| `SESSION_COOKIE_SECURE=1` | when served over HTTPS |
| `INITIAL_ADMIN_PASSWORD` / `INITIAL_ADMIN_EMAIL` | credentials of the first super admin on an empty database. If unset a random password is printed once and a password change is forced |
| `ERROR_NOTIFICATION_EMAIL` | optional address that receives 500-error e-mails |

Create/reset a super admin from the command line: `flask --app app create-superadmin`.

## Upgrading an existing installation

Start the new version: the schema migration is automatic and idempotent. Existing users (except super admins),
tickets, comments and logs are moved into a school created from your current system name/logo. Take a backup
first (Super admin → System → Backups, or `pg_dump`). Then add further schools as above.

## Notes and limits

* A user belongs to exactly one school. Usernames and e-mails are unique platform-wide (users may sign in with either);
  when importing without usernames they are derived from the e-mail and made unique automatically.
* SMTP settings and e-mail templates are platform-wide (super admin). Outgoing mails carry the school's name.
* Moving a user between schools is only allowed while they have no tickets/comments.
* Schools with data cannot be deleted - suspend them (users are signed out immediately).
* Run the tests with `python -m pytest`.
