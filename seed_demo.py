"""Create demo data: one school with an admin, user, IT agent, FM agent (+ HSE agent) and sample tickets.

Run:  python seed_demo.py        (idempotent; safe to run twice)
"""
import random
from datetime import timedelta

from app import app, db
from models import School, User, Ticket, Comment, utc_now

PASSWORD = 'Demo@1234'
SCHOOL = {'name': 'Demo International School', 'slug': 'demo-school', 'display_name': 'Demo School Helpdesk',
          'primary_color': '#1d4e89', 'secondary_color': '#3a86c8', 'contact_email': 'it@demo-school.example'}
USERS = [
    ('demo_admin', 'admin', 'Demo School Admin', 'admin@demo-school.example'),
    ('demo_user', 'user', 'Demo Teacher', 'teacher@demo-school.example'),
    ('demo_it', 'it_agent', 'Demo IT Agent', 'it@demo-school.example'),
    ('demo_fm', 'fm_agent', 'Demo FM Agent', 'fm@demo-school.example'),
    ('demo_hse', 'hse_agent', 'Demo HSE Agent', 'hse@demo-school.example'),
]
TICKETS = [
    ('IT', 'Projector not displaying in Room 12'), ('IT', 'Cannot log in to Wi-Fi'),
    ('IT', 'Printer jam in staff room'), ('IT', 'Laptop battery drains quickly'),
    ('FM', 'Leaking tap in cafeteria'), ('FM', 'Air conditioner not cooling in lab'),
    ('FM', 'Broken chair in Grade 5'), ('HSE', 'Fire extinguisher inspection overdue'),
    ('HSE', 'Slippery floor near entrance'), ('IT', 'Smart board calibration'),
]


def main():
    random.seed(7)
    with app.app_context():
        school = School.query.filter_by(slug=SCHOOL['slug']).first()
        if not school:
            school = School(**SCHOOL)
            db.session.add(school)
            db.session.flush()
        created = {}
        for username, role, full, email in USERS:
            u = User.query.execution_options(tenant_bypass=True).filter_by(username=username).first()
            if not u:
                u = User(username=username, email=email, role=role, full_name=full, school_id=school.id)
                db.session.add(u)
            u.set_password(PASSWORD)
            u.must_change_password = False
            created[username] = u
        db.session.flush()

        if not Ticket.query.execution_options(tenant_bypass=True).filter_by(school_id=school.id).first():
            now = utc_now().replace(tzinfo=None)
            agent_for = {'IT': created['demo_it'], 'FM': created['demo_fm'], 'HSE': created['demo_hse']}
            for i in range(40):
                category, title = random.choice(TICKETS)
                created_at = now - timedelta(days=random.randint(0, 60), hours=random.randint(0, 23))
                status = random.choices(['Open', 'Assigned', 'In Progress', 'Resolved', 'Closed'],
                                        [2, 2, 2, 3, 3])[0]
                agent = agent_for[category] if status != 'Open' else None
                updated = created_at + timedelta(hours=random.randint(2, 96)) if status in ('Resolved', 'Closed') \
                    else created_at
                t = Ticket(title=f'{title} #{i + 1}', description=f'{title}. Please investigate.',
                           category=category, priority=random.choice(['Low', 'Medium', 'High', 'Critical']),
                           status=status, created_by=created['demo_user'].id,
                           assigned_to=agent.id if agent else None,
                           created_at=created_at, updated_at=updated, school_id=school.id)
                db.session.add(t)
                if status in ('Resolved', 'Closed'):
                    db.session.flush()
                    db.session.add(Comment(ticket_id=t.id, user_id=agent.id, content='Issue fixed.',
                                           created_at=updated, school_id=school.id))
        db.session.commit()
    print(f'Demo school ready: /s/{SCHOOL["slug"]}   password for all demo users: {PASSWORD}')
    for username, role, _, _ in USERS:
        print(f'  {username:<11} {role}')


if __name__ == '__main__':
    main()
