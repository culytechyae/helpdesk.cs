#!/usr/bin/env python3
"""
Email Templates Initialization Script
This script creates default email templates for the Helpdesk system.
"""

import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, EmailTemplate

def init_email_templates():
    """Initialize email templates"""
    with app.app_context():
        templates = [
            {
                'template_type': 'ticket_created',
                'subject': 'Ticket #{ticket_id} Created - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>New Ticket Created</h2>
                    <p>Your ticket has been created successfully.</p>
                    <table style="border-collapse: collapse; width: 100%;">
                        <tr><td><strong>Ticket ID:</strong></td><td>#{ticket_id}</td></tr>
                        <tr><td><strong>Title:</strong></td><td>{ticket_title}</td></tr>
                        <tr><td><strong>Category:</strong></td><td>{ticket_category}</td></tr>
                        <tr><td><strong>Priority:</strong></td><td>{ticket_priority}</td></tr>
                        <tr><td><strong>Status:</strong></td><td>{ticket_status}</td></tr>
                        <tr><td><strong>Assigned To:</strong></td><td>{assigned_agent}</td></tr>
                        <tr><td><strong>Created:</strong></td><td>{created_date}</td></tr>
                    </table>
                    <p>You will be notified when your ticket is updated.</p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'ticket_assigned_to_agent',
                'subject': 'Ticket #{ticket_id} Assigned - {ticket_title}',
                'body': '''
                <html>
                <body>
                    <h2>Ticket Assigned</h2>
                    <p>A new ticket has been assigned to you.</p>
                    <table style="border-collapse: collapse; width: 100%;">
                        <tr><td><strong>Ticket ID:</strong></td><td>#{ticket_id}</td></tr>
                        <tr><td><strong>Title:</strong></td><td>{ticket_title}</td></tr>
                        <tr><td><strong>Category:</strong></td><td>{ticket_category}</td></tr>
                        <tr><td><strong>Priority:</strong></td><td>{ticket_priority}</td></tr>
                        <tr><td><strong>Created By:</strong></td><td>{creator_name}</td></tr>
                        <tr><td><strong>Created:</strong></td><td>{created_date}</td></tr>
                    </table>
                    <p>Please review and update the ticket status as needed.</p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'comment_added',
                'subject': 'Comment Added to Ticket #{ticket_id}',
                'body': '''
                <html>
                <body>
                    <h2>New Comment Added</h2>
                    <p>A new comment has been added to your ticket.</p>
                    <table style="border-collapse: collapse; width: 100%;">
                        <tr><td><strong>Ticket ID:</strong></td><td>#{ticket_id}</td></tr>
                        <tr><td><strong>Ticket Title:</strong></td><td>{ticket_title}</td></tr>
                        <tr><td><strong>Comment By:</strong></td><td>{comment_author}</td></tr>
                        <tr><td><strong>Comment:</strong></td><td>{comment_content}</td></tr>
                        <tr><td><strong>Date:</strong></td><td>{comment_date}</td></tr>
                    </table>
                    <p>Please log in to view the full comment and respond if needed.</p>
                </body>
                </html>
                '''
            },
            {
                'template_type': 'status_updated',
                'subject': 'Ticket #{ticket_id} Status Updated - {new_status}',
                'body': '''
                <html>
                <body>
                    <h2>Ticket Status Updated</h2>
                    <p>Your ticket status has been updated.</p>
                    <table style="border-collapse: collapse; width: 100%;">
                        <tr><td><strong>Ticket ID:</strong></td><td>#{ticket_id}</td></tr>
                        <tr><td><strong>Ticket Title:</strong></td><td>{ticket_title}</td></tr>
                        <tr><td><strong>Previous Status:</strong></td><td>{old_status}</td></tr>
                        <tr><td><strong>New Status:</strong></td><td>{new_status}</td></tr>
                        <tr><td><strong>Updated By:</strong></td><td>{updated_by}</td></tr>
                        <tr><td><strong>Date:</strong></td><td>{update_date}</td></tr>
                    </table>
                    <p>Please log in to view the full details.</p>
                </body>
                </html>
                '''
            }
        ]
        
        created_count = 0
        for template_data in templates:
            existing = EmailTemplate.query.filter_by(template_type=template_data['template_type']).first()
            if not existing:
                template = EmailTemplate(
                    template_type=template_data['template_type'],
                    subject=template_data['subject'],
                    body=template_data['body'],
                    is_active=True
                )
                db.session.add(template)
                created_count += 1
                print(f"Created template: {template_data['template_type']}")
            else:
                print(f"Template already exists: {template_data['template_type']}")
        
        db.session.commit()
        print(f"\nEmail templates initialization complete!")
        print(f"Created {created_count} new templates.")
        print(f"Total templates: {EmailTemplate.query.count()}")

if __name__ == '__main__':
    print("Initializing email templates...")
    init_email_templates() 