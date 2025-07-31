# Email Configuration and Troubleshooting Module
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import socket
import time

class EmailConfig:
    """Email configuration and troubleshooting class"""
    
    # Common SMTP configurations
    SMTP_CONFIGS = {
        'gmail': {
            'server': 'smtp.gmail.com',
            'port': 587,
            'security': 'TLS',
            'notes': 'Requires App Password if 2FA is enabled'
        },
        'outlook': {
            'server': 'smtp-mail.outlook.com',
            'port': 587,
            'security': 'TLS',
            'notes': 'Use email and password'
        },
        'yahoo': {
            'server': 'smtp.mail.yahoo.com',
            'port': 587,
            'security': 'TLS',
            'notes': 'Requires App Password'
        },
        'office365': {
            'server': 'smtp.office365.com',
            'port': 587,
            'security': 'TLS',
            'notes': 'Use email and password'
        },
        'custom': {
            'server': '',
            'port': 587,
            'security': 'TLS',
            'notes': 'Configure your custom SMTP server'
        }
    }
    
    @staticmethod
    def test_smtp_connection(server, port, timeout=10):
        """Test SMTP server connectivity"""
        try:
            print(f"Testing connection to {server}:{port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((server, port))
            sock.close()
            
            if result == 0:
                print(f"✅ Connection to {server}:{port} successful")
                return True
            else:
                print(f"❌ Connection to {server}:{port} failed")
                return False
        except Exception as e:
            print(f"❌ Connection test failed: {str(e)}")
            return False
    
    @staticmethod
    def test_smtp_authentication(server, port, email, password, timeout=30):
        """Test SMTP authentication"""
        try:
            print(f"Testing authentication for {email}...")
            
            # Create SMTP connection
            smtp = smtplib.SMTP(server, port, timeout=timeout)
            smtp.set_debuglevel(1)  # Enable debug output
            
            # Start TLS
            print("Starting TLS...")
            smtp.starttls()
            
            # Login
            print("Attempting login...")
            smtp.login(email, password)
            
            print("✅ Authentication successful!")
            smtp.quit()
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ Authentication failed: {str(e)}")
            print("💡 Troubleshooting tips:")
            print("   - Check if your email and password are correct")
            print("   - For Gmail: Use App Password if 2FA is enabled")
            print("   - For Outlook: Make sure 'Less secure apps' is enabled")
            print("   - Try using your full email address")
            return False
            
        except smtplib.SMTPConnectError as e:
            print(f"❌ Connection failed: {str(e)}")
            print("💡 Troubleshooting tips:")
            print("   - Check if the SMTP server and port are correct")
            print("   - Check your internet connection")
            print("   - Try a different port (587 or 465)")
            return False
            
        except Exception as e:
            print(f"❌ Authentication test failed: {str(e)}")
            return False
    
    @staticmethod
    def send_test_email(server, port, email, password, to_email, timeout=30):
        """Send a test email"""
        try:
            print(f"Sending test email from {email} to {to_email}...")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = email
            msg['To'] = to_email
            msg['Subject'] = "Test Email - Helpdesk System"
            
            body = f"""
            <html>
            <body>
                <h2>Test Email</h2>
                <p>This is a test email from the Helpdesk system.</p>
                <p>If you received this email, the email configuration is working correctly.</p>
                <p><strong>Sent at:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>SMTP Server:</strong> {server}:{port}</p>
                <p><strong>From Email:</strong> {email}</p>
                <hr>
                <p><small>This is an automated test email. Please do not reply.</small></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            smtp = smtplib.SMTP(server, port, timeout=timeout)
            smtp.starttls()
            smtp.login(email, password)
            
            text = msg.as_string()
            smtp.sendmail(email, to_email, text)
            smtp.quit()
            
            print("✅ Test email sent successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Test email failed: {str(e)}")
            return False
    
    @staticmethod
    def get_provider_config(provider):
        """Get SMTP configuration for a specific provider"""
        return EmailConfig.SMTP_CONFIGS.get(provider, EmailConfig.SMTP_CONFIGS['custom'])
    
    @staticmethod
    def validate_email_settings(server, port, email, password):
        """Validate email settings"""
        errors = []
        
        # Check server
        if not server or len(server.strip()) == 0:
            errors.append("SMTP server is required")
        
        # Check port
        try:
            port = int(port)
            if port < 1 or port > 65535:
                errors.append("Port must be between 1 and 65535")
        except (ValueError, TypeError):
            errors.append("Port must be a valid number")
        
        # Check email format
        if not email or '@' not in email:
            errors.append("Valid email address is required")
        
        # Check password
        if not password or len(password.strip()) == 0:
            errors.append("Password is required")
        
        return errors
    
    @staticmethod
    def get_troubleshooting_guide(provider='gmail'):
        """Get troubleshooting guide for specific provider"""
        guides = {
            'gmail': {
                'title': 'Gmail Configuration Guide',
                'steps': [
                    '1. Enable 2-Factor Authentication on your Google account',
                    '2. Generate an App Password:',
                    '   - Go to Google Account settings',
                    '   - Security > 2-Step Verification > App passwords',
                    '   - Generate password for "Mail"',
                    '3. Use the App Password instead of your regular password',
                    '4. SMTP Server: smtp.gmail.com',
                    '5. Port: 587',
                    '6. Security: TLS'
                ],
                'common_issues': [
                    'Authentication failed: Use App Password, not regular password',
                    'Connection failed: Check internet connection and firewall',
                    'Port blocked: Try port 587 or 465'
                ]
            },
            'outlook': {
                'title': 'Outlook/Hotmail Configuration Guide',
                'steps': [
                    '1. Use your full email address',
                    '2. Use your regular password',
                    '3. SMTP Server: smtp-mail.outlook.com',
                    '4. Port: 587',
                    '5. Security: TLS'
                ],
                'common_issues': [
                    'Authentication failed: Check email and password',
                    'Connection failed: Check internet connection',
                    'Security settings: Enable "Less secure apps" if needed'
                ]
            },
            'yahoo': {
                'title': 'Yahoo Configuration Guide',
                'steps': [
                    '1. Generate an App Password:',
                    '   - Go to Yahoo Account Security',
                    '   - App passwords > Generate app password',
                    '2. Use the App Password instead of your regular password',
                    '3. SMTP Server: smtp.mail.yahoo.com',
                    '4. Port: 587',
                    '5. Security: TLS'
                ],
                'common_issues': [
                    'Authentication failed: Use App Password, not regular password',
                    'Connection failed: Check internet connection',
                    'Account security: Enable app passwords in Yahoo settings'
                ]
            }
        }
        
        return guides.get(provider, guides['gmail'])

def create_email_settings_template():
    """Create default email templates"""
    from app import db, EmailTemplate
    
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
    
    db.session.commit()
    print("Email templates created successfully!") 