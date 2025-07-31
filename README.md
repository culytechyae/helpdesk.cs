# School Helpdesk System

A comprehensive helpdesk application for schools with user management, ticket creation, and agent assignment functionality.

## Features

### User Roles
- **Admin**: Full system access, user management, ticket assignment
- **IT Agent**: Handle IT-related tickets (3 agents available)
- **FM Agent**: Handle Facilities Management tickets (4 agents available)
- **Regular User**: Create tickets and track their status

### Core Functionality
- **Ticket Management**: Create, view, and update tickets
- **Auto-Assignment**: Tickets are automatically assigned to agents based on category and load balancing
- **Comment System**: Users and agents can add comments to tickets
- **Status Tracking**: Track ticket progress (Open → Assigned → In Progress → Resolved → Closed)
- **Priority Levels**: Low, Medium, High, Critical
- **Categories**: IT Support and Facilities Management
- **Email Notifications**: Automatic email notifications for ticket events
- **Email Settings**: Admin can configure SMTP settings for notifications

### Agent Assignment Logic
- IT tickets are assigned to IT agents in FIFO order with load balancing
- FM tickets are assigned to FM agents in FIFO order with load balancing
- System automatically finds the agent with the least assigned tickets

## Installation

1. **Clone or download the project files**

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the application**:
   Open your browser and go to `http://localhost:5000`

## Default Accounts

The system comes with pre-configured accounts:

### Admin Account
- **Username**: admin
- **Password**: admin123

### IT Agents
- **Username**: it_agent_1, it_agent_2, it_agent_3
- **Password**: password123

### FM Agents
- **Username**: fm_agent_1, fm_agent_2, fm_agent_3, fm_agent_4
- **Password**: password123

## Database

The application uses SQLite database (`helpdesk.db`) which is automatically created when you first run the application. The database includes:

- **Users table**: User accounts and roles
- **Tickets table**: Ticket information and status
- **Comments table**: Ticket comments and updates

## Usage Guide

### For Regular Users
1. Login with your credentials
2. Create new tickets for IT or FM issues
3. Track your ticket status and add comments
4. View ticket history and updates

### For Agents (IT/FM)
1. Login with agent credentials
2. View assigned tickets on dashboard
3. Update ticket status as you work on them
4. Add comments to communicate with users
5. Mark tickets as resolved when complete

### For Admins
1. Login with admin credentials
2. View all tickets and system statistics
3. Create new user accounts
4. Manage user roles and permissions
5. Assign tickets to specific agents if needed
6. Monitor system activity
7. Configure email settings for notifications

## Email Configuration

### Setting Up Email Notifications
1. Login as admin and go to "Email Settings"
2. Configure SMTP settings:
   - **SMTP Server**: e.g., smtp.gmail.com
   - **SMTP Port**: Usually 587 for TLS
   - **Email Address**: Your email address
   - **Password**: Your email password or app password
3. Test the configuration by sending a test email
4. Save settings to enable automatic notifications

### Email Notifications
The system sends automatic email notifications for:
- **Ticket Creation**: Notifies both creator and assigned agent
- **Manual Assignment**: Notifies new agent and ticket creator
- **Status Updates**: Notifies ticket creator when status changes

### Supported Email Providers
- **Gmail**: smtp.gmail.com, Port 587 (requires app password)
- **Outlook/Hotmail**: smtp-mail.outlook.com, Port 587
- **Yahoo**: smtp.mail.yahoo.com, Port 587
- **Custom SMTP**: Any SMTP server with proper credentials

## File Structure

```
helpdesk/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── base.html         # Base template with navigation
│   ├── index.html        # Landing page
│   ├── login.html        # Login form
│   ├── admin_dashboard.html    # Admin dashboard
│   ├── user_dashboard.html     # User dashboard
│   ├── agent_dashboard.html    # Agent dashboard
│   ├── create_ticket.html      # Ticket creation form
│   ├── view_ticket.html        # Ticket detail view
│   ├── admin_users.html        # User management
│   └── create_user.html        # User creation form
└── helpdesk.db          # SQLite database (created automatically)
```

## Technical Details

### Technology Stack
- **Backend**: Python Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login
- **Frontend**: Bootstrap 5, Font Awesome icons
- **Password Security**: Werkzeug password hashing

### Key Features
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Updates**: Ticket status updates immediately
- **Role-based Access**: Different interfaces for different user types
- **Load Balancing**: Automatic agent assignment based on current workload
- **Audit Trail**: All actions are logged with timestamps

## Security Features

- Password hashing using Werkzeug
- Session management with Flask-Login
- Role-based access control
- Input validation and sanitization
- SQL injection protection through SQLAlchemy

## Customization

### Adding New User Roles
1. Update the User model in `app.py`
2. Add role-specific logic in routes
3. Create corresponding dashboard templates

### Modifying Agent Assignment
Edit the auto-assignment logic in the `create_ticket` route in `app.py`

### Styling Changes
Modify the CSS in `templates/base.html` or add custom stylesheets

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in `app.py` line 280
2. **Database errors**: Delete `helpdesk.db` and restart the application
3. **Import errors**: Ensure all requirements are installed with `pip install -r requirements.txt`

### Support

For issues or questions, check the application logs or create a ticket in the system itself!

## License

This project is open source and available under the MIT License. 