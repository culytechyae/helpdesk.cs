# Email Configuration Troubleshooting Guide

## Overview
This guide helps you resolve common email configuration issues in the Helpdesk system.

## Quick Diagnosis

### 1. Check Current Status
- Go to Admin Dashboard → Email Settings
- Verify if settings are configured
- Check the status information at the bottom of the page

### 2. Test Connection
- Use the "Test Connection" button
- Check console output for detailed error messages
- Use the "Send Test Email" feature

## Common Issues and Solutions

### 🔐 Authentication Errors

#### Gmail Authentication Issues
**Error:** `SMTP Authentication failed: (535, b'5.7.8 Username and Password not accepted. Use an App Password.')`

**Solution:**
1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
3. Use the App Password instead of your regular password
4. Settings:
   - SMTP Server: `smtp.gmail.com`
   - Port: `587`
   - Security: TLS

#### Outlook Authentication Issues
**Error:** `SMTP Authentication failed`

**Solution:**
1. Use your full email address
2. Use your regular password (not App Password)
3. Settings:
   - SMTP Server: `smtp-mail.outlook.com`
   - Port: `587`
   - Security: TLS

#### Yahoo Authentication Issues
**Error:** `Authentication failed`

**Solution:**
1. Generate an App Password:
   - Go to Yahoo Account Security
   - App passwords → Generate app password
2. Use the App Password instead of your regular password
3. Settings:
   - SMTP Server: `smtp.mail.yahoo.com`
   - Port: `587`
   - Security: TLS

### 🌐 Connection Errors

#### SMTP Connection Failed
**Error:** `SMTP Connection failed`

**Solutions:**
1. **Check Internet Connection**
   - Ensure you have a stable internet connection
   - Try accessing other websites

2. **Verify SMTP Server and Port**
   - Double-check the SMTP server address
   - Try different ports: 587, 465, 25
   - Common servers:
     - Gmail: `smtp.gmail.com:587`
     - Outlook: `smtp-mail.outlook.com:587`
     - Yahoo: `smtp.mail.yahoo.com:587`

3. **Firewall Issues**
   - Check if your firewall is blocking the connection
   - Allow the application through your firewall
   - Try temporarily disabling firewall for testing

4. **Corporate Network**
   - Some corporate networks block SMTP ports
   - Contact your IT department
   - Use company SMTP server if available

#### Port Blocked
**Error:** `Connection refused` or `Timeout`

**Solutions:**
1. Try different ports:
   - Port 587 (TLS)
   - Port 465 (SSL)
   - Port 25 (not recommended for security)

2. Check with your email provider for correct port

### 🔒 Security Issues

#### SSL/TLS Errors
**Error:** `SSL/TLS connection failed`

**Solutions:**
1. Ensure TLS is enabled
2. Use port 587 for TLS
3. Use port 465 for SSL
4. Check if your email provider requires specific security settings

#### Less Secure Apps
**Error:** `Less secure app access not allowed`

**Solutions:**
1. **For Gmail:** Use App Password instead of regular password
2. **For Outlook:** Enable "Less secure apps" in account settings
3. **For Yahoo:** Use App Password

## Step-by-Step Configuration

### Gmail Setup
1. **Enable 2-Factor Authentication**
   - Go to Google Account settings
   - Security → 2-Step Verification
   - Enable 2FA

2. **Generate App Password**
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Select "Mail" and generate password

3. **Configure Settings**
   - SMTP Server: `smtp.gmail.com`
   - Port: `587`
   - Email: Your Gmail address
   - Password: App Password (not regular password)

### Outlook Setup
1. **Use Regular Password**
   - Use your full email address
   - Use your regular password

2. **Configure Settings**
   - SMTP Server: `smtp-mail.outlook.com`
   - Port: `587`
   - Email: Your Outlook email
   - Password: Your regular password

### Yahoo Setup
1. **Generate App Password**
   - Go to Yahoo Account Security
   - App passwords → Generate app password

2. **Configure Settings**
   - SMTP Server: `smtp.mail.yahoo.com`
   - Port: `587`
   - Email: Your Yahoo email
   - Password: App Password

## Testing Your Configuration

### 1. Connection Test
- Use the "Test Connection" button
- Check console output for detailed messages
- Verify server and port are reachable

### 2. Authentication Test
- The system will test authentication automatically
- Check for specific error messages
- Verify email and password are correct

### 3. Send Test Email
- Use the "Send Test Email" feature
- Enter a valid email address
- Check if the email is received

## Debug Information

### Console Output
The system provides detailed console output for troubleshooting:
```
Testing email configuration...
SMTP Server: smtp.gmail.com:587
From Email: your-email@gmail.com
To Email: test@example.com
Testing connection to smtp.gmail.com:587...
✅ Connection to smtp.gmail.com:587 successful
Testing authentication for your-email@gmail.com...
Starting TLS...
Attempting login...
✅ Authentication successful!
Sending test email from your-email@gmail.com to test@example.com...
✅ Test email sent successfully!
```

### Common Error Messages
- `Authentication failed`: Check email/password, use App Password for 2FA
- `Connection failed`: Check server/port, internet connection
- `Port blocked`: Try different ports (587, 465)
- `SSL/TLS error`: Check security settings

## Advanced Troubleshooting

### Network Diagnostics
1. **Test SMTP Server Reachability**
   ```bash
   telnet smtp.gmail.com 587
   ```

2. **Check DNS Resolution**
   ```bash
   nslookup smtp.gmail.com
   ```

3. **Test Port Connectivity**
   ```bash
   netstat -an | findstr :587
   ```

### Email Provider Specific Issues

#### Gmail
- **Issue:** "Less secure app access"
- **Solution:** Use App Password with 2FA

#### Outlook
- **Issue:** Authentication failed
- **Solution:** Enable "Less secure apps" or use App Password

#### Yahoo
- **Issue:** Password not accepted
- **Solution:** Generate and use App Password

### Corporate/Enterprise Email
- **Issue:** Company SMTP server
- **Solution:** Contact IT department for SMTP settings
- **Common Settings:**
  - Server: `smtp.company.com`
  - Port: `587` or `25`
  - Authentication: Usually required

## Prevention Tips

### 1. Use App Passwords
- Always use App Passwords for 2FA accounts
- Never use regular passwords with 2FA enabled

### 2. Regular Testing
- Test email configuration regularly
- Monitor for authentication failures
- Update passwords when needed

### 3. Backup Configuration
- Keep a backup of working email settings
- Document any special requirements
- Test after system updates

## Getting Help

### 1. Check Console Output
- Look for detailed error messages
- Note the specific error type
- Check the troubleshooting steps above

### 2. Contact Support
- If issues persist, contact your email provider
- Check their official documentation
- Verify account security settings

### 3. Alternative Solutions
- Try different email providers
- Use company SMTP server if available
- Consider using email service providers

## Quick Reference

### Common SMTP Settings
| Provider | Server | Port | Security | Notes |
|----------|--------|------|----------|-------|
| Gmail | smtp.gmail.com | 587 | TLS | Use App Password |
| Outlook | smtp-mail.outlook.com | 587 | TLS | Regular password |
| Yahoo | smtp.mail.yahoo.com | 587 | TLS | Use App Password |
| Office 365 | smtp.office365.com | 587 | TLS | Regular password |

### Error Code Reference
- `535`: Authentication failed
- `550`: Recipient not found
- `553`: Sender not authorized
- `554`: Transaction failed

### Testing Commands
```bash
# Test SMTP connection
telnet smtp.gmail.com 587

# Check if port is open
netstat -an | findstr :587

# Test DNS resolution
nslookup smtp.gmail.com
```

## Success Indicators

✅ **Configuration Working:**
- Connection test passes
- Authentication successful
- Test email sent and received
- No error messages in console

❌ **Configuration Issues:**
- Connection fails
- Authentication errors
- Test email not received
- Error messages in console

Follow this guide step by step to resolve your email configuration issues! 