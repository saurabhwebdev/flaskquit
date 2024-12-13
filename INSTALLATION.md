# QuitPuff Installation Guide

## Local Development Setup

### Prerequisites
- Python 3.12.2 or higher
- pip (Python package installer)
- Git

### Step 1: Clone the Repository
```bash
git clone <your-repository-url>
cd CTF
```

### Step 2: Set Up Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# For Windows:
.\venv\Scripts\activate
# For Unix/MacOS:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Initialize Database
```bash
python init_db.py
```

### Step 5: Run the Application
```bash
python app.py
```
The application will be available at `http://127.0.0.1:5000`

## Production Deployment (Render)

### Step 1: Create a Render Account
1. Go to [render.com](https://render.com)
2. Sign up for an account
3. Connect your GitHub repository

### Step 2: Create a New Web Service
1. Click "New +" and select "Web Service"
2. Connect your repository
3. Configure the following settings:
   - Name: Your app name
   - Environment: Python 3
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

### Step 3: Set Environment Variables
Add the following environment variables in Render dashboard:
- `FLASK_APP`: app.py
- `ADMIN_CREATE_TOKEN`: Your secret token for admin creation
- Any other environment-specific variables

## Creating Admin Account

### Method 1: Using Web Interface
1. Access the admin creation page using:
```
https://your-app.onrender.com/create-admin/your_secret_token
```
2. Fill in the admin details:
   - Full Name
   - Email
   - Password

### Method 2: Using Python Script
1. SSH into your server or use Render shell
2. Run the admin creation script:
```bash
python create_render_admin.py
```

Default admin credentials (if using script without environment variables):
- Email: admin@quitpuff.com
- Password: admin123
- Name: Admin User

To customize admin credentials, set these environment variables:
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME`

## Admin Features

### Accessing Admin Dashboard
After creating an admin account:
1. Log in with admin credentials
2. Access admin features through the profile dropdown menu:
   - Admin Dashboard (`/admin/dashboard`)
   - Manage Users (`/admin/users`)

### Admin Dashboard Features
- Total users count
- Total entries tracking
- Active users today
- User registration trends
- Most active users list
- Recent registrations
- Activity charts
- User management capabilities

### Security Notes
1. Change default admin password after first login
2. Keep your `ADMIN_CREATE_TOKEN` secure
3. Use strong passwords
4. Regularly monitor admin access

## Database Management

### Local Development
SQLite database is used by default:
- Location: `instance/database.db`
- Initialization: `python init_db.py`

### Production (PostgreSQL)
1. Render automatically provisions a PostgreSQL database
2. Database URL is provided as environment variable
3. Migrations handled automatically

### Backup and Restore
Use provided scripts:
```bash
# Backup
python backup_db.py

# Restore
python restore_db.py
```

## Troubleshooting

### Common Issues

1. Database Connection Errors
```bash
# Check database initialization
python init_db.py

# Verify environment variables
echo $DATABASE_URL
```

2. Admin Access Issues
```bash
# Verify admin status
python
>>> from app import app, db
>>> from models import User
>>> with app.app_context():
...     user = User.query.filter_by(email='your@email.com').first()
...     print(f"Is Admin: {user.is_admin}")
```

3. Deployment Issues
- Check Render logs for errors
- Verify Python version compatibility
- Ensure all requirements are in requirements.txt

### Getting Help
- Check the GitHub repository issues
- Contact the development team
- Review application logs

## Updates and Maintenance

### Updating Dependencies
```bash
pip freeze > requirements.txt
```

### Database Migrations
When making model changes:
```bash
flask db migrate -m "Description of changes"
flask db upgrade
``` 