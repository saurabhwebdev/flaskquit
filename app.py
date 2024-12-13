from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, CigaretteEntry
from flask_migrate import Migrate
from functools import wraps
from sqlalchemy import func
import os
from datetime import datetime, timedelta
import pytz
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Configure logging
if not app.debug:
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    # Set up file handler
    file_handler = RotatingFileHandler('logs/cigarette_tracker.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    app.logger.addHandler(console_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('Cigarette Tracker startup')

# Load configuration
app.config.from_object('config.Config')

# Initialize extensions
try:
    db.init_app(app)
    app.logger.info('Database initialized successfully')
except Exception as e:
    app.logger.error(f'Error initializing database: {str(e)}')
    raise

# Create tables if they don't exist
with app.app_context():
    try:
        db.create_all()
        app.logger.info('Database tables created successfully')
    except Exception as e:
        app.logger.error(f'Error creating database tables: {str(e)}')
        raise

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        app.logger.error(f'Error loading user {user_id}: {str(e)}')
        return None

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {str(error)}')
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        age = request.form.get('age')
        smoking_since = request.form.get('smoking_since')
        daily_cigarettes = request.form.get('daily_cigarettes')
        cigarette_cost = request.form.get('cigarette_cost')
        currency = request.form.get('currency', 'INR')
        pack_cost = request.form.get('pack_cost')
        cigarettes_per_pack = request.form.get('cigarettes_per_pack')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists')
            return redirect(url_for('signup'))

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            age=age,
            smoking_since=smoking_since,
            daily_cigarettes=daily_cigarettes,
            cigarette_cost=cigarette_cost,
            currency=currency,
            pack_cost=pack_cost,
            cigarettes_per_pack=cigarettes_per_pack
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('auth/signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials')
    return render_template('auth/login.html')

@app.route('/create-admin', methods=['POST'])
def create_admin_form():
    token = request.form.get('token')
    if token != 'SAU@808rabh':
        flash('Invalid admin token', 'error')
        return redirect(url_for('login'))

    return render_template('admin/create_admin.html')

@app.route('/submit-admin', methods=['POST'])
def submit_admin():
    token = request.form.get('token')
    if token != 'SAU@808rabh':
        flash('Invalid admin token', 'error')
        return redirect(url_for('login'))

    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    if not all([name, email, password]):
        flash('All fields are required', 'error')
        return redirect(url_for('create_admin_form'))

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already exists', 'error')
        return redirect(url_for('create_admin_form'))

    new_admin = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        is_admin=True
    )

    try:
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin account created successfully', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        flash('Error creating admin account', 'error')
        return redirect(url_for('create_admin_form'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get today's date
    today = datetime.now().date()
    
    # Get selected date from query parameters
    selected_date = request.args.get('date')
    
    # Base query for entries
    entries_query = CigaretteEntry.query.filter_by(user_id=current_user.id)
    
    # Initialize filter flag
    is_filtered = False
    
    if selected_date:
        try:
            filter_date = datetime.strptime(selected_date, '%Y-%m-%d').date()
            entries_query = entries_query.filter(
                db.func.date(CigaretteEntry.timestamp) == filter_date
            )
            is_filtered = True
        except ValueError:
            flash('Invalid date format', 'error')
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get paginated entries
    paginated_entries = entries_query.order_by(
        CigaretteEntry.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # Calculate total cigarettes and money spent (all time)
    total_cigarettes = CigaretteEntry.query.filter_by(user_id=current_user.id).with_entities(
        db.func.sum(CigaretteEntry.count)).scalar() or 0
    total_spent = total_cigarettes * current_user.cigarette_cost
    
    # Get today's entries for the first card
    today_entries = CigaretteEntry.query.filter_by(user_id=current_user.id).filter(
        db.func.date(CigaretteEntry.timestamp) == today
    ).all()
    today_count = sum(entry.count for entry in today_entries)
    
    # Calculate cumulative money saved
    # Get all dates from first entry to today
    first_entry = CigaretteEntry.query.filter_by(user_id=current_user.id).order_by(
        CigaretteEntry.timestamp.asc()
    ).first()
    
    total_saved = 0
    if first_entry:
        start_date = first_entry.timestamp.date()
        date_range = (today - start_date).days + 1
        
        # Calculate savings for each day
        for day_offset in range(date_range):
            current_date = start_date + timedelta(days=day_offset)
            
            # Get cigarettes smoked on this day
            day_entries = CigaretteEntry.query.filter_by(user_id=current_user.id).filter(
                db.func.date(CigaretteEntry.timestamp) == current_date
            ).all()
            day_count = sum(entry.count for entry in day_entries)
            
            # Calculate savings for this day
            day_target_cost = current_user.daily_cigarettes * current_user.cigarette_cost
            day_actual_cost = day_count * current_user.cigarette_cost
            day_saved = day_target_cost - day_actual_cost
            
            # Add to total savings
            total_saved += day_saved
    
    # Calculate monthly and yearly projections based on average daily savings
    if first_entry:
        days_tracked = (today - start_date).days + 1
        avg_daily_savings = total_saved / days_tracked
        monthly_projection = avg_daily_savings * 30
        yearly_projection = avg_daily_savings * 365
    else:
        monthly_projection = 0
        yearly_projection = 0
    
    return render_template('dashboard.html',
                         total_cigarettes=total_cigarettes,
                         total_spent=total_spent,
                         total_saved=total_saved,
                         monthly_projection=monthly_projection,
                         yearly_projection=yearly_projection,
                         today_count=today_count,
                         today=today,
                         selected_date=selected_date,
                         today_entries=paginated_entries.items,
                         pagination=paginated_entries,
                         per_page=per_page)

@app.route('/add_cigarette', methods=['POST'])
@login_required
def add_cigarette():
    entry = CigaretteEntry(
        user_id=current_user.id,
        timestamp=datetime.utcnow()
    )
    db.session.add(entry)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        try:
            current_user.name = request.form.get('name', current_user.name)
            current_user.age = request.form.get('age', current_user.age)
            current_user.smoking_since = request.form.get('smoking_since', current_user.smoking_since)
            current_user.daily_cigarettes = request.form.get('daily_cigarettes', current_user.daily_cigarettes)
            current_user.cigarette_cost = request.form.get('cigarette_cost', current_user.cigarette_cost)
            current_user.pack_cost = request.form.get('pack_cost', current_user.pack_cost)
            current_user.cigarettes_per_pack = request.form.get('cigarettes_per_pack', current_user.cigarettes_per_pack)
            member_since = request.form.get('member_since')
            if member_since:
                try:
                    current_user.created_at = datetime.strptime(member_since, '%Y-%m-%d')
                    db.session.commit()
                    flash('Profile updated successfully!', 'success')
                except ValueError:
                    flash('Invalid date format', 'error')
                    return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'error')
            
    return redirect(url_for('dashboard'))

@app.route('/delete_cigarette/<int:entry_id>', methods=['POST'])
@login_required
def delete_cigarette(entry_id):
    entry = CigaretteEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(entry)
        db.session.commit()
        flash('Entry deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting entry', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/edit_cigarette/<int:entry_id>', methods=['POST'])
@login_required
def edit_cigarette(entry_id):
    entry = CigaretteEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        count = request.form.get('count', type=int)
        timestamp = request.form.get('timestamp')
        if count:
            entry.count = count
        if timestamp:
            local_tz = pytz.timezone('Asia/Kolkata')
            local_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M')
            local_time = local_tz.localize(local_time)
            entry.timestamp = local_time.astimezone(pytz.utc).replace(tzinfo=None)
        
        db.session.commit()
        flash('Entry updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating entry', 'error')
    
    return redirect(url_for('dashboard'))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get basic stats
    total_users = User.query.count()
    total_entries = CigaretteEntry.query.count()
    active_today = db.session.query(func.count(func.distinct(CigaretteEntry.user_id))).filter(
        func.date(CigaretteEntry.timestamp) == datetime.utcnow().date()
    ).scalar()

    # Get user registration trends (last 7 days)
    registration_data = []
    for i in range(7):
        date = datetime.utcnow().date() - timedelta(days=i)
        count = User.query.filter(
            func.date(User.created_at) == date
        ).count()
        registration_data.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': count
        })

    # Get most active users
    most_active_users = db.session.query(
        User,
        func.count(CigaretteEntry.id).label('entry_count')
    ).join(CigaretteEntry).group_by(User).order_by(
        func.count(CigaretteEntry.id).desc()
    ).limit(5).all()

    # Get recent registrations
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # Get activity by hour (last 24 hours) - SQLite compatible version
    hourly_activity = []
    now = datetime.utcnow()
    for i in range(24):
        hour_start = now - timedelta(hours=i)
        hour_end = hour_start + timedelta(hours=1)
        count = CigaretteEntry.query.filter(
            CigaretteEntry.timestamp >= hour_start,
            CigaretteEntry.timestamp < hour_end
        ).count()
        hourly_activity.append({
            'hour': hour_start.strftime('%H:00'),
            'count': count
        })

    # Reverse the hourly activity to show most recent first
    hourly_activity.reverse()

    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_entries=total_entries,
                         active_today=active_today,
                         registration_data=registration_data,
                         most_active_users=most_active_users,
                         recent_users=recent_users,
                         hourly_activity=hourly_activity)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'Made {user.email} an admin.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/create-admin/<token>', methods=['GET', 'POST'])
def create_admin(token):
    # Check if the token matches the environment variable or a default value
    secret_token = os.getenv('ADMIN_CREATE_TOKEN', 'quitpuff_secret_token_2024')
    if token != secret_token:
        return "Invalid token", 403

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')

        try:
            # Check if user exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                if existing_user.is_admin:
                    flash('User is already an admin!', 'info')
                else:
                    existing_user.is_admin = True
                    db.session.commit()
                    flash('Made existing user an admin!', 'success')
            else:
                # Create new admin user
                admin = User(
                    name=name,
                    email=email,
                    password=generate_password_hash(password),
                    age=30,
                    smoking_since=0,
                    daily_cigarettes=0,
                    cigarette_cost=0.0,
                    currency='INR',
                    pack_cost=0.0,
                    cigarettes_per_pack=0,
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
                flash('Successfully created admin user!', 'success')

            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')

    return render_template('admin/create_admin.html')

if __name__ == '__main__':
    app.run(debug=True) 