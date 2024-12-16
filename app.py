from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, CigaretteEntry
from flask_migrate import Migrate
from functools import wraps
from sqlalchemy import func, text
import os
from datetime import datetime, timedelta
import pytz
import logging
from logging.handlers import RotatingFileHandler
from jinja2 import Environment

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Register min and max functions with Jinja2
app.jinja_env.globals.update(min=min, max=max)

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

# Add this after database initialization
@app.before_request
def before_request():
    try:
        # Test database connection using proper text() wrapper
        db.session.execute(text('SELECT 1'))
        app.logger.debug('Database connection successful')
    except Exception as e:
        app.logger.error(f'Database connection failed: {str(e)}')
        return 'Database connection error', 500

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
    today = datetime.now(pytz.UTC).date()
    
    # Get the selected date from query parameters, default to today
    selected_date_str = request.args.get('date', today.strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError:
        selected_date = today

    # Base query for entries
    entries_query = CigaretteEntry.query.filter_by(user_id=current_user.id)
    
    # Initialize filter flag
    is_filtered = False
    
    if selected_date:
        entries_query = entries_query.filter(
            db.func.date(CigaretteEntry.timestamp) == selected_date
        )
        is_filtered = True
    
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

def calculate_total_saved(user):
    """Calculate total money saved based on daily target vs actual consumption"""
    # Get all entries for the user
    entries = CigaretteEntry.query.filter_by(user_id=user.id).all()
    
    # Group entries by date
    entries_by_date = {}
    for entry in entries:
        date = entry.timestamp.date()
        if date not in entries_by_date:
            entries_by_date[date] = 0
        entries_by_date[date] += entry.count
    
    total_saved = 0
    # Calculate savings for days with entries
    for date, count in entries_by_date.items():
        daily_target_cost = user.daily_cigarettes * user.cigarette_cost
        daily_actual_cost = count * user.cigarette_cost
        daily_saved = daily_target_cost - daily_actual_cost
        total_saved += daily_saved
        app.logger.debug(f"Date: {date}, Target Cost: {daily_target_cost}, Actual Cost: {daily_actual_cost}, Saved: {daily_saved}")
    
    # Calculate savings for days with no entries
    if entries:
        first_entry = min(entries_by_date.keys())
        last_entry = max(entries_by_date.keys())
        total_days = (last_entry - first_entry).days + 1
        days_with_entries = len(entries_by_date)
        days_without_entries = total_days - days_with_entries
        
        # For days with no entries, all daily target money was saved
        zero_consumption_saved = days_without_entries * (user.daily_cigarettes * user.cigarette_cost)
        total_saved += zero_consumption_saved
        
        app.logger.debug(f"""
            Days without Entries: {days_without_entries}
            Additional Savings: {zero_consumption_saved}
            Total Saved: {total_saved}
        """)
    
    return total_saved

def calculate_yearly_projection(user):
    """Calculate yearly money savings projection based on current habits"""
    # Get entries from the last 30 days to calculate average daily savings
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_entries = CigaretteEntry.query.filter(
        CigaretteEntry.user_id == user.id,
        CigaretteEntry.timestamp >= thirty_days_ago
    ).all()
    
    # Group entries by date
    entries_by_date = {}
    for entry in recent_entries:
        date = entry.timestamp.date()
        if date not in entries_by_date:
            entries_by_date[date] = 0
        entries_by_date[date] += entry.count
    
    # Calculate average daily savings
    total_days = len(entries_by_date) or 1  # Avoid division by zero
    total_saved = 0
    
    for count in entries_by_date.values():
        daily_target_cost = user.daily_cigarettes * user.cigarette_cost
        daily_actual_cost = count * user.cigarette_cost
        total_saved += daily_target_cost - daily_actual_cost
    
    avg_daily_savings = total_saved / total_days
    yearly_projection = avg_daily_savings * 365
    
    return yearly_projection

def calculate_cigarettes_avoided(user):
    """Calculate total cigarettes not smoked since tracking started"""
    # Get all entries for the user
    entries = CigaretteEntry.query.filter_by(user_id=user.id).all()
    
    # Get the start date (either first entry or user creation date)
    start_date = user.created_at.date()
    if entries:
        first_entry_date = min(entry.timestamp.date() for entry in entries)
        start_date = min(start_date, first_entry_date)
    
    # Calculate total days since tracking started
    today = datetime.now().date()
    total_days = (today - start_date).days + 1
    
    # Group entries by date
    entries_by_date = {}
    for entry in entries:
        date = entry.timestamp.date()
        if date not in entries_by_date:
            entries_by_date[date] = 0
        entries_by_date[date] += entry.count
    
    total_not_smoked = 0
    total_target = 0
    
    # Calculate for each day since start
    for day_offset in range(total_days):
        current_date = start_date + timedelta(days=day_offset)
        daily_target = user.daily_cigarettes
        smoked_count = entries_by_date.get(current_date, 0)
        
        # Add to total target
        total_target += daily_target
        # Add to not smoked (target - actual)
        not_smoked_today = daily_target - smoked_count
        total_not_smoked += not_smoked_today
        
        app.logger.debug(f"""
            Date: {current_date}
            Daily Target: {daily_target}
            Actually Smoked: {smoked_count}
            Not Smoked Today: {not_smoked_today}
            Running Total Not Smoked: {total_not_smoked}
            Running Total Target: {total_target}
        """)
    
    return total_not_smoked, total_target

@app.context_processor
def inject_stats():
    if current_user.is_authenticated:
        try:
            # Calculate cigarettes avoided and total target
            cigarettes_avoided, total_target = calculate_cigarettes_avoided(current_user)
            total_saved = calculate_total_saved(current_user)
            yearly_projection = calculate_yearly_projection(current_user)
            
            # Log the final stats
            app.logger.info(f"""
            Stats for user {current_user.email}:
            Total Target: {total_target}
            Actually Not Smoked: {cigarettes_avoided}
            Total Saved: {total_saved}
            Yearly Projection: {yearly_projection}
            """)
            
            return {
                'total_cigarettes': cigarettes_avoided,
                'total_target': total_target,
                'total_saved': total_saved,
                'yearly_projection': yearly_projection
            }
        except Exception as e:
            app.logger.error(f"Error calculating stats: {str(e)}")
            return {
                'total_cigarettes': 0,
                'total_target': 0,
                'total_saved': 0.0,
                'yearly_projection': 0.0
            }
    return {
        'total_cigarettes': 0,
        'total_target': 0,
        'total_saved': 0.0,
        'yearly_projection': 0.0
    }

if __name__ == '__main__':
    app.run(debug=True) 