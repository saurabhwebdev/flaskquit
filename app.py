from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, CigaretteEntry
import os
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

if __name__ == '__main__':
    app.run(debug=True) 