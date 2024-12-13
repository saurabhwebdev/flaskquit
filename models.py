from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import pytz

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    age = db.Column(db.Integer)
    smoking_since = db.Column(db.Integer)
    daily_cigarettes = db.Column(db.Integer)
    cigarette_cost = db.Column(db.Float)
    currency = db.Column(db.String(3), default='INR')
    pack_cost = db.Column(db.Float)
    cigarettes_per_pack = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    entries = db.relationship('CigaretteEntry', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

class CigaretteEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Store in UTC
    count = db.Column(db.Integer, default=1)

    def get_local_time(self, timezone='Asia/Kolkata'):  # Default to IST
        utc_time = pytz.utc.localize(self.timestamp)
        local_tz = pytz.timezone(timezone)
        return utc_time.astimezone(local_tz)