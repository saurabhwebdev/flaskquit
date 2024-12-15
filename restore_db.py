from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import json
from datetime import datetime
import os
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

def restore_database():
    # Create a new Flask app instance for production database
    app = Flask(__name__)
    
    # Get the production database URL
    db_url = os.getenv('PROD_DATABASE_URL')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    # Configure the app with production database
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db = SQLAlchemy(app)
    
    # Define models here to ensure they're created with this db instance
    class User(db.Model):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)
        age = db.Column(db.Integer, nullable=False)
        smoking_since = db.Column(db.Integer, nullable=False)  # Years
        daily_cigarettes = db.Column(db.Integer, nullable=False)
        cigarette_cost = db.Column(db.Float, nullable=False)
        currency = db.Column(db.String(3), default='INR')
        pack_cost = db.Column(db.Float, nullable=False)
        cigarettes_per_pack = db.Column(db.Integer, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        is_admin = db.Column(db.Boolean, default=False)
        entries = db.relationship('CigaretteEntry', backref='user', lazy=True)

    class CigaretteEntry(db.Model):
        __tablename__ = 'cigarette_entries'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        count = db.Column(db.Integer, default=1)
    
    with app.app_context():
        # Drop all tables first to avoid conflicts
        print("Dropping existing tables...")
        db.drop_all()
        
        # Create all tables fresh
        print("Creating new tables...")
        db.create_all()
        
        try:
            # Read the backup file
            with open('database_backup.json', 'r') as f:
                data = json.load(f)
            
            print("Starting data restore...")
            print(f"Found {len(data['users'])} users and {len(data['entries'])} entries in backup file")
            
            # Restore Users
            max_user_id = 0
            for user_data in data['users']:
                user = User(
                    id=user_data['id'],
                    email=user_data['email'],
                    password=user_data['password'],
                    name=user_data['name'],
                    age=user_data['age'],
                    smoking_since=user_data['smoking_since'],
                    daily_cigarettes=user_data['daily_cigarettes'],
                    cigarette_cost=user_data['cigarette_cost'],
                    currency=user_data['currency'],
                    pack_cost=user_data['pack_cost'],
                    cigarettes_per_pack=user_data['cigarettes_per_pack'],
                    created_at=datetime.fromisoformat(user_data['created_at']),
                    is_admin=user_data.get('is_admin', False)
                )
                max_user_id = max(max_user_id, user_data['id'])
                db.session.add(user)
            
            # Commit users first to maintain referential integrity
            db.session.commit()
            print("Users restored successfully!")
            
            # Reset the users id sequence
            db.session.execute(text(f"ALTER SEQUENCE users_id_seq RESTART WITH {max_user_id + 1}"))
            db.session.commit()
            print(f"Reset users sequence to {max_user_id + 1}")
            
            # Restore Entries
            max_entry_id = 0
            for entry_data in data['entries']:
                entry = CigaretteEntry(
                    id=entry_data['id'],
                    user_id=entry_data['user_id'],
                    count=entry_data['count'],
                    timestamp=datetime.fromisoformat(entry_data['timestamp'])
                )
                max_entry_id = max(max_entry_id, entry_data['id'])
                db.session.add(entry)
            
            # Commit all changes
            db.session.commit()
            
            # Reset the entries id sequence
            db.session.execute(text(f"ALTER SEQUENCE cigarette_entries_id_seq RESTART WITH {max_entry_id + 1}"))
            db.session.commit()
            print(f"Reset entries sequence to {max_entry_id + 1}")
            
            print("Entries restored successfully!")
            print("Database restore completed!")
            
        except Exception as e:
            print(f"Error during restore: {str(e)}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    restore_database()
    print("Database restore process finished") 