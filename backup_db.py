from app import app, db
from models import User, CigaretteEntry
import json
from datetime import datetime

def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def backup_database():
    with app.app_context():
        # Export Users
        users = User.query.all()
        users_data = []
        for user in users:
            user_data = {
                'id': user.id,
                'email': user.email,
                'password': user.password,
                'name': user.name,
                'age': user.age,
                'smoking_since': user.smoking_since,
                'daily_cigarettes': user.daily_cigarettes,
                'cigarette_cost': float(user.cigarette_cost),
                'currency': user.currency,
                'pack_cost': float(user.pack_cost),
                'cigarettes_per_pack': user.cigarettes_per_pack,
                'created_at': user.created_at,
                'is_admin': user.is_admin
            }
            users_data.append(user_data)
        
        # Export Entries
        entries = CigaretteEntry.query.all()
        entries_data = []
        for entry in entries:
            entry_data = {
                'id': entry.id,
                'user_id': entry.user_id,
                'count': entry.count,
                'timestamp': entry.timestamp
            }
            entries_data.append(entry_data)
        
        # Save to JSON file
        data = {
            'users': users_data,
            'entries': entries_data
        }
        
        with open('database_backup.json', 'w') as f:
            json.dump(data, f, default=serialize_datetime, indent=2)

if __name__ == '__main__':
    backup_database()
    print("Database backed up to database_backup.json") 