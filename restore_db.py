from app import app, db
from models import User, CigaretteEntry
import json
from datetime import datetime

def restore_database():
    with app.app_context():
        # First, create all tables
        db.create_all()
        
        # Read the backup file
        with open('database_backup.json', 'r') as f:
            data = json.load(f)
        
        # Restore Users
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
                created_at=datetime.fromisoformat(user_data['created_at'])
            )
            db.session.add(user)
        
        # Commit users first to maintain referential integrity
        db.session.commit()
        
        # Restore Entries
        for entry_data in data['entries']:
            entry = CigaretteEntry(
                id=entry_data['id'],
                user_id=entry_data['user_id'],
                count=entry_data['count'],
                timestamp=datetime.fromisoformat(entry_data['timestamp'])
            )
            db.session.add(entry)
        
        # Commit all changes
        db.session.commit()

if __name__ == '__main__':
    restore_database()
    print("Database restored from database_backup.json") 