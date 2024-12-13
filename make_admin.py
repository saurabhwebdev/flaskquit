from app import app, db
from models import User
import sys
from sqlalchemy import text

def make_admin(email):
    with app.app_context():
        try:
            # Try to add is_admin column if it doesn't exist
            try:
                sql = text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')
                db.session.execute(sql)
                db.session.commit()
                print("Added is_admin column to user table")
            except Exception as e:
                print("Column might already exist or other error:", str(e))
                db.session.rollback()

            # Make the user an admin
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_admin = True
                db.session.commit()
                print(f"Successfully made {user.email} an admin!")
            else:
                print(f"No user found with email: {email}")
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <email>")
        print("Example: python make_admin.py admin@example.com")
        sys.exit(1)
    
    email = sys.argv[1]
    make_admin(email) 