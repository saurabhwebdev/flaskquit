from app import app, db
from models import User
from werkzeug.security import generate_password_hash
import sys

def create_admin(email, password):
    with app.app_context():
        try:
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                print(f"User {email} already exists!")
                return

            # Create new admin user
            admin = User(
                name='Admin User',
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
            print(f"Successfully created admin user: {email}")

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <email> <password>")
        print("Example: python create_admin.py admin@quitpuff.com adminpass123")
        sys.exit(1)
    
    email = sys.argv[1]
    password = sys.argv[2]
    create_admin(email, password) 