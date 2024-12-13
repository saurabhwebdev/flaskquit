from app import app, db
from models import User
from werkzeug.security import generate_password_hash
import os

def create_admin_user(email, password, name="Admin User"):
    with app.app_context():
        try:
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                if existing_user.is_admin:
                    print(f"User {email} is already an admin!")
                    return
                else:
                    # Make existing user an admin
                    existing_user.is_admin = True
                    db.session.commit()
                    print(f"Made existing user {email} an admin!")
                    return

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
            print(f"Successfully created admin user: {email}")

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    # Get credentials from environment variables or use defaults
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@quitpuff.com')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
    admin_name = os.getenv('ADMIN_NAME', 'Admin User')

    create_admin_user(admin_email, admin_password, admin_name)
    print("Script completed!") 