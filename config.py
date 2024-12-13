import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    # Ensure we have a secret key
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Get database URL with fallback
    DATABASE_URL = os.environ.get('DATABASE_URL', '')
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    # Use PostgreSQL URL from environment, fallback to SQLite
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or 'sqlite:///cigarette_tracker.db'
    
    # Debug mode (disable in production)
    DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'
    
    # Additional security headers
    SESSION_COOKIE_SECURE = os.environ.get('PRODUCTION', 'false').lower() == 'true'
    REMEMBER_COOKIE_SECURE = os.environ.get('PRODUCTION', 'false').lower() == 'true'