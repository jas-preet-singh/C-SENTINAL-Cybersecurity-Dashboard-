import os
import uuid
from functools import wraps
from flask import g, session, redirect, request, render_template, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from models import User

login_manager = LoginManager(app)
login_manager.login_view = 'local_auth.login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class LocalUser(UserMixin):
    def __init__(self, user_id, email, first_name, last_name, role='user'):
        self.id = user_id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.role = role

def create_default_admin():
    """Create a default admin user if none exists"""
    admin = User.query.filter_by(email='admin@cybersentinel.local').first()
    if not admin:
        admin = User(
            id=str(uuid.uuid4()),
            email='admin@cybersentinel.local',
            first_name='Admin',
            last_name='User',
            role='admin'
        )
        admin.set_password('admin123')  # Default password
        db.session.add(admin)
        db.session.commit()
        print("Created default admin user: admin@cybersentinel.local / admin123")

def require_login(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            session["next_url"] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Local login page"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please enter both email and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            # Create a LocalUser instance for Flask-Login
            local_user = LocalUser(
                user_id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                role=user.role
            )
            login_user(local_user)
            
            next_url = session.get('next_url')
            if next_url:
                session.pop('next_url', None)
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please enter both email and password', 'error')
            return render_template('login.html', show_register=True)
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('login.html', show_register=True)
        
        # Create new user with minimal required fields
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            first_name=None,  # Optional
            last_name=None,   # Optional
            role='user'
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('login.html', show_register=True)

@app.route('/logout')
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Initialize default admin on startup
with app.app_context():
    create_default_admin()
