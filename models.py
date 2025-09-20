from datetime import datetime
from app import db
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash

# (IMPORTANT) This table is mandatory for Replit Auth, don't drop it.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=True)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    profile_image_url = db.Column(db.String, nullable=True)
    role = db.Column(db.String, default='user')  # user, admin
    password_hash = db.Column(db.String, nullable=True)  # For local authentication
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

# (IMPORTANT) This table is mandatory for Replit Auth, don't drop it.
class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.String, db.ForeignKey(User.id))
    browser_session_key = db.Column(db.String, nullable=False)
    user = db.relationship(User)

    __table_args__ = (UniqueConstraint(
        'user_id',
        'browser_session_key',
        'provider',
        name='uq_user_browser_session_key_provider',
    ),)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey(User.id), nullable=False)
    filename = db.Column(db.String, nullable=False)
    original_filename = db.Column(db.String, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String, nullable=True)
    upload_time = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship(User, backref='uploads')

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey(User.id), nullable=False)
    job_type = db.Column(db.String, nullable=False)  # brute_force, scan, etc.
    status = db.Column(db.String, default='running')  # running, completed, cancelled, failed
    progress = db.Column(db.Integer, default=0)
    result = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship(User, backref='jobs')

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey(User.id), nullable=False)
    scan_type = db.Column(db.String, nullable=False)  # url, file, vulnerability
    target = db.Column(db.String, nullable=False)
    result = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String, nullable=True)  # low, medium, high
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship(User, backref='scan_results')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey(User.id), nullable=True)
    action = db.Column(db.String, nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String, nullable=True)  # Internal/container IP
    user_public_ip = db.Column(db.String, nullable=True)  # Real public IP
    user_agent = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship(User, backref='activity_logs')
