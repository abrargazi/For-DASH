from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import json
import requests
from geopy.distance import geodesic
import folium
from folium import plugins
import openai

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dash-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dash.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")

# OpenAI API Key (you'll need to set this in your environment)
openai.api_key = os.getenv('OPENAI_API_KEY', 'your-openai-api-key-here')

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'user', 'admin', 'rescue_team'
    phone = db.Column(db.String(20))
    location_lat = db.Column(db.Float)
    location_lng = db.Column(db.Float)
    is_online = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Help Request Model
class HelpRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)  # food, shelter, water, medical, evacuation
    description = db.Column(db.Text)
    urgency_level = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    location_lat = db.Column(db.Float, nullable=False)
    location_lng = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('help_requests', lazy=True))

# Resource Offer Model
class ResourceOffer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # shelter, food, transport, supplies
    description = db.Column(db.Text)
    quantity = db.Column(db.String(100))
    location_lat = db.Column(db.Float, nullable=False)
    location_lng = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('resource_offers', lazy=True))

# SOS Alert Model
class SOSAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_lat = db.Column(db.Float, nullable=False)
    location_lng = db.Column(db.Float, nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')  # active, responded, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('sos_alerts', lazy=True))

# Chat Message Model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    room_id = db.Column(db.String(100), nullable=False)  # For group chats or SOS rooms
    message = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')  # text, location, resource
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_messages', lazy=True))

# Bulletin Post Model
class BulletinPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_type = db.Column(db.String(50), nullable=False)  # announcement, warning, instruction, update
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    is_pinned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    author = db.relationship('User', backref=db.backref('bulletin_posts', lazy=True))

# Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)  # weather, roadblock, medical_camp, sos, etc.
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create demo accounts if they don't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@dash.com', user_type='admin')
            admin.set_password('admin123')
            db.session.add(admin)
        
        if not User.query.filter_by(username='user1').first():
            user1 = User(username='user1', email='user1@dash.com', user_type='user', phone='+1234567890')
            user1.set_password('user123')
            db.session.add(user1)
        
        if not User.query.filter_by(username='rescue1').first():
            rescue1 = User(username='rescue1', email='rescue1@dash.com', user_type='rescue_team', phone='+1234567891')
            rescue1.set_password('rescue123')
            db.session.add(rescue1)
        
        db.session.commit()
        print("Demo accounts created:")
        print("Admin: username=admin, password=admin123")
        print("User: username=user1, password=user123")
        print("Rescue Team: username=rescue1, password=rescue123")
    
    socketio.run(app, debug=True, host='localhost', port=5500)
