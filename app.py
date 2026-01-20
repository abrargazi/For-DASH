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

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.is_online = True
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        phone = request.form.get('phone', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')
        
        user = User(username=username, email=email, user_type=user_type, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.user_type == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.user_type == 'rescue_team':
        return redirect(url_for('rescue_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.user_type != 'user':
        return redirect(url_for('dashboard'))
    
    # Get recent help requests
    help_requests = HelpRequest.query.filter_by(user_id=current_user.id).order_by(HelpRequest.created_at.desc()).limit(5).all()
    
    # Get recent notifications
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Get recent bulletin posts
    bulletin_posts = BulletinPost.query.order_by(BulletinPost.created_at.desc()).limit(5).all()
    nearest_hospitals = nearest_hospitals_for_user(current_user, limit=3)
    
    # Get missing and found persons
    missing = MissingFoundPerson.query.filter_by(person_type='missing', status='active').order_by(MissingFoundPerson.created_at.desc()).limit(5).all()
    found = MissingFoundPerson.query.filter_by(person_type='found', status='active').order_by(MissingFoundPerson.created_at.desc()).limit(5).all()
    
    # Get disaster risks
    disaster_risks = DisasterRisk.query.filter_by(is_active=True).order_by(DisasterRisk.created_at.desc()).limit(5).all()

    return render_template('user_dashboard.html', 
                         help_requests=help_requests,
                         notifications=notifications,
                         bulletin_posts=bulletin_posts,
                         hospitals=nearest_hospitals,
                         missing=missing,
                         found=found,
                         disaster_risks=disaster_risks)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    # Analytics data
    total_users = User.query.count()
    active_sos = SOSAlert.query.filter_by(status='active').count()
    pending_requests = HelpRequest.query.filter_by(status='pending').count()
    available_resources = ResourceOffer.query.filter_by(is_available=True).count()
    hospital_count = Hospital.query.count()
    
    # Recent activity
    recent_sos = SOSAlert.query.order_by(SOSAlert.created_at.desc()).limit(10).all()
    recent_requests = HelpRequest.query.order_by(HelpRequest.created_at.desc()).limit(10).all()
    
    # Get missing and found persons (admin sees all reports from users and rescue teams)
    missing = MissingFoundPerson.query.filter_by(person_type='missing', status='active').order_by(MissingFoundPerson.created_at.desc()).limit(10).all()
    found = MissingFoundPerson.query.filter_by(person_type='found', status='active').order_by(MissingFoundPerson.created_at.desc()).limit(10).all()
    
    # Get rescue team missions
    rescue_missions = RescueMission.query.order_by(RescueMission.started_at.desc()).limit(10).all()
    
    # Get disaster risks
    disaster_risks = DisasterRisk.query.filter_by(is_active=True).order_by(DisasterRisk.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         active_sos=active_sos,
                         pending_requests=pending_requests,
                         available_resources=available_resources,
                         hospital_count=hospital_count,
                         recent_sos=recent_sos,
                         recent_requests=recent_requests,
                         missing=missing,
                         found=found,
                         rescue_missions=rescue_missions,
                         disaster_risks=disaster_risks)

@app.route('/rescue_dashboard')
@login_required
def rescue_dashboard():
    if current_user.user_type != 'rescue_team':
        return redirect(url_for('dashboard'))
    
    # Get active SOS alerts
    active_sos = SOSAlert.query.filter_by(status='active').order_by(SOSAlert.created_at.desc()).all()
    
    # Get high priority help requests
    urgent_requests = HelpRequest.query.filter(
        HelpRequest.urgency_level.in_(['high', 'critical']),
        HelpRequest.status == 'pending'
    ).order_by(HelpRequest.created_at.desc()).all()

    nearest_hospitals = nearest_hospitals_for_user(current_user, limit=3)
    missions = RescueMission.query.filter_by(rescue_team_id=current_user.id).order_by(RescueMission.started_at.desc()).limit(5).all()
    total_people_helped = sum(m.people_helped for m in missions)
    
    # Get missing and found persons
    missing = MissingFoundPerson.query.filter_by(person_type='missing', status='active').order_by(MissingFoundPerson.created_at.desc()).limit(5).all()
    found = MissingFoundPerson.query.filter_by(person_type='found', status='active').order_by(MissingFoundPerson.created_at.desc()).limit(5).all()
    
    # Get disaster risks
    disaster_risks = DisasterRisk.query.filter_by(is_active=True).order_by(DisasterRisk.created_at.desc()).limit(5).all()

    return render_template('rescue_dashboard.html',
                         active_sos=active_sos,
                         urgent_requests=urgent_requests,
                         hospitals=nearest_hospitals,
                         missions=missions,
                         total_people_helped=total_people_helped,
                         missing=missing,
                         found=found,
                         disaster_risks=disaster_risks)

# API Routes
@app.route('/api/update_location', methods=['POST'])
@login_required
def update_location():
    data = request.get_json()
    current_user.location_lat = data.get('lat')
    current_user.location_lng = data.get('lng')
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/api/send_sos', methods=['POST'])
@login_required
def send_sos():
    data = request.get_json()
    lat = data.get('lat')
    lng = data.get('lng')
    
    # If location not provided, use user's current location
    if not lat or not lng:
        if current_user.location_lat and current_user.location_lng:
            lat = current_user.location_lat
            lng = current_user.location_lng
        else:
            return jsonify({'status': 'error', 'message': 'Location is required'})
    
    sos_alert = SOSAlert(
        user_id=current_user.id,
        location_lat=lat,
        location_lng=lng,
        message=data.get('message', 'Emergency SOS Alert')
    )
    db.session.add(sos_alert)
    db.session.commit()
    
    # Get nearby hospitals (within 10km)
    nearby_hospitals = hospitals_near_location(sos_alert.location_lat, sos_alert.location_lng, max_distance_km=10)
    
    # Emit to rescue teams and admins
    socketio.emit('new_sos_alert', {
        'id': sos_alert.id,
        'user_id': current_user.id,
        'username': current_user.username,
        'lat': sos_alert.location_lat,
        'lng': sos_alert.location_lng,
        'message': sos_alert.message,
        'timestamp': sos_alert.created_at.isoformat(),
        'nearby_hospitals': nearby_hospitals
    }, room='rescue_teams')
    
    # Also notify admins
    socketio.emit('new_sos_alert', {
        'id': sos_alert.id,
        'user_id': current_user.id,
        'username': current_user.username,
        'lat': sos_alert.location_lat,
        'lng': sos_alert.location_lng,
        'message': sos_alert.message,
        'timestamp': sos_alert.created_at.isoformat(),
        'nearby_hospitals': nearby_hospitals
    }, room='admins')
    
    return jsonify({
        'status': 'success', 
        'alert_id': sos_alert.id,
        'nearby_hospitals': nearby_hospitals
    })

@app.route('/api/create_help_request', methods=['POST'])
@login_required
def create_help_request():
    data = request.get_json()
    help_request = HelpRequest(
        user_id=current_user.id,
        request_type=data.get('request_type'),
        description=data.get('description'),
        urgency_level=data.get('urgency_level'),
        location_lat=data.get('lat'),
        location_lng=data.get('lng')
    )
    db.session.add(help_request)
    db.session.commit()
    
    return jsonify({'status': 'success', 'request_id': help_request.id})

@app.route('/api/offer_resource', methods=['POST'])
@login_required
def offer_resource():
    data = request.get_json()
    resource_offer = ResourceOffer(
        user_id=current_user.id,
        resource_type=data.get('resource_type'),
        description=data.get('description'),
        quantity=data.get('quantity'),
        location_lat=data.get('lat'),
        location_lng=data.get('lng')
    )
    db.session.add(resource_offer)
    db.session.commit()
    
    return jsonify({'status': 'success', 'offer_id': resource_offer.id})

@app.route('/api/get_map_data')
@login_required
def get_map_data():
    # Get all active SOS alerts
    sos_alerts = SOSAlert.query.filter_by(status='active').all()
    
    # Get all pending help requests
    help_requests = HelpRequest.query.filter_by(status='pending').all()
    
    # Get all available resources
    resources = ResourceOffer.query.filter_by(is_available=True).all()
    
    return jsonify({
        'sos_alerts': [{
            'id': alert.id,
            'lat': alert.location_lat,
            'lng': alert.location_lng,
            'message': alert.message,
            'timestamp': alert.created_at.isoformat()
        } for alert in sos_alerts],
        'help_requests': [{
            'id': req.id,
            'lat': req.location_lat,
            'lng': req.location_lng,
            'type': req.request_type,
            'urgency': req.urgency_level,
            'description': req.description
        } for req in help_requests],
        'resources': [{
            'id': res.id,
            'lat': res.location_lat,
            'lng': res.location_lng,
            'type': res.resource_type,
            'description': res.description,
            'quantity': res.quantity
        } for res in resources]
    })

def serialize_hospital(hospital, user_lat=None, user_lng=None):
    """Return a serializable hospital dict with optional distance."""
    base = {
        'id': hospital.id,
        'name': hospital.name,
        'address': hospital.address,
        'contact_phone': hospital.contact_phone,
        'lat': hospital.location_lat,
        'lng': hospital.location_lng,
        'capacity_total': hospital.capacity_total,
        'capacity_available': hospital.capacity_available,
        'patients_admitted': max(hospital.capacity_total - hospital.capacity_available, 0),
        'services': hospital.services,
        'doctors': hospital.doctor_list(),
        'last_updated': hospital.last_updated.isoformat() if hospital.last_updated else None
    }
    if user_lat is not None and user_lng is not None:
        try:
            distance = geodesic((user_lat, user_lng), (hospital.location_lat, hospital.location_lng)).km
            base['distance_km'] = round(distance, 2)
        except Exception:
            base['distance_km'] = None
    return base

def nearest_hospitals_for_user(user, limit=5, max_distance_km=None):
    """Return nearest hospitals for a given user, limited and sorted by distance when possible."""
    hospitals = Hospital.query.all()
    user_lat = user.location_lat
    user_lng = user.location_lng
    hospital_list = []
    for h in hospitals:
        hospital_data = serialize_hospital(h, user_lat, user_lng)
        if max_distance_km is None or hospital_data.get('distance_km') is None or hospital_data.get('distance_km') <= max_distance_km:
            hospital_list.append(hospital_data)
    if user_lat is not None and user_lng is not None:
        hospital_list = sorted(hospital_list, key=lambda h: h.get('distance_km') if h.get('distance_km') is not None else 1e9)
    return hospital_list[:limit]

def hospitals_near_location(lat, lng, max_distance_km=10):
    """Return hospitals within max_distance_km of given location."""
    hospitals = Hospital.query.all()
    nearby = []
    for h in hospitals:
        try:
            distance = geodesic((lat, lng), (h.location_lat, h.location_lng)).km
            if distance <= max_distance_km:
                hospital_data = serialize_hospital(h, lat, lng)
                nearby.append(hospital_data)
        except Exception:
            continue
    return sorted(nearby, key=lambda h: h.get('distance_km', 1e9))

# Socket.IO Events
@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        if current_user.user_type == 'rescue_team':
            join_room('rescue_teams')
        elif current_user.user_type == 'admin':
            join_room('admins')
        emit('connected', {'user_id': current_user.id, 'username': current_user.username})

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        if current_user.user_type == 'rescue_team':
            leave_room('rescue_teams')
        elif current_user.user_type == 'admin':
            leave_room('admins')

@socketio.on('join_chat')
def on_join_chat(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{current_user.username} joined the chat'}, room=room)

@socketio.on('leave_chat')
def on_leave_chat(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{current_user.username} left the chat'}, room=room)

@socketio.on('send_message')
def on_send_message(data):
    room = data['room']
    message = data['message']
    
    # Save message to database
    chat_message = ChatMessage(
        sender_id=current_user.id,
        room_id=room,
        message=message
    )
    db.session.add(chat_message)
    db.session.commit()
    
    emit('new_message', {
        'id': chat_message.id,
        'sender': current_user.username,
        'message': message,
        'timestamp': chat_message.created_at.isoformat()
    }, room=room)

# AI Chat Assistant
@app.route('/api/ai_chat', methods=['POST'])
@login_required
def ai_chat():
    data = request.get_json()
    user_message = data.get('message', '')
    
    # Simple AI responses for emergency queries
    emergency_keywords = ['emergency', 'help', 'sos', 'danger', 'fire', 'flood', 'earthquake', 'medical']
    
    if any(keyword in user_message.lower() for keyword in emergency_keywords):
        response = "This appears to be an emergency. Please use the SOS button immediately or call emergency services. For immediate help, use the SOS feature in the app."
    else:
        response = "I'm here to help with disaster assistance information. How can I assist you today?"
    
    return jsonify({'response': response})

# Hospital routes
@app.route('/hospitals')
@login_required
def hospitals_page():
    hospitals = nearest_hospitals_for_user(current_user, limit=20)
    return render_template('hospital_list.html', hospitals=hospitals, user_lat=current_user.location_lat, user_lng=current_user.location_lng)

@app.route('/manage_hospitals')
@login_required
def manage_hospitals():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    hospitals = Hospital.query.order_by(Hospital.name).all()
    return render_template('manage_hospitals.html', hospitals=[serialize_hospital(h) for h in hospitals])

@app.route('/api/hospitals', methods=['GET'])
@login_required
def api_hospitals():
    lat = request.args.get('lat', type=float, default=current_user.location_lat)
    lng = request.args.get('lng', type=float, default=current_user.location_lng)
    hospitals = [serialize_hospital(h, lat, lng) for h in Hospital.query.all()]
    if lat is not None and lng is not None:
        hospitals = sorted(hospitals, key=lambda h: h.get('distance_km') if h.get('distance_km') is not None else 1e9)
    return jsonify({'status': 'success', 'hospitals': hospitals})

@app.route('/api/hospitals', methods=['POST'])
@login_required
def create_hospital():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    doctors = data.get('doctors', [])
    if isinstance(doctors, str):
        try:
            doctors = json.loads(doctors)
        except Exception:
            doctors = []
    
    address = data.get('address', '')
    lat = data.get('lat')
    lng = data.get('lng')
    
    # If lat/lng not provided, try to geocode the address
    if not lat or not lng:
        if address:
            try:
                from geopy.geocoders import Nominatim
                geolocator = Nominatim(user_agent="dash_app")
                location = geolocator.geocode(address, timeout=10)
                if location:
                    lat = location.latitude
                    lng = location.longitude
                else:
                    return jsonify({'status': 'error', 'message': 'Could not geocode address. Please provide a valid address.'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Geocoding error: {str(e)}'})
        else:
            return jsonify({'status': 'error', 'message': 'Address is required'})
    
<<<<<<< Updated upstream
=======
    hospital = Hospital(
        name=data.get('name'),
        address=address,
        contact_phone=data.get('contact_phone'),
        location_lat=lat,
        location_lng=lng,
        capacity_total=data.get('capacity_total', 0),
        capacity_available=data.get('capacity_available', 0),
        doctors=json.dumps(doctors),
        services=data.get('services', '')
    )
    db.session.add(hospital)
    db.session.commit()
    return jsonify({'status': 'success', 'hospital': serialize_hospital(hospital)})

@app.route('/api/hospitals/<int:hospital_id>', methods=['PUT', 'DELETE'])
@login_required
def update_or_delete_hospital(hospital_id):
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    hospital = Hospital.query.get_or_404(hospital_id)
    
    if request.method == 'DELETE':
        db.session.delete(hospital)
        db.session.commit()
        return jsonify({'status': 'success'})
    
    data = request.get_json()
    hospital.name = data.get('name', hospital.name)
    address = data.get('address', hospital.address)
    hospital.address = address
    
    # Update location if address changed
    lat = data.get('lat')
    lng = data.get('lng')
    if not lat or not lng:
        if address and address != hospital.address:
            try:
                from geopy.geocoders import Nominatim
                geolocator = Nominatim(user_agent="dash_app")
                location = geolocator.geocode(address, timeout=10)
                if location:
                    lat = location.latitude
                    lng = location.longitude
            except Exception:
                pass  # Keep existing coordinates if geocoding fails
    
    if lat and lng:
        hospital.location_lat = lat
        hospital.location_lng = lng
    
    hospital.contact_phone = data.get('contact_phone', hospital.contact_phone)
    hospital.capacity_total = data.get('capacity_total', hospital.capacity_total)
    hospital.capacity_available = data.get('capacity_available', hospital.capacity_available)
    doctors = data.get('doctors', hospital.doctors)
    if isinstance(doctors, str):
        try:
            doctors = json.loads(doctors)
        except Exception:
            doctors = hospital.doctor_list()
    hospital.doctors = json.dumps(doctors)
    hospital.services = data.get('services', hospital.services)
    db.session.commit()
    return jsonify({'status': 'success', 'hospital': serialize_hospital(hospital)})

# Rescue missions routes
@app.route('/api/create_mission', methods=['POST'])
@login_required
def create_mission():
    if current_user.user_type != 'rescue_team':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    mission = RescueMission(
        rescue_team_id=current_user.id,
        title=data.get('title'),
        description=data.get('description'),
        people_helped=data.get('people_helped', 0),
        status=data.get('status', 'active'),
        location=data.get('location')
    )
    db.session.add(mission)
    db.session.commit()
    
    # Notify admins about new mission
    socketio.emit('new_rescue_mission', {
        'id': mission.id,
        'rescue_team': current_user.username,
        'title': mission.title,
        'description': mission.description,
        'people_helped': mission.people_helped,
        'location': mission.location,
        'status': mission.status,
        'timestamp': mission.started_at.isoformat()
    }, room='admins')
    
    return jsonify({'status': 'success', 'mission_id': mission.id})

@app.route('/api/missions')
@login_required
def list_missions():
    if current_user.user_type == 'rescue_team':
        missions = RescueMission.query.filter_by(rescue_team_id=current_user.id).order_by(RescueMission.started_at.desc()).all()
    elif current_user.user_type == 'admin':
        missions = RescueMission.query.order_by(RescueMission.started_at.desc()).all()
    else:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    return jsonify({
        'status': 'success',
        'missions': [{
            'id': m.id,
            'title': m.title,
            'description': m.description,
            'people_helped': m.people_helped,
            'status': m.status,
            'location': m.location,
            'started_at': m.started_at.isoformat(),
            'completed_at': m.completed_at.isoformat() if m.completed_at else None,
            'rescue_team': m.rescue_team.username
        } for m in missions]
    })

# Profile page
@app.route('/profile')
@login_required
def profile():
    missions = []
    total_people_helped = 0
    if current_user.user_type == 'rescue_team':
        missions = RescueMission.query.filter_by(rescue_team_id=current_user.id).order_by(RescueMission.started_at.desc()).all()
        total_people_helped = sum(m.people_helped for m in missions)
    user_help_requests = HelpRequest.query.filter_by(user_id=current_user.id).order_by(HelpRequest.created_at.desc()).limit(10).all()
    return render_template('profile.html',
                           missions=missions,
                           total_people_helped=total_people_helped,
                           help_requests=user_help_requests)

# Bulletin Board Route
@app.route('/bulletin')
@login_required
def bulletin_board():
    posts = BulletinPost.query.order_by(BulletinPost.created_at.desc()).all()
    return render_template('bulletin_board.html', posts=posts)

# All Requests Route for Rescue Teams
@app.route('/all_requests')
@login_required
def all_requests():
    if current_user.user_type != 'rescue_team':
        return redirect(url_for('dashboard'))
    
    # Get all help requests
    all_help_requests = HelpRequest.query.order_by(HelpRequest.created_at.desc()).all()
    
    return render_template('all_requests.html', requests=all_help_requests)

# Create Bulletin Post Route
@app.route('/api/create_bulletin', methods=['POST'])
@login_required
def create_bulletin():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    post = BulletinPost(
        author_id=current_user.id,
        title=data.get('title'),
        content=data.get('content'),
        post_type=data.get('post_type'),
        priority=data.get('priority')
    )
    db.session.add(post)
    db.session.commit()
    
    # Send real-time update to all users
    socketio.emit('new_bulletin_post', {
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'post_type': post.post_type,
        'priority': post.priority,
        'author': current_user.username,
        'timestamp': post.created_at.isoformat()
    })
    
    return jsonify({'status': 'success', 'post_id': post.id})

# Send Notification Route
@app.route('/api/send_notification', methods=['POST'])
@login_required
def send_notification():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    target = data.get('target', 'all')
    
    # Determine target users
    if target == 'all':
        users = User.query.all()
    elif target == 'users':
        users = User.query.filter_by(user_type='user').all()
    elif target == 'rescue_teams':
        users = User.query.filter_by(user_type='rescue_team').all()
    else:
        users = User.query.all()
    
    # Create notifications for all target users
    for user in users:
        notification = Notification(
            user_id=user.id,
            title=data.get('title'),
            message=data.get('message'),
            notification_type=data.get('notification_type')
        )
        db.session.add(notification)
    
>>>>>>> Stashed changes
    db.session.commit()
    
    # Send real-time notification to all target users
    socketio.emit('new_notification', {
        'title': data.get('title'),
        'message': data.get('message'),
        'notification_type': data.get('notification_type'),
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({'status': 'success'})

<<<<<<< Updated upstream
=======
# Export Data Route
@app.route('/api/export_data')
@login_required
def export_data():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    # Get all data for export
    users = User.query.all()
    sos_alerts = SOSAlert.query.all()
    help_requests = HelpRequest.query.all()
    resource_offers = ResourceOffer.query.all()
    bulletin_posts = BulletinPost.query.all()
    
    # Create PDF export
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from io import BytesIO
    import base64
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph("DASH System Export Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 20))
    
    # Users table
    story.append(Paragraph("Users", styles['Heading2']))
    user_data = [['ID', 'Username', 'Email', 'Type', 'Created']]
    for user in users:
        user_data.append([str(user.id), user.username, user.email, user.user_type, user.created_at.strftime('%Y-%m-%d')])
    
    user_table = Table(user_data)
    user_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(user_table)
    story.append(Spacer(1, 20))
    
    # SOS Alerts table
    story.append(Paragraph("SOS Alerts", styles['Heading2']))
    sos_data = [['ID', 'User', 'Status', 'Created']]
    for alert in sos_alerts:
        sos_data.append([str(alert.id), alert.user.username, alert.status, alert.created_at.strftime('%Y-%m-%d %H:%M')])
    
    sos_table = Table(sos_data)
    sos_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(sos_table)
    story.append(Spacer(1, 20))
    
    # Help Requests table
    story.append(Paragraph("Help Requests", styles['Heading2']))
    request_data = [['ID', 'User', 'Type', 'Urgency', 'Status', 'Created']]
    for req in help_requests:
        request_data.append([str(req.id), req.user.username, req.request_type, req.urgency_level, req.status, req.created_at.strftime('%Y-%m-%d %H:%M')])
    
    request_table = Table(request_data)
    request_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(request_table)
    
    doc.build(story)
    buffer.seek(0)
    
    # Return PDF as base64
    pdf_data = base64.b64encode(buffer.getvalue()).decode()
    return jsonify({'status': 'success', 'pdf_data': pdf_data})

# User Management Route
@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    # Get all users
    all_users = User.query.order_by(User.created_at.desc()).all()
    
    return render_template('manage_users.html', users=all_users)

# Respond to SOS Route
@app.route('/api/respond_sos/<int:sos_id>', methods=['POST'])
@login_required
def respond_sos(sos_id):
    if current_user.user_type != 'rescue_team':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    sos_alert = SOSAlert.query.get_or_404(sos_id)
    sos_alert.status = 'responded'
    db.session.commit()
    
    return jsonify({'status': 'success'})

# Assign Request Route
@app.route('/api/assign_request/<int:request_id>', methods=['POST'])
@login_required
def assign_request(request_id):
    if current_user.user_type != 'rescue_team':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    help_request = HelpRequest.query.get_or_404(request_id)
    help_request.status = 'in_progress'
    db.session.commit()
    
    return jsonify({'status': 'success'})

# Update Request Status Route
@app.route('/api/update_request_status/<int:request_id>', methods=['POST'])
@login_required
def update_request_status(request_id):
    if current_user.user_type not in ['rescue_team', 'admin']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    help_request = HelpRequest.query.get_or_404(request_id)
    help_request.status = data.get('status')
    db.session.commit()
    
    return jsonify({'status': 'success'})

# Get User Details API
@app.route('/api/user_details/<int:user_id>')
@login_required
def get_user_details(user_id):
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    user = User.query.get_or_404(user_id)
    
    # Get user's activity
    sos_alerts = SOSAlert.query.filter_by(user_id=user_id).order_by(SOSAlert.created_at.desc()).limit(5).all()
    help_requests = HelpRequest.query.filter_by(user_id=user_id).order_by(HelpRequest.created_at.desc()).limit(5).all()
    resource_offers = ResourceOffer.query.filter_by(user_id=user_id).order_by(ResourceOffer.created_at.desc()).limit(5).all()
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'user_type': user.user_type,
            'phone': user.phone,
            'is_online': user.is_online,
            'created_at': user.created_at.isoformat()
        },
        'sos_alerts': [{
            'id': alert.id,
            'message': alert.message,
            'status': alert.status,
            'created_at': alert.created_at.isoformat()
        } for alert in sos_alerts],
        'help_requests': [{
            'id': req.id,
            'request_type': req.request_type,
            'urgency_level': req.urgency_level,
            'status': req.status,
            'created_at': req.created_at.isoformat()
        } for req in help_requests],
        'resource_offers': [{
            'id': offer.id,
            'resource_type': offer.resource_type,
            'is_available': offer.is_available,
            'created_at': offer.created_at.isoformat()
        } for offer in resource_offers]
    })
>>>>>>> Stashed changes

# Blood Bank Routes
@app.route('/blood_bank')
@login_required
def blood_bank():
    # Get all blood requests
    blood_requests = BloodRequest.query.order_by(BloodRequest.created_at.desc()).all()
    
    # Get all available blood donations
    blood_donations = BloodDonation.query.filter_by(is_available=True).order_by(BloodDonation.created_at.desc()).all()
    
    return render_template('blood_bank.html', 
                         blood_requests=blood_requests,
                         blood_donations=blood_donations)

# Create Blood Request Route
@app.route('/api/create_blood_request', methods=['POST'])
@login_required
def create_blood_request():
    data = request.get_json()
    blood_request = BloodRequest(
        user_id=current_user.id,
        blood_type=data.get('blood_type'),
        quantity=data.get('quantity'),
        urgency_level=data.get('urgency_level'),
        location_lat=data.get('lat'),
        location_lng=data.get('lng'),
        hospital_name=data.get('hospital_name'),
        patient_name=data.get('patient_name'),
        contact_phone=data.get('contact_phone'),
        description=data.get('description')
    )
    db.session.add(blood_request)
    db.session.commit()
    
    # Send real-time notification to rescue teams
    socketio.emit('new_blood_request', {
        'id': blood_request.id,
        'user_id': current_user.id,
        'username': current_user.username,
        'blood_type': blood_request.blood_type,
        'urgency': blood_request.urgency_level,
        'lat': blood_request.location_lat,
        'lng': blood_request.location_lng,
        'timestamp': blood_request.created_at.isoformat()
    })
    
    return jsonify({'status': 'success', 'request_id': blood_request.id})

# Create Blood Donation Route
@app.route('/api/create_blood_donation', methods=['POST'])
@login_required
def create_blood_donation():
    data = request.get_json()
    
    # Parse availability date if provided
    availability_date = None
    if data.get('availability_date'):
        try:
            availability_date = datetime.fromisoformat(data.get('availability_date'))
        except:
            pass
    
    blood_donation = BloodDonation(
        user_id=current_user.id,
        blood_type=data.get('blood_type'),
        quantity=data.get('quantity'),
        location_lat=data.get('lat'),
        location_lng=data.get('lng'),
        contact_phone=data.get('contact_phone'),
        availability_date=availability_date,
        description=data.get('description')
    )
    db.session.add(blood_donation)
    db.session.commit()
    
    return jsonify({'status': 'success', 'donation_id': blood_donation.id})

# Accept Blood Request Route (for rescue teams)
@app.route('/api/accept_blood_request/<int:request_id>', methods=['POST'])
@login_required
def accept_blood_request(request_id):
    if current_user.user_type != 'rescue_team':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    blood_request = BloodRequest.query.get_or_404(request_id)
    blood_request.status = 'accepted'
    blood_request.accepted_by = current_user.id
    db.session.commit()
    
    # Send notification to the requester
    notification = Notification(
        user_id=blood_request.user_id,
        title='Blood Request Accepted',
        message=f'Your blood request has been accepted by {current_user.username}. They will contact you soon.',
        notification_type='blood_request'
    )
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'status': 'success'})

# Update Blood Request Status Route
@app.route('/api/update_blood_request_status/<int:request_id>', methods=['POST'])
@login_required
def update_blood_request_status(request_id):
    if current_user.user_type not in ['rescue_team', 'admin']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    blood_request = BloodRequest.query.get_or_404(request_id)
    blood_request.status = data.get('status')
    db.session.commit()
    
    return jsonify({'status': 'success'})

# Get Blood Requests for Rescue Teams
@app.route('/api/blood_requests')
@login_required
def get_blood_requests():
    if current_user.user_type != 'rescue_team':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    # Get pending and accepted blood requests
    blood_requests = BloodRequest.query.filter(
        BloodRequest.status.in_(['pending', 'accepted', 'in_progress'])
    ).order_by(BloodRequest.created_at.desc()).all()
    
    return jsonify({
        'status': 'success',
        'requests': [{
            'id': req.id,
            'blood_type': req.blood_type,
            'quantity': req.quantity,
            'urgency_level': req.urgency_level,
            'patient_name': req.patient_name,
            'hospital_name': req.hospital_name,
            'contact_phone': req.contact_phone,
            'description': req.description,
            'status': req.status,
            'user': req.user.username,
            'created_at': req.created_at.isoformat(),
            'accepted_by': req.rescuer.username if req.rescuer else None
        } for req in blood_requests]
    })

# Get Blood Bank Statistics (for admin)
@app.route('/api/blood_bank_stats')
@login_required
def blood_bank_stats():
    if current_user.user_type != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    total_requests = BloodRequest.query.count()
    pending_requests = BloodRequest.query.filter_by(status='pending').count()
    accepted_requests = BloodRequest.query.filter_by(status='accepted').count()
    completed_requests = BloodRequest.query.filter_by(status='completed').count()
    total_donations = BloodDonation.query.count()
    available_donations = BloodDonation.query.filter_by(is_available=True).count()
    
    # Blood type statistics
    blood_type_stats = {}
    for blood_type in ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']:
        requests_count = BloodRequest.query.filter_by(blood_type=blood_type, status='pending').count()
        donations_count = BloodDonation.query.filter_by(blood_type=blood_type, is_available=True).count()
        blood_type_stats[blood_type] = {
            'requests': requests_count,
            'donations': donations_count
        }
    
    return jsonify({
        'total_requests': total_requests,
        'pending_requests': pending_requests,
        'accepted_requests': accepted_requests,
        'completed_requests': completed_requests,
        'total_donations': total_donations,
        'available_donations': available_donations,
        'blood_type_stats': blood_type_stats
    })

# ========== MISSING & FOUND PEOPLE ROUTES ==========
@app.route('/missing_found')
@login_required
def missing_found_page():
    missing = MissingFoundPerson.query.filter_by(person_type='missing', status='active').order_by(MissingFoundPerson.created_at.desc()).all()
    found = MissingFoundPerson.query.filter_by(person_type='found', status='active').order_by(MissingFoundPerson.created_at.desc()).all()
    return render_template('missing_found.html', missing=missing, found=found)

@app.route('/api/missing_found', methods=['POST'])
@login_required
def create_missing_found():
    data = request.get_json()
    lat = data.get('lat')
    lng = data.get('lng')
    
    # If location not provided, use user's current location
    if not lat or not lng:
        if current_user.location_lat and current_user.location_lng:
            lat = current_user.location_lat
            lng = current_user.location_lng
    
    person = MissingFoundPerson(
        user_id=current_user.id,
        person_type=data.get('person_type'),  # 'missing' or 'found'
        name=data.get('name'),
        age=data.get('age'),
        gender=data.get('gender'),
        description=data.get('description'),
        photo_url=data.get('photo_url'),
        last_seen_location=data.get('last_seen_location'),
        location_lat=lat,
        location_lng=lng,
        contact_phone=data.get('contact_phone')
    )
    db.session.add(person)
    db.session.commit()
    
    # Try to match with existing records
    matches = find_matches(person)
    
    # Notify all users, rescue teams, and admins about new missing/found report
    socketio.emit('new_missing_found_report', {
        'id': person.id,
        'person_type': person.person_type,
        'name': person.name,
        'age': person.age,
        'gender': person.gender,
        'description': person.description,
        'photo_url': person.photo_url,
        'last_seen_location': person.last_seen_location,
        'lat': person.location_lat,
        'lng': person.location_lng,
        'contact_phone': person.contact_phone,
        'reported_by': current_user.username,
        'timestamp': person.created_at.isoformat(),
        'matches': matches
    })
    
    return jsonify({'status': 'success', 'person_id': person.id, 'matches': matches})

def find_matches(person):
    """Find potential matches for a missing/found person."""
    if person.person_type == 'missing':
        candidates = MissingFoundPerson.query.filter_by(person_type='found', status='active').all()
    else:
        candidates = MissingFoundPerson.query.filter_by(person_type='missing', status='active').all()
    
    matches = []
    for candidate in candidates:
        score = calculate_match_score(person, candidate)
        if score > 0.6:  # 60% match threshold
            matches.append({
                'id': candidate.id,
                'name': candidate.name,
                'age': candidate.age,
                'score': score,
                'photo_url': candidate.photo_url
            })
    return sorted(matches, key=lambda x: x['score'], reverse=True)

def calculate_match_score(person1, person2):
    """Calculate match score between two person records."""
    score = 0.0
    if person1.name and person2.name and person1.name.lower() == person2.name.lower():
        score += 0.3
    if person1.age and person2.age and abs(person1.age - person2.age) <= 2:
        score += 0.2
    if person1.gender and person2.gender and person1.gender.lower() == person2.gender.lower():
        score += 0.2
    if person1.description and person2.description:
        # Simple keyword matching
        words1 = set(person1.description.lower().split())
        words2 = set(person2.description.lower().split())
        common = len(words1 & words2)
        if common > 0:
            score += min(0.3, common * 0.05)
    return min(score, 1.0)

@app.route('/api/match_person/<int:person1_id>/<int:person2_id>', methods=['POST'])
@login_required
def match_person(person1_id, person2_id):
    person1 = MissingFoundPerson.query.get_or_404(person1_id)
    person2 = MissingFoundPerson.query.get_or_404(person2_id)
    
    person1.matched_with = person2_id
    person2.matched_with = person1_id
    person1.status = 'matched'
    person2.status = 'matched'
    db.session.commit()
    
    # Notify about match
    socketio.emit('person_matched', {
        'person1_id': person1_id,
        'person2_id': person2_id,
        'person1_name': person1.name,
        'person2_name': person2.name
    })
    
    return jsonify({'status': 'success'})

# ========== DISASTER RISK ASSESSMENT ROUTES ==========
@app.route('/disaster_risk')
@login_required
def disaster_risk_page():
    risks = DisasterRisk.query.filter_by(is_active=True).order_by(DisasterRisk.created_at.desc()).all()
    return render_template('disaster_risk.html', risks=risks)

@app.route('/api/disaster_risk/assess', methods=['POST'])
@login_required
def assess_disaster_risk():
    if current_user.user_type not in ['admin', 'rescue_team']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    lat = data.get('lat')
    lng = data.get('lng')
    
    # Get weather data from OpenWeatherMap API (you'll need to add API key)
    weather_api_key = os.getenv('WEATHER_API_KEY', '')
    weather_data = {}
    if weather_api_key:
        try:
            url = f'https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lng}&appid={weather_api_key}'
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                weather_data = response.json()
        except Exception as e:
            print(f"Weather API error: {e}")
    
    # Analyze weather data to determine risk
    severity = 'low'
    disaster_type = 'none'
    recommendations = []
    
    if weather_data:
        main_weather = weather_data.get('weather', [{}])[0].get('main', '').lower()
        wind_speed = weather_data.get('wind', {}).get('speed', 0) * 3.6  # Convert to km/h
        
        if 'hurricane' in main_weather or wind_speed > 120:
            severity = 'critical'
            disaster_type = 'hurricane'
            recommendations = ['Evacuate immediately', 'Seek shelter in strong buildings', 'Stay away from windows']
        elif 'storm' in main_weather or wind_speed > 60:
            severity = 'high'
            disaster_type = 'storm'
            recommendations = ['Stay indoors', 'Avoid outdoor activities', 'Secure loose objects']
        elif 'rain' in main_weather:
            severity = 'moderate'
            disaster_type = 'flood'
            recommendations = ['Avoid low-lying areas', 'Monitor water levels', 'Prepare evacuation plan']
    
    risk = DisasterRisk(
        location_lat=lat,
        location_lng=lng,
        disaster_type=disaster_type,
        severity_level=severity,
        description=f"Weather-based risk assessment",
        weather_data=json.dumps(weather_data),
        action_recommendations='\n'.join(recommendations)
    )
    db.session.add(risk)
    db.session.commit()
    
    # Notify users in the area
    notify_users_in_area(lat, lng, risk)
    
    # Broadcast to all users, rescue teams, and admins
    socketio.emit('new_disaster_risk', {
        'id': risk.id,
        'disaster_type': disaster_type,
        'severity': severity,
        'description': risk.description,
        'recommendations': recommendations,
        'lat': lat,
        'lng': lng,
        'timestamp': risk.created_at.isoformat()
    })
    
    return jsonify({'status': 'success', 'risk': {
        'id': risk.id,
        'severity': severity,
        'disaster_type': disaster_type,
        'recommendations': recommendations
    }})

def notify_users_in_area(lat, lng, risk, radius_km=50):
    """Notify users within radius_km of the risk location."""
    users = User.query.filter(User.location_lat.isnot(None), User.location_lng.isnot(None)).all()
    for user in users:
        try:
            distance = geodesic((lat, lng), (user.location_lat, user.location_lng)).km
            if distance <= radius_km:
                notification = Notification(
                    user_id=user.id,
                    title=f'Disaster Risk Alert: {risk.disaster_type.title()}',
                    message=f'{risk.severity_level.upper()} risk detected. {risk.action_recommendations}',
                    notification_type='disaster_risk'
                )
                db.session.add(notification)
        except Exception:
            continue
    db.session.commit()

@app.route('/api/disaster_risk', methods=['GET', 'PUT'])
@login_required
def get_or_update_disaster_risks():
    if request.method == 'PUT':
        # Admin can update disaster risk
        if current_user.user_type != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized'})
        
        data = request.get_json()
        risk_id = data.get('id')
        risk = DisasterRisk.query.get_or_404(risk_id)
        
        risk.disaster_type = data.get('disaster_type', risk.disaster_type)
        risk.severity_level = data.get('severity_level', risk.severity_level)
        risk.description = data.get('description', risk.description)
        risk.action_recommendations = data.get('action_recommendations', risk.action_recommendations)
        risk.is_active = data.get('is_active', risk.is_active)
        db.session.commit()
        
        # Broadcast update to all users
        socketio.emit('disaster_risk_updated', {
            'id': risk.id,
            'disaster_type': risk.disaster_type,
            'severity': risk.severity_level,
            'description': risk.description,
            'recommendations': risk.action_recommendations,
            'is_active': risk.is_active,
            'timestamp': risk.updated_at.isoformat() if risk.updated_at else risk.created_at.isoformat()
        })
        
        return jsonify({'status': 'success', 'risk': {
            'id': risk.id,
            'disaster_type': risk.disaster_type,
            'severity': risk.severity_level,
            'description': risk.description,
            'recommendations': risk.action_recommendations
        }})
    
    # GET request - return all active risks
    risks = DisasterRisk.query.filter_by(is_active=True).order_by(DisasterRisk.created_at.desc()).all()
    return jsonify({
        'status': 'success',
        'risks': [{
            'id': r.id,
            'disaster_type': r.disaster_type,
            'severity': r.severity_level,
            'lat': r.location_lat,
            'lng': r.location_lng,
            'description': r.description,
            'recommendations': r.action_recommendations,
            'created_at': r.created_at.isoformat(),
            'updated_at': r.updated_at.isoformat() if r.updated_at else None
        } for r in risks]
    })

# ========== RESOURCE INVENTORY ROUTES ==========
@app.route('/resource_inventory')
@login_required
def resource_inventory_page():
    resources = ResourceInventory.query.order_by(ResourceInventory.resource_type).all()
    low_stock = ResourceInventory.query.filter(
        ResourceInventory.quantity_available <= ResourceInventory.low_stock_threshold
    ).all()
    return render_template('resource_inventory.html', resources=resources, low_stock=low_stock)

@app.route('/api/resource_inventory', methods=['POST'])
@login_required
def create_resource():
    if current_user.user_type not in ['admin', 'rescue_team']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    expiry_date = None
    if data.get('expiry_date'):
        try:
            expiry_date = datetime.fromisoformat(data.get('expiry_date'))
        except:
            pass
    
    resource = ResourceInventory(
        resource_type=data.get('resource_type'),
        resource_name=data.get('resource_name'),
        quantity_total=data.get('quantity_total', 0),
        quantity_available=data.get('quantity_available', data.get('quantity_total', 0)),
        location_lat=data.get('lat'),
        location_lng=data.get('lng'),
        location_name=data.get('location_name'),
        supplier_id=current_user.id,
        expiry_date=expiry_date,
        low_stock_threshold=data.get('low_stock_threshold', 10),
        unit=data.get('unit', 'units')
    )
    db.session.add(resource)
    db.session.commit()
    
    return jsonify({'status': 'success', 'resource_id': resource.id})

@app.route('/api/resource_inventory/<int:resource_id>', methods=['PUT', 'DELETE'])
@login_required
def update_resource(resource_id):
    if current_user.user_type not in ['admin', 'rescue_team']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    resource = ResourceInventory.query.get_or_404(resource_id)
    
    if request.method == 'DELETE':
        db.session.delete(resource)
        db.session.commit()
        return jsonify({'status': 'success'})
    
    data = request.get_json()
    resource.quantity_available = data.get('quantity_available', resource.quantity_available)
    resource.quantity_total = data.get('quantity_total', resource.quantity_total)
    resource.location_name = data.get('location_name', resource.location_name)
    db.session.commit()
    
    # Check for low stock
    if resource.quantity_available <= resource.low_stock_threshold:
        notify_low_stock(resource)
    
    return jsonify({'status': 'success'})

def notify_low_stock(resource):
    """Notify admins when resource stock is low."""
    admins = User.query.filter_by(user_type='admin').all()
    for admin in admins:
        notification = Notification(
            user_id=admin.id,
            title='Low Stock Alert',
            message=f'{resource.resource_name} is running low. Only {resource.quantity_available} {resource.unit} remaining.',
            notification_type='low_stock'
        )
        db.session.add(notification)
    db.session.commit()

@app.route('/api/resource_inventory/distribute', methods=['POST'])
@login_required
def distribute_resource():
    if current_user.user_type not in ['admin', 'rescue_team']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.get_json()
    resource = ResourceInventory.query.get_or_404(data.get('resource_id'))
    
    if resource.quantity_available < data.get('quantity', 0):
        return jsonify({'status': 'error', 'message': 'Insufficient stock'})
    
    distribution = ResourceDistribution(
        resource_id=resource.id,
        distributed_by=current_user.id,
        distributed_to=data.get('distributed_to'),
        quantity=data.get('quantity'),
        impact_notes=data.get('impact_notes')
    )
    resource.quantity_available -= data.get('quantity', 0)
    
    db.session.add(distribution)
    db.session.commit()
    
    return jsonify({'status': 'success'})

# ========== INJURY CLASSIFICATION ROUTES ==========
@app.route('/api/injury_report', methods=['POST'])
@login_required
def create_injury_report():
    data = request.get_json()
    
    # AI-based severity classification
    severity = classify_injury_severity(data)
    
    injury = InjuryReport(
        user_id=current_user.id,
        injury_type=data.get('injury_type'),
        severity=severity['severity'],
        description=data.get('description'),
        location_lat=data.get('lat'),
        location_lng=data.get('lng'),
        ai_confidence=severity['confidence'],
        sensor_data=json.dumps(data.get('sensor_data', {}))
    )
    db.session.add(injury)
    db.session.commit()
    
    # Notify rescue teams for critical injuries
    if severity['severity'] == 'critical':
        notify_rescue_teams(injury)
    
    return jsonify({'status': 'success', 'injury_id': injury.id, 'severity': severity})

def classify_injury_severity(data):
    """Classify injury severity using AI and data analysis."""
    description = (data.get('description', '') + ' ' + data.get('injury_type', '')).lower()
    sensor_data = data.get('sensor_data', {})
    
    critical_keywords = ['unconscious', 'bleeding', 'severe', 'critical', 'broken bone', 'head injury', 'chest pain', 'difficulty breathing']
    serious_keywords = ['pain', 'swelling', 'cut', 'bruise', 'sprain', 'fracture']
    
    score = 0.0
    if any(keyword in description for keyword in critical_keywords):
        score += 0.6
    if any(keyword in description for keyword in serious_keywords):
        score += 0.3
    
    # Check sensor data (if available)
    if sensor_data.get('heart_rate'):
        hr = sensor_data.get('heart_rate')
        if hr < 60 or hr > 120:
            score += 0.2
    
    if score >= 0.6:
        severity = 'critical'
        confidence = min(score, 0.95)
    elif score >= 0.3:
        severity = 'serious'
        confidence = min(score + 0.2, 0.85)
    else:
        severity = 'minor'
        confidence = 0.7
    
    return {'severity': severity, 'confidence': round(confidence, 2)}

def notify_rescue_teams(injury):
    """Notify rescue teams about critical injuries."""
    rescue_teams = User.query.filter_by(user_type='rescue_team', is_online=True).all()
    for team in rescue_teams:
        notification = Notification(
            user_id=team.id,
            title='Critical Injury Reported',
            message=f'Critical injury reported at location. Immediate response needed.',
            notification_type='critical_injury'
        )
        db.session.add(notification)
    db.session.commit()

# ========== FAKE NEWS DETECTION ROUTES ==========
@app.route('/api/news/check', methods=['POST'])
@login_required
def check_news():
    data = request.get_json()
    title = data.get('title', '')
    content = data.get('content', '')
    source_url = data.get('source_url', '')
    
    # AI-based fake news detection
    fake_score = detect_fake_news(title, content, source_url)
    
    news_post = NewsPost(
        user_id=current_user.id,
        title=title,
        content=content,
        source_url=source_url,
        is_fake=fake_score['is_fake'],
        ai_confidence=fake_score['confidence']
    )
    db.session.add(news_post)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'news_id': news_post.id,
        'is_fake': fake_score['is_fake'],
        'confidence': fake_score['confidence'],
        'reasons': fake_score['reasons']
    })

def detect_fake_news(title, content, source_url):
    """Detect fake news using AI and pattern analysis."""
    fake_indicators = []
    confidence = 0.0
    
    # Check for sensational language
    sensational_words = ['shocking', 'you won\'t believe', 'doctors hate', 'miracle cure', 'secret']
    if any(word in title.lower() or word in content.lower() for word in sensational_words):
        fake_indicators.append('Sensational language detected')
        confidence += 0.3
    
    # Check source credibility
    if source_url:
        credible_domains = ['bbc.com', 'reuters.com', 'ap.org', 'gov', 'edu']
        if not any(domain in source_url.lower() for domain in credible_domains):
            fake_indicators.append('Unverified source')
            confidence += 0.2
    
    # Check for excessive punctuation
    if title.count('!') > 2 or title.count('?') > 2:
        fake_indicators.append('Excessive punctuation')
        confidence += 0.1
    
    # Check content length (very short posts are often fake)
    if len(content) < 50:
        fake_indicators.append('Very short content')
        confidence += 0.1
    
    is_fake = confidence >= 0.4
    return {
        'is_fake': is_fake,
        'confidence': min(confidence, 0.95),
        'reasons': fake_indicators
    }

@app.route('/api/news/<int:news_id>/flag', methods=['POST'])
@login_required
def flag_news(news_id):
    if current_user.user_type not in ['admin', 'rescue_team']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    news = NewsPost.query.get_or_404(news_id)
    news.is_fake = True
    news.flagged_by = current_user.id
    news.verification_notes = request.get_json().get('notes', '')
    db.session.commit()
    
    return jsonify({'status': 'success'})

# ========== REWARD & REPUTATION ROUTES ==========
@app.route('/rewards')
@login_required
def rewards_page():
    reward = UserReward.query.filter_by(user_id=current_user.id).first()
    if not reward:
        reward = UserReward(user_id=current_user.id)
        db.session.add(reward)
        db.session.commit()
    
    transactions = RewardTransaction.query.filter_by(user_id=current_user.id).order_by(RewardTransaction.created_at.desc()).limit(20).all()
    
    # Get rescue teams that can be rewarded (for users only)
    rescue_teams = []
    if current_user.user_type == 'user':
        rescue_teams = User.query.filter_by(user_type='rescue_team').all()
    
    return render_template('rewards.html', reward=reward, transactions=transactions, rescue_teams=rescue_teams)

def award_points(user_id, points, transaction_type, description, related_id=None, badge=None):
    """Award points to a user."""
    reward = UserReward.query.filter_by(user_id=user_id).first()
    if not reward:
        reward = UserReward(user_id=user_id)
        db.session.add(reward)
    
    reward.points += points
    reward.total_contributions += 1
    reward.reputation_score = calculate_reputation(reward)
    
    if badge:
        badges = json.loads(reward.badges or '[]')
        if badge not in badges:
            badges.append(badge)
        reward.badges = json.dumps(badges)
    
    transaction = RewardTransaction(
        user_id=user_id,
        transaction_type=transaction_type,
        points_earned=points,
        badge_earned=badge,
        description=description,
        related_id=related_id
    )
    db.session.add(transaction)
    db.session.commit()

def calculate_reputation(reward):
    """Calculate reputation score based on contributions and points."""
    base_score = min(reward.points / 100, 5.0)  # Max 5.0 from points
    contribution_bonus = min(reward.total_contributions * 0.1, 2.0)  # Max 2.0 from contributions
    return round(base_score + contribution_bonus, 2)

@app.route('/api/give_reward', methods=['POST'])
@login_required
def give_reward():
    """Allow users to give rewards to rescue teams."""
    if current_user.user_type != 'user':
        return jsonify({'status': 'error', 'message': 'Only regular users can give rewards'})
    
    data = request.get_json()
    rescue_team_id = data.get('rescue_team_id')
    points = data.get('points', 10)  # Default 10 points
    message = data.get('message', 'Thank you for your help!')
    
    if not rescue_team_id:
        return jsonify({'status': 'error', 'message': 'Rescue team ID is required'})
    
    rescue_team = User.query.filter_by(id=rescue_team_id, user_type='rescue_team').first()
    if not rescue_team:
        return jsonify({'status': 'error', 'message': 'Rescue team not found'})
    
    # Check if user has enough points (optional - can be removed if users can give unlimited rewards)
    user_reward = UserReward.query.filter_by(user_id=current_user.id).first()
    if not user_reward:
        user_reward = UserReward(user_id=current_user.id)
        db.session.add(user_reward)
    
    # Award points to rescue team
    rescue_reward = UserReward.query.filter_by(user_id=rescue_team_id).first()
    if not rescue_reward:
        rescue_reward = UserReward(user_id=rescue_team_id)
        db.session.add(rescue_reward)
    
    rescue_reward.points += points
    rescue_reward.total_contributions += 1
    rescue_reward.reputation_score = calculate_reputation(rescue_reward)
    
    # Create transaction for rescue team (received reward)
    rescue_transaction = RewardTransaction(
        user_id=rescue_team_id,
        transaction_type='reward_received',
        points_earned=points,
        description=f'Reward from {current_user.username}: {message}',
        given_by=current_user.id
    )
    db.session.add(rescue_transaction)
    
    # Create transaction for user (gave reward)
    user_transaction = RewardTransaction(
        user_id=current_user.id,
        transaction_type='reward_given',
        points_earned=0,  # User doesn't earn points for giving rewards
        description=f'Gave reward to {rescue_team.username}: {message}',
        related_id=rescue_team_id
    )
    db.session.add(user_transaction)
    
    db.session.commit()
    
    # Notify rescue team
    notification = Notification(
        user_id=rescue_team_id,
        title='Reward Received!',
        message=f'You received {points} points from {current_user.username}: {message}',
        notification_type='reward'
    )
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': f'Reward given successfully! {rescue_team.username} received {points} points.'})

@app.route('/api/voice_sos', methods=['POST'])
@login_required
def voice_sos():
    """Voice-based SOS endpoint."""
    data = request.get_json()
    voice_text = data.get('voice_text', '').lower()
    lat = data.get('lat')
    lng = data.get('lng')
    
    # If location not provided, use user's current location
    if not lat or not lng:
        if current_user.location_lat and current_user.location_lng:
            lat = current_user.location_lat
            lng = current_user.location_lng
        else:
            return jsonify({'status': 'error', 'message': 'Location is required'})
    
    # Detect SOS phrases
    sos_phrases = ['help', 'emergency', 'sos', 'rescue', 'save me', 'need help', 'urgent']
    is_sos = any(phrase in voice_text for phrase in sos_phrases)
    
    if is_sos:
        sos_alert = SOSAlert(
            user_id=current_user.id,
            location_lat=lat,
            location_lng=lng,
            message=f'Voice SOS: {voice_text}'
        )
        db.session.add(sos_alert)
        db.session.commit()
        
        # Get nearby hospitals
        nearby_hospitals = hospitals_near_location(lat, lng, max_distance_km=10)
        
        # Emit to rescue teams and admins
        socketio.emit('new_sos_alert', {
            'id': sos_alert.id,
            'user_id': current_user.id,
            'username': current_user.username,
            'lat': sos_alert.location_lat,
            'lng': sos_alert.location_lng,
            'message': sos_alert.message,
            'timestamp': sos_alert.created_at.isoformat(),
            'nearby_hospitals': nearby_hospitals,
            'is_voice': True
        }, room='rescue_teams')
        
        socketio.emit('new_sos_alert', {
            'id': sos_alert.id,
            'user_id': current_user.id,
            'username': current_user.username,
            'lat': sos_alert.location_lat,
            'lng': sos_alert.location_lng,
            'message': sos_alert.message,
            'timestamp': sos_alert.created_at.isoformat(),
            'nearby_hospitals': nearby_hospitals,
            'is_voice': True
        }, room='admins')
        
        return jsonify({
            'status': 'success',
            'alert_id': sos_alert.id,
            'nearby_hospitals': nearby_hospitals
        })
    
    return jsonify({'status': 'error', 'message': 'SOS phrase not detected'})

# Jinja2 filters
@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value)
    except:
        return []

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
