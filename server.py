from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import os
from datetime import datetime, timedelta, timezone
import re

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///justiceconnect.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'JusticeConnect <noreply@justiceconnect.com>')

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# --- Models ---
class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    code = db.Column(db.String(6), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

class Victim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=True)
    postcode = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class Lawyer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=False)
    firm = db.Column(db.String(200), nullable=True)
    postcode = db.Column(db.String(20), nullable=False)
    bar_number = db.Column(db.String(50), unique=True, nullable=False)
    specialization = db.Column(db.String(200), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Submitted')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    victim_id = db.Column(db.Integer, db.ForeignKey('victim.id'), nullable=False)
    victim = db.relationship('Victim', backref=db.backref('cases', lazy=True, cascade="all, delete-orphan"))

# --- Helper Functions ---
def generate_verification_code(): return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email, code, user_type):
    try:
        subject = "JusticeConnect - Email Verification Code"
        body = f"Welcome to JusticeConnect!\n\nYour verification code is: {code}\n\nThis code expires in 15 minutes." if user_type == 'victim' else f"Thank you for your interest in JusticeConnect!\n\nYour verification code is: {code}\n\nThis code expires in 15 minutes."
        msg = Message(subject=subject, recipients=[email], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

def send_lawyer_welcome_email(email, name):
    try:
        subject = "JusticeConnect - Application Received"
        body = f"Dear {name},\n\nThank you for applying to join JusticeConnect as a legal professional!\nWe have received your application and it is currently under review. This process typically takes 2-3 business days.\n\nBest regards,\nThe JusticeConnect Team"
        msg = Message(subject=subject, recipients=[email], body=body)
        mail.send(msg)
    except Exception as e:
        print(f"Error sending lawyer welcome email: {e}")

def validate_email(e): return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', e)
def validate_phone(p): return len(re.sub(r'\D', '', p)) >= 10

# --- API Routes ---
@app.route('/api/send-verification-code', methods=['POST'])
def send_verification_code_route():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    user_type = data.get('user_type', 'victim')
    if not email or not validate_email(email): return jsonify({'message': 'Please enter a valid email address.'}), 400
    if user_type not in ['victim', 'lawyer']: return jsonify({'message': 'Invalid user type specified.'}), 400
    existing_user = Victim.query.filter_by(email=email).first() if user_type == 'victim' else Lawyer.query.filter_by(email=email).first()
    if existing_user: return jsonify({'message': 'An account with this email already exists.'}), 409
    VerificationCode.query.filter_by(email=email, user_type=user_type).delete()
    code = generate_verification_code()
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=15)
    verification = VerificationCode(email=email, code=code, user_type=user_type, expires_at=expires_at)
    db.session.add(verification)
    db.session.commit()
    if send_verification_email(email, code, user_type): return jsonify({'message': 'Verification code sent successfully.'}), 200
    else: return jsonify({'message': 'Failed to send verification email.'}), 500

@app.route('/api/register-victim', methods=['POST'])
def register_victim():
    data = request.get_json()
    required = ['name', 'email', 'phone', 'password', 'verification_code']
    if not all(field in data and data[field] for field in required): return jsonify({'message': 'Please fill in all required fields.'}), 400
    email = data['email'].strip().lower()
    verification = VerificationCode.query.filter_by(email=email, code=data['verification_code'].strip(), user_type='victim', is_used=False).first()
    if not verification: return jsonify({'message': 'Invalid or incorrect verification code.'}), 400
    if verification.expires_at < datetime.now(timezone.utc).replace(tzinfo=None): return jsonify({'message': 'Verification code has expired.'}), 400
    victim = Victim(name=data['name'].strip(), email=email, phone=data['phone'].strip(), address=data.get('address', '').strip(), postcode=data.get('postcode', '').strip(), password_hash=generate_password_hash(data['password']), is_verified=True)
    verification.is_used = True
    db.session.add(victim)
    db.session.commit()
    return jsonify({'message': 'Account created successfully! You can now log in.'}), 201

@app.route('/api/register-lawyer', methods=['POST'])
def register_lawyer():
    data = request.get_json()
    required = ['name', 'email', 'phone', 'postcode', 'bar_number', 'specialization', 'experience', 'password', 'verification_code']
    if not all(field in data and data[field] for field in required): return jsonify({'message': 'Please fill in all required fields.'}), 400
    email = data['email'].strip().lower()
    verification = VerificationCode.query.filter_by(email=email, code=data['verification_code'].strip(), user_type='lawyer', is_used=False).first()
    if not verification: return jsonify({'message': 'Invalid or incorrect verification code.'}), 400
    if verification.expires_at < datetime.now(timezone.utc).replace(tzinfo=None): return jsonify({'message': 'Verification code has expired.'}), 400
    lawyer = Lawyer(name=data['name'].strip(), email=email, phone=data['phone'].strip(), firm=data.get('firm', '').strip(), postcode=data['postcode'].strip(), bar_number=data['bar_number'].strip(), specialization=data['specialization'].strip(), experience=data['experience'], password_hash=generate_password_hash(data['password']), is_verified=True)
    verification.is_used = True
    db.session.add(lawyer)
    db.session.commit()
    send_lawyer_welcome_email(email, lawyer.name)
    return jsonify({'message': 'Account created successfully! You can now log in.'}), 201

@app.route('/api/login-victim', methods=['POST'])
def login_victim():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    victim = Victim.query.filter_by(email=email).first()
    if not victim or not check_password_hash(victim.password_hash, password): return jsonify({'message': 'Invalid email or password.'}), 401
    resp = make_response(jsonify({'message': 'Login successful!', 'user': {'id': victim.id, 'name': victim.name, 'type': 'victim'}}))
    resp.set_cookie('user_id', str(victim.id), max_age=timedelta(days=1), httponly=True, samesite='Lax')
    resp.set_cookie('user_type', 'victim', max_age=timedelta(days=1), httponly=True, samesite='Lax')
    return resp, 200

@app.route('/api/login-lawyer', methods=['POST'])
def login_lawyer():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    bar_number = data.get('bar_number', '')
    lawyer = Lawyer.query.filter_by(email=email, bar_number=bar_number).first()
    if not lawyer or not check_password_hash(lawyer.password_hash, password): return jsonify({'message': 'Invalid credentials provided.'}), 401
    resp = make_response(jsonify({'message': 'Login successful!', 'user': {'id': lawyer.id, 'name': lawyer.name, 'type': 'lawyer'}}))
    resp.set_cookie('user_id', str(lawyer.id), max_age=timedelta(days=1), httponly=True, samesite='Lax')
    resp.set_cookie('user_type', 'lawyer', max_age=timedelta(days=1), httponly=True, samesite='Lax')
    return resp, 200

@app.route('/api/add-case', methods=['POST'])
def add_case():
    victim_id = request.cookies.get('user_id')
    user_type = request.cookies.get('user_type')
    if not victim_id or user_type != 'victim': return jsonify({'message': 'Authentication required.'}), 401
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    if not title: return jsonify({'message': 'Case title is required.'}), 400
    new_case = Case(title=title, description=description, victim_id=int(victim_id))
    db.session.add(new_case)
    db.session.commit()
    return jsonify({'message': 'Case submitted successfully!'}), 201

# --- Page Rendering and Session Routes ---
@app.route('/')
def index(): return render_template('Landingpage.html')

@app.route('/victim-dashboard')
def victim_dashboard():
    victim_id = request.cookies.get('user_id')
    user_type = request.cookies.get('user_type')
    if not victim_id or user_type != 'victim': return redirect(url_for('index'))
    victim = db.session.get(Victim, int(victim_id))
    if not victim:
        resp = make_response(redirect(url_for('index')))
        resp.set_cookie('user_id', '', expires=0); resp.set_cookie('user_type', '', expires=0)
        return resp
    victim_cases = sorted(victim.cases, key=lambda case: case.created_at, reverse=True)
    return render_template('victim_dashboard.html', victim=victim, cases=victim_cases)

@app.route('/lawyer-dashboard')
def lawyer_dashboard():
    lawyer_id = request.cookies.get('user_id')
    user_type = request.cookies.get('user_type')
    if not lawyer_id or user_type != 'lawyer': return redirect(url_for('index'))
    lawyer = db.session.get(Lawyer, int(lawyer_id))
    if not lawyer:
        resp = make_response(redirect(url_for('index')))
        resp.set_cookie('user_id', '', expires=0); resp.set_cookie('user_type', '', expires=0)
        return resp
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template('lawyer_dashboard.html', lawyer=lawyer, cases=all_cases)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('user_id', '', expires=0)
    resp.set_cookie('user_type', '', expires=0)
    return resp

# --- Error Handlers & App Init ---
@app.errorhandler(404)
def not_found(e): return jsonify({'message': 'Endpoint not found.'}), 404
@app.errorhandler(500)
def internal_error(e): db.session.rollback(); return jsonify({'message': 'An internal server error occurred.'}), 500

@app.before_request
def create_tables(): db.create_all()

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

