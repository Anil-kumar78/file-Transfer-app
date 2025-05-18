from flask import Flask, request, jsonify, send_file, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime
import os
import jwt
from functools import wraps
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filetransfer.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_logs = db.relationship('AccessLog', backref='file', lazy=True)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    user = User(
        username=data['username'],
        password_hash=generate_password_hash(data['password'])
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password_hash, data['password']):
        token = jwt.encode(
            {'user_id': user.id},
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400

        # Ensure upload directory exists
        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), app.config['UPLOAD_FOLDER'])
        os.makedirs(upload_dir, exist_ok=True)

        # Generate encryption key
        key = Fernet.generate_key()
        f = Fernet(key)
        
        # Read and encrypt file
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        
        # Save encrypted file with unique filename
        safe_filename = f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filename = os.path.join(upload_dir, safe_filename)
        
        with open(filename, 'wb') as f:
            f.write(encrypted_data)
        
        try:
            # Create database entry
            db_file = File(
                filename=filename,
                original_filename=file.filename,
                encryption_key=key.decode(),
                user_id=current_user.id
            )
            db.session.add(db_file)
            db.session.flush()  # This will generate the file.id without committing
            
            # Log access
            log = AccessLog(
                file_id=db_file.id,  # Now we have the file.id
                user_id=current_user.id,
                action='upload'
            )
            db.session.add(log)
            db.session.commit()
            
            return jsonify({'message': 'File uploaded successfully'}), 201
            
        except Exception as db_error:
            db.session.rollback()
            # Clean up the uploaded file if database operation fails
            if os.path.exists(filename):
                os.remove(filename)
            raise db_error
        
    except Exception as e:
        print(f"Upload error: {str(e)}")  # For debugging
        return jsonify({'message': f'Error uploading file: {str(e)}'}), 500

@app.route('/download/<int:file_id>', methods=['GET'])
@token_required
def download_file(current_user, file_id):
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Log access
    log = AccessLog(
        file_id=file.id,
        user_id=current_user.id,
        action='download'
    )
    db.session.add(log)
    db.session.commit()
    
    # Decrypt and return file
    f = Fernet(file.encryption_key.encode())
    with open(file.filename, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = f.decrypt(encrypted_data)
    
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file.original_filename
    )

@app.route('/files', methods=['GET'])
@token_required
def list_files(current_user):
    files = File.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': f.id,
        'filename': f.original_filename,
        'upload_date': f.upload_date.isoformat()
    } for f in files])

@app.route('/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    logs = AccessLog.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'file_id': log.file_id,
        'action': log.action,
        'timestamp': log.timestamp.isoformat()
    } for log in logs])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Check if we're in production environment
    if os.environ.get('FLASK_ENV') == 'production':
        from waitress import serve
        print("Starting production server with Waitress...")
        serve(app, host='0.0.0.0', port=8080)
    else:
        print("Starting development server...")
        app.run(debug=True) 