from flask import Blueprint, request, jsonify, url_for
from . import db, bcrypt, jwt
from .models import User, File
from .utils import send_verification_email
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

bp = Blueprint('routes', __name__)

@bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    send_verification_email(new_user)
    return jsonify({'message': 'User created, please verify your email'}), 201

@bp.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = User.verify_reset_token(token)
    if not user:
        return jsonify({'message': 'Invalid or expired token'}), 400
    user.confirmed = True
    db.session.commit()
    return jsonify({'message': 'Account verified'}), 200

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        if not user.confirmed:
            return jsonify({'message': 'Please verify your email first'}), 400
        access_token = create_access_token(identity=user.id)
        return jsonify({'token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@bp.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user.is_ops:
        return jsonify({'message': 'Permission denied'}), 403
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if not file.filename.endswith(('.pptx', '.docx', '.xlsx')):
        return jsonify({'message': 'Invalid file type'}), 400
    file.save(f'uploads/{file.filename}')
    new_file = File(file_name=file.filename, user_id=user.id)
    db.session.add(new_file)
    db.session.commit()
    return jsonify({'message': 'File uploaded successfully'}), 201

@bp.route('/list_files', methods=['GET'])
@jwt_required()
def list_files():
    files = File.query.all()
    return jsonify([{'file_name': file.file_name, 'date_uploaded': file.date_uploaded} for file in files]), 200

@bp.route('/download_file/<int:file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user.is_ops:
        return jsonify({'message': 'Permission denied'}), 403
    file = File.query.get_or_404(file_id)
    download_url = url_for('routes.send_file', file_id=file.id, _external=True)
    return jsonify({'download_link': download_url, 'message': 'success'}), 200

@bp.route('/send_file/<int:file_id>', methods=['GET'])
@jwt_required()
def send_file(file_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user.is_ops:
        return jsonify({'message': 'Permission denied'}), 403
    file = File.query.get_or_404(file_id)
    return send_from_directory('uploads', file.file_name)
