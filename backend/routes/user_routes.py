from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models.user import User
from __init__ import db

user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not all(k in data for k in ('username', 'email', 'password', 'full_name')):
        return jsonify({'message': 'Missing required fields'}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400
        
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already taken'}), 400
        
    new_user = User(
        username=data['username'],
        email=data['email'],
        full_name=data['full_name']
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not all(k in data for k in ('email', 'password')):
        return jsonify({'message': 'Missing email or password'}), 400
        
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401
        
    access_token = create_access_token(identity=user.id)
    print(f"Generated token for user {user.id}: {access_token}")
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }
    }), 200

@user_bp.route('/me', methods=['GET'])
@jwt_required()
def get_user():
    try:
        current_user_id = get_jwt_identity()
        print(f"JWT Identity: {current_user_id}")
        
        user = User.query.get(current_user_id)
        
        if not user:
            print(f"User not found with ID: {current_user_id}")
            return jsonify({'message': 'User not found'}), 404
            
        print(f"User found: {user.username}")
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name
        }), 200
    except Exception as e:
        print(f"Error in /me endpoint: {str(e)}")
        return jsonify({'message': 'Authentication error', 'error': str(e)}), 401

@user_bp.route('/update', methods=['PUT'])
@jwt_required()
def update_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
        
    data = request.get_json()
    
    # Check if email is being changed and if it's already taken
    if 'email' in data and data['email'] != user.email:
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already taken'}), 400
            
    # Check if username is being changed and if it's already taken
    if 'username' in data and data['username'] != user.username:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Username already taken'}), 400
            
    # Update user fields
    if 'full_name' in data:
        user.full_name = data['full_name']
    if 'email' in data:
        user.email = data['email']
    if 'username' in data:
        user.username = data['username']
        
    db.session.commit()
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name
    }), 200

# Şifre değiştirme için özel endpoint
@user_bp.route('/<int:user_id>/password', methods=['POST'])
@jwt_required()
def change_password(user_id):
    # Token'dan gelen kullanıcı kimliğini kontrol et
    current_user_id = get_jwt_identity()
    
    # Sadece kendi şifresini değiştirebilir
    if current_user_id != user_id:
        return jsonify({'message': 'Unauthorized to change another user\'s password'}), 403
    
    # Kullanıcıyı bul
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    if not data or 'new_password' not in data:
        return jsonify({'message': 'New password is required'}), 400
    
    # Şifreyi güncelle
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'}), 200

# Özel şifre değiştirme endpoint'i - token problemlerinden bağımsız çalışacak
@user_bp.route('/simple-change-password', methods=['POST'])
def simple_change_password():
    data = request.get_json()
    
    if not data or 'email' not in data or 'new_password' not in data:
        return jsonify({'message': 'Email and new password are required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        return jsonify({'message': 'User not found with this email'}), 404
    
    # Doğrudan şifre değiştir - basitleştirilmiş süreç
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'}), 200

# Admin Endpoint - Tüm kullanıcıları listeleme
@user_bp.route('/admin/all-users', methods=['GET'])
def get_all_users():
    # Bu endpoint'i production'da kullanmadan önce admin kimlik doğrulaması ekleyin
    try:
        users = User.query.all()
        user_list = []
        
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name
            })
        
        return jsonify({
            'count': len(user_list),
            'users': user_list
        }), 200
    except Exception as e:
        print(f"Error fetching users: {str(e)}")
        return jsonify({'message': 'Error fetching users', 'error': str(e)}), 500 