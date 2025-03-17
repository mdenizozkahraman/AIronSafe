from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from services.user_service import create_user, authenticate_user, is_username_taken

auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    
    if is_username_taken(username):
        return jsonify({"message": "Username already taken"}), 400

    
    return create_user(username, password)


@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = authenticate_user(username, password)
    if user:
        token = create_access_token(identity=user.id)
        return jsonify({"token": token}), 200

    return jsonify({"message": "Invalid credentials"}), 401
