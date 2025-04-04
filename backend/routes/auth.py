from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from services.user_service import (
    create_user, 
    authenticate_user, 
    is_username_taken,
    get_user_by_id,
    update_user
)

auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')

    if not all([username, email, password]):
        return jsonify({"message": "Username, email and password are required"}), 400

    return create_user(username, email, password, full_name)


@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    user = authenticate_user(email, password)
    if user:
        token = create_access_token(identity=user.id)
        return jsonify({
            "token": token,
            "user": user.to_dict()
        }), 200

    return jsonify({"message": "Invalid credentials"}), 401


@auth.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = get_user_by_id(user_id)
    if user:
        return jsonify(user.to_dict()), 200
    return jsonify({"message": "User not found"}), 404


@auth.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    data = request.get_json()
    return update_user(user_id, data)
