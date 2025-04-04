from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from __init__ import db
from datetime import datetime


def create_user(username, email, password, full_name=None):
    if is_username_taken(username):
        return {"message": "Username already taken"}, 400
    
    if is_email_taken(email):
        return {"message": "Email already registered"}, 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(
        username=username,
        email=email,
        password=hashed_password,
        full_name=full_name
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return {"message": "User created successfully", "user": new_user.to_dict()}, 201
    except Exception as e:
        db.session.rollback()
        return {"message": "Error creating user", "error": str(e)}, 500


def authenticate_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        user.last_login = datetime.utcnow()
        db.session.commit()
        return user
    return None


def is_username_taken(username):
    return User.query.filter_by(username=username).first() is not None


def is_email_taken(email):
    return User.query.filter_by(email=email).first() is not None


def get_user_by_id(user_id):
    return User.query.get(user_id)


def update_user(user_id, data):
    user = get_user_by_id(user_id)
    if not user:
        return {"message": "User not found"}, 404
    
    try:
        if 'email' in data and data['email'] != user.email:
            if is_email_taken(data['email']):
                return {"message": "Email already taken"}, 400
            user.email = data['email']
        
        if 'full_name' in data:
            user.full_name = data['full_name']
        
        if 'password' in data:
            user.password = generate_password_hash(data['password'])
        
        db.session.commit()
        return {"message": "User updated successfully", "user": user.to_dict()}, 200
    except Exception as e:
        db.session.rollback()
        return {"message": "Error updating user", "error": str(e)}, 500
