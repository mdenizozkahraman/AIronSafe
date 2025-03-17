from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from __init__ import db


def create_user(username, password):
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return {"message": "User created successfully"}, 201


def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return user
    return None


def is_username_taken(username):
    return User.query.filter_by(username=username).first() is not None
