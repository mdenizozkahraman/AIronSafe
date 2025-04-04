from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.todo import Todo
from __init__ import db

todo_bp = Blueprint('todo_bp', __name__)

@todo_bp.route('', methods=['GET'])
@jwt_required()
def get_todos():
    current_user_id = get_jwt_identity()
    todos = Todo.query.filter_by(user_id=current_user_id).all()
    return jsonify([todo.to_dict() for todo in todos]), 200

@todo_bp.route('', methods=['POST'])
@jwt_required()
def create_todo():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'title' not in data:
        return jsonify({'message': 'Title is required'}), 400
        
    new_todo = Todo(
        title=data['title'],
        description=data.get('description', ''),
        user_id=current_user_id
    )
    
    db.session.add(new_todo)
    db.session.commit()
    
    return jsonify(new_todo.to_dict()), 201

@todo_bp.route('/<int:todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    current_user_id = get_jwt_identity()
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user_id).first()
    
    if not todo:
        return jsonify({'message': 'Todo not found'}), 404
        
    data = request.get_json()
    
    if 'title' in data:
        todo.title = data['title']
    if 'description' in data:
        todo.description = data['description']
    if 'completed' in data:
        todo.completed = data['completed']
        
    db.session.commit()
    
    return jsonify(todo.to_dict()), 200

@todo_bp.route('/<int:todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    current_user_id = get_jwt_identity()
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user_id).first()
    
    if not todo:
        return jsonify({'message': 'Todo not found'}), 404
        
    db.session.delete(todo)
    db.session.commit()
    
    return jsonify({'message': 'Todo deleted successfully'}), 200 