from flask import Blueprint, jsonify

hello_bp = Blueprint('hello_bp', __name__)

@hello_bp.route('/hello', methods=['GET'])
def hello():
    return jsonify({"message": "Hello from AIronSafe!"}) 