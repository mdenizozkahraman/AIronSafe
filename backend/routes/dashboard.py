from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

dashboard = Blueprint('dashboard', __name__)

@dashboard.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    return jsonify({
        "total_scans": 10,
        "critical_issues": 2,
        "high_issues": 3
    })
