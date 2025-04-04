from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config import Config


db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

    db.init_app(app)
    jwt.init_app(app)

    
    from routes.user_routes import user_bp
    from routes.todo_routes import todo_bp
    
    app.register_blueprint(user_bp, url_prefix="/api/users")
    app.register_blueprint(todo_bp, url_prefix="/api/todos")

    with app.app_context():
        db.create_all()

    @app.route('/health')
    def health():
        return jsonify({'status': 'ok'}), 200
        
    return app
