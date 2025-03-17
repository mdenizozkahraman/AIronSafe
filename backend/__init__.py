from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from config import Config


db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)

    
    from routes.auth import auth
    from routes.dashboard import dashboard
    
    app.register_blueprint(auth, url_prefix="/auth")
    app.register_blueprint(dashboard, url_prefix="/dashboard")

    with app.app_context():
        db.create_all()

    @app.route('/health')
    def health():
        return jsonify({'status': 'ok'}), 200
        
    return app
