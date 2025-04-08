from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager

import os
import logging

db = SQLAlchemy()
jwt = JWTManager()

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    # CORS settings
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Database connection settings
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@db/aironsafek'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # SECRET_KEY setting
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    
    # JWT settings
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or 'jwt-dev-secret-key'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour

    # Logging settings
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Test configuration
    if test_config is not None:
        app.config.from_mapping(test_config)

    # Initialize database
    db.init_app(app)
    
    # Initialize JWT Manager
    jwt.init_app(app)

    # Register blueprints
    from routes.dast_routes import dast_bp
    from routes.sast_routes import sast_bp
    
    app.register_blueprint(dast_bp, url_prefix='/api/dast')
    app.register_blueprint(sast_bp, url_prefix='/api/sast')

    # Create database tables
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {str(e)}")

    @app.route('/')
    def hello():
        return {'message': 'Hello, World!'}

    return app
