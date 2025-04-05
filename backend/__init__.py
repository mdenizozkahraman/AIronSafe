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

    # CORS ayarları
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Veritabanı bağlantı ayarları
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@db/aironsafek'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # SECRET_KEY ayarı
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    
    # JWT ayarları
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or 'jwt-dev-secret-key'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 saat

    # Logging ayarları
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Test konfigürasyonu için
    if test_config is not None:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # Veritabanını başlat
    db.init_app(app)
    
    # JWT Manager'ı başlat
    jwt.init_app(app)

    # Blueprint'leri kaydet
    # from routes.hello import hello_bp  # Bu satırı kaldırıyoruz
    # app.register_blueprint(hello_bp)   # Bu satırı kaldırıyoruz
    
    # Yeni blueprintleri kaydet
    from routes.auth_routes import auth_bp
    from routes.dast_routes import dast_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dast_bp, url_prefix='/api/dast')

    # Veritabanını oluştur
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
