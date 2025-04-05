from __init__ import create_app
from routes.user_routes import user_bp
from routes.todo_routes import todo_bp
from routes.dast_routes import dast_bp
from flask_cors import CORS

app = create_app()
app.register_blueprint(user_bp, url_prefix='/api/users')
app.register_blueprint(todo_bp, url_prefix='/api/todos')
app.register_blueprint(dast_bp, url_prefix='/api/dast')
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

if __name__ == '__main__':
    app.debug = True
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(host='0.0.0.0', port=5000)
