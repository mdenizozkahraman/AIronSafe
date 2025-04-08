from __init__ import create_app
from routes.user_routes import user_bp
from routes.todo_routes import todo_bp
from flask_cors import CORS

app = create_app()

# Register blueprints with correct URL prefixes
app.register_blueprint(user_bp, url_prefix='/api/users')
app.register_blueprint(todo_bp, url_prefix='/api/todos')

# Configure CORS
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
