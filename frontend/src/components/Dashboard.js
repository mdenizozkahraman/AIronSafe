import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import '../styles/Dashboard.css';

const Dashboard = () => {
    const [user, setUser] = useState(null);
    const [todos, setTodos] = useState([]);
    const [newTodo, setNewTodo] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/');
            return;
        }

        // Kullanıcı bilgilerini çek
        fetch('http://localhost:5000/api/users/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (!response.ok) throw new Error('Failed to fetch user data');
            return response.json();
        })
        .then(data => setUser(data))
        .catch(err => {
            console.error('Error fetching user data:', err);
            setError('Failed to load user data');
        });

        // Todo'ları çek
        fetch('http://localhost:5000/api/todos', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (!response.ok) throw new Error('Failed to fetch todos');
            return response.json();
        })
        .then(data => setTodos(data))
        .catch(err => {
            console.error('Error fetching todos:', err);
            setError('Failed to load todos');
        });
    }, [navigate]);

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/');
    };

    const handleAddTodo = async (e) => {
        e.preventDefault();
        const token = localStorage.getItem('token');
        
        try {
            const response = await fetch('http://localhost:5000/api/todos', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    title: newTodo,
                    description: ''
                })
            });

            if (!response.ok) throw new Error('Failed to add todo');
            
            const newTodoItem = await response.json();
            setTodos([...todos, newTodoItem]);
            setNewTodo('');
        } catch (err) {
            console.error('Error adding todo:', err);
            setError('Failed to add todo');
        }
    };

    const handleToggleTodo = async (todoId) => {
        const token = localStorage.getItem('token');
        const todo = todos.find(t => t.id === todoId);
        
        try {
            const response = await fetch(`http://localhost:5000/api/todos/${todoId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    completed: !todo.completed
                })
            });

            if (!response.ok) throw new Error('Failed to update todo');
            
            setTodos(todos.map(t => 
                t.id === todoId ? { ...t, completed: !t.completed } : t
            ));
        } catch (err) {
            console.error('Error updating todo:', err);
            setError('Failed to update todo');
        }
    };

    return (
        <div className="dashboard-container">
            <header className="dashboard-header">
                <span className="navbar-logo">AIronSafe</span>
                {user && <span className="user-info">Welcome, {user.full_name}</span>}
            </header>

            <nav className="dashboard-nav">
                <div className="dashboard-nav-links">
                    <Link to="/dashboard">Dashboard</Link>
                    <Link to="/sast">SAST</Link>
                    <Link to="/dast">DAST</Link>
                </div>
                <div>
                    <button onClick={handleLogout} className="logout-button">Logout</button>
                </div>
            </nav>

            <div className="container">
                <div className="sidebar">
                    <div className="user-profile">
                        <h3>Profile</h3>
                        {user && (
                            <div className="profile-info">
                                <p><strong>Username:</strong> {user.username}</p>
                                <p><strong>Email:</strong> {user.email}</p>
                            </div>
                        )}
                    </div>
                </div>

                <div className="main">
                    <div className="todos-section">
                        <h3>My Tasks</h3>
                        {error && <div className="error-message">{error}</div>}
                        
                        <form onSubmit={handleAddTodo} className="add-todo-form">
                            <input
                                type="text"
                                value={newTodo}
                                onChange={(e) => setNewTodo(e.target.value)}
                                placeholder="Add new task..."
                                required
                            />
                            <button type="submit">Add</button>
                        </form>

                        <div className="todos-list">
                            {todos.map(todo => (
                                <div 
                                    key={todo.id} 
                                    className={`todo-item ${todo.completed ? 'completed' : ''}`}
                                    onClick={() => handleToggleTodo(todo.id)}
                                >
                                    <span className="todo-checkbox">
                                        {todo.completed ? '✓' : ''}
                                    </span>
                                    <span className="todo-title">{todo.title}</span>
                                    <span className="todo-date">
                                        {new Date(todo.created_at).toLocaleDateString()}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
