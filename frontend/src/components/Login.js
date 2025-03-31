import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Login.css';

const Login = ({ switchToRegister }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();

        if (email === 'admin@aironsafe.com' && password === 'admin') {
            navigate('/dashboard');
        } else {
            alert('Invalid credentials');
        }
    };

    return (
        <div className="login-container">
            <div className="login-left">
                <div className="login-left-content">
                    <h1>Welcome to AIronSafe</h1>
                    <p>Advanced Web Application Security Testing Tool</p>
                    <div className="features">
                        <div className="feature-item">
                            <span className="feature-icon">🔍</span>
                            <span>SAST Analysis</span>
                        </div>
                        <div className="feature-item">
                            <span className="feature-icon">🌐</span>
                            <span>DAST Testing</span>
                        </div>
                        <div className="feature-item">
                            <span className="feature-icon">📊</span>
                            <span>Detailed Reports</span>
                        </div>
                    </div>
                </div>
            </div>
            <div className="login-right">
                <div className="login-form-container">
                    <h2>Login</h2>
                    <form onSubmit={handleLogin}>
                        <div className="form-group">
                            <input
                                type="email"
                                placeholder="Email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <input
                                type="password"
                                placeholder="Password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                            />
                        </div>
                        <button type="submit" className="login-button">Login</button>
                    </form>
                    <p className="register-link">
                        Don't have an account?{' '}
                        <a href="#" onClick={switchToRegister}>
                            Register
                        </a>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Login;
