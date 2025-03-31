import React, { useState } from 'react';
import { register } from '../services/authService';
import '../styles/Login.css';

const Register = ({ switchToLogin }) => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      alert('Passwords do not match');
      return;
    }
    const result = await register(username, email, password);
    if (result.message === 'User created successfully') {
      alert('Registration successful!');
      switchToLogin();
    } else {
      alert(result.message);
    }
  };

  return (
    <div className="login-container">
      <div className="login-left">
        <div className="login-left-content">
          <h1>Join AIronSafe</h1>
          <p>Start securing your web applications today</p>
          <div className="features">
            <div className="feature-item">
              <span className="feature-icon">🔒</span>
              <span>Advanced Security Analysis</span>
            </div>
            <div className="feature-item">
              <span className="feature-icon">⚡</span>
              <span>Real-time Monitoring</span>
            </div>
            <div className="feature-item">
              <span className="feature-icon">📱</span>
              <span>Cross-platform Support</span>
            </div>
          </div>
        </div>
      </div>
      <div className="login-right">
        <div className="login-form-container">
          <h2>Create Account</h2>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <input
                type="text"
                placeholder="Full Name"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
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
            <div className="form-group">
              <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="login-button">Register</button>
          </form>
          <p className="register-link">
            Already have an account?{' '}
            <a href="#" onClick={switchToLogin}>
              Login
            </a>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;
