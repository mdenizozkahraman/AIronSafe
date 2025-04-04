import React, { useState } from 'react';
import { register } from '../services/authService';
import '../styles/Login.css';

const Register = ({ switchToLogin }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    fullName: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      const result = await register(
        formData.username,
        formData.email,
        formData.password,
        formData.fullName
      );
      console.log('Registration result:', result);
      setSuccess('Registration successful! Redirecting to login...');
      setTimeout(() => {
        switchToLogin();
      }, 2000);
    } catch (err) {
      console.error('Registration error:', err);
      setError(err.message || 'Registration failed. Please try again.');
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
          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <input
                type="text"
                name="username"
                placeholder="Username"
                value={formData.username}
                onChange={handleChange}
                required
              />
            </div>
            <div className="form-group">
              <input
                type="text"
                name="fullName"
                placeholder="Full Name"
                value={formData.fullName}
                onChange={handleChange}
              />
            </div>
            <div className="form-group">
              <input
                type="email"
                name="email"
                placeholder="Email"
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>
            <div className="form-group">
              <input
                type="password"
                name="password"
                placeholder="Password"
                value={formData.password}
                onChange={handleChange}
                required
              />
            </div>
            <div className="form-group">
              <input
                type="password"
                name="confirmPassword"
                placeholder="Confirm Password"
                value={formData.confirmPassword}
                onChange={handleChange}
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
