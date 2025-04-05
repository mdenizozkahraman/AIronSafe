import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import SAST from './components/SAST';
import DAST from './components/DAST';
import Profile from './components/Profile';
import Login from './components/Login';
import Register from './components/Register';
import ForgotPassword from './components/ForgotPassword';
import HomePage from './components/HomePage';
import Logout from './components/Logout';

// Protected route component
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

function App() {
  const [darkMode, setDarkMode] = useState(localStorage.getItem('darkMode') === 'true' || false);
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));

  useEffect(() => {
    // Apply dark mode to the document
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('darkMode', darkMode);
  }, [darkMode]);

  useEffect(() => {
    // Güncel authentication durumunu kontrol et
    const checkAuth = () => {
      setIsAuthenticated(!!localStorage.getItem('token'));
    };
    
    // Sayfa yüklendiğinde kontrol et
    checkAuth();
    
    // localStorage değişikliklerini dinle
    window.addEventListener('storage', checkAuth);
    
    return () => {
      window.removeEventListener('storage', checkAuth);
    };
  }, []);

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setIsAuthenticated(false);
  };

  const checkIsAuthenticated = () => {
    return !!localStorage.getItem('token');
  };

  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/logout" element={<Logout />} />
        
        {/* Protected Routes */}
        <Route 
          path="/dashboard" 
          element={
            checkIsAuthenticated() ? 
            <Layout 
              darkMode={darkMode}
              toggleDarkMode={toggleDarkMode}
              handleLogout={handleLogout}
            >
              <Dashboard />
            </Layout> : 
            <Navigate to="/login" />
          } 
        />
        <Route 
          path="/sast" 
          element={
            checkIsAuthenticated() ? 
            <Layout 
              darkMode={darkMode}
              toggleDarkMode={toggleDarkMode}
              handleLogout={handleLogout}
            >
              <SAST />
            </Layout> : 
            <Navigate to="/login" />
          } 
        />
        <Route 
          path="/dast" 
          element={
            checkIsAuthenticated() ? 
            <Layout 
              darkMode={darkMode}
              toggleDarkMode={toggleDarkMode}
              handleLogout={handleLogout}
            >
              <DAST />
            </Layout> : 
            <Navigate to="/login" />
          } 
        />
        <Route 
          path="/profile" 
          element={
            checkIsAuthenticated() ? 
            <Layout 
              darkMode={darkMode}
              toggleDarkMode={toggleDarkMode}
              handleLogout={handleLogout}
            >
              <Profile />
            </Layout> : 
            <Navigate to="/login" />
          } 
        />
        
        {/* Fallback Route - Handle non-existent pages */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
