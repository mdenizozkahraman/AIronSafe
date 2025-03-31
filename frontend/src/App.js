import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import SAST from './components/SAST';
import DAST from './components/DAST';
import './App.css';

const App = () => {
  const [showLogin, setShowLogin] = useState(true);

  const switchToRegister = () => setShowLogin(false);
  const switchToLogin = () => setShowLogin(true);

  return (
    <Router>
      <div className="app-container">
        <header className="app-header">
          <span className="navbar-logo">AIronSafe</span>
        </header>

        <div className="app-content">
          <Routes>
            <Route 
              path="/" 
              element={
                showLogin ? 
                <Login switchToRegister={switchToRegister} /> : 
                <Register switchToLogin={switchToLogin} />
              } 
            />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/sast" element={<SAST />} />
            <Route path="/dast" element={<DAST />} />
          </Routes>
        </div>

        <footer className="app-footer">
          © 2025 AIronSafe. All Rights Reserved.
        </footer>
      </div>
    </Router>
  );
};

export default App;
