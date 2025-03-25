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
      <div style={styles.appContainer}>
        <header style={styles.header}>
          AIronSafe
        </header>

        <div style={styles.content}>
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

        <footer style={styles.footer}>
          © 2025 AIronSafe. All Rights Reserved.
        </footer>
      </div>
    </Router>
  );
};

const styles = {
  appContainer: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh'
  },
  header: {
    backgroundColor: '#ffffff',
    borderBottom: '1px solid #ddd',
    padding: '1.5rem 0',
    textAlign: 'center',
    fontSize: '2rem',
    fontWeight: 'bold',
    color: '#4CAF50',
    position: 'fixed',
    width: '100%',
    top: 0,
    zIndex: 10
  },
  content: {
    flexGrow: 1,
    marginTop: '5rem',
    overflowY: 'auto'
  },
  footer: {
    textAlign: 'center',
    padding: '1rem',
    backgroundColor: '#f9f9f9',
    borderTop: '1px solid #ddd',
    position: 'fixed',
    bottom: 0,
    width: '100%'
  }
};

export default App;
