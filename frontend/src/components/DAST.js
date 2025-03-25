import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import '../styles/DAST.css';

const DAST = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);

  const handleScan = async () => {
    if (!url) {
      alert('Please enter a URL first');
      return;
    }

    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      setResults({
        vulnerabilities: [
          { type: 'SQL Injection', severity: 'High', count: 1 },
          { type: 'Cross-Site Scripting (XSS)', severity: 'High', count: 2 },
          { type: 'Cross-Site Request Forgery', severity: 'Medium', count: 3 },
          { type: 'Information Disclosure', severity: 'Medium', count: 2 },
          { type: 'Missing Security Headers', severity: 'Low', count: 4 },
          { type: 'Cookie Security', severity: 'Low', count: 2 }
        ],
        totalIssues: 14,
        scanTime: '5 minutes 45 seconds',
        targetUrl: url
      });
    }, 2000);
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        AIronSafe Dashboard
      </header>

      <nav className="dashboard-nav">
        <div>
          <Link to="/dashboard">Dashboard</Link>
          <Link to="/sast">SAST</Link>
          <Link to="/dast" className="active">DAST</Link>
        </div>
        <div>
          <Link to="/">Logout</Link>
        </div>
      </nav>

      <div className="container">
        <div className="sidebar">
          <h3>DAST Analysis</h3>
          <ul>
            <li>New Scan</li>
            <li>Scan History</li>
            <li>Configuration</li>
            <li>Reports</li>
          </ul>
        </div>

        <div className="main">
          <div className="scan-section">
            <div className="url-input-box">
              <h2>Dynamic Application Security Testing</h2>
              <p>Enter the URL of your web application for security analysis</p>
              <div className="url-form">
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="example.com"
                  className="url-field"
                />
                <button 
                  onClick={handleScan}
                  disabled={scanning || !url}
                  className="scan-button"
                >
                  {scanning ? 'Scanning...' : 'Start Scan'}
                </button>
              </div>
            </div>
          </div>

          {results && (
            <>
              <div className="stats">
                <div className="card">
                  <h4>High Severity</h4>
                  <p className="high">{results.vulnerabilities.filter(v => v.severity === 'High').reduce((acc, v) => acc + v.count, 0)}</p>
                </div>
                <div className="card">
                  <h4>Medium Severity</h4>
                  <p className="medium">{results.vulnerabilities.filter(v => v.severity === 'Medium').reduce((acc, v) => acc + v.count, 0)}</p>
                </div>
                <div className="card">
                  <h4>Low Severity</h4>
                  <p className="low">{results.vulnerabilities.filter(v => v.severity === 'Low').reduce((acc, v) => acc + v.count, 0)}</p>
                </div>
              </div>

              <div className="vulnerabilities-list">
                <h4>Detected Vulnerabilities</h4>
                <div className="vuln-grid">
                  {results.vulnerabilities.map((vuln, index) => (
                    <div key={index} className={`vuln-card ${vuln.severity.toLowerCase()}`}>
                      <h3>{vuln.type}</h3>
                      <p className="severity">Severity: {vuln.severity}</p>
                      <p className="count">Found: {vuln.count}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="scan-info">
                <h4>Scan Information</h4>
                <p>Target URL: {results.targetUrl}</p>
                <p>Total Issues Found: {results.totalIssues}</p>
                <p>Scan Duration: {results.scanTime}</p>
              </div>
            </>
          )}
        </div>
      </div>

      <footer className="dashboard-footer">
        <p>&copy; 2025 AIronSafe. All Rights Reserved.</p>
      </footer>
    </div>
  );
};

export default DAST;
