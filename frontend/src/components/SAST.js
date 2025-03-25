import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import '../styles/SAST.css';

const SAST = () => {
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleScan = async () => {
    if (!file) {
      alert('Please select a file first');
      return;
    }

    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      setResults({
        vulnerabilities: [
          { type: 'SQL Injection', severity: 'High', count: 2 },
          { type: 'XSS', severity: 'Medium', count: 3 },
          { type: 'Command Injection', severity: 'High', count: 1 },
          { type: 'Path Traversal', severity: 'Medium', count: 2 },
          { type: 'Insecure Configuration', severity: 'Low', count: 4 }
        ],
        totalIssues: 12
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
          <Link to="/sast" className="active">SAST</Link>
          <Link to="/dast">DAST</Link>
        </div>
        <div>
          <Link to="/">Logout</Link>
        </div>
      </nav>

      <div className="container">
        <div className="sidebar">
          <h3>SAST Analysis</h3>
          <ul>
            <li>New Scan</li>
            <li>Scan History</li>
            <li>Configuration</li>
            <li>Reports</li>
          </ul>
        </div>

        <div className="main">
          <div className="scan-section">
            <div className="upload-box">
              <h2>Static Application Security Testing</h2>
              <div className="file-upload">
                <input
                  type="file"
                  onChange={handleFileChange}
                  accept=".zip,.rar,.7zip,.tar,.gz"
                />
                <button 
                  onClick={handleScan}
                  disabled={scanning || !file}
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

export default SAST;
