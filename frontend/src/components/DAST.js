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
        <span className="navbar-logo">AIronSafe</span>
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
              <div className="scan-summary-card">
                <h4>Scan Summary</h4>
                <div className="scan-summary-content">
                  <div className="scan-summary-section">
                    <h5>Target Information</h5>
                    <div className="scan-info-grid">
                      <div className="info-item">
                        <span className="info-label">Target URL</span>
                        <span className="info-value">{results.targetUrl}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Scan Duration</span>
                        <span className="info-value">{results.scanTime}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Scan Status</span>
                        <span className="info-value status-complete">Completed</span>
                      </div>
                    </div>
                  </div>

                  <div className="scan-summary-section">
                    <h5>Vulnerability Overview</h5>
                    <div className="scan-info-grid">
                      <div className="info-item">
                        <span className="info-label">Total Issues</span>
                        <span className="info-value highlight">{results.totalIssues}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">High Severity</span>
                        <span className="info-value high">{results.vulnerabilities.filter(v => v.severity === 'High').reduce((acc, v) => acc + v.count, 0)}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Medium Severity</span>
                        <span className="info-value medium">{results.vulnerabilities.filter(v => v.severity === 'Medium').reduce((acc, v) => acc + v.count, 0)}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Low Severity</span>
                        <span className="info-value low">{results.vulnerabilities.filter(v => v.severity === 'Low').reduce((acc, v) => acc + v.count, 0)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="scan-summary-section">
                    <h5>Most Common Issues</h5>
                    <div className="common-issues-list">
                      {results.vulnerabilities
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 3)
                        .map((vuln, index) => (
                          <div key={index} className="common-issue-item">
                            <div className="issue-info">
                              <span className="issue-name">{vuln.type}</span>
                              <span className={`issue-severity ${vuln.severity.toLowerCase()}`}>{vuln.severity}</span>
                            </div>
                            <span className="issue-count">{vuln.count} instances</span>
                          </div>
                        ))}
                    </div>
                  </div>
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
    </div>
  );
};

export default DAST;
