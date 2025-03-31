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
          { type: 'SQL Injection', severity: 'High', count: 2, location: 'database/queries.py:45' },
          { type: 'Command Injection', severity: 'High', count: 1, location: 'utils/system.py:23' },
          { type: 'Insecure Deserialization', severity: 'Medium', count: 3, location: 'api/parser.py:78' },
          { type: 'Hardcoded Credentials', severity: 'Medium', count: 2, location: 'config/settings.py:12' },
          { type: 'Debug Mode Enabled', severity: 'Low', count: 1, location: 'app/main.py:8' },
          { type: 'Insecure Import', severity: 'Low', count: 2, location: 'utils/loader.py:34' }
        ],
        totalIssues: 11,
        scanTime: '3 minutes 20 seconds',
        scannedFile: file.name,
        fileSize: file.size,
        fileType: file.name.split('.').pop()
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
              <p>Upload your source code files for security analysis. Supported formats: .py, .java, .c, .cpp, .js, .php, .cs, .rb, .go</p>
              <div className="file-upload">
                <input
                  type="file"
                  onChange={handleFileChange}
                  accept=".py,.java,.c,.cpp,.js,.php,.cs,.rb,.go"
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
              <div className="scan-summary-card">
                <h4>Scan Summary</h4>
                <div className="scan-summary-content">
                  <div className="scan-summary-section">
                    <h5>File Information</h5>
                    <div className="scan-info-grid">
                      <div className="info-item">
                        <span className="info-label">Scanned File</span>
                        <span className="info-value">{results.scannedFile}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">File Type</span>
                        <span className="info-value">{results.fileType.toUpperCase()}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">File Size</span>
                        <span className="info-value">{(results.fileSize / 1024).toFixed(2)} KB</span>
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
                    <h5>Most Critical Issues</h5>
                    <div className="common-issues-list">
                      {results.vulnerabilities
                        .filter(v => v.severity === 'High')
                        .map((vuln, index) => (
                          <div key={index} className="common-issue-item">
                            <div className="issue-info">
                              <span className="issue-name">{vuln.type}</span>
                              <span className="issue-location">{vuln.location}</span>
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
                      <p className="location">Location: {vuln.location}</p>
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

export default SAST;
