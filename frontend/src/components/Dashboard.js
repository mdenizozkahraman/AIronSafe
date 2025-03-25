import React from 'react';
import { Link } from 'react-router-dom';
import '../styles/Dashboard.css';

const Dashboard = () => {
    return (
        <div className="dashboard-container">
            <header className="dashboard-header">
                AIronSafe Dashboard
            </header>

            <nav className="dashboard-nav">
                <div>
                    <Link to="/dashboard">Dashboard</Link>
                    <Link to="/sast">SAST</Link>
                    <Link to="/dast">DAST</Link>
                </div>
                <div>
                    <Link to="/">Logout</Link>
                </div>
            </nav>

            <div className="container">
                <div className="sidebar">
                    <h3>Navigation</h3>
                    <ul>
                        <li>Overview</li>
                        <li>Recent Scans</li>
                        <li>Reports</li>
                        <li>Settings</li>
                    </ul>
                </div>

                <div className="main">
                    <div className="stats">
                        <div className="card">
                            <h4>Total Scans</h4>
                            <p>120</p>
                        </div>
                        <div className="card">
                            <h4>Critical Issues</h4>
                            <p>15</p>
                        </div>
                        <div className="card">
                            <h4>Resolved Issues</h4>
                            <p>105</p>
                        </div>
                    </div>

                    <div className="chart">
                        <h4>Scan Activity (Last 30 Days)</h4>
                        <p>[Chart Placeholder]</p>
                    </div>

                    <div className="recent-activity">
                        <h4>Recent Activity</h4>
                        <ul>
                            <li>SAST scan completed on file1.py</li>
                            <li>DAST scan completed for https://example.com</li>
                            <li>Report generated: Report_01.pdf</li>
                        </ul>
                    </div>
                </div>
            </div>

            <footer className="dashboard-footer">
                <p>&copy; 2025 AIronSafe. All Rights Reserved.</p>
            </footer>
        </div>
    );
};

export default Dashboard;
