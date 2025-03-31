import React from 'react';
import { Link } from 'react-router-dom';
import '../styles/Dashboard.css';

const Dashboard = () => {
    const handleActivityClick = (type, details) => {
        // Bu fonksiyon ilgili sayfaya yönlendirme yapacak
        console.log(`Clicked ${type}: ${details}`);
    };

    return (
        <div className="dashboard-container">
            <header className="dashboard-header">
                <span className="navbar-logo">AIronSafe</span>
            </header>

            <nav className="dashboard-nav">
                <div className="dashboard-nav-links">
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

                    <div className="activity-section">
                        <div className="recent-activity-card">
                            <h4>Recent Activity</h4>
                            <div className="activity-list">
                                <div className="activity-item" onClick={() => handleActivityClick('sast', 'file1.py')}>
                                    <div className="activity-icon sast">🔍</div>
                                    <div className="activity-content">
                                        <h5>SAST Scan Completed</h5>
                                        <p>file1.py</p>
                                    </div>
                                    <span className="activity-time">2 hours ago</span>
                                </div>

                                <div className="activity-item" onClick={() => handleActivityClick('dast', 'https://example.com')}>
                                    <div className="activity-icon dast">🌐</div>
                                    <div className="activity-content">
                                        <h5>DAST Scan Completed</h5>
                                        <p>https://example.com</p>
                                    </div>
                                    <span className="activity-time">3 hours ago</span>
                                </div>

                                <div className="activity-item" onClick={() => handleActivityClick('report', 'Report_01.pdf')}>
                                    <div className="activity-icon report">📊</div>
                                    <div className="activity-content">
                                        <h5>Report Generated</h5>
                                        <p>Report_01.pdf</p>
                                    </div>
                                    <span className="activity-time">5 hours ago</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
