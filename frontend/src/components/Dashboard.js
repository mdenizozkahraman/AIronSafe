import React from 'react';
import { commonStyles } from '../styles/commonStyles';

const Dashboard = () => {
    return (
        <div style={commonStyles.container}>
            {/* Header */}
            <header style={commonStyles.header}>
                AIronSafe Dashboard
            </header>

            {/* Navbar */}
            <nav style={commonStyles.nav}>
                <div>
                    <a href="/dashboard" style={commonStyles.link}>Dashboard</a>
                    <a href="/sast" style={commonStyles.link}>SAST</a>
                    <a href="/dast" style={commonStyles.link}>DAST</a>
                </div>
                <div>
                    <a href="/" style={commonStyles.link}>Logout</a>
                </div>
            </nav>

            {/* Content */}
            <div style={commonStyles.content}>
                {/* Sidebar */}
                <div style={commonStyles.sidebar}>
                    <h3>Navigation</h3>
                    <ul>
                        <li>Overview</li>
                        <li>Recent Scans</li>
                        <li>Reports</li>
                        <li>Settings</li>
                    </ul>
                </div>

                {/* Main */}
                <div style={commonStyles.main}>
                    <div style={commonStyles.stats}>
                        <div style={commonStyles.card}>
                            <h4>Total Scans</h4>
                            <p>120</p>
                        </div>
                        <div style={commonStyles.card}>
                            <h4>Critical Issues</h4>
                            <p>15</p>
                        </div>
                        <div style={commonStyles.card}>
                            <h4>Resolved Issues</h4>
                            <p>105</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
